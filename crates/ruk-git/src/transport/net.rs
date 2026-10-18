//! Network remote endpoints: URL parsing plus the SSH and git-daemon
//! transports.
//!
//! [`parse_endpoint`] classifies any remote string through `gix-url` (an
//! existing dependency, so no new crates): bare paths and `file://` URLs
//! are local, `ssh://` URLs and scp-like `host:path` spellings dial over
//! SSH, `git://` URLs dial a git daemon over TCP, and `http(s)://` URLs
//! parse to a named gap (this slice ships no HTTP client).
//!
//! The wire grammars stay owned in-process: [`open_stream`] only yields a
//! duplex byte stream, and callers drive [`super::fetch::receive`] and
//! [`super::push::push_over`] over it exactly as the scripted peers do in
//! tests. [`discover`] reads one advertisement (v0 refs or v2 `ls-refs`)
//! and maps it onto [`AdvertisedLocalRef`] rows so the fetch/push verbs can
//! expand refspecs without a local source store.
//!
//! Oracle anchors: `git/connect.c` (SSH command construction,
//! `GIT_SSH_COMMAND`/`GIT_SSH`), `git/Documentation/gitprotocol-pack.txt`
//! (git:// request shape), `git/builtin/ls-remote.c` (discovery).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use ruk_core::ids::HashKind;
use ruk_core::refdata::{RefName, RefTarget};

use super::pktline::PktReader;
use super::refadv::{self, AdvertisedRef, Initial};
use super::session::{AdvertisedLocalRef, Service};
use super::{Interrupt, pktline};
use crate::GitError;

/// Default git-daemon port (`git/Documentation/gitprotocol-pack.txt`).
const GIT_DAEMON_PORT: u16 = 9418;

/// A parsed fetch/push endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A repository path on this host: bare paths and `file://` URLs.
    Local {
        /// The path as spelled (relative stays relative; the CLI resolves
        /// it against the working directory).
        path: PathBuf,
    },
    /// `ssh://[user@]host[:port]/path` or scp-like `[user@]host:path`.
    Ssh {
        /// Remote host.
        host: String,
        /// Explicit port, if any (`-p`).
        port: Option<u16>,
        /// Remote user, if any (`user@host`).
        user: Option<String>,
        /// Repository path on the remote.
        path: String,
    },
    /// `git://host[:port]/path`: plaintext git-daemon transport.
    Git {
        /// Daemon host.
        host: String,
        /// Explicit port, if any (default [`GIT_DAEMON_PORT`]).
        port: Option<u16>,
        /// Repository path on the daemon.
        path: String,
    },
    /// `http(s)://` URLs: parsed, then refused as a named gap (no HTTP
    /// client in this slice).
    Http {
        /// Whether the scheme was `https`.
        secure: bool,
        /// The URL as spelled, echoed for diagnostics.
        url: String,
    },
}

impl Endpoint {
    /// Whether this endpoint is served without a network connection.
    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local { .. })
    }
}

/// Parses `spec` into an endpoint through `gix-url`, so scp-like
/// spellings and percent escapes behave the way Git spells them.
///
/// A bare `host:path` without a user or scheme stays a local path (Git
/// would dial SSH there; local colons win here so existing local remotes
/// keep working).
///
/// # Errors
/// [`GitError::Invalid`] for empty or unparsable input, [`GitError::Unsupported`]
/// for `ext::` and remote-helper schemes.
pub fn parse_endpoint(spec: &str) -> Result<Endpoint, GitError> {
    if spec.is_empty() {
        return Err(GitError::Invalid {
            detail: "empty remote".to_owned(),
        });
    }
    // A colon before any slash without `user@` is ambiguous with local
    // `dir:name` paths; keep those local and let explicit `ssh://` URLs
    // and `user@host:path` spellings request SSH. Remote-helper `name::`
    // forms still parse as helpers so they refuse loudly instead of
    // running a local path by accident.
    if !spec.contains("://") && !looks_like_explicit_ssh(spec) && !is_helper_form(spec) {
        return Ok(Endpoint::Local {
            path: PathBuf::from(spec),
        });
    }
    let url = gix_url::parse(spec).map_err(|err| GitError::Invalid {
        detail: format!("unparsable remote {spec:?}: {err}"),
    })?;
    let path_text = std::str::from_utf8(url.path.as_ref()).map_err(|_| GitError::Invalid {
        detail: format!("remote path is not UTF-8: {spec:?}"),
    })?;
    match url.scheme {
        gix_url::Scheme::File => {
            if let Some(host) = url.host.as_deref()
                && !host.is_empty()
                && host != "localhost"
            {
                return Err(GitError::Invalid {
                    detail: format!("file:// remote with host {host:?} is not local: {spec:?}"),
                });
            }
            Ok(Endpoint::Local {
                path: PathBuf::from(path_text),
            })
        }
        gix_url::Scheme::Ssh => Ok(Endpoint::Ssh {
            host: url.host.ok_or_else(|| GitError::Invalid {
                detail: format!("ssh remote without a host: {spec:?}"),
            })?,
            port: url.port,
            user: url.user,
            path: path_text.to_owned(),
        }),
        gix_url::Scheme::Git => Ok(Endpoint::Git {
            host: url.host.ok_or_else(|| GitError::Invalid {
                detail: format!("git:// remote without a host: {spec:?}"),
            })?,
            port: url.port,
            path: path_text.to_owned(),
        }),
        gix_url::Scheme::Http => Ok(Endpoint::Http {
            secure: false,
            url: spec.to_owned(),
        }),
        gix_url::Scheme::Https => Ok(Endpoint::Http {
            secure: true,
            url: spec.to_owned(),
        }),
        gix_url::Scheme::Ext => Err(GitError::Unsupported {
            command: format!("ext:: remote {spec:?} (remote helpers are out of scope)"),
        }),
        gix_url::Scheme::Helper(name) | gix_url::Scheme::HelperUrl(name) => {
            Err(GitError::Unsupported {
                command: format!("remote-helper {name:?} for {spec:?} (out of scope)"),
            })
        }
    }
}

/// Whether `spec` is a remote-helper `name::address` form: a leading name
/// of word characters, dots, or dashes, then a double colon.
fn is_helper_form(spec: &str) -> bool {
    spec.split_once("::").is_some_and(|(name, _)| {
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    })
}

/// Whether `spec` is an scp-like SSH spelling with an explicit user:
/// `user@host:path` with the colon before any slash.
fn looks_like_explicit_ssh(spec: &str) -> bool {
    let Some(at) = spec.find('@') else {
        return false;
    };
    let Some(colon) = spec.find(':') else {
        return false;
    };
    at < colon && !spec[..colon].contains('/')
}

/// The refusal for HTTP endpoints: parsed but unserved, a named gap.
#[must_use]
pub fn http_gap(url: &str) -> GitError {
    GitError::Unsupported {
        command: format!(
            "{url}: http(s) remotes need an HTTP client (named gap; use a local path, file://, ssh:// or git://)"
        ),
    }
}

/// Single-quotes `text` for a remote shell: safe for paths starting with
/// `-`, which then cannot mask as command-line arguments.
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// The remote command the SSH server runs: `git-upload-pack '<path>'`.
fn remote_command(service: Service, path: &str) -> String {
    format!("{} {}", service.name(), shell_quote(path))
}

/// How to spawn the SSH connection: a program plus argv, or a shell line
/// when `GIT_SSH_COMMAND` overrides the program (`git/connect.c`).
fn ssh_invocation(
    login: &str,
    port: Option<u16>,
    service: Service,
    path: &str,
    ssh_program: &str,
    ssh_command: Option<&str>,
) -> SshInvocation {
    let remote = remote_command(service, path);
    match ssh_command {
        Some(command) if !command.is_empty() => {
            let mut line = command.to_owned();
            if let Some(port) = port {
                line.push_str(&format!(" -p {port}"));
            }
            line.push(' ');
            line.push_str(&shell_quote(&login));
            line.push(' ');
            line.push_str(&shell_quote(&remote));
            SshInvocation::Shell(line)
        }
        _ => {
            let mut argv = vec![ssh_program.to_owned()];
            if let Some(port) = port {
                argv.push("-p".to_owned());
                argv.push(port.to_string());
            }
            argv.push(login.to_owned());
            argv.push(remote);
            SshInvocation::Exec(argv)
        }
    }
}

/// One SSH spawn shape.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SshInvocation {
    /// Run `program argv...` directly (no shell).
    Exec(Vec<String>),
    /// Run through `sh -c` (a `GIT_SSH_COMMAND` override).
    Shell(String),
}

/// A live SSH connection: the child's pipes plus the child itself.
pub struct SshStream {
    stdin: ChildStdin,
    stdout: ChildStdout,
    #[allow(dead_code)]
    child: Child,
}

impl Read for SshStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stdout.read(buf)
    }
}

impl Write for SshStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stdin.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stdin.flush()
    }
}

impl Drop for SshStream {
    fn drop(&mut self) {
        // Best-effort reap: killing an exited child is a harmless error,
        // and the wait after it releases the zombie either way.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Opens an SSH `service` stream to `host`, honoring `GIT_SSH_COMMAND`
/// and `GIT_SSH` the way Git does.
///
/// # Errors
/// [`GitError::Io`] when the command cannot spawn.
pub fn ssh_connect(
    host: &str,
    port: Option<u16>,
    user: Option<&str>,
    service: Service,
    path: &str,
) -> Result<SshStream, GitError> {
    let ssh_program = std::env::var("GIT_SSH").unwrap_or_else(|_| "ssh".to_owned());
    let ssh_command = std::env::var("GIT_SSH_COMMAND").ok();
    ssh_connect_with(host, port, user, service, path, &ssh_program, ssh_command.as_deref())
}

/// Builds the `user@host` login, refusing leading dashes: a `-evil` host
/// would otherwise parse as an ssh flag in the spawned argv
/// (`git/connect.c` blocks the same "strange hostname").
///
/// # Errors
/// [`GitError::Invalid`] for an empty or dash-led host or user.
fn ssh_login(host: &str, user: Option<&str>) -> Result<String, GitError> {
    if host.is_empty() || host.starts_with('-') {
        return Err(GitError::Invalid {
            detail: format!("strange hostname {host:?} blocked"),
        });
    }
    if user.is_some_and(|name| name.is_empty() || name.starts_with('-')) {
        return Err(GitError::Invalid {
            detail: "strange ssh user blocked".to_owned(),
        });
    }
    Ok(match user {
        Some(name) => format!("{name}@{host}"),
        None => host.to_owned(),
    })
}

/// Opens an SSH stream with an explicit program and override: the testable
/// half of [`ssh_connect`], which only resolves the environment.
///
/// # Errors
/// [`GitError::Invalid`] for a dash-led host or user, [`GitError::Io`]
/// when the command cannot spawn.
pub fn ssh_connect_with(
    host: &str,
    port: Option<u16>,
    user: Option<&str>,
    service: Service,
    path: &str,
    ssh_program: &str,
    ssh_command: Option<&str>,
) -> Result<SshStream, GitError> {
    let login = ssh_login(host, user)?;
    let what = format!("ssh to {login}");
    let mut command = match ssh_invocation(&login, port, service, path, ssh_program, ssh_command) {
        SshInvocation::Exec(argv) => {
            let mut command = Command::new(&argv[0]);
            command.args(&argv[1..]);
            command
        }
        SshInvocation::Shell(line) => {
            let mut command = Command::new("sh");
            command.arg("-c").arg(&line);
            command
        }
    };
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().map_err(|err| GitError::Io {
        detail: format!("cannot run {what}: {err}"),
    })?;
    let stdin = child.stdin.take().ok_or_else(|| GitError::Io {
        detail: format!("{what} has no stdin pipe"),
    })?;
    let stdout = child.stdout.take().ok_or_else(|| GitError::Io {
        detail: format!("{what} has no stdout pipe"),
    })?;
    Ok(SshStream {
        stdin,
        stdout,
        child,
    })
}

/// Builds the git-daemon request as one pkt-line: 4-hex length prefix
/// around `git-upload-pack <path> NUL host=<host> NUL version=2 NUL`.
/// The daemon reads it with `packet_read_line`, so raw bytes would die on
/// the `git-` "length" (`git/connect.c`, `git_connect_git` via
/// `packet_write`).
fn git_request(service: Service, host: &str, port: Option<u16>, path: &str) -> Vec<u8> {
    let mut body = format!("{} {path}", service.name()).into_bytes();
    body.push(0);
    match port {
        Some(port) => body.extend_from_slice(format!("host={host}:{port}").as_bytes()),
        None => body.extend_from_slice(format!("host={host}").as_bytes()),
    }
    body.push(0);
    body.extend_from_slice(b"version=2");
    body.push(0);
    let mut out = format!("{:04x}", body.len() + 4).into_bytes();
    out.extend_from_slice(&body);
    out
}

/// Dials a git daemon and sends the service request.
///
/// # Errors
/// [`GitError::Io`] when the daemon cannot be reached.
pub fn git_connect(
    host: &str,
    port: Option<u16>,
    service: Service,
    path: &str,
) -> Result<TcpStream, GitError> {
    let stream = TcpStream::connect((host, port.unwrap_or(GIT_DAEMON_PORT))).map_err(|err| {
        GitError::Io {
            detail: format!("cannot reach git://{host}: {err}"),
        }
    })?;
    let request = git_request(service, host, port, path);
    (&stream as &TcpStream)
        .write_all(&request)
        .map_err(|err| GitError::Io {
            detail: format!("cannot request git://{host}: {err}"),
        })?;
    Ok(stream)
}

/// One duplex network stream: SSH child pipes or a daemon socket.
pub enum Stream {
    /// SSH child pipes (reaped on drop).
    Ssh(SshStream),
    /// git-daemon socket.
    Tcp(TcpStream),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Ssh(stream) => stream.read(buf),
            Self::Tcp(stream) => stream.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Ssh(stream) => stream.write(buf),
            Self::Tcp(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Ssh(stream) => stream.flush(),
            Self::Tcp(stream) => stream.flush(),
        }
    }
}

/// Opens one duplex stream to a network endpoint: SSH spawns, git dials.
///
/// # Errors
/// [`GitError::Invalid`] for local or HTTP endpoints (the caller routes
/// those elsewhere), [`GitError::Io`] when the peer cannot be reached.
pub fn open_stream(endpoint: &Endpoint, service: Service) -> Result<Stream, GitError> {
    match endpoint {
        Endpoint::Ssh {
            host,
            port,
            user,
            path,
        } => Ok(Stream::Ssh(ssh_connect(
            host,
            *port,
            user.as_deref(),
            service,
            path,
        )?)),
        Endpoint::Git { host, port, path } => Ok(Stream::Tcp(git_connect(
            host,
            *port,
            service,
            path,
        )?)),
        Endpoint::Local { .. } => Err(GitError::Invalid {
            detail: "local endpoints need no network stream".to_owned(),
        }),
        Endpoint::Http { url, .. } => Err(http_gap(url)),
    }
}

/// Reads one advertisement over an open stream: v0/v1 refs directly, or
/// one `ls-refs` round trip against a v2 server. The stream closes on
/// return, the way `ls-remote` hangs up after discovery.
///
/// # Errors
/// Grammar failures are [`GitError::Corrupt`].
pub fn discover<R: Read + Write>(
    stream: R,
    kind: HashKind,
) -> Result<Vec<AdvertisedRef>, GitError> {
    let mut pkt = PktReader::new(stream, Interrupt::none());
    match refadv::read_initial(&mut pkt, kind)? {
        Initial::Refs(advertisement) => Ok(advertisement.refs),
        Initial::V2(caps) => {
            let request = refadv::ls_refs_request(&caps, kind, &[])?;
            pktline::send(pkt.get_mut(), &request)?;
            refadv::read_ls_refs(&mut pkt, kind)
        }
    }
}

/// Discovers a network endpoint's refs: opens the stream, reads the
/// advertisement, hangs up.
///
/// # Errors
/// Routing errors from [`open_stream`], grammar failures from [`discover`].
pub fn discover_endpoint(
    endpoint: &Endpoint,
    service: Service,
    kind: HashKind,
) -> Result<Vec<AdvertisedRef>, GitError> {
    discover(open_stream(endpoint, service)?, kind)
}

/// Maps wire refs onto local advertisement rows for refspec expansion:
/// direct tips stay direct, symrefs stay symbolic, peeled `^{}` dupes and
/// unborn entries without a target drop out.
///
/// # Errors
/// [`GitError::Invalid`] for a symref target that is not a ref name.
pub fn to_local_refs(refs: Vec<AdvertisedRef>) -> Result<Vec<AdvertisedLocalRef>, GitError> {
    let mut out = Vec::new();
    for entry in refs {
        if entry.name.ends_with(b"^{}") {
            continue;
        }
        let target = match (entry.oid, entry.symref_target) {
            (Some(oid), _) => RefTarget::Direct(oid),
            (None, Some(pointed)) => {
                let name = RefName::new(pointed).map_err(|err| GitError::Invalid {
                    detail: format!("advertised symref target refused: {err}"),
                })?;
                RefTarget::Symbolic(name)
            }
            (None, None) => continue,
        };
        out.push(AdvertisedLocalRef {
            name: entry.name,
            target,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::pktline as pkt;
    use super::*;
    use ruk_core::ids::HashKind;

    fn sha1(hex: &str) -> ruk_core::ids::Oid {
        ruk_core::ids::Oid::from_hex(hex).expect("hex")
    }

    #[test]
    fn parses_local_and_file_endpoints() {
        assert_eq!(
            parse_endpoint("/srv/repos/a").expect("path"),
            Endpoint::Local {
                path: PathBuf::from("/srv/repos/a"),
            }
        );
        assert_eq!(
            parse_endpoint("../relative").expect("relative"),
            Endpoint::Local {
                path: PathBuf::from("../relative"),
            }
        );
        assert_eq!(
            parse_endpoint("file:///srv/repos/a").expect("file url"),
            Endpoint::Local {
                path: PathBuf::from("/srv/repos/a"),
            }
        );
        // A bare colon path without a user stays local.
        assert_eq!(
            parse_endpoint("weird:name").expect("colon path"),
            Endpoint::Local {
                path: PathBuf::from("weird:name"),
            }
        );
        assert!(parse_endpoint("").is_err());
    }

    #[test]
    fn parses_ssh_and_git_endpoints() {
        assert_eq!(
            parse_endpoint("ssh://git@host.x:2222/srv/a.git").expect("ssh url"),
            Endpoint::Ssh {
                host: "host.x".to_owned(),
                port: Some(2222),
                user: Some("git".to_owned()),
                path: "/srv/a.git".to_owned(),
            }
        );
        assert_eq!(
            parse_endpoint("git@host.x:srv/a.git").expect("scp-like"),
            Endpoint::Ssh {
                host: "host.x".to_owned(),
                port: None,
                user: Some("git".to_owned()),
                path: "srv/a.git".to_owned(),
            }
        );
        assert_eq!(
            parse_endpoint("git://host.x:9419/srv/a.git").expect("git url"),
            Endpoint::Git {
                host: "host.x".to_owned(),
                port: Some(9419),
                path: "/srv/a.git".to_owned(),
            }
        );
    }

    #[test]
    fn parses_http_to_the_named_gap() {
        assert_eq!(
            parse_endpoint("https://host.x/a.git").expect("https url"),
            Endpoint::Http {
                secure: true,
                url: "https://host.x/a.git".to_owned(),
            }
        );
        assert!(matches!(
            parse_endpoint("http://host.x/a.git").expect("http url"),
            Endpoint::Http { secure: false, .. }
        ));
        assert!(matches!(
            parse_endpoint("ext::sh -c foo"),
            Err(GitError::Unsupported { .. })
        ));
    }

    #[test]
    fn shell_quotes_paths_safely() {
        assert_eq!(shell_quote("/srv/a.git"), "'/srv/a.git'");
        assert_eq!(shell_quote("-p"), "'-p'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(
            remote_command(Service::UploadPack, "/srv/a.git"),
            "git-upload-pack '/srv/a.git'"
        );
    }

    #[test]
    fn ssh_invocation_honors_env_overrides() {
        assert_eq!(
            ssh_invocation(
                "git@host.x",
                Some(2222),
                Service::UploadPack,
                "/srv/a.git",
                "ssh",
                None,
            ),
            SshInvocation::Exec(vec![
                "ssh".to_owned(),
                "-p".to_owned(),
                "2222".to_owned(),
                "git@host.x".to_owned(),
                "git-upload-pack '/srv/a.git'".to_owned(),
            ])
        );
        assert_eq!(
            ssh_invocation(
                "host.x",
                None,
                Service::ReceivePack,
                "a.git",
                "ssh",
                Some("ssh -i key"),
            ),
            SshInvocation::Shell(
                "ssh -i key 'host.x' 'git-receive-pack '\\''a.git'\\'''".to_owned()
            )
        );
    }

    #[test]
    fn ssh_login_blocks_dash_led_hosts_and_users() {
        assert_eq!(ssh_login("host.x", Some("git")).expect("login"), "git@host.x");
        assert!(matches!(
            ssh_connect_with("-oProxyCommand=evil", None, None, Service::UploadPack, "/x", "ssh", None),
            Err(GitError::Invalid { .. })
        ));
        assert!(matches!(
            ssh_connect_with("host.x", None, Some("-l"), Service::UploadPack, "/x", "ssh", None),
            Err(GitError::Invalid { .. })
        ));
    }

    #[test]
    fn git_request_frames_service_host_and_version() {
        let request = git_request(Service::UploadPack, "host.x", None, "/srv/a.git");
        let len =
            usize::from_str_radix(std::str::from_utf8(&request[..4]).expect("hex"), 16)
                .expect("length");
        assert_eq!(len, request.len());
        assert!(request[4..].starts_with(b"git-upload-pack /srv/a.git\0"));
        assert!(request.ends_with(b"host=host.x\0version=2\0"));
        let request = git_request(Service::ReceivePack, "host.x", Some(9419), "/a");
        let len =
            usize::from_str_radix(std::str::from_utf8(&request[..4]).expect("hex"), 16)
                .expect("length");
        assert_eq!(len, request.len());
        assert!(request.ends_with(b"host=host.x:9419\0version=2\0"));
    }

    fn advertisement_bytes(tip: &str) -> Vec<u8> {
        let mut out = Vec::new();
        pkt::encode_data(
            &mut out,
            format!("{tip} HEAD\0symref=HEAD:refs/heads/main multi_ack\n").as_bytes(),
        )
        .expect("frame");
        pkt::encode_data(
            &mut out,
            format!("{tip} refs/heads/main\n").as_bytes(),
        )
        .expect("frame");
        pkt::encode_flush(&mut out);
        out
    }

    #[test]
    fn discovers_refs_over_a_fake_ssh_command() {
        // The spawn half is real (env override, pipes, duplex read); only
        // the far end is a script serving a canned advertisement.
        let dir = std::env::temp_dir().join(format!(
            "ruk-net-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch");
        let tip = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";
        std::fs::write(dir.join("adv.bin"), advertisement_bytes(tip)).expect("canned");
        let script = dir.join("fake-ssh.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\ncat \"{}\"\n", dir.join("adv.bin").display()),
        )
        .expect("script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script).expect("meta").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).expect("chmod");
        }
        let stream = ssh_connect_with(
            "far.test",
            None,
            None,
            Service::UploadPack,
            "/srv/a.git",
            "ssh",
            Some(script.to_str().expect("utf8")),
        )
        .expect("spawn");
        let refs = to_local_refs(discover(stream, HashKind::Sha1).expect("discover")).expect("map");
        assert!(refs.iter().any(|entry| entry.name == b"refs/heads/main"
            && entry.target == RefTarget::Direct(sha1(tip))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn git_daemon_handshake_serves_discovery() {
        use std::io::Write as _;
        let tip = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";
        let listener =
            std::net::TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let request = read_git_request(&socket);
            assert!(request.starts_with(b"git-upload-pack /srv/a.git\0"));
            assert!(request.windows(5).any(|w| w == b"host="));
            socket
                .write_all(&advertisement_bytes(tip))
                .expect("advertisement");
        });
        let endpoint = Endpoint::Git {
            host: "127.0.0.1".to_owned(),
            port: Some(port),
            path: "/srv/a.git".to_owned(),
        };
        let refs = to_local_refs(
            discover_endpoint(&endpoint, Service::UploadPack, HashKind::Sha1).expect("discover"),
        )
        .expect("map");
        assert!(refs.iter().any(|entry| entry.name == b"refs/heads/main"));
        server.join().expect("server");
    }

    use super::super::fetch;
    use super::super::pack::IngestLimits;
    use super::super::serve::{HeadAdvertisement, serve_receive_pack, serve_upload_pack};
    use super::super::session::test_support::{store_with_pack, test_store};
    use ruk_core::LfsMode;
    use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTransaction, RefUpdate};
    use ruk_core::refs::prepare_checked_transaction;

    const FOUR: &str = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";

    fn set_ref(store: &ruk_core::store::Store, kind: HashKind, name: &[u8], target: &str) {
        let update = RefUpdate {
            expected: RefExpect::Absent,
            change: RefChange::Set(RefTarget::Direct(sha1(target))),
            name: RefName::new(name.to_vec()).expect("ref name"),
        };
        let transaction = RefTransaction::new(kind, vec![update]).expect("transaction");
        let prepared = prepare_checked_transaction(store, &transaction).expect("prepare");
        store
            .publish(Vec::new(), &prepared.into_mutations())
            .expect("publish ref");
    }

    fn loopback() -> (std::net::TcpListener, u16) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("loopback");
        let port = listener.local_addr().expect("addr").port();
        (listener, port)
    }

    /// Reads one pkt-line-framed git-daemon request the way the daemon
    /// consumes it before the service sees the stream; returns the body
    /// past the length prefix.
    fn read_git_request(socket: &std::net::TcpStream) -> Vec<u8> {
        use std::io::Read as _;
        let mut stream = socket;
        let mut prefix = [0u8; 4];
        stream.read_exact(&mut prefix).expect("length prefix");
        let len = usize::from_str_radix(std::str::from_utf8(&prefix).expect("hex"), 16)
            .expect("length");
        let mut body = vec![0u8; len - 4];
        stream.read_exact(&mut body).expect("request body");
        body
    }

    #[test]
    fn fetch_pack_flows_over_a_daemon_socket() {
        // Client and server speak the real protocol over a real socket:
        // dial + handshake, advertisement, wants, pack, verify, publish.
        let kind = HashKind::Sha1;
        let server_store = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        set_ref(&server_store, kind, b"refs/heads/main", FOUR);
        let head = HeadAdvertisement {
            oid: sha1(FOUR),
            symref: Some(b"refs/heads/main".to_vec()),
        };
        let (listener, port) = loopback();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().expect("accept");
            let request = read_git_request(&socket);
            assert!(request.starts_with(b"git-upload-pack /srv/a.git\0"));
            let reader = socket.try_clone().expect("split");
            serve_upload_pack(reader, socket, &server_store, kind, &head, &Interrupt::none())
                .expect("serve");
        });
        let dest = test_store(kind);
        let stream = git_connect("127.0.0.1", Some(port), Service::UploadPack, "/srv/a.git")
            .expect("dial");
        let request = fetch::FetchWireRequest {
            wants: vec![sha1(FOUR)],
            haves: Vec::new(),
            filter: None,
            depth: None,
            shallow: Vec::new(),
            list_refs: false,
            ref_prefixes: Vec::new(),
        };
        let received =
            fetch::receive(stream, kind, &dest, &request, IngestLimits::default(), &Interrupt::none())
                .expect("receive");
        let report = fetch::verify_closure(
            &dest,
            &received.staged,
            &[sha1(FOUR)],
            None,
            &received.shallow,
            &Interrupt::none(),
        )
        .expect("verify");
        assert_eq!(report.wanted, vec![sha1(FOUR)]);
        fetch::publish_fetch(&dest, received.staged, &[]).expect("publish");
        assert!(dest.read(sha1(FOUR)).is_ok());
        server.join().expect("server");
    }

    #[test]
    fn push_updates_land_over_a_daemon_socket() {
        use ruk_core::change::PlanId;
        use super::super::push::{PushPlanRecord, PushUpdate, PushWireRequest, push_over};
        use super::super::push::{PushState, RefResult};

        let kind = HashKind::Sha1;
        let client = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let server_store = test_store(kind);
        let head = HeadAdvertisement {
            oid: kind.zero_oid(),
            symref: None,
        };
        let (listener, port) = loopback();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().expect("accept");
            let request = read_git_request(&socket);
            assert!(request.starts_with(b"git-receive-pack /srv/a.git\0"));
            let reader = socket.try_clone().expect("split");
            serve_receive_pack(
                reader,
                socket,
                &server_store,
                kind,
                &head,
                &Interrupt::none(),
                LfsMode::Deny,
            )
            .expect("serve");
            assert!(
                server_store
                    .fact(ruk_core::store::types::FactTable::Refs, b"refs/heads/main",)
                    .expect("read")
                    .is_some(),
                "ref published on the server"
            );
        });
        let updates = vec![PushUpdate {
            name: b"refs/heads/main".to_vec(),
            old: kind.zero_oid(),
            new: sha1(FOUR),
        }];
        let request = PushWireRequest {
            updates: updates.clone(),
            atomic: false,
        };
        let mut plan = PushPlanRecord::prepare(PlanId::generate(), b"peer".to_vec(), false, updates);
        let stream = git_connect("127.0.0.1", Some(port), Service::ReceivePack, "/srv/a.git")
            .expect("dial");
        let outcomes =
            push_over(stream, &client, kind, &mut plan, &request, &Interrupt::none())
                .expect("push");
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].result, RefResult::Ok);
        assert_eq!(plan.state, PushState::Confirmed);
        server.join().expect("server");
    }

    #[test]
    fn maps_wire_refs_skipping_peeled_and_unborn() {
        let tip = sha1("b7ee0f83149b8f52744bf4de0bc706afcd5302c8");
        let refs = to_local_refs(vec![
            AdvertisedRef {
                name: b"refs/heads/main".to_vec(),
                oid: Some(tip),
                peeled: None,
                symref_target: None,
            },
            AdvertisedRef {
                name: b"refs/tags/v1^{}".to_vec(),
                oid: Some(tip),
                peeled: Some(tip),
                symref_target: None,
            },
            AdvertisedRef {
                name: b"HEAD".to_vec(),
                oid: None,
                peeled: None,
                symref_target: Some(b"refs/heads/main".to_vec()),
            },
            AdvertisedRef {
                name: b"refs/heads/empty".to_vec(),
                oid: None,
                peeled: None,
                symref_target: None,
            },
        ])
        .expect("map");
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].target, RefTarget::Direct(tip));
    }
}
