use std::num::NonZeroU16;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use ruk_core::protocol::PushSshIdentity;
use tokio::io::AsyncReadExt as _;

use super::{EgressPolicy, Endpoint, SshDial, SshInvocation, pinned_dial, resolve_addrs};
use crate::GitError;
use crate::transport::Interrupt;
use crate::transport::session::Service;

const PROBE_BYTES: u64 = 64 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// A push endpoint whose SSH user and port no longer depend on ambient configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenPushDestination {
    /// Parsed endpoint with every SSH user and port supplied explicitly.
    pub endpoint: Endpoint,
    /// The identity persisted with the original remote spelling.
    pub ssh_identity: Option<PushSshIdentity>,
}

/// Resolves SSH settings before any push guard or durable plan is created.
/// Run this blocking operation outside an asynchronous executor worker.
///
/// # Errors
/// Invalid configuration, unsupported SSH commands, cancellation, and bounded probe failures.
pub fn freeze_push_destination(
    remote: &str,
    policy: &EgressPolicy,
    interrupt: &Interrupt,
) -> Result<FrozenPushDestination, GitError> {
    let mut endpoint = super::parse_endpoint(remote)?;
    let ssh_identity = resolve_identity(&endpoint, policy, interrupt)?;
    apply_identity(&mut endpoint, ssh_identity.as_ref())?;
    Ok(FrozenPushDestination {
        endpoint,
        ssh_identity,
    })
}

/// Reconstructs an endpoint using the settings recorded before the original push.
///
/// # Errors
/// Invalid or missing SSH identity, or an identity attached to another transport.
pub fn restore_push_destination(
    remote: &str,
    identity: Option<&PushSshIdentity>,
) -> Result<Endpoint, GitError> {
    let mut endpoint = super::parse_endpoint(remote)?;
    apply_identity(&mut endpoint, identity)?;
    Ok(endpoint)
}

fn apply_identity(
    endpoint: &mut Endpoint,
    identity: Option<&PushSshIdentity>,
) -> Result<(), GitError> {
    match (endpoint, identity) {
        (
            Endpoint::Ssh {
                host, port, user, ..
            },
            Some(identity),
        ) => {
            super::ssh_login(host, Some(&identity.user))?;
            validate_identity(identity)?;
            if port.is_some_and(|port| port != identity.port.get())
                || user.as_ref().is_some_and(|user| user != &identity.user)
            {
                return Err(GitError::Invalid {
                    detail: "frozen SSH identity disagrees with the explicit destination"
                        .to_owned(),
                });
            }
            *port = Some(identity.port.get());
            *user = Some(identity.user.clone());
            Ok(())
        }
        (Endpoint::Ssh { .. }, None) => Err(GitError::Invalid {
            detail: "push destination has no frozen SSH user and port".to_owned(),
        }),
        (_, Some(_)) => Err(GitError::Invalid {
            detail: "SSH identity is only valid for an SSH destination".to_owned(),
        }),
        (_, None) => Ok(()),
    }
}

fn validate_identity(identity: &PushSshIdentity) -> Result<(), GitError> {
    if identity.user.is_empty()
        || identity.user.len() > 1024
        || identity.user.starts_with('-')
        || identity.user.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(GitError::Invalid {
            detail: "SSH configuration carries an invalid user".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn explicit_identity(endpoint: &Endpoint) -> Result<Option<PushSshIdentity>, GitError> {
    let Endpoint::Ssh {
        port: Some(port),
        user: Some(user),
        ..
    } = endpoint
    else {
        return Ok(None);
    };
    let identity = PushSshIdentity {
        user: user.clone(),
        port: NonZeroU16::new(*port).ok_or_else(|| GitError::Invalid {
            detail: "SSH destination port must be nonzero".to_owned(),
        })?,
    };
    validate_identity(&identity)?;
    Ok(Some(identity))
}

fn resolve_identity(
    endpoint: &Endpoint,
    policy: &EgressPolicy,
    interrupt: &Interrupt,
) -> Result<Option<PushSshIdentity>, GitError> {
    let program = std::env::var("GIT_SSH").unwrap_or_else(|_| "ssh".to_owned());
    let command = std::env::var("GIT_SSH_COMMAND").ok();
    let variant = std::env::var("GIT_SSH_VARIANT").ok();
    resolve_identity_with(
        endpoint,
        policy,
        interrupt,
        &program,
        command.as_deref(),
        variant.as_deref(),
    )
}

fn resolve_identity_with(
    endpoint: &Endpoint,
    policy: &EgressPolicy,
    interrupt: &Interrupt,
    program: &str,
    command: Option<&str>,
    variant: Option<&str>,
) -> Result<Option<PushSshIdentity>, GitError> {
    let Endpoint::Ssh {
        host,
        port,
        user,
        path,
    } = endpoint
    else {
        return Ok(None);
    };
    interrupt.check("resolving the push SSH identity")?;
    super::ssh_login(host, user.as_deref())?;
    check_push_client(program, command, variant)?;
    if let Some(identity) = explicit_identity(endpoint)? {
        return Ok(Some(identity));
    }
    let label = format!("ssh://{host}");
    let resolved = resolve_addrs(&label, host, port.unwrap_or(22))?;
    let allowed = policy.filter_addrs(&label, &resolved)?;
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let mut identity = None;
    for addr in allowed {
        interrupt.check("resolving the push SSH identity")?;
        let dial = pinned_dial(
            &addr,
            host,
            *port,
            user.as_deref(),
            Service::ReceivePack,
            path,
        )?;
        let invocation = probe_invocation(&dial, program, command);
        let output = run_probe(invocation, deadline, interrupt)?;
        let next = parse_identity(&output)?;
        if identity.as_ref().is_some_and(|identity| identity != &next) {
            return Err(GitError::Invalid {
                detail: "SSH configuration selects different users or ports across destination addresses; provide both explicitly".to_owned(),
            });
        }
        identity = Some(next);
    }
    Ok(Some(
        identity.expect("egress policy returned at least one address"),
    ))
}

pub(super) fn check_push_client(
    program: &str,
    command: Option<&str>,
    variant: Option<&str>,
) -> Result<(), GitError> {
    if variant.is_some_and(|variant| !matches!(variant, "" | "auto" | "ssh")) {
        return Err(unsupported_probe());
    }
    let words = openssh_words(program, command)?;
    push_options(&words[1..]).map(|_| ())
}

fn unsupported_probe() -> GitError {
    GitError::Unsupported {
        command: "push SSH requires a direct OpenSSH command with supported options and literal arguments or ~/ paths".to_owned(),
    }
}

fn openssh_words(program: &str, command: Option<&str>) -> Result<Vec<String>, GitError> {
    let home = std::env::var("HOME").ok();
    openssh_words_with_home(program, command, home.as_deref())
}

fn openssh_words_with_home(
    program: &str,
    command: Option<&str>,
    home: Option<&str>,
) -> Result<Vec<String>, GitError> {
    let mut words = if let Some(command) = command.filter(|command| !command.is_empty()) {
        if command.bytes().any(|byte| {
            matches!(
                byte,
                b'\0'
                    | b'\n'
                    | b'\r'
                    | b'$'
                    | b'\x60'
                    | b';'
                    | b'&'
                    | b'|'
                    | b'<'
                    | b'>'
                    | b'#'
                    | b'*'
                    | b'?'
            )
        }) {
            return Err(unsupported_probe());
        }
        shlex::split(&expand_command_home(command, home)?).ok_or_else(unsupported_probe)?
    } else {
        vec![program.to_owned()]
    };
    if words.first().is_some_and(|word| word == "exec") {
        words.remove(0);
    }
    let program = words.first().ok_or_else(unsupported_probe)?;
    let name = Path::new(program)
        .file_name()
        .and_then(|name| name.to_str());
    if !name.is_some_and(|name| name == "ssh" || name.eq_ignore_ascii_case("ssh.exe")) {
        return Err(unsupported_probe());
    }
    Ok(words)
}

#[derive(Clone, Copy)]
enum ShellQuote {
    Unquoted,
    Single,
    Double,
}

fn expand_command_home(command: &str, home: Option<&str>) -> Result<String, GitError> {
    let mut expanded = String::with_capacity(command.len());
    let mut chars = command.chars().peekable();
    let mut quote = ShellQuote::Unquoted;
    let mut escaped = false;
    let mut word_start = true;
    while let Some(ch) = chars.next() {
        if escaped {
            expanded.push(ch);
            escaped = false;
            continue;
        }
        match (quote, ch) {
            (ShellQuote::Single, '\'') => quote = ShellQuote::Unquoted,
            (ShellQuote::Single, _) => {}
            (ShellQuote::Double, '"') => quote = ShellQuote::Unquoted,
            (ShellQuote::Double, '\\') => escaped = true,
            (ShellQuote::Double, _) => {}
            (ShellQuote::Unquoted, '\\') => {
                escaped = true;
                word_start = false;
            }
            (ShellQuote::Unquoted, '\'') => {
                quote = ShellQuote::Single;
                word_start = false;
            }
            (ShellQuote::Unquoted, '"') => {
                quote = ShellQuote::Double;
                word_start = false;
            }
            (ShellQuote::Unquoted, ch) if ch.is_ascii_whitespace() => word_start = true,
            (ShellQuote::Unquoted, '~') if word_start => {
                let next = chars.peek().copied();
                if next.is_none_or(|ch| ch == '/' || ch.is_ascii_whitespace()) {
                    if let Some(home) = home.filter(|home| !home.is_empty()) {
                        expanded.push_str(&super::shell_quote(home));
                        word_start = false;
                        continue;
                    }
                } else if !matches!(next, Some('\'' | '"' | '\\')) {
                    return Err(unsupported_probe());
                }
                word_start = false;
            }
            (ShellQuote::Unquoted, _) => word_start = false,
        }
        expanded.push(ch);
    }
    Ok(expanded)
}

fn push_options(words: &[String]) -> Result<Vec<String>, GitError> {
    let mut options = Vec::with_capacity(words.len());
    let mut index = 0;
    while let Some(word) = words.get(index) {
        let flags = word.strip_prefix('-').ok_or_else(unsupported_probe)?;
        if flags.is_empty() || flags == "-" {
            return Err(unsupported_probe());
        }
        for (offset, flag) in flags.char_indices() {
            if "BDEFIJLPRSbceilmopw".contains(flag) {
                let attached = &flags[offset + flag.len_utf8()..];
                let value = if attached.is_empty() {
                    index += 1;
                    words.get(index).ok_or_else(unsupported_probe)?.as_str()
                } else {
                    attached
                };
                if flag != 'S' {
                    options.extend([format!("-{flag}"), value.to_owned()]);
                }
                break;
            }
            if !"246ACKMTXYagkqvxy".contains(flag) {
                return Err(unsupported_probe());
            }
            if flag != 'M' {
                options.push(format!("-{flag}"));
            }
        }
        index += 1;
    }
    Ok(options)
}

pub(super) fn disable_connection_sharing(argv: &mut Vec<String>) {
    argv.extend(
        [
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ControlPersist=no",
            "-S",
            "none",
        ]
        .map(str::to_owned),
    );
}

pub(super) fn pinned_openssh_command(
    dial: &SshDial<'_>,
    command: &str,
) -> Result<Vec<String>, GitError> {
    let mut words = openssh_words("ssh", Some(command))?;
    let mut flags = words.split_off(1);
    if matches!(dial.service, Service::ReceivePack) {
        flags = push_options(&flags)?;
        disable_connection_sharing(&mut words);
    }
    if let Some(port) = dial.port {
        words.extend(["-p".to_owned(), port.to_string()]);
    }
    if let Some((user, _)) = dial.login.rsplit_once('@') {
        words.extend(["-l".to_owned(), user.to_owned()]);
    }
    if let Some(alias) = dial.host_key_alias {
        words.extend(["-o".to_owned(), format!("HostKeyAlias={alias}")]);
    }
    if let Some(ip) = dial.pinned_ip {
        words.extend(["-o".to_owned(), format!("Hostname={ip}")]);
    }
    words.extend(flags);
    Ok(words)
}

fn probe_invocation(dial: &SshDial<'_>, program: &str, command: Option<&str>) -> SshInvocation {
    let mut argv = if let Some(command) = command.filter(|command| !command.is_empty()) {
        pinned_openssh_command(dial, command).expect("probe command was validated")
    } else {
        let mut argv = vec![program.to_owned()];
        disable_connection_sharing(&mut argv);
        if let Some(port) = dial.port {
            argv.extend(["-p".to_owned(), port.to_string()]);
        }
        if let Some(alias) = dial.host_key_alias {
            argv.extend(["-o".to_owned(), format!("HostKeyAlias={alias}")]);
        }
        if let Some(ip) = dial.pinned_ip {
            argv.extend(["-o".to_owned(), format!("Hostname={ip}")]);
        }
        argv
    };
    argv.insert(1, "-G".to_owned());
    argv.push(dial.login.clone());
    SshInvocation::Exec(argv)
}

fn parse_identity(bytes: &[u8]) -> Result<PushSshIdentity, GitError> {
    let invalid = || GitError::Invalid {
        detail: "SSH configuration probe did not return one valid user and port".to_owned(),
    };
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let mut user = None;
    let mut port = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        match key {
            "user" => {
                if user.replace(value.to_owned()).is_some() {
                    return Err(invalid());
                }
            }
            "port" => {
                if port.is_some()
                    || value.is_empty()
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(invalid());
                }
                port = Some(value.parse::<NonZeroU16>().map_err(|_| invalid())?);
            }
            _ => {}
        }
    }
    let identity = PushSshIdentity {
        user: user.ok_or_else(invalid)?,
        port: port.ok_or_else(invalid)?,
    };
    validate_identity(&identity)?;
    Ok(identity)
}

fn run_probe(
    invocation: SshInvocation,
    deadline: Instant,
    interrupt: &Interrupt,
) -> Result<Vec<u8>, GitError> {
    interrupt.check("resolving the push SSH identity")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| GitError::Io {
            detail: format!("cannot start SSH configuration probe: {err}"),
        })?;
    runtime.block_on(async {
        let mut command = match invocation {
            SshInvocation::Exec(argv) => {
                let mut command = tokio::process::Command::new(&argv[0]);
                command.args(&argv[1..]);
                command
            }
            SshInvocation::Shell(line) => {
                let mut command = tokio::process::Command::new("sh");
                command.arg("-c").arg(line);
                command
            }
        };
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| GitError::Io {
                detail: format!("cannot start SSH configuration probe: {err}"),
            })?;
        #[cfg(unix)]
        let group = rustix::process::Pid::from_raw(
            i32::try_from(child.id().expect("spawned process ID"))
                .expect("Unix process ID fits a signed integer"),
        )
        .expect("spawned process ID is nonzero");
        let stdout = child.stdout.take().expect("probe stdout was piped");
        let mut poll = tokio::time::interval(Duration::from_millis(10));
        let result = {
            let work = async {
                let mut output = Vec::new();
                stdout
                    .take(PROBE_BYTES + 1)
                    .read_to_end(&mut output)
                    .await
                    .map_err(|err| GitError::Io {
                        detail: format!("cannot read SSH configuration probe: {err}"),
                    })?;
                if output.len() as u64 > PROBE_BYTES {
                    return Err(GitError::Limit {
                        detail: "SSH configuration probe exceeds 64 KiB".to_owned(),
                    });
                }
                let status = child.wait().await.map_err(|err| GitError::Io {
                    detail: format!("cannot wait for SSH configuration probe: {err}"),
                })?;
                if !status.success() {
                    return Err(GitError::Invalid {
                        detail: "SSH configuration probe failed".to_owned(),
                    });
                }
                Ok(output)
            };
            tokio::pin!(work);
            loop {
                tokio::select! {
                    result = &mut work => break result,
                    _ = poll.tick() => {
                        if let Err(err) = interrupt.check("resolving the push SSH identity") {
                            break Err(err);
                        }
                    }
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                        break Err(GitError::Io {
                            detail: "SSH configuration probe exceeded its deadline".to_owned(),
                        });
                    }
                }
            }
        };
        if result.is_err() {
            #[cfg(unix)]
            {
                let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            }
            let _ = child.kill().await;
        }
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(user: &str, port: u16) -> PushSshIdentity {
        PushSshIdentity {
            user: user.to_owned(),
            port: NonZeroU16::new(port).expect("nonzero port"),
        }
    }

    #[test]
    fn frozen_identity_preserves_relative_paths_and_original_host_alias() {
        let expected = identity("alice", 2222);
        for (remote, path) in [
            ("alice@HostAlias:relative/repo.git", "relative/repo.git"),
            ("ssh://HostAlias/absolute/repo.git", "/absolute/repo.git"),
            ("ssh://alice@[2001:db8::1]:2222/repo.git", "/repo.git"),
        ] {
            let before = super::super::parse_endpoint(remote).expect("endpoint");
            let Endpoint::Ssh {
                host: before_host, ..
            } = before
            else {
                panic!("SSH endpoint");
            };
            let restored =
                restore_push_destination(remote, Some(&expected)).expect("identity applies");
            let Endpoint::Ssh {
                host,
                user,
                port,
                path: actual,
            } = restored
            else {
                panic!("SSH endpoint");
            };
            assert_eq!(host, before_host);
            assert_eq!(port, Some(2222));
            assert_eq!(user.as_deref(), Some("alice"));
            assert_eq!(actual, path);
        }
        assert!(restore_push_destination("alice@host:relative.git", None).is_err());
        assert!(restore_push_destination("ssh://bob@host/repo.git", Some(&expected)).is_err());
        assert!(restore_push_destination("ssh://alice@host:22/repo.git", Some(&expected)).is_err());
        assert!(restore_push_destination("https://host/repo.git", Some(&expected)).is_err());
        assert!(restore_push_destination("https://host/repo.git", None).is_ok());
    }

    #[test]
    fn configuration_output_requires_one_valid_user_and_port() {
        assert_eq!(
            parse_identity(b"host alias\nuser alice\nport 2222\nhostname 127.0.0.1\n")
                .expect("settings"),
            identity("alice", 2222),
        );
        for output in [
            b"user alice\n".as_slice(),
            b"port 22\n".as_slice(),
            b"user alice\nuser bob\nport 22\n".as_slice(),
            b"user alice\nport 22\nport 2222\n".as_slice(),
            b"user alice\nport 0\n".as_slice(),
            b"user alice\nport 65536\n".as_slice(),
            b"user alice\nport +22\n".as_slice(),
            b"user \nport 22\n".as_slice(),
            b"user -option\nport 22\n".as_slice(),
            b"user ali\0ce\nport 22\n".as_slice(),
            b"user \xff\nport 22\n".as_slice(),
        ] {
            assert!(parse_identity(output).is_err(), "{output:?}");
        }
    }

    #[test]
    fn only_recognized_ssh_commands_are_probed() {
        for (program, command, variant) in [
            ("ssh", None, None),
            ("ssh", None, Some("auto")),
            ("/usr/bin/ssh", None, Some("ssh")),
            ("ignored", Some("ssh -F '/tmp/config with spaces'"), None),
            ("ignored", Some("exec /usr/bin/ssh -i /tmp/key"), None),
        ] {
            check_push_client(program, command, variant).expect("recognized OpenSSH command");
        }
        for (program, command, variant) in [
            ("plink", None, None),
            ("plink", None, Some("auto")),
            ("custom-wrapper", None, Some("ssh")),
            ("ssh", None, Some("simple")),
            ("ignored", Some("sh /tmp/custom-ssh"), None),
            ("ignored", Some("ssh -F $CONFIG"), None),
            ("ignored", Some("ssh; other-command"), None),
            ("ignored", Some("ssh # comment"), None),
        ] {
            assert!(matches!(
                check_push_client(program, command, variant),
                Err(GitError::Unsupported { .. }),
            ));
        }
    }

    #[test]
    fn command_prefixes_cannot_replace_the_destination_or_hide_pin_flags() {
        for command in [
            "ssh other-host",
            "ssh --",
            "ssh -",
            "ssh -F",
            "ssh -vM -S",
            "ssh -9",
            "ssh -W other-host:22",
            "ssh -G",
            "ssh -Q cipher",
            "ssh -O check",
            "ssh -N",
            "ssh -V",
            "ssh -Z",
            "ssh -f",
            "ssh -n",
            "ssh -s",
            "ssh -tt",
        ] {
            assert!(
                matches!(
                    check_push_client("ssh", Some(command), Some("auto")),
                    Err(GitError::Unsupported { .. }),
                ),
                "{command}"
            );
        }
    }

    #[test]
    fn command_home_expansion_preserves_shell_quoting() {
        let home = "/tmp/home with ' quote";
        for (command, expected) in [
            ("ssh -F ~/.ssh/work", format!("{home}/.ssh/work")),
            ("ssh -F '~/.ssh/work'", "~/.ssh/work".to_owned()),
            ("ssh -F \"~/.ssh/work\"", "~/.ssh/work".to_owned()),
            ("ssh -F \\~/.ssh/work", "~/.ssh/work".to_owned()),
            ("ssh -F ~/'ssh config'", format!("{home}/ssh config")),
            ("ssh -F ~\"/ssh config\"", "~/ssh config".to_owned()),
            ("ssh -F ~", home.to_owned()),
        ] {
            let words = openssh_words_with_home("ssh", Some(command), Some(home))
                .expect("supported home expansion");
            assert_eq!(words, vec!["ssh".to_owned(), "-F".to_owned(), expected]);
        }
        assert!(
            openssh_words_with_home("ssh", Some("ssh -F ~another/config"), Some(home)).is_err()
        );
        assert_eq!(
            openssh_words_with_home("ssh", Some("ssh -F '~another/config'"), Some(home))
                .expect("quoted user prefix stays literal"),
            vec!["ssh", "-F", "~another/config"],
        );
        assert_eq!(
            openssh_words_with_home("ssh", Some("ssh -F~/.ssh/work"), Some(home))
                .expect("tilde inside an argument stays literal"),
            vec!["ssh", "-F~/.ssh/work"],
        );
    }

    #[test]
    fn command_home_expansion_defers_to_openssh_without_home() {
        for home in [None, Some("")] {
            for (command, expected) in [
                ("ssh -i ~/.ssh/work", vec!["-i", "~/.ssh/work"]),
                ("ssh -i~/.ssh/work", vec!["-i", "~/.ssh/work"]),
                ("ssh -F ~/.ssh/config", vec!["-F", "~/.ssh/config"]),
                ("ssh -F~/.ssh/config", vec!["-F", "~/.ssh/config"]),
                (
                    "ssh -o IdentityFile=~/.ssh/work",
                    vec!["-o", "IdentityFile=~/.ssh/work"],
                ),
                (
                    "ssh -oIdentityFile=~/.ssh/work",
                    vec!["-o", "IdentityFile=~/.ssh/work"],
                ),
            ] {
                let words = openssh_words_with_home("ssh", Some(command), home)
                    .expect("OpenSSH receives its original path syntax");
                assert_eq!(
                    push_options(&words[1..]).expect("supported options"),
                    expected
                );
            }
        }
    }

    #[test]
    fn probe_has_pinned_configuration_arguments_without_remote_command() {
        let addr = "127.0.0.1:22".parse().expect("address");
        let dial = pinned_dial(
            &addr,
            "HostAlias",
            None,
            None,
            Service::ReceivePack,
            "relative/repo.git",
        )
        .expect("dial");
        assert_eq!(
            probe_invocation(&dial, "ssh", None),
            SshInvocation::Exec(vec![
                "ssh".to_owned(),
                "-G".to_owned(),
                "-o".to_owned(),
                "ControlMaster=no".to_owned(),
                "-o".to_owned(),
                "ControlPath=none".to_owned(),
                "-o".to_owned(),
                "ControlPersist=no".to_owned(),
                "-S".to_owned(),
                "none".to_owned(),
                "-o".to_owned(),
                "HostKeyAlias=HostAlias".to_owned(),
                "-o".to_owned(),
                "Hostname=127.0.0.1".to_owned(),
                "HostAlias".to_owned(),
            ]),
        );
    }

    #[test]
    fn fully_explicit_identity_needs_neither_probe_nor_dns() {
        let endpoint = super::super::parse_endpoint("ssh://alice@invalid.invalid:2222/repo.git")
            .expect("endpoint");
        let actual = resolve_identity_with(
            &endpoint,
            &EgressPolicy::deny_private(),
            &Interrupt::none(),
            "/missing/path/ssh",
            None,
            None,
        )
        .expect("explicit settings require neither probe nor DNS");
        assert_eq!(actual, Some(identity("alice", 2222)));
    }

    #[test]
    fn explicit_identity_rejects_commands_that_could_override_pinned_options() {
        let endpoint = super::super::parse_endpoint("ssh://alice@invalid.invalid:22/repo.git")
            .expect("endpoint");
        for (program, command, variant) in [
            ("ssh", Some("ssh -p 2222 -l bob -F \"$CONFIG\""), None),
            ("custom-client", None, None),
            ("ssh", None, Some("simple")),
        ] {
            let result = resolve_identity_with(
                &endpoint,
                &EgressPolicy::deny_private(),
                &Interrupt::none(),
                program,
                command,
                variant,
            );
            assert!(matches!(result, Err(GitError::Unsupported { .. })));
        }
    }

    #[cfg(unix)]
    #[test]
    fn openssh_config_freezes_default_and_custom_ports_without_crossing_targets() {
        let root = std::env::temp_dir().join(format!(
            "ruk-ssh-identity-{}",
            ruk_core::change::PlanId::generate(),
        ));
        std::fs::create_dir_all(&root).expect("scratch directory");
        let config = root.join("ssh config");
        for port in [22, 2222] {
            std::fs::write(
                &config,
                format!(
                    "Host 127.0.0.1\n  Port {port}\n  User alice\n  HostName ignored.invalid\n"
                ),
            )
            .expect("configuration");
            let command = format!(
                "ssh -F {}",
                super::super::shell_quote(config.to_str().expect("UTF-8 test path")),
            );
            let resolve = |remote: &str| {
                let endpoint = super::super::parse_endpoint(remote).expect("endpoint");
                resolve_identity_with(
                    &endpoint,
                    &EgressPolicy::deny_private().allow_loopback(),
                    &Interrupt::none(),
                    "ssh",
                    Some(&command),
                    None,
                )
                .expect("OpenSSH prints configuration without connecting")
                .expect("SSH identity")
            };
            let implicit = resolve("ssh://127.0.0.1/absolute/repo.git");
            assert_eq!(implicit, identity("alice", port));
            assert_eq!(
                implicit,
                resolve(&format!("ssh://alice@127.0.0.1:{port}/absolute/repo.git")),
            );
            assert_eq!(implicit, resolve("alice@127.0.0.1:relative/repo.git"));
            let explicit_default = resolve("ssh://alice@127.0.0.1:22/absolute/repo.git");
            assert_eq!(implicit == explicit_default, port == 22);
            assert_ne!(
                implicit,
                resolve("ssh://bob@127.0.0.1:22/absolute/repo.git")
            );
        }
        std::fs::remove_dir_all(root).expect("scratch cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn configuration_probe_bounds_output_deadline_and_cancellation() {
        let run = |script: &str, timeout: Duration, interrupt: &Interrupt| {
            run_probe(
                SshInvocation::Exec(vec!["sh".to_owned(), "-c".to_owned(), script.to_owned()]),
                Instant::now() + timeout,
                interrupt,
            )
        };
        assert!(matches!(
            run(
                "exec dd if=/dev/zero bs=65537 count=1 2>/dev/null",
                Duration::from_secs(2),
                &Interrupt::none(),
            ),
            Err(GitError::Limit { .. }),
        ));
        assert!(matches!(
            run("exit 9", Duration::from_secs(2), &Interrupt::none()),
            Err(GitError::Invalid { .. }),
        ));
        let started = Instant::now();
        assert!(matches!(
            run(
                "exec sleep 10",
                Duration::from_millis(30),
                &Interrupt::none()
            ),
            Err(GitError::Io { .. }),
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let interrupt = Interrupt::none().with_cancel(std::sync::Arc::clone(&cancel));
        let setter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        assert!(matches!(
            run("exec sleep 10", Duration::from_secs(2), &interrupt),
            Err(GitError::Cancelled { .. }),
        ));
        setter.join().expect("cancellation thread");
    }
    #[cfg(unix)]
    #[test]
    fn frozen_identity_overrides_command_options_and_later_config_changes() {
        let root = std::env::temp_dir().join(format!(
            "ruk-ssh-frozen-command-{}",
            ruk_core::change::PlanId::generate(),
        ));
        std::fs::create_dir_all(&root).expect("scratch directory");
        let config = root.join("config");
        std::fs::write(&config, "Host *\n  User alice\n  Port 2222\n")
            .expect("original configuration");
        let config_flag = format!(
            "-F {}",
            super::super::shell_quote(config.to_str().expect("UTF-8 path")),
        );
        let command = format!("ssh {config_flag}");
        let original = super::super::parse_endpoint("ssh://127.0.0.1/relative.git")
            .expect("original endpoint");
        let frozen = resolve_identity_with(
            &original,
            &EgressPolicy::deny_private().allow_loopback(),
            &Interrupt::none(),
            "ssh",
            Some(&command),
            None,
        )
        .expect("original settings")
        .expect("SSH identity");
        assert_eq!(frozen, identity("alice", 2222));
        std::fs::write(&config, "Host *\n  User bob\n  Port 22\n").expect("changed configuration");
        let restored = restore_push_destination("ssh://127.0.0.1/relative.git", Some(&frozen))
            .expect("historical identity");
        let Endpoint::Ssh {
            host,
            port,
            user,
            path,
        } = restored
        else {
            panic!("SSH endpoint");
        };
        let dial = pinned_dial(
            &"127.0.0.1:2222".parse().expect("address"),
            &host,
            port,
            user.as_deref(),
            Service::ReceivePack,
            &path,
        )
        .expect("dial");
        for flags in [
            "",
            "-p 22 -l bob",
            "-o Port=22 -o User=bob -o HostName=192.0.2.20",
        ] {
            let command = format!("ssh {config_flag} {flags}");
            let probe = probe_invocation(&dial, "ssh", Some(&command));
            let output = run_probe(
                probe.clone(),
                Instant::now() + Duration::from_secs(2),
                &Interrupt::none(),
            )
            .expect("configuration probe");
            assert_eq!(parse_identity(&output).expect("settings"), frozen);
            assert!(
                std::str::from_utf8(&output)
                    .expect("OpenSSH configuration")
                    .lines()
                    .any(|line| line == "hostname 127.0.0.1")
            );
            let SshInvocation::Exec(mut transport) =
                super::super::ssh_invocation(&dial, "ssh", Some(&command))
            else {
                panic!("recognized command uses direct arguments");
            };
            assert_eq!(
                transport.pop().as_deref(),
                Some("git-receive-pack '/relative.git'")
            );
            transport.insert(1, "-G".to_owned());
            assert_eq!(probe, SshInvocation::Exec(transport));
        }
        std::fs::remove_dir_all(root).expect("scratch cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn frozen_push_disables_configured_and_command_line_connection_sharing() {
        use std::net::TcpListener;
        use std::os::unix::net::UnixListener;

        let root = Path::new("/tmp").join(format!(
            "ruk-ssh-unshared-{}",
            ruk_core::change::PlanId::generate(),
        ));
        std::fs::create_dir(&root).expect("short unique scratch directory");
        let socket_path = root.join("old-master");
        let old_master = UnixListener::bind(&socket_path).expect("old control socket");
        old_master
            .set_nonblocking(true)
            .expect("nonblocking control socket");
        let destination = TcpListener::bind("127.0.0.1:0").expect("new destination");
        destination
            .set_nonblocking(true)
            .expect("nonblocking destination");
        let address = destination.local_addr().expect("new destination address");
        let config = root.join("config");
        std::fs::write(
            &config,
            format!(
                "Host *\n  User alice\n  Port {}\n  ControlMaster auto\n  ControlPath {}\n  ControlPersist yes\n",
                address.port(),
                super::super::shell_quote(socket_path.to_str().expect("UTF-8 socket")),
            ),
        )
        .expect("multiplexing configuration");
        let dial = pinned_dial(
            &address,
            "127.0.0.1",
            Some(address.port()),
            Some("alice"),
            Service::ReceivePack,
            "relative/repo.git",
        )
        .expect("pinned destination");
        let socket = super::super::shell_quote(socket_path.to_str().expect("UTF-8 socket"));
        let mut transport = None;
        for flags in [
            String::new(),
            format!("-M -S {socket}"),
            format!("-oControlMaster=yes -oControlPath={socket} -oControlPersist=yes"),
            format!("-vvMS{socket}"),
        ] {
            let command = format!(
                "ssh -F {} -o ConnectTimeout=1 -o BatchMode=yes {flags}",
                super::super::shell_quote(config.to_str().expect("UTF-8 configuration")),
            );
            check_push_client("ssh", Some(&command), Some("auto")).expect("OpenSSH options parse");
            let output = run_probe(
                probe_invocation(&dial, "ssh", Some(&command)),
                Instant::now() + Duration::from_secs(2),
                &Interrupt::none(),
            )
            .expect("OpenSSH evaluates pinned configuration");
            let output = std::str::from_utf8(&output).expect("configuration output");
            assert!(output.lines().any(|line| line == "controlmaster false"));
            assert!(output.lines().any(|line| line == "controlpersist no"));
            assert!(
                output
                    .lines()
                    .all(|line| !line.starts_with("controlpath ") || line == "controlpath none")
            );
            transport = Some(super::super::ssh_invocation(&dial, "ssh", Some(&command)));
        }
        let result = run_probe(
            transport.expect("transport invocation"),
            Instant::now() + Duration::from_secs(2),
            &Interrupt::none(),
        );
        assert!(matches!(
            result,
            Err(GitError::Io { .. } | GitError::Invalid { .. })
        ));
        assert!(
            matches!(old_master.accept(), Err(err) if err.kind() == std::io::ErrorKind::WouldBlock)
        );
        let (connected, peer) = destination
            .accept()
            .expect("SSH dialed the frozen endpoint");
        assert!(peer.ip().is_loopback());
        drop(connected);
        drop(destination);
        drop(old_master);
        std::fs::remove_dir_all(root).expect("scratch cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn failed_probe_terminates_children_in_its_process_group() {
        let root = std::env::temp_dir().join(format!(
            "ruk-ssh-probe-children-{}",
            ruk_core::change::PlanId::generate(),
        ));
        std::fs::create_dir_all(&root).expect("scratch directory");
        for (index, exit) in ["wait", "exit 9"].into_iter().enumerate() {
            let marker = root.join(format!("outlived-probe-{index}"));
            let script = format!(
                "(sleep 0.2; printf leaked > {}) >/dev/null 2>&1 & {exit}",
                super::super::shell_quote(marker.to_str().expect("UTF-8 path")),
            );
            let result = run_probe(
                SshInvocation::Exec(vec!["sh".to_owned(), "-c".to_owned(), script]),
                Instant::now() + Duration::from_millis(30),
                &Interrupt::none(),
            );
            assert!(matches!(
                result,
                Err(GitError::Io { .. } | GitError::Invalid { .. })
            ));
            std::thread::sleep(Duration::from_millis(300));
            assert!(
                !marker.exists(),
                "failed probe descendants cannot outlive the probe"
            );
        }
        std::fs::remove_dir_all(root).expect("scratch cleanup");
    }
}
