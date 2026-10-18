//! git credential-helper fill with environment fallback.
//!
//! This module never spawns `git`: the transport invariant owns every
//! grammar in-process and starts no system Git process. Instead it reads
//! `credential.helper` from git config files in-process and runs the
//! configured **external** helper program directly as
//! `<program> get <args...>` with the `protocol=`/`host=`/`url=` description
//! on stdin, parsing the `username=`/`password=` answer lines.
//!
//! Named gaps (fall through to the `GIT_AUTH_*` environment, then to
//! anonymous):
//!
//! - Bare built-in helper names (`store`, `cache`, `manager`, ...): those
//!   live behind the `git` binary (`git-credential-<name>`), which this
//!   crate never executes.
//! - `!`-prefixed shell commands: no shell is spawned here.
//! - URL-scoped sections match by prefix only (see [`scope_matches`]); git
//!   config `include` directives are not followed.
//!
//! Anything missing (no config, no external helper, a refused or timed-out
//! helper, no username in the answer) is `None`. A helper failure therefore
//! never fails an anonymous attempt; it only skips authenticated ones.
//!
//! Every helper hop is bounded: [`HELPER_TIMEOUT`] per attempt through a
//! monotonic deadline, at most [`MAX_HELPERS`] attempts, no retries. Tests
//! inject a stub through [`credential_fill_with`] /
//! [`auth_header_for_url_with`] instead of spawning processes.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use super::http;

/// Per-helper-attempt budget, enforced with a monotonic deadline.
const HELPER_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap on helper attempts per fill, so a long chain cannot stall a fetch.
const MAX_HELPERS: usize = 16;
/// Largest single gitconfig file parsed; larger files are skipped.
const MAX_CONFIG_BYTES: usize = 1 << 20;

/// Splits an `http(s)` URL into the `(protocol, host)` pair the credential
/// protocol wants. The host is the bare hostname (no userinfo, no port, no
/// brackets): the full `url=` line still carries the exact endpoint for
/// helpers that scope on path or port.
fn credential_parts(url: &str) -> Option<(String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let protocol = scheme.to_ascii_lowercase();
    if protocol != "http" && protocol != "https" {
        return None;
    }
    let authority = match rest.find('/') {
        Some(index) => &rest[..index],
        None => rest,
    };
    let hostport = authority.rsplit('@').next().unwrap_or("");
    let host = if let Some(bracketed) = hostport.strip_prefix('[') {
        bracketed.split(']').next()?
    } else {
        match hostport.rsplit_once(':') {
            Some((host, port))
                if !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) =>
            {
                host
            }
            _ => hostport,
        }
    };
    if host.is_empty() {
        return None;
    }
    Some((protocol, host.to_owned()))
}

/// Parses `git credential` helper stdout: the first `username=` and
/// `password=` lines win. A missing username is no answer (`None`); a
/// missing password defaults to empty, the way an empty password behaves
/// on the wire.
fn parse_fill_output(out: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(out).ok()?;
    let mut username: Option<String> = None;
    let mut password = String::new();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("username=") {
            if username.is_none() {
                username = Some(value.to_owned());
            }
        } else if let Some(value) = line.strip_prefix("password=") {
            if password.is_empty() {
                password = value.to_owned();
            }
        }
    }
    username
        .filter(|name| !name.is_empty())
        .map(|name| (name, password))
}

/// One `helper = <value>` config row: `scope` is the `[credential "<url>"]`
/// subsection when present, `value` the raw right-hand side (empty means
/// git's reset: clear the chain so far).
struct CredentialHelperRow {
    scope: Option<String>,
    value: String,
}

/// Gitconfig files in increasing precedence: system, `$HOME/.gitconfig`,
/// then XDG. `GIT_CONFIG_NOSYSTEM` drops the system file, `GIT_CONFIG_SYSTEM`
/// and `GIT_CONFIG_GLOBAL` override their paths. Missing or unreadable files
/// are skipped by the caller, never an error.
fn config_paths() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push_once = |path: PathBuf| {
        if !out.contains(&path) {
            out.push(path);
        }
    };
    if std::env::var_os("GIT_CONFIG_NOSYSTEM").is_none() {
        let system = std::env::var_os("GIT_CONFIG_SYSTEM")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/gitconfig"));
        push_once(system);
    }
    if let Some(global) = std::env::var_os("GIT_CONFIG_GLOBAL") {
        if !global.is_empty() {
            push_once(PathBuf::from(global));
        }
        return out;
    }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return out;
    };
    push_once(home.join(".gitconfig"));
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(xdg) if !xdg.is_empty() => push_once(PathBuf::from(xdg).join("git/config")),
        _ => push_once(home.join(".config/git/config")),
    }
    out
}

/// Splits a `[name "subsection"]` header into its lowercase section name and
/// optional subsection. A malformed header matches nothing.
fn parse_section_header(line: &str) -> (String, Option<String>) {
    let Some(inner) = line.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) else {
        return (String::new(), None);
    };
    let inner = inner.trim();
    match inner.split_once([' ', '\t']) {
        Some((name, rest)) => {
            let subsection = rest
                .trim()
                .strip_prefix('"')
                .and_then(|quoted| quoted.strip_suffix('"'))
                .unwrap_or_else(|| rest.trim());
            (name.to_ascii_lowercase(), Some(subsection.to_owned()))
        }
        None => (inner.to_ascii_lowercase(), None),
    }
}

/// Cuts a trailing `#`/`;` comment that starts a token. Values containing
/// those characters without preceding whitespace keep them; helper program
/// paths never need quoting here.
fn strip_inline_comment(value: &str) -> &str {
    let mut start = None;
    for (index, byte) in value.bytes().enumerate() {
        if byte != b'#' && byte != b';' {
            continue;
        }
        let boundary = index == 0 || value.as_bytes()[index - 1].is_ascii_whitespace();
        if boundary {
            start = Some(index);
            break;
        }
    }
    match start {
        Some(index) => value[..index].trim_end(),
        None => value,
    }
}

/// Collects every `credential.helper` row in one config file, in file order.
/// Only `key = value` rows count; `include` directives are not followed.
fn parse_config_entries(text: &str) -> Vec<CredentialHelperRow> {
    let mut entries = Vec::new();
    let mut section = String::new();
    let mut subsection: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            let (name, sub) = parse_section_header(line);
            section = name;
            subsection = sub;
            continue;
        }
        if section != "credential" {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("helper") {
            continue;
        }
        entries.push(CredentialHelperRow {
            scope: subsection.clone(),
            value: strip_inline_comment(value.trim()).to_owned(),
        });
    }
    entries
}

/// Whether a `[credential "<pattern>"]` subsection matches `url`: the
/// pattern must be a prefix ending on a URL boundary (`/`, `?`, `#`, or the
/// end), so `https://host` never matches `https://hostile`.
fn scope_matches(pattern: &str, url: &str) -> bool {
    let pattern = pattern.trim_end_matches('/');
    if pattern.is_empty() {
        return false;
    }
    if url == pattern {
        return true;
    }
    let Some(rest) = url.strip_prefix(pattern) else {
        return false;
    };
    rest.starts_with(['/', '?', '#'])
}

/// Expands a leading `~/` against `$HOME`. A bare `~` without a home is no
/// program at all.
fn expand_home(path: &str) -> Option<String> {
    if !path.starts_with('~') {
        return Some(path.to_owned());
    }
    let home = std::env::var_os("HOME")?;
    if path == "~" {
        return Some(home.to_string_lossy().into_owned());
    }
    let rest = path.strip_prefix("~/")?;
    Some(
        PathBuf::from(home)
            .join(rest)
            .to_string_lossy()
            .into_owned(),
    )
}

/// Classifies one helper value into a directly runnable `(program, args)`:
/// only values whose first word names a path (contains `/` or starts with
/// `~`) run. Bare built-in names (`store`, `cache`, ...) resolve through
/// the `git` binary, which this crate never executes; `!` shell commands
/// would need a shell. Both are named gaps (`None`).
fn classify_helper(value: &str) -> Option<(String, Vec<String>)> {
    let value = value.trim();
    if value.is_empty() || value.starts_with('!') {
        return None;
    }
    let mut words = value.split_whitespace();
    let first = words.next()?;
    if !first.contains('/') && !first.starts_with('~') {
        return None;
    }
    let program = expand_home(first)?;
    Some((program, words.map(str::to_owned).collect()))
}

/// Orders parsed rows for `url`: matching scoped rows first (file order),
/// then top-level rows (file order). An empty value resets the chain, the
/// way git's `helper =` (empty) clears previously accumulated helpers.
fn helper_commands_for(url: &str, entries: &[CredentialHelperRow]) -> Vec<(String, Vec<String>)> {
    let mut ordered: Vec<&CredentialHelperRow> = entries
        .iter()
        .filter(|entry| {
            entry
                .scope
                .as_ref()
                .is_some_and(|scope| scope_matches(scope, url))
        })
        .collect();
    ordered.extend(entries.iter().filter(|entry| entry.scope.is_none()));
    let mut out = Vec::new();
    for entry in ordered {
        if entry.value.trim().is_empty() {
            out.clear();
            continue;
        }
        if let Some(command) = classify_helper(&entry.value) {
            if out.len() < MAX_HELPERS {
                out.push(command);
            }
        }
    }
    out
}

/// Reads every config file and resolves the runnable helper chain for `url`.
/// Unreadable files, oversized files and non-UTF-8 files are skipped.
fn helper_commands(url: &str) -> Vec<(String, Vec<String>)> {
    let mut entries = Vec::new();
    for path in config_paths() {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.len() > MAX_CONFIG_BYTES {
            continue;
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        entries.extend(parse_config_entries(text));
    }
    helper_commands_for(url, &entries)
}

/// Spawns one external helper as `<program> get <args...>` with `input` on
/// stdin, bounded by [`HELPER_TIMEOUT`] on a monotonic deadline. A refusal,
/// a non-zero exit, an unreadable answer, or a timeout is `None`.
fn run_helper(program: &str, args: &[String], input: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new(program)
        .arg("get")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env("GIT_TERMINAL_PROMPT", "0")
        .spawn()
        .ok()?;
    write_input(&mut child, input)?;
    let mut stdout = child.stdout.take()?;
    let (tx, ry) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let answer = stdout.read_to_end(&mut out).ok().map(|_| out);
        let _ = tx.send(answer);
    });
    let status = wait_bounded(&mut child, Instant::now() + HELPER_TIMEOUT)?;
    if !status.success() {
        return None;
    }
    ry.recv_timeout(Duration::from_secs(2)).ok()?
}

/// Writes the credential description into the helper's stdin. A broken pipe
/// (helper exited early) is a refusal, reported before any wait.
fn write_input(child: &mut Child, input: &[u8]) -> Option<()> {
    let mut stdin = child.stdin.take()?;
    stdin.write_all(input).ok()?;
    drop(stdin);
    Some(())
}

/// Waits until `deadline` for the helper to exit, reaping it on timeout. A
/// wait failure is a refusal.
fn wait_bounded(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    loop {
        let exited = child.try_wait().ok().flatten();
        if let Some(status) = exited {
            return Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Fills credentials for `url` by trying each configured helper in order
/// through `runner`, the seam tests inject a stub through: `runner`
/// receives `(program, args, stdin)` and answers the stdout bytes (or
/// `None` for a refused fill). The first answer carrying a username wins.
#[must_use]
pub fn credential_fill_with(
    url: &str,
    helpers: &[(String, Vec<String>)],
    runner: impl Fn(&str, &[String], &[u8]) -> Option<Vec<u8>>,
) -> Option<(String, String)> {
    let (protocol, host) = credential_parts(url)?;
    let input = format!("protocol={protocol}\nhost={host}\nurl={url}\n\n").into_bytes();
    for (program, args) in helpers {
        let Some(out) = runner(program, args, &input) else {
            continue;
        };
        if let Some(answer) = parse_fill_output(&out) {
            return Some(answer);
        }
    }
    None
}

/// Fills credentials for `url` through the live config plus live helper
/// processes. Empty when no external helper is configured or none answers.
#[must_use]
pub fn credential_fill(url: &str) -> Option<(String, String)> {
    let helpers = helper_commands(url);
    if helpers.is_empty() {
        return None;
    }
    credential_fill_with(url, &helpers, run_helper)
}

/// Standard-alphabet base64 with padding for one Basic value (the same
/// spelling [`super::http`] uses for its env header; duplicated so this
/// module needs no visibility into that private helper).
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut word: u32 = 0;
        for (index, byte) in chunk.iter().enumerate() {
            let shift = 16 - 8 * index;
            let shifted = u32::from(*byte) << shift;
            word |= shifted;
        }
        let pad = 3 - chunk.len();
        for index in 0..4 - pad {
            let sextet = (word >> (18 - 6 * index)) & 0x3F;
            // Widening only: u32 to usize never narrows, and the mask
            // proves the value is below 64.
            out.push(ALPHABET[sextet as usize] as char);
        }
        for _ in 0..pad {
            out.push('=');
        }
    }
    out
}

/// An `Authorization` header for `url`: the first answering helper as
/// Basic, then the `GIT_AUTH_*` environment. Helper failure is non-fatal
/// to anonymous attempts: it falls through to the environment, which may
/// itself be empty.
#[must_use]
pub fn auth_header_for_url_with(
    url: &str,
    vars: &HashMap<String, String>,
    helpers: &[(String, Vec<String>)],
    runner: impl Fn(&str, &[String], &[u8]) -> Option<Vec<u8>>,
) -> Option<(String, String)> {
    if let Some((username, password)) = credential_fill_with(url, helpers, runner) {
        let encoded = base64_encode(format!("{username}:{password}").as_bytes());
        if encoded.is_empty() {
            return http::git_auth_header(vars);
        }
        return Some(("authorization".to_owned(), format!("Basic {encoded}")));
    }
    http::git_auth_header(vars)
}

/// An `Authorization` header for `url` through the live helpers, then the
/// environment.
#[must_use]
pub fn auth_header_for_url(
    url: &str,
    vars: &HashMap<String, String>,
) -> Option<(String, String)> {
    let helpers = helper_commands(url);
    if helpers.is_empty() {
        return http::git_auth_header(vars);
    }
    auth_header_for_url_with(url, vars, &helpers, run_helper)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn external_helper(program: &str) -> (String, Vec<String>) {
        (program.to_owned(), Vec::new())
    }

    #[test]
    fn fill_sends_the_description_and_parses_the_answer() {
        let out = credential_fill_with(
            "https://host.x/a.git",
            &[external_helper("/usr/bin/helper")],
            |program, args, input| {
                assert_eq!(program, "/usr/bin/helper");
                assert!(args.is_empty());
                let text = std::str::from_utf8(input).expect("stdin");
                assert!(text.contains("protocol=https\n"), "{text:?}");
                assert!(text.contains("host=host.x\n"), "{text:?}");
                assert!(text.contains("url=https://host.x/a.git\n"), "{text:?}");
                Some(b"protocol=https\nhost=host.x\nusername=alice\npassword=s3cret\n".to_vec())
            },
        );
        assert_eq!(out, Some(("alice".to_owned(), "s3cret".to_owned())));
    }

    #[test]
    fn fill_skips_refusals_for_the_next_helper() {
        let out = credential_fill_with(
            "https://host.x/a",
            &[external_helper("/bin/first"), external_helper("/bin/second")],
            |program, _, _| {
                if program == "/bin/second" {
                    return Some(b"username=bob\npassword=\n".to_vec());
                }
                None
            },
        );
        assert_eq!(out, Some(("bob".to_owned(), String::new())));
    }

    #[test]
    fn fill_refuses_without_a_username() {
        assert_eq!(
            credential_fill_with(
                "https://host.x/a",
                &[external_helper("/bin/helper")],
                |_, _, _| Some(b"protocol=https\nhost=host.x\npassword=orphan\n".to_vec())
            ),
            None
        );
        assert_eq!(
            credential_fill_with("https://host.x/a", &[external_helper("/bin/helper")], |_, _, _| None),
            None
        );
        assert_eq!(
            credential_fill_with("ftp://host.x/a", &[external_helper("/bin/helper")], |_, _, _| Some(
                b"username=a\npassword=b\n".to_vec()
            )),
            None
        );
    }

    #[test]
    fn config_orders_scoped_before_top_level_and_honors_reset() {
        let entries = parse_config_entries(
            "[credential]\n\thelper = /bin/top\n[credential \"https://host.x/sub\"]\n\thelper = /bin/scoped\n",
        );
        let chain = helper_commands_for("https://host.x/sub/a", &entries);
        assert_eq!(chain, vec![external_helper("/bin/scoped"), external_helper("/bin/top")]);
        let other = helper_commands_for("https://elsewhere.x/a", &entries);
        assert_eq!(other, vec![external_helper("/bin/top")]);
        let reset = parse_config_entries("[credential]\n\thelper = /bin/a\n\thelper =\n\thelper = /bin/b\n");
        assert_eq!(helper_commands_for("https://host.x/a", &reset), vec![external_helper("/bin/b")]);
    }

    #[test]
    fn builtins_shell_and_non_matching_scopes_are_gaps() {
        let entries = parse_config_entries(
            "[credential]\n\thelper = store\n\thelper = !shell-cmd\n\thelper = cache --timeout 300\n",
        );
        assert!(helper_commands_for("https://host.x/a", &entries).is_empty());
        assert!(scope_matches("https://host.x/sub", "https://host.x/sub/a"));
        assert!(!scope_matches("https://host", "https://hostile.x/a"));
        assert!(!scope_matches("", "https://host.x/a"));
        assert_eq!(classify_helper("~/bin/helper --flag"), {
            let home = std::env::var_os("HOME").map(|home| PathBuf::from(home).join("bin/helper").to_string_lossy().into_owned());
            home.map(|program| (program, vec!["--flag".to_owned()]))
        });
    }

    #[test]
    fn helper_answer_wins_over_the_environment() {
        let header = auth_header_for_url_with(
            "https://host.x/a.git",
            &vars(&[("GIT_AUTH_TOKEN", "tok")]),
            &[external_helper("/bin/helper")],
            |_, _, _| Some(b"username=alice\npassword=s3cret\n".to_vec()),
        )
        .expect("header");
        assert_eq!(header.0, "authorization");
        assert_eq!(header.1, "Basic YWxpY2U6czNjcmV0");
    }

    #[test]
    fn helper_failure_falls_back_to_the_environment() {
        let header = auth_header_for_url_with(
            "https://host.x/a.git",
            &vars(&[("GIT_AUTH_TOKEN", "tok")]),
            &[external_helper("/bin/helper")],
            |_, _, _| None,
        );
        assert_eq!(
            header,
            Some(("authorization".to_owned(), "Bearer tok".to_owned()))
        );
        assert_eq!(
            auth_header_for_url_with("https://host.x/a.git", &vars(&[]), &[], |_, _, _| None),
            None
        );
    }

    #[test]
    fn credential_parts_strips_userinfo_and_ports() {
        assert_eq!(
            credential_parts("https://user@host.x:8443/a.git"),
            Some(("https".to_owned(), "host.x".to_owned()))
        );
        assert_eq!(
            credential_parts("http://host.x/a"),
            Some(("http".to_owned(), "host.x".to_owned()))
        );
        assert!(credential_parts("ftp://host.x/a").is_none());
        assert!(credential_parts("https:///a").is_none());
    }

    #[test]
    fn helper_attempts_are_time_bounded() {
        let started = Instant::now();
        let out = run_helper("/bin/sleep", &["30".to_owned()], b"protocol=https\nhost=h\n\n");
        assert_eq!(out, None);
        assert!(
            started.elapsed() < HELPER_TIMEOUT + Duration::from_secs(5),
            "helper overran its budget"
        );
    }
}
