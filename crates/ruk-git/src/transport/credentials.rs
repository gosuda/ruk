//! git credential-helper fill with environment fallback.
//!
//! This module never spawns `git`: the transport invariant owns every
//! grammar in-process and starts no system Git process. Instead it reads
//! `credential.helper` from git config files in-process and runs the
//! configured **external** helper program directly as
//! `<program> get <args...>` with the `protocol=`/`host=`/`url=` description
//! on stdin, parsing the `username=`/`password=` answer lines.
//!
//! `!`-prefixed values run through `sh -c "<command> get"`, exactly like
//! git (`git/credential.c` `credential_do` appends the operation to the
//! command line and always uses a shell). The command travels verbatim from
//! the user's own config files with only the fixed ` get` suffix appended:
//! no URL, host, or other input is interpolated into the shell line. That is
//! the same trust shape as `GIT_SSH_COMMAND`, which [`super::net`] already
//! runs through `sh -c`; spawning `sh` here introduces no new principal.
//!
//! Named gaps (fall through to the `GIT_AUTH_*` environment, then to
//! anonymous):
//!
//! - Bare built-in helper names (`store`, `cache`, `manager`, ...): those
//!   resolve to `git-credential-<name>` binaries from the Git distribution,
//!   which this crate never executes. PATH-resolved Git binaries would widen
//!   the trust boundary past explicitly configured programs, and interactive
//!   ones like `manager` can block on GUI prompts, which is unsafe for a
//!   daemon.
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
use std::fmt;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

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
                if !host.is_empty()
                    && !port.is_empty()
                    && port.bytes().all(|b| b.is_ascii_digit()) =>
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
        } else if let Some(value) = line.strip_prefix("password=")
            && password.is_empty()
        {
            password = value.to_owned();
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
    config_paths_in(&std::env::vars().collect())
}

/// The [`config_paths`] file list resolved against an explicit environment
/// map instead of the process one, so callers carrying their own
/// environment (like the bare `credential` verb with its captured `CliEnv`)
/// stay hermetic under test. Semantics match [`config_paths`] exactly:
/// presence (even empty) of `GIT_CONFIG_NOSYSTEM` drops the system file.
fn config_paths_in(vars: &HashMap<String, String>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push_once = |path: PathBuf| {
        if !out.contains(&path) {
            out.push(path);
        }
    };
    if !vars.contains_key("GIT_CONFIG_NOSYSTEM") {
        let system = vars
            .get("GIT_CONFIG_SYSTEM")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/gitconfig"));
        push_once(system);
    }
    if let Some(global) = vars.get("GIT_CONFIG_GLOBAL") {
        if !global.is_empty() {
            push_once(PathBuf::from(global));
        }
        return out;
    }
    let Some(home) = vars.get("HOME").map(PathBuf::from) else {
        return out;
    };
    push_once(home.join(".gitconfig"));
    match vars.get("XDG_CONFIG_HOME") {
        Some(xdg) if !xdg.is_empty() => push_once(PathBuf::from(xdg).join("git/config")),
        _ => push_once(home.join(".config/git/config")),
    }
    out
}

/// Splits a `[name "subsection"]` header into its lowercase section name and
/// optional subsection. A malformed header matches nothing.
fn parse_section_header(line: &str) -> (String, Option<String>) {
    let Some(inner) = line
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    else {
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

/// Whether a `[credential "<pattern>"]` (or `[http "<base>"]`) subsection
/// matches `url`: the pattern must be a prefix ending on a URL boundary
/// (`/`, `?`, `#`, or the end), so `https://host` never matches
/// `https://hostile`. Shared with the `http.extraHeader` resolver, which
/// documents its simplification against git's `urlmatch` normalization.
pub(crate) fn scope_matches(pattern: &str, url: &str) -> bool {
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
/// a `!`-prefixed value runs through the shell as
/// `("sh", ["-c", <command>])` ([`run_helper`] appends the ` get`
/// operation, mirroring `git/credential.c` `credential_do`); otherwise only
/// values whose first word names a path (contains `/` or starts with `~`)
/// run. Bare built-in names (`store`, `cache`, ...) resolve to
/// `git-credential-<name>` binaries, which this crate never executes: a
/// named gap (`None`).
fn classify_helper(value: &str) -> Option<(String, Vec<String>)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some(line) = value.strip_prefix('!') {
        if line.trim().is_empty() {
            return None;
        }
        return Some(("sh".to_owned(), vec!["-c".to_owned(), line.to_owned()]));
    }
    let mut words = value.split_whitespace();
    let first = words.next()?;
    if !first.contains('/') && !first.starts_with('~') {
        return None;
    }
    let program = expand_home(first)?;
    Some((program, words.map(str::to_owned).collect()))
}

/// Resolves the runnable helper chain for `url` in file order: rows run
/// top to bottom, a scoped row only when its pattern matches `url`, a
/// top-level row always. An empty value resets the chain, the way git's
/// `helper =` (empty) clears previously accumulated helpers
/// (`git/credential.c` appends in config read order).
fn helper_commands_for(url: &str, entries: &[CredentialHelperRow]) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for entry in entries {
        if entry.value.trim().is_empty() {
            out.clear();
            continue;
        }
        if let Some(scope) = entry.scope.as_ref()
            && !scope_matches(scope, url)
        {
            continue;
        }
        if let Some(command) = classify_helper(&entry.value)
            && out.len() < MAX_HELPERS
        {
            out.push(command);
        }
    }
    out
}

/// Collects every `http.extraHeader` row in one config file, in file order:
/// `(scope, value)` with `scope` from `[http "<base>"]` subsections (`None`
/// is bare `http.extraHeader`). Multivalued by nature: every row is kept,
/// including empty ones (an empty value resets the accumulated list when
/// the rows resolve through [`http::extra_headers_for_url`]). Section and
/// key compare case-insensitively like git's config; the scope keeps its
/// case. Values share this module's minimal config grammar (no quoting): a
/// ` #`/` ;` starts a comment, the same limitation helper paths accept.
fn parse_http_extra_header_entries(text: &str) -> Vec<http::ExtraHeaderRow> {
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
        if section != "http" {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("extraheader") {
            continue;
        }
        entries.push(http::ExtraHeaderRow {
            scope: subsection.clone(),
            value: strip_inline_comment(value.trim()).to_owned(),
        });
    }
    entries
}

/// Reads every config file's `http.extraHeader` rows in file order.
/// Unreadable files, oversized files and non-UTF-8 files are skipped.
#[must_use]
pub fn http_extra_header_rows() -> Vec<http::ExtraHeaderRow> {
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
        entries.extend(parse_http_extra_header_entries(text));
    }
    entries
}

/// Reads every config file and resolves the runnable helper chain for `url`.
/// Unreadable files, oversized files and non-UTF-8 files are skipped.
fn helper_commands(url: &str) -> Vec<(String, Vec<String>)> {
    helper_commands_in(url, &std::env::vars().collect())
}

/// The [`helper_commands`] chain resolved against an explicit environment
/// map, so environment-carrying callers stay hermetic under test.
fn helper_commands_in(url: &str, vars: &HashMap<String, String>) -> Vec<(String, Vec<String>)> {
    let mut entries = Vec::new();
    for path in config_paths_in(vars) {
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

/// Whether `(program, args)` names a `!` shell helper: exactly
/// `("sh", ["-c", <line>])`, the only shape [`classify_helper`] produces
/// for one. An explicitly configured absolute `sh` path never collides:
/// its program spells the full path, not the bare `"sh"`.
fn is_shell_helper(program: &str, args: &[String]) -> bool {
    program == "sh" && args.len() == 2 && args[0] == "-c"
}

/// The shell line git runs for a `!` helper: the configured command
/// verbatim plus the credential operation (`git/credential.c`
/// `credential_do` appends `get`, `store`, or `erase`).
fn shell_command_line(line: &str, op: &str) -> String {
    format!("{line} {op}")
}

/// Spawns one external helper as `<program> <op> <args...>` — or, for a `!`
/// shell helper, as `sh -c "<command> <op>"` — with `input` on stdin,
/// bounded by [`HELPER_TIMEOUT`] on a monotonic deadline. A refusal, a
/// non-zero exit, an unreadable answer, or a timeout is `None`.
fn run_helper_op(program: &str, args: &[String], op: &str, input: &[u8]) -> Option<Vec<u8>> {
    let mut command = if is_shell_helper(program, args) {
        let mut shell = Command::new("sh");
        shell.arg("-c").arg(shell_command_line(&args[1], op));
        shell
    } else {
        let mut direct = Command::new(program);
        direct.arg(op).args(args);
        direct
    };
    let mut child = command
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

/// The three-argument seam the URL fill keeps: the operation is always
/// `get`, so `store`/`erase` callers use [`run_helper_op`] directly.
fn run_helper(program: &str, args: &[String], input: &[u8]) -> Option<Vec<u8>> {
    run_helper_op(program, args, "get", input)
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

/// Largest stdin description the bare `credential` verb accepts: real
/// descriptions are a handful of short lines, so anything larger is a
/// caller error, not a credential.
pub const MAX_CREDENTIAL_INPUT: usize = 64 << 10;

/// Parses a `git credential` description from stdin bytes: `key=value`
/// lines up to the first blank line, mirroring how the oracle reads its
/// `struct credential` (`git/credential.c` `credential_read`). Lines
/// without `=` and empty keys never name a field and are skipped; later
/// duplicates are kept in order so the caller can echo the description
/// back verbatim.
#[must_use]
pub fn parse_credential_input(bytes: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(bytes).lines() {
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.is_empty() {
            continue;
        }
        out.push((key.to_owned(), value.to_owned()));
    }
    out
}

/// Serializes a description for a helper's stdin: one `key=value` line per
/// pair plus the terminating blank line.
fn credential_input_bytes(desc: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, value) in desc {
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value.as_bytes());
        out.push(b'\n');
    }
    out.push(b'\n');
    out
}

/// Reads one field out of a parsed description.
fn credential_field<'a>(desc: &'a [(String, String)], key: &str) -> Option<&'a str> {
    desc.iter()
        .find(|(known, _)| known == key)
        .map(|(_, value)| value.as_str())
}

/// Derives the URL helper scoping uses from a description: the `url=` field
/// verbatim when present, else `protocol://host[/path]` synthesized from
/// the components (`git/credential.c` hands helpers the same description
/// and helpers scope on what they recognize; the config chain here scopes
/// on URL prefix, so the components must become a URL). `None` runs only
/// unscoped helpers.
#[must_use]
pub fn credential_scope_url(desc: &[(String, String)]) -> Option<String> {
    if let Some(url) = credential_field(desc, "url")
        && !url.is_empty()
    {
        return Some(url.to_owned());
    }
    let protocol = credential_field(desc, "protocol")?;
    let host = credential_field(desc, "host")?;
    if protocol.is_empty() || host.is_empty() {
        return None;
    }
    match credential_field(desc, "path") {
        Some(path) if !path.is_empty() => Some(format!("{protocol}://{host}/{path}")),
        _ => Some(format!("{protocol}://{host}")),
    }
}

/// Resolves the runnable helper chain for a description through the live
/// config: scoped rows match the derived scope URL, unscoped rows always
/// run. A description without scope runs only unscoped helpers (every
/// scoped pattern fails a prefix match against the empty URL).
#[must_use]
pub fn helper_chain_for(desc: &[(String, String)]) -> Vec<(String, Vec<String>)> {
    helper_chain_for_in(desc, &std::env::vars().collect())
}

/// The [`helper_chain_for`] chain resolved against an explicit environment
/// map, so environment-carrying callers stay hermetic under test.
#[must_use]
pub fn helper_chain_for_in(
    desc: &[(String, String)],
    vars: &HashMap<String, String>,
) -> Vec<(String, Vec<String>)> {
    match credential_scope_url(desc) {
        Some(url) => helper_commands_in(&url, vars),
        None => helper_commands_in("", vars),
    }
}

/// Overwrites `key` in `pairs` in place, appending it when absent, so a
/// `fill` answer echoes the input description with the found fields.
fn upsert_credential(pairs: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some(slot) = pairs.iter_mut().find(|(known, _)| known == key) {
        slot.1 = value.to_owned();
    } else {
        pairs.push((key.to_owned(), value.to_owned()));
    }
}

/// Fills a parsed description through `runner`, the injectable seam tests
/// use: `runner` receives `(program, args, op, stdin)` and answers the
/// stdout bytes (or `None` for a refused operation). Only the `get`
/// operation runs, and the first answer carrying a username wins; the
/// returned pairs echo the input description with the found `username=`
/// (and a non-empty `password=`) merged in, the way the oracle prints the
/// filled credential. An input `password=` survives a helper answer that
/// names no password.
#[must_use]
pub fn credential_fill_desc_with(
    desc: &[(String, String)],
    helpers: &[(String, Vec<String>)],
    runner: impl Fn(&str, &[String], &str, &[u8]) -> Option<Vec<u8>>,
) -> Option<Vec<(String, String)>> {
    let input = credential_input_bytes(desc);
    for (program, args) in helpers {
        let Some(out) = runner(program, args, "get", &input) else {
            continue;
        };
        if let Some((username, password)) = parse_fill_output(&out) {
            let mut merged = desc.to_vec();
            upsert_credential(&mut merged, "username", &username);
            if !password.is_empty() {
                upsert_credential(&mut merged, "password", &password);
            }
            return Some(merged);
        }
    }
    None
}

/// Runs one fire-and-forget operation (`store` for `approve`, `erase` for
/// `reject`) across the whole chain: every helper runs and every answer is
/// ignored, mirroring `git/credential.c` `credential_do`, which only the
/// `get` operation short-circuits.
pub fn credential_store_op_desc_with(
    desc: &[(String, String)],
    op: &str,
    helpers: &[(String, Vec<String>)],
    runner: impl Fn(&str, &[String], &str, &[u8]) -> Option<Vec<u8>>,
) {
    let input = credential_input_bytes(desc);
    for (program, args) in helpers {
        let _ = runner(program, args, op, &input);
    }
}

/// Fills a parsed description through the live config plus live helper
/// processes, with config files resolved against `vars`. Empty when no
/// external helper is configured or none answers.
#[must_use]
pub fn credential_fill_desc(
    desc: &[(String, String)],
    vars: &HashMap<String, String>,
) -> Option<Vec<(String, String)>> {
    let helpers = helper_chain_for_in(desc, vars);
    if helpers.is_empty() {
        return None;
    }
    credential_fill_desc_with(desc, &helpers, run_helper_op)
}

/// Approves a parsed description through the live helpers (`store` across
/// the whole chain, config files resolved against `vars`). Helper failures
/// are silent: there is nothing to report back to a `store` caller.
pub fn credential_approve_desc(desc: &[(String, String)], vars: &HashMap<String, String>) {
    let helpers = helper_chain_for_in(desc, vars);
    credential_store_op_desc_with(desc, "store", &helpers, run_helper_op);
}

/// Rejects a parsed description through the live helpers (`erase` across
/// the whole chain, config files resolved against `vars`), silent like its
/// `store` sibling.
pub fn credential_reject_desc(desc: &[(String, String)], vars: &HashMap<String, String>) {
    let helpers = helper_chain_for_in(desc, vars);
    credential_store_op_desc_with(desc, "erase", &helpers, run_helper_op);
}

/// Standard-alphabet base64 with padding for one Basic value (the same
/// spelling [`super::http`] uses for its env header; duplicated so this
/// module needs no visibility into that private helper).
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
pub fn auth_header_for_url(url: &str, vars: &HashMap<String, String>) -> Option<(String, String)> {
    let helpers = helper_commands(url);
    if helpers.is_empty() {
        return http::git_auth_header(vars);
    }
    auth_header_for_url_with(url, vars, &helpers, run_helper)
}

/// How one call authenticates to a remote. `None` sends nothing; any other
/// kind sends exactly one `Authorization` header and never consults helpers
/// or the environment (H4b fail closed). SSH key injection stays deferred.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportAuthKind {
    /// No credential: anonymous, or ambient resolution downstream.
    #[default]
    None,
    /// HTTP Basic: `credential` is `user:password` in the clear.
    Basic,
    /// Bearer token: `credential` is the token in the clear.
    Bearer,
}

/// A credential injected on one call for remote authentication.
///
/// The secret travels only toward the transport job that needs it: [`fmt::Debug`]
/// redacts it, and digest helpers take only parsed commands plus limits,
/// so it never enters argument digests, receipts, or logs. `origin`
/// scopes it to one `scheme://host[:port]`; a cross-origin redirect drops
/// it instead of forwarding it.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportAuth {
    /// Which header the credential becomes, or none.
    #[serde(default)]
    pub kind: TransportAuthKind,
    /// The secret: `user:password` for basic, the token for bearer.
    #[serde(default)]
    pub credential: String,
    /// The `scheme://host[:port]` this credential may be sent to.
    #[serde(default)]
    pub origin: String,
}

impl fmt::Debug for TransportAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportAuth")
            .field("kind", &self.kind)
            .field("credential", &"[redacted]")
            .field("origin", &self.origin)
            .finish()
    }
}

impl TransportAuth {
    /// No credential: anonymous, or ambient resolution downstream.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Fails closed on a half-specified credential: an explicit kind needs
    /// both the secret and a well-formed origin scope; `None` carries
    /// nothing and always passes.
    ///
    /// # Errors
    /// [`crate::GitError::Invalid`] naming the missing half.
    pub fn validate(&self) -> Result<(), crate::GitError> {
        if self.kind == TransportAuthKind::None {
            return Ok(());
        }
        if self.credential.is_empty() {
            return Err(crate::GitError::Invalid {
                detail: "injected transport auth needs its credential".to_owned(),
            });
        }
        let scoped = Self::origin_of(&format!("{}/", self.origin));
        if scoped.as_deref() != Some(self.origin.as_str()) {
            return Err(crate::GitError::Invalid {
                detail: "injected transport auth needs a scheme://host[:port] origin".to_owned(),
            });
        }
        Ok(())
    }

    /// The `Authorization` header for `url`, only when `url` stays inside
    /// the credential's origin scope. A cross-origin `url` yields nothing:
    /// the caller drops the credential instead of forwarding it.
    #[must_use]
    pub fn header_for(&self, url: &str) -> Option<(String, String)> {
        match self.kind {
            TransportAuthKind::None => None,
            TransportAuthKind::Basic | TransportAuthKind::Bearer => {
                if self.credential.is_empty() {
                    return None;
                }
                let origin = Self::origin_of(url)?;
                if origin != self.origin {
                    return None;
                }
                let value = match self.kind {
                    TransportAuthKind::Basic => {
                        format!("Basic {}", base64_encode(self.credential.as_bytes()))
                    }
                    TransportAuthKind::Bearer => {
                        format!("Bearer {}", self.credential)
                    }
                    TransportAuthKind::None => return None,
                };
                Some(("authorization".to_owned(), value))
            }
        }
    }

    /// The origin scope of one `http(s)` URL: lowercase
    /// `scheme://host:port` with browser defaults (80/443) filled in, the
    /// same normalization [`super::http::same_origin`] compares. Userinfo
    /// never enters the scope. `None` for non-HTTP URLs.
    #[must_use]
    pub fn origin_of(url: &str) -> Option<String> {
        let (scheme, rest) = url.split_once("://")?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return None;
        }
        let authority = rest.split('/').next()?;
        let hostport = authority.rsplit('@').next().unwrap_or_default();
        let (host, port) = if let Some(bracketed) = hostport.strip_prefix('[') {
            let end = bracketed.find(']')?;
            let host = bracketed[..end].to_ascii_lowercase();
            if host.is_empty() {
                return None;
            }
            let port = match bracketed[end + 1..].strip_prefix(':') {
                Some(text) => text.parse::<u16>().ok()?,
                None if end + 1 == bracketed.len() => 0,
                None => return None,
            };
            (host, port)
        } else if let Some((host, text)) = hostport.rsplit_once(':')
            && !text.is_empty()
            && text.bytes().all(|byte| byte.is_ascii_digit())
        {
            if host.is_empty() {
                return None;
            }
            (host.to_ascii_lowercase(), text.parse::<u16>().ok()?)
        } else {
            if hostport.is_empty() {
                return None;
            }
            (hostport.to_ascii_lowercase(), 0)
        };
        let port = if port == 0 {
            if scheme == "https" { 443 } else { 80 }
        } else {
            port
        };
        Some(format!("{scheme}://{host}:{port}"))
    }
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
            &[
                external_helper("/bin/first"),
                external_helper("/bin/second"),
            ],
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
            credential_fill_with(
                "https://host.x/a",
                &[external_helper("/bin/helper")],
                |_, _, _| None
            ),
            None
        );
        assert_eq!(
            credential_fill_with(
                "ftp://host.x/a",
                &[external_helper("/bin/helper")],
                |_, _, _| Some(b"username=a\npassword=b\n".to_vec())
            ),
            None
        );
    }

    #[test]
    fn config_keeps_file_order_and_honors_reset() {
        let entries = parse_config_entries(
            "[credential]\n\thelper = /bin/top\n[credential \"https://host.x/sub\"]\n\thelper = /bin/scoped\n",
        );
        // File order, not scoped-first: git appends in config read order,
        // so the top-level helper answers before the scoped one.
        let chain = helper_commands_for("https://host.x/sub/a", &entries);
        assert_eq!(
            chain,
            vec![external_helper("/bin/top"), external_helper("/bin/scoped")]
        );
        let other = helper_commands_for("https://elsewhere.x/a", &entries);
        assert_eq!(other, vec![external_helper("/bin/top")]);
        let reset = parse_config_entries(
            "[credential]\n\thelper = /bin/a\n\thelper =\n\thelper = /bin/b\n",
        );
        assert_eq!(
            helper_commands_for("https://host.x/a", &reset),
            vec![external_helper("/bin/b")]
        );
    }

    #[test]
    fn shell_helpers_run_and_builtins_stay_gaps() {
        let entries = parse_config_entries(
            "[credential]\n\thelper = store\n\thelper = !/bin/shell-helper --fast\n\thelper = cache --timeout 300\n\thelper = manager-core\n\thelper = !\n",
        );
        // Bare built-in names and the empty `!` stay gaps; only the shell
        // helper classifies, as `sh -c <line>` (the live layer appends
        // ` get`, mirroring `git/credential.c` `credential_do`).
        let chain = helper_commands_for("https://host.x/a", &entries);
        assert_eq!(
            chain,
            vec![(
                "sh".to_owned(),
                vec!["-c".to_owned(), "/bin/shell-helper --fast".to_owned()]
            )]
        );
        assert_eq!(
            shell_command_line("/bin/shell-helper --fast", "get"),
            "/bin/shell-helper --fast get"
        );
        // The stub seam sees the shell program form and answers through it.
        let out = credential_fill_with("https://host.x/a", &chain, |program, args, input| {
            assert_eq!(program, "sh");
            assert_eq!(
                args,
                &["-c".to_owned(), "/bin/shell-helper --fast".to_owned()]
            );
            let text = std::str::from_utf8(input).expect("stdin");
            assert!(text.contains("protocol=https\n"), "{text:?}");
            assert!(text.contains("host=host.x\n"), "{text:?}");
            Some(b"username=carol\npassword=pw\n".to_vec())
        });
        assert_eq!(out, Some(("carol".to_owned(), "pw".to_owned())));
        assert!(scope_matches("https://host.x/sub", "https://host.x/sub/a"));
        assert!(!scope_matches("https://host", "https://hostile.x/a"));
        assert!(!scope_matches("", "https://host.x/a"));
        assert_eq!(classify_helper("~/bin/helper --flag"), {
            let home = std::env::var_os("HOME").map(|home| {
                PathBuf::from(home)
                    .join("bin/helper")
                    .to_string_lossy()
                    .into_owned()
            });
            home.map(|program| (program, vec!["--flag".to_owned()]))
        });
    }

    #[test]
    fn extra_header_rows_keep_file_order_scopes_and_resets() {
        let rows = parse_http_extra_header_entries(
            "[http]\n\textraHeader = X-One: 1\n[http \"https://host.x/sub\"]\n\textraHeader = X-Sub: 2\n\textraHeader =\n[credential]\n\thelper = /bin/top\n[http]\n\textraHeader = X-Two: 2\n",
        );
        assert_eq!(
            rows,
            vec![
                http::ExtraHeaderRow {
                    scope: None,
                    value: "X-One: 1".to_owned(),
                },
                http::ExtraHeaderRow {
                    scope: Some("https://host.x/sub".to_owned()),
                    value: "X-Sub: 2".to_owned(),
                },
                http::ExtraHeaderRow {
                    scope: Some("https://host.x/sub".to_owned()),
                    value: String::new(),
                },
                http::ExtraHeaderRow {
                    scope: None,
                    value: "X-Two: 2".to_owned(),
                },
            ]
        );
        // Section and key match case-insensitively; other sections and keys
        // never leak in.
        let rows = parse_http_extra_header_entries(
            "[HTTP]\n\tEXTRAHEADER = X-Up: yes\n[http]\n\tsslVerify = false\n",
        );
        assert_eq!(
            rows,
            vec![http::ExtraHeaderRow {
                scope: None,
                value: "X-Up: yes".to_owned(),
            }]
        );
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
    fn shell_helper_appends_get_inside_the_sh_dash_c_string() {
        // `sh -c "echo hello get"`: the operation must land inside the
        // `-c` string as one argument, never as an argv element before it.
        let out = run_helper(
            "sh",
            &["-c".to_owned(), "echo hello".to_owned()],
            b"protocol=https\nhost=h\n\n",
        )
        .expect("shell helper answers");
        assert_eq!(String::from_utf8(out).expect("utf8"), "hello get\n");
    }

    #[test]
    fn helper_attempts_are_time_bounded() {
        let started = Instant::now();
        let out = run_helper(
            "/bin/sleep",
            &["30".to_owned()],
            b"protocol=https\nhost=h\n\n",
        );
        assert_eq!(out, None);
        assert!(
            started.elapsed() < HELPER_TIMEOUT + Duration::from_secs(5),
            "helper overran its budget"
        );
    }

    #[test]
    fn config_paths_honor_explicit_environments() {
        let env = vars(&[
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/tmp/cred-test-global"),
        ]);
        assert_eq!(
            config_paths_in(&env),
            vec![PathBuf::from("/tmp/cred-test-global")]
        );
        // An empty global still pins discovery to it, skipping home files.
        let env = vars(&[("GIT_CONFIG_GLOBAL", "")]);
        assert_eq!(config_paths_in(&env), vec![PathBuf::from("/etc/gitconfig")]);
        let env = vars(&[
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("HOME", "/tmp/cred-test-home"),
        ]);
        assert_eq!(
            config_paths_in(&env),
            vec![
                PathBuf::from("/tmp/cred-test-home/.gitconfig"),
                PathBuf::from("/tmp/cred-test-home/.config/git/config"),
            ]
        );
    }

    #[test]
    fn credential_input_parses_to_the_first_blank_line() {
        let desc = parse_credential_input(b"protocol=https\nhost=host.x\n\nusername=late\n");
        assert_eq!(
            desc,
            vec![
                ("protocol".to_owned(), "https".to_owned()),
                ("host".to_owned(), "host.x".to_owned()),
            ]
        );
        // Lines without `=` and empty keys never name a field.
        let desc = parse_credential_input(b"protocol=https\nbare\n=empty\npath=a=b\n\n");
        assert_eq!(
            desc,
            vec![
                ("protocol".to_owned(), "https".to_owned()),
                ("path".to_owned(), "a=b".to_owned()),
            ]
        );
    }

    #[test]
    fn credential_scope_prefers_url_then_components() {
        let desc = vec![
            ("url".to_owned(), "https://host.x/a.git".to_owned()),
            ("protocol".to_owned(), "https".to_owned()),
            ("host".to_owned(), "host.x".to_owned()),
        ];
        assert_eq!(
            credential_scope_url(&desc),
            Some("https://host.x/a.git".to_owned())
        );
        let desc = vec![
            ("protocol".to_owned(), "https".to_owned()),
            ("host".to_owned(), "host.x".to_owned()),
            ("path".to_owned(), "a.git".to_owned()),
        ];
        assert_eq!(
            credential_scope_url(&desc),
            Some("https://host.x/a.git".to_owned())
        );
        let desc = vec![("protocol".to_owned(), "https".to_owned())];
        assert_eq!(credential_scope_url(&desc), None);
    }

    #[test]
    fn credential_desc_fill_merges_the_answer_into_the_description() {
        let desc = vec![
            ("protocol".to_owned(), "https".to_owned()),
            ("host".to_owned(), "host.x".to_owned()),
        ];
        let out = credential_fill_desc_with(
            &desc,
            &[external_helper("/bin/helper")],
            |program, _args, op, input| {
                assert_eq!(program, "/bin/helper");
                assert_eq!(op, "get");
                assert_eq!(input, b"protocol=https\nhost=host.x\n\n");
                Some(b"username=alice\npassword=s3cret\n".to_vec())
            },
        );
        assert_eq!(
            out,
            Some(vec![
                ("protocol".to_owned(), "https".to_owned()),
                ("host".to_owned(), "host.x".to_owned()),
                ("username".to_owned(), "alice".to_owned()),
                ("password".to_owned(), "s3cret".to_owned()),
            ])
        );
        // A helper answer without a username is no answer.
        assert_eq!(
            credential_fill_desc_with(&desc, &[external_helper("/bin/helper")], |_, _, _, _| Some(
                b"password=orphan\n".to_vec()
            )),
            None
        );
    }

    #[test]
    fn injected_auth_debug_redacts_the_secret() {
        let auth = TransportAuth {
            kind: TransportAuthKind::Bearer,
            credential: "tok_s3cret".to_owned(),
            origin: "https://host.x:443".to_owned(),
        };
        let rendered = format!("{auth:?}");
        assert!(rendered.contains("Bearer"), "{rendered:?}");
        assert!(rendered.contains("https://host.x:443"), "{rendered:?}");
        assert!(!rendered.contains("tok_s3cret"), "{rendered:?}");
    }

    #[test]
    fn injected_auth_validate_fails_closed() {
        TransportAuth::none()
            .validate()
            .expect("none carries nothing");
        for auth in [
            TransportAuth {
                kind: TransportAuthKind::Bearer,
                credential: String::new(),
                origin: "https://host.x:443".to_owned(),
            },
            TransportAuth {
                kind: TransportAuthKind::Basic,
                credential: "alice:pw".to_owned(),
                origin: String::new(),
            },
            TransportAuth {
                kind: TransportAuthKind::Bearer,
                credential: "tok".to_owned(),
                origin: "not an origin".to_owned(),
            },
        ] {
            auth.validate().expect_err("half-specified auth must fail");
        }
        TransportAuth {
            kind: TransportAuthKind::Bearer,
            credential: "tok".to_owned(),
            origin: "https://host.x:443".to_owned(),
        }
        .validate()
        .expect("full credential passes");
    }

    #[test]
    fn injected_auth_stays_inside_its_origin() {
        let auth = TransportAuth {
            kind: TransportAuthKind::Basic,
            credential: "alice:pw".to_owned(),
            origin: "https://host.x:443".to_owned(),
        };
        let (name, value) = auth
            .header_for("https://host.x/a.git")
            .expect("same origin sends");
        assert_eq!(name, "authorization");
        assert_eq!(value, "Basic YWxpY2U6cHc=");
        assert_eq!(
            auth.header_for("http://host.x/a.git"),
            None,
            "scheme downgrade drops the credential"
        );
        assert_eq!(
            auth.header_for("https://other.x/a.git"),
            None,
            "cross origin drops the credential"
        );
        assert_eq!(
            auth.header_for("https://alice:pw@host.x/a.git"),
            Some((name.clone(), value.clone())),
            "userinfo in the URL never widens the scope"
        );
        assert_eq!(TransportAuth::none().header_for("https://host.x/a"), None);
    }

    #[test]
    fn injected_auth_origin_of_normalizes_ports() {
        assert_eq!(
            TransportAuth::origin_of("https://host.x/a.git"),
            Some("https://host.x:443".to_owned())
        );
        assert_eq!(
            TransportAuth::origin_of("http://host.x:8080/a"),
            Some("http://host.x:8080".to_owned())
        );
        assert_eq!(TransportAuth::origin_of("ssh://host.x/a"), None);
        assert_eq!(TransportAuth::origin_of("https://"), None);
    }

    #[test]
    fn credential_desc_store_runs_every_helper_with_its_operation() {
        let desc = vec![("protocol".to_owned(), "https".to_owned())];
        let seen = std::sync::Mutex::new(Vec::new());
        credential_store_op_desc_with(
            &desc,
            "store",
            &[external_helper("/bin/a"), external_helper("/bin/b")],
            |program, _, op, _| {
                seen.lock()
                    .expect("seen")
                    .push((program.to_owned(), op.to_owned()));
                None
            },
        );
        assert_eq!(
            seen.lock().expect("seen").as_slice(),
            &[
                ("/bin/a".to_owned(), "store".to_owned()),
                ("/bin/b".to_owned(), "store".to_owned()),
            ]
        );
    }
}
