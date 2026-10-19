//! `remote-helper`: the `git-remote-ruk` transport-helper bridge.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `remote-helper` | `fast-export`/`fast-import` stream subset over the remote-helper stdio protocol | implemented (`import`/`export`/`option` capabilities, `list`/`list for-push`, per-batch `import`, framed `export` with `ok`/`error` statuses; `ruk::` URLs only) |
//!
//! Oracle anchors: `git/Documentation/gitremote-helpers.adoc` (the command
//! grammar), `git/transport-helper.c` (`fetch_with_import` for the `import`
//! batch shape, `push_refs_with_export` for the `export` stream plus the
//! `ok`/`error` status report, `get_remote_heads` for the `list` grammar),
//! `git/transport.c:transport_get` for the `<transport>::<address>` split.
//!
//! A stock `git` running `git clone ruk::/path/to/repo` (or
//! `git fetch`/`git push` against a `ruk::` remote) spawns this binary as
//! `git-remote-ruk <remote> <address>` on `PATH` and speaks the
//! remote-helper protocol on stdio. The helper bridges that wire to the
//! native store with the two verbs that already round-trip history:
//! `import` batches are answered with a `fast-export` stream (which git
//! feeds to its own `fast-import`), and `export` payloads (a stock
//! `fast-export` stream) are applied with the `fast-import` parser.
//!
//! Divergences from the oracles:
//! - Only `ruk::` (local-path) URLs resolve; anything else is `NotFound`
//!   naming the path. There is deliberately no `fetch`/`push` (pack) or
//!   `connect` capability, so git always takes the `import`/`export` path.
//! - `connect` is advertised first, so stock git takes the native pack
//!   protocol for every fetch and push: `connect git-upload-pack` and
//!   `connect git-receive-pack` spawn the matching serve verb
//!   (`upload-pack`/`receive-pack` over the same `<dir>`) as a child and
//!   proxy stdio both ways until EOF, exactly like `git-remote-ext`
//!   proxies its `ext::` command. Packs carry exact objects with full
//!   parentage, so oids survive the round trip bit-for-bit (including
//!   merges, whose dropped-`from` fast-export form cannot). The
//!   `import`/`export` path stays as the fallback git takes when `connect`
//!   answers `fallback` or dies.
//! - Two refspecs are advertised, `refs/heads/*:refs/ruk/<alias>/heads/*`
//!   and `refs/tags/*:refs/ruk/<alias>/tags/*`, with `<alias>` derived
//!   from the helper URL (or `_`). They matter on the fallback path and
//!   for push: stock `push` dies without at least one `refspec`
//!   capability (`push_refs_with_export` checks the set before exporting),
//!   and its `^<private>` exclusion assumes the private ref tracks the
//!   remote state. `import` streams rewrite branch and tag names into the
//!   namespace; a fetch therefore never touches same-named local
//!   branches, and remote-tracking refs still update from `FETCH_HEAD`.
//!   Keeping every imported name inside the namespace also keeps the
//!   stock side's first ref transaction empty: a real-named tag written
//!   during a clone trips git's empty-repo fast path (`initial ref
//!   transaction called with existing refs`).
//!
//! Fallback fidelity limit: stock fast-export omits `from`/`merge` lines
//! for rev-list-excluded parents, so an incremental fallback push stores
//! parentless (re-oided) commits. The `connect` path never has this
//! shape; the fallback reports success per applied ref regardless.
//! - Refs outside `refs/heads/*` and `refs/tags/*` ride `import` streams
//!   under their real names (neither refspec has an opinion on them),
//!   matching the old implied-`*:*` behavior for notes, stash, and
//!   replacement refs.
//! - `option depth` (and the other `deepen-*` spellings) is accepted and
//!   ignored: the import always carries full history, never a shallow
//!   boundary. `option dry-run true` skips the store write but still
//!   reports `ok` per touched ref.
//! - `check-connectivity` is not advertised, so no `connectivity-ok` line
//!   is ever emitted; every emitted stream is self-contained by
//!   construction (the exporter walks the full closure).
//! - A stock `fast-export` delete (`reset <ref>` from the all-zero oid)
//!   is normalized to a bare `reset <ref>`, which the importer already
//!   applies as a ref deletion.
//! - Pushes overwrite refs unconditionally (the importer's own rule, the
//!   same contract every `export`-capable helper offers): non-fast-forward
//!   protection is git's client-side check in `builtin/push.c`, which
//!   refuses before the helper is ever invoked unless `--force` is given.
//! - An `import` batch naming only unknown or unexportable refs answers
//!   `done` alone (an empty fast-import, a no-op), so cloning an empty
//!   store warns instead of failing. Tag-only batches ride on a carrier
//!   branch (`HEAD`'s, else the first) because the exporter needs a
//!   named ref to hang history on. `list` advertises only refs the
//!   exporter can emit (commits and tags peeling to commits); anything
//!   else in the store stays invisible to the stock side.
//! - `signed-tags` is not advertised, so pushes arrive with signatures
//!   stripped (`warn-strip`), matching what the importer parses.
//!
//! Consistency: each command opens the store anew, so every `list` and
//! `import` reads at a per-command snapshot (snapshot isolation within a
//! command, no linearizability across the session: a concurrent writer
//! may land between our `list` and the `import` batch, and the batch then
//! carries the newer history). Each `export` batch applies in the
//! importer's single store transaction, so a push batch is all-or-nothing.
//! Both directions are idempotent for a retrying caller: re-importing a
//! batch replays the same commits under the same refs, and re-exporting
//! overwrites the same refs with the same values.

use std::io::{BufRead, Write as _};
use std::path::PathBuf;

use ruk_core::ids::HashKind;
use ruk_core::refdata::{RefName, RefRead as _, RefTarget};
use ruk_core::store::{ObjectKind, Store};
use ruk_git::GitError;
use ruk_git::transport::session::open_local_store;

use super::state::{MAX_OBJECT_BYTES, commit_record, list_refs, load_or_default, open_store_at};
use super::tree::read_object_bytes;
use super::{CliEnv, Ctx, verbs_fastio};

/// Argv[0] basename stock git spawns for `ruk::` URLs.
const HELPER_ARG0: &str = "git-remote-ruk";

/// Symbolic hops followed when an `import` name is itself a symref.
const MAX_SYMREF_HOPS: usize = 32;

/// Longest command line accepted from the peer (1 MiB).
///
/// Every stdio hop is bounded: command lines by this cap, `data` blocks
/// by [`MAX_OBJECT_BYTES`]. An unbounded `read_until` would let one slow
/// or corrupt peer grow memory without limit; past either cap the session
/// fails closed with `Limit`.
const MAX_COMMAND_LINE: usize = 1 << 20;

/// Chunk size for bounded `data` block copies.
const DATA_COPY_CHUNK: u64 = 64 << 10;

/// One helper session: the remote store root plus the protocol options
/// set so far. The store is opened per command (cheap, and every command
/// then sees the previous command's writes).
#[derive(Clone, Debug)]
pub(crate) struct HelperSession {
    /// Repository root holding `.ruk/` (resolved from the helper URL).
    pub(crate) root: PathBuf,
    /// Environment carried for identity fallback inside `fast-import`.
    pub(crate) env: CliEnv,
    /// `option dry-run true`: parse and report, never publish.
    pub(crate) dry_run: bool,
    /// Private-namespace alias from the helper URL (or `_`).
    pub(crate) alias: String,
}

/// Runs `ruk remote-helper <remote> [<url>]` against captured stdin.
///
/// The verb form of the helper: `<remote>` names the remote (or doubles as
/// the URL for a direct `ruk remote-helper <url>` call), `<url>` defaults
/// to `<remote>`. The protocol exchange reads `stdin` and the reply bytes
/// return on stdout, so the verb stays testable without descriptors.
pub(crate) fn remote_helper(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let mut positionals: Vec<&str> = Vec::new();
    for arg in args {
        if arg == "--" {
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            return Err(GitError::Usage {
                detail: "usage: remote-helper <remote> [<url>]".to_owned(),
            });
        }
        positionals.push(arg);
    }
    let (remote, url) = match positionals.as_slice() {
        [] => {
            return Err(GitError::Usage {
                detail: "usage: remote-helper <remote> [<url>]".to_owned(),
            });
        }
        [only] => (*only, *only),
        [remote, url] => (*remote, *url),
        _ => {
            return Err(GitError::Usage {
                detail: "usage: remote-helper <remote> [<url>]".to_owned(),
            });
        }
    };
    let input = super::read_stdin_bytes(&ctx.env)?;
    let root = helper_root(&ctx.env, url)?;
    // Fail fast on an unresolvable URL before reading any commands.
    open_helper_store(&root)?;
    let mut session = HelperSession {
        root,
        env: ctx.env.clone(),
        dry_run: false,
        alias: helper_alias(url, remote),
    };
    let mut reader = std::io::BufReader::new(input.as_slice());
    let mut out = Vec::new();
    serve_commands(&mut session, &mut reader, &mut out)?;
    Ok(out)
}

/// Matches argv[0] against the helper name git spawns for `ruk::` URLs.
///
/// Returns the `(remote, url)` pair from argv when this binary was invoked
/// as `git-remote-ruk` (a `PATH` symlink to `ruk` suffices), else `None`
/// so `main` falls through to the normal dispatches.
#[must_use]
pub(crate) fn remote_helper_argv0(argv: &[String]) -> Option<(String, String)> {
    let invoked = argv
        .first()
        .and_then(|arg0| std::path::Path::new(arg0).file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == HELPER_ARG0);
    if !invoked {
        return None;
    }
    match argv {
        [_, remote, url, ..] => Some((remote.clone(), url.clone())),
        [_, only] => Some((only.clone(), only.clone())),
        _ => None,
    }
}

/// Runs the live stdio loop for an argv[0] helper invocation.
///
/// Owns both descriptors the way the protocol demands: commands stream in
/// incrementally (a batch never waits for EOF) and every response flushes
/// before git blocks reading it.
pub(crate) fn run_remote_helper(remote: String, url: String) -> std::process::ExitCode {
    use std::process::ExitCode;

    let env = CliEnv::capture();
    let root = match helper_root(&env, &url) {
        Ok(root) => root,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "ruk {HELPER_ARG0}: {err}");
            return ExitCode::from(err.exit_code());
        }
    };
    if let Err(err) = open_helper_store(&root) {
        let _ = writeln!(std::io::stderr(), "ruk {HELPER_ARG0}: {err}");
        return ExitCode::from(err.exit_code());
    }
    let mut session = HelperSession {
        root,
        env,
        dry_run: false,
        alias: helper_alias(&url, &remote),
    };
    // Handle-level descriptors, never held locks: `BufReader<Stdin>` and
    // `Stdout` lock internally per call and are both `Send`, so the
    // `connect` proxy may borrow them on scoped threads. Holding
    // `stdin.lock()`/`stdout.lock()` across the session would deadlock
    // those threads on the global locks.
    let mut reader = std::io::BufReader::new(std::io::stdin());
    let mut writer = std::io::stdout();
    match serve_commands(&mut session, &mut reader, &mut writer) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "ruk {HELPER_ARG0}: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}

/// Derives the private-namespace alias from the helper address.
///
/// The address (argv[1], stable across clone/fetch/push for one remote)
/// sanitizes to `[A-Za-z0-9-]` runs, trimmed and capped; anything
/// unusable falls back to the remote name when it is already ref-safe,
/// else `_`. Two addresses can sanitize alike, but that only costs a
/// full-history send: the importer still refuses unresolvable parents
/// loudly instead of publishing a corrupt closure.
fn helper_alias(url: &str, remote: &str) -> String {
    let stripped = url
        .strip_prefix("ruk::")
        .or_else(|| url.strip_prefix("ruk://"))
        .unwrap_or(url);
    let mut token = String::with_capacity(stripped.len());
    for char in stripped.chars() {
        if char.is_ascii_alphanumeric() {
            token.push(char);
        } else if !token.ends_with('-') {
            token.push('-');
        }
    }
    let trimmed = token.trim_matches('-');
    let capped = trimmed
        .char_indices()
        .nth(48)
        .map_or(trimmed, |(index, _)| &trimmed[..index]);
    if !capped.is_empty()
        && RefName::new(format!("refs/ruk/{capped}/heads/main")).is_ok()
    {
        return capped.to_owned();
    }
    if !remote.is_empty()
        && remote
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        && RefName::new(format!("refs/ruk/{remote}/heads/main")).is_ok()
    {
        return remote.to_owned();
    }
    "_".to_owned()
}

/// Maps one advertised ref to the full name the `import` stream must
/// carry for `commit`/`reset` lines: branches move under
/// `refs/ruk/<alias>/heads/`, tags under `refs/tags/ruk/<alias>/`.
///
/// Bare tag names resolve against `refs/tags/` first, mirroring the
/// importer (both emitters spell lightweight resets full but annotated
/// tags short), so `reset refs/tags/v2` maps exactly like a bare tag
/// would. `tag` command lines take a separate short spelling (see the
/// `tag` arm in [`remap_stream`]): stock fast-import prefixes every
/// `tag` name with `refs/tags/`, so only short names survive it.
fn map_import_name(session: &HelperSession, name: &str) -> String {
    let resolved;
    let full = if name.starts_with("refs/") {
        name
    } else {
        resolved = format!("refs/tags/{name}");
        &resolved
    };
    if let Some(rest) = full
        .strip_prefix("refs/heads/")
        .filter(|rest| !rest.is_empty())
    {
        return format!("refs/ruk/{}/heads/{rest}", session.alias);
    }
    if let Some(rest) = full
        .strip_prefix("refs/tags/")
        .filter(|rest| !rest.is_empty())
    {
        return format!("refs/tags/ruk/{}/{rest}", session.alias);
    }
    name.to_owned()
}

/// Strips the `ruk::` (or bare `ruk://`) scheme to a repository root.
///
/// Git already strips `<transport>::` before spawning the helper
/// (`remove_ext_force`), so the address usually arrives bare; both
/// spellings are still accepted so direct `ruk remote-helper` calls take
/// the same URLs. Relative paths resolve against the caller's cwd.
fn helper_root(env: &CliEnv, url: &str) -> Result<PathBuf, GitError> {
    let path = url
        .strip_prefix("ruk::")
        .or_else(|| url.strip_prefix("ruk://"))
        .unwrap_or(url);
    let candidate = PathBuf::from(path);
    if candidate.as_os_str().is_empty() {
        return Err(GitError::NotFound {
            detail: "empty ruk remote URL".to_owned(),
        });
    }
    Ok(if candidate.is_absolute() {
        candidate
    } else {
        env.cwd.join(candidate)
    })
}

/// Opens the remote native store at one resolved root.
///
/// Mirrors the serve verbs' fallback: a repository root holding `.ruk`
/// first, then whatever `open_local_store` recognizes (a bare store
/// directory), so both layouts answer the helper.
fn open_helper_store(root: &PathBuf) -> Result<Store, GitError> {
    match open_store_at(root) {
        Ok(store) => Ok(store),
        Err(first) => match open_local_store(root) {
            Ok(store) => Ok(store),
            Err(_) => Err(first),
        },
    }
}

/// Builds the per-command context over the remote store for the
/// `fast-export`/`fast-import` verbs, which borrow the store they serve.
fn helper_ctx(session: &HelperSession, store: Store) -> Result<Ctx, GitError> {
    let kind = store.hash_kind();
    Ok(Ctx {
        store: Some(store),
        root: session.root.clone(),
        file_base: session.root.clone(),
        kind: Some(kind),
        env: session.env.clone(),
        bare: true,
        cli_config: Vec::new(),
        stderr: Vec::new(),
    })
}

/// Runs the command loop until EOF: git closes our stdin on disconnect.
///
/// `reader` must stay incremental (never read to EOF first): an `export`
/// payload shares the pipe with later commands, and an `import` answer
/// must flush before git sends anything else.
pub(crate) fn serve_commands<R: BufRead + Send, W: std::io::Write + Send>(
    session: &mut HelperSession,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), GitError> {
    let mut line = Vec::new();
    loop {
        if read_line_capped(reader, &mut line)? == 0 {
            return Ok(());
        }
        let command = command_text(&line);
        if command.is_empty() {
            continue;
        }
        if command == "capabilities" {
            // The private-namespace refspec keeps pushed history
            // incremental (`push_refs_with_export` excludes from the
            // private ref) and fetches off local branches; stock `push`
            // dies without at least one `refspec` capability.
            writer
                .write_all(
                    format!(
                        "connect\nimport\nexport\nrefspec refs/heads/*:refs/ruk/{0}/heads/*\nrefspec refs/tags/*:refs/tags/ruk/{0}/*\noption\nobject-format\n\n",
                        session.alias
                    )
                    .as_bytes(),
                )
                .map_err(io_error)?;
            writer.flush().map_err(io_error)?;
        } else if command == "list" || command == "list for-push" {
            emit_list(session, writer)?;
        } else if let Some(rest) = command.strip_prefix("option ") {
            run_option(session, rest, writer)?;
        } else if let Some(name) = command.strip_prefix("import ") {
            run_import_batch(session, name, reader, writer)?;
        } else if command == "export" {
            run_export(session, reader, writer)?;
        } else if let Some(service) = command.strip_prefix("connect ") {
            run_connect(session, service, reader, writer)?;
            // The pack connection owns both descriptors from here: the
            // helper exits when it ends, per the protocol.
            return Ok(());
        } else {
            return Err(GitError::Unsupported {
                command: format!("remote-helper command {command:?}"),
            });
        }
    }
}

/// Strips one `\n` (or `\r\n`) terminator for command matching.
fn command_text(line: &[u8]) -> &str {
    let mut bytes = line;
    if bytes.last() == Some(&b'\n') {
        bytes = &bytes[..bytes.len() - 1];
    }
    if bytes.last() == Some(&b'\r') {
        bytes = &bytes[..bytes.len() - 1];
    }
    std::str::from_utf8(bytes).unwrap_or("")
}

/// Answers `option <name> <value>` with `ok` or `unsupported`.
///
/// Only `dry-run` changes session behavior; depth and its `deepen-*`
/// family are accepted and ignored (the import always carries full
/// history), and every other known git option is accepted as inert.
fn run_option<W: std::io::Write>(
    session: &mut HelperSession,
    rest: &str,
    writer: &mut W,
) -> Result<(), GitError> {
    let (name, value) = rest
        .split_once(' ')
        .map(|(name, value)| (name, unquote_option(value)))
        .unwrap_or((rest, String::new()));
    let known = matches!(
        name,
        "verbosity"
            | "progress"
            | "depth"
            | "deepen-since"
            | "deepen-not"
            | "deepen-relative"
            | "followtags"
            | "dry-run"
            | "servpath"
            | "check-connectivity"
            | "force"
            | "cloning"
            | "update-shallow"
            | "pushcert"
            | "push-option"
            | "from-promisor"
            | "no-dependents"
            | "atomic"
            | "family"
            | "object-format"
    );
    if !known {
        writer.write_all(b"unsupported\n").map_err(io_error)?;
        writer.flush().map_err(io_error)?;
        return Ok(());
    }
    if name == "dry-run" {
        session.dry_run = matches!(value.as_str(), "true" | "1" | "yes");
    }
    writer.write_all(b"ok\n").map_err(io_error)?;
    writer.flush().map_err(io_error)?;
    Ok(())
}

/// Unquotes one C-style option value (`option` sends quoted values).
fn unquote_option(value: &str) -> String {
    let quoted = value.strip_prefix('"').and_then(|inner| inner.strip_suffix('"'));
    let Some(inner) = quoted else {
        return value.to_owned();
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(char) = chars.next() {
        if char != '\\' {
            out.push(char);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some(next) => out.push(next),
            None => out.push('\\'),
        }
    }
    out
}

/// Answers `list` with one `<oid> <name>` row per exportable ref, the
/// `HEAD` symref when it resolves, and the `:object-format` keyword.
///
/// Mirrors `transport-helper.c:get_remote_heads`: `@<dest> HEAD` carries
/// the symref, `?` rows are never emitted (unresolvable refs are skipped
/// instead), attributes are absent, and a blank line ends the list.
fn emit_list<W: std::io::Write>(session: &HelperSession, writer: &mut W) -> Result<(), GitError> {
    let store = open_helper_store(&session.root)?;
    let kind = store.hash_kind();
    writer
        .write_all(format!(":object-format {}\n", algo_name(kind)).as_bytes())
        .map_err(io_error)?;
    let (workspace, _) = load_or_default(&store)?;
    match &workspace.head {
        ruk_core::workspace::HeadRef::Symbolic(name) => {
            let text = String::from_utf8_lossy(name.as_bytes()).into_owned();
            if head_target_listed(&store, &text)? {
                writer
                    .write_all(format!("@{text} HEAD\n").as_bytes())
                    .map_err(io_error)?;
            }
        }
        ruk_core::workspace::HeadRef::Detached(oid) => {
            if *oid != kind.zero_oid()
                && let Ok(record) = commit_record(&store, *oid)
            {
                let _ = record;
                writer
                    .write_all(format!("{} HEAD\n", oid.to_hex()).as_bytes())
                    .map_err(io_error)?;
            }
        }
    }
    for (name, target) in list_refs(&store)? {
        let text = String::from_utf8_lossy(name.as_bytes()).into_owned();
        match target {
            RefTarget::Direct(oid) => {
                if is_exportable(&store, oid) {
                    writer
                        .write_all(format!("{} {text}\n", oid.to_hex()).as_bytes())
                        .map_err(io_error)?;
                }
            }
            RefTarget::Symbolic(dest) => {
                writer
                    .write_all(
                        format!(
                            "@{} {text}\n",
                            String::from_utf8_lossy(dest.as_bytes())
                        )
                        .as_bytes(),
                    )
                    .map_err(io_error)?;
            }
        }
    }
    writer.write_all(b"\n").map_err(io_error)?;
    writer.flush().map_err(io_error)?;
    Ok(())
}

/// Reports whether the `HEAD` target names a ref `list` will advertise.
///
/// Advertising an unborn `HEAD` target poisons empty clones (git would
/// `import` a ref that cannot export), so an unborn head stays silent and
/// the list simply carries no `HEAD` row.
fn head_target_listed(store: &Store, target: &str) -> Result<bool, GitError> {
    let Ok(name) = RefName::new(target) else {
        return Ok(false);
    };
    let refs = ruk_core::refs::StoreRefs::new(store);
    match refs.get(&name).map_err(ref_error)? {
        Some(RefTarget::Direct(oid)) => Ok(is_exportable(store, oid)),
        Some(RefTarget::Symbolic(_)) => Ok(true),
        None => Ok(false),
    }
}

/// Reports whether one oid can ride an `import` stream: a commit, or a
/// tag object peeling to one (the exporter's own `classify_tag_ref`
/// rule, so `list` and the stream never disagree).
fn is_exportable(store: &Store, oid: ruk_core::ids::Oid) -> bool {
    if commit_record(store, oid).is_ok() {
        return true;
    }
    let Ok((ObjectKind::Tag, payload)) = read_object_bytes(store, oid) else {
        return false;
    };
    tag_target(&payload).is_some_and(|target| commit_record(store, target).is_ok())
}

/// Reads the `object <hex>` line of an annotated tag payload.
fn tag_target(payload: &[u8]) -> Option<ruk_core::ids::Oid> {
    for line in payload.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix(b"object ") {
            let text = std::str::from_utf8(rest).ok()?;
            return text.parse::<ruk_core::ids::Oid>().ok();
        }
    }
    None
}

/// Answers one `import` batch (`import <ref>` lines, blank-terminated)
/// with a single `fast-export` stream ending in `done`.
///
/// `first` is the `import` line that opened the batch; the remaining
/// lines (plus the terminating blank) stream from `reader`, the way
/// `fetch_with_import` writes them before waiting on fast-import.
fn run_import_batch<R: BufRead, W: std::io::Write>(
    session: &mut HelperSession,
    first: &str,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), GitError> {
    let mut names = vec![first.to_owned()];
    let mut line = Vec::new();
    loop {
        if read_line_capped(reader, &mut line)? == 0 {
            return Ok(());
        }
        let text = command_text(&line);
        if text.is_empty() {
            break;
        }
        if let Some(name) = text.strip_prefix("import ") {
            names.push(name.to_owned());
            continue;
        }
        return Err(GitError::Unsupported {
            command: format!("remote-helper import batch line {text:?}"),
        });
    }
    let store = open_helper_store(&session.root)?;
    let mut exportable: Vec<String> = Vec::new();
    for name in &names {
        if let Some(resolved) = resolve_import_name(&store, name)?
            && !exportable.contains(&resolved)
        {
            exportable.push(resolved);
        }
    }
    if exportable.is_empty() {
        // Nothing to emit (an unborn `HEAD` target on an empty store):
        // `done` alone is an empty fast-import, a silent no-op.
        writer.write_all(b"done\n").map_err(io_error)?;
        writer.flush().map_err(io_error)?;
        return Ok(());
    }
    if !exportable.iter().any(|name| name.starts_with("refs/heads/")) {
        // Tag-only batches name no exporting branch ref, which the
        // exporter refuses: carry the tag history on the `HEAD` branch
        // (else the first branch), whose commits land harmlessly in the
        // private namespace while giving the tag blocks history to
        // point at. No branches at all stays an honest error below.
        if let Some(carrier) = carrier_branch(&store)? {
            exportable.insert(0, carrier);
        }
    }
    let mut ctx = helper_ctx(session, store)?;
    let stream = verbs_fastio::fast_export(&mut ctx, &exportable)?;
    let stream = remap_stream(&stream, session)?;
    writer.write_all(&stream).map_err(io_error)?;
    writer.flush().map_err(io_error)?;
    Ok(())
}

/// Picks one branch to carry a tag-only batch: the `HEAD` target when
/// it resolves to an exportable branch, else the first exportable
/// branch in ref order.
fn carrier_branch(store: &Store) -> Result<Option<String>, GitError> {
    let (workspace, _) = load_or_default(store)?;
    let mut candidates: Vec<String> = Vec::new();
    if let ruk_core::workspace::HeadRef::Symbolic(name) = &workspace.head {
        candidates.push(String::from_utf8_lossy(name.as_bytes()).into_owned());
    }
    for (name, target) in list_refs(store)? {
        if !matches!(target, RefTarget::Direct(_)) {
            continue;
        }
        let text = String::from_utf8_lossy(name.as_bytes()).into_owned();
        if text.starts_with("refs/heads/") && !candidates.contains(&text) {
            candidates.push(text);
        }
    }
    for candidate in &candidates {
        if let Some(resolved) = resolve_import_name(store, candidate)? {
            return Ok(Some(resolved));
        }
    }
    Ok(None)
}

/// Resolves one `import` name to the full ref the exporter takes.
///
/// Symref hops resolve to their terminal (capped, like the serve-side
/// chain reads); missing or unexportable names resolve to `None` and the
/// caller skips them.
fn resolve_import_name(store: &Store, name: &str) -> Result<Option<String>, GitError> {
    let Ok(mut current) = RefName::new(name) else {
        return Ok(None);
    };
    let refs = ruk_core::refs::StoreRefs::new(store);
    for _ in 0..=MAX_SYMREF_HOPS {
        match refs.get(&current).map_err(ref_error)? {
            None => return Ok(None),
            Some(RefTarget::Direct(oid)) => {
                if !is_exportable(store, oid) {
                    return Ok(None);
                }
                return Ok(Some(
                    String::from_utf8_lossy(current.as_bytes()).into_owned(),
                ));
            }
            Some(RefTarget::Symbolic(dest)) => current = dest,
        }
    }
    Err(GitError::Invalid {
        detail: format!("import ref {name:?} exceeds the symref hop limit"),
    })
}

/// Applies one `export` payload: the framed fast-import stream git's own
/// `fast-export` wrote to our stdin, then `ok`/`error` per touched ref.
///
/// Mirrors `push_refs_with_export` plus `push_update_refs_status`: the
/// status report (one line per ref, blank-terminated) is what git reads
/// after its exporter exits.
fn run_export<R: BufRead, W: std::io::Write>(
    session: &mut HelperSession,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), GitError> {
    let mut stream = Vec::new();
    let mut touched: Vec<String> = Vec::new();
    read_stream(reader, &mut stream, &mut touched)?;
    if !session.dry_run {
        let store = open_helper_store(&session.root)?;
        let mut ctx = helper_ctx(session, store)?;
        ctx.env.stdin = Some(stream);
        if let Err(err) = verbs_fastio::fast_import(&mut ctx, &[]) {
            let reason = err.to_string().replace(['\n', '\r'], " ");
            for name in &touched {
                writer
                    .write_all(format!("error {name} {reason}\n").as_bytes())
                    .map_err(io_error)?;
            }
            writer.write_all(b"\n").map_err(io_error)?;
            writer.flush().map_err(io_error)?;
            return Err(err);
        }
    }
    for name in &touched {
        writer
            .write_all(format!("ok {name}\n").as_bytes())
            .map_err(io_error)?;
    }
    writer.write_all(b"\n").map_err(io_error)?;
    writer.flush().map_err(io_error)?;
    Ok(())
}

/// Reads one framed fast-import stream through its top-level `done`.
///
/// `data <n>` blocks (and `data <<marker` heredocs) copy verbatim so a
/// `done` line inside blob or message bytes never ends the stream early;
/// every other line passes through untouched except a stock delete
/// spelling (`from` the all-zero oid), which is dropped so the bare
/// `reset` deletes the ref. Top-level `commit`/`reset`/`tag` names feed
/// `touched` (order-preserving, deduplicated) for the status report.
fn read_stream<R: BufRead>(
    reader: &mut R,
    out: &mut Vec<u8>,
    touched: &mut Vec<String>,
) -> Result<(), GitError> {
    let mut line = Vec::new();
    loop {
        if read_line_capped(reader, &mut line)? == 0 {
            return Err(GitError::Invalid {
                detail: "export stream ended before done".to_owned(),
            });
        }
        let text = command_text(&line);
        if text == "done" {
            out.extend_from_slice(b"done\n");
            return Ok(());
        }
        if is_data_header(text) {
            out.extend_from_slice(&line);
            copy_data_block(reader, text, out)?;
            continue;
        }
        if is_zero_from(text) {
            continue;
        }
        if let Some(name) = top_ref_command(text)
            && !touched.iter().any(|seen| seen == name)
        {
            touched.push(name.to_owned());
        }
        out.extend_from_slice(&line);
    }
}

/// Reads one `\n`-terminated line, capped at [`MAX_COMMAND_LINE`].
///
/// Returns the byte count (zero at EOF). Chunked `fill_buf`/`consume`
/// keeps the bound before the bytes accumulate, instead of detecting the
/// overflow after an unbounded `read_until`.
fn read_line_capped<R: BufRead>(reader: &mut R, buf: &mut Vec<u8>) -> Result<usize, GitError> {
    buf.clear();
    let mut total = 0usize;
    loop {
        let chunk_len;
        let newline_at;
        {
            let chunk = reader.fill_buf().map_err(io_error)?;
            if chunk.is_empty() {
                return Ok(total);
            }
            newline_at = chunk.iter().position(|byte| *byte == b'\n');
            chunk_len = newline_at.map_or(chunk.len(), |pos| pos + 1);
            if total.saturating_add(chunk_len) > MAX_COMMAND_LINE {
                return Err(GitError::Limit {
                    detail: format!(
                        "helper command line exceeds {MAX_COMMAND_LINE} bytes"
                    ),
                });
            }
            buf.extend_from_slice(&chunk[..chunk_len]);
        }
        reader.consume(chunk_len);
        total += chunk_len;
        if newline_at.is_some() {
            return Ok(total);
        }
    }
}

/// Rewrites one exported stream's top-level branch and tag names into
/// the private namespace, copying `data` blocks verbatim so payload
/// bytes never confuse the scan.
///
/// Only lines [`map_import_name`] moves are rewritten (`commit`,
/// `reset`, and `tag` alike); anything else passes through untouched. A
/// corrupt stream (truncated `data`) fails closed instead of emitting a
/// half-renamed script.
fn remap_stream(stream: &[u8], session: &HelperSession) -> Result<Vec<u8>, GitError> {
    let mut out = Vec::with_capacity(stream.len());
    let mut cursor = stream;
    while !cursor.is_empty() {
        let end = cursor
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(cursor.len(), |pos| pos + 1);
        let (line, rest) = cursor.split_at(end);
        cursor = rest;
        let text = command_text(line);
        if text == "done" {
            out.extend_from_slice(b"done\n");
            return Ok(out);
        }
        if is_data_header(text) {
            out.extend_from_slice(line);
            copy_data_slice(&mut cursor, text, &mut out)?;
            continue;
        }
        // `commit` and `reset` lines take full refnames, which both
        // importers accept verbatim; `tag` lines must stay short because
        // stock fast-import prefixes the name with `refs/tags/` itself,
        // so a full mapped tag name would land doubled.
        let mut rewritten = false;
        if let Some(name) = text
            .strip_prefix("commit ")
            .or_else(|| text.strip_prefix("reset "))
        {
            let prefix = if text.starts_with("commit ") {
                "commit "
            } else {
                "reset "
            };
            let mapped = map_import_name(session, name);
            if mapped != name {
                out.extend_from_slice(prefix.as_bytes());
                out.extend_from_slice(mapped.as_bytes());
                out.push(b'\n');
                rewritten = true;
            }
        } else if let Some(name) = text.strip_prefix("tag ") {
            let rest = name.strip_prefix("refs/tags/").unwrap_or(name);
            let in_tag_space =
                !name.starts_with("refs/") || name.starts_with("refs/tags/");
            let already = rest
                .strip_prefix("ruk/")
                .and_then(|tail| tail.strip_prefix(session.alias.as_str()))
                .and_then(|tail| tail.strip_prefix('/'));
            if in_tag_space && !rest.is_empty() && already.is_none() {
                out.extend_from_slice(b"tag ");
                out.extend_from_slice(
                    format!("ruk/{}/{}", session.alias, rest).as_bytes(),
                );
                out.push(b'\n');
                rewritten = true;
            }
        }
        if !rewritten {
            out.extend_from_slice(line);
            if !line.ends_with(b"\n") {
                out.push(b'\n');
            }
        }
    }
    Err(GitError::Invalid {
        detail: "export stream ended before done".to_owned(),
    })
}

/// Copies one `data` block from a byte slice, advancing the cursor past
/// it. Mirrors [`copy_data_block`] for already-buffered streams.
fn copy_data_slice(
    cursor: &mut &[u8],
    header: &str,
    out: &mut Vec<u8>,
) -> Result<(), GitError> {
    if let Some(marker) = header.strip_prefix("data<<") {
        if marker.is_empty() {
            return Err(GitError::Invalid {
                detail: "data heredoc needs a marker".to_owned(),
            });
        }
        loop {
            let end = cursor
                .iter()
                .position(|byte| *byte == b'\n')
                .ok_or_else(|| GitError::Invalid {
                    detail: "export stream ended inside a data heredoc".to_owned(),
                })?;
            let (line, rest) = cursor.split_at(end + 1);
            *cursor = rest;
            out.extend_from_slice(line);
            if command_text(line) == marker {
                return Ok(());
            }
        }
    }
    let digits = header.strip_prefix("data ").unwrap_or(header);
    let count: u64 = digits.parse().map_err(|_| GitError::Invalid {
        detail: format!("bad data length {digits:?}"),
    })?;
    if count > MAX_OBJECT_BYTES {
        return Err(GitError::Limit {
            detail: format!("data block of {count} bytes exceeds the object bound"),
        });
    }
    let width = usize::try_from(count).map_err(|_| GitError::Limit {
        detail: "data block does not fit in memory".to_owned(),
    })?;
    if cursor.len() < width {
        return Err(GitError::Invalid {
            detail: "export stream ended inside a data block".to_owned(),
        });
    }
    let (body, rest) = cursor.split_at(width);
    out.extend_from_slice(body);
    *cursor = rest;
    Ok(())
}

/// Serves one `connect <service>` command by proxying the native pack
/// protocol to the matching serve verb as a child process.
///
/// Maps `git-upload-pack` to `ruk upload-pack <dir>` (fetch) and
/// `git-receive-pack` to `ruk receive-pack <dir>` (push), spawned from
/// the current executable so a `PATH` symlink keeps working. Replies
/// with the empty line (connected), then pumps the caller-side reader
/// to the child and the child to the caller-side writer on two scoped
/// threads until both directions hit EOF — the same full-duplex shape
/// `git-remote-ext` runs for `ext::` commands. Borrowing the live
/// reader (instead of re-locking global stdio, which the session
/// already holds and would deadlock) also drains any bytes the caller
/// buffered ahead. The child inherits stderr, so serve-side diagnostics
/// reach the terminal. Returns after the connection ends (the helper
/// exits); a nonzero child status surfaces as `Io`.
///
/// The request/response lockstep guarantees no pipelined bytes sit past
/// the command line: git waits for this reply before emitting any
/// protocol bytes.
///
/// # Errors
/// [`GitError::Unsupported`] for unknown services, [`GitError::Io`] for
/// spawn, proxy, or serve-child failures.
fn run_connect<R: std::io::BufRead + Send, W: std::io::Write + Send>(
    session: &HelperSession,
    service: &str,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), GitError> {
    let verb = match service {
        "git-upload-pack" => "upload-pack",
        "git-receive-pack" => "receive-pack",
        _ => {
            return Err(GitError::Unsupported {
                command: format!("remote-helper connect service {service:?}"),
            });
        }
    };
    let exe = std::env::current_exe().map_err(io_error)?;
    let mut child = std::process::Command::new(exe)
        .arg(verb)
        .arg(session.root.as_os_str())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(io_error)?;
    writer.write_all(b"\n").map_err(io_error)?;
    writer.flush().map_err(io_error)?;
    let mut stdin = child.stdin.take().ok_or_else(|| GitError::Io {
        detail: "pack server stdin is unavailable".to_owned(),
    })?;
    let mut stdout = child.stdout.take().ok_or_else(|| GitError::Io {
        detail: "pack server stdout is unavailable".to_owned(),
    })?;
    // Two pumps, one per direction: either side may stream while the
    // other idles (pack negotiation interleaves reads and writes), so a
    // single half-duplex copy would stall. Each chunk flushes on the
    // server-to-caller leg; without it block buffering holds pack bytes
    // back and both ends wait forever. Scoped threads borrow the live
    // descriptors (owned by this call, joined before it returns), so no
    // pump outlives the connection and a panic still joins its sibling.
    std::thread::scope(|scope| {
        let uplink = scope.spawn(|| pump(reader, &mut stdin, false));
        let downlink = scope.spawn(|| pump(&mut stdout, writer, true));
        let uplink = uplink.join();
        let downlink = downlink.join();
        uplink
            .map_err(|_| GitError::Io {
                detail: "pack upload pump failed".to_owned(),
            })?
            .map_err(io_error)?;
        downlink
            .map_err(|_| GitError::Io {
                detail: "pack download pump failed".to_owned(),
            })?
            .map_err(io_error)
    })?;
    let status = child.wait().map_err(io_error)?;
    if status.success() {
        return Ok(());
    }
    Err(GitError::Io {
        detail: format!("pack server for {service} exited {status}"),
    })
}

/// Copies `reader` to `writer`, forwarding every short read at once and
/// flushing every chunk when asked (the pipe-to-terminal leg).
///
/// One `read` call per turn, never a fill loop: the pack protocol is
/// strict request/response (git sends a small request, then waits for
/// the server), so batching reads to a full buffer holds one side's
/// bytes while both ends wait — a four-way deadlock on the first round
/// trip. The 32 KiB chunk only bounds memory per turn.
fn pump(
    reader: &mut impl std::io::Read,
    writer: &mut impl std::io::Write,
    flush: bool,
) -> std::io::Result<()> {
    let mut chunk = vec![0u8; 32 << 10];
    loop {
        match reader.read(&mut chunk)? {
            0 => {
                if flush {
                    writer.flush()?;
                }
                return Ok(());
            }
            count => {
                writer.write_all(&chunk[..count])?;
                if flush {
                    writer.flush()?;
                }
            }
        }
    }
}

/// Reports whether one stream line opens a `data` block.
fn is_data_header(text: &str) -> bool {
    text == "data" || text.starts_with("data ") || text.starts_with("data<<")
}

/// Copies one `data` block verbatim: `<n>` bytes plus its newline, or a
/// `<<marker` heredoc through the closing marker line.
fn copy_data_block<R: BufRead>(reader: &mut R, header: &str, out: &mut Vec<u8>) -> Result<(), GitError> {
    if let Some(marker) = header.strip_prefix("data<<") {
        if marker.is_empty() {
            return Err(GitError::Invalid {
                detail: "data heredoc needs a marker".to_owned(),
            });
        }
        let mut line = Vec::new();
        loop {
            if read_line_capped(reader, &mut line)? == 0 {
                return Err(GitError::Invalid {
                    detail: "export stream ended inside a data heredoc".to_owned(),
                });
            }
            out.extend_from_slice(&line);
            if command_text(&line) == marker {
                return Ok(());
            }
        }
    }
    let digits = header.strip_prefix("data ").unwrap_or(header);
    let count: u64 = digits.parse().map_err(|_| GitError::Invalid {
        detail: format!("bad data length {digits:?}"),
    })?;
    if count > MAX_OBJECT_BYTES {
        return Err(GitError::Limit {
            detail: format!("data block of {count} bytes exceeds the object bound"),
        });
    }
    // A `data <n>` block is exactly n payload bytes (the payload carries
    // its own trailing newline when it has one); the next byte already
    // starts the following line, so no delimiter is consumed here. This
    // mirrors the importer's `read_data`, which reads exactly `count`.
    let mut remaining = count;
    while remaining > 0 {
        let want = remaining.min(DATA_COPY_CHUNK);
        let Ok(width) = usize::try_from(want) else {
            return Err(GitError::Limit {
                detail: "data chunk does not fit in memory".to_owned(),
            });
        };
        let mut chunk = vec![0u8; width];
        reader.read_exact(&mut chunk).map_err(io_error)?;
        out.extend_from_slice(&chunk);
        remaining -= want;
    }
    Ok(())
}

/// Reports whether one line is a stock delete spelling: `from` the
/// all-zero oid of either hash width.
fn is_zero_from(text: &str) -> bool {
    let Some(oid) = text.strip_prefix("from ") else {
        return false;
    };
    !oid.is_empty() && oid.len() <= 64 && oid.bytes().all(|byte| byte == b'0')
}

/// Names the ref one top-level `commit`/`reset`/`tag` line updates.
fn top_ref_command(text: &str) -> Option<&str> {
    for prefix in ["commit ", "reset ", "tag "] {
        if let Some(name) = text.strip_prefix(prefix)
            && !name.is_empty()
        {
            return Some(name);
        }
    }
    None
}

/// Names the remote hash algorithm for the `:object-format` list line.
fn algo_name(kind: HashKind) -> &'static str {
    match kind {
        HashKind::Sha1 => "sha1",
        HashKind::Sha256 => "sha256",
    }
}

/// Maps a ref-layer read failure into the interpreter error.
fn ref_error(err: impl Into<ruk_core::error::CoreError>) -> GitError {
    GitError::from(err.into())
}

/// Maps a stdio failure into the interpreter error.
fn io_error(err: std::io::Error) -> GitError {
    GitError::Io {
        detail: format!("remote-helper stdio: {err}"),
    }
}
