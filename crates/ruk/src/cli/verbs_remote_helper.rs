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
//! - No `refspec` capability is advertised (the implied `*:*` applies), so
//!   `import` streams name the real refs. A stock-git `fetch` therefore
//!   writes those same names through its own fast-import: remote-tracking
//!   refs still update from `FETCH_HEAD`, but same-named local branches
//!   converge to the fetched values instead of staying untouched.
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
//!   store warns instead of failing. `list` advertises only refs the
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
    let _ = remote;
    let input = super::read_stdin_bytes(&ctx.env)?;
    let root = helper_root(&ctx.env, url)?;
    // Fail fast on an unresolvable URL before reading any commands.
    open_helper_store(&root)?;
    let mut session = HelperSession {
        root,
        env: ctx.env.clone(),
        dry_run: false,
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
    let _ = remote;
    let mut session = HelperSession {
        root,
        env,
        dry_run: false,
    };
    let stdin = std::io::stdin();
    let mut reader = std::io::BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    match serve_commands(&mut session, &mut reader, &mut writer) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "ruk {HELPER_ARG0}: {err}");
            ExitCode::from(err.exit_code())
        }
    }
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
pub(crate) fn serve_commands<R: BufRead, W: std::io::Write>(
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
            writer
                .write_all(b"import\nexport\noption\nobject-format\n\n")
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
    let mut ctx = helper_ctx(session, store)?;
    let stream = verbs_fastio::fast_export(&mut ctx, &exportable)?;
    writer.write_all(&stream).map_err(io_error)?;
    writer.flush().map_err(io_error)?;
    Ok(())
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
    let mut newline = [0u8; 1];
    reader.read_exact(&mut newline).map_err(io_error)?;
    if newline != [b'\n'] {
        return Err(GitError::Invalid {
            detail: "data block misses its trailing newline".to_owned(),
        });
    }
    out.push(b'\n');
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
