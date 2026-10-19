//! Object verbs: `hash-object`, `cat-file`, `mktree`, `commit-tree`,
//! `write-tree`, `verify-pack`, `count-objects`, `ls-tree`,
//! `check-ref-format`, `index-pack`, `pack-objects`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `hash-object` | `HashKind::hash_git_object` + optional store write | implemented |
//! | `cat-file` | bounded transport object read | implemented (`-p`, `-t`, `-s`, `-e`, `--batch-check [--batch-all-objects]`) |
//! | `mktree` | canonical tree build + publish | implemented |
//! | `commit-tree` | canonical commit payload + publish | implemented |
//! | `write-tree` | index tree build | implemented |
//! | `verify-pack` | pack ingest in verify mode, staged output dropped | implemented |
//! | `count-objects` | `Store::iter_objects` census, no payload I/O | implemented (`<n> objects, <bytes>`) |
//! | `ls-tree` | tree parse/flatten | implemented (`-r`, `--name-only`) |
//! | `check-ref-format` | `RefName` validation | implemented |
//! | `index-pack` | ingest plus publication with commit-record facts (no `.idx`: the store keeps no loose/pack split) | implemented (`-v`, `--stdin`) |
//! | `pack-objects` | self-contained pack v2 to `<base>.pack` or `--stdout` | implemented (`--stdout`, `--revs`, `--all`, `--thin` with `--stdout`, `--no-thin`, `--delta-base-offset`/`--no-delta-base-offset`) |
//!
//! Oracle anchors: `git/builtin/hash-object.c`, `git/builtin/cat-file.c`,
//! `git/builtin/mktree.c`, `git/builtin/commit-tree.c`,
//! `git/builtin/write-tree.c`, `git/builtin/verify-pack.c`,
//! `git/builtin/count-objects.c`, `git/builtin/ls-tree.c`,
//! `git/builtin/check-ref-format.c`, `git/builtin/index-pack.c`,
//! `git/builtin/pack-objects.c`.

use ruk_core::heads::Head;
use ruk_core::index::Stage;
use ruk_core::records::Records;
use ruk_core::refdata::RefName;
use ruk_core::store::{ObjectKind, Store};
use ruk_git::GitError;

use super::state::{IdentityRole, identity, merged_rows, scan_index};
use super::tree::{
    TreeEntry, TreeMode, build_index_tree, commit_payload, encode_tree, parse_tree, peel_to_tree,
    read_bounded, read_object_bytes, store_object,
};
use super::{Ctx, FlagSpec, collect, line};

/// Hashes bytes as an object id, optionally storing the object.
///
/// Oracle: `git/builtin/hash-object.c`.
pub(crate) fn hash_object(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "write",
            short: Some('w'),
            takes_value: false,
        },
        FlagSpec {
            long: "type",
            short: Some('t'),
            takes_value: true,
        },
        FlagSpec {
            long: "stdin",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let object_type = opts.single("type")?.unwrap_or_else(|| "blob".to_owned());
    if !["blob", "tree", "commit"].contains(&object_type.as_str()) {
        return Err(GitError::Invalid {
            detail: format!("unknown object type {object_type:?}"),
        });
    }
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    if opts.positionals.is_empty() || opts.is_set("stdin") {
        inputs.push(super::read_stdin_bytes(&ctx.env)?);
    }
    for file in &opts.positionals {
        // Relative paths resolve against the invocation directory (`-C`),
        // not the process root, the way the oracle honors `-C` globally.
        let full = std::path::Path::new(file);
        let full = if full.is_absolute() {
            full.to_path_buf()
        } else {
            ctx.env.cwd.join(full)
        };
        let handle = std::fs::File::open(&full).map_err(|err| GitError::Io {
            detail: format!("opening {file}: {err}"),
        })?;
        inputs.push(read_bounded(handle, super::state::MAX_OBJECT_BYTES)?);
    }
    let mut out = Vec::new();
    for body in &inputs {
        out.extend_from_slice(&hash_one(ctx, &object_type, body, opts.is_set("write"))?);
    }
    Ok(out)
}

/// Hashes and optionally stores one object body.
fn hash_one(ctx: &Ctx, object_type: &str, body: &[u8], write: bool) -> Result<Vec<u8>, GitError> {
    let kind = ctx.kind().unwrap_or(ruk_core::ids::HashKind::Sha1);
    match object_type {
        "tree" => {
            parse_tree(kind, body)?;
        }
        "commit" => {
            check_commit_body(body)?;
        }
        _ => {}
    }
    let oid = kind
        .hash_git_object(object_type, body)
        .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?;
    if write {
        let store = ctx.store()?;
        let store_kind = ctx.kind()?;
        if oid.kind() != store_kind {
            return Err(GitError::ObjectFormat {
                detail: "object width disagrees with the repository".to_owned(),
            });
        }
        if object_type == "commit" {
            store_commit_object(store, body.to_vec())?;
        } else {
            let object_kind = match object_type {
                "tree" => ObjectKind::Tree,
                _ => ObjectKind::Blob,
            };
            let body_len = u64::try_from(body.len()).map_err(|_| GitError::Limit {
                detail: "object body exceeds the length range".to_owned(),
            })?;
            let prepared = store
                .prepare(object_kind, body_len, std::io::Cursor::new(body), None)
                .map_err(GitError::from)?;
            if prepared.oid() != oid {
                return Err(GitError::Corrupt {
                    detail: "stored identity disagrees with the hash".to_owned(),
                });
            }
            store.publish(vec![prepared], &[]).map_err(GitError::from)?;
        }
    }
    Ok(line(oid.to_hex().into_bytes()))
}

/// Stores one commit payload with its change record, so the commit is
/// visible to history walks instead of dangling in the object store.
///
/// Re-storing a known commit keeps its record and republishes the object,
/// which the store accepts as a compatible duplicate.
fn store_commit_object(store: &Store, payload: Vec<u8>) -> Result<ruk_core::ids::Oid, GitError> {
    let kind = store.hash_kind();
    let oid = kind
        .hash_git_object("commit", &payload)
        .map_err(|err| GitError::from(ruk_core::error::CoreError::from(err)))?;
    let records = Records::new(store);
    if records
        .get_commit(&Head::Git { oid })
        .map_err(GitError::from)?
        .is_some()
    {
        return store_object(store, ObjectKind::Commit, payload).map(|_| oid);
    }
    let mut batch = records.batch_preparer();
    batch
        .add_import_git(payload, None)
        .map_err(GitError::from)?;
    let done = batch.finish().map_err(GitError::from)?;
    store
        .publish(done.prepared_objects, &done.mutations)
        .map_err(GitError::from)?;
    Ok(oid)
}

/// Checks the minimal commit shape `hash-object -t commit` requires.
fn check_commit_body(body: &[u8]) -> Result<(), GitError> {
    let line_end = body
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(body.len());
    if body[..line_end].starts_with(b"tree ") {
        return Ok(());
    }
    Err(GitError::Invalid {
        detail: "commit body has no tree line".to_owned(),
    })
}

/// Prints object contents, types, sizes, or existence.
///
/// Oracle: `git/builtin/cat-file.c`.
pub(crate) fn cat_file(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "pretty",
            short: Some('p'),
            takes_value: false,
        },
        FlagSpec {
            long: "type",
            short: Some('t'),
            takes_value: false,
        },
        FlagSpec {
            long: "size",
            short: Some('s'),
            takes_value: false,
        },
        FlagSpec {
            long: "exists",
            short: Some('e'),
            takes_value: false,
        },
        FlagSpec {
            long: "batch-check",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "batch-all-objects",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if opts.is_set("batch-all-objects") && !opts.is_set("batch-check") {
        return Err(GitError::Invalid {
            detail: "cat-file --batch-all-objects requires --batch-check".to_owned(),
        });
    }
    if opts.is_set("batch-check") {
        return batch_check(ctx, &opts);
    }
    let [rev] = opts.positionals.as_slice() else {
        return Err(GitError::Invalid {
            detail: "usage: cat-file (-p|-t|-s|-e) <object>".to_owned(),
        });
    };
    // Resolve refs, `HEAD`, and ancestry suffixes the way the oracle does;
    // raw object ids still parse when no ref matches.
    let oid = super::state::resolve_rev(store, kind, rev)
        .or_else(|_| ruk_git::parse_oid_for(rev, kind))?;
    let modes = [
        opts.is_set("pretty"),
        opts.is_set("type"),
        opts.is_set("size"),
        opts.is_set("exists"),
    ];
    if modes.iter().filter(|set| **set).count() != 1 {
        return Err(GitError::Invalid {
            detail: "cat-file needs exactly one of -p, -t, -s, -e".to_owned(),
        });
    }
    let (object_kind, body) = read_object_bytes(store, oid)?;
    if opts.is_set("pretty") {
        return Ok(body);
    }
    if opts.is_set("type") {
        return Ok(line(kind_name_of(object_kind).as_bytes().to_vec()));
    }
    if opts.is_set("size") {
        return Ok(line(body.len().to_string().into_bytes()));
    }
    Ok(Vec::new())
}

/// Prints `<oid> <type> <size>` per object without payload I/O: the whole
/// census for `--batch-all-objects`, else one line per revision read from
/// standard input (unknown revisions report `<rev> missing`, the way the
/// oracle's batch-check mode does).
///
/// Oracle: `git/builtin/cat-file.c` (`batch_check`).
fn batch_check(ctx: &Ctx, opts: &super::Collected) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if opts.is_set("batch-all-objects") {
        if !opts.positionals.is_empty() {
            return Err(GitError::Invalid {
                detail: "cat-file --batch-all-objects takes no object argument".to_owned(),
            });
        }
        let mut out = Vec::new();
        for (oid, object_kind, len) in store.iter_objects().map_err(GitError::from)? {
            out.extend_from_slice(
                format!("{} {} {len}\n", oid.to_hex(), kind_name_of(object_kind)).as_bytes(),
            );
        }
        return Ok(out);
    }
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: cat-file --batch-check [--batch-all-objects] (revisions on stdin)"
                .to_owned(),
        });
    }
    let stdin = super::read_stdin_text(&ctx.env)?;
    let mut out = Vec::new();
    for input in stdin.lines() {
        let rev = input.split_whitespace().next().unwrap_or_default();
        if rev.is_empty() {
            continue;
        }
        let oid = super::state::resolve_rev(store, kind, rev)
            .or_else(|_| ruk_git::parse_oid_for(rev, kind));
        let oid = match oid {
            Err(_) => {
                out.extend_from_slice(format!("{rev} missing\n").as_bytes());
                continue;
            }
            Ok(oid) => oid,
        };
        // Absence reports `missing`; damage aborts. Collapsing `Corrupt`
        // into `missing` would hide committed corruption the store already
        // latched quarantine for, so only `NotFound` takes the missing arm.
        match read_object_bytes(store, oid) {
            Ok((object_kind, body)) => out.extend_from_slice(
                format!(
                    "{} {} {}\n",
                    oid.to_hex(),
                    kind_name_of(object_kind),
                    body.len()
                )
                .as_bytes(),
            ),
            Err(GitError::NotFound { .. }) => {
                out.extend_from_slice(format!("{} missing\n", oid.to_hex()).as_bytes());
            }
            Err(err) => return Err(err),
        }
    }
    Ok(out)
}

/// Names one stored object kind.
pub(crate) fn kind_name_of(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::Blob => "blob",
        ObjectKind::Tree => "tree",
        ObjectKind::Commit => "commit",
        ObjectKind::Tag => "tag",
        ObjectKind::Conflict => "conflict",
    }
}

/// Builds a tree object from `ls-tree` formatted standard input.
///
/// Oracle: `git/builtin/mktree.c`.
pub(crate) fn mktree(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "missing-ok",
        short: None,
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "mktree takes no arguments".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let _ = opts.is_set("missing-ok");
    let stdin = super::read_stdin_text(&ctx.env)?;
    let mut entries = Vec::new();
    for stdin_line in stdin.lines() {
        entries.push(parse_mktree_line(kind, stdin_line)?);
    }
    entries.sort_by(|left: &TreeEntry, right: &TreeEntry| {
        let mut left_key = left.name.clone();
        let mut right_key = right.name.clone();
        if left.mode.is_tree() {
            left_key.push(b'/');
        }
        if right.mode.is_tree() {
            right_key.push(b'/');
        }
        left_key.cmp(&right_key)
    });
    let body = encode_tree(&entries);
    let oid = store_object(store, ObjectKind::Tree, body)?;
    Ok(line(oid.to_hex().into_bytes()))
}

/// Parses one `mode SP type SP oid TAB name` mktree input line.
fn parse_mktree_line(
    kind: ruk_core::ids::HashKind,
    stdin_line: &str,
) -> Result<TreeEntry, GitError> {
    let (mode_text, rest) = stdin_line
        .split_once(' ')
        .ok_or_else(|| GitError::Invalid {
            detail: format!("bad mktree line {stdin_line:?}"),
        })?;
    let (type_text, rest) = rest.split_once(' ').ok_or_else(|| GitError::Invalid {
        detail: format!("bad mktree line {stdin_line:?}"),
    })?;
    let (oid_text, name) = rest.split_once('\t').ok_or_else(|| GitError::Invalid {
        detail: format!("bad mktree line {stdin_line:?}"),
    })?;
    let mode = TreeMode::parse(mode_text.as_bytes()).ok_or_else(|| GitError::Invalid {
        detail: format!("bad mktree mode {mode_text:?}"),
    })?;
    let want_type = match mode {
        TreeMode::Tree => "tree",
        TreeMode::Gitlink => "commit",
        _ => "blob",
    };
    if type_text != want_type {
        return Err(GitError::Invalid {
            detail: format!("mktree type {type_text:?} disagrees with mode {mode_text:?}"),
        });
    }
    let oid = ruk_git::parse_oid_for(oid_text, kind)?;
    if name.is_empty() || name.contains('/') {
        return Err(GitError::Invalid {
            detail: format!("bad mktree name {name:?}"),
        });
    }
    Ok(TreeEntry {
        mode,
        name: name.as_bytes().to_vec(),
        oid,
    })
}

/// Creates a commit object without touching any ref.
///
/// Oracle: `git/builtin/commit-tree.c`.
pub(crate) fn commit_tree(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "parent",
            short: Some('p'),
            takes_value: true,
        },
        FlagSpec {
            long: "message",
            short: Some('m'),
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let [tree_text] = opts.positionals.as_slice() else {
        return Err(GitError::Invalid {
            detail: "usage: commit-tree <tree> [-p <parent>]... -m <message>".to_owned(),
        });
    };
    let tree = ruk_git::parse_oid_for(tree_text, kind)?;
    let (tree_kind, _) = read_object_bytes(store, tree)?;
    if tree_kind != ObjectKind::Tree {
        return Err(GitError::Invalid {
            detail: format!("object {} is not a tree", tree.to_hex()),
        });
    }
    let mut parents = Vec::new();
    for parent_text in opts.all("parent")? {
        let parent = ruk_git::parse_oid_for(&parent_text, kind)?;
        super::state::commit_record(store, parent)?;
        parents.push(parent.to_hex());
    }
    let messages = opts.all("message")?;
    if messages.is_empty() {
        return Err(GitError::Invalid {
            detail: "commit-tree needs -m <message>".to_owned(),
        });
    }
    let message = messages.join("\n\n").into_bytes();
    let author = identity(ctx, IdentityRole::Author)?;
    let committer = identity(ctx, IdentityRole::Committer)?;
    let payload = commit_payload(&tree.to_hex(), &parents, &author, &committer, &message);
    let oid = store_commit_object(store, payload)?;
    Ok(line(oid.to_hex().into_bytes()))
}

/// Creates a tree object from the current index.
///
/// Oracle: `git/builtin/write-tree.c`.
pub(crate) fn write_tree(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "missing-ok",
        short: None,
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "write-tree takes no arguments".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let _ = opts.is_set("missing-ok");
    let rows = scan_index(store, kind)?;
    for (_, stage, _) in &rows {
        if *stage != Stage::Zero {
            return Err(GitError::Invalid {
                detail: "unmerged paths must be resolved first".to_owned(),
            });
        }
    }
    let oid = build_index_tree(store, kind, &merged_rows(&rows))?;
    Ok(line(oid.to_hex().into_bytes()))
}

/// Validates a pack file by ingesting it without publishing.
///
/// Oracle: `git/builtin/verify-pack.c`. Staged objects are dropped: no
/// repository state changes, so this stays verification, not import.
pub(crate) fn verify_pack(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [FlagSpec {
        long: "verbose",
        short: Some('v'),
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let [path] = opts.positionals.as_slice() else {
        return Err(GitError::Invalid {
            detail: "usage: verify-pack [-v] <pack>".to_owned(),
        });
    };
    let file = std::fs::File::open(path).map_err(|err| GitError::Io {
        detail: format!("opening {path}: {err}"),
    })?;
    let staged = ruk_git::transport::pack::ingest_pack(
        file,
        kind,
        store,
        ruk_git::transport::pack::IngestLimits::default(),
        &ruk_git::transport::Interrupt::none(),
    )?;
    let mut out = Vec::new();
    if opts.is_set("verbose") {
        for object in staged.objects() {
            out.extend_from_slice(
                format!(
                    "{} {}\n",
                    object.oid().to_hex(),
                    kind_name_of(object.kind())
                )
                .as_bytes(),
            );
        }
    }
    out.extend_from_slice(
        format!("{}: ok ({} objects verified)\n", path, staged.oids().len()).as_bytes(),
    );
    Ok(out)
}

/// Counts committed objects and their decoded bytes: one pass over the
/// [`Store::iter_objects`](ruk_core::store::Store::iter_objects) census,
/// with no payload I/O. The store keeps no loose/pack split, so the
/// rendering is ruk-native (`<n> objects, <bytes>`) instead of the
/// oracle's loose/in-pack rows.
///
/// Oracle: `git/builtin/count-objects.c`.
pub(crate) fn count_objects(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let opts = collect(args, &[])?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: count-objects".to_owned(),
        });
    }
    let store = ctx.store()?;
    let mut count: u64 = 0;
    let mut bytes: u64 = 0;
    for (_, _, len) in store.iter_objects().map_err(GitError::from)? {
        count = count.saturating_add(1);
        bytes = bytes.saturating_add(len);
    }
    Ok(line(format!("{count} objects, {bytes} bytes").into_bytes()))
}

/// Lists tree contents, flat or recursive.
///
/// Oracle: `git/builtin/ls-tree.c`.
pub(crate) fn ls_tree(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "recursive",
            short: Some('r'),
            takes_value: false,
        },
        FlagSpec {
            long: "name-only",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let [rev] = opts.positionals.as_slice() else {
        return Err(GitError::Invalid {
            detail: "usage: ls-tree [-r] <tree-ish>".to_owned(),
        });
    };
    let oid = super::state::resolve_rev(store, kind, rev)?;
    let tree = peel_to_tree(store, kind, oid)?;
    let mut out = Vec::new();
    if opts.is_set("recursive") {
        for (path, mode, oid) in super::tree::flatten_tree(store, kind, tree)? {
            out.extend_from_slice(&ls_tree_line(&opts, &mode, &oid, &path, tree_is_dir(mode))?);
        }
        return Ok(out);
    }
    let (_, body) = read_object_bytes(store, tree)?;
    for entry in parse_tree(kind, &body)? {
        out.extend_from_slice(&ls_tree_line(
            &opts,
            &entry.mode,
            &entry.oid,
            &entry.name,
            entry.mode.is_tree(),
        )?);
    }
    Ok(out)
}

/// Renders one `ls-tree` line in long or name-only form.
fn ls_tree_line(
    opts: &super::Collected,
    mode: &TreeMode,
    oid: &ruk_core::ids::Oid,
    name: &[u8],
    is_dir: bool,
) -> Result<Vec<u8>, GitError> {
    if opts.is_set("name-only") {
        let mut out = name.to_vec();
        if is_dir {
            out.push(b'/');
        }
        out.push(b'\n');
        return Ok(out);
    }
    let type_name = match mode {
        TreeMode::Tree => "tree",
        TreeMode::Gitlink => "commit",
        _ => "blob",
    };
    Ok(format!(
        "{:06o} {type_name} {}\t{}\n",
        mode.octal(),
        oid.to_hex(),
        String::from_utf8_lossy(name)
    )
    .into_bytes())
}

/// Reports whether a mode is the directory mode.
fn tree_is_dir(mode: TreeMode) -> bool {
    mode.is_tree()
}

/// Validates a ref name.
///
/// Oracle: `git/builtin/check-ref-format.c`.
pub(crate) fn check_ref_format(_ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "print",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "branch",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    if let Some(pattern) = opts.single("branch")? {
        let full = format!("refs/heads/{pattern}");
        RefName::new(full.clone()).map_err(|err| GitError::Invalid {
            detail: format!("bad branch name: {err}"),
        })?;
        return Ok(line(full.into_bytes()));
    }
    let [name] = opts.positionals.as_slice() else {
        return Err(GitError::Invalid {
            detail: "usage: check-ref-format [--print] <name>".to_owned(),
        });
    };
    RefName::new(name.clone()).map_err(|err| GitError::Invalid {
        detail: format!("bad ref name: {err}"),
    })?;
    if opts.is_set("print") {
        return Ok(line(name.as_bytes().to_vec()));
    }
    Ok(Vec::new())
}

/// Indexes a pack file into the store: integrity-verified ingest plus
/// publication, the store's analog of writing the oracle's `.idx`.
///
/// Oracle: `git/builtin/index-pack.c`. The store keeps no loose/pack
/// split, so there is no index file to write: the pack is verified the
/// way `verify-pack` verifies it (header, entries, trailer checksum,
/// deltas, identities) and then published with its commit-record facts,
/// the same tail `unbundle` and fetch use, so history verbs see the
/// arrivals. The pack comes from `--stdin` or from the one `<pack>`
/// positional, never both. Named gaps (usage errors): `-o`,
/// `--index-version`, `--fix-thin` (thin bases must already be committed,
/// the thin-pack rule ingest enforces), `--strict`, `--verify`,
/// `--check-self-contained-and-connected`, `--keep`, `--progress`,
/// `--threads`, `--max-input-size`.
pub(crate) fn index_pack(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    const USAGE: &str = "usage: index-pack [-v] (--stdin | <pack>)";
    let specs = [
        FlagSpec {
            long: "verbose",
            short: Some('v'),
            takes_value: false,
        },
        FlagSpec {
            long: "stdin",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let path = match (opts.is_set("stdin"), opts.positionals.as_slice()) {
        (true, []) => None,
        (false, [path]) => Some(path.clone()),
        _ => {
            return Err(GitError::Invalid {
                detail: USAGE.to_owned(),
            });
        }
    };
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let (label, bytes) = match path {
        Some(path) => {
            let bytes = std::fs::read(&path).map_err(|err| GitError::Io {
                detail: format!("reading {path}: {err}"),
            })?;
            (path, bytes)
        }
        None => ("stdin".to_owned(), super::read_stdin_bytes(&ctx.env)?),
    };
    let staged = ruk_git::transport::pack::ingest_pack(
        &bytes[..],
        kind,
        store,
        ruk_git::transport::pack::IngestLimits::default(),
        &ruk_git::transport::Interrupt::none(),
    )?;
    let count = staged.oids().len();
    let mut out = Vec::new();
    if opts.is_set("verbose") {
        for object in staged.objects() {
            out.extend_from_slice(
                format!(
                    "{} {}\n",
                    object.oid().to_hex(),
                    kind_name_of(object.kind())
                )
                .as_bytes(),
            );
        }
    }
    let facts = ruk_git::transport::fetch::commit_record_facts(store, &staged)?;
    store
        .publish(staged.into_objects(), &facts)
        .map_err(GitError::from)?;
    out.extend_from_slice(format!("{label}: ok ({count} objects indexed)\n").as_bytes());
    Ok(out)
}

/// Creates a packed archive of objects, into `<base>.pack` or, with
/// `--stdout`, onto standard output.
///
/// Oracle: `git/builtin/pack-objects.c`. Selection mirrors the oracle:
/// input always comes from stdin (exactly one output target: `--stdout`
/// xor `<base>`, no trailing positionals). Without `--revs`/`--all`,
/// stdin lines name exact objects (`<hex>[ SP <path>]`, one per line; a
/// leading `-` marks a thin preferred base, accepted and skipped, see
/// below). With `--revs`, stdin lines are rev-list
/// arguments (one per line, ending at the first blank line; `--not` and
/// `--shallow` lines are refused with their ruk spellings), and `--all`
/// unions every ref tip. Selected commits close over their trees, blobs,
/// and tag targets (a directly named tag packs the tag plus its target's
/// tree, not the target's ancestry: name the commit rev for ancestry);
/// gitlink entries are never packed (entries minus gitlinks, the pack
/// layer's own link rule), and a native conflict entry is refused the way
/// the wire writer refuses it. Emission is always a self-contained pack
/// v2: `--thin` is honored only with `--stdout` (the oracle refuses
/// `--thin` for an indexable pack) and, with no receiver haves to pair,
/// entries stay full rather than `REF_DELTA`; `--delta-base-offset` and
/// `--no-delta-base-offset` are accepted inert (the writer emits full
/// entries, never `OFS_DELTA`). Named gaps (usage errors): `--depth`,
/// `--window`, `--compression`, `--threads`, `--max-pack-size`,
/// `--progress`/`-q`, `--non-empty`, `--unpacked`, `--filter`,
/// `--shallow`, `--keep-true-parents`, `--honor-pack-keep`,
/// `--include-tag`, `--stdin-packs`, `--cruft`, `--keep-pack`,
/// `--local`, `--incremental`.
pub(crate) fn pack_objects(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    const USAGE: &str =
        "usage: pack-objects [--stdout | <base>] [--revs] [--all] [--thin] < <list>";
    let specs = [
        FlagSpec {
            long: "stdout",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "revs",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "all",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "thin",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-thin",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "delta-base-offset",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "no-delta-base-offset",
            short: None,
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    if opts.is_set("thin") && !opts.is_set("stdout") {
        return Err(GitError::Invalid {
            detail: "--thin cannot be used to build an indexable pack".to_owned(),
        });
    }
    let base = match (opts.is_set("stdout"), opts.positionals.as_slice()) {
        (true, []) => None,
        (false, [base]) => Some(base.clone()),
        _ => {
            return Err(GitError::Invalid {
                detail: USAGE.to_owned(),
            });
        }
    };
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let stdin = super::read_stdin_text(&ctx.env)?;
    let payloads = if opts.is_set("revs") || opts.is_set("all") {
        pack_rev_closure(store, kind, &opts, &stdin)?
    } else {
        pack_exact_objects(store, &stdin)?
    };
    let entries: Vec<ruk_git::transport::pack::PackEntry<'_>> = payloads
        .iter()
        .map(
            |(oid, object_kind, bytes)| ruk_git::transport::pack::PackEntry {
                oid: *oid,
                kind: *object_kind,
                bytes,
                base: None,
            },
        )
        .collect();
    let mut pack = Vec::new();
    ruk_git::transport::pack::write_pack(
        &mut pack,
        kind,
        &entries,
        &ruk_git::transport::Interrupt::none(),
    )?;
    match base {
        None => Ok(pack),
        Some(base) => {
            let name = format!("{base}.pack");
            let dest = super::verbs_bundle::join_cwd(ctx, &name);
            std::fs::write(&dest, &pack).map_err(|err| GitError::Io {
                detail: format!("writing {}: {err}", dest.display()),
            })?;
            Ok(Vec::new())
        }
    }
}

/// Packs exactly the objects stdin names, with no closure expansion.
///
/// One `<hex>[ SP <path>]` per line, the oracle's object-list grammar; a
/// leading `-` marks a thin preferred base, which is accepted and skipped:
/// it names no object to pack (thin delta pairing belongs to the push
/// negotiation, which owns the permitted-base contract). A blank or non-hex
/// `Invalid`, the way the oracle dies on garbage.
fn pack_exact_objects(
    store: &Store,
    stdin: &str,
) -> Result<Vec<(ruk_core::ids::Oid, ObjectKind, Vec<u8>)>, GitError> {
    let mut payloads = Vec::new();
    for line_text in stdin.lines() {
        let token = line_text.split_whitespace().next().unwrap_or("");
        if let Some(_base) = token.strip_prefix('-') {
            continue;
        }
        let oid = ruk_core::ids::Oid::from_hex(token).map_err(|_| GitError::Invalid {
            detail: format!("expected object ID, got garbage:\n {line_text}"),
        })?;
        let (object_kind, bytes) = read_object_bytes(store, oid)?;
        if object_kind == ObjectKind::Conflict {
            return Err(GitError::Invalid {
                detail: format!(
                    "object {} is a native conflict and cannot travel on the Git wire",
                    oid.to_hex()
                ),
            });
        }
        payloads.push((oid, object_kind, bytes));
    }
    payloads.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(payloads)
}

/// Expands `--revs`/`--all` stdin lines through the `rev-list` machinery
/// and closes over the selected commits.
fn pack_rev_closure(
    store: &Store,
    kind: ruk_core::ids::HashKind,
    opts: &super::Collected,
    stdin: &str,
) -> Result<Vec<(ruk_core::ids::Oid, ObjectKind, Vec<u8>)>, GitError> {
    let mut rev_args = Vec::new();
    for line_text in stdin.lines() {
        if line_text.is_empty() {
            break;
        }
        if line_text == "--not" {
            return Err(GitError::Invalid {
                detail: "--not lines are not supported; spell excludes as ^<rev> or <a>..<b>"
                    .to_owned(),
            });
        }
        if line_text.starts_with("--shallow") {
            return Err(GitError::Unsupported {
                command: "pack-objects: shallow lines are not supported".to_owned(),
            });
        }
        rev_args.push(line_text.to_owned());
    }
    let (tips, exclude) = super::verbs_history::parse_log_revs(store, kind, &rev_args, None)?;
    let mut all_tips = tips;
    if opts.is_set("all") {
        all_tips.extend(pack_all_tips(store, kind)?);
    }
    // The history walk takes commits only (`enqueue` fails closed on any
    // other kind), so partition first: other objects seed the closure
    // directly and traverse freely.
    let mut commit_tips = Vec::new();
    let mut extra_seeds = Vec::new();
    let mut seen_tip = std::collections::HashSet::new();
    for tip in all_tips {
        if !seen_tip.insert(tip) {
            continue;
        }
        if super::state::commit_record(store, tip).is_ok() {
            commit_tips.push(tip);
        } else {
            extra_seeds.push(tip);
        }
    }
    let history =
        super::verbs_history::walk_history_excluding(store, &commit_tips, &exclude, None)?;
    let mut allowed: std::collections::HashSet<ruk_core::ids::Oid> =
        history.iter().map(|(oid, _)| *oid).collect();
    let mut seeds: Vec<ruk_core::ids::Oid> = history.iter().map(|(oid, _)| *oid).collect();
    for tip in extra_seeds {
        allowed.insert(tip);
        seeds.push(tip);
    }
    pack_closure(store, kind, &seeds, &allowed)
}

/// Collects every ref tip for `--all`: commit tips for the history walk
/// plus tag objects as-is. Unlike the `rev-list --all` tip set, tag tips
/// are kept: the pack must carry the tag objects themselves.
fn pack_all_tips(
    store: &Store,
    kind: ruk_core::ids::HashKind,
) -> Result<Vec<ruk_core::ids::Oid>, GitError> {
    let mut tips = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (name, _) in super::state::list_refs(store)? {
        let text = String::from_utf8_lossy(name.as_bytes()).into_owned();
        match super::state::resolve_rev(store, kind, &text) {
            Ok(oid) => {
                if seen.insert(oid) {
                    tips.push(oid);
                }
            }
            Err(GitError::NotFound { .. }) => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(tips)
}

/// Collects the pack closure for revision-selected seeds: every seed plus
/// its tree subtree, every traversed tag with its target. Commit parents
/// outside `allowed` stay out, so `^` excludes and range floors hold;
/// non-commit seeds traverse freely. Termination is by visited set, so no
/// depth bound is needed. Gitlink entries are never queued (entries minus
/// gitlinks, the pack layer's own link rule); a native conflict entry is
/// refused, the way the wire writer refuses it.
fn pack_closure(
    store: &Store,
    kind: ruk_core::ids::HashKind,
    seeds: &[ruk_core::ids::Oid],
    allowed: &std::collections::HashSet<ruk_core::ids::Oid>,
) -> Result<Vec<(ruk_core::ids::Oid, ObjectKind, Vec<u8>)>, GitError> {
    use std::collections::{HashSet, VecDeque};
    let mut visited: HashSet<ruk_core::ids::Oid> = HashSet::new();
    let mut queue: VecDeque<ruk_core::ids::Oid> = seeds.iter().copied().collect();
    let mut out = Vec::new();
    while let Some(oid) = queue.pop_front() {
        if !visited.insert(oid) {
            continue;
        }
        let (object_kind, bytes) = read_object_bytes(store, oid)?;
        if object_kind == ObjectKind::Conflict {
            return Err(GitError::Invalid {
                detail: format!(
                    "object {} is a native conflict and cannot travel on the Git wire",
                    oid.to_hex()
                ),
            });
        }
        match object_kind {
            ObjectKind::Commit => {
                let record = super::state::commit_record(store, oid)?;
                for parent in record
                    .parents()
                    .iter()
                    .filter_map(|head| head.as_git().copied())
                {
                    if allowed.contains(&parent) {
                        queue.push_back(parent);
                    }
                }
                queue.push_back(super::tree::commit_tree_oid(&record)?);
            }
            ObjectKind::Tree => {
                for entry in parse_tree(kind, &bytes)? {
                    if !matches!(entry.mode, TreeMode::Gitlink) {
                        queue.push_back(entry.oid);
                    }
                }
            }
            ObjectKind::Tag => {
                queue.push_back(pack_tag_target(kind, oid, &bytes)?);
            }
            ObjectKind::Blob | ObjectKind::Conflict => {}
        }
        out.push((oid, object_kind, bytes));
    }
    out.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(out)
}

/// Reads the `object <hex>` target of one tag payload, the same header
/// the bundle peel reads. The target's own kind decides traversal; a
/// tag-to-blob needs no commit.
fn pack_tag_target(
    kind: ruk_core::ids::HashKind,
    oid: ruk_core::ids::Oid,
    bytes: &[u8],
) -> Result<ruk_core::ids::Oid, GitError> {
    let first = bytes
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let hex = first
        .strip_prefix(b"object ")
        .ok_or_else(|| GitError::Corrupt {
            detail: format!("tag {} has no object header", oid.to_hex()),
        })?;
    let text = std::str::from_utf8(hex).map_err(|_| GitError::Corrupt {
        detail: format!("tag {} has a non-UTF-8 object header", oid.to_hex()),
    })?;
    ruk_git::parse_oid_for(text, kind)
}
