//! Object verbs: `hash-object`, `cat-file`, `mktree`, `commit-tree`,
//! `write-tree`, `verify-pack`, `count-objects`, `ls-tree`,
//! `check-ref-format`, `index-pack`, `pack-objects`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `hash-object` | `HashKind::hash_git_object` + optional store write | implemented |
//! | `cat-file` | bounded transport object read | implemented (`-p`, `-t`, `-s`, `-e`) |
//! | `mktree` | canonical tree build + publish | implemented |
//! | `commit-tree` | canonical commit payload + publish | implemented |
//! | `write-tree` | index tree build | implemented |
//! | `verify-pack` | pack ingest in verify mode, staged output dropped | implemented |
//! | `count-objects` | no object census in the store API | unsupported |
//! | `ls-tree` | tree parse/flatten | implemented (`-r`, `--name-only`) |
//! | `check-ref-format` | `RefName` validation | implemented |
//! | `index-pack` | declared absent for this slice | unsupported |
//! | `pack-objects` | declared absent for this slice | unsupported |
//!
//! Oracle anchors: `git/builtin/hash-object.c`, `git/builtin/cat-file.c`,
//! `git/builtin/mktree.c`, `git/builtin/commit-tree.c`,
//! `git/builtin/write-tree.c`, `git/builtin/verify-pack.c`,
//! `git/builtin/count-objects.c`, `git/builtin/ls-tree.c`,
//! `git/builtin/check-ref-format.c`, `git/builtin/index-pack.c`,
//! `git/builtin/pack-objects.c`.

use ruk_core::heads::Head;
use ruk_core::index::{FileMode, Stage};
use ruk_core::records::Records;
use ruk_core::refdata::RefName;
use ruk_core::store::{ObjectKind, Store};
use ruk_git::GitError;

use super::state::{IdentityRole, identity, merged_rows, scan_index};
use super::tree::{
    TreeEntry, build_index_tree, commit_payload, encode_tree, parse_tree, peel_to_tree,
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
        let path = std::path::Path::new(file);
        let handle = std::fs::File::open(path).map_err(|err| GitError::Io {
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
    ];
    let opts = collect(args, &specs)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let [rev] = opts.positionals.as_slice() else {
        return Err(GitError::Invalid {
            detail: "usage: cat-file (-p|-t|-s|-e) <object>".to_owned(),
        });
    };
    let oid = ruk_git::parse_oid_for(rev, kind)?;
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

/// Names one stored object kind.
fn kind_name_of(kind: ObjectKind) -> &'static str {
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
        if left.mode.octal() == 0o040_000 {
            left_key.push(b'/');
        }
        if right.mode.octal() == 0o040_000 {
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
    let mode_value = u32::from_str_radix(mode_text, 8).map_err(|_| GitError::Invalid {
        detail: format!("bad mktree mode {mode_text:?}"),
    })?;
    let mode = FileMode::from_octal(mode_value).map_err(|err| GitError::Invalid {
        detail: format!("bad mktree mode: {err}"),
    })?;
    let want_type = match mode.octal() {
        0o040_000 => "tree",
        0o160_000 => "commit",
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

/// Counts objects. Unsupported: the store API exposes no object census.
///
/// Oracle: `git/builtin/count-objects.c`.
pub(crate) fn count_objects(_ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let _ = args;
    Err(GitError::Unsupported {
        command: "count-objects: the store exposes no object census".to_owned(),
    })
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
            entry.mode.octal() == 0o040_000,
        )?);
    }
    Ok(out)
}

/// Renders one `ls-tree` line in long or name-only form.
fn ls_tree_line(
    opts: &super::Collected,
    mode: &FileMode,
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
    let type_name = match mode.octal() {
        0o040_000 => "tree",
        0o160_000 => "commit",
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
fn tree_is_dir(mode: FileMode) -> bool {
    mode.octal() == 0o040_000
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

/// Builds a pack index. Declared absent for this slice.
///
/// Oracle: `git/builtin/index-pack.c`.
pub(crate) fn index_pack(_ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let _ = args;
    Err(GitError::Unsupported {
        command: "index-pack: pack indexing is absent in this slice".to_owned(),
    })
}

/// Creates a packed archive. Declared absent for this slice.
///
/// Oracle: `git/builtin/pack-objects.c`.
pub(crate) fn pack_objects(_ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let _ = args;
    Err(GitError::Unsupported {
        command: "pack-objects: pack generation is absent in this slice".to_owned(),
    })
}
