//! Notes and replace verbs: `notes`, `replace`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `notes` | `refs/notes/commits` commit holding a flat `<target-hex>` to blob map | implemented (`add`/`show`/`list`/`append`/`edit`/`copy`/`remove`/`get-ref`/`merge`/`prune`; `--ref`, `GIT_NOTES_REF`, `core.notesRef`; `edit` reads `-m`/`-F`/stdin, no editor) |
//! | `replace` | `refs/replace/<hex>` direct refs plus read-time redirect | implemented (create with `-f`, `-l [<pattern>]`, `-d`; redirect covers commit reads and history walks plus explicit tip redirection in `log`/`blame`/`diff`/`checkout`) |
//!
//! Notes state is one commit behind the notes ref: its tree maps the full
//! hex of each annotated object to the blob holding the note, so
//! `refs/notes/commits` always points at a commit, never a blob or tree.
//! Removing the last note deletes the ref instead of leaving an empty
//! commit behind.
//!
//! Replace refs redirect reads, not writes: `commit_record`, `walk_record`,
//! and `nth_parent` consult `refs/replace/*` (see `state`), so every walk
//! step follows the replacement while the original objects stay stored.
//! `log`, `blame`, `diff`, and `checkout` additionally redirect their
//! resolved tip oids; other verbs inherit walk-level redirection only.
//!
//! Named gaps: blob/tree bytes (`read_object_bytes`), raw revision
//! resolution (`resolve_rev`, `rev-parse`), and transport/pack paths never
//! consult replace refs, so pack integrity is unaffected and per-blob
//! content substitution inside trees does not apply. Notes and replace refs
//! never transfer over `fetch`/`push`/`clone`. `replace --format`,
//! graft-style parent rewriting, and `notes merge` strategies (`-s`) beyond
//! union-or-refuse stay `Unsupported`. `--no-replace-objects` stays
//! accepted and inert (it predates replace refs; no disable path exists yet).
//!
//! Oracle anchors: `git/builtin/notes.c`, `git/builtin/replace.c`.

use std::collections::BTreeMap;

use ruk_core::error::CoreError;
use ruk_core::heads::Head;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::records::Records;
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTarget, RefUpdate};
use ruk_core::store::{ObjectKind, Store};
use ruk_git::GitError;

use super::state::{
    IdentityRole, apply_refs, commit_record, identity, list_refs, read_ref, resolve_rev_raw,
};
use super::tree::{
    TreeEntry, TreeMode, commit_payload, encode_tree, flatten_tree, read_object_bytes, store_object,
};
use super::{Collected, Ctx, FlagSpec, collect};

/// Default notes ref, the way the oracle defaults to `refs/notes/commits`.
const DEFAULT_NOTES_REF: &str = "refs/notes/commits";

/// Resolves the notes ref for one invocation: `--ref`, then `GIT_NOTES_REF`,
/// then `core.notesRef`, then the default. A bare name reads as
/// `refs/notes/<name>`; a `refs/` name is used whole.
fn notes_ref_name(ctx: &Ctx, opts: &Collected) -> Result<RefName, GitError> {
    let raw = match opts.single("ref")? {
        Some(value) => value,
        None => match ctx.env.get("GIT_NOTES_REF") {
            Some(value) => value.to_owned(),
            None => match ctx.config_get("core.notesRef") {
                Some(value) => value,
                None => {
                    return RefName::new(DEFAULT_NOTES_REF).map_err(|err| GitError::Invalid {
                        detail: format!("bad notes ref: {err}"),
                    });
                }
            },
        },
    };
    let full = if raw.starts_with("refs/") {
        raw
    } else {
        format!("refs/notes/{raw}")
    };
    RefName::new(full).map_err(|err| GitError::Invalid {
        detail: format!("bad notes ref: {err}"),
    })
}

/// Loads the notes map once for `log --show-notes`: target hex to note
/// blob, behind a caller-resolved ref name (short names read as
/// `refs/notes/<name>`, `refs/` names whole; the caller applies the
/// `GIT_NOTES_REF`/`core.notesRef`/default chain). A missing ref is an
/// empty map; a ref pointing at a non-commit is corrupt, the same rules
/// [`load_notes`] enforces.
pub(crate) fn notes_entries(
    store: &Store,
    kind: HashKind,
    refname: &str,
) -> Result<Vec<(String, Oid)>, GitError> {
    let full = if refname.starts_with("refs/") {
        refname.to_owned()
    } else {
        format!("refs/notes/{refname}")
    };
    let name = RefName::new(full).map_err(|err| GitError::Invalid {
        detail: format!("bad notes ref: {err}"),
    })?;
    Ok(load_notes(store, kind, &name)?
        .entries
        .into_iter()
        .collect())
}

/// Resolves a non-notes ref the same short-or-full way (`merge` source).
fn other_notes_ref_name(text: &str) -> Result<RefName, GitError> {
    let full = if text.starts_with("refs/") {
        text.to_owned()
    } else {
        format!("refs/notes/{text}")
    };
    RefName::new(full).map_err(|err| GitError::Invalid {
        detail: format!("bad notes ref: {err}"),
    })
}

/// Follows one ref through symbolic links, giving up on loops.
fn deref_ref(store: &Store, name: &RefName) -> Result<Option<Oid>, GitError> {
    let mut current = read_ref(store, name)?;
    for _ in 0..16 {
        match current {
            None => return Ok(None),
            Some(RefTarget::Direct(oid)) => return Ok(Some(oid)),
            Some(RefTarget::Symbolic(next)) => current = read_ref(store, &next)?,
        }
    }
    Err(GitError::Corrupt {
        detail: format!("ref {name} has a symbolic loop"),
    })
}

/// One loaded notes head: the backing commit plus `<target-hex>` to note-blob rows.
struct NotesHead {
    /// Backing notes commit, when the ref exists.
    commit: Option<Oid>,
    /// Target hex to note blob oid, in hex order.
    entries: BTreeMap<String, Oid>,
}

/// Loads the notes map behind a ref. A missing ref is an empty map; a ref
/// pointing at a non-commit is corrupt, never silently reinterpreted.
fn load_notes(store: &Store, kind: HashKind, name: &RefName) -> Result<NotesHead, GitError> {
    let Some(oid) = deref_ref(store, name)? else {
        return Ok(NotesHead {
            commit: None,
            entries: BTreeMap::new(),
        });
    };
    let (object_kind, _) = read_object_bytes(store, oid)?;
    if object_kind != ObjectKind::Commit {
        return Err(GitError::Corrupt {
            detail: format!("notes ref {name} does not point to a commit"),
        });
    }
    let record = commit_record(store, oid)?;
    let tree = super::tree::commit_tree_oid(&record)?;
    let mut entries = BTreeMap::new();
    for (path, _, blob) in flatten_tree(store, kind, tree)? {
        let hex = String::from_utf8(path).map_err(|_| GitError::Corrupt {
            detail: format!("notes ref {name} holds a non-UTF-8 entry"),
        })?;
        let target = Oid::from_hex(&hex).map_err(|_| GitError::Corrupt {
            detail: format!("notes ref {name} holds a non-hex entry {hex:?}"),
        })?;
        if target.kind() != kind {
            return Err(GitError::Corrupt {
                detail: format!("notes ref {name} holds a wrong-width entry {hex:?}"),
            });
        }
        entries.insert(hex, blob);
    }
    Ok(NotesHead {
        commit: Some(oid),
        entries,
    })
}

/// Publishes a notes map: flat hex-name tree, one commit on the previous
/// head, ref moved. An empty map deletes the ref instead of committing.
fn store_notes(ctx: &Ctx, name: &RefName, head: &NotesHead, message: &str) -> Result<(), GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    if head.entries.is_empty() {
        if deref_ref(store, name)?.is_some() {
            apply_refs(
                store,
                kind,
                vec![RefUpdate {
                    name: name.clone(),
                    expected: RefExpect::Any,
                    change: RefChange::Delete,
                }],
            )?;
        }
        return Ok(());
    }
    let mut tree_entries: Vec<TreeEntry> = head
        .entries
        .iter()
        .map(|(hex, oid)| TreeEntry {
            mode: TreeMode::Regular,
            name: hex.as_bytes().to_vec(),
            oid: *oid,
        })
        .collect();
    tree_entries.sort_by(|left, right| left.name.cmp(&right.name));
    let tree_oid = store_object(store, ObjectKind::Tree, encode_tree(&tree_entries))?;
    let author = identity(ctx, IdentityRole::Author)?;
    let committer = identity(ctx, IdentityRole::Committer)?;
    let parents = head
        .commit
        .map(|oid| vec![oid.to_hex()])
        .unwrap_or_default();
    let payload = commit_payload(
        &tree_oid.to_hex(),
        &parents,
        &author,
        &committer,
        message.as_bytes(),
    );
    let commit_oid = store_notes_commit(store, payload)?;
    apply_refs(
        store,
        kind,
        vec![RefUpdate {
            name: name.clone(),
            expected: if head.commit.is_some() {
                RefExpect::Any
            } else {
                RefExpect::Absent
            },
            change: RefChange::Set(RefTarget::Direct(commit_oid)),
        }],
    )?;
    Ok(())
}

/// Stores one notes commit payload with its record facts, the way
/// `commit-tree` publishes through [`Records::batch_preparer`].
fn store_notes_commit(store: &Store, payload: Vec<u8>) -> Result<Oid, GitError> {
    let kind = store.hash_kind();
    let oid = kind
        .hash_git_object("commit", &payload)
        .map_err(|err| GitError::from(CoreError::from(err)))?;
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

/// Reads the note message: repeatable `-m` (joined with newlines), then
/// `-F <file>` (`-` reads stdin), then raw stdin. Empty input refuses
/// instead of storing a bare editor launch.
fn note_message(ctx: &Ctx, opts: &Collected) -> Result<Vec<u8>, GitError> {
    let mut parts = opts.all("message")?;
    if let Some(path) = opts.single("file")? {
        let bytes = if path == "-" {
            super::read_stdin_bytes(&ctx.env)?
        } else {
            std::fs::read(ctx.env.cwd.join(&path)).map_err(|err| GitError::Io {
                detail: format!("reading {path}: {err}"),
            })?
        };
        parts.push(String::from_utf8_lossy(&bytes).into_owned());
    }
    if parts.is_empty() {
        let stdin = super::read_stdin_bytes(&ctx.env)?;
        if stdin.is_empty() {
            return Err(GitError::Invalid {
                detail: "no note message: use -m, -F, or stdin".to_owned(),
            });
        }
        return Ok(stdin);
    }
    Ok(parts.join("\n").into_bytes())
}

/// Resolves one annotated object without replace redirection: notes attach
/// to the stored object, not its replacement.
fn notes_target(ctx: &Ctx, text: &str) -> Result<Oid, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    resolve_rev_raw(store, kind, text)
}

/// Adds, shows, lists, edits, copies, removes, merges, and prunes notes.
///
/// Oracle: `git/builtin/notes.c`.
pub(crate) fn notes(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "ref",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "message",
            short: Some('m'),
            takes_value: true,
        },
        FlagSpec {
            long: "file",
            short: Some('F'),
            takes_value: true,
        },
        FlagSpec {
            long: "force",
            short: Some('f'),
            takes_value: false,
        },
        FlagSpec {
            long: "stdin",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "dry-run",
            short: Some('n'),
            takes_value: false,
        },
        FlagSpec {
            long: "verbose",
            short: Some('v'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    let (sub, rest) = match opts.positionals.split_first() {
        Some(pair) => pair,
        None => {
            return Err(GitError::Invalid {
                detail: "usage: notes [--ref <ref>] <list|add|append|edit|show|copy|remove|get-ref|merge|prune> [...]".to_owned(),
            });
        }
    };
    match sub.as_str() {
        "list" => notes_list(ctx, &opts, rest),
        "show" => notes_show(ctx, &opts, rest),
        "add" => notes_upsert(ctx, &opts, rest, UpsertMode::Add),
        "append" => notes_append(ctx, &opts, rest),
        "edit" => notes_upsert(ctx, &opts, rest, UpsertMode::Force),
        "copy" => notes_copy(ctx, &opts, rest),
        "remove" => notes_remove(ctx, &opts, rest),
        "get-ref" => notes_get_ref(ctx, &opts, rest),
        "merge" => notes_merge(ctx, &opts, rest),
        "prune" => notes_prune(ctx, &opts, rest),
        other => Err(GitError::Invalid {
            detail: format!("unknown notes subcommand {other:?}"),
        }),
    }
}

/// Lists `<note-blob-hex> <target-hex>` rows, optionally for one object.
fn notes_list(ctx: &Ctx, opts: &Collected, rest: &[String]) -> Result<Vec<u8>, GitError> {
    if rest.len() > 1 {
        return Err(GitError::Invalid {
            detail: "notes list takes at most one object".to_owned(),
        });
    }
    let name = notes_ref_name(ctx, opts)?;
    let store = ctx.store()?;
    let head = load_notes(store, ctx.kind()?, &name)?;
    let mut out = Vec::new();
    match rest.first() {
        Some(text) => {
            let oid = notes_target(ctx, text)?;
            if let Some(blob) = head.entries.get(&oid.to_hex()) {
                out.extend_from_slice(format!("{} {}\n", blob.to_hex(), oid.to_hex()).as_bytes());
            }
        }
        None => {
            for (hex, blob) in &head.entries {
                out.extend_from_slice(format!("{} {hex}\n", blob.to_hex()).as_bytes());
            }
        }
    }
    Ok(out)
}

/// Prints one raw note body.
fn notes_show(ctx: &Ctx, opts: &Collected, rest: &[String]) -> Result<Vec<u8>, GitError> {
    if rest.len() != 1 {
        return Err(GitError::Invalid {
            detail: "notes show takes exactly one object".to_owned(),
        });
    }
    let name = notes_ref_name(ctx, opts)?;
    let store = ctx.store()?;
    let head = load_notes(store, ctx.kind()?, &name)?;
    let oid = notes_target(ctx, &rest[0])?;
    let Some(blob) = head.entries.get(&oid.to_hex()) else {
        return Err(GitError::NotFound {
            detail: format!("no note for object {}", oid.to_hex()),
        });
    };
    let (_, body) = read_object_bytes(store, *blob)?;
    Ok(body)
}

/// Whether an upsert refuses or overwrites an existing note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UpsertMode {
    /// `add`: refuse when present unless `-f`.
    Add,
    /// `edit`: always overwrite (content comes from `-m`/`-F`/stdin; no
    /// editor exists, which `edit` would otherwise launch).
    Force,
}

/// Adds a note, or overwrites one for `edit` / `add -f`.
fn notes_upsert(
    ctx: &Ctx,
    opts: &Collected,
    rest: &[String],
    mode: UpsertMode,
) -> Result<Vec<u8>, GitError> {
    if rest.len() != 1 {
        return Err(GitError::Invalid {
            detail: "notes add takes exactly one object".to_owned(),
        });
    }
    let name = notes_ref_name(ctx, opts)?;
    let store = ctx.store()?;
    let mut head = load_notes(store, ctx.kind()?, &name)?;
    let oid = notes_target(ctx, &rest[0])?;
    if mode == UpsertMode::Add && head.entries.contains_key(&oid.to_hex()) && !opts.is_set("force")
    {
        return Err(GitError::Invalid {
            detail: format!(
                "object {} already has a note (use -f to overwrite)",
                oid.to_hex()
            ),
        });
    }
    let body = note_message(ctx, opts)?;
    let blob = store_object(store, ObjectKind::Blob, body)?;
    head.entries.insert(oid.to_hex(), blob);
    store_notes(
        ctx,
        &name,
        &head,
        &format!("notes: note for {}", oid.to_hex()),
    )?;
    Ok(Vec::new())
}

/// Appends a message to a note, creating it when absent.
fn notes_append(ctx: &Ctx, opts: &Collected, rest: &[String]) -> Result<Vec<u8>, GitError> {
    if rest.len() != 1 {
        return Err(GitError::Invalid {
            detail: "notes append takes exactly one object".to_owned(),
        });
    }
    let name = notes_ref_name(ctx, opts)?;
    let store = ctx.store()?;
    let mut head = load_notes(store, ctx.kind()?, &name)?;
    let oid = notes_target(ctx, &rest[0])?;
    let addition = note_message(ctx, opts)?;
    let mut combined = match head.entries.get(&oid.to_hex()) {
        Some(blob) => {
            let (_, old) = read_object_bytes(store, *blob)?;
            let mut text = String::from_utf8_lossy(&old).into_owned();
            while text.ends_with('\n') {
                text.pop();
            }
            if text.is_empty() {
                Vec::new()
            } else {
                let mut out = text.into_bytes();
                out.push(b'\n');
                out
            }
        }
        None => Vec::new(),
    };
    combined.extend_from_slice(&addition);
    let blob = store_object(store, ObjectKind::Blob, combined)?;
    head.entries.insert(oid.to_hex(), blob);
    store_notes(
        ctx,
        &name,
        &head,
        &format!("notes: append for {}", oid.to_hex()),
    )?;
    Ok(Vec::new())
}

/// Copies a note blob from one object to another.
fn notes_copy(ctx: &Ctx, opts: &Collected, rest: &[String]) -> Result<Vec<u8>, GitError> {
    if rest.len() != 2 {
        return Err(GitError::Invalid {
            detail: "notes copy takes exactly two objects".to_owned(),
        });
    }
    let name = notes_ref_name(ctx, opts)?;
    let store = ctx.store()?;
    let mut head = load_notes(store, ctx.kind()?, &name)?;
    let from = notes_target(ctx, &rest[0])?;
    let to = notes_target(ctx, &rest[1])?;
    let Some(blob) = head.entries.get(&from.to_hex()).copied() else {
        return Err(GitError::NotFound {
            detail: format!("no note for object {}", from.to_hex()),
        });
    };
    if head.entries.contains_key(&to.to_hex()) && !opts.is_set("force") {
        return Err(GitError::Invalid {
            detail: format!(
                "object {} already has a note (use -f to overwrite)",
                to.to_hex()
            ),
        });
    }
    head.entries.insert(to.to_hex(), blob);
    store_notes(
        ctx,
        &name,
        &head,
        &format!("notes: copy {} to {}", from.to_hex(), to.to_hex()),
    )?;
    Ok(Vec::new())
}

/// Removes notes for objects named on argv, on stdin with `--stdin`, or both.
fn notes_remove(ctx: &Ctx, opts: &Collected, rest: &[String]) -> Result<Vec<u8>, GitError> {
    let mut texts: Vec<String> = rest.to_vec();
    if opts.is_set("stdin") {
        let stdin = super::read_stdin_bytes(&ctx.env)?;
        for line in String::from_utf8_lossy(&stdin).lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                texts.push(trimmed.to_owned());
            }
        }
    }
    if texts.is_empty() {
        return Err(GitError::Invalid {
            detail: "notes remove takes at least one object".to_owned(),
        });
    }
    let name = notes_ref_name(ctx, opts)?;
    let store = ctx.store()?;
    let mut head = load_notes(store, ctx.kind()?, &name)?;
    for text in &texts {
        let oid = notes_target(ctx, text)?;
        if head.entries.remove(&oid.to_hex()).is_none() {
            return Err(GitError::NotFound {
                detail: format!("no note for object {}", oid.to_hex()),
            });
        }
    }
    store_notes(ctx, &name, &head, "notes: remove")?;
    Ok(Vec::new())
}

/// Prints the notes ref this invocation would use.
fn notes_get_ref(ctx: &Ctx, opts: &Collected, rest: &[String]) -> Result<Vec<u8>, GitError> {
    if !rest.is_empty() {
        return Err(GitError::Invalid {
            detail: "notes get-ref takes no object".to_owned(),
        });
    }
    let name = notes_ref_name(ctx, opts)?;
    Ok(format!("{name}\n").into_bytes())
}

/// Unions another notes ref into this one, refusing differing blobs.
fn notes_merge(ctx: &Ctx, opts: &Collected, rest: &[String]) -> Result<Vec<u8>, GitError> {
    if rest.len() != 1 {
        return Err(GitError::Invalid {
            detail: "notes merge takes exactly one notes ref".to_owned(),
        });
    }
    let name = notes_ref_name(ctx, opts)?;
    let other_name = other_notes_ref_name(&rest[0])?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut head = load_notes(store, kind, &name)?;
    let other = load_notes(store, kind, &other_name)?;
    let mut out = Vec::new();
    for (hex, blob) in &other.entries {
        match head.entries.get(hex) {
            None => {
                head.entries.insert(hex.clone(), *blob);
                if opts.is_set("verbose") {
                    out.extend_from_slice(format!("merged {hex}\n").as_bytes());
                }
            }
            Some(known) if known == blob => {}
            Some(_) => {
                return Err(GitError::Invalid {
                    detail: format!("cannot merge note for {hex}: differs on both sides"),
                });
            }
        }
    }
    store_notes(ctx, &name, &head, &format!("notes: merge {}", rest[0]))?;
    Ok(out)
}

/// Drops notes whose target object no longer exists: `-n` reports without
/// writing, `-v` reports while writing.
fn notes_prune(ctx: &Ctx, opts: &Collected, rest: &[String]) -> Result<Vec<u8>, GitError> {
    if !rest.is_empty() {
        return Err(GitError::Invalid {
            detail: "notes prune takes no object".to_owned(),
        });
    }
    let name = notes_ref_name(ctx, opts)?;
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let mut head = load_notes(store, kind, &name)?;
    let dry = opts.is_set("dry-run");
    let verbose = opts.is_set("verbose");
    let mut out = Vec::new();
    let mut dead = Vec::new();
    for (hex, _) in &head.entries {
        let Ok(target) = Oid::from_hex(hex) else {
            continue;
        };
        if read_object_bytes(store, target).is_err() {
            dead.push(hex.clone());
        }
    }
    for hex in &dead {
        if dry {
            out.extend_from_slice(format!("would prune {hex}\n").as_bytes());
        } else {
            head.entries.remove(hex);
            if verbose {
                out.extend_from_slice(format!("pruned {hex}\n").as_bytes());
            }
        }
    }
    if !dry && !dead.is_empty() {
        store_notes(ctx, &name, &head, "notes: prune")?;
    }
    Ok(out)
}

/// The ref holding the replacement for `orig`, when present.
fn replace_ref_name(orig: &Oid) -> Result<RefName, GitError> {
    RefName::new(format!("refs/replace/{}", orig.to_hex())).map_err(|err| GitError::Invalid {
        detail: format!("bad replacement name: {err}"),
    })
}

/// Matches `<pattern>` with `*` (any run) and `?` (one byte), for `-l`.
fn replace_glob(pattern: &str, text: &str) -> bool {
    fn go(pattern: &[u8], text: &[u8]) -> bool {
        if pattern.is_empty() {
            return text.is_empty();
        }
        match pattern[0] {
            b'*' => {
                let mut rest = &pattern[1..];
                while rest.first() == Some(&b'*') {
                    rest = &rest[1..];
                }
                (0..=text.len()).any(|index| go(rest, &text[index..]))
            }
            b'?' => !text.is_empty() && go(&pattern[1..], &text[1..]),
            byte => text.first() == Some(&byte) && go(&pattern[1..], &text[1..]),
        }
    }
    go(pattern.as_bytes(), text.as_bytes())
}

/// Creates, lists, and deletes object replacements.
///
/// Oracle: `git/builtin/replace.c`.
pub(crate) fn replace(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "list",
            short: Some('l'),
            takes_value: false,
        },
        FlagSpec {
            long: "delete",
            short: Some('d'),
            takes_value: false,
        },
        FlagSpec {
            long: "force",
            short: Some('f'),
            takes_value: false,
        },
        FlagSpec {
            long: "format",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "graft",
            short: Some('g'),
            takes_value: false,
        },
        FlagSpec {
            long: "edit",
            short: Some('e'),
            takes_value: false,
        },
    ];
    let opts = collect(args, &specs)?;
    if opts.single("format")?.is_some() {
        return Err(GitError::Unsupported {
            command: "replace --format".to_owned(),
        });
    }
    if opts.is_set("graft") {
        return Err(GitError::Unsupported {
            command: "replace --graft".to_owned(),
        });
    }
    if opts.is_set("edit") {
        return Err(GitError::Unsupported {
            command: "replace -e".to_owned(),
        });
    }
    if opts.is_set("list") {
        return replace_list(ctx, &opts.positionals);
    }
    if opts.is_set("delete") {
        return replace_delete(ctx, &opts.positionals);
    }
    match opts.positionals.as_slice() {
        [orig_text, repl_text] => replace_create(ctx, opts.is_set("force"), orig_text, repl_text),
        _ => Err(GitError::Invalid {
            detail: "usage: replace [-f] <object> <replacement>; replace -d <object>...; replace -l [<pattern>]".to_owned(),
        }),
    }
}

/// Points `refs/replace/<orig>` at the replacement, refusing clobbers
/// without `-f` and self-replacement outright (the read loop would spin).
fn replace_create(
    ctx: &Ctx,
    force: bool,
    orig_text: &str,
    repl_text: &str,
) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let orig = resolve_rev_raw(store, kind, orig_text)?;
    let repl = resolve_rev_raw(store, kind, repl_text)?;
    if orig == repl {
        return Err(GitError::Invalid {
            detail: "cannot replace an object with itself".to_owned(),
        });
    }
    if read_object_bytes(store, orig).is_err() {
        return Err(GitError::NotFound {
            detail: format!("object {} does not exist", orig.to_hex()),
        });
    }
    if read_object_bytes(store, repl).is_err() {
        return Err(GitError::NotFound {
            detail: format!("replacement {} does not exist", repl.to_hex()),
        });
    }
    let name = replace_ref_name(&orig)?;
    if read_ref(store, &name)?.is_some() && !force {
        return Err(GitError::Invalid {
            detail: format!(
                "replacement for {} already exists (use -f to overwrite)",
                orig.to_hex()
            ),
        });
    }
    apply_refs(
        store,
        kind,
        vec![RefUpdate {
            name,
            expected: RefExpect::Any,
            change: RefChange::Set(RefTarget::Direct(repl)),
        }],
    )?;
    Ok(Vec::new())
}

/// Lists replaced object hexes, one per line, filtered by an optional glob.
fn replace_list(ctx: &Ctx, patterns: &[String]) -> Result<Vec<u8>, GitError> {
    if patterns.len() > 1 {
        return Err(GitError::Invalid {
            detail: "replace -l takes at most one pattern".to_owned(),
        });
    }
    const PREFIX: &str = "refs/replace/";
    let mut out = Vec::new();
    for (name, _) in list_refs(ctx.store()?)? {
        let text = String::from_utf8_lossy(name.as_bytes()).into_owned();
        let Some(hex) = text.strip_prefix(PREFIX) else {
            continue;
        };
        if let Some(pattern) = patterns.first() {
            if !replace_glob(pattern, hex) && !replace_glob(pattern, &text) {
                continue;
            }
        }
        out.extend_from_slice(format!("{hex}\n").as_bytes());
    }
    Ok(out)
}

/// Deletes the replacement refs for the named objects.
fn replace_delete(ctx: &Ctx, targets: &[String]) -> Result<Vec<u8>, GitError> {
    if targets.is_empty() {
        return Err(GitError::Invalid {
            detail: "replace -d takes at least one object".to_owned(),
        });
    }
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    for text in targets {
        let orig = resolve_rev_raw(store, kind, text)?;
        let name = replace_ref_name(&orig)?;
        if read_ref(store, &name)?.is_none() {
            return Err(GitError::NotFound {
                detail: format!("no replacement for {}", orig.to_hex()),
            });
        }
        apply_refs(
            store,
            kind,
            vec![RefUpdate {
                name,
                expected: RefExpect::Any,
                change: RefChange::Delete,
            }],
        )?;
    }
    Ok(Vec::new())
}
