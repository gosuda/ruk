//! Preimage capture and unsafe-overwrite rejection.
//!
//! Every path the materialization may touch is observed before the journal
//! exists: the caller's planned paths, every untracked blocker in the way of
//! a target (a non-directory ancestor, or content inside a directory a file
//! replaces), and every directory a file replaces. Actual worktree bytes are
//! hashed and compared with the snapshot manifest entry (`expected`); a path
//! that differs is an unsafe overwrite and the whole call fails with
//! `E_DIRTY` before anything is published or written, unless the path is
//! listed in the explicit discard set. Discarded content is still captured
//! as a preimage blob, so abort can restore it.
//!
//! Comparison is by content hash, not by stat: the bytes are read anyway to
//! capture them, so no timestamp ambiguity can mark a changed file clean.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;

use crate::bytes::ByteString;
use crate::error::{CoreError, ErrorCode};
use crate::ids::{HashKind, Oid};
use crate::index::{FileMode, RepoPath};
use crate::store::{ObjectKind, PreparedObject, Store};
use crate::workspace::Scope;

use super::journal::{JournalEntry, Preimage, Shape, TargetEntry, Transition, ancestors};
use super::safety::{self, Ancestry, Observed, WorkRoot};

/// Largest symlink target read back from the store.
const MAX_LINK_BYTES: u64 = 64 * 1024;

/// Largest number of untracked directory entries one capture may walk.
const MAX_WALK_ENTRIES: usize = 1 << 20;

/// Largest number of dirty paths named in one `E_DIRTY` message.
const DIRTY_REPORT_LIMIT: usize = 32;

/// One entry of a tree manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ManifestEntry {
    pub(crate) mode: FileMode,
    pub(crate) oid: Oid,
}

/// One planned path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PlanEntry {
    pub(crate) path: RepoPath,
    /// The snapshot manifest's entry: what the worktree held when it was
    /// last recorded. `None` means the path was not tracked there.
    pub(crate) expected: Option<ManifestEntry>,
    /// What the path must become; `None` deletes it.
    pub(crate) target: Option<ManifestEntry>,
    /// Link bytes for a symlink target whose blob is supplied in
    /// [`super::MaterializePlan::target_objects`] rather than committed.
    /// Verified against the target oid.
    pub(crate) target_link: Option<ByteString>,
}

/// Captured journal entries and the preimage blobs to publish with them.
#[derive(Debug)]
pub(crate) struct Captured {
    pub(crate) entries: Vec<JournalEntry>,
    pub(crate) objects: Vec<PreparedObject>,
}

#[derive(Clone, Debug)]
struct Planned {
    expected: Option<ManifestEntry>,
    target: Option<TargetEntry>,
}

impl Planned {
    const UNTRACKED: Self = Self {
        expected: None,
        target: None,
    };
}

/// Observes, checks and captures every affected path.
///
/// # Errors
/// `E_INVALID` for a malformed plan (duplicate path, wrong hash kind, a
/// target below another file target, out-of-scope target, `.ruk` path);
/// `E_DIRTY` naming every unsafe overwrite; `E_CAPACITY` past the walk
/// bound; `E_IO`.
pub(crate) fn capture(
    store: &Store,
    root: &WorkRoot,
    plan: Vec<PlanEntry>,
    discard: &BTreeSet<RepoPath>,
    scope: &Scope,
) -> Result<Captured, CoreError> {
    let kind = store.hash_kind();
    let mut planned = validate_plan(store, plan, scope)?;
    let target_dirs: BTreeSet<Vec<u8>> = planned
        .iter()
        .filter(|(_, entry)| entry.target.is_some())
        .flat_map(|(path, _)| ancestors(path).map(<[u8]>::to_vec))
        .collect();
    let mut dirty = Vec::new();
    add_ancestor_blockers(root, &mut planned, discard, &mut dirty)?;
    add_replaced_dir_contents(root, &mut planned, &target_dirs, discard, &mut dirty)?;

    let mut observed = Vec::with_capacity(planned.len());
    for (path, entry) in &planned {
        let seen = root.observe(kind, path)?;
        if seen == Observed::Other {
            dirty.push(format!("{} (special file)", lossy(path.as_bytes())));
        } else if !expected_matches(entry.expected.as_ref(), &seen) && !discard.contains(path) {
            dirty.push(lossy(path.as_bytes()));
        }
        observed.push(seen);
    }
    if !dirty.is_empty() {
        return Err(dirty_error(dirty));
    }

    let mut objects = Vec::new();
    let mut prepared: BTreeSet<Oid> = BTreeSet::new();
    let mut entries = Vec::with_capacity(planned.len());
    for ((path, entry), seen) in planned.into_iter().zip(observed) {
        let preimage = capture_preimage(
            store,
            root,
            &path,
            entry.expected.as_ref(),
            seen,
            &mut objects,
            &mut prepared,
        )?;
        entries.push((path, entry.target, preimage));
    }
    Ok(Captured {
        entries: assign_transitions(entries, &target_dirs),
        objects,
    })
}

fn validate_plan(
    store: &Store,
    plan: Vec<PlanEntry>,
    scope: &Scope,
) -> Result<BTreeMap<RepoPath, Planned>, CoreError> {
    let kind = store.hash_kind();
    let mut planned = BTreeMap::new();
    for entry in plan {
        safety::check_repo_path(&entry.path)?;
        let name = lossy(entry.path.as_bytes());
        for manifest in entry.expected.iter().chain(entry.target.iter()) {
            manifest
                .oid
                .expect_kind(kind, "materialization manifest")
                .map_err(CoreError::from)?;
        }
        if entry.target.is_some() && !scope.includes_file(&entry.path) {
            return Err(invalid(format!(
                "{name}: target lies outside the workspace scope"
            )));
        }
        let target = match entry.target {
            Some(manifest) => Some(target_entry(
                store,
                kind,
                &name,
                manifest,
                entry.target_link,
            )?),
            None if entry.target_link.is_some() => {
                return Err(invalid(format!(
                    "{name}: link bytes without a symlink target"
                )));
            }
            None => None,
        };
        let previous = planned.insert(
            entry.path,
            Planned {
                expected: entry.expected,
                target,
            },
        );
        if previous.is_some() {
            return Err(invalid(format!("{name}: path planned twice")));
        }
    }
    for (path, entry) in &planned {
        if entry.target.is_none() {
            continue;
        }
        for ancestor in ancestors(path) {
            if planned
                .get(ancestor)
                .is_some_and(|parent| parent.target.is_some())
            {
                return Err(invalid(format!(
                    "{}: target lies below file target {}",
                    lossy(path.as_bytes()),
                    lossy(ancestor)
                )));
            }
        }
    }
    Ok(planned)
}

fn target_entry(
    store: &Store,
    kind: HashKind,
    name: &str,
    manifest: ManifestEntry,
    link: Option<ByteString>,
) -> Result<TargetEntry, CoreError> {
    if manifest.mode != FileMode::Symlink {
        if link.is_some() {
            return Err(invalid(format!(
                "{name}: link bytes for a non-symlink target"
            )));
        }
        return Ok(TargetEntry {
            mode: manifest.mode,
            oid: manifest.oid,
            link: None,
        });
    }
    let link = match link {
        Some(link) => link,
        None => ByteString::new(read_link_blob(store, manifest.oid)?),
    };
    if kind
        .hash_git_object("blob", link.as_bytes())
        .map_err(CoreError::from)?
        != manifest.oid
    {
        return Err(invalid(format!(
            "{name}: symlink bytes do not hash to the target oid"
        )));
    }
    if link.is_empty() || link.as_bytes().contains(&0) {
        return Err(invalid(format!(
            "{name}: symlink target is empty or contains NUL"
        )));
    }
    Ok(TargetEntry {
        mode: FileMode::Symlink,
        oid: manifest.oid,
        link: Some(link),
    })
}

fn read_link_blob(store: &Store, oid: Oid) -> Result<Vec<u8>, CoreError> {
    let mut object = store.read(oid)?;
    if object.kind != ObjectKind::Blob {
        return Err(invalid(format!("symlink target {oid} is not a blob")));
    }
    if object.bytes.len() > MAX_LINK_BYTES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            format!("symlink target {oid} exceeds {MAX_LINK_BYTES} bytes"),
        ));
    }
    let mut link = Vec::new();
    object
        .bytes
        .read_to_end(&mut link)
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("read symlink blob {oid}: {err}")))?;
    Ok(link)
}

/// A file or symlink ancestor of a target is either journaled for removal,
/// explicitly discarded (then journaled), or an unsafe overwrite.
fn add_ancestor_blockers(
    root: &WorkRoot,
    planned: &mut BTreeMap<RepoPath, Planned>,
    discard: &BTreeSet<RepoPath>,
    dirty: &mut Vec<String>,
) -> Result<(), CoreError> {
    let mut blockers = BTreeSet::new();
    for (path, entry) in planned.iter() {
        if entry.target.is_none() {
            continue;
        }
        if let Ancestry::Blocked { ancestor } = root.ancestry(path)? {
            blockers.insert(ancestor);
        }
    }
    for ancestor in blockers {
        let path = RepoPath::new(ancestor).map_err(CoreError::from)?;
        if planned.contains_key(&path) {
            continue;
        }
        if discard.contains(&path) {
            planned.insert(path, Planned::UNTRACKED);
        } else {
            dirty.push(format!("{} (blocks a target)", lossy(path.as_bytes())));
        }
    }
    Ok(())
}

/// A directory standing where a target needs a non-directory must contain
/// only journaled content. Its subdirectories are journaled automatically
/// (they hold no bytes); untracked files need discard.
fn add_replaced_dir_contents(
    root: &WorkRoot,
    planned: &mut BTreeMap<RepoPath, Planned>,
    target_dirs: &BTreeSet<Vec<u8>>,
    discard: &BTreeSet<RepoPath>,
    dirty: &mut Vec<String>,
) -> Result<(), CoreError> {
    let mut stack: Vec<RepoPath> = Vec::new();
    for (path, entry) in planned.iter() {
        let wants_dir = match &entry.target {
            Some(target) => target.mode == FileMode::Gitlink,
            None => target_dirs.contains(path.as_bytes()),
        };
        if wants_dir {
            continue;
        }
        if let Some(full) = root.resolve_clear(path).ok().flatten()
            && safety::lstat(&full)?.is_some_and(|meta| safety::is_real_dir(&meta))
        {
            stack.push(path.clone());
        }
    }
    let mut budget = MAX_WALK_ENTRIES;
    while let Some(dir) = stack.pop() {
        let full = root.join(dir.as_bytes())?;
        let listing = fs::read_dir(&full).map_err(|err| safety::io_error("list", &full, &err))?;
        for child in listing {
            let child = child.map_err(|err| safety::io_error("list", &full, &err))?;
            budget = budget.checked_sub(1).ok_or_else(|| {
                CoreError::new(
                    ErrorCode::ECapacity,
                    format!("more than {MAX_WALK_ENTRIES} entries inside replaced directories"),
                )
            })?;
            let mut bytes = dir.as_bytes().to_vec();
            bytes.push(b'/');
            bytes.extend_from_slice(&name_bytes(&child.file_name())?);
            let Ok(path) = RepoPath::new(bytes.clone()) else {
                dirty.push(format!("{} (unrepresentable name)", lossy(&bytes)));
                continue;
            };
            let file_type = child
                .file_type()
                .map_err(|err| safety::io_error("stat", &child.path(), &err))?;
            if file_type.is_dir() {
                planned.entry(path.clone()).or_insert(Planned::UNTRACKED);
                stack.push(path);
                continue;
            }
            if planned.contains_key(&path) {
                continue;
            }
            if discard.contains(&path) {
                planned.insert(path, Planned::UNTRACKED);
            } else {
                dirty.push(format!(
                    "{} (untracked, in a replaced directory)",
                    lossy(&bytes)
                ));
            }
        }
    }
    Ok(())
}

fn expected_matches(expected: Option<&ManifestEntry>, seen: &Observed) -> bool {
    let Some(expected) = expected else {
        return matches!(seen, Observed::Absent | Observed::Dir);
    };
    match (expected.mode, seen) {
        (FileMode::Regular | FileMode::Executable, Observed::File { .. }) => Shape::File {
            executable: expected.mode == FileMode::Executable,
            oid: expected.oid,
        }
        .matches(seen),
        (FileMode::Symlink, Observed::Symlink { oid, .. }) => *oid == expected.oid,
        (FileMode::Gitlink, Observed::Dir) => true,
        _ => false,
    }
}

/// Records what the path holds. Bytes already committed under the
/// expected oid are not re-stored; anything else is prepared now.
fn capture_preimage(
    store: &Store,
    root: &WorkRoot,
    path: &RepoPath,
    expected: Option<&ManifestEntry>,
    seen: Observed,
    objects: &mut Vec<PreparedObject>,
    prepared: &mut BTreeSet<Oid>,
) -> Result<Preimage, CoreError> {
    let mut committed = |oid: Oid| {
        expected.is_some_and(|entry| entry.oid == oid && entry.mode != FileMode::Gitlink)
            || !prepared.insert(oid)
    };
    match seen {
        Observed::Absent => Ok(Preimage::Absent),
        Observed::Dir => Ok(Preimage::Directory),
        Observed::Other => Err(dirty_error(vec![lossy(path.as_bytes())])),
        Observed::Symlink { link, oid } => {
            if !committed(oid) {
                let len = u64::try_from(link.len()).unwrap_or(u64::MAX);
                objects.push(store.prepare(ObjectKind::Blob, len, link.as_slice(), None)?);
            }
            Ok(Preimage::Symlink {
                link: ByteString::new(link),
                oid,
            })
        }
        Observed::File { executable, oid } => {
            if !committed(oid) {
                objects.push(prepare_file(store, root, path, oid)?);
            }
            Ok(Preimage::File { executable, oid })
        }
    }
}

fn prepare_file(
    store: &Store,
    root: &WorkRoot,
    path: &RepoPath,
    observed: Oid,
) -> Result<PreparedObject, CoreError> {
    let changed = || {
        CoreError::new(
            ErrorCode::EDirty,
            format!("{} changed while it was captured", lossy(path.as_bytes())),
        )
    };
    let full = root.resolve_clear(path)?.ok_or_else(changed)?;
    let file = safety::open_no_follow(&full)?;
    let len = file
        .metadata()
        .map_err(|err| safety::io_error("stat", &full, &err))?
        .len();
    let prepared = store.prepare(ObjectKind::Blob, len, file, None)?;
    if prepared.oid() != observed {
        return Err(changed());
    }
    Ok(prepared)
}

/// Derives each path's transition and drops paths already at their target.
fn assign_transitions(
    entries: Vec<(RepoPath, Option<TargetEntry>, Preimage)>,
    target_dirs: &BTreeSet<Vec<u8>>,
) -> Vec<JournalEntry> {
    let mut deleted: BTreeMap<(bool, Oid), RepoPath> = BTreeMap::new();
    for (path, target, preimage) in &entries {
        if target.is_none()
            && !target_dirs.contains(path.as_bytes())
            && let Preimage::File { executable, oid } = preimage
        {
            deleted
                .entry((*executable, *oid))
                .or_insert_with(|| path.clone());
        }
    }
    let mut journal = Vec::with_capacity(entries.len());
    for (path, target, preimage) in entries {
        let target_shape = match &target {
            Some(entry) => entry.shape(),
            None if target_dirs.contains(path.as_bytes()) => Shape::Dir,
            None => Shape::Absent,
        };
        let pre_shape = preimage.shape();
        if pre_shape == target_shape {
            continue;
        }
        let transition = match (&pre_shape, &target_shape) {
            (Shape::Absent, Shape::File { executable, oid }) => deleted
                .remove(&(*executable, *oid))
                .map_or(Transition::Create, |from| Transition::Rename { from }),
            (Shape::Absent, _) => Transition::Create,
            (_, Shape::Absent) => Transition::Delete,
            (pre, post) if pre.is_dir() || post.is_dir() => Transition::DirFileSwap,
            (Shape::Symlink { .. }, _) | (_, Shape::Symlink { .. }) => Transition::SymlinkChange,
            (Shape::File { oid: before, .. }, Shape::File { oid: after, .. })
                if before == after =>
            {
                Transition::ModeChange
            }
            _ => Transition::Modify,
        };
        journal.push(JournalEntry {
            path,
            target,
            preimage,
            transition,
        });
    }
    journal
}

#[cfg(unix)]
fn name_bytes(name: &std::ffi::OsStr) -> Result<Vec<u8>, CoreError> {
    use std::os::unix::ffi::OsStrExt;
    Ok(name.as_bytes().to_vec())
}

#[cfg(not(unix))]
fn name_bytes(name: &std::ffi::OsStr) -> Result<Vec<u8>, CoreError> {
    name.to_str()
        .map(|text| text.as_bytes().to_vec())
        .ok_or_else(|| invalid("non-UTF-8 name in a replaced directory".to_owned()))
}

fn dirty_error(mut paths: Vec<String>) -> CoreError {
    paths.sort();
    paths.dedup();
    let total = paths.len();
    let mut message = format!("{total} unsafe overwrite(s) before materialization: ");
    message.push_str(
        &paths
            .iter()
            .take(DIRTY_REPORT_LIMIT)
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
    );
    if total > DIRTY_REPORT_LIMIT {
        message.push_str(&format!(", and {} more", total - DIRTY_REPORT_LIMIT));
    }
    CoreError::new(ErrorCode::EDirty, message)
        .with_hint("list the paths in discard to overwrite them explicitly")
}

fn invalid(message: String) -> CoreError {
    CoreError::new(ErrorCode::EInvalid, message)
}

pub(crate) fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
