//! Hosted read producers: the coordinator arms for the browsing reads.
//!
//! The CLI renders the same objects as text. These helpers build the
//! protocol replies instead: they resolve revisions through [`Records`],
//! walk trees with [`parse_tree`], and page through [`Page`] with the
//! coordinator's read leases. Nothing here publishes.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Read as _;

use sha2::{Digest, Sha256};

use crate::ByteString;
use crate::MAX_CONTROL_FRAME_BYTES;
use crate::change::ChangeId;
use crate::commit::CommitRecord;
use crate::error::{CoreError, ErrorCode};
use crate::graph::composite::GraphIndex;
use crate::heads::Head;
use crate::ids::{HashKind, Oid};
use crate::index::{FileMode, RepoPath};
use crate::protocol::{ChangeRef, EntryKind, QueryDigest, RevisionRef, TreeEntry};
use crate::records::Records;
use crate::store::Store;
use crate::store::types::ObjectKind;
use crate::workcopy::tree::{TreeItem, TreeMode, git_order, parse_tree};

/// Resolves one head to its tree, refusing conflicted commits.
pub(crate) fn head_tree(store: &Store, head: &Head) -> Result<Oid, CoreError> {
    let record = Records::new(store)
        .get_commit(head)?
        .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "unknown head"))?;
    record
        .tree()
        .as_resolved()
        .copied()
        .ok_or_else(|| CoreError::new(ErrorCode::EConflicted, "head is conflicted"))
}

/// Resolves one head to its commit record.
pub(crate) fn head_commit(store: &Store, head: &Head) -> Result<CommitRecord, CoreError> {
    Records::new(store)
        .get_commit(head)?
        .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "unknown head"))
}

/// Resolves one revision to its tree, refusing workspaces and conflicts.
pub(crate) fn revision_tree(store: &Store, at: &RevisionRef) -> Result<Oid, CoreError> {
    match at {
        RevisionRef::Head { head } => head_tree(store, head),
        RevisionRef::Change { change } => {
            let head = change_head(store, change)?;
            head_tree(store, &head)
        }
        RevisionRef::Workspace { .. } => Err(CoreError::new(
            ErrorCode::EInvalid,
            "workspace revisions need a workcopy crawl",
        )),
    }
}

/// Bytes one hosted read may load before refusing.
///
/// The length check runs before the object loads, so a hostile blob or
/// tree cannot force an unbounded allocation on the read path.
pub(crate) const READ_MAX_BYTES: u64 = 16_777_216;

/// Reads one object fully, refusing bodies past [`READ_MAX_BYTES`].
fn bounded_object_bytes(store: &Store, oid: Oid) -> Result<Vec<u8>, CoreError> {
    if store
        .object_len(oid)
        .map_err(CoreError::from)?
        .is_some_and(|len| len > READ_MAX_BYTES)
    {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "object exceeds the hosted read bound",
        ));
    }
    let object = store.read(oid).map_err(CoreError::from)?;
    let mut bytes = Vec::new();
    object
        .bytes
        .take(READ_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| CoreError::new(ErrorCode::EIo, err.to_string()))?;
    let loaded = u64::try_from(bytes.len())
        .map_err(|_| CoreError::new(ErrorCode::ELimit, "object exceeds the hosted read bound"))?;
    if loaded > READ_MAX_BYTES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "object exceeds the hosted read bound",
        ));
    }
    Ok(bytes)
}

/// Reads one blob fully, refusing other objects.
pub(crate) fn blob_bytes(store: &Store, oid: Oid) -> Result<Vec<u8>, CoreError> {
    let object = store.read(oid).map_err(CoreError::from)?;
    if object.kind != ObjectKind::Blob {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "path names a non-blob object",
        ));
    }
    bounded_object_bytes(store, oid)
}

/// Inline content, refusing bodies past the control frame bound.
pub(crate) fn inline_body(bytes: Vec<u8>) -> Result<crate::protocol::ByteSource, CoreError> {
    if bytes.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "blob exceeds the inline body bound",
        ));
    }
    Ok(crate::protocol::ByteSource::Inline {
        data: ByteString::from(bytes),
    })
}

/// Parses one stored tree object in git order.
pub(crate) fn tree_items(
    store: &Store,
    kind: HashKind,
    root: Oid,
) -> Result<Vec<TreeItem>, CoreError> {
    let object = store.read(root).map_err(CoreError::from)?;
    if object.kind != ObjectKind::Tree {
        return Err(CoreError::new(
            ErrorCode::ECorrupt,
            "tree object has the wrong kind",
        ));
    }
    let bytes = bounded_object_bytes(store, root)?;
    let mut items = parse_tree(kind, &bytes)?;
    items.sort_by(git_order);
    Ok(items)
}

/// Maps one tree mode to its protocol entry kind.
pub(crate) fn entry_kind(mode: TreeMode) -> EntryKind {
    match mode {
        TreeMode::Tree => EntryKind::Tree,
        TreeMode::File(FileMode::Regular) => EntryKind::Regular,
        TreeMode::File(FileMode::Executable) => EntryKind::Executable,
        TreeMode::File(FileMode::Symlink) => EntryKind::Symlink,
        TreeMode::File(FileMode::Gitlink) => EntryKind::Gitlink,
    }
}

/// Builds one protocol tree entry with its stored blob length.
///
/// Trees and gitlinks carry no size. A blob link to a missing object
/// refuses `E_CORRUPT`: the tree is damaged.
pub(crate) fn sized_tree_entry(
    store: &Store,
    name: Vec<u8>,
    mode: TreeMode,
    oid: Oid,
) -> Result<TreeEntry, CoreError> {
    let kind = entry_kind(mode);
    let size = match mode {
        TreeMode::Tree => None,
        TreeMode::File(FileMode::Gitlink) => None,
        TreeMode::File(_) => {
            let length = store
                .object_len(oid)
                .map_err(CoreError::from)?
                .ok_or_else(|| {
                    CoreError::new(ErrorCode::ECorrupt, "tree entry links a missing object")
                })?;
            Some(length)
        }
    };
    Ok(TreeEntry {
        name: ByteString::from(name),
        oid,
        kind,
        size,
    })
}

/// Query digest binding one file directory page.
pub(crate) fn file_query_digest(root: Oid, path: Option<&RepoPath>) -> QueryDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"ruk.file/v1\x00");
    hasher.update(root.as_bytes());
    match path {
        None => hasher.update([0x00]),
        Some(path) => {
            hasher.update([0x01]);
            hasher.update(path.as_bytes());
        }
    }
    QueryDigest::from_bytes(hasher.finalize().into())
}

/// Cells one hosted line alignment may fill before the read refuses.
///
/// The bound caps both time and the `u32` length table: past it the caller
/// reports [`ErrorCode::ELimit`] instead of aligning.
pub(crate) const LCS_MAX_CELLS: u64 = 1_048_576;

/// Tree entries one diff side may flatten before the read refuses.
pub(crate) const DIFF_MAX_ENTRIES: usize = 32_768;

/// Commits one blame walk may visit before the read refuses.
pub(crate) const BLAME_MAX_COMMITS: usize = 4_096;

/// Distinct blob versions one blame walk may cache before the read refuses.
pub(crate) const BLAME_MAX_VERSIONS: usize = 256;

/// Context lines around each unified hunk.
const DIFF_CONTEXT: usize = 3;

/// One alignment step between two line sequences.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LcsOp {
    Match,
    Del,
    Ins,
}

/// Aligns two line sequences with a cell-capped dynamic program.
///
/// Returns the operation script turning `old` into `new`. Past
/// [`LCS_MAX_CELLS`] the read refuses with [`ErrorCode::ELimit`]; the
/// unbounded notebook `compute_lcs` is never used on this path.
pub(crate) fn lcs_align(old: &[&[u8]], new: &[&[u8]]) -> Result<Vec<LcsOp>, CoreError> {
    let rows = u64::try_from(old.len())
        .map_err(|_| CoreError::new(ErrorCode::ELimit, "alignment exceeds its cell bound"))?
        + 1;
    let cols = u64::try_from(new.len())
        .map_err(|_| CoreError::new(ErrorCode::ELimit, "alignment exceeds its cell bound"))?
        + 1;
    let cells = rows
        .checked_mul(cols)
        .ok_or_else(|| CoreError::new(ErrorCode::ELimit, "alignment exceeds its cell bound"))?;
    if cells > LCS_MAX_CELLS {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "alignment exceeds its cell bound",
        ));
    }
    let stride = new.len() + 1;
    let cell_count = usize::try_from(cells)
        .map_err(|_| CoreError::new(ErrorCode::ELimit, "alignment exceeds its cell bound"))?;
    let mut table = vec![0u32; cell_count];
    for (i, old_line) in old.iter().enumerate() {
        for (j, new_line) in new.iter().enumerate() {
            let value = if old_line == new_line {
                table[i * stride + j] + 1
            } else {
                table[i * stride + j + 1].max(table[(i + 1) * stride + j])
            };
            table[(i + 1) * stride + j + 1] = value;
        }
    }
    let mut ops = Vec::new();
    let (mut i, mut j) = (old.len(), new.len());
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old[i - 1] == new[j - 1] {
            ops.push(LcsOp::Match);
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || table[(i - 1) * stride + j] < table[i * stride + j - 1]) {
            ops.push(LcsOp::Ins);
            j -= 1;
        } else {
            ops.push(LcsOp::Del);
            i -= 1;
        }
    }
    ops.reverse();
    Ok(ops)
}

/// Splits blob bytes into lines, keeping each terminator with its line.
pub(crate) fn split_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            lines.push(&bytes[start..index + 1]);
            start = index + 1;
        }
    }
    if start < bytes.len() {
        lines.push(&bytes[start..]);
    }
    lines
}

/// Renders one unified patch from an alignment script.
///
/// Hunk headers count lines with their terminators stripped; emitted lines
/// carry the raw line bytes without the terminator plus one `\n`.
pub(crate) fn unified_patch(
    old_label: &str,
    new_label: &str,
    old: &[&[u8]],
    new: &[&[u8]],
    ops: &[LcsOp],
) -> Vec<u8> {
    let mut tagged: Vec<(LcsOp, &[u8])> = Vec::with_capacity(ops.len());
    let (mut oi, mut ni) = (0_usize, 0_usize);
    for op in ops.iter().copied() {
        match op {
            LcsOp::Match => {
                tagged.push((op, old[oi]));
                oi += 1;
                ni += 1;
            }
            LcsOp::Del => {
                tagged.push((op, old[oi]));
                oi += 1;
            }
            LcsOp::Ins => {
                tagged.push((op, new[ni]));
                ni += 1;
            }
        }
    }
    let mut hunks: Vec<(usize, usize)> = Vec::new();
    let mut cursor = 0;
    while cursor < tagged.len() {
        let next_change = tagged[cursor..]
            .iter()
            .position(|(op, _)| *op != LcsOp::Match);
        let Some(offset) = next_change else {
            break;
        };
        let change_at = cursor + offset;
        let hunk_start = change_at.saturating_sub(DIFF_CONTEXT);
        let mut hunk_end = change_at + 1;
        loop {
            let following = tagged[hunk_end..]
                .iter()
                .position(|(op, _)| *op != LcsOp::Match);
            match following {
                None => {
                    hunk_end = tagged.len();
                    break;
                }
                Some(gap) if gap > 2 * DIFF_CONTEXT => {
                    hunk_end += DIFF_CONTEXT;
                    break;
                }
                Some(gap) => {
                    hunk_end += gap + 1;
                }
            }
        }
        let end = hunk_end.min(tagged.len());
        hunks.push((hunk_start, end));
        cursor = end;
    }
    let mut out = Vec::new();
    out.extend_from_slice(format!("--- {old_label}\n").as_bytes());
    out.extend_from_slice(format!("+++ {new_label}\n").as_bytes());
    for (start, end) in hunks {
        let (mut old_count, mut new_count) = (0_usize, 0_usize);
        let (mut old_base, mut new_base) = (0_usize, 0_usize);
        for (op, _) in &tagged[..start] {
            match op {
                LcsOp::Match => {
                    old_base += 1;
                    new_base += 1;
                }
                LcsOp::Del => old_base += 1,
                LcsOp::Ins => new_base += 1,
            }
        }
        for (op, _) in &tagged[start..end] {
            match op {
                LcsOp::Match => {
                    old_count += 1;
                    new_count += 1;
                }
                LcsOp::Del => old_count += 1,
                LcsOp::Ins => new_count += 1,
            }
        }
        out.extend_from_slice(
            format!(
                "@@ -{},{} +{},{} @@\n",
                old_base + 1,
                old_count,
                new_base + 1,
                new_count
            )
            .as_bytes(),
        );
        for (op, line) in &tagged[start..end] {
            let prefix = match op {
                LcsOp::Match => b' ',
                LcsOp::Del => b'-',
                LcsOp::Ins => b'+',
            };
            out.push(prefix);
            let stripped = line.strip_suffix(b"\n").unwrap_or(line);
            out.extend_from_slice(stripped);
            out.push(b'\n');
        }
    }
    out
}

/// Flattens one tree into path-keyed file entries, recursing into
/// subdirectories in place.
///
/// Directory entries themselves are not recorded: a file replacing a
/// directory (or the reverse) surfaces as deletions plus additions at the
/// paths below. Past [`DIFF_MAX_ENTRIES`] the read refuses with
/// [`ErrorCode::ELimit`].
pub(crate) fn flatten_tree(
    store: &Store,
    kind: HashKind,
    root: Oid,
) -> Result<BTreeMap<Vec<u8>, (TreeMode, Oid)>, CoreError> {
    let mut flat: BTreeMap<Vec<u8>, (TreeMode, Oid)> = BTreeMap::new();
    let mut stack: Vec<(Vec<u8>, Oid)> = vec![(Vec::new(), root)];
    while let Some((prefix, oid)) = stack.pop() {
        for item in tree_items(store, kind, oid)? {
            if flat.len() >= DIFF_MAX_ENTRIES {
                return Err(CoreError::new(
                    ErrorCode::ELimit,
                    "diff visits more entries than its bound",
                ));
            }
            let mut path = prefix.clone();
            path.extend_from_slice(&item.name);
            match item.mode {
                TreeMode::Tree => {
                    path.push(b'/');
                    stack.push((path, item.oid));
                }
                mode => {
                    flat.insert(path, (mode, item.oid));
                }
            }
        }
    }
    Ok(flat)
}

/// One path whose file entries differ between two trees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TreeFileChange {
    pub(crate) path: Vec<u8>,
    pub(crate) old: Option<(TreeMode, Oid)>,
    pub(crate) new: Option<(TreeMode, Oid)>,
}

/// Diffs two flattened trees with a merge join over path bytes.
///
/// Both sides flatten through [`flatten_tree`], so the entry bound applies
/// per side; the join itself is linear in the flattened sizes.
pub(crate) fn diff_trees(
    store: &Store,
    kind: HashKind,
    left: Oid,
    right: Oid,
) -> Result<Vec<TreeFileChange>, CoreError> {
    let old_map = flatten_tree(store, kind, left)?;
    let new_map = flatten_tree(store, kind, right)?;
    let mut old_iter = old_map.into_iter().peekable();
    let mut new_iter = new_map.into_iter().peekable();
    let mut changes = Vec::new();
    loop {
        match (old_iter.peek(), new_iter.peek()) {
            (None, None) => break,
            (Some(_), None) => {
                let (path, entry) = old_iter.next().expect("peeked old entry");
                changes.push(TreeFileChange {
                    path,
                    old: Some(entry),
                    new: None,
                });
            }
            (None, Some(_)) => {
                let (path, entry) = new_iter.next().expect("peeked new entry");
                changes.push(TreeFileChange {
                    path,
                    old: None,
                    new: Some(entry),
                });
            }
            (Some((old_path, _)), Some((new_path, _))) => {
                if old_path == new_path {
                    let (path, old_entry) = old_iter.next().expect("peeked old entry");
                    let (_, new_entry) = new_iter.next().expect("peeked new entry");
                    if old_entry != new_entry {
                        changes.push(TreeFileChange {
                            path,
                            old: Some(old_entry),
                            new: Some(new_entry),
                        });
                    }
                } else if old_path < new_path {
                    let (path, entry) = old_iter.next().expect("peeked old entry");
                    changes.push(TreeFileChange {
                        path,
                        old: Some(entry),
                        new: None,
                    });
                } else {
                    let (path, entry) = new_iter.next().expect("peeked new entry");
                    changes.push(TreeFileChange {
                        path,
                        old: None,
                        new: Some(entry),
                    });
                }
            }
        }
    }
    Ok(changes)
}

/// Commits one graph build may index before the read refuses.
///
/// The index pages the whole `Commits` table, so an unbounded history
/// would pin the read: past this many commits the caller rethinks its
/// revset instead of waiting out a full-store walk.
pub(crate) const GRAPH_MAX_COMMITS: usize = 1_000_000;

/// Builds the production graph index over every commit in the store.
///
/// Pages [`FactTable::Commits`] and inserts commits parents-first through
/// [`GraphIndexBuilder`], so the revset engine serves `log` and `query`
/// from store state instead of test-only graphs. Parents order through
/// one Kahn pass over the paged rows: linear in commits plus parent
/// edges, deterministic in head order. A commit whose parent is missing
/// from the table refuses [`ErrorCode::ECorrupt`]: history must be
/// complete. Changed-path Bloom data is not indexed (every `files()`
/// candidate verifies against a real tree diff instead of skipping), and
/// the build holds no lane: it pages facts without publishing.
pub(crate) fn build_graph_index(store: &Store) -> Result<GraphIndex, CoreError> {
    use crate::graph::composite::{GraphIndex, GraphIndexBuilder};
    use crate::records::types::RecordPageBudget;
    let records = Records::new(store);
    let mut parents_of: BTreeMap<Head, (ChangeId, Vec<Head>)> = BTreeMap::new();
    let mut after: Option<Head> = None;
    loop {
        let page =
            records.page_commits(after.as_ref(), RecordPageBudget::new(1_024, 16_777_216))?;
        let more = page.more;
        let next = page.next_cursor;
        for (head, record) in page.items {
            if parents_of.len() >= GRAPH_MAX_COMMITS {
                return Err(CoreError::new(
                    ErrorCode::ELimit,
                    "commit graph exceeds the hosted read bound",
                ));
            }
            parents_of.insert(head, (record.change_id(), record.parents().to_vec()));
        }
        if !more {
            break;
        }
        after = next;
    }
    let mut children_of: BTreeMap<Head, Vec<Head>> = BTreeMap::new();
    let mut open_parents: BTreeMap<Head, usize> = BTreeMap::new();
    for (head, (_, parents)) in &parents_of {
        let mut open = 0;
        for parent in parents {
            if parents_of.contains_key(parent) {
                open += 1;
                children_of.entry(*parent).or_default().push(*head);
            } else {
                return Err(CoreError::new(
                    ErrorCode::ECorrupt,
                    "commit parent is missing from the store",
                ));
            }
        }
        open_parents.insert(*head, open);
    }
    let mut ready: Vec<Head> = open_parents
        .iter()
        .filter(|(_, open)| **open == 0)
        .map(|(head, _)| *head)
        .collect();
    let mut builder = GraphIndexBuilder::new(GraphIndex::empty(store.hash_kind()));
    let mut ordered = 0;
    while let Some(head) = ready.pop() {
        let (change, parents) = parents_of
            .get(&head)
            .cloned()
            .ok_or_else(|| CoreError::new(ErrorCode::ECorrupt, "commit graph lost a head"))?;
        builder.add_commit(head, change, &parents, Vec::new())?;
        ordered += 1;
        if let Some(children) = children_of.remove(&head) {
            for child in children {
                if let Some(open) = open_parents.get_mut(&child) {
                    *open -= 1;
                    if *open == 0 {
                        ready.push(child);
                    }
                }
            }
        }
    }
    if ordered != parents_of.len() {
        return Err(CoreError::new(
            ErrorCode::ECorrupt,
            "commit graph has no parents-first order",
        ));
    }
    let budget = crate::budget::ByteBudget::new(268_435_456);
    builder.finish(&budget)
}

/// Parses one revset and evaluates one page of matches.
///
/// The index builds through [`build_graph_index`] and the context resolves
/// `attested()` against stored statements, so `log` and `query` share one
/// bounded path: [`eval_page`] refuses limits past 1000 and the lease
/// cursor carries the engine offset.
pub(crate) fn eval_revset_page(
    store: &Store,
    revset: &crate::protocol::RevsetText,
    limit: Option<usize>,
    cursor: Option<&crate::revset::eval::RevsetCursor>,
) -> Result<crate::revset::eval::RevsetPage, CoreError> {
    use crate::revset::eval::{EvalContext, eval_page};
    let ast = crate::revset::parse(revset)?;
    let graph = build_graph_index(store)?;
    let ctx = EvalContext::with_attestation(store, &graph);
    eval_page(&ctx, &ast, limit, cursor)
}

/// Hashes one revset query into the lease digest binding its pages.
pub(crate) fn revset_query_digest(tag: &[u8], revset: &crate::protocol::RevsetText) -> QueryDigest {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update([0x00]);
    hasher.update(revset.as_str().as_bytes());
    QueryDigest::from_bytes(hasher.finalize().into())
}

/// Splits one blob into cached line vectors, or `None` for a binary blob.
pub(crate) fn text_lines(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    if bytes.contains(&0) {
        return None;
    }
    Some(split_lines(bytes))
}

/// One blame file version: its blob id with its owned lines.
pub(crate) type BlameVersion = (Oid, Vec<Vec<u8>>);

/// Loads the file at `path` in one commit's tree: its blob lines keyed by
/// blob oid, or `None` when the path is absent or not a plain file.
///
/// Conflicted commits and directories read as absent: the blame walk
/// attributes lines their descendants carry to the descendant.
fn blame_version(
    store: &Store,
    head: &Head,
    path: &RepoPath,
    versions: &mut HashMap<Oid, Vec<Vec<u8>>>,
) -> Result<Option<BlameVersion>, CoreError> {
    use crate::ops::tree_edit::lookup;
    use crate::workcopy::tree::TreeMode;
    let record = Records::new(store)
        .get_commit(head)?
        .ok_or_else(|| CoreError::new(ErrorCode::ECorrupt, "blame commit is missing"))?;
    let tree = match record.tree().as_resolved() {
        Some(tree) => *tree,
        None => return Ok(None),
    };
    let node = lookup(store, tree, path)?;
    let blob = match node {
        Some((TreeMode::File(mode), oid))
            if mode == crate::index::FileMode::Regular
                || mode == crate::index::FileMode::Executable =>
        {
            oid
        }
        _ => return Ok(None),
    };
    if let Some(lines) = versions.get(&blob) {
        return Ok(Some((blob, lines.clone())));
    }
    if versions.len() >= BLAME_MAX_VERSIONS {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "blame visits more file versions than its bound",
        ));
    }
    let bytes = blob_bytes(store, blob)?;
    let Some(refs) = text_lines(&bytes) else {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "blame needs a text file",
        ));
    };
    let owned: Vec<Vec<u8>> = refs.iter().map(|line| line.to_vec()).collect();
    versions.insert(blob, owned.clone());
    Ok(Some((blob, owned)))
}

/// Live blame positions one walk may track before the read refuses.
///
/// Merge fan-out multiplies positions per line; the bound caps both time
/// and memory instead of letting a pathological DAG widen the walk.
pub(crate) const BLAME_MAX_POSITIONS: usize = 65_536;

/// Attributes every line of the file at `path` in `start` to the commit
/// that introduced it.
///
/// Walks ancestors breadth-first from `start`, tracking for each start
/// line the `(commit, index)` positions where its content currently lives.
/// Visiting a commit aligns its file version against every parent version
/// with [`lcs_align`]: a position matching a parent line moves there,
/// while a position no parent carries is introduced by the commit.
/// Commits past [`BLAME_MAX_COMMITS`], positions past
/// [`BLAME_MAX_POSITIONS`], or one alignment past [`LCS_MAX_CELLS`]
/// refuse with [`ErrorCode::ELimit`]. Binary files refuse
/// [`ErrorCode::EInvalid`]; directories and missing paths refuse at
/// lookup.
///
/// Returns the start version's lines with the attributing head per line.
pub(crate) fn blame_attribute(
    store: &Store,
    start: &Head,
    path: &RepoPath,
) -> Result<(Vec<Vec<u8>>, Vec<Head>), CoreError> {
    use crate::ops::tree_edit::lookup;
    use crate::workcopy::tree::TreeMode;
    let root = head_tree(store, start)?;
    let start_oid = match lookup(store, root, path)? {
        Some((TreeMode::File(mode), oid))
            if mode == crate::index::FileMode::Regular
                || mode == crate::index::FileMode::Executable =>
        {
            oid
        }
        Some(_) => {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "blame needs a file path",
            ));
        }
        None => {
            return Err(CoreError::new(ErrorCode::ENotFound, "no entry at path"));
        }
    };
    let start_bytes = blob_bytes(store, start_oid)?;
    let Some(start_refs) = text_lines(&start_bytes) else {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "blame needs a text file",
        ));
    };
    let start_lines: Vec<Vec<u8>> = start_refs.iter().map(|line| line.to_vec()).collect();
    let mut versions: HashMap<Oid, Vec<Vec<u8>>> = HashMap::new();
    versions.insert(start_oid, start_lines.clone());
    let mut attr: Vec<Option<Head>> = vec![None; start_lines.len()];
    let mut lives: Vec<Vec<(Head, usize)>> = start_lines
        .iter()
        .enumerate()
        .map(|(index, _)| vec![(*start, index)])
        .collect();
    let mut live_positions = start_lines.len();
    let mut visited: HashSet<Head> = HashSet::new();
    let mut queue: VecDeque<Head> = VecDeque::from([*start]);
    while let Some(current) = queue.pop_front() {
        if live_positions == 0 {
            break;
        }
        if !visited.insert(current) {
            continue;
        }
        if visited.len() > BLAME_MAX_COMMITS {
            return Err(CoreError::new(
                ErrorCode::ELimit,
                "blame walks more commits than its bound",
            ));
        }
        let record = Records::new(store)
            .get_commit(&current)?
            .ok_or_else(|| CoreError::new(ErrorCode::ECorrupt, "blame commit is missing"))?;
        let at_current: Vec<usize> = lives
            .iter()
            .enumerate()
            .filter(|(_, positions)| positions.iter().any(|(head, _)| *head == current))
            .map(|(index, _)| index)
            .collect();
        if record.parents().is_empty() {
            for index in at_current {
                if attr[index].is_none() {
                    attr[index] = Some(current);
                    live_positions -= lives[index].len();
                    lives[index].clear();
                }
            }
            continue;
        }
        let current_version = blame_version(store, &current, path, &mut versions)?;
        let Some((current_oid, current_lines)) = current_version else {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "blame lost a line position at a version without the file",
            ));
        };
        let current_refs: Vec<&[u8]> = current_lines.iter().map(Vec::as_slice).collect();
        let mut parents: Vec<(Head, Option<BlameVersion>)> = Vec::new();
        for parent in record.parents() {
            parents.push((*parent, blame_version(store, parent, path, &mut versions)?));
        }
        let mut moves: Vec<(usize, Vec<(Head, usize)>)> = Vec::new();
        for index in &at_current {
            let mut targets: Vec<(Head, usize)> = Vec::new();
            for line_index in lives[*index]
                .iter()
                .filter(|(head, _)| *head == current)
                .map(|(_, line)| *line)
                .collect::<Vec<_>>()
            {
                if let Some(next) =
                    resolve_blame_position(&current_refs, line_index, &parents, current_oid)?
                {
                    targets.push(next);
                }
            }
            moves.push((*index, targets));
        }
        for (index, mut targets) in moves {
            let before = lives[index].len();
            if targets.is_empty() {
                lives[index].clear();
                live_positions -= before;
                attr[index] = Some(current);
            } else {
                lives[index].retain(|(head, _)| *head != current);
                lives[index].append(&mut targets);
                lives[index].sort();
                lives[index].dedup();
                let after = lives[index].len();
                live_positions = live_positions - before + after;
            }
        }
        if live_positions > BLAME_MAX_POSITIONS {
            return Err(CoreError::new(
                ErrorCode::ELimit,
                "blame tracks more live lines than its bound",
            ));
        }
        for parent in record.parents() {
            queue.push_back(*parent);
        }
    }
    let mut heads = Vec::with_capacity(attr.len());
    for slot in attr {
        heads.push(slot.unwrap_or(*start));
    }
    Ok((start_lines, heads))
}

/// Resolves where one blame position moves: the matching parent line, or
/// `None` when no parent carries the line and the current commit
/// introduces it.
///
/// An identical parent blob transfers the index untouched; a parent
/// without the file contributes no match. Otherwise the cell-capped
/// [`lcs_align`] maps current lines onto parent lines.
fn resolve_blame_position(
    current_refs: &[&[u8]],
    line_index: usize,
    parents: &[(Head, Option<BlameVersion>)],
    current_oid: Oid,
) -> Result<Option<(Head, usize)>, CoreError> {
    let mut introduced = true;
    let mut target: Option<(Head, usize)> = None;
    for (parent, version) in parents {
        let Some((oid, lines)) = version else {
            continue;
        };
        if *oid == current_oid {
            target = Some((*parent, line_index));
            introduced = false;
            continue;
        }
        let parent_refs: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
        let ops = lcs_align(current_refs, &parent_refs)?;
        let mut current_at = 0;
        let mut parent_at = 0;
        for op in ops {
            match op {
                LcsOp::Match => {
                    if current_at == line_index {
                        target = Some((*parent, parent_at));
                        introduced = false;
                    }
                    current_at += 1;
                    parent_at += 1;
                }
                LcsOp::Del => {
                    current_at += 1;
                }
                LcsOp::Ins => {
                    parent_at += 1;
                }
            }
        }
    }
    if introduced {
        return Ok(None);
    }
    Ok(target)
}

/// Resolves one change reference to its single head.
pub(crate) fn change_head(store: &Store, change: &ChangeRef) -> Result<Head, CoreError> {
    if let Some(head) = change.head {
        let entry = Records::new(store)
            .get_change(&change.change)?
            .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "unknown change"))?;
        if !entry.contains_head(&head) {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "change does not contain the named head",
            ));
        }
        return Ok(head);
    }
    let entry = Records::new(store)
        .get_change(&change.change)?
        .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "unknown change"))?;
    match entry.heads.as_slice() {
        [head] => Ok(*head),
        _ => Err(CoreError::new(
            ErrorCode::EDivergent,
            "change is divergent: name one head",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lcs_align_matches_insert_delete() {
        let old: Vec<&[u8]> = vec![b"a", b"b"];
        let new: Vec<&[u8]> = vec![b"a"];
        assert_eq!(
            lcs_align(&old, &new).expect("align"),
            vec![LcsOp::Match, LcsOp::Del]
        );
        let old: Vec<&[u8]> = vec![b"a"];
        let new: Vec<&[u8]> = vec![b"a", b"b"];
        assert_eq!(
            lcs_align(&old, &new).expect("align"),
            vec![LcsOp::Match, LcsOp::Ins]
        );
        let empty: Vec<&[u8]> = Vec::new();
        assert_eq!(
            lcs_align(&empty, &empty).expect("align"),
            Vec::<LcsOp>::new()
        );
    }

    #[test]
    fn lcs_align_refuses_past_cell_bound() {
        let line: &[u8] = b"x";
        let wide: Vec<&[u8]> = vec![line; 1_025];
        let err = lcs_align(&wide, &wide).expect_err("1026x1026 cells refuse");
        assert_eq!(err.code, ErrorCode::ELimit);
        let edge: Vec<&[u8]> = vec![line; 1_023];
        lcs_align(&edge, &edge).expect("1024x1024 cells fit the bound");
    }

    #[test]
    fn unified_patch_groups_separated_changes() {
        let old: Vec<&[u8]> = vec![
            b"l0\n", b"l1\n", b"l2\n", b"l3\n", b"l4\n", b"l5\n", b"l6\n", b"l7\n", b"l8\n",
            b"l9\n",
        ];
        let new: Vec<&[u8]> = vec![
            b"l0\n",
            b"CHANGED\n",
            b"l2\n",
            b"l3\n",
            b"l4\n",
            b"l5\n",
            b"l6\n",
            b"l7\n",
            b"l8\n",
            b"l9\n",
            b"EXTRA\n",
        ];
        let ops = lcs_align(&old, &new).expect("align");
        let patch = unified_patch("a/f", "b/f", &old, &new, &ops);
        let text = String::from_utf8(patch).expect("patch is UTF-8");
        assert_eq!(text.matches("@@").count() / 2, 2, "two hunks: {text}");
        assert!(text.contains("-l1\n"), "deletion renders: {text}");
        assert!(text.contains("+CHANGED\n"), "insertion renders: {text}");
    }
}
