//! LFS pointer gate for receive-pack.
//!
//! The store policy ([`LfsMode`]) refuses Git LFS pointer blobs by default
//! and records them plainly only under `lfs = "pointers"`. The workcopy
//! lanes enforce that in both directions already; this module enforces it
//! on the receive-pack ingest path, where pushed blobs would otherwise
//! land with no LFS awareness.
//!
//! The gate polices what a push *introduces*: staged blobs whose bytes
//! match [`is_pointer`] refuse exactly the live ref updates whose new-tip
//! closure reaches them. Pointer blobs already committed (recorded under
//! an earlier `pointers` policy) stay settled state — a mode flip does not
//! rewrite history, and unreachable pack extras are stored the way hook
//! refusals leave unreferenced objects. Under [`LfsMode::Pointers`] there
//! is nothing to do: ingest already records the bytes plainly and payloads
//! are never fetched, exactly what the policy promises.
//!
//! Oracle anchors: the git-lfs pointer spec
//! (`version https://git-lfs.github.com/spec/v1`, `oid sha256:<hex>`,
//! `size <digits>`); `git/builtin/receive-pack.c` (per-ref `ng` verdicts).

use std::collections::{HashSet, VecDeque};
use std::ops::Deref;

use ruk_core::ids::{HashKind, Oid};
use ruk_core::store::Store;
use ruk_core::store::types::ObjectKind;
use ruk_core::{LfsMode, is_pointer};

use super::pack::{StagedPack, object_links};
use super::{Interrupt, read_object};
use crate::GitError;

/// Largest committed object pulled through the pointer walk. Committed
/// blobs carry no links, so their bodies are never buffered at all.
const WALK_OBJECT_BYTES: u64 = 512 << 20;

/// The refusal line for a ref update whose closure introduces a pointer
/// blob under [`LfsMode::Deny`]. One line, so it travels intact into the
/// `ng` report the way hook refusals do.
#[must_use]
pub fn refused_reason() -> String {
    "Git LFS pointer blob refused (E_UNSUPPORTED_LFS); set lfs = \"pointers\" in the store policy.toml to record pointer bytes plainly".to_owned()
}

/// Staged blobs whose bytes are Git LFS pointers: what this push would
/// introduce. Empty under [`LfsMode::Pointers`] by construction — callers
/// skip the gate entirely in that mode.
#[must_use]
pub fn staged_pointers(staged: &StagedPack) -> Vec<Oid> {
    staged
        .oids()
        .iter()
        .copied()
        .filter(|oid| {
            matches!(staged.payload(*oid), Some((ObjectKind::Blob, bytes)) if is_pointer(bytes))
        })
        .collect()
}

/// New tips whose closure (over staged plus committed objects) reaches one
/// of `pointers`. Each tip walks independently with interrupt checks; a
/// missing object fails closed rather than silently accepting.
///
/// # Errors
/// Closure read failures and [`GitError::Corrupt`] for malformed payloads.
pub fn tips_reaching_pointers(
    store: &Store,
    staged: &StagedPack,
    kind: HashKind,
    tips: &[Oid],
    pointers: &HashSet<Oid>,
    interrupt: &Interrupt,
) -> Result<HashSet<Oid>, GitError> {
    let mut refused = HashSet::new();
    for tip in tips {
        interrupt.check("scanning pushed objects for LFS pointers")?;
        if reaches_pointer(store, staged, kind, *tip, pointers, interrupt)? {
            refused.insert(*tip);
        }
    }
    Ok(refused)
}

/// Whether `tip`'s closure contains a pointer blob. Committed objects are
/// traversed for links but never content-checked: only staged blobs are
/// newly introduced by this push.
fn reaches_pointer(
    store: &Store,
    staged: &StagedPack,
    kind: HashKind,
    tip: Oid,
    pointers: &HashSet<Oid>,
    interrupt: &Interrupt,
) -> Result<bool, GitError> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::from([tip]);
    while let Some(oid) = queue.pop_front() {
        interrupt.check("scanning pushed objects for LFS pointers")?;
        if !visited.insert(oid) {
            continue;
        }
        if pointers.contains(&oid) {
            return Ok(true);
        }
        let Some(bytes) = linked_bytes(store, staged, oid)? else {
            continue;
        };
        queue.extend(links_of(bytes.kind(), &bytes, kind)?);
    }
    Ok(false)
}

/// Linkable bytes for one object: the kind plus a borrow of the resident
/// staged payload or of one committed read. Committed blobs carry no links
/// and map to nothing, so their bodies are never buffered.
enum LinkedBytes<'a> {
    Borrowed(ObjectKind, &'a [u8]),
    Owned(ObjectKind, Vec<u8>),
}

impl LinkedBytes<'_> {
    fn kind(&self) -> ObjectKind {
        match self {
            Self::Borrowed(kind, _) | Self::Owned(kind, _) => *kind,
        }
    }
}

impl Deref for LinkedBytes<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Borrowed(_, bytes) => bytes,
            Self::Owned(_, bytes) => bytes,
        }
    }
}

fn linked_bytes<'a>(
    store: &Store,
    staged: &'a StagedPack,
    oid: Oid,
) -> Result<Option<LinkedBytes<'a>>, GitError> {
    if let Some((kind, bytes)) = staged.payload(oid) {
        if matches!(kind, ObjectKind::Blob) {
            return Ok(None);
        }
        return Ok(Some(LinkedBytes::Borrowed(kind, bytes)));
    }
    let (kind, bytes) = read_object(store, oid, WALK_OBJECT_BYTES)?;
    if matches!(kind, ObjectKind::Blob) {
        return Ok(None);
    }
    Ok(Some(LinkedBytes::Owned(kind, bytes)))
}

/// The traversal edges of one object: tree, parents, tree entries, and tag
/// targets.
fn links_of(kind: ObjectKind, payload: &[u8], hash: HashKind) -> Result<Vec<Oid>, GitError> {
    let links = object_links(kind, payload, hash)?;
    let mut out = Vec::with_capacity(
        links.parents.len() + links.entries.len() + usize::from(links.tree.is_some()),
    );
    out.extend(links.tree);
    out.extend(links.parents);
    out.extend(links.entries.iter().map(|(oid, _)| *oid));
    out.extend(links.tag_target.map(|(oid, _)| oid));
    Ok(out)
}

/// Command indices whose ref update the push must refuse under `mode`:
/// every non-delete live update whose new-tip closure introduces a pointer
/// blob. `live` pairs command order with the update's new tip, the way the
/// serve half tracks verdicts. Under [`LfsMode::Pointers`] the refusals are
/// always empty.
///
/// # Errors
/// Closure read failures (fail closed, never silently accept).
pub fn refusals_for_live(
    store: &Store,
    staged: &StagedPack,
    kind: HashKind,
    mode: LfsMode,
    live: &[(usize, Oid)],
    interrupt: &Interrupt,
) -> Result<Vec<(usize, String)>, GitError> {
    if mode != LfsMode::Deny {
        return Ok(Vec::new());
    }
    let pointers: HashSet<Oid> = staged_pointers(staged).into_iter().collect();
    if pointers.is_empty() {
        return Ok(Vec::new());
    }
    let zero = kind.zero_oid();
    let tips: Vec<Oid> = live
        .iter()
        .map(|(_, tip)| *tip)
        .filter(|tip| *tip != zero)
        .collect();
    let refused = tips_reaching_pointers(store, staged, kind, &tips, &pointers, interrupt)?;
    let reason = refused_reason();
    Ok(live
        .iter()
        .filter(|(_, tip)| refused.contains(tip))
        .map(|(index, _)| (*index, reason.clone()))
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use ruk_core::ids::HashKind;

    use super::super::pack::{IngestLimits, PackEntry, ingest_pack, write_pack};
    use super::super::session::test_support::test_store;
    use super::*;

    const POINTER: &[u8] = b"version https://git-lfs.github.com/spec/v1\noid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d0b46e9c\nsize 14\n";

    fn pointer_pack(kind: HashKind) -> (Vec<u8>, Oid, Oid) {
        let blob_oid = kind.hash_git_object("blob", POINTER).expect("blob id");
        let mut tree = b"100644 asset.bin\0".to_vec();
        tree.extend_from_slice(blob_oid.as_bytes());
        let tree_oid = kind.hash_git_object("tree", &tree).expect("tree id");
        let commit = format!(
            "tree {}\nauthor T <t@example.invalid> 0 +0000\ncommitter T <t@example.invalid> 0 +0000\n\npointer\n",
            tree_oid.to_hex()
        );
        let commit_oid = kind
            .hash_git_object("commit", commit.as_bytes())
            .expect("commit id");
        let entries = [
            (blob_oid, ObjectKind::Blob, POINTER.to_vec()),
            (tree_oid, ObjectKind::Tree, tree),
            (commit_oid, ObjectKind::Commit, commit.into_bytes()),
        ];
        let pack_entries: Vec<PackEntry<'_>> = entries
            .iter()
            .map(|(oid, kind, bytes)| PackEntry {
                oid: *oid,
                kind: *kind,
                bytes,
                base: None,
            })
            .collect();
        let mut pack = Vec::new();
        write_pack(&mut pack, kind, &pack_entries, &Interrupt::none()).expect("pack");
        (pack, blob_oid, commit_oid)
    }

    #[test]
    fn staged_scan_finds_only_pointer_blobs() {
        let kind = HashKind::Sha1;
        let store = test_store(kind);
        let (pack, blob_oid, _) = pointer_pack(kind);
        let staged = ingest_pack(
            &pack[..],
            kind,
            &store,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("ingest");
        assert_eq!(staged_pointers(&staged), vec![blob_oid]);
    }

    #[test]
    fn tip_closure_reaches_the_staged_pointer() {
        let kind = HashKind::Sha1;
        let store = test_store(kind);
        let (pack, blob_oid, commit_oid) = pointer_pack(kind);
        let staged = ingest_pack(
            &pack[..],
            kind,
            &store,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("ingest");
        let pointers: HashSet<Oid> = HashSet::from([blob_oid]);
        let refused = tips_reaching_pointers(
            &store,
            &staged,
            kind,
            &[commit_oid],
            &pointers,
            &Interrupt::none(),
        )
        .expect("walk");
        assert!(refused.contains(&commit_oid));
    }

    #[test]
    fn unrelated_tip_reaches_no_pointer() {
        let kind = HashKind::Sha1;
        let store = test_store(kind);
        let (pack, blob_oid, _) = pointer_pack(kind);
        let staged = ingest_pack(
            &pack[..],
            kind,
            &store,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("ingest");
        let plain = b"just text\n";
        let prepared = store
            .prepare(
                ruk_core::store::types::ObjectKind::Blob,
                plain.len() as u64,
                &plain[..],
                None,
            )
            .expect("plain blob");
        let plain_oid = prepared.oid();
        store
            .publish(vec![prepared], &[])
            .expect("publish plain blob");
        let pointers: HashSet<Oid> = HashSet::from([blob_oid]);
        let refused = tips_reaching_pointers(
            &store,
            &staged,
            kind,
            &[plain_oid],
            &pointers,
            &Interrupt::none(),
        )
        .expect("walk");
        assert!(refused.is_empty());
    }
}
