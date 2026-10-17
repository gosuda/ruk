//! `rebase`: rebase one commit onto a new base and propagate to descendants.
//!
//! Replaces the parents of the rebased root commit with the new base, creates
//! a new commit with the supplied post-rebase tree and the original commit's
//! metadata, and propagates the rewrite to each specified descendant in
//! parent-first order with its original tree preserved.
//!
//! The operation never resolves content merges itself: when `tree` is absent,
//! it refuses with `E_UNSUPPORTED_OPERATION`. Every rewrite in the tree or
//! chain is staged in memory and published in a single atomic store batch;
//! a failure at any point publishes nothing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bytes::ByteString;
use crate::change::ChangeId;
use crate::commit::{CommitRecord, NativeCommitInput};
use crate::conflict::ExtraHeader;
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::ids::Oid;
use crate::merge::Merge;
use crate::ops::PreparedOp;
use crate::records::Records;
use crate::store::types::ObjectKind;
use crate::store::{Store, StoreError};

/// What commit to rebase, where to place it, and which descendants to rewrite.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RebaseRequest {
    /// The commit to rebase.
    pub head: Head,
    /// The new base commit.
    pub onto: Head,
    /// Heads to skip during the rebase.
    #[serde(default)]
    pub skip: Vec<Head>,
    /// The post-rebase tree for `head`. Content resolution is not performed
    /// by this operation, so `tree` must be provided.
    #[serde(default)]
    pub tree: Option<Oid>,
    /// Descendant heads to rewrite, ordered parent-first.
    #[serde(default)]
    pub descendants: Vec<Head>,
}

impl RebaseRequest {
    /// Creates a rebase request for a single commit onto a new base.
    #[must_use]
    pub fn new(head: Head, onto: Head, tree: Option<Oid>) -> Self {
        Self {
            head,
            onto,
            skip: Vec::new(),
            tree,
            descendants: Vec::new(),
        }
    }
}

/// What rebase produced.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RebaseResult {
    /// The new head of the rebased root commit.
    pub head: Head,
    /// All rewritten heads in order, root-first (starting with `head`).
    pub rewritten: Vec<Head>,
    /// The change ID of the rebased root commit.
    pub change_id: ChangeId,
}

/// Rebases one commit onto a new base and propagates to its descendants.
///
/// # Preconditions
/// - `tree` is supplied and names a stored tree object of this repository's hash kind.
/// - `onto` is a stored commit of this repository's hash kind.
/// - `head` is a stored commit and a current head of its change.
/// - Every head in `skip` is not inside the rebased set (`head` and `descendants`).
/// - Every descendant in `descendants` is a stored commit, a current head of its
///   change, and its parents are either in the rewrite map or valid current original parents.
///
/// # Errors
/// `E_INVALID` when `tree` is absent (with `E_UNSUPPORTED_OPERATION` in the message),
/// when a skipped head is inside the rebased set, or when `head` equals `onto` or is
/// present in `descendants`; `E_STALE` when `head` or a descendant is not a current head
/// of its change, or when a descendant's parent is neither in the map nor a valid current
/// parent; `E_NOT_FOUND` when `tree`, `head`, `onto`, or any descendant is not stored;
/// `E_OBJECT_FORMAT` for an object ID of the wrong width.
pub fn rebase(store: &Store, request: RebaseRequest) -> Result<RebaseResult, CoreError> {
    let prepared = prepare_rebase(store, request)?;
    store
        .publish(prepared.objects, &prepared.facts)
        .map_err(store_error)?;
    Ok(prepared.output)
}

/// Validates one rebase and stages its publication parts without publishing.
///
/// Runs every check [`rebase`] runs — every rewrite in the chain is staged
/// in memory — and returns the staged objects, exact-expectation facts, and
/// the output publication will produce.
pub fn prepare_rebase(
    store: &Store,
    request: RebaseRequest,
) -> Result<PreparedOp<RebaseResult>, CoreError> {
    let Some(tree) = request.tree else {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "content resolution is not part of this operation (E_UNSUPPORTED_OPERATION)",
        ));
    };

    let kind = store.hash_kind();
    tree.expect_kind(kind, "tree")?;
    request.head.validate(kind)?;
    request.onto.validate(kind)?;
    for s in &request.skip {
        s.validate(kind)?;
    }
    for d in &request.descendants {
        d.validate(kind)?;
    }

    require_tree(store, tree)?;
    require_stored_commit(store, &request.onto)?;

    if request.head == request.onto {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "cannot rebase a commit onto itself",
        ));
    }

    if request.skip.contains(&request.head) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "skipped head {} is inside the rebased set",
                describe_head(&request.head)
            ),
        ));
    }

    if request.descendants.contains(&request.head) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "descendants contains rebase root {}",
                describe_head(&request.head)
            ),
        ));
    }

    if request.descendants.contains(&request.onto) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "cannot rebase onto descendant {}",
                describe_head(&request.onto)
            ),
        ));
    }

    for (index, desc) in request.descendants.iter().enumerate() {
        if request.descendants[..index].contains(desc) {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "duplicate descendant {} at index {index}",
                    describe_head(desc)
                ),
            ));
        }
        if request.skip.contains(desc) {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "skipped head {} is inside the rebased set",
                    describe_head(desc)
                ),
            ));
        }
    }

    let records = Records::new(store);
    let head_record = records.get_commit(&request.head)?.ok_or_else(|| {
        CoreError::new(
            ErrorCode::ENotFound,
            format!("commit {} is not stored", describe_head(&request.head)),
        )
    })?;

    let head_change = records
        .get_change(&head_record.change_id())?
        .ok_or_else(|| {
            CoreError::new(
                ErrorCode::ENotFound,
                format!("change {} is not stored", head_record.change_id()),
            )
        })?;
    if !head_change.contains_head(&request.head) {
        return Err(CoreError::new(
            ErrorCode::EStale,
            format!(
                "commit {} is not a current head of change {}",
                describe_head(&request.head),
                head_record.change_id()
            ),
        ));
    }

    let mut preparer = records.batch_preparer();
    let mut head_map: BTreeMap<Head, Head> = BTreeMap::new();
    let mut rewritten = Vec::with_capacity(1 + request.descendants.len());

    let root_input = NativeCommitInput {
        change_id: head_record.change_id(),
        tree: Merge::from_vec(vec![tree]),
        parents: vec![request.onto],
        predecessor: Some(request.head),
        author: head_record.author()?,
        committer: head_record.committer()?,
        extra_headers: copy_extra_headers(&head_record),
        message: ByteString::from(head_record.message()),
        provenance: head_record.provenance().cloned(),
    };
    let new_root_head = preparer.add_native_commit(root_input)?;
    head_map.insert(request.head, new_root_head);
    rewritten.push(new_root_head);

    for desc_head in &request.descendants {
        let desc_record = records.get_commit(desc_head)?.ok_or_else(|| {
            CoreError::new(
                ErrorCode::ENotFound,
                format!("descendant {} is not stored", describe_head(desc_head)),
            )
        })?;

        let desc_change = records
            .get_change(&desc_record.change_id())?
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::ENotFound,
                    format!("change {} is not stored", desc_record.change_id()),
                )
            })?;
        if !desc_change.contains_head(desc_head) {
            return Err(CoreError::new(
                ErrorCode::EStale,
                format!(
                    "descendant {} is not a current head of change {}",
                    describe_head(desc_head),
                    desc_record.change_id()
                ),
            ));
        }

        let new_parents = resolve_descendant_parents(
            &records,
            &head_map,
            &request.descendants,
            desc_head,
            desc_record.parents(),
        )?;

        let desc_input = NativeCommitInput {
            change_id: desc_record.change_id(),
            tree: desc_record.tree().clone(),
            parents: new_parents,
            predecessor: Some(*desc_head),
            author: desc_record.author()?,
            committer: desc_record.committer()?,
            extra_headers: copy_extra_headers(&desc_record),
            message: ByteString::from(desc_record.message()),
            provenance: desc_record.provenance().cloned(),
        };
        let new_desc_head = preparer.add_native_commit(desc_input)?;
        head_map.insert(*desc_head, new_desc_head);
        rewritten.push(new_desc_head);
    }

    let batch = preparer.finish()?;
    Ok(PreparedOp {
        objects: batch.prepared_objects,
        facts: batch.mutations,
        output: RebaseResult {
            head: new_root_head,
            rewritten,
            change_id: head_record.change_id(),
        },
    })
}

/// Resolves and rewrites the parents of one descendant commit.
///
/// Precondition: each parent must either be in `head_map` (rewritten earlier in
/// this rebase batch) or be a valid original parent still stored and active.
/// Refuses with `E_STALE` if an intermediate parent has not yet been mapped,
/// if an unmapped parent is not stored or no longer a current head of its change,
/// or if none of the descendant's parents were mapped (not a true descendant).
fn resolve_descendant_parents(
    records: &Records<'_>,
    head_map: &BTreeMap<Head, Head>,
    descendants: &[Head],
    desc_head: &Head,
    parents: &[Head],
) -> Result<Vec<Head>, CoreError> {
    let mut has_mapped_parent = false;
    let mut new_parents = Vec::with_capacity(parents.len());

    for parent in parents {
        if let Some(mapped) = head_map.get(parent) {
            new_parents.push(*mapped);
            has_mapped_parent = true;
            continue;
        }

        if descendants.contains(parent) {
            return Err(CoreError::new(
                ErrorCode::EStale,
                format!(
                    "parent {} of descendant {} is not yet in the map",
                    describe_head(parent),
                    describe_head(desc_head),
                ),
            ));
        }

        require_active_parent(records, parent, desc_head)?;
        new_parents.push(*parent);
    }

    if !has_mapped_parent {
        return Err(CoreError::new(
            ErrorCode::EStale,
            format!(
                "descendant {} parent is neither in the map nor its original parent",
                describe_head(desc_head),
            ),
        ));
    }

    Ok(new_parents)
}

/// Refuses an unmapped parent that is neither stored nor an active head of its change.
fn require_active_parent(
    records: &Records<'_>,
    parent: &Head,
    desc_head: &Head,
) -> Result<(), CoreError> {
    let parent_commit = records.get_commit(parent)?.ok_or_else(|| {
        CoreError::new(
            ErrorCode::EStale,
            format!(
                "parent {} of descendant {} is neither in the map nor stored",
                describe_head(parent),
                describe_head(desc_head),
            ),
        )
    })?;
    let parent_change = records
        .get_change(&parent_commit.change_id())?
        .ok_or_else(|| {
            CoreError::new(
                ErrorCode::EStale,
                format!(
                    "change for parent {} of descendant {} is not stored",
                    describe_head(parent),
                    describe_head(desc_head),
                ),
            )
        })?;
    if !parent_change.contains_head(parent) {
        return Err(CoreError::new(
            ErrorCode::EStale,
            format!(
                "parent {} of descendant {} is neither in the map nor its original parent",
                describe_head(parent),
                describe_head(desc_head),
            ),
        ));
    }
    Ok(())
}

/// Copies extra headers excluding any native change-id header.
#[must_use]
fn copy_extra_headers(record: &CommitRecord) -> Vec<ExtraHeader> {
    record
        .extra_headers()
        .iter()
        .filter(|header| header.name.as_bytes() != b"change-id")
        .cloned()
        .collect()
}

/// Refuses a parent that is not a stored commit of this repository.
fn require_stored_commit(store: &Store, parent: &Head) -> Result<(), CoreError> {
    let records = Records::new(store);
    if records.get_commit(parent)?.is_some() {
        return Ok(());
    }
    Err(CoreError::new(
        ErrorCode::ENotFound,
        format!("parent {} is not a stored commit", describe_head(parent)),
    ))
}

/// Refuses a tree that is not a stored tree of this repository.
fn require_tree(store: &Store, tree: Oid) -> Result<(), CoreError> {
    let Some(len) = store.object_len(tree)? else {
        return Err(CoreError::new(
            ErrorCode::ENotFound,
            format!("tree {tree} is not stored"),
        ));
    };
    let read = store.read(tree)?;
    if read.kind != ObjectKind::Tree {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "{tree} is a {:?} object of {len} bytes, not a tree",
                read.kind
            ),
        ));
    }
    Ok(())
}

#[must_use]
fn describe_head(head: &Head) -> String {
    match head {
        Head::Git { oid } => oid.to_string(),
        Head::Conflicted { key } => format!("{key:?}"),
    }
}

#[must_use]
fn store_error(error: StoreError) -> CoreError {
    CoreError::new(error.code(), error.to_string())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use super::*;
    use crate::conflict::{Signature, TzOffset};
    use crate::ids::HashKind;
    use crate::ops::new::{NewRequest, new as create_commit};
    use crate::store::PreparationBudget;

    struct Fixture {
        root: std::path::PathBuf,
        store: Store,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("ruk-rebase-test-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let store = Store::create(
                &root,
                HashKind::Sha1,
                Arc::new(PreparationBudget::reference_defaults()),
            )
            .expect("create test store");
            Self { root, store }
        }

        fn publish(&self, kind: ObjectKind, bytes: &[u8]) -> Oid {
            let len = u64::try_from(bytes.len()).expect("test object fits u64");
            let prepared = self
                .store
                .prepare(kind, len, Cursor::new(bytes), None)
                .expect("prepare object");
            let oid = prepared.oid();
            self.store
                .publish(vec![prepared], &[])
                .expect("publish object");
            oid
        }

        fn tree(&self, marker: &[u8]) -> Oid {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(b"100644 x");
            bytes.push(*marker.first().expect("marker"));
            bytes.push(0);
            bytes.extend_from_slice(&[0x11; 20]);
            self.publish(ObjectKind::Tree, &bytes)
        }

        fn commit(&self, tree: Oid, parents: Vec<Head>, message: &str) -> Head {
            let result = create_commit(
                &self.store,
                NewRequest {
                    tree,
                    parents,
                    author: signature("Ada", "ada@example.invalid", 1_700_000_000),
                    committer: signature("Ada", "ada@example.invalid", 1_700_000_000),
                    message: ByteString::from(message),
                    change_id: None,
                    predecessor: None,
                    provenance: None,
                },
            )
            .expect("create test commit");
            result.head
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn signature(name: &str, email: &str, timestamp: i64) -> Signature {
        Signature {
            name: ByteString::from(name),
            email: ByteString::from(email),
            timestamp,
            offset: TzOffset::UTC,
        }
    }

    #[test]
    fn a_two_descendant_chain_rebases_onto_a_new_base() {
        let fixture = Fixture::new("two-descendants");
        let base0 = fixture.commit(fixture.tree(b"0"), Vec::new(), "base0\n");
        let onto = fixture.commit(fixture.tree(b"1"), Vec::new(), "onto\n");
        let root = fixture.commit(fixture.tree(b"2"), vec![base0], "root\n");
        let d1 = fixture.commit(fixture.tree(b"3"), vec![root], "d1\n");
        let d2 = fixture.commit(fixture.tree(b"4"), vec![d1], "d2\n");

        let records = Records::new(&fixture.store);
        let root_record = records
            .get_commit(&root)
            .expect("read root")
            .expect("root exists");
        let root_change_id = root_record.change_id();
        let d1_record = records
            .get_commit(&d1)
            .expect("read d1")
            .expect("d1 exists");
        let d1_change_id = d1_record.change_id();
        let d2_record = records
            .get_commit(&d2)
            .expect("read d2")
            .expect("d2 exists");
        let d2_change_id = d2_record.change_id();

        let resolved_root_tree = fixture.tree(b"5");
        let request = RebaseRequest {
            head: root,
            onto,
            skip: Vec::new(),
            tree: Some(resolved_root_tree),
            descendants: vec![d1, d2],
        };

        let result = rebase(&fixture.store, request).expect("rebase succeeds");
        assert_eq!(result.head, result.rewritten[0]);
        assert_eq!(result.rewritten.len(), 3);
        assert_eq!(result.change_id, root_change_id);

        let h_new = result.rewritten[0];
        let d1_new = result.rewritten[1];
        let d2_new = result.rewritten[2];

        assert_ne!(h_new, root);
        assert_ne!(d1_new, d1);
        assert_ne!(d2_new, d2);

        let records = Records::new(&fixture.store);
        let h_new_rec = records
            .get_commit(&h_new)
            .expect("read h_new")
            .expect("h_new exists");
        assert_eq!(h_new_rec.parents(), &[onto]);
        assert_eq!(h_new_rec.predecessor(), Some(root));
        assert_eq!(h_new_rec.change_id(), root_change_id);
        assert_eq!(h_new_rec.tree(), &Merge::resolved(resolved_root_tree));

        let d1_new_rec = records
            .get_commit(&d1_new)
            .expect("read d1_new")
            .expect("d1_new exists");
        assert_eq!(d1_new_rec.parents(), &[h_new]);
        assert_eq!(d1_new_rec.predecessor(), Some(d1));
        assert_eq!(d1_new_rec.change_id(), d1_change_id);
        assert_eq!(d1_new_rec.tree(), d1_record.tree());

        let d2_new_rec = records
            .get_commit(&d2_new)
            .expect("read d2_new")
            .expect("d2_new exists");
        assert_eq!(d2_new_rec.parents(), &[d1_new]);
        assert_eq!(d2_new_rec.predecessor(), Some(d2));
        assert_eq!(d2_new_rec.change_id(), d2_change_id);
        assert_eq!(d2_new_rec.tree(), d2_record.tree());

        let root_change = records
            .get_change(&root_change_id)
            .expect("read root change")
            .expect("root change exists");
        assert!(root_change.contains_head(&h_new));
        assert!(!root_change.contains_head(&root));

        let d1_change = records
            .get_change(&d1_change_id)
            .expect("read d1 change")
            .expect("d1 change exists");
        assert!(d1_change.contains_head(&d1_new));
        assert!(!d1_change.contains_head(&d1));

        let d2_change = records
            .get_change(&d2_change_id)
            .expect("read d2 change")
            .expect("d2 change exists");
        assert!(d2_change.contains_head(&d2_new));
        assert!(!d2_change.contains_head(&d2));
    }

    #[test]
    fn missing_tree_refuses_without_resolving_content() {
        let fixture = Fixture::new("missing-tree");
        let base = fixture.commit(fixture.tree(b"0"), Vec::new(), "base\n");
        let onto = fixture.commit(fixture.tree(b"1"), Vec::new(), "onto\n");
        let root = fixture.commit(fixture.tree(b"2"), vec![base], "root\n");

        let request = RebaseRequest {
            head: root,
            onto,
            skip: Vec::new(),
            tree: None,
            descendants: Vec::new(),
        };

        let error = rebase(&fixture.store, request).expect_err("missing tree must refuse");
        assert_eq!(error.code, ErrorCode::EInvalid);
        assert!(error.message.contains("E_UNSUPPORTED_OPERATION"));

        let records = Records::new(&fixture.store);
        let root_rec = records
            .get_commit(&root)
            .expect("read root")
            .expect("root exists");
        let change = records
            .get_change(&root_rec.change_id())
            .expect("read change")
            .expect("change exists");
        assert!(change.contains_head(&root));
    }

    #[test]
    fn skipped_head_inside_rebased_set_is_refused() {
        let fixture = Fixture::new("skip-in-set");
        let base = fixture.commit(fixture.tree(b"0"), Vec::new(), "base\n");
        let onto = fixture.commit(fixture.tree(b"1"), Vec::new(), "onto\n");
        let root = fixture.commit(fixture.tree(b"2"), vec![base], "root\n");
        let d1 = fixture.commit(fixture.tree(b"3"), vec![root], "d1\n");

        let request = RebaseRequest {
            head: root,
            onto,
            skip: vec![d1],
            tree: Some(fixture.tree(b"4")),
            descendants: vec![d1],
        };

        let error = rebase(&fixture.store, request).expect_err("skip in set must fail");
        assert_eq!(error.code, ErrorCode::EInvalid);

        let records = Records::new(&fixture.store);
        let root_rec = records
            .get_commit(&root)
            .expect("read root")
            .expect("root exists");
        let root_change = records
            .get_change(&root_rec.change_id())
            .expect("read change")
            .expect("change exists");
        assert!(root_change.contains_head(&root));
        let d1_rec = records
            .get_commit(&d1)
            .expect("read d1")
            .expect("d1 exists");
        let d1_change = records
            .get_change(&d1_rec.change_id())
            .expect("read d1 change")
            .expect("d1 change exists");
        assert!(d1_change.contains_head(&d1));
    }

    #[test]
    fn descendant_with_unmapped_parent_is_refused_and_publishes_nothing() {
        let fixture = Fixture::new("unmapped-parent");
        let base = fixture.commit(fixture.tree(b"0"), Vec::new(), "base\n");
        let onto = fixture.commit(fixture.tree(b"1"), Vec::new(), "onto\n");
        let root = fixture.commit(fixture.tree(b"2"), vec![base], "root\n");
        let d1 = fixture.commit(fixture.tree(b"3"), vec![root], "d1\n");
        let d2 = fixture.commit(fixture.tree(b"4"), vec![d1], "d2\n");

        // Omit d1 from descendants so d2's parent d1 is not in the map
        let request = RebaseRequest {
            head: root,
            onto,
            skip: Vec::new(),
            tree: Some(fixture.tree(b"5")),
            descendants: vec![d2],
        };

        let error = rebase(&fixture.store, request).expect_err("unmapped parent must fail");
        assert_eq!(error.code, ErrorCode::EStale);

        // Verify root was not published (atomicity check)
        let records = Records::new(&fixture.store);
        let root_rec = records
            .get_commit(&root)
            .expect("read root")
            .expect("root exists");
        let root_change = records
            .get_change(&root_rec.change_id())
            .expect("read change")
            .expect("change exists");
        assert!(root_change.contains_head(&root));
    }

    #[test]
    fn rebase_onto_self_is_refused() {
        let fixture = Fixture::new("onto-self");
        let base = fixture.commit(fixture.tree(b"0"), Vec::new(), "base\n");
        let root = fixture.commit(fixture.tree(b"1"), vec![base], "root\n");

        let request = RebaseRequest {
            head: root,
            onto: root,
            skip: Vec::new(),
            tree: Some(fixture.tree(b"2")),
            descendants: Vec::new(),
        };

        let error = rebase(&fixture.store, request).expect_err("rebase onto self must fail");
        assert_eq!(error.code, ErrorCode::EInvalid);
    }
}
