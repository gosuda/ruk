//! Real-Store tests for the create and describe operations.
//!
//! Each test publishes through the public operation and reads back through
//! the public operation, so a defect in either half fails here.

use std::io::Cursor;
use std::sync::Arc;

use crate::bytes::ByteString;
use crate::change::ChangeId;
use crate::conflict::{Signature, TzOffset};
use crate::error::ErrorCode;
use crate::heads::Head;
use crate::ids::{HashKind, Oid};
use crate::ops::{
    ChangeDescription, CommitDescription, DescribeRequest, Description, NewRequest, NewResult,
    describe, new,
};
use crate::records::{ChangeState, Records};
use crate::store::types::ObjectKind;
use crate::store::{PreparationBudget, Store};

struct Fixture {
    root: std::path::PathBuf,
    store: Store,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("ruk-ops-test-{}-{tag}", std::process::id()));
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
        let prepared = self
            .store
            .prepare(
                kind,
                u64::try_from(bytes.len()).expect("test object fits u64"),
                Cursor::new(bytes),
                None,
            )
            .expect("prepare object");
        let oid = prepared.oid();
        self.store
            .publish(vec![prepared], &[])
            .expect("publish object");
        oid
    }

    fn tree(&self, marker: &[u8]) -> Oid {
        // A tree object whose single entry name differs per marker, so the
        // fixtures are distinct objects rather than one shared empty tree.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"100644 x");
        bytes.push(*marker.first().expect("marker"));
        bytes.push(0);
        bytes.extend_from_slice(&[0x11; 20]);
        self.publish(ObjectKind::Tree, &bytes)
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

fn request(tree: Oid, parents: Vec<Head>, message: &str) -> NewRequest {
    NewRequest {
        tree,
        parents,
        author: signature("Ada", "ada@example.invalid", 1_700_000_000),
        committer: signature("Ada", "ada@example.invalid", 1_700_000_000),
        message: ByteString::from(message),
        change_id: None,
        predecessor: None,
        provenance: None,
    }
}

fn commit_description(fixture: &Fixture, head: Head) -> CommitDescription {
    match describe(&fixture.store, DescribeRequest::commit(head)).expect("describe commit") {
        Description::Commit(described) => described,
        Description::Change(_) => panic!("a commit request must answer with a commit"),
    }
}

fn change_description(fixture: &Fixture, change_id: ChangeId) -> ChangeDescription {
    match describe(&fixture.store, DescribeRequest::change(change_id)).expect("describe change") {
        Description::Change(described) => described,
        Description::Commit(_) => panic!("a change request must answer with a change"),
    }
}

fn created(fixture: &Fixture, message: &str) -> NewResult {
    new(
        &fixture.store,
        request(fixture.tree(b"a"), Vec::new(), message),
    )
    .expect("create root commit")
}

#[test]
fn a_created_commit_reads_back_with_its_exact_fields() {
    let fixture = Fixture::new("roundtrip");
    let tree = fixture.tree(b"a");
    let mut request = request(tree, Vec::new(), "root\n");
    let change_id = ChangeId::generate();
    request.change_id = Some(change_id);

    let created = new(&fixture.store, request).expect("create commit");
    assert_eq!(created.change_id, change_id);
    assert_eq!(created.head.as_git(), created.oid.as_ref());

    let described = commit_description(&fixture, created.head);
    assert_eq!(described.head, created.head);
    assert_eq!(described.change_id, change_id);
    assert_eq!(described.tree, vec![tree.to_string()]);
    assert!(described.parents.is_empty());
    assert_eq!(described.predecessor, None);
    assert!(described.exportable);
    assert_eq!(described.message, "root\n");
    assert!(described.author.starts_with("Ada <ada@example.invalid> "));
}

#[test]
fn a_parent_child_chain_describes_each_commit() {
    let fixture = Fixture::new("chain");
    let root = created(&fixture, "root\n");
    let child = new(
        &fixture.store,
        request(fixture.tree(b"b"), vec![root.head], "child\n"),
    )
    .expect("create child");

    let described = commit_description(&fixture, child.head);
    assert_eq!(described.parents, vec![root.head]);
    assert_ne!(described.change_id, root.change_id);
}

#[test]
fn a_change_describes_its_head_and_state() {
    let fixture = Fixture::new("change");
    let created = created(&fixture, "root\n");

    let ChangeDescription {
        change_id,
        heads,
        divergent,
        state,
    } = change_description(&fixture, created.change_id);
    assert_eq!(change_id, created.change_id);
    assert_eq!(heads, vec![created.head]);
    assert!(!divergent);
    assert_eq!(state, ChangeState::Active);
}

#[test]
fn a_second_commit_without_a_predecessor_diverges_the_change() {
    let fixture = Fixture::new("divergent");
    let first = created(&fixture, "first\n");
    let second = new(
        &fixture.store,
        NewRequest {
            change_id: Some(first.change_id),
            ..request(fixture.tree(b"b"), Vec::new(), "second\n")
        },
    )
    .expect("create divergent sibling");

    let described = change_description(&fixture, first.change_id);
    assert!(described.divergent);
    assert_eq!(described.heads.len(), 2);
    assert!(described.heads.contains(&first.head));
    assert!(described.heads.contains(&second.head));
}

#[test]
fn a_tree_digest_that_is_not_stored_is_not_found() {
    let fixture = Fixture::new("unbound-tree");
    let unstored = Oid::from_hex(&"ab".repeat(20)).expect("sha1 width");
    let error = new(&fixture.store, request(unstored, Vec::new(), "root\n"))
        .expect_err("an unstored tree cannot be committed");
    assert_eq!(error.code, ErrorCode::ENotFound);
}

#[test]
fn an_object_that_is_not_a_tree_is_invalid() {
    let fixture = Fixture::new("blob-tree");
    let blob = fixture.publish(ObjectKind::Blob, b"not a tree");
    let error = new(&fixture.store, request(blob, Vec::new(), "root\n"))
        .expect_err("a blob cannot be a tree");
    assert_eq!(error.code, ErrorCode::EInvalid);
}

#[test]
fn an_unstored_parent_is_not_found() {
    let fixture = Fixture::new("unstored-parent");
    let absent = Oid::from_hex(&"cd".repeat(20)).expect("sha1 width");
    let error = new(
        &fixture.store,
        request(
            fixture.tree(b"a"),
            vec![Head::Git { oid: absent }],
            "root\n",
        ),
    )
    .expect_err("an unstored parent cannot be committed");
    assert_eq!(error.code, ErrorCode::ENotFound);
}

#[test]
fn a_stale_predecessor_publishes_nothing() {
    let fixture = Fixture::new("stale");
    let created = created(&fixture, "root\n");
    let other = new(
        &fixture.store,
        request(fixture.tree(b"b"), Vec::new(), "other\n"),
    )
    .expect("create unrelated commit");

    let error = new(
        &fixture.store,
        NewRequest {
            change_id: Some(created.change_id),
            predecessor: Some(other.head),
            ..request(fixture.tree(b"c"), Vec::new(), "rewrite\n")
        },
    )
    .expect_err("a predecessor from another change is stale");
    assert_eq!(error.code, ErrorCode::EStale);

    let records = Records::new(&fixture.store);
    let entry = records
        .get_change(&created.change_id)
        .expect("read change")
        .expect("change stored");
    assert_eq!(entry.heads, vec![created.head]);
}

#[test]
fn a_predecessor_rewrites_the_change_head() {
    let fixture = Fixture::new("rewrite");
    let first = created(&fixture, "first\n");
    let rewritten = new(
        &fixture.store,
        NewRequest {
            change_id: Some(first.change_id),
            predecessor: Some(first.head),
            ..request(fixture.tree(b"b"), Vec::new(), "second\n")
        },
    )
    .expect("rewrite the change head");

    let described = change_description(&fixture, first.change_id);
    assert_eq!(described.heads, vec![rewritten.head]);
    assert!(!described.divergent);

    let rewritten_record = commit_description(&fixture, rewritten.head);
    assert_eq!(rewritten_record.predecessor, Some(first.head));
}

#[test]
fn a_request_naming_both_a_commit_and_a_change_is_invalid() {
    let fixture = Fixture::new("both");
    let created = created(&fixture, "root\n");
    let error = describe(
        &fixture.store,
        DescribeRequest {
            head: Some(created.head),
            change_id: Some(created.change_id),
        },
    )
    .expect_err("a request must name exactly one target");
    assert_eq!(error.code, ErrorCode::EInvalid);
}

#[test]
fn a_request_naming_neither_target_is_invalid() {
    let fixture = Fixture::new("neither");
    let error = describe(
        &fixture.store,
        DescribeRequest {
            head: None,
            change_id: None,
        },
    )
    .expect_err("a request must name exactly one target");
    assert_eq!(error.code, ErrorCode::EInvalid);
}

#[test]
fn an_unstored_commit_description_is_not_found() {
    let fixture = Fixture::new("absent-commit");
    let absent = Oid::from_hex(&"ef".repeat(20)).expect("sha1 width");
    let error = describe(
        &fixture.store,
        DescribeRequest::commit(Head::Git { oid: absent }),
    )
    .expect_err("an absent commit has no description");
    assert_eq!(error.code, ErrorCode::ENotFound);
}
