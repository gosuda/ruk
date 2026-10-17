//! End-to-end export tests: fixture store → export → reopen with gix
//! readers (never the git CLI).
//!
//! These tests need the parent-owned promotions in
//! `local://ruk-git-export-api.md` (public `ruk_core::refs`,
//! `Store::fact_page`, public durability installs, and the agreed
//! [`crate::GitError`] variants): ref rows are published through
//! `prepare_checked_transaction`, which lives behind that visibility.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ruk_core::ByteString;
use ruk_core::OperationId;
use ruk_core::conflict::{Signature, TzOffset};
use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTarget, RefTransaction, RefUpdate};
use ruk_core::refs::prepare_set_ref_conflict;
use ruk_core::refs::{ReflogKey, ReflogRecord, prepare_append_reflog, prepare_checked_transaction};
use ruk_core::store::{ObjectKind, PreparationBudget, Store};
use ruk_core::workspace::HeadRef;

use super::{ExportReport, ExportRequest, export_repository};
use crate::GitError;

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A fresh directory; removed when the test ends.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let id = NEXT.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("ruk-export-test-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn test_store(scratch: &Scratch, name: &str, kind: HashKind) -> Store {
    let root = scratch.path(name);
    Store::create(&root, kind, Arc::new(PreparationBudget::default())).unwrap()
}

fn put(store: &Store, kind: ObjectKind, bytes: &[u8]) -> Oid {
    let len = u64::try_from(bytes.len()).unwrap();
    let prepared = store.prepare(kind, len, bytes, None).unwrap();
    let oid = prepared.oid();
    let publication = store.publish(vec![prepared], &[]).unwrap();
    assert_eq!(publication.objects, vec![oid]);
    oid
}

fn set_ref(store: &Store, name: &str, target: RefTarget) {
    let update = RefUpdate {
        name: RefName::new(name.as_bytes().to_vec()).unwrap(),
        expected: RefExpect::Absent,
        change: RefChange::Set(target),
    };
    let transaction = RefTransaction::new(store.hash_kind(), vec![update]).unwrap();
    let prepared = prepare_checked_transaction(store, &transaction).unwrap();
    store.publish(Vec::new(), &prepared.mutations).unwrap();
}

fn commit_bytes(tree: Oid, parents: &[Oid], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"tree ");
    out.extend_from_slice(tree.to_hex().as_bytes());
    out.push(b'\n');
    for parent in parents {
        out.extend_from_slice(b"parent ");
        out.extend_from_slice(parent.to_hex().as_bytes());
        out.push(b'\n');
    }
    out.extend_from_slice(b"author a <a@example.com> 1 +0000\n");
    out.extend_from_slice(b"committer a <a@example.com> 1 +0000\n");
    out.extend_from_slice(b"\n");
    out.extend_from_slice(message);
    out
}

fn signature() -> Signature {
    Signature {
        name: ByteString::from("a"),
        email: ByteString::from("a@example.com"),
        timestamp: 1,
        offset: TzOffset::UTC,
    }
}

/// A blob, an empty tree, a commit, and an annotated tag, all published.
struct Chain {
    blob: Oid,
    tree: Oid,
    commit: Oid,
    tag: Oid,
}

fn tree_bytes(entries: &[(&str, u32, Oid)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut sorted: Vec<(&str, u32, Oid)> = entries.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (name, mode, oid) in sorted {
        out.extend_from_slice(format!("{mode:o} {name}\0").as_bytes());
        out.extend_from_slice(oid.as_bytes());
    }
    out
}

fn chain(store: &Store) -> Chain {
    let blob = put(store, ObjectKind::Blob, b"hello\n");
    let tree = put(
        store,
        ObjectKind::Tree,
        &tree_bytes(&[("hello.txt", 0o100644, blob)]),
    );
    let commit = put(
        store,
        ObjectKind::Commit,
        &commit_bytes(tree, &[], b"init\n"),
    );
    let mut tag = Vec::new();
    tag.extend_from_slice(b"object ");
    tag.extend_from_slice(commit.to_hex().as_bytes());
    tag.extend_from_slice(b"\ntype commit\ntag v1\ntagger a <a@example.com> 1 +0000\n\nrelease\n");
    let tag = put(store, ObjectKind::Tag, &tag);
    Chain {
        blob,
        tree,
        commit,
        tag,
    }
}

fn gix_kind(kind: HashKind) -> gix_hash::Kind {
    kind.gix()
}

/// Every object of the export, inflated independently and byte-compared
/// with the store.
fn assert_pack_matches_store(store: &Store, dir: &Path, report: &ExportReport, kind: HashKind) {
    use std::io::Read as _;
    let pack_path = dir.join(format!("objects/pack/{}.pack", report.pack.name));
    let idx_path = dir.join(format!("objects/pack/{}.idx", report.pack.name));
    let pack_bytes = std::fs::read(&pack_path).unwrap();
    let pack = gix_pack::data::File::at(&pack_path, gix_kind(kind)).unwrap();
    let index = gix_pack::index::File::at(&idx_path, gix_kind(kind)).unwrap();
    assert_eq!(u64::from(pack.num_objects()), report.pack.objects);
    assert_eq!(u64::from(index.num_objects()), report.pack.objects);
    assert_eq!(Oid::from(index.pack_checksum()), report.pack.checksum);
    for entry in index.iter() {
        let oid = Oid::from(entry.oid);
        let stored = store.read(oid).unwrap();
        let mut expected = Vec::new();
        let mut spool = stored.bytes;
        spool.read_to_end(&mut expected).unwrap();
        let decoded = pack.entry(entry.pack_offset).unwrap();
        let start = usize::try_from(decoded.data_offset).unwrap();
        // The decoder stops at the end of the zlib stream; trailing pack
        // bytes are ignored, so no size arithmetic is shared with the
        // exporter under test.
        let mut decoder = flate2::read::ZlibDecoder::new(&pack_bytes[start..]);
        let mut actual = Vec::new();
        decoder.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected, "object {oid} differs");
    }
}

#[test]
fn empty_store_exports_a_bare_skeleton() {
    let scratch = Scratch::new();
    let store = test_store(&scratch, "store", HashKind::Sha1);
    let target = scratch.path("out.git");
    let head = HeadRef::Symbolic(RefName::new(b"refs/heads/main" as &[u8]).unwrap());
    let report = export_repository(
        &store,
        &ExportRequest {
            target: target.clone(),
            head: head.clone(),
            store_root: scratch.path("store"),
        },
    )
    .unwrap();
    assert_eq!(
        std::fs::read(target.join("HEAD")).unwrap(),
        b"ref: refs/heads/main\n"
    );
    assert!(target.join("objects/pack").is_dir());
    assert!(target.join("refs/heads").is_dir());
    assert!(target.join("refs/tags").is_dir());
    assert_eq!(report.pack.objects, 0);
    assert!(report.unexported_refs.is_empty());
    assert!(report.is_lossless());
    assert!(report.head.exported);
    assert_pack_matches_store(&store, &target, &report, HashKind::Sha1);
    let json = sonic_rs::to_string(&report).unwrap();
    assert!(json.contains("\"object_format\":\"sha1\""));
}

#[test]
fn round_trip_commit_tree_blob_and_annotated_tag() {
    let scratch = Scratch::new();
    let store = test_store(&scratch, "store", HashKind::Sha1);
    let built = chain(&store);
    set_ref(&store, "refs/heads/main", RefTarget::Direct(built.commit));
    set_ref(&store, "refs/tags/v1", RefTarget::Direct(built.tag));
    let target = scratch.path("out.git");
    let report = export_repository(
        &store,
        &ExportRequest {
            target: target.clone(),
            head: HeadRef::Symbolic(RefName::new(b"refs/heads/main" as &[u8]).unwrap()),
            store_root: scratch.path("store"),
        },
    )
    .unwrap();
    assert!(report.is_lossless());
    assert_eq!(report.pack.objects, 4);
    assert_eq!(report.refs.packed, 2);
    let packed = std::fs::read(target.join("packed-refs")).unwrap();
    let text = String::from_utf8(packed).unwrap();
    assert!(text.starts_with("# pack-refs with: peeled fully-peeled sorted \n"));
    assert!(text.contains(&format!("{} refs/heads/main\n", built.commit)));
    assert!(text.contains(&format!("{} refs/tags/v1\n", built.tag)));
    assert!(text.contains(&format!("^{}\n", built.commit)));
    let index = gix_pack::index::File::at(
        target.join(format!("objects/pack/{}.idx", report.pack.name)),
        gix_kind(HashKind::Sha1),
    )
    .unwrap();
    for oid in [built.blob, built.tree, built.commit, built.tag] {
        assert!(index.lookup(gix_hash::ObjectId::from(oid)).is_some());
    }
    assert_pack_matches_store(&store, &target, &report, HashKind::Sha1);
}

#[test]
fn conflicted_bookmark_is_named_never_exported() {
    let scratch = Scratch::new();
    let store = test_store(&scratch, "store", HashKind::Sha1);
    let built = chain(&store);
    // A second commit reachable only from the conflicted ref.
    let other = put(
        &store,
        ObjectKind::Commit,
        &commit_bytes(built.tree, &[], b"other\n"),
    );
    set_ref(&store, "refs/heads/main", RefTarget::Direct(built.commit));
    set_ref(&store, "refs/heads/conflicted", RefTarget::Direct(other));
    let conflict =
        ruk_core::merge::Merge::from_removes_adds([Some(other)], [Some(other), Some(built.commit)]);
    let name = RefName::new(b"refs/heads/conflicted" as &[u8]).unwrap();
    let mutation = prepare_set_ref_conflict(&store, &name, &conflict).unwrap();
    store.publish(Vec::new(), &[mutation]).unwrap();

    let target = scratch.path("out.git");
    let report = export_repository(
        &store,
        &ExportRequest {
            target: target.clone(),
            head: HeadRef::Symbolic(RefName::new(b"refs/heads/main" as &[u8]).unwrap()),
            store_root: scratch.path("store"),
        },
    )
    .unwrap();
    assert!(!report.is_lossless());
    let named: Vec<_> = report
        .unexported_refs
        .iter()
        .filter(|u| u.name.as_bytes() == b"refs/heads/conflicted")
        .collect();
    assert_eq!(named.len(), 1);
    assert_eq!(named[0].reason, super::report::UnexportedReason::Conflicted);
    let packed = String::from_utf8(std::fs::read(target.join("packed-refs")).unwrap()).unwrap();
    assert!(!packed.contains("refs/heads/conflicted"));
    // The commit reachable only from the refused root is nowhere in the pack.
    let index = gix_pack::index::File::at(
        target.join(format!("objects/pack/{}.idx", report.pack.name)),
        gix_kind(HashKind::Sha1),
    )
    .unwrap();
    assert!(index.lookup(gix_hash::ObjectId::from(other)).is_none());
    assert!(
        index
            .lookup(gix_hash::ObjectId::from(built.commit))
            .is_some()
    );
}

#[test]
fn native_record_root_is_named_not_rendered() {
    let scratch = Scratch::new();
    let store = test_store(&scratch, "store", HashKind::Sha1);
    let built = chain(&store);
    let native = put(&store, ObjectKind::Conflict, b"conflict-v1 native");
    set_ref(&store, "refs/heads/main", RefTarget::Direct(built.commit));
    set_ref(&store, "refs/heads/native", RefTarget::Direct(native));
    let target = scratch.path("out.git");
    let report = export_repository(
        &store,
        &ExportRequest {
            target: target.clone(),
            head: HeadRef::Symbolic(RefName::new(b"refs/heads/main" as &[u8]).unwrap()),
            store_root: scratch.path("store"),
        },
    )
    .unwrap();
    let named: Vec<_> = report
        .unexported_refs
        .iter()
        .filter(|u| u.name.as_bytes() == b"refs/heads/native")
        .collect();
    assert_eq!(named.len(), 1);
    assert_eq!(
        named[0].reason,
        super::report::UnexportedReason::NativeRecord
    );
    assert_eq!(named[0].oid, Some(native));
    let index = gix_pack::index::File::at(
        target.join(format!("objects/pack/{}.idx", report.pack.name)),
        gix_kind(HashKind::Sha1),
    )
    .unwrap();
    assert!(index.lookup(gix_hash::ObjectId::from(native)).is_none());
}

#[test]
fn native_parent_marks_the_whole_branch() {
    let scratch = Scratch::new();
    let store = test_store(&scratch, "store", HashKind::Sha1);
    let built = chain(&store);
    let native = put(&store, ObjectKind::Conflict, b"conflict-v1 native");
    // A Git commit can never have a native parent through the commit model,
    // but the store holds raw objects: prove the walk refuses the closure.
    let raw = {
        let mut out = Vec::new();
        out.extend_from_slice(b"tree ");
        out.extend_from_slice(built.tree.to_hex().as_bytes());
        out.extend_from_slice(b"\nparent ");
        out.extend_from_slice(native.to_hex().as_bytes());
        out.extend_from_slice(b"\nauthor a <a> 1 +0000\ncommitter a <a> 1 +0000\n\nchild\n");
        out
    };
    let child = put(&store, ObjectKind::Commit, &raw);
    set_ref(&store, "refs/heads/main", RefTarget::Direct(child));
    let target = scratch.path("out.git");
    let report = export_repository(
        &store,
        &ExportRequest {
            target: target.clone(),
            head: HeadRef::Symbolic(RefName::new(b"refs/heads/main" as &[u8]).unwrap()),
            store_root: scratch.path("store"),
        },
    )
    .unwrap();
    let named: Vec<_> = report
        .unexported_refs
        .iter()
        .filter(|u| u.name.as_bytes() == b"refs/heads/main")
        .collect();
    assert_eq!(named.len(), 1);
    assert_eq!(
        named[0].reason,
        super::report::UnexportedReason::NativeInClosure
    );
    assert!(!report.head.exported);
}

#[test]
fn dangling_parent_without_promisor_is_corrupt() {
    let scratch = Scratch::new();
    let store = test_store(&scratch, "store", HashKind::Sha1);
    let tree = put(&store, ObjectKind::Tree, b"");
    let missing = HashKind::Sha1
        .hash_git_object("blob", b"never-stored")
        .unwrap();
    let commit = put(
        &store,
        ObjectKind::Commit,
        &commit_bytes(tree, &[missing], b"dangling\n"),
    );
    set_ref(&store, "refs/heads/main", RefTarget::Direct(commit));
    let error = export_repository(
        &store,
        &ExportRequest {
            target: scratch.path("out.git"),
            head: HeadRef::Symbolic(RefName::new(b"refs/heads/main" as &[u8]).unwrap()),
            store_root: scratch.path("store"),
        },
    )
    .unwrap_err();
    assert!(matches!(error, GitError::Corrupt { .. }), "got {error:?}");
}

#[test]
fn detached_head_at_native_record_is_refused() {
    let scratch = Scratch::new();
    let store = test_store(&scratch, "store", HashKind::Sha1);
    let native = put(&store, ObjectKind::Conflict, b"conflict-v1 native");
    let error = export_repository(
        &store,
        &ExportRequest {
            target: scratch.path("out.git"),
            head: HeadRef::Detached(native),
            store_root: scratch.path("store"),
        },
    )
    .unwrap_err();
    assert!(matches!(error, GitError::Invalid { .. }), "got {error:?}");
}

#[test]
fn sha256_repo_emits_sha256_object_format() {
    let scratch = Scratch::new();
    let store = test_store(&scratch, "store", HashKind::Sha256);
    let built = chain(&store);
    set_ref(&store, "refs/heads/main", RefTarget::Direct(built.commit));
    let target = scratch.path("out.git");
    let report = export_repository(
        &store,
        &ExportRequest {
            target: target.clone(),
            head: HeadRef::Symbolic(RefName::new(b"refs/heads/main" as &[u8]).unwrap()),
            store_root: scratch.path("store"),
        },
    )
    .unwrap();
    let config = String::from_utf8(std::fs::read(target.join("config")).unwrap()).unwrap();
    assert!(config.contains("repositoryformatversion = 1"));
    assert!(config.contains("objectformat = sha256"));
    assert_eq!(report.object_format, "sha256");
    assert_pack_matches_store(&store, &target, &report, HashKind::Sha256);
}

#[test]
fn reflogs_follow_exported_refs_only() {
    let scratch = Scratch::new();
    let store = test_store(&scratch, "store", HashKind::Sha1);
    let built = chain(&store);
    set_ref(&store, "refs/heads/main", RefTarget::Direct(built.commit));
    let name = RefName::new(b"refs/heads/main" as &[u8]).unwrap();
    let record = ReflogRecord {
        operation: OperationId(1),
        old_oid: None,
        new_oid: Some(built.commit),
        committer: signature(),
        message: ByteString::from("branch: Created from export test"),
    };
    let key = ReflogKey::new(name, OperationId(1), 0);
    let mutation = prepare_append_reflog(&store, &key, &record).unwrap();
    store.publish(Vec::new(), &[mutation]).unwrap();
    let target = scratch.path("out.git");
    let report = export_repository(
        &store,
        &ExportRequest {
            target: target.clone(),
            head: HeadRef::Symbolic(RefName::new(b"refs/heads/main" as &[u8]).unwrap()),
            store_root: scratch.path("store"),
        },
    )
    .unwrap();
    assert_eq!(report.reflogs.refs, 1);
    assert_eq!(report.reflogs.entries, 1);
    assert!(report.reflogs.dropped.is_empty());
    let log = std::fs::read(target.join("logs/refs/heads/main")).unwrap();
    assert!(log.ends_with(b"branch: Created from export test\n"));
    assert!(log.starts_with(b"0000000000000000000000000000000000000000 "));
}

#[test]
fn existing_target_is_refused() {
    let scratch = Scratch::new();
    let store = test_store(&scratch, "store", HashKind::Sha1);
    let target = scratch.path("out.git");
    std::fs::create_dir_all(&target).unwrap();
    let error = export_repository(
        &store,
        &ExportRequest {
            target,
            head: HeadRef::Symbolic(RefName::new(b"refs/heads/main" as &[u8]).unwrap()),
            store_root: scratch.path("store"),
        },
    )
    .unwrap_err();
    assert!(matches!(error, GitError::Invalid { .. }), "got {error:?}");
}
