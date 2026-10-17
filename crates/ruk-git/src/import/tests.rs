//! Import behavior: byte preservation, CAS planning, divergence,
//! quarantine, and error naming. Every source is built programmatically;
//! no test invokes the git CLI or the network.

use ruk_core::change::ChangeId;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefName, RefTarget};
use ruk_core::store::{FactTable, ObjectKind, Store};

use super::fixtures::{Fixture, IndexFormat, PackBody, PackObject, observation, read_object};
use super::{DirectPublish, ImportProgress, ImportReport, PublishSink, import_repository};
use crate::GitError;
use crate::import::refs::{decode_observation, encode_observation, observation_key};
use crate::import::walk::object_links;

#[derive(Debug)]
struct CountingSink<'a> {
    inner: DirectPublish<'a>,
    calls: usize,
}

impl PublishSink for CountingSink<'_> {
    fn publish(
        &mut self,
        objects: Vec<ruk_core::store::PreparedObject>,
        facts: Vec<ruk_core::store::FactMutation>,
    ) -> Result<ruk_core::store::Publication, GitError> {
        self.calls += 1;
        self.inner.publish(objects, facts)
    }
}

fn ref_name(name: &str) -> RefName {
    RefName::new(name.as_bytes().to_vec()).expect("ref name")
}

fn outcome<'a>(report: &'a ImportReport, name: &str) -> &'a super::RefOutcome {
    report
        .refs
        .iter()
        .find(|entry| entry.name == ref_name(name))
        .unwrap_or_else(|| panic!("no outcome for {name}"))
}

fn change_hex(byte: u8) -> (ChangeId, String) {
    let id = ChangeId::from_bytes([byte; 16]);
    let hex = id.to_reverse_hex();
    (id, format!("change-id {hex}\n"))
}

/// A small loose repository: blob, tree (with a non-UTF-8 name and a
/// gitlink the walk must not follow), commit with unknown headers and a
/// usable change-id, annotated tag, branch ref, tag ref, symbolic HEAD.
fn loose_repo() -> (Fixture, Store, TestOids) {
    let fixture = Fixture::sha1();
    let blob = fixture.blob(b"hello\n");
    let foreign: Oid = Oid::from_bytes(&[0xabu8; 20]).expect("foreign");
    let mut tree_payload = Vec::new();
    tree_payload.extend_from_slice(b"100644 \xff\xfe\0");
    tree_payload.extend_from_slice(blob.as_bytes());
    tree_payload.extend_from_slice(b"100644 file\0");
    tree_payload.extend_from_slice(blob.as_bytes());
    tree_payload.extend_from_slice(b"160000 sub\0");
    tree_payload.extend_from_slice(foreign.as_bytes());
    // Re-sort: entries must be ordered ` \xff\xfe` < `file` < `sub`.
    let tree_oid = fixture.loose("tree", &tree_payload);
    let (_id, header) = change_hex(0x11);
    let extra = format!("{header}x-custom yes\nmergetag first\nmergetag second\ngpgsig -----BEGIN\n \n -----END\n");
    let (commit_payload, commit) =
        fixture.commit(tree_oid, &[], extra.as_bytes(), b"initial\n");
    let (tag_payload, tag) = fixture.tag(commit, "commit", b"v1");
    fixture.write_ref("refs/heads/main", commit);
    fixture.write_ref("refs/tags/v1", tag);
    fixture.write_head("ref: refs/heads/main\n");
    let store = fixture.store();
    (
        fixture,
        store,
        TestOids {
            blob,
            tree: tree_oid,
            tree_payload,
            commit,
            commit_payload,
            tag,
            tag_payload,
            foreign,
        },
    )
}

struct TestOids {
    blob: Oid,
    tree: Oid,
    tree_payload: Vec<u8>,
    commit: Oid,
    commit_payload: Vec<u8>,
    tag: Oid,
    tag_payload: Vec<u8>,
    foreign: Oid,
}

#[test]
fn loose_import_preserves_bytes_and_refs() {
    let (fixture, store, oids) = loose_repo();
    let progress = ImportProgress::new();
    let mut sink = DirectPublish(&store);
    let request = fixture.request(1, b"origin");
    let report = import_repository(&store, &request, &progress, &mut sink).expect("import");

    assert_eq!(report.object_format, HashKind::Sha1);
    assert_eq!(report.refs_seen, 2);
    assert_eq!(report.objects, 4);
    assert!(report.batches >= 1);

    for (oid, kind, payload) in [
        (oids.blob, ObjectKind::Blob, b"hello\n".as_slice()),
        (oids.tree, ObjectKind::Tree, oids.tree_payload.as_slice()),
        (oids.commit, ObjectKind::Commit, oids.commit_payload.as_slice()),
        (oids.tag, ObjectKind::Tag, oids.tag_payload.as_slice()),
    ] {
        let (kind_got, bytes) = read_object(&store, oid);
        assert_eq!(kind_got, kind);
        assert_eq!(bytes, payload);
    }

    // The foreign gitlink was never followed.
    assert!(store.read(oids.foreign).is_err());

    let main = outcome(&report, "refs/heads/main");
    assert_eq!(main.decision, super::RefDecision::Created);
    assert_eq!(main.imported, RefTarget::Direct(oids.commit));
    assert_eq!(main.peeled, None);
    let tag = outcome(&report, "refs/tags/v1");
    assert_eq!(tag.decision, super::RefDecision::Created);
    assert_eq!(tag.peeled, Some(oids.commit));

    assert_eq!(
        observation(&store, b"origin", "refs/heads/main"),
        Some(RefTarget::Direct(oids.commit))
    );
    assert_eq!(
        observation(&store, b"origin", "refs/tags/v1"),
        Some(RefTarget::Direct(oids.tag))
    );

    match &report.head {
        Some(super::SourceHead::Symbolic { name, target }) => {
            assert_eq!(*name, ref_name("refs/heads/main"));
            assert_eq!(*target, Some(oids.commit));
        }
        other => panic!("unexpected head {other:?}"),
    }

    let (id, _) = change_hex(0x11);
    assert!(report.commits.new_changes.contains(&(id, oids.commit)));
    assert!(report.commits.divergent.is_empty());
    assert!(report.commits.noncanonical_change_ids.is_empty());
}

#[test]
fn reimport_is_idempotent() {
    let (fixture, store, oids) = loose_repo();
    let progress = ImportProgress::new();
    let mut sink = DirectPublish(&store);
    import_repository(&store, &fixture.request(1, b"origin"), &progress, &mut sink)
        .expect("first");
    let report =
        import_repository(&store, &fixture.request(2, b"origin"), &progress, &mut sink)
            .expect("second");

    for name in ["refs/heads/main", "refs/tags/v1"] {
        assert_eq!(outcome(&report, name).decision, super::RefDecision::Unchanged);
    }
    assert_eq!(report.commits.known, vec![oids.commit]);
    assert!(report.commits.new_changes.is_empty());
    assert!(report.commits.divergent.is_empty());
}

#[test]
fn known_change_id_with_new_oid_diverges() {
    let (fixture, store, oids) = loose_repo();
    let progress = ImportProgress::new();
    let mut sink = DirectPublish(&store);
    import_repository(&store, &fixture.request(1, b"origin"), &progress, &mut sink)
        .expect("first");

    let second = Fixture::sha1();
    let blob = second.blob(b"different\n");
    let (_, tree) = second.tree(&[(false, b"file", blob)]);
    let (_id, header) = change_hex(0x11);
    let (_, commit) = second.commit(tree, &[], header.as_bytes(), b"rewritten\n");
    second.write_ref("refs/heads/main", commit);
    second.write_head("ref: refs/heads/main\n");

    let report = import_repository(&store, &second.request(2, b"origin"), &progress, &mut sink)
        .expect("second");
    let (id, _) = change_hex(0x11);
    assert!(report.commits.divergent.contains(&(id, commit)));
    assert_eq!(
        outcome(&report, "refs/heads/main").decision,
        super::RefDecision::Updated {
            previous: RefTarget::Direct(oids.commit),
        }
    );
    // The old OID is still intact.
    let (_, bytes) = read_object(&store, oids.commit);
    assert_eq!(bytes, oids.commit_payload);
}

#[test]
fn ref_moves_without_base_conflict_and_keep_local() {
    // Source one owns the ref; source two moves it under another namespace
    // without an observation base, which must not clobber the stored ref.
    let first = Fixture::sha1();
    let blob_a = first.blob(b"a\n");
    let (_, tree_a) = first.tree(&[(false, b"a", blob_a)]);
    let (_, commit_a) = first.commit(tree_a, &[], b"", b"a\n");
    first.write_ref("refs/heads/main", commit_a);
    first.write_head("ref: refs/heads/main\n");
    let store = first.store();
    let progress = ImportProgress::new();
    let mut sink = DirectPublish(&store);
    import_repository(&store, &first.request(1, b"s1"), &progress, &mut sink).expect("first");

    let second = Fixture::sha1();
    let blob_b = second.blob(b"b\n");
    let (_, tree_b) = second.tree(&[(false, b"b", blob_b)]);
    let (_, commit_b) = second.commit(tree_b, &[], b"", b"b\n");
    second.write_ref("refs/heads/main", commit_b);

    let report = import_repository(&store, &second.request(2, b"s2"), &progress, &mut sink)
        .expect("second");
    assert_eq!(
        outcome(&report, "refs/heads/main").decision,
        super::RefDecision::Conflicted {
            local: RefTarget::Direct(commit_a),
        }
    );
    assert_eq!(
        observation(&store, b"s2", "refs/heads/main"),
        Some(RefTarget::Direct(commit_b))
    );

    // Reimporting the same source now sees a natively kept ref: the source
    // did not move since the observation, so the local ref stays.
    let report = import_repository(&store, &second.request(3, b"s2"), &progress, &mut sink)
        .expect("third");
    assert_eq!(
        outcome(&report, "refs/heads/main").decision,
        super::RefDecision::KeptLocal {
            local: RefTarget::Direct(commit_a),
        }
    );
}

#[test]
fn symbolic_refs_diverge_without_merge() {
    let first = Fixture::sha1();
    let blob = first.blob(b"x\n");
    let (_, tree) = first.tree(&[(false, b"x", blob)]);
    let (_, commit) = first.commit(tree, &[], b"", b"x\n");
    first.write_ref("refs/heads/main", commit);
    first.write_ref("refs/heads/other", commit);
    std::fs::write(
        first.git_dir.join("refs").join("heads").join("alias"),
        "ref: refs/heads/main\n",
    )
    .expect("symref");
    let store = first.store();
    let progress = ImportProgress::new();
    let mut sink = DirectPublish(&store);
    let report = import_repository(&store, &first.request(1, b"s1"), &progress, &mut sink)
        .expect("first");
    assert_eq!(
        outcome(&report, "refs/heads/alias").decision,
        super::RefDecision::Created
    );

    let second = Fixture::sha1();
    let blob = second.blob(b"x\n");
    let (_, tree) = second.tree(&[(false, b"x", blob)]);
    let (_, commit) = second.commit(tree, &[], b"", b"x\n");
    second.write_ref("refs/heads/other", commit);
    std::fs::write(
        second.git_dir.join("refs").join("heads").join("alias"),
        "ref: refs/heads/other\n",
    )
    .expect("symref");
    let report = import_repository(&store, &second.request(2, b"s2"), &progress, &mut sink)
        .expect("second");
    assert_eq!(
        outcome(&report, "refs/heads/alias").decision,
        super::RefDecision::SymbolicDiverged {
            local: RefTarget::Symbolic(ref_name("refs/heads/main")),
        }
    );
}

#[test]
fn noncanonical_change_id_falls_back_to_oid() {
    let fixture = Fixture::sha1();
    let blob = fixture.blob(b"n\n");
    let (_, tree) = fixture.tree(&[(false, b"n", blob)]);
    let (_, commit) = fixture.commit(
        tree,
        &[],
        b"change-id nope\nchange-id still-nope\n",
        b"forked\n",
    );
    fixture.write_ref("refs/heads/main", commit);
    let store = fixture.store();
    let progress = ImportProgress::new();
    let mut sink = DirectPublish(&store);
    let report = import_repository(&store, &fixture.request(1, b"o"), &progress, &mut sink)
        .expect("import");
    assert_eq!(report.commits.noncanonical_change_ids, vec![commit]);
    assert_eq!(report.commits.new_changes.len(), 1);
    assert_eq!(report.commits.new_changes[0].1, commit);
}

fn packed_repo(format: IndexFormat) -> (Fixture, Store, PackIds) {
    let fixture = Fixture::sha1();
    let base = b"base content\n".to_vec();
    let derived = b"base CONTENT with more text appended here\n".to_vec();
    let base_payload = base.clone();
    let base_oid = fixture.oid("blob", &base);
    let derived_oid = fixture.oid("blob", &derived);
    // The commit's tree links both blobs, so the pack's delta base is
    // reachable: a delta base that lives only in the pack would never be
    // emitted by the ref-closure walk.
    let tree_payload = Fixture::tree_payload(&[
        (false, b"base.txt", base_oid),
        (false, b"derived.txt", derived_oid),
    ]);
    let commit_payload = Fixture::commit_payload(
        fixture.oid("tree", &tree_payload),
        &[],
        b"",
        b"packed\n",
    );
    let tag_payload = Fixture::tag_payload(
        fixture.oid("commit", &commit_payload),
        "commit",
        b"v1",
    );
    let oids = fixture.pack(
        &[
            PackObject::full(3, base_payload.clone()),
            PackObject {
                kind: 3,
                payload: derived.clone(),
                body: PackBody::OfsDelta { base: base_oid },
            },
            PackObject::full(2, tree_payload.clone()),
            PackObject::full(1, commit_payload.clone()),
            PackObject::full(4, tag_payload.clone()),
        ],
        format,
    );
    let commit = fixture.oid("commit", &commit_payload);
    let tag = fixture.oid("tag", &tag_payload);
    fixture.write_packed_refs(&[
        format!("{} refs/heads/packed", commit.to_hex()),
        format!("{} refs/tags/v1", tag.to_hex()),
        format!("^{}", commit.to_hex()),
    ]);
    fixture.write_head("ref: refs/heads/packed\n");
    let store = fixture.store();
    (
        fixture,
        store,
        PackIds {
            base: oids[0],
            base_payload,
            derived: oids[1],
            derived_payload: derived,
            commit,
            commit_payload,
            tag,
        },
    )
}

struct PackIds {
    base: Oid,
    base_payload: Vec<u8>,
    derived: Oid,
    derived_payload: Vec<u8>,
    commit: Oid,
    commit_payload: Vec<u8>,
    tag: Oid,
}

#[test]
fn pack_v2_idx_v2_with_delta_and_peel() {
    let (_fixture, store, ids) = packed_repo(IndexFormat::V2);
    let progress = ImportProgress::new();
    let mut sink = DirectPublish(&store);
    let request = _fixture.request(1, b"origin");
    let report = import_repository(&store, &request, &progress, &mut sink).expect("import");

    let (_, bytes) = read_object(&store, ids.base);
    assert_eq!(bytes, ids.base_payload);
    let (_, bytes) = read_object(&store, ids.derived);
    assert_eq!(bytes, ids.derived_payload);
    let (_, bytes) = read_object(&store, ids.commit);
    assert_eq!(bytes, ids.commit_payload);

    let tag = outcome(&report, "refs/tags/v1");
    assert_eq!(tag.imported, RefTarget::Direct(ids.tag));
    assert_eq!(tag.peeled, Some(ids.commit));
    let branch = outcome(&report, "refs/heads/packed");
    assert_eq!(branch.decision, super::RefDecision::Created);
}

#[test]
fn pack_v2_idx_v1() {
    let (_fixture, store, ids) = packed_repo(IndexFormat::V1);
    let progress = ImportProgress::new();
    let mut sink = DirectPublish(&store);
    let request = _fixture.request(1, b"origin");
    let report = import_repository(&store, &request, &progress, &mut sink).expect("import");
    let (_, bytes) = read_object(&store, ids.derived);
    assert_eq!(bytes, ids.derived_payload);
    assert_eq!(report.objects, 5);
}

#[test]
fn sha256_pack_v3() {
    // Nothing is loose here: every object comes from a v3 pack with a v2
    // index, so the test fails unless gix reads that combination.
    let fixture = Fixture::new(HashKind::Sha256);
    fixture.write_config("[extensions]\n\tobjectFormat = sha256\n");
    let blob_payload = b"sha256 blob\n".to_vec();
    let blob = fixture.oid("blob", &blob_payload);
    let tree_payload = Fixture::tree_payload(&[(false, b"f", blob)]);
    let tree = fixture.oid("tree", &tree_payload);
    let commit_payload = Fixture::commit_payload(tree, &[], b"", b"sha256\n");
    let commit = fixture.oid("commit", &commit_payload);
    fixture.pack(
        &[
            PackObject::full(3, blob_payload.clone()),
            PackObject::full(2, tree_payload),
            PackObject::full(1, commit_payload),
        ],
        IndexFormat::V2,
    );
    fixture.write_ref("refs/heads/main", commit);
    fixture.write_head("ref: refs/heads/main\n");
    let store = fixture.store();
    let progress = ImportProgress::new();
    let mut sink = DirectPublish(&store);
    let request = fixture.request(1, b"origin");
    let report = import_repository(&store, &request, &progress, &mut sink).expect("import");
    assert_eq!(report.object_format, HashKind::Sha256);
    assert_eq!(report.objects, 3);
    let (_, bytes) = read_object(&store, blob);
    assert_eq!(bytes, blob_payload);
    assert_eq!(
        outcome(&report, "refs/heads/main").decision,
        super::RefDecision::Created
    );
}

#[test]
fn corrupt_object_fails_without_ref_facts() {
    let (fixture, store, oids) = loose_repo();
    fixture.loose_raw(oids.tree, b"not a deflated object");
    let progress = ImportProgress::new();
    let mut sink = DirectPublish(&store);
    let error = import_repository(&store, &fixture.request(1, b"o"), &progress, &mut sink)
        .expect_err("corrupt");
    assert!(matches!(error, GitError::Corrupt { .. }), "{error:?}");
    let key = observation_key(b"o", &ref_name("refs/heads/main"));
    assert_eq!(store.fact(FactTable::RemoteObservations, &key).expect("fact"), None);
}

#[test]
fn missing_object_names_oid_and_referrer() {
    let fixture = Fixture::sha1();
    let missing = Oid::from_bytes(&[0x77u8; 20]).expect("oid");
    let (_, commit) = fixture.commit(missing, &[], b"", b"dangling\n");
    fixture.write_ref("refs/heads/main", commit);
    let store = fixture.store();
    let progress = ImportProgress::new();
    let mut sink = DirectPublish(&store);
    let error = import_repository(&store, &fixture.request(1, b"o"), &progress, &mut sink)
        .expect_err("missing");
    match error {
        GitError::NotFound { detail } => {
            assert!(detail.contains(&missing.to_string()), "{detail}");
            assert!(detail.contains(&commit.to_string()), "{detail}");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn empty_source_is_noop() {
    let fixture = Fixture::sha1();
    let store = fixture.store();
    let progress = ImportProgress::new();
    let mut sink = CountingSink {
        inner: DirectPublish(&store),
        calls: 0,
    };
    let report = import_repository(&store, &fixture.request(1, b"o"), &progress, &mut sink)
        .expect("empty");
    assert_eq!(report.objects, 0);
    assert_eq!(report.batches, 0);
    assert!(report.refs.is_empty());
    assert_eq!(report.head, None);
    assert_eq!(sink.calls, 0);
}

#[test]
fn cross_format_source_fails() {
    let source = Fixture::sha1();
    source.blob(b"x\n");
    let target = Fixture::new(HashKind::Sha256);
    let store = target.store();
    let progress = ImportProgress::new();
    let mut sink = DirectPublish(&store);
    let request = source.request(1, b"o");
    let request = super::ImportRequest {
        git_dir: &source.git_dir,
        ..request
    };
    let error = import_repository(&store, &request, &progress, &mut sink).expect_err("format");
    assert!(matches!(error, GitError::ObjectFormat { .. }), "{error:?}");
}

#[test]
fn cancelled_import_publishes_nothing() {
    let (fixture, store, _) = loose_repo();
    let progress = ImportProgress::new();
    progress.cancel();
    let mut sink = CountingSink {
        inner: DirectPublish(&store),
        calls: 0,
    };
    let error = import_repository(&store, &fixture.request(1, b"o"), &progress, &mut sink)
        .expect_err("cancelled");
    assert!(matches!(error, GitError::Cancelled { .. }), "{error:?}");
    assert_eq!(sink.calls, 0);
}

#[test]
fn shallow_boundary_is_recorded() {
    let (fixture, store, oids) = loose_repo();
    fixture.write_shallow(&[oids.commit]);
    let progress = ImportProgress::new();
    let mut sink = DirectPublish(&store);
    let report = import_repository(&store, &fixture.request(1, b"o"), &progress, &mut sink)
        .expect("import");
    assert_eq!(report.shallow, vec![oids.commit]);
    let key = super::refs::shallow_key(oids.commit);
    assert_eq!(
        store.fact(FactTable::Shallow, &key).expect("fact"),
        Some(Vec::new())
    );
}

#[test]
fn object_links_cover_all_kinds() {
    let hash = HashKind::Sha1;
    assert!(object_links(ObjectKind::Blob, b"data", hash).expect("blob").links.is_empty());

    let blob = HashKind::Sha1.hash_git_object("blob", b"f").expect("blob");
    let tree_hex = blob.to_hex();
    let mut tree = format!("100644 f\0").into_bytes();
    tree.extend_from_slice(blob.as_bytes());
    let mut with_link = tree.clone();
    let foreign = Oid::from_bytes(&[9u8; 20]).expect("oid");
    with_link.extend_from_slice(b"160000 sub\0");
    with_link.extend_from_slice(foreign.as_bytes());
    let links = object_links(ObjectKind::Tree, &with_link, hash).expect("tree");
    assert_eq!(links.links.len(), 1);
    assert_eq!(links.links[0].oid, blob);
    assert_eq!(links.links[0].kind, ObjectKind::Blob);
    let _ = tree_hex;

    let tree_id = HashKind::Sha1.hash_git_object("tree", &tree).expect("tree");
    let parent = Oid::from_bytes(&[8u8; 20]).expect("oid");
    let payload = Fixture::commit_payload(tree_id, &[parent], b"", b"m\n");
    let links = object_links(ObjectKind::Commit, &payload, hash).expect("commit");
    assert_eq!(
        links.links,
        vec![
            super::walk::Link {
                oid: tree_id,
                kind: ObjectKind::Tree
            },
            super::walk::Link {
                oid: parent,
                kind: ObjectKind::Commit
            },
        ]
    );

    let tag = Fixture::tag_payload(tree_id, "tree", b"t");
    let links = object_links(ObjectKind::Tag, &tag, hash).expect("tag");
    assert_eq!(links.links.len(), 1);
    assert_eq!(links.links[0].oid, tree_id);

    // Unsorted entries are tolerated the way Git reads them: both objects
    // still join the closure.
    let mut unsorted = format!("100644 b\0").into_bytes();
    unsorted.extend_from_slice(blob.as_bytes());
    unsorted.extend_from_slice(b"100644 a\0");
    unsorted.extend_from_slice(blob.as_bytes());
    let links = object_links(ObjectKind::Tree, &unsorted, hash).expect("tolerant");
    assert_eq!(links.links.len(), 2);
}

#[test]
fn observation_codec_round_trips() {
    let hash = HashKind::Sha1;
    let direct = RefTarget::Direct(Oid::from_bytes(&[3u8; 20]).expect("oid"));
    let symbolic = RefTarget::Symbolic(ref_name("refs/heads/main"));
    for target in [direct, symbolic] {
        let bytes = encode_observation(&target);
        assert_eq!(decode_observation(&bytes, hash).expect("decode"), target);
    }
    assert!(decode_observation(b"", hash).is_err());
    assert!(decode_observation(b"\x02rest", hash).is_err());
    assert!(decode_observation(b"\x00short", hash).is_err());
    let key = observation_key(b"origin", &ref_name("refs/heads/main"));
    assert_eq!(&key[..7], b"origin\x00");
}
