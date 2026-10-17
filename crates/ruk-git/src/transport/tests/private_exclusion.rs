use std::collections::BTreeSet;

use ruk_core::ids::{HashKind, Oid};
use ruk_core::store::{ObjectKind, Store};

use crate::transport::Interrupt;
use crate::transport::fetch::{
    Filter, collect_haves_filtered, filter_haves_for_wire, promisor_facts,
};
use crate::transport::private::{PrivateClosure, PrivateFilter};
use crate::transport::push::{PushUpdate, push_closure_filtered};
use crate::transport::session::test_support::test_store;

fn put(store: &Store, kind: ObjectKind, bytes: &[u8]) -> Oid {
    let len = u64::try_from(bytes.len()).expect("fixture fits");
    let prepared = store.prepare(kind, len, bytes, None).expect("prepare");
    let oid = prepared.oid();
    store.publish(vec![prepared], &[]).expect("publish");
    oid
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
    out.extend_from_slice(b"author t <t@example.com> 1 +0000\n");
    out.extend_from_slice(b"committer t <t@example.com> 1 +0000\n");
    out.extend_from_slice(b"\n");
    out.extend_from_slice(message);
    out
}

fn tree_bytes(entries: &[(&str, u32, Oid)]) -> Vec<u8> {
    let mut sorted: Vec<(&str, u32, Oid)> = entries.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = Vec::new();
    for (name, mode, oid) in sorted {
        out.extend_from_slice(format!("{mode:o} {name}\0").as_bytes());
        out.extend_from_slice(oid.as_bytes());
    }
    out
}

#[derive(Debug)]
struct TwoChains {
    public: Vec<Oid>,
    private: Vec<Oid>,
    public_tip: Oid,
    private_tip: Oid,
}

fn two_chains(store: &Store) -> TwoChains {
    let blob_a = put(store, ObjectKind::Blob, b"public\n");
    let tree_a = put(
        store,
        ObjectKind::Tree,
        &tree_bytes(&[("a.txt", 0o100644, blob_a)]),
    );
    let commit_a = put(
        store,
        ObjectKind::Commit,
        &commit_bytes(tree_a, &[], b"public\n"),
    );
    let blob_p = put(store, ObjectKind::Blob, b"private\n");
    let tree_p = put(
        store,
        ObjectKind::Tree,
        &tree_bytes(&[("p.txt", 0o100644, blob_p)]),
    );
    let commit_p = put(
        store,
        ObjectKind::Commit,
        &commit_bytes(tree_p, &[], b"private\n"),
    );
    TwoChains {
        public: vec![commit_a, tree_a, blob_a],
        private: vec![commit_p, tree_p, blob_p],
        public_tip: commit_a,
        private_tip: commit_p,
    }
}

fn update(name: &[u8], old: Oid, new: Oid) -> PushUpdate {
    PushUpdate {
        name: name.to_vec(),
        old,
        new,
    }
}

fn set_of(oids: &[Oid]) -> BTreeSet<Oid> {
    oids.iter().copied().collect()
}

#[test]
fn private_closure_expands_through_links() {
    let store = test_store(HashKind::Sha1);
    let chains = two_chains(&store);
    let closure =
        PrivateClosure::expand(&store, &[chains.private_tip], &Interrupt::none()).expect("expand");
    assert_eq!(
        set_of(&chains.private),
        closure.oids().iter().copied().collect()
    );
    assert!(!closure.contains(chains.public_tip));
}

#[test]
fn filtered_closure_holds_no_private_object() {
    let store = test_store(HashKind::Sha1);
    let chains = two_chains(&store);
    let filter = PrivateFilter::from_oids(chains.private.iter().copied());
    let kind = HashKind::Sha1;
    let live = [update(
        b"refs/heads/public",
        kind.zero_oid(),
        chains.public_tip,
    )];
    let refs: Vec<&PushUpdate> = live.iter().collect();
    let entries =
        push_closure_filtered(&store, kind, &refs, &filter, &Interrupt::none()).expect("closure");
    let emitted: Vec<Oid> = entries.iter().map(|entry| entry.oid).collect();
    assert_eq!(set_of(&emitted), set_of(&chains.public));
    for oid in &chains.private {
        assert!(!emitted.contains(oid));
    }
}

#[test]
fn filtered_closure_drops_an_excluded_root() {
    let store = test_store(HashKind::Sha1);
    let chains = two_chains(&store);
    let filter = PrivateFilter::from_oids(chains.private.iter().copied());
    let kind = HashKind::Sha1;
    let live = [update(
        b"refs/heads/private",
        kind.zero_oid(),
        chains.private_tip,
    )];
    let refs: Vec<&PushUpdate> = live.iter().collect();
    let entries =
        push_closure_filtered(&store, kind, &refs, &filter, &Interrupt::none()).expect("closure");
    assert!(entries.is_empty());
}

#[test]
fn haves_and_wire_lists_hold_no_private_oid() {
    let store = test_store(HashKind::Sha1);
    let chains = two_chains(&store);
    let filter = PrivateFilter::from_oids(chains.private.iter().copied());
    let haves = collect_haves_filtered(
        &store,
        &[chains.public_tip, chains.private_tip],
        100,
        &filter,
        &Interrupt::none(),
    )
    .expect("haves");
    assert_eq!(haves, vec![chains.public_tip]);
    let wire = filter_haves_for_wire(&store, &[chains.public_tip, chains.private_tip], &filter)
        .expect("wire");
    assert_eq!(wire, vec![chains.public_tip]);
}

#[test]
fn promised_tips_leave_haves() {
    let store = test_store(HashKind::Sha1);
    let chains = two_chains(&store);
    store
        .publish(
            Vec::new(),
            &promisor_facts(b"origin", Filter::BlobNone, &[chains.private_tip]).expect("facts"),
        )
        .expect("promise");
    let haves = collect_haves_filtered(
        &store,
        &[chains.public_tip, chains.private_tip],
        100,
        &PrivateFilter::empty(),
        &Interrupt::none(),
    )
    .expect("haves");
    assert_eq!(haves, vec![chains.public_tip]);
}
