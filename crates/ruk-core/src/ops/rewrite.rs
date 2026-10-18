//! `rewrite`: shared descendant-closure helpers for history-rewrite translations.
//!
//! `describe`, `rebase`, `squash`, and `abandon` all re-parent the commits
//! below their rewrite roots. The commit graph lives in the `Commits` table
//! as parent lists with no separate child index, so descendants are found by
//! paging every commit and walking down from the roots. Nothing here evaluates
//! content: per-commit tree derivation stays with the callers' producers, and
//! an unstored root simply has no children (existence is checked by the
//! translator resolving its targets first).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::error::CoreError;
use crate::heads::Head;
use crate::records::Records;
use crate::records::types::RecordPageBudget;
use crate::store::Store;

/// Pages every stored commit with its parent list.
fn all_parents(store: &Store) -> Result<Vec<(Head, Vec<Head>)>, CoreError> {
    let records = Records::new(store);
    let budget = RecordPageBudget::new(4096, 1 << 26);
    let mut after = None;
    let mut out = Vec::new();
    loop {
        let page = records.page_commits(after.as_ref(), budget)?;
        for (head, record) in &page.items {
            out.push((*head, record.parents().to_vec()));
        }
        after = page.next_cursor;
        if !page.more {
            break;
        }
    }
    Ok(out)
}

/// Direct children of `head`: stored commits listing it as a parent, in key order.
pub fn children(store: &Store, head: &Head) -> Result<Vec<Head>, CoreError> {
    let mut out = Vec::new();
    for (child, parents) in all_parents(store)? {
        if parents.contains(head) {
            out.push(child);
        }
    }
    out.sort();
    Ok(out)
}

/// Every commit descended from `roots` (transitively), parent-first.
///
/// Roots themselves are excluded even when one root descends from another;
/// callers resolving several roots check that overlap separately. A rewritten
/// parent always precedes its children: emission is topological over the
/// closure (Kahn's algorithm, smallest head first), so a merge child follows
/// every rewritten parent, not just the one that discovered it. Breadth-first
/// discovery alone cannot promise that: with edges `a→b, a→c, b→d, c→e, e→d`
/// it emits `d` before `e`, and staging `d` then would keep the superseded
/// `e` as a parent.
pub fn descendants(store: &Store, roots: &[Head]) -> Result<Vec<Head>, CoreError> {
    let all = all_parents(store)?;
    let mut child_map: BTreeMap<Head, Vec<Head>> = BTreeMap::new();
    let mut parent_map: BTreeMap<Head, Vec<Head>> = BTreeMap::new();
    for (child, parents) in &all {
        for parent in parents {
            child_map.entry(*parent).or_default().push(*child);
        }
        parent_map.insert(*child, parents.clone());
    }
    let root_set: BTreeSet<Head> = roots.iter().copied().collect();
    let mut member: BTreeSet<Head> = BTreeSet::new();
    let mut queue: VecDeque<Head> = roots.iter().copied().collect();
    while let Some(head) = queue.pop_front() {
        if let Some(children) = child_map.get(&head) {
            for child in children {
                if !root_set.contains(child) && member.insert(*child) {
                    queue.push_back(*child);
                }
            }
        }
    }
    let mut pending: BTreeMap<Head, usize> = BTreeMap::new();
    for member_head in &member {
        let unmoved_parents = parent_map
            .get(member_head)
            .map(|parents| {
                parents
                    .iter()
                    .filter(|parent| member.contains(parent))
                    .count()
            })
            .unwrap_or(0);
        pending.insert(*member_head, unmoved_parents);
    }
    let mut ready: BTreeSet<Head> = pending
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(head, _)| *head)
        .collect();
    let mut out = Vec::new();
    while let Some(head) = ready.iter().next().copied() {
        ready.remove(&head);
        out.push(head);
        if let Some(children) = child_map.get(&head) {
            for child in children {
                if let Some(count) = pending.get_mut(child) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        ready.insert(*child);
                    }
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use super::*;
    use crate::bytes::ByteString;
    use crate::change::ChangeId;
    use crate::conflict::{Signature, TzOffset};
    use crate::ids::HashKind;
    use crate::ops::{NewRequest, prepare_new};
    use crate::store::PreparationBudget;
    use crate::store::types::ObjectKind;

    struct Fixture {
        root: std::path::PathBuf,
        store: Store,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "ruk-rewrite-test-{}-{}",
                std::process::id(),
                tag
            ));
            let _ = std::fs::remove_dir_all(&root);
            let store = Store::create(
                &root,
                HashKind::Sha1,
                Arc::new(PreparationBudget::reference_defaults()),
            )
            .expect("create test store");
            Self { root, store }
        }

        fn commit(&self, parents: Vec<Head>, message: &str) -> Head {
            let tree = self
                .store
                .prepare(ObjectKind::Tree, 0, Cursor::new(Vec::new()), None)
                .expect("prepare empty tree");
            let tree_oid = tree.oid();
            self.store.publish(vec![tree], &[]).ok();
            let signature = Signature {
                name: ByteString::from("Test"),
                email: ByteString::from("test@example.invalid"),
                timestamp: 1_700_000_000,
                offset: TzOffset::UTC,
            };
            let prepared = prepare_new(
                &self.store,
                NewRequest {
                    tree: tree_oid,
                    parents,
                    author: signature.clone(),
                    committer: signature,
                    message: ByteString::from(message),
                    change_id: Some(ChangeId::generate()),
                    predecessor: None,
                    provenance: None,
                },
            )
            .expect("prepare fixture commit");
            let head = prepared.output.head;
            self.store
                .publish(prepared.objects, &prepared.facts)
                .expect("publish fixture commit");
            head
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn linear_chain_reports_parent_first() {
        let fixture = Fixture::new("linear");
        let a = fixture.commit(Vec::new(), "a");
        let b = fixture.commit(vec![a], "b");
        let c = fixture.commit(vec![b], "c");
        assert_eq!(
            descendants(&fixture.store, &[a]).expect("closure"),
            vec![b, c]
        );
        assert_eq!(descendants(&fixture.store, &[b]).expect("closure"), vec![c]);
        assert!(
            descendants(&fixture.store, &[c])
                .expect("closure")
                .is_empty()
        );
    }

    #[test]
    fn diamond_reports_each_descendant_once() {
        let fixture = Fixture::new("diamond");
        let a = fixture.commit(Vec::new(), "a");
        let b = fixture.commit(vec![a], "b");
        let c = fixture.commit(vec![a], "c");
        let d = fixture.commit(vec![b, c], "d");
        let closure = descendants(&fixture.store, &[a]).expect("closure");
        assert_eq!(closure.len(), 3);
        assert!(closure.contains(&b) && closure.contains(&c) && closure.contains(&d));
        assert_eq!(*closure.last().expect("merge child last"), d);
    }

    #[test]
    fn merge_child_follows_every_rewritten_parent() {
        let fixture = Fixture::new("topo");
        let a = fixture.commit(Vec::new(), "a");
        let b = fixture.commit(vec![a], "b");
        let c = fixture.commit(vec![a], "c");
        let e = fixture.commit(vec![c], "e");
        let d = fixture.commit(vec![b, e], "d");
        let closure = descendants(&fixture.store, &[a]).expect("closure");
        let position = |head: Head| closure.iter().position(|h| *h == head).expect("member");
        assert!(position(b) < position(d));
        assert!(position(c) < position(e));
        assert!(position(e) < position(d));
    }

    #[test]
    fn roots_are_excluded_even_when_nested() {
        let fixture = Fixture::new("roots");
        let a = fixture.commit(Vec::new(), "a");
        let b = fixture.commit(vec![a], "b");
        // Every root is excluded from the closure, including a root that
        // descends from another root; callers check that overlap separately.
        assert!(
            descendants(&fixture.store, &[a, b])
                .expect("closure")
                .is_empty()
        );
        // Per-root closures still report the nesting for the overlap check.
        assert_eq!(descendants(&fixture.store, &[a]).expect("closure"), vec![b]);
    }
}
