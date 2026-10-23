//! `rewrite`: shared descendant-closure helpers for history-rewrite translations.
//!
//! `describe`, `rebase`, `squash`, and `abandon` all re-parent the commits
//! below their rewrite roots. The commit graph lives in the `Commits` table
//! as parent lists with no separate child index, so descendants are found by
//! paging every commit and walking down from the roots. Only live commits
//! count: rewrites never delete the superseded records they replace, and
//! abandoned changes keep theirs, so parent links alone would drag stale
//! generations (and dead changes) into the closure, and restaging one with
//! `predecessor: Some(old)` then fails `E_STALE` in
//! `ChangeEntry::replace_head`. Membership is therefore intersected with the
//! current heads of every `Active` change from the `Changes` table. Nothing
//! here evaluates content: per-commit tree derivation stays with the callers'
//! producers, and an unstored root simply has no children (existence is
//! checked by the translator resolving its targets first).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::error::CoreError;
use crate::heads::Head;
use crate::records::Records;
use crate::records::types::{ChangeState, RecordPageBudget};
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

/// Current heads of every live change: the only commits a rewrite may restage.
///
/// Paging the `Changes` table (not the graph) is what makes the set sound:
/// a superseded commit is absent from its change's heads, and an abandoned
/// change contributes none of its heads, so neither can leak into a closure.
fn live_heads(store: &Store) -> Result<BTreeSet<Head>, CoreError> {
    let records = Records::new(store);
    let budget = RecordPageBudget::new(4096, 1 << 26);
    let mut after = None;
    let mut live = BTreeSet::new();
    loop {
        let page = records.page_changes(after.as_ref(), budget)?;
        for (_, entry) in &page.items {
            if entry.state == ChangeState::Active {
                live.extend(entry.heads.iter().copied());
            }
        }
        after = page.next_cursor;
        if !page.more {
            break;
        }
    }
    Ok(live)
}

/// Direct live children of `head`: current change heads listing it as a
/// parent, in key order. Superseded and abandoned commits still name their
/// parents, so without the liveness cut a stale sibling would read as a
/// child needing rewrite (and break squash's no-sibling check).
pub fn children(store: &Store, head: &Head) -> Result<Vec<Head>, CoreError> {
    let live = live_heads(store)?;
    let mut out = Vec::new();
    for (child, parents) in all_parents(store)? {
        if live.contains(&child) && parents.contains(head) {
            out.push(child);
        }
    }
    out.sort();
    Ok(out)
}

/// Every live commit descended from `roots` (transitively), parent-first.
///
/// Only current heads of `Active` changes are members: superseded generations
/// and abandoned commits are skipped even though their parent links still
/// point into the closure, so a second rewrite in a chain restages live heads
/// instead of failing `E_STALE` on their predecessors. Roots themselves are
/// excluded even when one root descends from another;
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
    let live = live_heads(store)?;
    let mut member: BTreeSet<Head> = BTreeSet::new();
    let mut queue: VecDeque<Head> = roots.iter().copied().collect();
    while let Some(head) = queue.pop_front() {
        let Some(children) = child_map.get(&head) else {
            continue;
        };
        for child in children {
            if live.contains(child) && !root_set.contains(child) && member.insert(*child) {
                queue.push_back(*child);
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
    use crate::store::types::ObjectKind;
    use crate::store::{EventContext, EventSource, PreparationBudget};

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
            self.mint(parents, message, ChangeId::generate(), None)
        }

        fn commit_on(&self, parents: Vec<Head>, message: &str, change: ChangeId) -> Head {
            self.mint(parents, message, change, None)
        }

        /// Restages `old` as a new head of `change`, the way describe/rebase
        /// rewrite one closure member: the old record stays stored, but only
        /// the new head stays a current head of the change.
        fn rewrite(&self, old: Head, parents: Vec<Head>, message: &str, change: ChangeId) -> Head {
            self.mint(parents, message, change, Some(old))
        }

        fn mint(
            &self,
            parents: Vec<Head>,
            message: &str,
            change: ChangeId,
            predecessor: Option<Head>,
        ) -> Head {
            let tree = self
                .store
                .prepare(ObjectKind::Tree, 0, Cursor::new(Vec::new()), None)
                .expect("prepare empty tree");
            let tree_oid = tree.oid();
            self.store
                .publish(
                    vec![tree],
                    &[],
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .ok();
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
                    change_id: Some(change),
                    predecessor,
                    provenance: None,
                },
            )
            .expect("prepare fixture commit");
            let head = prepared.output.head;
            self.store
                .publish(
                    prepared.objects,
                    &prepared.facts,
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("publish fixture commit");
            head
        }

        /// Every closure member must still be a current head of its change:
        /// restaging one with `predecessor: Some(old)` (what describe/rebase
        /// do per member) hits `E_STALE` otherwise.
        fn assert_restageable(&self, closure: &[Head]) {
            let records = Records::new(&self.store);
            for old in closure {
                let record = records
                    .get_commit(old)
                    .expect("read commit")
                    .expect("closure member is stored");
                let entry = records
                    .get_change(&record.change_id())
                    .expect("read change")
                    .expect("closure member has a change");
                assert!(
                    entry.contains_head(old),
                    "stale {old:?} leaked into the rewrite closure"
                );
            }
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
    fn chained_rewrites_close_over_live_heads_only() {
        // A←B←C, then "describe B" rewrites B→B′ and C→C′. The old records
        // stay stored with their parent links, but "describe A" must close
        // over {B′, C′} only: restaging stale B used to fail E_STALE.
        let fixture = Fixture::new("chain");
        let change_b = ChangeId::generate();
        let change_c = ChangeId::generate();
        let a = fixture.commit(Vec::new(), "a");
        let b = fixture.commit_on(vec![a], "b", change_b);
        let c = fixture.commit_on(vec![b], "c", change_c);
        let b2 = fixture.rewrite(b, vec![a], "b2", change_b);
        let c2 = fixture.rewrite(c, vec![b2], "c2", change_c);
        assert_eq!(children(&fixture.store, &a).expect("children"), vec![b2]);
        let closure = descendants(&fixture.store, &[a]).expect("closure");
        assert_eq!(closure, vec![b2, c2]);
        fixture.assert_restageable(&closure);
    }

    #[test]
    fn abandoned_commits_leave_the_closure() {
        let fixture = Fixture::new("abandon");
        let a = fixture.commit(Vec::new(), "a");
        let b = fixture.commit(vec![a], "b");
        crate::ops::abandon(
            &fixture.store,
            crate::ops::AbandonRequest { heads: vec![b] },
        )
        .expect("abandon");
        assert!(children(&fixture.store, &a).expect("children").is_empty());
        assert!(
            descendants(&fixture.store, &[a])
                .expect("closure")
                .is_empty()
        );
    }

    #[test]
    fn stale_siblings_do_not_read_as_children() {
        // D←S (the squash source) plus D←X, where X is rebased onto E. The
        // stale X record still names D, but the squash no-sibling check
        // (`children(D) == [S]`) must not see it.
        let fixture = Fixture::new("siblings");
        let change_x = ChangeId::generate();
        let d = fixture.commit(Vec::new(), "d");
        let s = fixture.commit(vec![d], "s");
        let e = fixture.commit(Vec::new(), "e");
        let x = fixture.commit_on(vec![d], "x", change_x);
        let x2 = fixture.rewrite(x, vec![e], "x2", change_x);
        assert_eq!(children(&fixture.store, &d).expect("children"), vec![s]);
        assert_eq!(children(&fixture.store, &e).expect("moved child"), vec![x2]);
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
