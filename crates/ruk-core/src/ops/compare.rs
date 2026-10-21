//! Bounded merge-base and ahead/behind comparison over a commit graph.
//!
//! The algorithms are generic over graph access so the local CLI (which
//! follows `refs/replace/*` redirects) and the hosted coordinator (which
//! reads its own store) share one implementation: `canonicalize` maps
//! every visited commit to the identity the walk judges (redirects for
//! the CLI, the identity for hosted), `parents` enumerates commit parents,
//! and `committer_time` orders the keyset walk. A shared visit budget
//! bounds every walk; exhausting it reports `exact: false` instead of
//! guessing.
//!
//! Soundness: both sides walk fully, and exclusives are set differences,
//! so completed walks agree exactly with `git rev-list --left-right
//! --count`. Stopping at merge bases instead would over-count: a common
//! commit can sit behind a non-base path that never crosses a base. On
//! truncation a side counts only against a completed peer, so every
//! reported count is a lower bound and the count peer to a truncated
//! side is zero. `exact: false` discloses any truncation.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashSet};

use crate::ids::Oid;

/// Default per-compare commit visit budget, matching the daemon default.
pub const DEFAULT_COMPARE_MAX_COMMITS: usize = 10_000;

/// What one bounded comparison found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompareOutcome {
    /// Minimal merge bases: common ancestors that are not ancestors of
    /// another common commit. Empty when the tips share no history, or
    /// when base discovery exhausted the budget.
    pub bases: Vec<Oid>,
    /// Commits reachable from `head` but not `base`, within the budget.
    pub ahead: u64,
    /// Commits reachable from `base` but not `head`, within the budget.
    pub behind: u64,
    /// False when any walk exhausted the budget. Every reported count is
    /// still a lower bound: the count peer to a truncated side is zero.
    pub exact: bool,
}

/// One visit against the shared budget. False means the walk that just
/// spent its last visit must stop and report inexact.
fn charge(budget: &mut u64) -> bool {
    match budget.checked_sub(1) {
        Some(remaining) => {
            *budget = remaining;
            true
        }
        None => false,
    }
}

/// Finds one common ancestor by paint-down, mirroring the CLI pairwise
/// walk: the left tip paints fully, then the right walk returns its first
/// hit. `None` means no common ancestor, or the budget ran out; pass an
/// inexhaustible budget to distinguish the two exactly.
pub fn merge_base<E>(
    canonicalize: &impl Fn(Oid) -> Oid,
    parents: &impl Fn(Oid) -> Result<Vec<Oid>, E>,
    budget: &mut u64,
    left: Oid,
    right: Oid,
) -> Result<Option<Oid>, E> {
    if left == right {
        return Ok(Some(left));
    }
    let mut left_seen = HashSet::new();
    let mut queue = vec![left];
    while let Some(oid) = queue.pop() {
        let oid = canonicalize(oid);
        if !left_seen.insert(oid) {
            continue;
        }
        if !charge(budget) {
            return Ok(None);
        }
        queue.extend(parents(oid)?);
    }
    let mut right_seen = HashSet::new();
    let mut queue = vec![right];
    while let Some(oid) = queue.pop() {
        let oid = canonicalize(oid);
        if left_seen.contains(&oid) {
            return Ok(Some(oid));
        }
        if !right_seen.insert(oid) {
            continue;
        }
        if !charge(budget) {
            return Ok(None);
        }
        queue.extend(parents(oid)?);
    }
    Ok(None)
}

/// Date-ordered walk queue: committer-timestamp heap with insertion order
/// breaking ties, so a child always precedes its parents while unrelated
/// branches interleave strictly by date. Mirrors the CLI walk order, so
/// moved callers observe identical output.
struct OrderedWalk {
    heap: BinaryHeap<OrderedEntry>,
    seq: u64,
}

struct OrderedEntry {
    stamp: i64,
    seq: u64,
    oid: Oid,
}

impl PartialEq for OrderedEntry {
    fn eq(&self, other: &Self) -> bool {
        self.stamp == other.stamp && self.seq == other.seq && self.oid == other.oid
    }
}

impl Eq for OrderedEntry {}

impl PartialOrd for OrderedEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderedEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.stamp
            .cmp(&other.stamp)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

impl OrderedWalk {
    fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            seq: 0,
        }
    }

    fn enqueue<E>(
        &mut self,
        canonicalize: &impl Fn(Oid) -> Oid,
        seen: &mut HashSet<Oid>,
        committer_time: &impl Fn(Oid) -> Result<i64, E>,
        oid: Oid,
    ) -> Result<(), E> {
        let oid = canonicalize(oid);
        if !seen.insert(oid) {
            return Ok(());
        }
        let stamp = committer_time(oid)?;
        self.heap.push(OrderedEntry {
            stamp,
            seq: self.seq,
            oid,
        });
        self.seq += 1;
        Ok(())
    }

    fn pop(&mut self) -> Option<Oid> {
        self.heap.pop().map(|entry| entry.oid)
    }
}

/// Walks every commit reachable from `tips` in CLI log order, returning
/// discovery order, the visited set, and whether the walk completed
/// inside the budget.
fn walk_ordered<E>(
    canonicalize: &impl Fn(Oid) -> Oid,
    parents: &impl Fn(Oid) -> Result<Vec<Oid>, E>,
    committer_time: &impl Fn(Oid) -> Result<i64, E>,
    budget: &mut u64,
    tips: &[Oid],
) -> Result<(Vec<Oid>, HashSet<Oid>, bool), E> {
    let mut seen = HashSet::new();
    let mut walk = OrderedWalk::new();
    for tip in tips {
        walk.enqueue(canonicalize, &mut seen, committer_time, *tip)?;
    }
    let mut order = Vec::new();
    while let Some(oid) = walk.pop() {
        if !charge(budget) {
            return Ok((order, seen, false));
        }
        order.push(oid);
        for parent in parents(oid)? {
            walk.enqueue(canonicalize, &mut seen, committer_time, parent)?;
        }
    }
    Ok((order, seen, true))
}

/// True when `ancestor` reaches `descendant` through parent links, mirroring
/// the CLI ancestry check. The second return reports whether the search
/// completed inside the budget.
fn ancestor_within<E>(
    canonicalize: &impl Fn(Oid) -> Oid,
    parents: &impl Fn(Oid) -> Result<Vec<Oid>, E>,
    budget: &mut u64,
    ancestor: Oid,
    descendant: Oid,
) -> Result<(bool, bool), E> {
    if ancestor == descendant {
        return Ok((true, true));
    }
    let mut seen = HashSet::new();
    let mut queue = vec![descendant];
    while let Some(oid) = queue.pop() {
        let oid = canonicalize(oid);
        if oid == ancestor {
            return Ok((true, true));
        }
        if !seen.insert(oid) {
            continue;
        }
        if !charge(budget) {
            return Ok((false, false));
        }
        queue.extend(parents(oid)?);
    }
    Ok((false, true))
}

/// Drops duplicate and ancestor-dominated candidates, keeping the minimal
/// base set in discovery order. The second return reports whether every
/// ancestry check completed inside the budget.
fn minimize_within<E>(
    canonicalize: &impl Fn(Oid) -> Oid,
    parents: &impl Fn(Oid) -> Result<Vec<Oid>, E>,
    budget: &mut u64,
    candidates: Vec<Oid>,
) -> Result<(Vec<Oid>, bool), E> {
    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    for oid in candidates {
        if seen.insert(oid) {
            unique.push(oid);
        }
    }
    let mut bases = Vec::new();
    for cand in &unique {
        let mut dominated = false;
        for other in &unique {
            if cand == other {
                continue;
            }
            let (is_ancestor, complete) =
                ancestor_within(canonicalize, parents, budget, *cand, *other)?;
            if !complete {
                return Ok((Vec::new(), false));
            }
            if is_ancestor {
                dominated = true;
                break;
            }
        }
        if !dominated {
            bases.push(*cand);
        }
    }
    Ok((bases, true))
}

/// Finds every merge base of two tips: common ancestors that are not
/// themselves ancestors of another common ancestor. A criss-cross merge
/// returns all bases. Pass an inexhaustible budget for exact results;
/// a truncated budget yields a prefix of the work, not a base set.
pub fn merge_bases_all<E>(
    canonicalize: &impl Fn(Oid) -> Oid,
    parents: &impl Fn(Oid) -> Result<Vec<Oid>, E>,
    committer_time: &impl Fn(Oid) -> Result<i64, E>,
    budget: &mut u64,
    left: Oid,
    right: Oid,
) -> Result<Vec<Oid>, E> {
    if left == right {
        return Ok(vec![left]);
    }
    let (left_order, left_set, _) =
        walk_ordered(canonicalize, parents, committer_time, budget, &[left])?;
    let (right_order, _, _) =
        walk_ordered(canonicalize, parents, committer_time, budget, &[right])?;
    let mut common = Vec::new();
    for oid in right_order {
        if left_set.contains(&oid) {
            common.push(oid);
        }
    }
    let _ = left_order;
    let (bases, _) = minimize_within(canonicalize, parents, budget, common)?;
    Ok(bases)
}

/// Drops duplicate and ancestor-dominated candidates, keeping the minimal
/// base set in discovery order. Pass an inexhaustible budget for exact
/// results; a truncated budget yields a prefix of the work.
pub fn minimize_bases<E>(
    canonicalize: &impl Fn(Oid) -> Oid,
    parents: &impl Fn(Oid) -> Result<Vec<Oid>, E>,
    budget: &mut u64,
    candidates: Vec<Oid>,
) -> Result<Vec<Oid>, E> {
    let (bases, _) = minimize_within(canonicalize, parents, budget, candidates)?;
    Ok(bases)
}

/// Discovers the minimal merge bases of two tips, reporting whether the
/// discovery completed inside the budget. An incomplete discovery is
/// unsound as a counting boundary, so the caller must not count against
/// it.
fn discover_bases<E>(
    canonicalize: &impl Fn(Oid) -> Oid,
    parents: &impl Fn(Oid) -> Result<Vec<Oid>, E>,
    committer_time: &impl Fn(Oid) -> Result<i64, E>,
    budget: &mut u64,
    left: Oid,
    right: Oid,
) -> Result<(Vec<Oid>, bool), E> {
    if left == right {
        return Ok((vec![left], true));
    }
    let (_, left_set, left_complete) =
        walk_ordered(canonicalize, parents, committer_time, budget, &[left])?;
    if !left_complete {
        return Ok((Vec::new(), false));
    }
    let (right_order, _, right_complete) =
        walk_ordered(canonicalize, parents, committer_time, budget, &[right])?;
    if !right_complete {
        return Ok((Vec::new(), false));
    }
    let mut common = Vec::new();
    for oid in right_order {
        if left_set.contains(&oid) {
            common.push(oid);
        }
    }
    minimize_within(canonicalize, parents, budget, common)
}

/// Walks every commit reachable from `tip` in keyset order (committer
/// time descending, oid ascending), returning the visited set and whether
/// the walk completed inside the budget.
fn walk_side<E>(
    canonicalize: &impl Fn(Oid) -> Oid,
    parents: &impl Fn(Oid) -> Result<Vec<Oid>, E>,
    committer_time: &impl Fn(Oid) -> Result<i64, E>,
    budget: &mut u64,
    tip: Oid,
) -> Result<(HashSet<Oid>, bool), E> {
    let mut heap: BinaryHeap<(i64, Reverse<Oid>)> = BinaryHeap::new();
    let mut seen = HashSet::new();
    let tip = canonicalize(tip);
    seen.insert(tip);
    heap.push((committer_time(tip)?, Reverse(tip)));
    while let Some((_, Reverse(oid))) = heap.pop() {
        let oid = canonicalize(oid);
        if !charge(budget) {
            return Ok((seen, false));
        }
        for parent in parents(oid)? {
            let parent = canonicalize(parent);
            if seen.insert(parent) {
                heap.push((committer_time(parent)?, Reverse(parent)));
            }
        }
    }
    Ok((seen, true))
}

/// Compares `base` and `head`: minimal merge bases plus bounded
/// ahead/behind counts. The oracle is `git rev-list --left-right --count`:
/// with a budget the walks complete, `exact` holds, and the counts agree
/// exactly. On exhaustion the reported bases are empty and each count is
/// a lower bound: the count peer to a truncated side is zero.
pub fn compare<E>(
    canonicalize: &impl Fn(Oid) -> Oid,
    parents: &impl Fn(Oid) -> Result<Vec<Oid>, E>,
    committer_time: &impl Fn(Oid) -> Result<i64, E>,
    mut budget: u64,
    base: Oid,
    head: Oid,
) -> Result<CompareOutcome, E> {
    let budget = &mut budget;
    let (bases, complete) =
        discover_bases(canonicalize, parents, committer_time, budget, base, head)?;
    if !complete {
        return Ok(CompareOutcome {
            bases: Vec::new(),
            ahead: 0,
            behind: 0,
            exact: false,
        });
    }
    let (head_set, head_complete) = walk_side(canonicalize, parents, committer_time, budget, head)?;
    let (base_set, base_complete) = walk_side(canonicalize, parents, committer_time, budget, base)?;
    // A side counts only against a completed peer: with the peer fully
    // explored every observed exclusive is proven, so the count is a lower
    // bound. Peer to a truncated side the count is zero, never a guess.
    let ahead = if base_complete {
        u64::try_from(head_set.difference(&base_set).count()).unwrap_or(u64::MAX)
    } else {
        0
    };
    let behind = if head_complete {
        u64::try_from(base_set.difference(&head_set).count()).unwrap_or(u64::MAX)
    } else {
        0
    };
    Ok(CompareOutcome {
        bases,
        ahead,
        behind,
        exact: head_complete && base_complete,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Parents of one commit from a record map fixture.
    fn map_parents(graph: &HashMap<Oid, (Vec<Oid>, i64)>, oid: Oid) -> Result<Vec<Oid>, String> {
        graph
            .get(&oid)
            .map(|(parents, _)| parents.clone())
            .ok_or_else(|| format!("unknown commit {oid}"))
    }

    /// Committer time of one commit from a record map fixture.
    fn map_time(graph: &HashMap<Oid, (Vec<Oid>, i64)>, oid: Oid) -> Result<i64, String> {
        graph
            .get(&oid)
            .map(|(_, time)| *time)
            .ok_or_else(|| format!("unknown commit {oid}"))
    }

    fn identity(oid: Oid) -> Oid {
        oid
    }

    /// Builds a fixture graph from `(id, time, parents)` rows.
    fn fixture(rows: &[(u8, i64, &[u8])]) -> HashMap<Oid, (Vec<Oid>, i64)> {
        let oid = |n: u8| Oid::from_bytes(&[n; 20]).expect("fixture oid");
        rows.iter()
            .map(|(id, time, parents)| {
                (oid(*id), (parents.iter().map(|p| oid(*p)).collect(), *time))
            })
            .collect()
    }

    #[expect(
        clippy::type_complexity,
        reason = "test-only closure pair; the production API takes plain impl Fn params"
    )]
    fn closures<'a>(
        graph: &'a HashMap<Oid, (Vec<Oid>, i64)>,
    ) -> (
        impl Fn(Oid) -> Result<Vec<Oid>, String> + 'a,
        impl Fn(Oid) -> Result<i64, String> + 'a,
    ) {
        (
            move |oid| map_parents(graph, oid),
            move |oid| map_time(graph, oid),
        )
    }

    #[test]
    fn linear_history_counts_ahead_and_behind_exactly() {
        // 1 <- 2 <- 3; base 1, head 3.
        let graph = fixture(&[(1, 100, &[]), (2, 200, &[1]), (3, 300, &[2])]);
        let (parents, time) = closures(&graph);
        let oid = |n: u8| Oid::from_bytes(&[n; 20]).expect("fixture oid");
        let outcome =
            compare(&identity, &parents, &time, u64::MAX, oid(1), oid(3)).expect("compare");
        assert_eq!(outcome.bases, vec![oid(1)]);
        assert_eq!((outcome.ahead, outcome.behind), (2, 0));
        assert!(outcome.exact);
        let outcome =
            compare(&identity, &parents, &time, u64::MAX, oid(3), oid(1)).expect("compare");
        assert_eq!(outcome.bases, vec![oid(1)]);
        assert_eq!((outcome.ahead, outcome.behind), (0, 2));
        assert!(outcome.exact);
        let outcome =
            compare(&identity, &parents, &time, u64::MAX, oid(2), oid(2)).expect("compare");
        assert_eq!(outcome.bases, vec![oid(2)]);
        assert_eq!((outcome.ahead, outcome.behind), (0, 0));
        assert!(outcome.exact);
    }

    #[test]
    fn criss_cross_returns_all_bases() {
        // X <- M1, X <- M2 and Y <- M1, Y <- M2: bases of (M1, M2) are X, Y.
        let graph = fixture(&[
            (1, 100, &[]),
            (2, 150, &[]),
            (3, 200, &[1, 2]),
            (4, 250, &[1, 2]),
        ]);
        let (parents, time) = closures(&graph);
        let oid = |n: u8| Oid::from_bytes(&[n; 20]).expect("fixture oid");
        let outcome =
            compare(&identity, &parents, &time, u64::MAX, oid(3), oid(4)).expect("compare");
        assert_eq!(outcome.bases.len(), 2);
        assert!(outcome.bases.contains(&oid(1)));
        assert!(outcome.bases.contains(&oid(2)));
        assert_eq!((outcome.ahead, outcome.behind), (1, 1));
        assert!(outcome.exact);
    }

    #[test]
    fn ancestor_shaped_common_commits_do_not_inflate_ahead() {
        // H parents [P, B]; P -> Y; B -> Y. Y is common but dominated by B,
        // and reachable from H without crossing B, so a boundary-stop walk
        // would count it. Oracle ahead is {H, P} = 2: Y must not count.
        let graph = fixture(&[
            (1, 100, &[]),
            (2, 200, &[1]),
            (3, 250, &[1]),
            (4, 300, &[3, 2]),
        ]);
        let (parents, time) = closures(&graph);
        let oid = |n: u8| Oid::from_bytes(&[n; 20]).expect("fixture oid");
        let outcome =
            compare(&identity, &parents, &time, u64::MAX, oid(2), oid(4)).expect("compare");
        assert_eq!(outcome.bases, vec![oid(2)]);
        assert_eq!((outcome.ahead, outcome.behind), (2, 0));
        assert!(outcome.exact);
    }

    #[test]
    fn disjoint_histories_have_no_bases() {
        let graph = fixture(&[(1, 100, &[]), (2, 200, &[])]);
        let (parents, time) = closures(&graph);
        let oid = |n: u8| Oid::from_bytes(&[n; 20]).expect("fixture oid");
        let outcome =
            compare(&identity, &parents, &time, u64::MAX, oid(1), oid(2)).expect("compare");
        assert!(outcome.bases.is_empty());
        assert_eq!((outcome.ahead, outcome.behind), (1, 1));
        assert!(outcome.exact);
    }

    #[test]
    fn exhausted_discovery_reports_unknown() {
        // Linear 1..=6; base 1, head 6; budget 3 cannot finish discovery.
        let graph = fixture(&[
            (1, 100, &[]),
            (2, 200, &[1]),
            (3, 300, &[2]),
            (4, 400, &[3]),
            (5, 500, &[4]),
            (6, 600, &[5]),
        ]);
        let (parents, time) = closures(&graph);
        let oid = |n: u8| Oid::from_bytes(&[n; 20]).expect("fixture oid");
        let outcome = compare(&identity, &parents, &time, 3, oid(1), oid(6)).expect("compare");
        assert!(!outcome.exact);
        assert!(
            outcome.bases.is_empty(),
            "unsound bases are withheld, not guessed"
        );
        assert_eq!((outcome.ahead, outcome.behind), (0, 0));
    }

    #[test]
    fn truncated_peer_still_reports_a_lower_bound() {
        // Base side runs 1..=11, head side runs 1,12,13. True counts are
        // ahead 2, behind 10. The budget finishes discovery and the head
        // walk but truncates the base walk after four visits.
        let graph = fixture(&[
            (1, 100, &[]),
            (2, 200, &[1]),
            (3, 300, &[2]),
            (4, 400, &[3]),
            (5, 500, &[4]),
            (6, 600, &[5]),
            (7, 700, &[6]),
            (8, 800, &[7]),
            (9, 900, &[8]),
            (10, 1000, &[9]),
            (11, 1100, &[10]),
            (12, 1200, &[1]),
            (13, 1300, &[12]),
        ]);
        let (parents, time) = closures(&graph);
        let oid = |n: u8| Oid::from_bytes(&[n; 20]).expect("fixture oid");
        let outcome = compare(&identity, &parents, &time, 20, oid(11), oid(13)).expect("compare");
        assert!(!outcome.exact);
        assert_eq!(outcome.bases, vec![oid(1)]);
        assert_eq!(
            outcome.behind, 4,
            "four observed base exclusives under a true count of 10: the \
             frontier commit counts as observed once discovered"
        );
        assert_eq!(
            outcome.ahead, 0,
            "ahead zeroes against a truncated peer, never guesses"
        );
    }

    #[test]
    fn merge_base_returns_none_without_common_history() {
        let graph = fixture(&[(1, 100, &[]), (2, 200, &[])]);
        let (parents, _) = closures(&graph);
        let oid = |n: u8| Oid::from_bytes(&[n; 20]).expect("fixture oid");
        let mut budget = u64::MAX;
        assert_eq!(
            merge_base(&identity, &parents, &mut budget, oid(1), oid(2)).expect("merge base"),
            None
        );
    }

    #[test]
    fn keyset_walks_agree_across_runs() {
        // Siblings with equal timestamps: oid order decides, deterministically.
        let graph = fixture(&[
            (1, 100, &[]),
            (2, 200, &[1]),
            (3, 200, &[1]),
            (4, 300, &[2, 3]),
        ]);
        let (parents, time) = closures(&graph);
        let oid = |n: u8| Oid::from_bytes(&[n; 20]).expect("fixture oid");
        let first = compare(&identity, &parents, &time, u64::MAX, oid(1), oid(4)).expect("compare");
        let second =
            compare(&identity, &parents, &time, u64::MAX, oid(1), oid(4)).expect("compare");
        assert_eq!(first, second, "repeated walks agree exactly");
        assert_eq!((first.ahead, first.behind), (3, 0));
        assert!(first.exact);
    }
}
