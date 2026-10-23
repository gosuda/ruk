//! Generation-aware graph traversal, reachability walks, and shallow ancestry.
//!
//! # Generation pruning
//!
//! Invariant: $G(c) = 1 + \max_{p \in parents(c)} G(p)$, with $G(root) = 1$.
//! A commit $A$ can only be an ancestor of $D$ if $G(A) < G(D)$ (or $A == D$).
//! If $G(A) \ge G(D)$ and $A \ne D$, reachability is proven `ProvenNo`
//! immediately in $O(1)$ without examining any graph edges.
//!
//! # Shallow tri-state
//!
//! - If $A$ is reached: [`ShallowAncestry::ProvenYes`].
//! - If all search paths terminate cleanly without hitting a shallow boundary: [`ShallowAncestry::ProvenNo`].
//! - If search was cut off by one or more shallow boundaries without proving reachability:
//!   [`ShallowAncestry::Indeterminate`].
//!
//! # Bounded step and cancellation APIs
//!
//! Traversals execute within caller-supplied step limits and check a cancellation
//! predicate regularly. Intermediate pages use bounded [`SmallVec`] buffers.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};

use smallvec::SmallVec;

use crate::error::{CoreError, ErrorCode};
use crate::graph::types::{Generation, GlobalPosition, ShallowAncestry};
use crate::heads::Head;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HeapNode {
    generation: Generation,
    position: GlobalPosition,
}

impl Ord for HeapNode {
    fn cmp(&self, other: &Self) -> Ordering {
        self.generation.cmp(&other.generation)
    }
}

impl PartialOrd for HeapNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Bounded page result from an ancestor traversal step.
#[expect(dead_code, reason = "never used; goes live when revset is wired")]
#[derive(Clone, Debug)]
pub(crate) struct TraversalPage {
    pub(crate) positions: SmallVec<[GlobalPosition; 64]>,
    pub(crate) has_more: bool,
    pub(crate) hit_shallow: bool,
}

/// Abstract graph access required by traversal algorithms.
pub(crate) trait GraphAccess {
    fn get_generation(&self, pos: GlobalPosition) -> Result<Generation, CoreError>;
    fn get_parents(&self, pos: GlobalPosition) -> Result<SmallVec<[GlobalPosition; 2]>, CoreError>;
    fn get_head(&self, pos: GlobalPosition) -> Result<Head, CoreError>;
}

/// Resumable bounded ancestor traversal stepper.
pub(crate) struct AncestorStepper {
    heap: BinaryHeap<HeapNode>,
    visited: HashSet<GlobalPosition>,
    shallow_heads: Option<HashSet<Head>>,
    hit_shallow: bool,
    steps_taken: usize,
}

#[expect(dead_code, reason = "never used; goes live when revset is wired")]
impl AncestorStepper {
    pub(crate) fn new(
        graph: &dyn GraphAccess,
        roots: &[GlobalPosition],
        shallow: Option<&[Head]>,
    ) -> Result<Self, CoreError> {
        let mut heap = BinaryHeap::new();
        let mut visited = HashSet::new();

        for &pos in roots {
            if visited.insert(pos) {
                let generation = graph.get_generation(pos)?;
                heap.push(HeapNode {
                    generation,
                    position: pos,
                });
            }
        }

        let shallow_heads = shallow.map(|s| s.iter().copied().collect());

        Ok(Self {
            heap,
            visited,
            shallow_heads,
            hit_shallow: false,
            steps_taken: 0,
        })
    }

    pub(crate) fn step_batch(
        &mut self,
        graph: &dyn GraphAccess,
        max_results: usize,
        cancel: &dyn Fn() -> bool,
        max_steps: usize,
    ) -> Result<TraversalPage, CoreError> {
        let mut positions = SmallVec::new();
        let page_bound = max_results.min(1000);

        while let Some(node) = self.heap.pop() {
            if cancel() {
                return Err(CoreError::new(ErrorCode::ECancelled, "traversal cancelled"));
            }

            self.steps_taken += 1;
            if self.steps_taken > max_steps {
                return Err(CoreError::new(
                    ErrorCode::ELimit,
                    format!("traversal exceeded maximum step limit {max_steps}"),
                ));
            }

            if let Some(shallow_set) = &self.shallow_heads {
                let head = graph.get_head(node.position)?;
                if shallow_set.contains(&head) {
                    self.hit_shallow = true;
                    positions.push(node.position);
                    if positions.len() >= page_bound {
                        break;
                    }
                    continue;
                }
            }

            positions.push(node.position);

            let parents = graph.get_parents(node.position)?;
            for parent_pos in parents {
                if self.visited.insert(parent_pos) {
                    let generation = graph.get_generation(parent_pos)?;
                    self.heap.push(HeapNode {
                        generation,
                        position: parent_pos,
                    });
                }
            }

            if positions.len() >= page_bound {
                break;
            }
        }

        let has_more = !self.heap.is_empty();
        Ok(TraversalPage {
            positions,
            has_more,
            hit_shallow: self.hit_shallow,
        })
    }

    #[must_use]
    pub(crate) const fn steps_taken(&self) -> usize {
        self.steps_taken
    }

    #[must_use]
    pub(crate) const fn hit_shallow(&self) -> bool {
        self.hit_shallow
    }
}

pub(crate) fn is_ancestor(
    graph: &dyn GraphAccess,
    ancestor: GlobalPosition,
    descendant: GlobalPosition,
    shallow: Option<&[Head]>,
    cancel: &dyn Fn() -> bool,
    max_steps: usize,
) -> Result<ShallowAncestry, CoreError> {
    if ancestor == descendant {
        return Ok(ShallowAncestry::ProvenYes);
    }

    let gen_ancestor = graph.get_generation(ancestor)?;
    let gen_descendant = graph.get_generation(descendant)?;

    if gen_ancestor >= gen_descendant {
        return Ok(ShallowAncestry::ProvenNo);
    }

    let mut heap = BinaryHeap::new();
    let mut visited = HashSet::new();
    let shallow_set: Option<HashSet<Head>> = shallow.map(|s| s.iter().copied().collect());

    visited.insert(descendant);
    heap.push(HeapNode {
        generation: gen_descendant,
        position: descendant,
    });

    let mut hit_shallow = false;
    let mut steps = 0usize;

    while let Some(node) = heap.pop() {
        if cancel() {
            return Err(CoreError::new(
                ErrorCode::ECancelled,
                "reachability walk cancelled",
            ));
        }

        steps += 1;
        if steps > max_steps {
            return Err(CoreError::new(
                ErrorCode::ELimit,
                format!("reachability walk exceeded maximum step limit {max_steps}"),
            ));
        }

        if node.position == ancestor {
            return Ok(ShallowAncestry::ProvenYes);
        }

        if node.generation < gen_ancestor {
            break;
        }

        if let Some(s_set) = &shallow_set {
            let head = graph.get_head(node.position)?;
            if s_set.contains(&head) {
                hit_shallow = true;
                continue;
            }
        }

        let parents = graph.get_parents(node.position)?;
        for p in parents {
            if !visited.insert(p) {
                continue;
            }

            let p_gen = graph.get_generation(p)?;
            if p_gen >= gen_ancestor {
                heap.push(HeapNode {
                    generation: p_gen,
                    position: p,
                });
            }
        }
    }

    if hit_shallow {
        Ok(ShallowAncestry::Indeterminate)
    } else {
        Ok(ShallowAncestry::ProvenNo)
    }
}

pub(crate) fn find_heads(
    graph: &dyn GraphAccess,
    candidates: &[GlobalPosition],
    cancel: &dyn Fn() -> bool,
    max_steps_per_pair: usize,
) -> Result<SmallVec<[GlobalPosition; 4]>, CoreError> {
    if candidates.is_empty() {
        return Ok(SmallVec::new());
    }
    if candidates.len() == 1 {
        let mut v = SmallVec::new();
        v.push(candidates[0]);
        return Ok(v);
    }

    let mut is_ancestor_flags = vec![false; candidates.len()];

    for (i, &cand_i) in candidates.iter().enumerate() {
        if is_ancestor_flags[i] {
            continue;
        }
        for (j, &cand_j) in candidates.iter().enumerate() {
            if i == j || is_ancestor_flags[i] {
                continue;
            }
            let res = is_ancestor(graph, cand_i, cand_j, None, cancel, max_steps_per_pair)?;
            if res == ShallowAncestry::ProvenYes {
                is_ancestor_flags[i] = true;
            }
        }
    }

    let mut result = SmallVec::new();
    for (i, &cand) in candidates.iter().enumerate() {
        if !is_ancestor_flags[i] {
            result.push(cand);
        }
    }
    Ok(result)
}

pub(crate) fn find_roots(
    graph: &dyn GraphAccess,
    candidates: &[GlobalPosition],
    cancel: &dyn Fn() -> bool,
    max_steps_per_pair: usize,
) -> Result<SmallVec<[GlobalPosition; 4]>, CoreError> {
    if candidates.is_empty() {
        return Ok(SmallVec::new());
    }
    if candidates.len() == 1 {
        let mut v = SmallVec::new();
        v.push(candidates[0]);
        return Ok(v);
    }

    let mut has_ancestor_flags = vec![false; candidates.len()];

    for (i, &cand_i) in candidates.iter().enumerate() {
        for (j, &cand_j) in candidates.iter().enumerate() {
            if i == j || has_ancestor_flags[i] {
                continue;
            }
            let res = is_ancestor(graph, cand_j, cand_i, None, cancel, max_steps_per_pair)?;
            if res == ShallowAncestry::ProvenYes {
                has_ancestor_flags[i] = true;
            }
        }
    }

    let mut result = SmallVec::new();
    for (i, &cand) in candidates.iter().enumerate() {
        if !has_ancestor_flags[i] {
            result.push(cand);
        }
    }
    Ok(result)
}
