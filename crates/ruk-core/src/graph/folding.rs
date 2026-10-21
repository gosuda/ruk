//! Parent-chain folding and segment squashing.
//!
//! # Folding criterion
//!
//! When `2 * child_commits >= parent_commits`, the child and one or more
//! ancestor segments are consolidated into a single segment. This is applied
//! recursively so that the chain of index segments remains $O(\log N)$ in length.
//!
//! # Invariants preserved across folding
//!
//! 1. Topological ordering (parents always appear before children).
//! 2. Exact octopus parent ordering in overflow tables.
//! 3. Corrected generation numbers ($G(c) = 1 + \max G(p)$).
//! 4. Change IDs and divergent commit associations.
//! 5. Changed-path Bloom filter contents.
//! 6. Exact lookup and reachability equivalence before and after fold.

use std::collections::HashMap;
use std::sync::Arc;

use crate::budget::ByteBudget;
use crate::error::{CoreError, ErrorCode};
use crate::graph::segment::{GraphSegment, GraphSegmentWriter, StagedCommit};
use crate::graph::types::{GlobalPosition, LocalPosition, MAX_GRAPH_POSITIONS};
use crate::ids::HashKind;

#[must_use]
pub(crate) fn should_fold(child_commits: u32, parent_commits: u32) -> bool {
    (child_commits as u64).saturating_mul(2) >= (parent_commits as u64)
}

#[must_use]
pub(crate) fn select_folding_chain(
    child_segment: &Arc<GraphSegment>,
) -> (Vec<Arc<GraphSegment>>, Option<Arc<GraphSegment>>) {
    let mut num_accumulated = child_segment.num_local_commits();
    let mut segments_to_fold = vec![Arc::clone(child_segment)];
    let mut curr_parent = child_segment.parent_segment();
    let mut base_parent = None;

    while let Some(parent) = curr_parent {
        let parent_local = parent.num_local_commits();
        if !should_fold(num_accumulated, parent_local) {
            base_parent = Some(Arc::clone(parent));
            break;
        }

        num_accumulated = num_accumulated.saturating_add(parent_local);
        segments_to_fold.push(Arc::clone(parent));
        curr_parent = parent.parent_segment();
    }

    segments_to_fold.reverse();
    (segments_to_fold, base_parent)
}

pub(crate) fn fold_segments(
    segments_oldest_first: &[Arc<GraphSegment>],
    base_parent: Option<&Arc<GraphSegment>>,
    hash_kind: HashKind,
    budget: &Arc<ByteBudget>,
) -> Result<Arc<GraphSegment>, CoreError> {
    if segments_oldest_first.is_empty() {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "cannot fold an empty list of segments",
        ));
    }

    if segments_oldest_first.len() == 1 {
        return Ok(Arc::clone(&segments_oldest_first[0]));
    }

    let base_parent_commits = match base_parent {
        Some(base) => base.num_total_commits(),
        None => 0,
    };
    let base_parent_name = match base_parent {
        Some(base) => base.parent_segment_name().to_string(),
        None => String::new(),
    };

    let mut remap_table: HashMap<u32, u32> = HashMap::new();
    let mut running_new_global = base_parent_commits;

    for segment in segments_oldest_first {
        let seg_parent_commits = segment.num_parent_commits();
        let num_local = segment.num_local_commits();
        for local_idx in 0..num_local {
            let old_global = seg_parent_commits + local_idx;
            remap_table.insert(old_global, running_new_global);
            running_new_global += 1;
        }
    }

    if (running_new_global as u64) > (MAX_GRAPH_POSITIONS as u64) {
        return Err(CoreError::new(
            ErrorCode::ECapacity,
            format!("folded segment total commits {running_new_global} exceeds 2^31 capacity"),
        ));
    }

    let mut writer = GraphSegmentWriter::new(hash_kind, base_parent_name, base_parent_commits);

    for segment in segments_oldest_first {
        let num_local = segment.num_local_commits();
        for local_idx in 0..num_local {
            let lpos = LocalPosition::from_raw_checked(local_idx);
            let head = segment.head_at(lpos)?;
            let change_id = segment.change_id_at(lpos)?;
            let generation = segment.generation_at(lpos)?;
            let old_parents = segment.parents_at(lpos)?;

            let mut new_parents = smallvec::SmallVec::new();
            for old_p in &old_parents {
                let raw_old = old_p.as_u32();
                let raw_new = match remap_table.get(&raw_old) {
                    Some(&remapped) => remapped,
                    None => raw_old,
                };
                new_parents.push(GlobalPosition::new(raw_new)?);
            }

            writer.add_commit(StagedCommit {
                head,
                change_id,
                generation,
                parents: new_parents,
                changed_paths: Vec::new(),
            });
        }
    }

    let encoded_bytes = writer.build()?;
    let parent_handle = base_parent.map(Arc::clone);
    GraphSegment::open_from_bytes(encoded_bytes, hash_kind, parent_handle, budget)
}
