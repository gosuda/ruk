//! Composite multi-segment graph index and incremental builder.
//!
//! # Architecture
//!
//! [`GraphIndex`] chains one or more immutable [`GraphSegment`]s (root to leaf).
//! Commit positions are partitioned across the segments:
//! - Segment 0 owns global positions `[0, N_0)`.
//! - Segment 1 owns global positions `[N_0, N_0 + N_1)`.
//! - Segment $k$ owns global positions `[N_{parents}, N_{parents} + N_k)`.
//!
//! Total indexed commits cannot exceed $2^{31}$ ([`MAX_GRAPH_POSITIONS`]).
//!
//! Reverse lookups check newest segments first, so recent commits resolve immediately.
//! Divergence lookups use bounded pages and resumable cursors.
//! Prefix queries evaluate against sorted segment indices with early stopping on ambiguity.

use std::sync::Arc;

use smallvec::SmallVec;

use crate::budget::ByteBudget;
use crate::change::ChangeId;
use crate::error::{CoreError, ErrorCode};
use crate::graph::folding::{fold_segments, select_folding_chain};
use crate::graph::segment::{GraphSegment, GraphSegmentWriter, StagedCommit};
use crate::graph::traversal::GraphAccess;
use crate::graph::types::{
    Generation, GlobalPosition, LocalPosition, MAX_GRAPH_POSITIONS, PrefixResolution,
};
use crate::heads::Head;
use crate::ids::HashKind;

/// Resumable cursor for multi-segment divergent change queries.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used only in test builds; dead in lib build")
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct ChangeIdCursor {
    pub(crate) segment_idx: usize,
    pub(crate) overflow_offset: usize,
}

/// One bounded page of a composite divergence query. Unlike the per-segment
/// [`crate::graph::segment::ChangeIdPage`], the continuation is a [`ChangeIdCursor`] spanning
/// segments rather than an overflow offset inside one.
#[expect(dead_code, reason = "never used; goes live when revset is wired")]
#[derive(Clone, Debug)]
pub(crate) struct DivergentPage<T> {
    pub(crate) items: SmallVec<[T; 8]>,
    pub(crate) total_count: usize,
    pub(crate) next_cursor: Option<ChangeIdCursor>,
}

/// Composite graph index spanning chained immutable v1 segments.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used only in test builds; dead in lib build")
)]
#[derive(Clone)]
pub(crate) struct GraphIndex {
    segments_oldest_first: Vec<Arc<GraphSegment>>,
    hash_kind: HashKind,
}

#[expect(dead_code, reason = "never used; goes live when revset is wired")]
impl GraphIndex {
    /// Constructs a composite index from a chain of segments ordered oldest first.
    pub(crate) fn new(
        segments_oldest_first: Vec<Arc<GraphSegment>>,
        hash_kind: HashKind,
    ) -> Result<Self, CoreError> {
        if segments_oldest_first.is_empty() {
            return Ok(Self {
                segments_oldest_first,
                hash_kind,
            });
        }

        let first = &segments_oldest_first[0];
        if first.num_parent_commits() != 0 {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "first segment in chain must have num_parent_commits = 0",
            ));
        }

        let mut expected_parent_commits = first.num_total_commits();
        for (i, seg) in segments_oldest_first.iter().enumerate().skip(1) {
            if seg.num_parent_commits() != expected_parent_commits {
                return Err(CoreError::new(
                    ErrorCode::ECorrupt,
                    format!(
                        "segment {i} claims {} parent commits but previous segments total {expected_parent_commits}",
                        seg.num_parent_commits()
                    ),
                ));
            }
            expected_parent_commits = seg.num_total_commits();
        }

        if (expected_parent_commits as u64) > (MAX_GRAPH_POSITIONS as u64) {
            return Err(CoreError::new(
                ErrorCode::ECapacity,
                format!(
                    "composite index total commits {expected_parent_commits} exceeds 2^31 capacity"
                ),
            ));
        }

        Ok(Self {
            segments_oldest_first,
            hash_kind,
        })
    }

    /// Empty composite index for a given hash kind.
    #[must_use]
    pub(crate) fn empty(hash_kind: HashKind) -> Self {
        Self {
            segments_oldest_first: Vec::new(),
            hash_kind,
        }
    }

    /// Total number of indexed commits across all segments.
    #[must_use]
    pub(crate) fn num_total_commits(&self) -> u32 {
        self.segments_oldest_first
            .last()
            .map(|s| s.num_total_commits())
            .unwrap_or(0)
    }

    /// Slice of all segments ordered oldest first.
    #[must_use]
    pub(crate) fn segments(&self) -> &[Arc<GraphSegment>] {
        &self.segments_oldest_first
    }

    /// Newest (leaf) segment in the chain.
    #[must_use]
    pub(crate) fn leaf_segment(&self) -> Option<&Arc<GraphSegment>> {
        self.segments_oldest_first.last()
    }

    /// Repository hash kind.
    #[must_use]
    pub(crate) const fn hash_kind(&self) -> HashKind {
        self.hash_kind
    }

    /// Finds the owning segment and local position for `pos`.
    pub(crate) fn find_segment_for_pos(
        &self,
        pos: GlobalPosition,
    ) -> Result<(&GraphSegment, LocalPosition), CoreError> {
        let raw = pos.as_u32();
        for seg in self.segments_oldest_first.iter().rev() {
            let start = seg.num_parent_commits();
            let end = seg.num_total_commits();
            if raw >= start && raw < end {
                let local_idx = raw - start;
                let local_pos = LocalPosition::from_raw_checked(local_idx);
                return Ok((seg.as_ref(), local_pos));
            }
        }
        Err(CoreError::new(
            ErrorCode::ENotFound,
            format!("global commit position {pos} not found in any segment"),
        ))
    }

    /// Resolves `Head` at `pos`.
    pub(crate) fn pos_to_head(&self, pos: GlobalPosition) -> Result<Head, CoreError> {
        let (seg, lpos) = self.find_segment_for_pos(pos)?;
        seg.head_at(lpos)
    }

    /// Resolves `Generation` at `pos`.
    pub(crate) fn pos_to_generation(&self, pos: GlobalPosition) -> Result<Generation, CoreError> {
        let (seg, lpos) = self.find_segment_for_pos(pos)?;
        seg.generation_at(lpos)
    }

    /// Resolves parents at `pos`.
    pub(crate) fn pos_to_parents(
        &self,
        pos: GlobalPosition,
    ) -> Result<SmallVec<[GlobalPosition; 2]>, CoreError> {
        let (seg, lpos) = self.find_segment_for_pos(pos)?;
        seg.parents_at(lpos)
    }

    /// Resolves `ChangeId` at `pos`.
    pub(crate) fn pos_to_change_id(&self, pos: GlobalPosition) -> Result<ChangeId, CoreError> {
        let (seg, lpos) = self.find_segment_for_pos(pos)?;
        seg.change_id_at(lpos)
    }

    /// Finds global position for a commit `Head`.
    #[must_use]
    pub(crate) fn head_to_pos(&self, head: &Head) -> Option<GlobalPosition> {
        for seg in self.segments_oldest_first.iter().rev() {
            if let Some(lpos) = seg.find_head(head) {
                let global_raw = seg.num_parent_commits() + lpos.as_u32();
                return Some(GlobalPosition::from_raw_checked(global_raw));
            }
        }
        None
    }

    /// Resumable bounded page lookup for heads associated with `change_id`.
    pub(crate) fn change_id_to_heads_page(
        &self,
        change_id: &ChangeId,
        cursor: Option<ChangeIdCursor>,
        limit: usize,
    ) -> Result<DivergentPage<Head>, CoreError> {
        let page_bound = limit.min(64);
        let start_seg = cursor
            .map(|c| c.segment_idx)
            .unwrap_or(self.segments_oldest_first.len());
        let mut overflow_offset = cursor.map(|c| c.overflow_offset).unwrap_or(0);
        let mut heads = SmallVec::new();
        let mut total_divergent = 0usize;

        // Iterate segments from newest to oldest
        for seg_idx in (0..start_seg).rev() {
            let seg = &self.segments_oldest_first[seg_idx];
            let remaining = page_bound - heads.len();
            let page = seg.find_change_id_page(change_id, overflow_offset, remaining)?;
            total_divergent += page.total_count;

            for lpos in page.items {
                let head = seg.head_at(lpos)?;
                if !heads.contains(&head) {
                    heads.push(head);
                }
            }

            if let Some(next_off) = page.next_offset {
                return Ok(DivergentPage {
                    items: heads,
                    total_count: total_divergent,
                    next_cursor: Some(ChangeIdCursor {
                        segment_idx: seg_idx + 1,
                        overflow_offset: next_off,
                    }),
                });
            }

            overflow_offset = 0;
            if heads.len() >= page_bound {
                let next_cursor = if seg_idx > 0 {
                    Some(ChangeIdCursor {
                        segment_idx: seg_idx,
                        overflow_offset: 0,
                    })
                } else {
                    None
                };
                return Ok(DivergentPage {
                    items: heads,
                    total_count: total_divergent,
                    next_cursor,
                });
            }
        }

        Ok(DivergentPage {
            items: heads,
            total_count: total_divergent,
            next_cursor: None,
        })
    }

    /// Bounded lookup of heads for a change ID, up to `limit`.
    pub(crate) fn change_id_to_heads_bounded(
        &self,
        change_id: &ChangeId,
        limit: usize,
    ) -> Result<SmallVec<[Head; 8]>, CoreError> {
        let page = self.change_id_to_heads_page(change_id, None, limit.min(64))?;
        let mut out = SmallVec::new();
        for h in page.items {
            out.push(h);
        }
        Ok(out)
    }

    /// Resumable bounded page lookup for global positions associated with `change_id`.
    pub(crate) fn change_id_to_positions_page(
        &self,
        change_id: &ChangeId,
        cursor: Option<ChangeIdCursor>,
        limit: usize,
    ) -> Result<DivergentPage<GlobalPosition>, CoreError> {
        let page_bound = limit.min(64);
        let start_seg = cursor
            .map(|c| c.segment_idx)
            .unwrap_or(self.segments_oldest_first.len());
        let mut overflow_offset = cursor.map(|c| c.overflow_offset).unwrap_or(0);
        let mut positions = SmallVec::new();
        let mut total_divergent = 0usize;

        for seg_idx in (0..start_seg).rev() {
            let seg = &self.segments_oldest_first[seg_idx];
            let remaining = page_bound - positions.len();
            let page = seg.find_change_id_page(change_id, overflow_offset, remaining)?;
            total_divergent += page.total_count;

            for lpos in page.items {
                let gpos =
                    GlobalPosition::from_raw_checked(seg.num_parent_commits() + lpos.as_u32());
                if !positions.contains(&gpos) {
                    positions.push(gpos);
                }
            }

            if let Some(next_off) = page.next_offset {
                return Ok(DivergentPage {
                    items: positions,
                    total_count: total_divergent,
                    next_cursor: Some(ChangeIdCursor {
                        segment_idx: seg_idx + 1,
                        overflow_offset: next_off,
                    }),
                });
            }

            overflow_offset = 0;
            if positions.len() >= page_bound {
                let next_cursor = if seg_idx > 0 {
                    Some(ChangeIdCursor {
                        segment_idx: seg_idx,
                        overflow_offset: 0,
                    })
                } else {
                    None
                };
                return Ok(DivergentPage {
                    items: positions,
                    total_count: total_divergent,
                    next_cursor,
                });
            }
        }

        Ok(DivergentPage {
            items: positions,
            total_count: total_divergent,
            next_cursor: None,
        })
    }

    /// Indexed prefix lookup against commit heads across segments; stops on ambiguity.
    pub(crate) fn resolve_head_prefix(
        &self,
        prefix: &str,
    ) -> Result<PrefixResolution<Head>, CoreError> {
        let mut resolution = PrefixResolution::NoMatch;
        for seg in self.segments_oldest_first.iter().rev() {
            let seg_res = seg.resolve_head_prefix(prefix)?;
            resolution = resolution.combine(seg_res);
            if resolution == PrefixResolution::AmbiguousMatch {
                // Early stop on ambiguity across segments
                return Ok(PrefixResolution::AmbiguousMatch);
            }
        }
        Ok(resolution)
    }

    /// Indexed prefix lookup against change IDs across segments; stops on ambiguity.
    pub(crate) fn resolve_change_id_prefix(
        &self,
        prefix: &str,
    ) -> Result<PrefixResolution<ChangeId>, CoreError> {
        let mut resolution = PrefixResolution::NoMatch;
        for seg in self.segments_oldest_first.iter().rev() {
            let seg_res = seg.resolve_change_id_prefix(prefix)?;
            resolution = resolution.combine(seg_res);
            if resolution == PrefixResolution::AmbiguousMatch {
                return Ok(PrefixResolution::AmbiguousMatch);
            }
        }
        Ok(resolution)
    }
}

impl GraphAccess for GraphIndex {
    fn get_generation(&self, pos: GlobalPosition) -> Result<Generation, CoreError> {
        self.pos_to_generation(pos)
    }

    fn get_parents(&self, pos: GlobalPosition) -> Result<SmallVec<[GlobalPosition; 2]>, CoreError> {
        self.pos_to_parents(pos)
    }

    fn get_head(&self, pos: GlobalPosition) -> Result<Head, CoreError> {
        self.pos_to_head(pos)
    }
}

/// Incremental builder that adds commits on top of an existing index.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used only in test builds; dead in lib build")
)]
pub(crate) struct GraphIndexBuilder {
    base_index: GraphIndex,
    staged: Vec<StagedCommit>,
    staged_heads: std::collections::HashMap<Head, GlobalPosition>,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "used only in test builds; dead in lib build")
)]
impl GraphIndexBuilder {
    #[must_use]
    pub(crate) fn new(base_index: GraphIndex) -> Self {
        Self {
            base_index,
            staged: Vec::new(),
            staged_heads: std::collections::HashMap::new(),
        }
    }

    pub(crate) fn add_commit(
        &mut self,
        head: Head,
        change_id: ChangeId,
        parent_heads: &[Head],
        changed_paths: Vec<Vec<u8>>,
    ) -> Result<GlobalPosition, CoreError> {
        if self.base_index.head_to_pos(&head).is_some() || self.staged_heads.contains_key(&head) {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("commit head already exists in graph index: {head:?}"),
            ));
        }

        let mut resolved_parents = SmallVec::new();
        let mut parent_generations = Vec::new();

        for p_head in parent_heads {
            let p_pos = if let Some(&pos) = self.staged_heads.get(p_head) {
                pos
            } else if let Some(pos) = self.base_index.head_to_pos(p_head) {
                pos
            } else {
                return Err(CoreError::new(
                    ErrorCode::ENotFound,
                    format!("parent head not found in graph index: {p_head:?}"),
                ));
            };

            resolved_parents.push(p_pos);
            let parent_generation = if let Some(&_pos) = self.staged_heads.get(p_head) {
                let staged_idx = self.staged.iter().position(|c| &c.head == p_head);
                match staged_idx {
                    Some(idx) => self.staged[idx].generation,
                    None => Generation::ROOT,
                }
            } else {
                self.base_index.pos_to_generation(p_pos)?
            };
            parent_generations.push(parent_generation);
        }

        let generation = Generation::from_parents(&parent_generations);
        let current_total =
            (self.base_index.num_total_commits() as u64) + (self.staged.len() as u64);
        if current_total >= (MAX_GRAPH_POSITIONS as u64) {
            return Err(CoreError::new(
                ErrorCode::ECapacity,
                "commit count reaches maximum graph capacity 2^31",
            ));
        }

        let assigned_pos = GlobalPosition::from_raw_checked(current_total as u32);
        self.staged_heads.insert(head, assigned_pos);

        self.staged.push(StagedCommit {
            head,
            change_id,
            generation,
            parents: resolved_parents,
            changed_paths,
        });

        Ok(assigned_pos)
    }

    pub(crate) fn finish(self, budget: &Arc<ByteBudget>) -> Result<GraphIndex, CoreError> {
        if self.staged.is_empty() {
            return Ok(self.base_index);
        }

        let hash_kind = self.base_index.hash_kind();
        let parent_segment = self.base_index.leaf_segment().cloned();
        let parent_name = parent_segment
            .as_ref()
            .map(|s| s.parent_segment_name().to_string())
            .unwrap_or_default();
        let num_parent_commits = self.base_index.num_total_commits();

        let mut writer = GraphSegmentWriter::new(hash_kind, parent_name, num_parent_commits);
        for staged in self.staged {
            writer.add_commit(staged);
        }

        let bytes = writer.build()?;
        let child_seg = GraphSegment::open_from_bytes(bytes, hash_kind, parent_segment, budget)?;

        let (segments_to_fold, base_parent) = select_folding_chain(&child_seg);
        if segments_to_fold.len() > 1 {
            let folded_seg =
                fold_segments(&segments_to_fold, base_parent.as_ref(), hash_kind, budget)?;
            let mut final_segments = Vec::new();
            if let Some(base) = base_parent {
                for seg in self.base_index.segments() {
                    final_segments.push(Arc::clone(seg));
                    if seg.num_total_commits() == base.num_total_commits() {
                        break;
                    }
                }
            }
            final_segments.push(folded_seg);
            GraphIndex::new(final_segments, hash_kind)
        } else {
            let mut new_segments = self.base_index.segments().to_vec();
            new_segments.push(child_seg);
            GraphIndex::new(new_segments, hash_kind)
        }
    }
}
