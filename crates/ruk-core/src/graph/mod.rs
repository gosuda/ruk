//! Immutable graph acceleration engine for Ruk.

pub(crate) mod bloom;
pub(crate) mod cache;
pub(crate) mod composite;
pub(crate) mod folding;
pub(crate) mod segment;
pub(crate) mod traversal;
pub(crate) mod types;

#[cfg(test)]
mod tests;

pub(crate) use bloom::{
    bloom_hashes, build_bloom_filter, check_bloom_filter, expand_path_and_ancestors,
    murmur3_seeded, DEFAULT_BITS_PER_ENTRY, DEFAULT_MAX_CHANGED_PATHS, DEFAULT_NUM_HASHES,
};
pub(crate) use cache::{CachedReachabilityEntry, ReachabilityCache};
pub(crate) use composite::{ChangeIdCursor, GraphIndex, GraphIndexBuilder};
pub(crate) use folding::{fold_segments, select_folding_chain, should_fold};
pub(crate) use segment::{
    ChangeIdPage, CommitGraphEntry, GraphSegment, GraphSegmentWriter, StagedCommit,
};
pub(crate) use traversal::{
    find_heads, find_roots, is_ancestor, AncestorStepper, GraphAccess, TraversalPage,
};
pub(crate) use types::{
    BloomMatch, ExactPathVerifier, Generation, GlobalPosition, LocalPosition, ParentPositions,
    PrefixResolution, ShallowAncestry, GRAPH_SEGMENT_MAGIC, GRAPH_SEGMENT_V1_FORMAT,
    MAX_GRAPH_POSITIONS, MAX_INDEXED_COMMITS, NO_PARENT, OVERFLOW_FLAG,
};
