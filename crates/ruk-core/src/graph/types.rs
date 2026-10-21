//! Core types, position indices, generations, and error definitions for the
//! immutable graph engine.
//!
//! # Graph bounds and positions
//!
//! The graph indexes commits across chained immutable v1 segments. Total
//! indexed commits cannot exceed $2^{31}$ (valid positions `0` through
//! `2^{31} - 1`). High bit `0x8000_0000` is reserved as an overflow flag for
//! parent pointers and change ID lookup in segment tables.

use std::fmt;
use std::ops::Range;

use smallvec::SmallVec;

use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;

/// Maximum valid commit position in the graph ($2^{31} - 1$).
/// Total capacity is $2^{31}$ positions (`0` through `0x7FFF_FFFF`).
#[expect(
    unreachable_pub,
    reason = "graph is a private mod; surface not yet reexported"
)]
pub const MAX_GRAPH_POSITIONS: u32 = 0x8000_0000;

/// Maximum number of indexed commits across composite graph segments ($2^{31}$).
#[expect(dead_code, reason = "never used; goes live when revset is wired")]
#[expect(
    unreachable_pub,
    reason = "graph is a private mod; surface not yet re-exported"
)]
pub const MAX_INDEXED_COMMITS: u64 = 0x8000_0000;

/// Flag indicating that a parent or change entry points to the segment's
/// overflow table rather than an inlined local/global position.
#[expect(
    unreachable_pub,
    reason = "graph is a private mod; surface not yet reexported"
)]
pub const OVERFLOW_FLAG: u32 = 0x8000_0000;

/// Value indicating no parent in an entry slot (e.g. root commit or single parent).
#[expect(
    unreachable_pub,
    reason = "graph is a private mod; surface not yet reexported"
)]
pub const NO_PARENT: u32 = 0xFFFF_FFFF;

/// Format version for v1 graph segments.
#[expect(
    unreachable_pub,
    reason = "graph is a private mod; surface not yet reexported"
)]
pub const GRAPH_SEGMENT_V1_FORMAT: u32 = 1;

/// Magic bytes identifying a Ruk graph segment file (`b"RUKGRAPH"`).
#[expect(
    unreachable_pub,
    reason = "graph is a private mod; surface not yet reexported"
)]
pub const GRAPH_SEGMENT_MAGIC: [u8; 8] = *b"RUKGRAPH";

/// Global commit position across all segments in a composite index chain.
///
/// Invariant: position must be strictly less than `MAX_GRAPH_POSITIONS` ($2^{31}$).
/// Exceeding this boundary fails with [`ErrorCode::ECapacity`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[expect(
    unreachable_pub,
    reason = "graph is a private mod; surface not yet reexported"
)]
pub struct GlobalPosition(u32);

impl GlobalPosition {
    /// Validates and constructs a global position.
    ///
    /// # Errors
    /// Returns [`ErrorCode::ECapacity`] if `pos >= 2^31`.
    #[expect(
        unreachable_pub,
        reason = "graph is a private mod; surface not yet re-exported"
    )]
    pub fn new(pos: u32) -> Result<Self, CoreError> {
        if pos >= MAX_GRAPH_POSITIONS {
            return Err(CoreError::new(
                ErrorCode::ECapacity,
                format!("global commit position {pos} exceeds maximum capacity 2^31 (0x8000_0000)"),
            ));
        }
        Ok(Self(pos))
    }

    /// Internal constructor for values already verified to be within capacity bounds.
    #[must_use]
    pub(crate) const fn from_raw_checked(pos: u32) -> Self {
        Self(pos)
    }

    /// Returns the raw position index.
    #[expect(
        unreachable_pub,
        reason = "graph is a private mod; surface not yet re-exported"
    )]
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Converts to usize for array indexing.
    #[expect(
        unreachable_pub,
        reason = "graph is a private mod; surface not yet re-exported"
    )]
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Debug for GlobalPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GlobalPosition({})", self.0)
    }
}

impl fmt::Display for GlobalPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}", self.0)
    }
}

/// Local commit position within a single graph segment.
///
/// Invariant: position must be strictly less than `MAX_GRAPH_POSITIONS` ($2^{31}$).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[expect(
    unreachable_pub,
    reason = "graph is a private mod; surface not yet reexported"
)]
pub struct LocalPosition(u32);

#[expect(dead_code, reason = "never used; goes live when revset is wired")]
impl LocalPosition {
    /// Validates and constructs a local position.
    ///
    /// # Errors
    /// Returns [`ErrorCode::ECapacity`] if `pos >= 2^31`.
    #[expect(
        unreachable_pub,
        reason = "graph is a private mod; surface not yet re-exported"
    )]
    pub fn new(pos: u32) -> Result<Self, CoreError> {
        if pos >= MAX_GRAPH_POSITIONS {
            return Err(CoreError::new(
                ErrorCode::ECapacity,
                format!("local commit position {pos} exceeds maximum capacity 2^31 (0x8000_0000)"),
            ));
        }
        Ok(Self(pos))
    }

    /// Internal constructor for values verified to be within segment entry bounds.
    #[must_use]
    pub(crate) const fn from_raw_checked(pos: u32) -> Self {
        Self(pos)
    }

    /// Returns the raw local position index.
    #[expect(
        unreachable_pub,
        reason = "graph is a private mod; surface not yet re-exported"
    )]
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Converts to usize for array indexing.
    #[expect(
        unreachable_pub,
        reason = "graph is a private mod; surface not yet re-exported"
    )]
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl fmt::Debug for LocalPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LocalPosition({})", self.0)
    }
}

impl fmt::Display for LocalPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "L@{}", self.0)
    }
}

/// Corrected generation number for early-termination reachability walks.
///
/// $G(c) = 1 + \max_{p \in parents(c)} G(p)$, with $G(root) = 1$.
///
/// Invariant: for every parent $p$ of $c$, $G(p) < G(c)$.
/// Early pruning: $p$ cannot be an ancestor of $c$ if $G(p) \ge G(c)$.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[expect(
    unreachable_pub,
    reason = "graph is a private mod; surface not yet reexported"
)]
pub struct Generation(u32);

#[expect(dead_code, reason = "never used; goes live when revset is wired")]
impl Generation {
    /// Root commit generation ($1$).
    #[expect(
        unreachable_pub,
        reason = "graph is a private mod; surface not yet re-exported"
    )]
    pub const ROOT: Self = Self(1);

    /// Constructs a generation number from a checked non-zero integer.
    ///
    /// # Errors
    /// Returns [`ErrorCode::EInvalid`] if `gen == 0`.
    #[expect(
        unreachable_pub,
        reason = "graph is a private mod; surface not yet re-exported"
    )]
    pub fn new(generation: u32) -> Result<Self, CoreError> {
        if generation == 0 {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "generation number must be strictly positive (>= 1)",
            ));
        }
        Ok(Self(generation))
    }

    /// Internal constructor for raw values.
    #[must_use]
    pub(crate) const fn from_raw(generation: u32) -> Self {
        Self(generation)
    }

    /// Computes child generation from ordered parents.
    #[expect(
        unreachable_pub,
        reason = "graph is a private mod; surface not yet re-exported"
    )]
    #[must_use]
    pub fn from_parents(parents: &[Generation]) -> Self {
        let max_parent = parents.iter().map(|g| g.0).max().unwrap_or(0);
        Self(max_parent.saturating_add(1))
    }

    /// Returns the raw generation value.
    #[expect(
        unreachable_pub,
        reason = "graph is a private mod; surface not yet re-exported"
    )]
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for Generation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Gen({})", self.0)
    }
}

impl fmt::Display for Generation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gen:{}", self.0)
    }
}

/// Parent positions for a commit entry.
///
/// Supports 0, 1, 2 parents inlined, or an ordered octopus merge (> 2 parents)
/// referencing a range in the segment's overflow table.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(dead_code, reason = "never used; goes live when revset is wired")]
#[expect(
    unreachable_pub,
    reason = "graph is a private mod; surface not yet re-exported"
)]
pub enum ParentPositions {
    /// Root commit with no parents.
    Zero,
    /// Single parent commit.
    One(GlobalPosition),
    /// Two-parent merge commit.
    Two(GlobalPosition, GlobalPosition),
    /// Ordered octopus merge with 3 or more parents stored in overflow table.
    Octopus(Range<u32>),
}

impl ParentPositions {
    /// Extracts all parent positions in exact order.
    #[expect(dead_code, reason = "never used; goes live when revset is wired")]
    #[expect(
        unreachable_pub,
        reason = "graph is a private mod; surface not yet re-exported"
    )]
    pub fn collect_parents(&self, overflow: &[GlobalPosition]) -> SmallVec<[GlobalPosition; 2]> {
        match self {
            Self::Zero => SmallVec::new(),
            Self::One(p) => {
                let mut v = SmallVec::new();
                v.push(*p);
                v
            }
            Self::Two(p1, p2) => {
                let mut v = SmallVec::new();
                v.push(*p1);
                v.push(*p2);
                v
            }
            Self::Octopus(range) => {
                let start = range.start as usize;
                let end = range.end as usize;
                if start <= end && end <= overflow.len() {
                    SmallVec::from_slice(&overflow[start..end])
                } else {
                    SmallVec::new()
                }
            }
        }
    }
}

/// Three-way outcome for shallow ancestry checks.
///
/// Missing shallow evidence must never be coerced into a false negative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[expect(
    unreachable_pub,
    reason = "graph is a private mod; surface not yet reexported"
)]
pub enum ShallowAncestry {
    /// Ancestor is proven to be an ancestor of descendant without crossing
    /// shallow boundaries.
    ProvenYes,
    /// Ancestor is proven not to be an ancestor (search terminated cleanly
    /// by generation pruning or exhausted ancestors without hitting shallow cutoffs).
    ProvenNo,
    /// Search reached a shallow boundary without finding ancestor; cannot prove
    /// yes or no without fetching deeper objects. Callers may return `E_SHALLOW`.
    Indeterminate,
}

/// Result of evaluating a changed-path Bloom filter for a commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[expect(
    unreachable_pub,
    reason = "graph is a private mod; surface not yet reexported"
)]
pub enum BloomMatch {
    /// Bloom filter indicates the path might be changed (or filter is
    /// missing/truncated). Must be verified against tree diff.
    Candidate,
    /// Bloom filter is intact and tested definitely negative for at least one
    /// component of the path. Commit definitely did not change path.
    DefinitelyNo,
}

/// Three-way prefix resolution outcome for commit IDs and change IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[expect(
    unreachable_pub,
    reason = "graph is a private mod; surface not yet reexported"
)]
#[expect(
    clippy::enum_variant_names,
    reason = "revset matches on NoMatch/SingleMatch/AmbiguousMatch; renaming touches another subtree"
)]
pub enum PrefixResolution<T> {
    /// No matching identity found.
    NoMatch,
    /// Exactly one unambiguous matching identity found.
    SingleMatch(T),
    /// Multiple distinct matching identities share this prefix.
    AmbiguousMatch,
}

impl<T: PartialEq> PrefixResolution<T> {
    /// Combines two prefix search results across index segments.
    #[expect(
        unreachable_pub,
        reason = "graph is a private mod; surface not yet reexported"
    )]
    #[must_use]
    pub fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::AmbiguousMatch, _) | (_, Self::AmbiguousMatch) => Self::AmbiguousMatch,
            (Self::NoMatch, res) | (res, Self::NoMatch) => res,
            (Self::SingleMatch(a), Self::SingleMatch(b)) => {
                if a == b {
                    Self::SingleMatch(a)
                } else {
                    Self::AmbiguousMatch
                }
            }
        }
    }
}

/// Verifies whether a commit actually changed a path after Bloom filter
/// candidate match.
#[expect(dead_code, reason = "never used; goes live when revset is wired")]
#[expect(
    unreachable_pub,
    reason = "graph is a private mod; surface not yet re-exported"
)]
pub trait ExactPathVerifier: Send + Sync {
    /// Returns true if `head` actually modified `path`.
    fn verify_path(&self, head: &Head, path: &[u8]) -> Result<bool, CoreError>;
}

impl<F> ExactPathVerifier for F
where
    F: Fn(&Head, &[u8]) -> Result<bool, CoreError> + Send + Sync,
{
    fn verify_path(&self, head: &Head, path: &[u8]) -> Result<bool, CoreError> {
        (self)(head, path)
    }
}

/// Helper to format unexpected EOF errors into [`CoreError`].
#[expect(dead_code, reason = "never used; goes live when revset is wired")]
pub(crate) fn unexpected_eof(what: &str) -> CoreError {
    CoreError::new(
        ErrorCode::ECorrupt,
        format!("unexpected end of file reading {what}"),
    )
}

/// Helper to validate table count without overflowing `usize`.
#[expect(dead_code, reason = "never used; goes live when revset is wired")]
pub(crate) fn validate_count(
    count: u32,
    max_allowed: usize,
    what: &str,
) -> Result<usize, CoreError> {
    let count_usize = usize::try_from(count).map_err(|_| {
        CoreError::new(
            ErrorCode::ECapacity,
            format!("{what} count {count} exceeds system addressable memory"),
        )
    })?;
    if count_usize > max_allowed {
        return Err(CoreError::new(
            ErrorCode::ECorrupt,
            format!("{what} count {count} exceeds allowed bounds {max_allowed}"),
        ));
    }
    Ok(count_usize)
}
