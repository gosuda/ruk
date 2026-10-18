//! Native change operations.
//!
//! Each operation states its request, its preconditions, and its result, and
//! publishes exactly one durable batch. Operations do not parse argv and do
//! not render text; the CLI and the hosted daemon both call these functions
//! and own their own presentation.

pub mod abandon;
pub mod describe;
pub mod edit;
pub mod new;
pub mod rebase;
pub mod resolve;
pub mod revert;
pub mod rewrite;
pub mod split;
pub mod squash;
pub(crate) mod tree_edit;

#[cfg(test)]
mod tests;

use crate::store::types::{FactMutation, PreparedObject};

pub use abandon::{AbandonRequest, AbandonResult, abandon, prepare_abandon};
pub use describe::{ChangeDescription, CommitDescription, DescribeRequest, Description, describe};
pub use edit::{EditRequest, EditResult, edit, prepare_edit};
pub use new::{NewRequest, NewResult, new, prepare_new};
pub use rebase::{RebaseRequest, RebaseResult, prepare_rebase, rebase};
pub use resolve::{ResolveRequest, ResolveResult, prepare_resolve, resolve};
pub use revert::{RevertRequest, RevertResult, prepare_revert, revert};
pub use rewrite::{children, descendants};
pub use split::{SplitRequest, SplitResult, prepare_split, split};
pub use squash::{SquashRequest, SquashResult, prepare_squash, squash};

/// One operation's pre-publication parts: the staged objects, the
/// exact-expectation fact mutations, and the output publication will produce.
///
/// `prepare_*` validates and stages without touching the store; the `<op>`
/// wrapper publishes the parts atomically and returns the output, so the
/// CLI keeps its byte-identical behavior while the hosted lane can submit
/// the same parts through its own publication path.
#[derive(Debug)]
pub struct PreparedOp<Output> {
    /// Staged object spools to publish.
    pub objects: Vec<PreparedObject>,
    /// Exact-expectation fact mutations to publish.
    pub facts: Vec<FactMutation>,
    /// The output publication will produce.
    pub output: Output,
}
