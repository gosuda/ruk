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
pub mod split;
pub mod squash;

#[cfg(test)]
mod tests;

pub use abandon::{AbandonRequest, AbandonResult, abandon};
pub use describe::{ChangeDescription, CommitDescription, DescribeRequest, Description, describe};
pub use edit::{EditRequest, EditResult, edit};
pub use new::{NewRequest, NewResult, new};
pub use rebase::{RebaseRequest, RebaseResult, rebase};
pub use resolve::{ResolveRequest, ResolveResult, resolve};
pub use revert::{RevertRequest, RevertResult, revert};
pub use split::{SplitRequest, SplitResult, split};
pub use squash::{SquashRequest, SquashResult, squash};
