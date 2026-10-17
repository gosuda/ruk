//! Native change operations.
//!
//! Each operation states its request, its preconditions, and its result, and
//! publishes exactly one durable batch. Operations do not parse argv and do
//! not render text; the CLI and the hosted daemon both call these functions
//! and own their own presentation.

pub mod describe;
pub mod new;

#[cfg(test)]
mod tests;

pub use describe::{ChangeDescription, CommitDescription, DescribeRequest, Description, describe};
pub use new::{NewRequest, NewResult, new};
