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
