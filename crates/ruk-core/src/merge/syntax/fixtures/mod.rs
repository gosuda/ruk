//! Behavioral fixtures for every plain language and variant.
//!
//! Each fixture is a `{base, ours, theirs}` triplet with the exact expected
//! disposition: merged bytes or a specific decline reason. Fixtures inspect
//! results and preserved edits, not parser non-nulls. The parent test owner
//! executes them against real providers; nothing here runs during this
//! source-only slice.
//!
//! Fixture names read `language/case`. Reasons use
//! [`DeclineReason`](super::DeclineReason) spellings.

pub mod code;
pub mod data;
pub mod ml;
pub mod script;
pub mod web;

use super::DeclineReason;
use crate::merge::syntax::grammar::Language;

/// One merge fixture: a source triplet plus its exact expected disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fixture {
    /// Catalogued language of all three inputs.
    pub language: Language,
    /// `language/case` name.
    pub name: &'static str,
    /// Common ancestor bytes.
    pub base: &'static str,
    /// First side bytes.
    pub ours: &'static str,
    /// Second side bytes.
    pub theirs: &'static str,
    /// Exact expected disposition.
    pub expect: Expectation,
}

/// Exact expected disposition of a fixture triplet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expectation {
    /// Merges to exactly these bytes.
    Merge(&'static str),
    /// Declines with exactly this reason.
    Decline(DeclineReason),
}

/// Every fixture in canonical order, grouped by language family.
#[must_use]
pub fn all_fixtures() -> Vec<Fixture> {
    let mut all = Vec::new();
    all.extend(code::fixtures());
    all.extend(web::fixtures());
    all.extend(script::fixtures());
    all.extend(ml::fixtures());
    all.extend(data::fixtures());
    all
}

/// Counts fixtures per language for gate completeness checks.
#[must_use]
pub fn count_by_language() -> Vec<(Language, usize)> {
    let mut counts = Vec::new();
    for language in Language::ALL {
        let count = all_fixtures()
            .iter()
            .filter(|fixture| fixture.language == language)
            .count();
        if count > 0 {
            counts.push((language, count));
        }
    }
    counts
}
