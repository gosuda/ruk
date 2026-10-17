//! Fixture harness: runs every behavioral fixture through the real driver
//! with the pinned providers and asserts the exact expected disposition.
//!
//! A fixture failure means the adapter's node-kind table drifted against
//! its pinned grammar, the driver's conservative rules changed, or the
//! fixture expectation itself is wrong — in that order of suspicion. The
//! harness never accepts a plausible subset: every fixture must dispose
//! exactly as declared.

use super::fixtures::{Expectation, all_fixtures};
use super::grammar::{Cancel, GrammarRegistry, Language};
use super::treesitter::TsGrammar;
use super::{SyntaxOutcome, SyntaxRequest, merge_triplet};
use crate::ByteString;

/// Collects live providers, failing the test on any pinned export that
/// refuses its grammar (readiness blocks; it never marks unsupported).
/// The caller keeps the returned vector alive beside its registry.
fn live_providers() -> Vec<TsGrammar> {
    let mut providers = Vec::new();
    for provider in super::treesitter::registry_providers() {
        match provider {
            Ok(grammar) => providers.push(grammar),
            Err(err) => panic!("provider construction failed: {err}"),
        }
    }
    assert!(!providers.is_empty(), "no providers registered");
    providers
}

/// Checks one fixture outcome against its declared disposition, recording
/// a report entry on mismatch.
fn check_fixture(
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
    name: &'static str,
    language: Language,
    base: &str,
    ours: &str,
    theirs: &str,
    expect: Expectation,
    failures: &mut Vec<String>,
) {
    let request = SyntaxRequest {
        path: ByteString::from(name),
        language,
        base: base.as_bytes(),
        ours: ours.as_bytes(),
        theirs: theirs.as_bytes(),
    };
    let outcome =
        merge_triplet(&request, registry, cancel).unwrap_or_else(|err| panic!("{name} errored: {err}"));
    let matched = match (expect, &outcome) {
        (Expectation::Merge(expected), SyntaxOutcome::Merged { bytes, .. }) => {
            bytes.as_slice() == expected.as_bytes()
        }
        (Expectation::Decline(reason), SyntaxOutcome::Declined { reason: got, .. }) => {
            *got == reason
        }
        _ => false,
    };
    if !matched {
        failures.push(format!("- {name}: expected {expect:?}, got {outcome:?}"));
    }
}

#[test]
fn all_fixtures_dispose_exactly() {
    let providers = live_providers();
    let mut registry = GrammarRegistry::new();
    for grammar in &providers {
        registry.insert(grammar);
    }
    let cancel = Cancel::never();
    let fixtures = all_fixtures();
    assert!(!fixtures.is_empty(), "no fixtures declared");
    let mut failures = Vec::new();
    for fixture in &fixtures {
        check_fixture(
            &registry,
            &cancel,
            fixture.name,
            fixture.language,
            fixture.base,
            fixture.ours,
            fixture.theirs,
            fixture.expect,
            &mut failures,
        );
    }
    if !failures.is_empty() {
        panic!(
            "{} of {} fixtures mis-disposed:\n{}",
            failures.len(),
            fixtures.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn readiness_samples_parse_clean() {
    let providers = live_providers();
    let mut registry = GrammarRegistry::new();
    for grammar in &providers {
        registry.insert(grammar);
    }
    let cancel = Cancel::never();
    for language in Language::ALL {
        if !language.is_plain() {
            continue;
        }
        let Some(grammar) = registry.get(language) else {
            panic!("no provider registered for {}", language.id());
        };
        let sample = language.readiness_sample();
        let tree = grammar
            .parse(sample.as_bytes(), &cancel)
            .unwrap_or_else(|err| panic!("{} sample failed to parse: {err}", language.id()));
        assert!(
            !tree.has_error(),
            "{} readiness sample holds ERROR or missing nodes",
            language.id()
        );
    }
}
