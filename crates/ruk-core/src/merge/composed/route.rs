//! Route one path to its merge engine.
//!
//! The caller holds a `{base, ours, theirs}` triplet and a resolved language;
//! this function picks the plain engine, a composed adapter, or an explicit
//! decline. It is the single place that decides which engine a path reaches,
//! so a language added to the catalogue cannot be silently unrouted.

use crate::bytes::ByteString;
use crate::merge::composed::host::{ComposedOutcome, ComposedRequest, merge_host};
use crate::merge::composed::markdown::merge_markdown;
use crate::merge::composed::mdx::merge_mdx;
use crate::merge::composed::notebook::merge_notebook;
use crate::merge::composed::{MergeMode, MergeNotices, NoticeCode, NoticeCollector};
use crate::merge::syntax::adapters::DeclineReason;
use crate::merge::syntax::{
    Cancel, GrammarRegistry, Language, SyntaxError, SyntaxOutcome, SyntaxRequest, merge_triplet,
};

/// Which engine owns a language.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    /// The plain source-unit engine.
    Plain,
    /// Host composition over embedded regions: HTML, Vue, Svelte.
    Host,
    /// Markdown with fenced code regions.
    Markdown,
    /// MDX composition.
    Mdx,
    /// Jupyter notebook alignment.
    Notebook,
}

/// The engine a catalogued language routes to.
#[must_use]
pub const fn engine_for(language: Language) -> Engine {
    match language {
        Language::Html | Language::Vue | Language::Svelte => Engine::Host,
        Language::Markdown => Engine::Markdown,
        Language::Mdx => Engine::Mdx,
        Language::Notebook => Engine::Notebook,
        _ => Engine::Plain,
    }
}

/// Merges one file through the engine its language selects.
///
/// Explicit git mode never reaches an adapter; the caller is responsible for
/// keeping git-mode content results on the Git path. In syntax mode a
/// composed engine answers `Clean`, `Conflict`, or `Declined`, and the plain
/// engine answers `Merged` or `Declined`; both are returned unchanged so the
/// caller owns fallback and publication.
///
/// # Errors
/// Propagates [`SyntaxError`] from the selected engine: cancellation, a
/// resource limit, or an invalid request.
pub fn merge_file(
    request: ComposedRequest<'_>,
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
) -> Result<MergeOutcome, SyntaxError> {
    if request.mode == MergeMode::Git {
        return Ok(git_mode_decline(&request));
    }
    match engine_for(request.language) {
        Engine::Plain => {
            merge_plain(&request, registry, cancel).map(|outcome| plain_outcome(&outcome))
        }
        engine => merge_composed(engine, &request, registry, cancel),
    }
}

/// The plain engine's outcome in this module's vocabulary.
fn plain_outcome(outcome: &SyntaxOutcome) -> MergeOutcome {
    match outcome {
        SyntaxOutcome::Merged { bytes, notices, .. } => MergeOutcome::Merged {
            bytes: bytes.clone(),
            engine: Engine::Plain,
            notices: notices.clone(),
        },
        SyntaxOutcome::Declined {
            reason,
            detail,
            notices,
        } => MergeOutcome::Declined {
            engine: Engine::Plain,
            reason: *reason,
            detail: detail.clone(),
            notices: notices.clone(),
        },
    }
}

/// The plain engine reads the same triplet without taking the path.
fn merge_plain(
    request: &ComposedRequest<'_>,
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
) -> Result<SyntaxOutcome, SyntaxError> {
    merge_triplet(
        &SyntaxRequest {
            path: request.path.clone(),
            language: request.language,
            base: request.base,
            ours: request.ours,
            theirs: request.theirs,
        },
        registry,
        cancel,
    )
}

fn merge_composed(
    engine: Engine,
    composed: &ComposedRequest<'_>,
    registry: &GrammarRegistry<'_>,
    cancel: &Cancel,
) -> Result<MergeOutcome, SyntaxError> {
    let composed = ComposedRequest {
        path: composed.path.clone(),
        language: composed.language,
        base: composed.base,
        ours: composed.ours,
        theirs: composed.theirs,
        mode: MergeMode::Syntax,
    };
    let outcome = match engine {
        Engine::Host => merge_host(&composed, registry, cancel),
        Engine::Markdown => merge_markdown(&composed, registry, cancel),
        Engine::Mdx => merge_mdx(&composed, registry, cancel),
        Engine::Notebook => merge_notebook(&composed, registry, cancel),
        Engine::Plain => unreachable!("the plain engine never reaches composed routing"),
    }?;
    Ok(to_outcome(engine, outcome))
}

/// A merged file or a typed refusal.
///
/// Composed engines splice host and child bytes under their own provenance,
/// so a composed result carries bytes and notices rather than the plain
/// engine's base-relative edit list. A `Conflict` keeps no bytes: the caller
/// keeps the native conflict terms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    /// Merged bytes, produced by the named engine.
    Merged {
        /// Merged file bytes.
        bytes: Vec<u8>,
        /// The engine that produced them.
        engine: Engine,
        /// Notices recorded during the merge.
        notices: MergeNotices,
    },
    /// No merged bytes; the caller keeps conflict terms.
    Declined {
        /// The engine that declined.
        engine: Engine,
        /// Machine-readable reason.
        reason: DeclineReason,
        /// One-line diagnostic.
        detail: String,
        /// Notices recording the evidence.
        notices: MergeNotices,
    },
}

/// A composed result in this module's outcome vocabulary.
fn to_outcome(engine: Engine, outcome: ComposedOutcome) -> MergeOutcome {
    match outcome {
        ComposedOutcome::Clean { bytes, notices } => MergeOutcome::Merged {
            bytes,
            engine,
            notices,
        },
        ComposedOutcome::Conflict { notices } => MergeOutcome::Declined {
            engine,
            reason: DeclineReason::SameUnitChanged,
            detail: conflict_detail(&notices),
            notices,
        },
        ComposedOutcome::Declined { reason, notices } => MergeOutcome::Declined {
            engine,
            reason,
            detail: conflict_detail(&notices),
            notices,
        },
    }
}

fn conflict_detail(notices: &MergeNotices) -> String {
    notices.entries().first().map_or_else(
        || "composed merge declined".to_owned(),
        |notice| notice.detail().to_owned(),
    )
}

/// Explicit git mode: no adapter runs, and the caller's Git path owns content.
fn git_mode_decline(request: &ComposedRequest<'_>) -> MergeOutcome {
    let mut collector = NoticeCollector::new();
    let detail = format!(
        "{} is in explicit git mode; the Git content path owns this result",
        request.language.id()
    );
    if let Ok(notice) = crate::merge::composed::MergeNotice::new(
        request.path.clone(),
        None,
        request.language.id(),
        NoticeCode::SyntaxAmbiguous,
        &detail,
    ) {
        collector.record(notice);
    }
    MergeOutcome::Declined {
        engine: engine_for(request.language),
        reason: DeclineReason::UnsupportedConstruct,
        detail,
        notices: collector.finish(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_catalogued_language_has_one_engine() {
        for language in Language::ALL {
            let engine = engine_for(language);
            // The plain adapter table and the router agree everywhere except
            // HTML, whose plain adapter owns documents but not the script and
            // style bodies: the host adapter owns those, so HTML routes Host.
            let expected = match (language.is_plain(), language) {
                (false, Language::Markdown) => Engine::Markdown,
                (false, Language::Mdx) => Engine::Mdx,
                (false, Language::Notebook) => Engine::Notebook,
                (false, _) => Engine::Host,
                (true, Language::Html) => Engine::Host,
                (true, _) => Engine::Plain,
            };
            assert_eq!(engine, expected, "{} routed to {engine:?}", language.id());
        }
    }

    #[test]
    fn composed_languages_route_to_their_own_engine() {
        assert_eq!(engine_for(Language::Html), Engine::Host);
        assert_eq!(engine_for(Language::Vue), Engine::Host);
        assert_eq!(engine_for(Language::Svelte), Engine::Host);
        assert_eq!(engine_for(Language::Markdown), Engine::Markdown);
        assert_eq!(engine_for(Language::Mdx), Engine::Mdx);
        assert_eq!(engine_for(Language::Notebook), Engine::Notebook);
    }

    #[test]
    fn git_mode_never_reaches_an_adapter() {
        let request = ComposedRequest {
            path: ByteString::from("README.md"),
            language: Language::Markdown,
            base: b"a\n",
            ours: b"b\n",
            theirs: b"c\n",
            mode: MergeMode::Git,
        };
        let outcome = merge_file(request, &GrammarRegistry::new(), &Cancel::never())
            .expect("git mode declines instead of merging");
        let MergeOutcome::Declined { reason, detail, .. } = outcome else {
            panic!("git mode must not produce a merged result");
        };
        assert_eq!(reason, DeclineReason::UnsupportedConstruct);
        assert!(detail.contains("git mode"));
    }
}
