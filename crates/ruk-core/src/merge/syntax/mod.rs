//! Syntax-assisted three-way content merge for plain languages.
//!
//! The plain engine merges one `{base, ours, theirs}` source triplet in a
//! catalogued plain language ([`Language::is_plain`]) into verified
//! byte-range edits or a specific conservative decline. Composed languages
//! (Vue, Svelte, Markdown, MDX, notebooks) are catalogue entries only; the
//! plain entry point declines them with [`DeclineReason::ComposedLanguage`]
//! so the composed-file owner can route them without a generic parser
//! pretending to merge them.
//!
//! All new schema and component versions are v1. The single merge-notice
//! record stays owned by [`crate::merge::composed`]; this module only
//! builds it. Errors are [`SyntaxError`]; declines are [`SyntaxOutcome::Declined`]
//! with a notice. Cancellation never falls back.
//!
//! Parent wiring (Slice 0 owns it): declare `pub mod syntax;` in
//! `crate::merge`, add the pinned grammar crates plus `tree-sitter =
//! "=0.27.1"` and `tree-sitter-language = "=0.1.9"` to manifests, compile
//! the vendored Vue C sources through `cc = "=1.8.0"` in `build.rs`, and
//! implement [`grammar::Grammar`] per pinned export. The exact manifest,
//! feature, and build-script requirements are published at
//! `local://ruk-syntax-engine-api.md`.

pub mod adapters;
pub mod alignment;
pub mod fixtures;
pub mod grammar;
#[cfg(test)]
mod harness;
pub mod treesitter;
pub mod vue_ffi;

pub use adapters::{Adapter, Decline, DeclineReason, SourceUnit, UnitKey, adapter_for};
pub use alignment::merge_triplet;
pub use grammar::{
    Cancel, Grammar, GrammarPin, GrammarRegistry, LANGUAGE_SET_VERSION, Language,
    MAX_TRIPLET_BYTES, ParsedNode, ParsedTree, SyntaxError, dispatch, manifest_digest,
    manifest_digest_input, sha256_hex,
};
pub use treesitter::{TsGrammar, registry_providers};

use serde::{Deserialize, Serialize};

use crate::ByteString;
use crate::merge::composed::{MergeNotice, MergeNotices, NoticeCollector, NoticeRegion};

/// One bounded source triplet to merge, with its validated language.
#[derive(Debug)]
pub struct SyntaxRequest<'a> {
    /// Byte-exact repository path, carried into notices.
    pub path: ByteString,
    /// Catalogued plain language for all three inputs.
    pub language: Language,
    /// Common ancestor bytes.
    pub base: &'a [u8],
    /// First side bytes.
    pub ours: &'a [u8],
    /// Second side bytes.
    pub theirs: &'a [u8],
}

impl SyntaxRequest<'_> {
    /// Combined input bytes, saturating; checked against [`MAX_TRIPLET_BYTES`]
    /// by the driver.
    #[must_use]
    pub fn total_len(&self) -> u64 {
        // Lengths cannot approach u64::MAX on any supported platform; any
        // conversion failure saturates, and the driver bound rejects the
        // triplet before parsing either way.
        let mut total = 0_u64;
        for len in [self.base.len(), self.ours.len(), self.theirs.len()] {
            total = total.saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
        }
        total
    }
}

/// Which side supplied a merged edit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EditSource {
    Ours,
    Theirs,
}

/// One validated replacement of a base byte range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteEdit {
    /// Half-open byte range in the base input.
    pub start: u32,
    /// Half-open byte end in the base input.
    pub end: u32,
    /// Replacement bytes spliced into the base range.
    pub replacement: Vec<u8>,
    /// Which side supplied the replacement.
    pub provenance: EditSource,
}

/// Provenance of one applied edit: the side, the structural unit, and both
/// base-relative and side-relative ranges.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EditProvenance {
    /// Which side supplied the replacement.
    pub source: EditSource,
    /// Structural unit the edit belongs to (`insert:…` for insertions).
    pub unit: String,
    /// Base range replaced.
    pub base_start: u32,
    /// Base range end.
    pub base_end: u32,
    /// Side range the replacement was read from.
    pub side_start: u32,
    /// Side range end.
    pub side_end: u32,
}

/// Merge provenance: grammar identity, input digest binding, and per-edit
/// records. The coordinator validates returned edits against these digests
/// before publication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntaxProvenance {
    /// Canonical language identifier.
    pub language: String,
    /// Grammar origin and version (`origin@version`).
    pub grammar: String,
    /// Generated parser ABI (0 for host libraries, which never reach the
    /// plain merger).
    pub abi: u8,
    /// SHA-256 hex of the base input.
    pub base_digest: String,
    /// SHA-256 hex of the ours input.
    pub ours_digest: String,
    /// SHA-256 hex of the theirs input.
    pub theirs_digest: String,
    /// Per-edit records in application order.
    pub edits: Vec<EditProvenance>,
}

impl SyntaxProvenance {
    /// Builds provenance for `req` with its input digests bound.
    #[must_use]
    pub fn new(req: &SyntaxRequest<'_>, edits: Vec<EditProvenance>) -> Self {
        let pin = req.language.grammar_pin();
        Self {
            language: req.language.id().to_owned(),
            grammar: format!("{}@{}", pin.origin, pin.version),
            abi: pin.abi,
            base_digest: sha256_hex(req.base),
            ours_digest: sha256_hex(req.ours),
            theirs_digest: sha256_hex(req.theirs),
            edits,
        }
    }
}

/// Typed outcome of one triplet merge: verified edits with provenance, or a
/// specific conservative decline with the single existing notice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyntaxOutcome {
    /// Merged cleanly. `bytes` parsed with the same grammar without ERROR
    /// or missing nodes; `edits` splice into base to reproduce `bytes`.
    Merged {
        /// Merged file bytes.
        bytes: Vec<u8>,
        /// Base-relative edits that produce `bytes`.
        edits: Vec<ByteEdit>,
        /// Grammar identity, digest binding, and per-edit records.
        provenance: SyntaxProvenance,
        /// Notices (empty on a syntax-clean result).
        notices: MergeNotices,
    },
    /// The syntax stage declined; the caller runs bounded text merge and
    /// reports `notices`.
    Declined {
        /// Machine-readable reason.
        reason: DeclineReason,
        /// One-line diagnostic.
        detail: String,
        /// The single existing notice for this decline.
        notices: MergeNotices,
    },
}

impl SyntaxOutcome {
    /// Whether the triplet merged cleanly.
    #[must_use]
    pub const fn is_merged(&self) -> bool {
        matches!(self, Self::Merged { .. })
    }

    /// Whether the syntax stage declined.
    #[must_use]
    pub const fn is_declined(&self) -> bool {
        matches!(self, Self::Declined { .. })
    }
}

/// Builds the single-decline notice set for `path`: one entry with the
/// reason's notice code (notebooks report `notebook_structure_declined`),
/// the canonical language identifier, and the diagnostic detail.
pub fn decline_notices(
    req: &SyntaxRequest<'_>,
    reason: DeclineReason,
    detail: &str,
    region: Option<NoticeRegion>,
) -> MergeNotices {
    let mut collector = NoticeCollector::new();
    if let Ok(notice) = MergeNotice::new(
        req.path.clone(),
        region,
        req.language.id(),
        alignment::notice_code_for(reason, req.language),
        detail,
    ) {
        collector.record(notice);
    }
    collector.finish()
}
