//! Merge mode, merge-result metadata, and the one canonical merge notice.
//!
//! The composed-file specification fixes a single structured notice record
//! that every surface reuses unchanged: native JSON replies (`merge_notices`),
//! the hosted IPC `MergeNotices` event, CLI stderr, and the Forgejo merge
//! result. This module is that record's only definition; nothing re-defines
//! its fields, its coalescing rule, its entry cap, or its truncation flag.
//!
//! * Coalescing: repeated notices that share `(path, language, code)` collapse
//!   into one entry carrying an occurrence count. The retained region and
//!   detail are those of the first occurrence (the representative).
//! * Cap: at most [`MAX_NOTICES`] entries are retained per operation. Once the
//!   cap is reached, further distinct notices are counted but not retained;
//!   `notices_truncated` is set and `total_occurrences` still counts every
//!   occurrence. A `notebook_outputs_cleared` notice is never displaced by
//!   another code: when the cap is full it evicts the newest other-code entry
//!   instead, so output clearing stays visible. It is dropped only when every
//!   retained entry is itself an output-clearing entry.
//! * A notice describes a decision; it never turns a conflict into success.
//!
//! Every merge or mergeability result also carries the effective mode and the
//! `language_set_version` that produced it ([`MergeMetadata`]), so a caller
//! distinguishes a syntax result from a Git result without inferring it from
//! which backend ran. [`MergeReport`] bundles the two and rejects the one
//! contradiction the contract rules out: a Git-mode result carrying notices,
//! because explicit Git mode bypasses every syntax and notebook adapter.
//!
//! Every type here deserializes through a validating constructor, so untrusted
//! JSON or stored bytes cannot produce a value that violates an invariant.
//! No field uses `skip_serializing_if`: these values are also stored through
//! the non-self-describing postcard codec.

use core::fmt::{self, Write as _};
use core::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::bytes::ByteString;
use crate::error::CoreModelError;

/// Maximum retained notice entries per operation.
pub const MAX_NOTICES: usize = 100;

/// Maximum bytes of diagnostic `detail` text kept on one notice. The detail is
/// diagnostic text, not a parser contract; the cap bounds a notice set's size
/// together with [`MAX_NOTICES`]. A path is as long as the repository path it
/// names, so the transport's own frame limit still applies to the encoded set.
pub const MAX_DETAIL_BYTES: usize = 1024;

/// Maximum bytes of a notice's language identifier.
pub const MAX_LANGUAGE_BYTES: usize = 64;

/// The content-merge strategy resolved once per logical operation.
///
/// There is deliberately no third "auto" mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MergeMode {
    /// Syntax-assisted three-way merging (the default).
    Syntax,
    /// Stock-Git content merging; bypasses every syntax adapter.
    Git,
}

impl MergeMode {
    /// The spelling used by `--merge-mode` and `ruk.mergeMode`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syntax => "syntax",
            Self::Git => "git",
        }
    }
}

impl fmt::Display for MergeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MergeMode {
    type Err = CoreModelError;

    /// Parses exactly `syntax` or `git`; any other value is invalid before
    /// any mutation can happen.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "syntax" => Ok(Self::Syntax),
            "git" => Ok(Self::Git),
            other => Err(CoreModelError::Invalid {
                what: "merge mode",
                detail: other.to_owned(),
            }),
        }
    }
}

/// The mode and grammar/adapter version that produced a merge result.
///
/// `language_set_version` starts at 1 and changes whenever grammar pins,
/// dispatch, composition, or structural merge rules change. The build-generated
/// manifest digest that accompanies it belongs to the policy-resolution tuple,
/// not to a result, and is not part of this record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "MergeMetadataFields")]
pub struct MergeMetadata {
    effective_mode: MergeMode,
    language_set_version: u32,
}

#[derive(Deserialize, JsonSchema)]
struct MergeMetadataFields {
    effective_mode: MergeMode,
    language_set_version: u32,
}

impl TryFrom<MergeMetadataFields> for MergeMetadata {
    type Error = CoreModelError;

    fn try_from(fields: MergeMetadataFields) -> Result<Self, Self::Error> {
        Self::new(fields.effective_mode, fields.language_set_version)
    }
}

impl MergeMetadata {
    /// # Errors
    /// `language_set_version` is 0; versions start at 1.
    pub fn new(
        effective_mode: MergeMode,
        language_set_version: u32,
    ) -> Result<Self, CoreModelError> {
        if language_set_version == 0 {
            return Err(CoreModelError::Invalid {
                what: "language set version",
                detail: "versions start at 1".to_owned(),
            });
        }
        Ok(Self {
            effective_mode,
            language_set_version,
        })
    }

    #[must_use]
    pub const fn effective_mode(&self) -> MergeMode {
        self.effective_mode
    }

    #[must_use]
    pub const fn language_set_version(&self) -> u32 {
        self.language_set_version
    }
}

/// Why a merge produced a notice. The serialized spelling is the plan's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NoticeCode {
    SyntaxLimit,
    SyntaxParseDeclined,
    SyntaxAmbiguous,
    SyntaxWorkerFailed,
    EmbeddedLanguageUnsupported,
    NotebookOutputsCleared,
    NotebookStructureDeclined,
}

impl NoticeCode {
    /// The serialized spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SyntaxLimit => "syntax_limit",
            Self::SyntaxParseDeclined => "syntax_parse_declined",
            Self::SyntaxAmbiguous => "syntax_ambiguous",
            Self::SyntaxWorkerFailed => "syntax_worker_failed",
            Self::EmbeddedLanguageUnsupported => "embedded_language_unsupported",
            Self::NotebookOutputsCleared => "notebook_outputs_cleared",
            Self::NotebookStructureDeclined => "notebook_structure_declined",
        }
    }
}

/// Which merge input a notice's byte range indexes into.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NoticeInput {
    Base,
    Ours,
    Theirs,
    Result,
}

impl NoticeInput {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::Ours => "ours",
            Self::Theirs => "theirs",
            Self::Result => "result",
        }
    }
}

/// A byte range inside one merge input.
///
/// Offsets index the input named by `input`, never a guessed output position.
/// The range is half-open: `start_byte..end_byte`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "NoticeRegionFields")]
pub struct NoticeRegion {
    input: NoticeInput,
    start_byte: u64,
    end_byte: u64,
}

#[derive(Deserialize, JsonSchema)]
struct NoticeRegionFields {
    input: NoticeInput,
    start_byte: u64,
    end_byte: u64,
}

impl TryFrom<NoticeRegionFields> for NoticeRegion {
    type Error = CoreModelError;

    fn try_from(fields: NoticeRegionFields) -> Result<Self, Self::Error> {
        Self::new(fields.input, fields.start_byte, fields.end_byte)
    }
}

impl NoticeRegion {
    /// # Errors
    /// `start_byte` is greater than `end_byte`.
    pub fn new(input: NoticeInput, start_byte: u64, end_byte: u64) -> Result<Self, CoreModelError> {
        if start_byte > end_byte {
            return Err(CoreModelError::Invalid {
                what: "notice region",
                detail: format!("start {start_byte} is after end {end_byte}"),
            });
        }
        Ok(Self {
            input,
            start_byte,
            end_byte,
        })
    }

    #[must_use]
    pub const fn input(&self) -> NoticeInput {
        self.input
    }

    #[must_use]
    pub const fn start_byte(&self) -> u64 {
        self.start_byte
    }

    #[must_use]
    pub const fn end_byte(&self) -> u64 {
        self.end_byte
    }
}

/// One structured merge notice, possibly coalescing many occurrences.
///
/// `path` is a byte-exact repository path. `region` and `detail` describe the
/// first (representative) occurrence; `occurrences` counts every coalesced
/// one and is at least 1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "MergeNoticeFields")]
pub struct MergeNotice {
    path: ByteString,
    region: Option<NoticeRegion>,
    language: String,
    code: NoticeCode,
    detail: String,
    occurrences: u64,
}

#[derive(Deserialize, JsonSchema)]
struct MergeNoticeFields {
    path: ByteString,
    region: Option<NoticeRegion>,
    language: String,
    code: NoticeCode,
    detail: String,
    occurrences: u64,
}

impl TryFrom<MergeNoticeFields> for MergeNotice {
    type Error = CoreModelError;

    fn try_from(fields: MergeNoticeFields) -> Result<Self, Self::Error> {
        if fields.occurrences == 0 {
            return Err(CoreModelError::Invalid {
                what: "notice occurrences",
                detail: "a retained notice has at least one occurrence".to_owned(),
            });
        }
        if fields.detail.len() > MAX_DETAIL_BYTES {
            return Err(CoreModelError::Invalid {
                what: "notice detail",
                detail: format!("{} bytes exceeds {MAX_DETAIL_BYTES}", fields.detail.len()),
            });
        }
        validate_path(&fields.path)?;
        validate_language(&fields.language)?;
        Ok(Self {
            path: fields.path,
            region: fields.region,
            language: fields.language,
            code: fields.code,
            detail: fields.detail,
            occurrences: fields.occurrences,
        })
    }
}

fn validate_path(path: &ByteString) -> Result<(), CoreModelError> {
    if path.is_empty() || path.as_bytes().contains(&0) {
        return Err(CoreModelError::Invalid {
            what: "notice path",
            detail: "must be non-empty and contain no NUL".to_owned(),
        });
    }
    Ok(())
}

fn validate_language(language: &str) -> Result<(), CoreModelError> {
    if language.is_empty()
        || language.len() > MAX_LANGUAGE_BYTES
        || !language.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(CoreModelError::Invalid {
            what: "notice language",
            detail: format!("expected 1..={MAX_LANGUAGE_BYTES} printable ASCII bytes, no spaces"),
        });
    }
    Ok(())
}

impl MergeNotice {
    /// Builds a single-occurrence notice.
    ///
    /// `detail` longer than [`MAX_DETAIL_BYTES`] is cut at a character
    /// boundary; it is diagnostic text and never parsed.
    ///
    /// # Errors
    /// An empty path or a path containing NUL, or a language that is empty,
    /// longer than [`MAX_LANGUAGE_BYTES`], or not printable ASCII.
    pub fn new(
        path: impl Into<ByteString>,
        region: Option<NoticeRegion>,
        language: impl Into<String>,
        code: NoticeCode,
        detail: impl Into<String>,
    ) -> Result<Self, CoreModelError> {
        let path = path.into();
        let language = language.into();
        validate_path(&path)?;
        validate_language(&language)?;
        let mut detail = detail.into();
        if detail.len() > MAX_DETAIL_BYTES {
            let mut end = MAX_DETAIL_BYTES;
            while !detail.is_char_boundary(end) {
                end -= 1;
            }
            detail.truncate(end);
        }
        Ok(Self {
            path,
            region,
            language,
            code,
            detail,
            occurrences: 1,
        })
    }

    #[must_use]
    pub fn path(&self) -> &ByteString {
        &self.path
    }

    #[must_use]
    pub const fn region(&self) -> Option<&NoticeRegion> {
        self.region.as_ref()
    }

    #[must_use]
    pub fn language(&self) -> &str {
        &self.language
    }

    #[must_use]
    pub const fn code(&self) -> NoticeCode {
        self.code
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// How many occurrences this entry stands for (at least 1).
    #[must_use]
    pub const fn occurrences(&self) -> u64 {
        self.occurrences
    }

    fn same_key(&self, other: &Self) -> bool {
        self.code == other.code && self.language == other.language && self.path == other.path
    }
}

/// A concise, terminal-safe one-line rendering for CLI stderr: control
/// characters in the path and detail are escaped, never emitted raw.
impl fmt::Display for MergeNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} ({})",
            self.code.as_str(),
            self.path.as_bytes().escape_ascii(),
            self.language
        )?;
        if let Some(region) = &self.region {
            write!(
                f,
                " {}[{}..{}]",
                region.input.as_str(),
                region.start_byte,
                region.end_byte
            )?;
        }
        if self.occurrences > 1 {
            write!(f, " x{}", self.occurrences)?;
        }
        if !self.detail.is_empty() {
            f.write_str(": ")?;
            for ch in self.detail.chars() {
                if ch.is_control() {
                    write!(f, "{}", ch.escape_default())?;
                } else {
                    f.write_char(ch)?;
                }
            }
        }
        Ok(())
    }
}

/// The bounded notice set of one operation: the value of the native reply
/// field `merge_notices` and the payload of the hosted `MergeNotices` event.
///
/// Invariants (enforced at every construction and on deserialization):
/// at most [`MAX_NOTICES`] entries; entry keys `(path, language, code)` are
/// unique; the entries' occurrences sum to at most `total_occurrences`; and
/// `notices_truncated` is true exactly when occurrences were not retained.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "MergeNoticesFields")]
pub struct MergeNotices {
    entries: Vec<MergeNotice>,
    notices_truncated: bool,
    total_occurrences: u64,
}

#[derive(Deserialize, JsonSchema)]
struct MergeNoticesFields {
    entries: Vec<MergeNotice>,
    notices_truncated: bool,
    total_occurrences: u64,
}

impl TryFrom<MergeNoticesFields> for MergeNotices {
    type Error = CoreModelError;

    fn try_from(fields: MergeNoticesFields) -> Result<Self, Self::Error> {
        let invalid = |detail: String| CoreModelError::Invalid {
            what: "merge notices",
            detail,
        };
        if fields.entries.len() > MAX_NOTICES {
            return Err(invalid(format!(
                "{} entries exceed the cap of {MAX_NOTICES}",
                fields.entries.len()
            )));
        }
        for (index, entry) in fields.entries.iter().enumerate() {
            if fields.entries[..index]
                .iter()
                .any(|prior| prior.same_key(entry))
            {
                return Err(invalid(format!(
                    "duplicate coalescing key for {} at entry {index}",
                    entry.code.as_str()
                )));
            }
        }
        let retained: u128 = fields
            .entries
            .iter()
            .map(|entry| u128::from(entry.occurrences))
            .sum();
        let total = u128::from(fields.total_occurrences);
        if retained > total {
            return Err(invalid(format!(
                "entries hold {retained} occurrences but the total is {total}"
            )));
        }
        if fields.notices_truncated != (total > retained) {
            return Err(invalid(
                "notices_truncated must be true exactly when occurrences were not retained"
                    .to_owned(),
            ));
        }
        Ok(Self {
            entries: fields.entries,
            notices_truncated: fields.notices_truncated,
            total_occurrences: fields.total_occurrences,
        })
    }
}

impl MergeNotices {
    #[must_use]
    pub fn entries(&self) -> &[MergeNotice] {
        &self.entries
    }

    /// True when occurrences exist that no retained entry accounts for.
    #[must_use]
    pub const fn notices_truncated(&self) -> bool {
        self.notices_truncated
    }

    /// Every occurrence recorded, retained or not.
    #[must_use]
    pub const fn total_occurrences(&self) -> u64 {
        self.total_occurrences
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_occurrences == 0
    }
}

/// Accumulates the notices of one operation across all of its files.
///
/// Per-file adapters hand their [`MergeNotices`] to [`Self::absorb`]; the
/// operation then holds one bounded set no matter how many files it touched.
#[derive(Debug, Default)]
pub struct NoticeCollector {
    entries: Vec<MergeNotice>,
    truncated: bool,
    total: u64,
}

impl NoticeCollector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a notice, coalescing it into an existing entry with the same
    /// `(path, language, code)` and applying the retention cap.
    pub fn record(&mut self, notice: MergeNotice) {
        self.total = self.total.saturating_add(notice.occurrences);
        if let Some(existing) = self.entries.iter_mut().find(|e| e.same_key(&notice)) {
            existing.occurrences = existing.occurrences.saturating_add(notice.occurrences);
            return;
        }
        if self.entries.len() < MAX_NOTICES {
            self.entries.push(notice);
            return;
        }
        self.truncated = true;
        if notice.code == NoticeCode::NotebookOutputsCleared
            && let Some(position) = self
                .entries
                .iter()
                .rposition(|e| e.code != NoticeCode::NotebookOutputsCleared)
        {
            // The evicted entry's occurrences stay counted in `total`.
            self.entries.remove(position);
            self.entries.push(notice);
        }
    }

    /// Folds another bounded set into this one, preserving its occurrence
    /// counts, its representative ranges, and the occurrences it had already
    /// dropped.
    pub fn absorb(&mut self, other: MergeNotices) {
        let retained = other
            .entries
            .iter()
            .fold(0_u64, |sum, entry| sum.saturating_add(entry.occurrences));
        let dropped = other.total_occurrences.saturating_sub(retained);
        self.truncated |= other.notices_truncated;
        for entry in other.entries {
            self.record(entry);
        }
        self.total = self.total.saturating_add(dropped);
    }

    #[must_use]
    pub fn finish(self) -> MergeNotices {
        MergeNotices {
            entries: self.entries,
            notices_truncated: self.truncated,
            total_occurrences: self.total,
        }
    }
}

/// The metadata and notices that accompany one merge or mergeability result.
///
/// A Git-mode result carries no notices: explicit Git mode bypasses every
/// syntax and notebook adapter, so a notice there would misreport which
/// driver produced the bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "MergeReportFields")]
pub struct MergeReport {
    metadata: MergeMetadata,
    merge_notices: MergeNotices,
}

#[derive(Deserialize, JsonSchema)]
struct MergeReportFields {
    metadata: MergeMetadata,
    merge_notices: MergeNotices,
}

impl TryFrom<MergeReportFields> for MergeReport {
    type Error = CoreModelError;

    fn try_from(fields: MergeReportFields) -> Result<Self, Self::Error> {
        Self::new(fields.metadata, fields.merge_notices)
    }
}

impl MergeReport {
    /// # Errors
    /// Notices accompany a `git`-mode result.
    pub fn new(
        metadata: MergeMetadata,
        merge_notices: MergeNotices,
    ) -> Result<Self, CoreModelError> {
        if metadata.effective_mode == MergeMode::Git && !merge_notices.is_empty() {
            return Err(CoreModelError::Invalid {
                what: "merge report",
                detail: "a git-mode result cannot carry syntax merge notices".to_owned(),
            });
        }
        Ok(Self {
            metadata,
            merge_notices,
        })
    }

    #[must_use]
    pub const fn metadata(&self) -> &MergeMetadata {
        &self.metadata
    }

    #[must_use]
    pub const fn merge_notices(&self) -> &MergeNotices {
        &self.merge_notices
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn notice(path: &str, language: &str, code: NoticeCode) -> MergeNotice {
        MergeNotice::new(path, None, language, code, "detail").expect("valid notice")
    }

    fn finish(notices: Vec<MergeNotice>) -> MergeNotices {
        let mut collector = NoticeCollector::new();
        for entry in notices {
            collector.record(entry);
        }
        collector.finish()
    }

    fn cap() -> u64 {
        u64::try_from(MAX_NOTICES).expect("cap fits u64")
    }

    fn retained(notices: &MergeNotices) -> u64 {
        notices.entries().iter().map(MergeNotice::occurrences).sum()
    }

    #[test]
    fn repeated_notices_coalesce_and_keep_the_first_range() {
        let first = NoticeRegion::new(NoticeInput::Ours, 10, 20).expect("region");
        let later = NoticeRegion::new(NoticeInput::Theirs, 90, 99).expect("region");
        let mut collector = NoticeCollector::new();
        collector.record(
            MergeNotice::new(
                "a.rs",
                Some(first),
                "rust",
                NoticeCode::SyntaxAmbiguous,
                "first",
            )
            .expect("notice"),
        );
        collector.record(
            MergeNotice::new(
                "a.rs",
                Some(later),
                "rust",
                NoticeCode::SyntaxAmbiguous,
                "later",
            )
            .expect("notice"),
        );
        collector.record(notice("a.rs", "rust", NoticeCode::SyntaxLimit));
        collector.record(notice("a.rs", "python", NoticeCode::SyntaxAmbiguous));
        collector.record(notice("b.rs", "rust", NoticeCode::SyntaxAmbiguous));
        let merged = collector.finish();

        assert_eq!(merged.entries().len(), 4);
        assert_eq!(merged.total_occurrences(), 5);
        assert!(!merged.notices_truncated());
        let representative = &merged.entries()[0];
        assert_eq!(representative.occurrences(), 2);
        assert_eq!(representative.region(), Some(&first));
        assert_eq!(representative.detail(), "first");
    }

    #[test]
    fn cap_counts_but_does_not_retain_the_overflow() {
        let mut collector = NoticeCollector::new();
        for index in 0..=MAX_NOTICES {
            collector.record(notice(
                &format!("f{index}.rs"),
                "rust",
                NoticeCode::SyntaxLimit,
            ));
        }
        // A repeat of a dropped key stays dropped but is still counted.
        collector.record(notice(
            &format!("f{MAX_NOTICES}.rs"),
            "rust",
            NoticeCode::SyntaxLimit,
        ));
        let merged = collector.finish();
        assert_eq!(merged.entries().len(), MAX_NOTICES);
        assert!(merged.notices_truncated());
        assert_eq!(merged.total_occurrences(), cap() + 2);
        assert_eq!(retained(&merged), cap());
    }

    #[test]
    fn output_clearing_survives_a_full_set_by_evicting_another_code() {
        let mut collector = NoticeCollector::new();
        for index in 0..MAX_NOTICES {
            collector.record(notice(
                &format!("f{index}.rs"),
                "rust",
                NoticeCode::SyntaxLimit,
            ));
        }
        collector.record(notice(
            "n.ipynb",
            "python",
            NoticeCode::NotebookOutputsCleared,
        ));
        let merged = collector.finish();
        assert_eq!(merged.entries().len(), MAX_NOTICES);
        assert!(merged.notices_truncated());
        assert_eq!(merged.total_occurrences(), cap() + 1);
        let cleared = merged.entries().last().expect("last entry");
        assert_eq!(cleared.code(), NoticeCode::NotebookOutputsCleared);
        // The newest other-code entry was the one displaced.
        assert!(
            !merged
                .entries()
                .iter()
                .any(|e| e.path().as_bytes() == format!("f{}.rs", MAX_NOTICES - 1).as_bytes())
        );
    }

    #[test]
    fn output_clearing_is_dropped_only_when_the_set_is_all_clearing() {
        let mut collector = NoticeCollector::new();
        for index in 0..MAX_NOTICES {
            collector.record(notice(
                &format!("n{index}.ipynb"),
                "python",
                NoticeCode::NotebookOutputsCleared,
            ));
        }
        collector.record(notice(
            "late.ipynb",
            "python",
            NoticeCode::NotebookOutputsCleared,
        ));
        let merged = collector.finish();
        assert_eq!(merged.entries().len(), MAX_NOTICES);
        assert!(merged.notices_truncated());
        assert_eq!(merged.total_occurrences(), cap() + 1);
        assert!(
            !merged
                .entries()
                .iter()
                .any(|e| e.path().as_bytes() == b"late.ipynb")
        );
    }

    #[test]
    fn absorb_carries_counts_ranges_and_prior_truncation() {
        let mut file_a = NoticeCollector::new();
        for index in 0..=MAX_NOTICES {
            file_a.record(notice(
                &format!("a{index}.rs"),
                "rust",
                NoticeCode::SyntaxLimit,
            ));
        }
        let file_a = file_a.finish();
        assert!(file_a.notices_truncated());

        let mut file_b = NoticeCollector::new();
        file_b.record(notice("b.rs", "rust", NoticeCode::SyntaxLimit));
        file_b.record(notice("b.rs", "rust", NoticeCode::SyntaxLimit));
        let file_b = file_b.finish();

        let mut operation = NoticeCollector::new();
        operation.absorb(file_b);
        operation.absorb(file_a);
        let merged = operation.finish();
        assert!(merged.notices_truncated());
        assert_eq!(merged.total_occurrences(), 2 + cap() + 1);
        assert_eq!(merged.entries()[0].occurrences(), 2);
        assert!(merged.entries().len() <= MAX_NOTICES);
        // The set a plain round trip would validate.
        let json = serde_json::to_string(&merged).expect("serialize");
        assert_eq!(
            serde_json::from_str::<MergeNotices>(&json).expect("parse"),
            merged
        );
    }

    #[test]
    fn detail_is_truncated_on_a_character_boundary() {
        let detail = "é".repeat(MAX_DETAIL_BYTES);
        let built = MergeNotice::new("a.rs", None, "rust", NoticeCode::SyntaxLimit, detail)
            .expect("notice");
        assert!(built.detail().len() <= MAX_DETAIL_BYTES);
        assert!(built.detail().chars().all(|ch| ch == 'é'));
    }

    #[test]
    fn constructors_reject_unusable_identity_fields() {
        let make = |path: &[u8], language: &str| {
            MergeNotice::new(path, None, language, NoticeCode::SyntaxLimit, "")
        };
        assert!(make(b"", "rust").is_err());
        assert!(make(b"a\0b", "rust").is_err());
        assert!(make(b"a.rs", "").is_err());
        assert!(make(b"a.rs", "has space").is_err());
        assert!(make(b"a.rs", &"x".repeat(MAX_LANGUAGE_BYTES + 1)).is_err());
        assert!(make(b"a.rs", &"x".repeat(MAX_LANGUAGE_BYTES)).is_ok());
        assert!(NoticeRegion::new(NoticeInput::Base, 5, 4).is_err());
        assert!(NoticeRegion::new(NoticeInput::Base, 5, 5).is_ok());
    }

    #[test]
    fn non_utf8_paths_survive_json_exactly() {
        let path = vec![b'd', b'/', 0xff, 0xfe, b'.', b'm', b'd'];
        let built = MergeNotice::new(
            path.clone(),
            None,
            "markdown",
            NoticeCode::EmbeddedLanguageUnsupported,
            "info string",
        )
        .expect("notice");
        let json = serde_json::to_string(&built).expect("serialize");
        assert!(json.contains("\"hex\""), "{json}");
        let back: MergeNotice = serde_json::from_str(&json).expect("parse");
        assert_eq!(back.path().as_bytes(), path.as_slice());
        assert_eq!(back, built);
    }

    #[test]
    fn wire_form_uses_the_plan_spellings() {
        let region = NoticeRegion::new(NoticeInput::Result, 1, 2).expect("region");
        let built = MergeNotice::new(
            "n.ipynb",
            Some(region),
            "python",
            NoticeCode::NotebookOutputsCleared,
            "cells c1",
        )
        .expect("notice");
        let value: serde_json::Value = serde_json::to_value(finish(vec![built])).expect("value");
        assert_eq!(value["notices_truncated"], false);
        assert_eq!(value["total_occurrences"], 1);
        let entry = &value["entries"][0];
        assert_eq!(entry["code"], "notebook_outputs_cleared");
        assert_eq!(entry["region"]["input"], "result");
        assert_eq!(entry["path"], "n.ipynb");
        assert_eq!(entry["occurrences"], 1);
    }

    #[test]
    fn deserialization_rejects_every_broken_invariant() {
        let entry = |path: &str, occurrences: u64| {
            format!(
                "{{\"path\":\"{path}\",\"region\":null,\"language\":\"rust\",\
                 \"code\":\"syntax_limit\",\"detail\":\"\",\"occurrences\":{occurrences}}}"
            )
        };
        let set = |entries: &str, truncated: bool, total: u64| {
            format!(
                "{{\"entries\":[{entries}],\"notices_truncated\":{truncated},\
                 \"total_occurrences\":{total}}}"
            )
        };
        let parse = |json: &str| serde_json::from_str::<MergeNotices>(json);

        assert!(parse(&set(&entry("a", 2), false, 2)).is_ok());
        assert!(parse(&set(&entry("a", 2), true, 5)).is_ok());
        // Zero occurrences.
        assert!(parse(&set(&entry("a", 0), false, 0)).is_err());
        // Entries exceed the declared total.
        assert!(parse(&set(&entry("a", 3), false, 2)).is_err());
        // Truncation flag contradicts the counts, both directions.
        assert!(parse(&set(&entry("a", 1), true, 1)).is_err());
        assert!(parse(&set(&entry("a", 1), false, 2)).is_err());
        // Duplicate coalescing key.
        let twice = format!("{},{}", entry("a", 1), entry("a", 1));
        assert!(parse(&set(&twice, false, 2)).is_err());
        // Over the cap.
        let many = (0..=MAX_NOTICES)
            .map(|index| entry(&format!("f{index}"), 1))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse(&set(&many, false, cap() + 1)).is_err());
        // Unknown code and an inverted region.
        let unknown = entry("a", 1).replace("syntax_limit", "syntax_whatever");
        assert!(parse(&set(&unknown, false, 1)).is_err());
        let inverted = entry("a", 1).replace(
            "\"region\":null",
            "\"region\":{\"input\":\"base\",\"start_byte\":9,\"end_byte\":3}",
        );
        assert!(parse(&set(&inverted, false, 1)).is_err());
    }

    #[test]
    fn metadata_and_report_enforce_their_contract() {
        assert!(MergeMetadata::new(MergeMode::Syntax, 0).is_err());
        assert!(
            serde_json::from_str::<MergeMetadata>(
                "{\"effective_mode\":\"syntax\",\"language_set_version\":0}"
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<MergeMetadata>(
                "{\"effective_mode\":\"auto\",\"language_set_version\":1}"
            )
            .is_err()
        );
        let syntax = MergeMetadata::new(MergeMode::Syntax, 1).expect("syntax");
        let git = MergeMetadata::new(MergeMode::Git, 1).expect("git");
        let some = finish(vec![notice("a.rs", "rust", NoticeCode::SyntaxLimit)]);

        assert!(MergeReport::new(syntax, some.clone()).is_ok());
        assert!(MergeReport::new(git, MergeNotices::default()).is_ok());
        assert!(MergeReport::new(git, some.clone()).is_err());

        let report = MergeReport::new(syntax, some).expect("report");
        let json = serde_json::to_string(&report).expect("serialize");
        assert_eq!(
            serde_json::from_str::<MergeReport>(&json).expect("parse"),
            report
        );
        let stored = postcard::to_allocvec(&report).expect("postcard serialize");
        assert_eq!(
            postcard::from_bytes::<MergeReport>(&stored).expect("postcard parse"),
            report
        );
        let forged = json.replace("\"syntax\"", "\"git\"");
        assert!(serde_json::from_str::<MergeReport>(&forged).is_err());
    }

    #[test]
    fn merge_mode_parses_only_the_two_spellings() {
        assert_eq!(
            "syntax".parse::<MergeMode>().expect("syntax"),
            MergeMode::Syntax
        );
        assert_eq!("git".parse::<MergeMode>().expect("git"), MergeMode::Git);
        for bad in ["", "Syntax", "GIT", "auto", " git"] {
            assert!(bad.parse::<MergeMode>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn display_escapes_terminal_control_characters() {
        let region = NoticeRegion::new(NoticeInput::Ours, 3, 9).expect("region");
        let built = MergeNotice::new(
            b"a\x1b[2Jb.md".to_vec(),
            Some(region),
            "markdown",
            NoticeCode::EmbeddedLanguageUnsupported,
            "label \x1b[31mred\nnext",
        )
        .expect("notice");
        let text = built.to_string();
        assert!(!text.contains('\x1b'), "{text:?}");
        assert!(!text.contains('\n'), "{text:?}");
        assert!(
            text.starts_with("embedded_language_unsupported: a\\x1b[2Jb.md (markdown) ours[3..9]")
        );
    }

    fn code_strategy() -> impl Strategy<Value = NoticeCode> {
        prop_oneof![
            Just(NoticeCode::SyntaxLimit),
            Just(NoticeCode::SyntaxParseDeclined),
            Just(NoticeCode::SyntaxAmbiguous),
            Just(NoticeCode::SyntaxWorkerFailed),
            Just(NoticeCode::EmbeddedLanguageUnsupported),
            Just(NoticeCode::NotebookOutputsCleared),
            Just(NoticeCode::NotebookStructureDeclined),
        ]
    }

    fn notices_strategy() -> impl Strategy<Value = Vec<MergeNotice>> {
        proptest::collection::vec(
            (
                0_u32..140,
                0_u32..2,
                code_strategy(),
                proptest::option::of(0_u64..50),
            ),
            0..400,
        )
        .prop_map(|raw| {
            raw.into_iter()
                .map(|(path, language, code, start)| {
                    let region = start
                        .map(|start| NoticeRegion::new(NoticeInput::Base, start, start + 1))
                        .transpose()
                        .expect("region");
                    MergeNotice::new(
                        format!("p{path}"),
                        region,
                        format!("l{language}"),
                        code,
                        "d",
                    )
                    .expect("notice")
                })
                .collect::<Vec<_>>()
        })
    }

    proptest! {
        #[test]
        fn collection_accounts_for_every_occurrence(notices in notices_strategy()) {
            let count = u64::try_from(notices.len()).expect("length fits u64");
            let cleared_keys: std::collections::HashSet<(Vec<u8>, String)> = notices
                .iter()
                .filter(|n| n.code() == NoticeCode::NotebookOutputsCleared)
                .map(|n| (n.path().as_bytes().to_vec(), n.language().to_owned()))
                .collect();
            let merged = finish(notices);

            prop_assert!(merged.entries().len() <= MAX_NOTICES);
            prop_assert_eq!(merged.total_occurrences(), count);
            prop_assert_eq!(merged.notices_truncated(), merged.total_occurrences() > retained(&merged));
            for (index, entry) in merged.entries().iter().enumerate() {
                prop_assert!(!merged.entries()[..index].iter().any(|p| p.same_key(entry)));
            }
            if cleared_keys.len() <= MAX_NOTICES {
                for (path, language) in &cleared_keys {
                    let retained_cleared = merged.entries().iter().any(|e| {
                        e.code() == NoticeCode::NotebookOutputsCleared
                            && e.path().as_bytes() == path.as_slice()
                            && e.language() == language
                    });
                    prop_assert!(
                        retained_cleared,
                        "notebook-outputs-cleared notice retained for {path:?} {language:?}",
                        path = path,
                        language = language
                    );
                }
            }
            let json = serde_json::to_string(&merged).expect("serialize");
            prop_assert_eq!(serde_json::from_str::<MergeNotices>(&json).expect("parse"), merged);
        }

        #[test]
        fn absorbing_per_file_sets_accounts_for_every_occurrence(
            first in notices_strategy(),
            second in notices_strategy(),
        ) {
            let count = u64::try_from(first.len() + second.len()).expect("length fits u64");
            let mut operation = NoticeCollector::new();
            operation.absorb(finish(first));
            operation.absorb(finish(second));
            let merged = operation.finish();

            prop_assert!(merged.entries().len() <= MAX_NOTICES);
            prop_assert_eq!(merged.total_occurrences(), count);
            prop_assert_eq!(merged.notices_truncated(), merged.total_occurrences() > retained(&merged));
            let json = serde_json::to_string(&merged).expect("serialize");
            prop_assert_eq!(serde_json::from_str::<MergeNotices>(&json).expect("parse"), merged);
        }
    }
}
