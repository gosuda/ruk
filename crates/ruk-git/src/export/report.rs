//! The export loss report.
//!
//! Export writes Git state only. Everything else the store holds is named
//! here, one entry per [`LossCategory`], each listed even when empty so a
//! reader never has to infer that a category was considered. Fact tables
//! reach a category only through [`disposition`], an exhaustive match: a
//! new table does not compile until it is classified as exported or lost.

use std::path::Path;

use ruk_core::ByteString;
use ruk_core::MAX_CONTROL_FRAME_BYTES;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::RefName;
use ruk_core::store::{FactPageBudget, FactTable, Store};
use ruk_core::workspace::HeadRef;
use serde::Serialize;

use super::objects::NativeReason;
use crate::GitError;

/// Version of the report document.
pub const REPORT_VERSION: u32 = 1;
/// Keys named per loss category; the row count is always complete.
pub const SAMPLE_KEYS: usize = 100;
/// Rows read per page while counting a table.
const PAGE_ROWS: usize = 1000;
/// The capability policy file inside the store directory.
const POLICY_FILE: &str = "policy.toml";

/// A class of native state that a Git repository cannot carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LossCategory {
    /// Unresolved native ref conflicts (conflicted bookmarks).
    RefConflicts,
    /// Last-observed remote state used for three-way tracking merges.
    RemoteTracking,
    /// Change ids, change history, imported-change mapping, commit records.
    ChangeMetadata,
    /// The operation log and its head (undo history).
    OperationLog,
    /// Workspaces, their index, status, directory and apply journals.
    Workspaces,
    /// Path claims.
    Claims,
    /// Sessions, receipts, and leases.
    Coordination,
    /// Verified attestation rows. A `refs/notes/ruk-attest` ref, when the
    /// store has one, is exported as an ordinary ref.
    Attestations,
    /// Push plans, land plans, and published-head records.
    Publication,
    /// Retention pins.
    RetentionPins,
    /// Promisor records of objects a partial clone omitted. The export
    /// fails instead of omitting one inside its closure; this counts the
    /// records outside it.
    Promisor,
    /// LFS payload presence rows. Payload bytes live outside the object
    /// graph in the sidecar, so only the presence rows are lost here.
    LfsObjects,
    /// The coordinator capability policy file (`policy.toml`).
    CapabilityPolicy,
}

impl LossCategory {
    /// Every category, in report order.
    pub const ALL: [Self; 13] = [
        Self::RefConflicts,
        Self::RemoteTracking,
        Self::ChangeMetadata,
        Self::OperationLog,
        Self::Workspaces,
        Self::Claims,
        Self::Coordination,
        Self::Attestations,
        Self::Publication,
        Self::RetentionPins,
        Self::Promisor,
        Self::LfsObjects,
        Self::CapabilityPolicy,
    ];
}

/// How export treats one fact table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Written to the Git repository (refs, reflogs, shallow boundaries);
    /// rows that cannot be written are named individually in the report.
    Exported,
    /// Not representable in Git; counted under the category.
    Lost(LossCategory),
}

/// The export treatment of `table`. Exhaustive by construction.
#[must_use]
pub const fn disposition(table: FactTable) -> Disposition {
    use Disposition::{Exported, Lost};
    use LossCategory as L;
    match table {
        FactTable::Refs | FactTable::Reflogs | FactTable::Shallow => Exported,
        FactTable::RefConflicts => Lost(L::RefConflicts),
        FactTable::RemoteObservations => Lost(L::RemoteTracking),
        FactTable::Changes
        | FactTable::ImportedChanges
        | FactTable::ChangeHistory
        | FactTable::Commits => Lost(L::ChangeMetadata),
        FactTable::Ops | FactTable::OpHead | FactTable::Events | FactTable::EventHead => {
            Lost(L::OperationLog)
        }
        FactTable::Workspaces
        | FactTable::WsIndex
        | FactTable::WsStatus
        | FactTable::WsDirs
        | FactTable::WsApply => Lost(L::Workspaces),
        FactTable::Claims => Lost(L::Claims),
        FactTable::Receipts
        | FactTable::Sessions
        | FactTable::Leases
        | FactTable::ServiceReceipts
        | FactTable::RepoMeta => Lost(L::Coordination),
        FactTable::Attestations => Lost(L::Attestations),
        FactTable::PushPlans
        | FactTable::LandPlans
        | FactTable::PublishedHeads
        | FactTable::ReleasedTags => Lost(L::Publication),
        FactTable::Pins => Lost(L::RetentionPins),
        FactTable::Promisor => Lost(L::Promisor),
        FactTable::LfsObjects => Lost(L::LfsObjects),
    }
}

/// One loss category's census.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Loss {
    pub category: LossCategory,
    /// Every row of every table in the category (1 for a present policy
    /// file).
    pub rows: u64,
    /// The first keys in table order, at most [`SAMPLE_KEYS`].
    pub sample_keys: Vec<ByteString>,
    /// Whether `rows` exceeds the sample.
    pub sample_truncated: bool,
}

/// Why one ref was not written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnexportedReason {
    /// The ref has an unresolved native conflict.
    Conflicted,
    /// The ref names a native record.
    NativeRecord,
    /// The ref's closure reaches a native record.
    NativeInClosure,
    /// A symbolic ref whose chain ends at a ref that was not exported.
    SymbolicToUnexported,
}

impl From<NativeReason> for UnexportedReason {
    fn from(reason: NativeReason) -> Self {
        match reason {
            NativeReason::NativeRecord => Self::NativeRecord,
            NativeReason::NativeInClosure => Self::NativeInClosure,
        }
    }
}

/// A ref present in the store and absent from the export.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UnexportedRef {
    pub name: RefName,
    pub reason: UnexportedReason,
    /// The native object found, for native reasons.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid: Option<Oid>,
    /// Number of terms of the conflict, for a conflicted ref.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms: Option<usize>,
}

/// A reflog entry that was not written, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReflogDropReason {
    /// The ref itself was not exported.
    RefNotExported,
    /// The message contains a newline, which the line format cannot carry.
    MultiLineMessage,
}

/// Reflog entries of one ref that were not written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DroppedReflog {
    pub name: RefName,
    pub reason: ReflogDropReason,
    pub entries: u64,
}

/// The repository HEAD as written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HeadReport {
    pub target: HeadRef,
    /// False when a symbolic HEAD names a ref that was not exported (Git
    /// then sees an unborn branch).
    pub exported: bool,
}

/// The written pack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PackReport {
    /// File stem: `pack-<hex>`.
    pub name: String,
    pub objects: u64,
    pub checksum: Oid,
}

/// Counts of written refs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RefsReport {
    /// Direct refs in `packed-refs`.
    pub packed: u64,
    /// Symbolic refs written as loose files.
    pub symbolic: u64,
}

/// Written and dropped reflog entries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ReflogsReport {
    pub refs: u64,
    pub entries: u64,
    pub dropped: Vec<DroppedReflog>,
}

/// Everything an administrator needs before using the export: what was
/// written, and every fact that was not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExportReport {
    pub version: u32,
    pub object_format: &'static str,
    pub head: HeadReport,
    pub pack: PackReport,
    pub refs: RefsReport,
    pub reflogs: ReflogsReport,
    /// Shallow boundary commits written to `shallow`.
    pub shallow: Vec<Oid>,
    pub unexported_refs: Vec<UnexportedRef>,
    pub losses: Vec<Loss>,
}

impl ExportReport {
    /// Whether the export dropped anything at all. A shallow export is
    /// never lossless: ancestors above the boundaries are absent.
    #[must_use]
    pub fn is_lossless(&self) -> bool {
        self.unexported_refs.is_empty()
            && self.reflogs.dropped.is_empty()
            && self.shallow.is_empty()
            && self.losses.iter().all(|loss| loss.rows == 0)
    }
}

/// The report spelling of a hash kind, as in Git's `objectformat`.
#[must_use]
pub const fn object_format(kind: HashKind) -> &'static str {
    match kind {
        HashKind::Sha1 => "sha1",
        HashKind::Sha256 => "sha256",
    }
}

/// Censuses every lost table and the policy file.
///
/// # Errors
/// Store failures while paging.
pub(crate) fn census(store: &Store, store_root: &Path) -> Result<Vec<Loss>, GitError> {
    let mut losses: Vec<Loss> = LossCategory::ALL
        .iter()
        .map(|&category| Loss {
            category,
            rows: 0,
            sample_keys: Vec::new(),
            sample_truncated: false,
        })
        .collect();
    for table in FactTable::ALL {
        let Disposition::Lost(category) = disposition(table) else {
            continue;
        };
        let Some(loss) = losses.iter_mut().find(|loss| loss.category == category) else {
            continue;
        };
        scan_table(store, table, loss)?;
    }
    let policy = store_root.join(POLICY_FILE);
    let present = std::fs::symlink_metadata(&policy)
        .map(|_| true)
        .or_else(|err| match err.kind() {
            std::io::ErrorKind::NotFound => Ok(false),
            _ => Err(super::pack::io_error(err)),
        })?;
    if present
        && let Some(loss) = losses
            .iter_mut()
            .find(|loss| loss.category == LossCategory::CapabilityPolicy)
    {
        loss.rows = 1;
        loss.sample_keys.push(ByteString::from(POLICY_FILE));
    }
    Ok(losses)
}

/// Counts every row of `table` into `loss`, sampling the first keys.
fn scan_table(store: &Store, table: FactTable, loss: &mut Loss) -> Result<(), GitError> {
    let mut after: Option<Vec<u8>> = None;
    loop {
        let budget = FactPageBudget::new(PAGE_ROWS, MAX_CONTROL_FRAME_BYTES);
        let page = store.fact_page(table, after.as_deref(), budget)?;
        for row in &page.rows {
            loss.rows = loss.rows.saturating_add(1);
            if loss.sample_keys.len() < SAMPLE_KEYS {
                loss.sample_keys.push(ByteString::from(row.key.as_slice()));
            } else {
                loss.sample_truncated = true;
            }
        }
        if !page.more {
            return Ok(());
        }
        let Some(last) = page.rows.into_iter().next_back() else {
            return Ok(());
        };
        after = Some(last.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_table_has_a_disposition_and_every_category_a_table_or_file() {
        let mut categories: Vec<LossCategory> = FactTable::ALL
            .iter()
            .filter_map(|&table| match disposition(table) {
                Disposition::Lost(category) => Some(category),
                Disposition::Exported => None,
            })
            .collect();
        categories.push(LossCategory::CapabilityPolicy);
        categories.sort();
        categories.dedup();
        let mut all = LossCategory::ALL.to_vec();
        all.sort();
        assert_eq!(categories, all);
    }

    #[test]
    fn exported_tables_are_exactly_refs_reflogs_shallow() {
        let exported: Vec<FactTable> = FactTable::ALL
            .iter()
            .copied()
            .filter(|&table| disposition(table) == Disposition::Exported)
            .collect();
        assert_eq!(
            exported,
            vec![FactTable::Refs, FactTable::Reflogs, FactTable::Shallow]
        );
    }
}
