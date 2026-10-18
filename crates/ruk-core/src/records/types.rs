//! Typed records models and page structures.
//!
//! Owns definitions of:
//! - [`ChangeState`] and [`ChangeEntry`] for `FactTable::Changes`
//! - [`ChangeHistoryEntry`] for `FactTable::ChangeHistory`
//! - [`ImportedChangeEntry`] for `FactTable::ImportedChanges`
//! - Paging budgets and results ([`RecordPageBudget`], [`RecordPage`], [`HistoryPage`])
//! - Prepared results ([`PreparedNativeCommit`], [`PreparedImport`], [`PreparedRecordBatch`])
//! - [`ImportOutcome`] for Git import operations

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::MAX_CONTROL_FRAME_BYTES;
use crate::change::ChangeId;
use crate::commit::CommitRecord;
use crate::error::{CoreError, CoreModelError, ErrorCode};
use crate::heads::Head;
use crate::ids::HashKind;
use crate::store::{FactMutation, PreparedObject};

/// Status of a logical change in Ruk.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum ChangeState {
    Active,
    Abandoned,
}

/// A stored change entry in `FactTable::Changes`.
///
/// Contains the change state and its current heads. When multiple current heads
/// exist, the change is divergent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ChangeEntry {
    pub state: ChangeState,
    pub heads: Vec<Head>,
}

impl ChangeEntry {
    /// Creates a new change entry with a single initial head.
    #[must_use]
    pub fn new(state: ChangeState, head: Head) -> Self {
        Self {
            state,
            heads: vec![head],
        }
    }

    /// Whether this change has multiple current heads (divergence).
    #[must_use]
    pub fn is_divergent(&self) -> bool {
        self.heads.len() > 1
    }

    /// Whether this change currently contains `head`.
    #[must_use]
    pub fn contains_head(&self, head: &Head) -> bool {
        self.heads.contains(head)
    }

    /// Adds a head to this change entry if not already present.
    ///
    /// Preserves sorted order. Fails with [`ErrorCode::ELimit`] if the resulting
    /// serialized entry exceeds the control frame row limit ([`MAX_CONTROL_FRAME_BYTES`]).
    /// Returns `Ok(true)` if added, or `Ok(false)` if already present.
    pub fn add_head(&mut self, head: Head) -> Result<bool, CoreError> {
        if self.contains_head(&head) {
            return Ok(false);
        }
        self.heads.push(head);
        self.heads.sort_unstable();

        let encoded_len = self.estimated_encoded_len();
        if encoded_len > MAX_CONTROL_FRAME_BYTES {
            // Revert insertion before failing
            self.heads.retain(|h| *h != head);
            return Err(CoreError::new(
                ErrorCode::ELimit,
                format!(
                    "change entry heads list exceeds maximum row capacity of {MAX_CONTROL_FRAME_BYTES} bytes"
                ),
            ));
        }
        Ok(true)
    }

    /// Replaces an existing current head with a new head (local rewrite).
    ///
    /// # Errors
    /// [`ErrorCode::EStale`] if `old_head` is not found among current heads.
    /// [`ErrorCode::ELimit`] if the updated entry exceeds [`MAX_CONTROL_FRAME_BYTES`].
    pub fn replace_head(&mut self, old_head: &Head, new_head: Head) -> Result<(), CoreError> {
        let Some(pos) = self.heads.iter().position(|h| h == old_head) else {
            return Err(CoreError::new(
                ErrorCode::EStale,
                format!("predecessor head {old_head:?} is not a current head of this change"),
            ));
        };

        self.heads.remove(pos);
        if !self.heads.contains(&new_head) {
            self.heads.push(new_head);
            self.heads.sort_unstable();
        }
        Ok(())
    }

    /// Marks this change as abandoned.
    pub fn abandon(&mut self) {
        self.state = ChangeState::Abandoned;
    }

    /// Validates internal semantic invariants against the repository hash kind.
    ///
    /// A headless entry is valid only when abandoned: `abandon` drains the
    /// last head and flips the state, so stored `Abandoned` rows legitimately
    /// carry no heads. A headless `Active` entry is corruption.
    ///
    /// # Errors
    /// [`CoreModelError::Invalid`] if an `Active` entry has no `heads`, or if
    /// `heads` has duplicates.
    /// [`CoreModelError::ObjectFormat`] if any head has an invalid width.
    pub fn validate(&self, kind: HashKind) -> Result<(), CoreModelError> {
        if self.heads.is_empty() && self.state != ChangeState::Abandoned {
            return Err(CoreModelError::Invalid {
                what: "change entry",
                detail: "change entry must have at least one head".to_owned(),
            });
        }
        for (i, head) in self.heads.iter().enumerate() {
            head.validate(kind)?;
            if self.heads[..i].contains(head) {
                return Err(CoreModelError::Invalid {
                    what: "change entry",
                    detail: format!("duplicate head {head:?} in change entry"),
                });
            }
        }
        Ok(())
    }

    /// Estimated serialized postcard byte length of this entry.
    #[must_use]
    fn estimated_encoded_len(&self) -> usize {
        // Postcard enum discriminant (1 byte) + vec varint len (up to 5 bytes)
        // + each head (~33 bytes)
        1 + 5 + (self.heads.len() * 34)
    }
}

/// Value stored in `FactTable::ChangeHistory` representing `(ChangeId, Head)` membership.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ChangeHistoryEntry;

/// Value stored in `FactTable::ImportedChanges` mapping an imported OID to a local ChangeId.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ImportedChangeEntry {
    pub change_id: ChangeId,
}

/// Bounded limits for a records page query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordPageBudget {
    pub rows: usize,
    pub bytes: usize,
}

impl RecordPageBudget {
    /// Creates a budget with explicit row and byte upper limits.
    #[must_use]
    pub const fn new(rows: usize, bytes: usize) -> Self {
        Self { rows, bytes }
    }
}

/// A bounded page of records with continuation state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordPage<K, V> {
    pub items: Vec<(K, V)>,
    pub more: bool,
    pub next_cursor: Option<K>,
}

/// Bounded page of change history heads with continuation state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryPage {
    pub heads: Vec<Head>,
    pub more: bool,
    pub next_cursor: Option<Head>,
}

/// Outcome of preparing a single native commit creation or trusted local rewrite.
pub struct PreparedNativeCommit {
    pub head: Head,
    pub record: CommitRecord,
    pub prepared_object: PreparedObject,
    pub mutations: Vec<FactMutation>,
}

/// Outcome of preparing an imported Git commit payload.
pub struct PreparedImport {
    pub head: Head,
    pub change_id: ChangeId,
    pub record: CommitRecord,
    pub is_divergent: bool,
    pub prepared_object: PreparedObject,
    pub mutations: Vec<FactMutation>,
}

/// Prepared artifacts for a multi-record batch publication.
pub struct PreparedRecordBatch {
    pub prepared_objects: Vec<PreparedObject>,
    pub mutations: Vec<FactMutation>,
}

/// Outcome of observing an imported Git commit within an import batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportOutcome {
    /// Exact head already known in this change; no new mutations emitted.
    Known { head: Head, change_id: ChangeId },
    /// Created a new change entry for this head.
    NewChange { head: Head, change_id: ChangeId },
    /// Added a divergent head to an existing change entry.
    Divergent { head: Head, change_id: ChangeId },
}

impl ImportOutcome {
    #[must_use]
    pub const fn head(&self) -> Head {
        match *self {
            Self::Known { head, .. }
            | Self::NewChange { head, .. }
            | Self::Divergent { head, .. } => head,
        }
    }

    #[must_use]
    pub const fn change_id(&self) -> ChangeId {
        match *self {
            Self::Known { change_id, .. }
            | Self::NewChange { change_id, .. }
            | Self::Divergent { change_id, .. } => change_id,
        }
    }

    #[must_use]
    pub const fn is_known(&self) -> bool {
        matches!(self, Self::Known { .. })
    }

    #[must_use]
    pub const fn is_divergent(&self) -> bool {
        matches!(self, Self::Divergent { .. })
    }
}
