//! Commit bridge: verified Git payloads into the native records boundary.
//!
//! Every commit the walk emits is already re-hashed; this module observes
//! its payload through [`ruk_core::records::ImportBatch`], which preserves
//! the exact bytes and header order, mints no predecessor, and stages the
//! commit object itself. The batch returns one [`CommitTally`] per commit:
//! known OIDs are idempotent, declared `change-id` headers map to their
//! change, new OIDs with a known change-id diverge, and commits without a
//! usable change-id (absent or non-canonical, e.g. repeated) receive the
//! stable by-OID mapping and are reported as non-canonical when a header
//! was present but unusable.

use ruk_core::change::ChangeId;
use ruk_core::heads::Head;
use ruk_core::ids::Oid;
use ruk_core::records::{ImportBatch, ImportOutcome};

use crate::GitError;

/// Per-commit import outcome, in emission order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitTally {
    /// Commits whose exact OID was already known: no new facts.
    pub known: Vec<Oid>,
    /// Commits that opened a fresh change.
    pub new_changes: Vec<(ChangeId, Oid)>,
    /// Commits that added a divergent head to a known change.
    pub divergent: Vec<(ChangeId, Oid)>,
    /// Commits that carried a `change-id` header which was not exactly one
    /// well-formed value, so identity fell back to the by-OID mapping.
    pub noncanonical_change_ids: Vec<Oid>,
}

impl CommitTally {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            known: Vec::new(),
            new_changes: Vec::new(),
            divergent: Vec::new(),
            noncanonical_change_ids: Vec::new(),
        }
    }
}

/// Observes one verified commit payload: the staged object and its record
/// facts join the batch, and the outcome joins `tally`.
///
/// # Errors
/// [`GitError::Corrupt`] when the head is not the expected OID or the
/// payload is not a well-formed commit; record-boundary failures as their
/// own codes.
pub(crate) fn observe_commit(
    batch: &mut ImportBatch<'_>,
    oid: Oid,
    payload: Vec<u8>,
    tally: &mut CommitTally,
) -> Result<(), GitError> {
    let usable = ruk_core::commit::CommitRecord::git_header_change_id(&payload);
    let noncanonical = usable.is_none() && has_change_id_header(&payload);
    let outcome = batch
        .observe_git_payload(payload, None)
        .map_err(GitError::from)?;
    let (head, change_id) = match outcome {
        ImportOutcome::Known { head, change_id } => {
            tally.known.push(oid);
            (head, change_id)
        }
        ImportOutcome::NewChange { head, change_id } => {
            tally.new_changes.push((change_id, oid));
            (head, change_id)
        }
        ImportOutcome::Divergent { head, change_id } => {
            tally.divergent.push((change_id, oid));
            (head, change_id)
        }
    };
    if noncanonical {
        tally.noncanonical_change_ids.push(oid);
    }
    let _ = change_id;
    if !matches!(head, Head::Git { oid: recorded } if recorded == oid) {
        return Err(GitError::Corrupt {
            detail: format!("commit {oid} recorded as {head:?}"),
        });
    }
    Ok(())
}

/// Reports whether `payload` carries any `change-id` header line, usable
/// or not. The scan stops at the blank line that ends the header block, so
/// message text never counts; a continuation line (leading space) never
/// starts a header.
#[must_use]
pub fn has_change_id_header(payload: &[u8]) -> bool {
    for line in payload.split(|&byte| byte == b'\n') {
        if line.is_empty() {
            break;
        }
        if line.starts_with(b"change-id ") || line == b"change-id" {
            return true;
        }
    }
    false
}
