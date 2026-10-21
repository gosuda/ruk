//! Signed attestations over exact commits.
//!
//! An attestation is an [`AttestStatement`] signed as an SSHSIG in namespace
//! `ruk-attest` by one plain `ssh-ed25519` key. This module owns the local path:
//! verifying signatures ([`verify_statement`]), preparing exact-CAS fact
//! mutations for single and batched imports ([`prepare_add`],
//! [`prepare_batch`]), bounded queries with derived statuses ([`list`],
//! [`subject_statements`], [`attested`]), land requirement evaluation
//! ([`evaluate_requirements`]), and streamed export and reload ([`export`],
//! [`parse_export`]).
//!
//! # Trust
//!
//! Nothing is trusted without verification. The signer fingerprint is derived
//! from the verified embedded key and is never accepted from input. Every stored
//! row is verified again when it is read; a row that fails is committed
//! corruption and latches store quarantine. Timestamps are signed claims. No
//! code here compares them to choose a winner.
//!
//! # Statuses
//!
//! Within one `(subject, kind, signer)` group, a statement that a same-group
//! statement supersedes is [`AttestationStatus::Superseded`]. Otherwise, when
//! the group's live statements disagree on the result, each live statement is
//! [`AttestationStatus::Ambiguous`] until a signed supersession removes the
//! disagreement. Otherwise it is [`AttestationStatus::Live`].
//!
//! # Preconditions
//!
//! The `prepare_*` functions run under sole publication-lane ownership with a
//! live object lease covering their subjects. The lease keeps subject commits
//! from being collected between the commit-kind check and publication. They
//! never publish: the caller publishes [`PreparedAttestations::mutations`]
//! through the coordinator.
//!
//! # Storage
//!
//! Rows live in the attestations fact table in two key families (see the
//! `layout` module): one subject-major statement row per `(subject, kind, signer,
//! digest)`, and one `(kind, signer, digest)`-major order index that makes export
//! streaming. The signed payload does not name its signer, so two signers may sign
//! one canonical payload; each signer's copy is its own row and group member.

mod export;
mod layout;
mod prepare;
mod query;
mod rows;
mod status;
mod verify;
mod work;

#[cfg(test)]
mod tests;

use crate::error::CoreError;

pub use export::{ExportSummary, export, parse_export};
pub(crate) use layout::{is_order_key, is_statement_key};
pub use prepare::{Disposition, PreparedAttestations, PreparedRecord, prepare_add, prepare_batch};
pub use query::{
    AttestationPage, BoundedRequirement, Gap, LandEvaluation, RequirementEvaluation,
    RequirementOutcome, StatementFilter, attested, evaluate_bounded_requirements,
    evaluate_requirements, list, subject_statements,
};
pub(crate) use rows::stored_statement_identity;
pub use verify::{ATTEST_NAMESPACE, VerifiedStatement, verify_statement};

/// Most statements one import may carry.
pub const MAX_IMPORT_STATEMENTS: usize = 4096;

/// Most statements one `(subject, kind, signer)` group may hold.
pub const MAX_GROUP_STATEMENTS: usize = 1024;

/// Most statements one subject may hold across all kinds and signers.
pub const MAX_SUBJECT_STATEMENTS: usize = 4096;

/// Most requirements one land evaluation accepts.
pub const MAX_LAND_REQUIREMENTS: usize = 64;

/// Most distinct trusted signers one land evaluation accepts.
pub const MAX_TRUSTED_SIGNERS: usize = 256;

/// Work completed so far in one admitted attestation call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    /// Statements, rows, or index entries examined so far.
    pub examined: u64,
    /// Mutations prepared, or export bytes written, so far.
    pub produced: u64,
}

/// Cooperative cancellation and progress hook for admitted attestation work.
///
/// The hook runs before each unit of work. Returning an error aborts the call
/// with that error; a caller passes `E_CANCELLED` once its admission is
/// revoked. Pass `&|_| Ok(())` when no gate applies.
pub type Checkpoint<'a> = dyn Fn(Progress) -> Result<(), CoreError> + 'a;
