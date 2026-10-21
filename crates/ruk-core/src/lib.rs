//! Ruk native model, merge algebra, and typed schemas.
//!
//! This crate owns the slice-1 model surface: exact Git object identity, the
//! ported jj merge algebra, commit records and native conflict encoding, ref
//! authority, workspace state, capability grammar, and the typed
//! request/reply schemas of the core protocol, plus the durable object and
//! fact [`store`]. It contains no transport or repository-operation code;
//! later slices build on these validated types and the store.
//!
//! Foundational modules: [`ids`], [`change`], [`heads`], [`error`],
//! [`bytes`], [`merge`], [`conflict`], [`store`]. The single merge-notice
//! record lives at [`merge::composed`] and is reused unchanged by every
//! surface.

/// Largest length-prefixed JSON control frame, in bytes. The one control
/// bound: the wire protocol, the CLI's input documents, and every
/// attestation text field are limited by it and by nothing narrower.
pub const MAX_CONTROL_FRAME_BYTES: usize = 16 * 1024 * 1024;

pub mod attestation;
mod budget;
pub mod bytes;
pub mod capability;
pub mod change;
pub mod commit;
pub mod conflict;
pub mod contained;
pub mod coord;
pub mod error;
mod graph;
pub mod heads;
pub mod ids;
pub mod index;
pub mod merge;
pub mod ops;
mod physical;
pub mod protocol;
pub mod records;
pub mod refdata;
pub mod refs;
#[expect(
    dead_code,
    reason = "unwired subsystem; consumers land in later changeset rows"
)]
#[expect(
    unreachable_pub,
    reason = "unwired subsystem; public surface not yet re-exported"
)]
mod revset;
pub mod store;
pub mod tree;
mod workcopy;
#[expect(
    dead_code,
    reason = "unwired subsystem; consumers land in later changeset rows"
)]
mod workcopy_journal;
pub mod workspace;

pub use bytes::ByteString;
pub use change::{
    ChangeId, CheckedOperationId, ClaimId, LeaseId, OperationId, PlanId, RequestId, SessionId,
    StoreId, WorkspaceId,
};
pub use error::{CoreError, CoreModelError, ErrorCode, ExitClass};
pub use heads::Head;
pub use ids::{CommitKey, HashKind, Oid};
pub use store::{PreparationBudget, Store, StoreError};
pub use workcopy::lfs::{LfsMode, is_pointer, mode_for_store, parse_pointer};
