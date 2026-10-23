//! Typed error surface and the native exit-code class map.
//!
//! The closed error-code set is fixed by the core contract; a new code
//! arrives only through a schema revision. The hosted contract's extra
//! outcomes (unsupported command family, syntax worker unhealthy, stale
//! preview tuple, stale conversion inventory, invalid mode, notebook
//! structure declined) are carried by these codes and the typed merge
//! notices; none adds a code.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The one closed error-code registry. The serde and schema form is the
/// contract spelling (`E_STALE`), identical to [`ErrorCode::as_str`].
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
pub enum ErrorCode {
    #[serde(rename = "E_STALE")]
    EStale,
    #[serde(rename = "E_LEASE_LOST")]
    ELeaseLost,
    #[serde(rename = "E_REQUEST_REUSED")]
    ERequestReused,
    #[serde(rename = "E_CONFLICTED")]
    EConflicted,
    #[serde(rename = "E_DIVERGENT")]
    EDivergent,
    #[serde(rename = "E_OBJECT_FORMAT")]
    EObjectFormat,
    #[serde(rename = "E_REMOTE_MOVED")]
    ERemoteMoved,
    #[serde(rename = "E_PUSH_REJECTED")]
    EPushRejected,
    #[serde(rename = "E_PUSH_UNCERTAIN")]
    EPushUncertain,
    #[serde(rename = "E_OFFLINE")]
    EOffline,
    #[serde(rename = "E_UNDO_CONFLICT")]
    EUndoConflict,
    #[serde(rename = "E_CLAIMED")]
    EClaimed,
    #[serde(rename = "E_FORBIDDEN")]
    EForbidden,
    #[serde(rename = "E_POLICY")]
    EPolicy,
    #[serde(rename = "E_UNSUPPORTED_LFS")]
    EUnsupportedLfs,
    #[serde(rename = "E_UNSUPPORTED_GIT_COMMAND")]
    EUnsupportedGitCommand,
    #[serde(rename = "E_COORDINATOR_UNRESPONSIVE")]
    ECoordinatorUnresponsive,
    #[serde(rename = "E_CAPACITY")]
    ECapacity,
    #[serde(rename = "E_CORRUPT")]
    ECorrupt,
    #[serde(rename = "E_NOT_FOUND")]
    ENotFound,
    #[serde(rename = "E_INVALID")]
    EInvalid,
    #[serde(rename = "E_IO")]
    EIo,
    #[serde(rename = "E_LIMIT")]
    ELimit,
    #[serde(rename = "E_VERSION")]
    EVersion,
    #[serde(rename = "E_DIRTY")]
    EDirty,
    #[serde(rename = "E_WORKSPACE_APPLYING")]
    EWorkspaceApplying,
    #[serde(rename = "E_WORKSPACE_RECOVERY")]
    EWorkspaceRecovery,
    #[serde(rename = "E_CANCELLED")]
    ECancelled,
    #[serde(rename = "E_SHALLOW")]
    EShallow,
    #[serde(rename = "E_HOSTED")]
    EHosted,
}

impl ErrorCode {
    /// Every code, in contract order. The registry is closed: this array and
    /// [`Self::as_str`] are exhaustive over the enum.
    pub const ALL: [Self; 30] = [
        Self::EStale,
        Self::ELeaseLost,
        Self::ERequestReused,
        Self::EConflicted,
        Self::EDivergent,
        Self::EObjectFormat,
        Self::ERemoteMoved,
        Self::EPushRejected,
        Self::EPushUncertain,
        Self::EOffline,
        Self::EUndoConflict,
        Self::EClaimed,
        Self::EForbidden,
        Self::EPolicy,
        Self::EUnsupportedLfs,
        Self::EUnsupportedGitCommand,
        Self::ECoordinatorUnresponsive,
        Self::ECapacity,
        Self::ECorrupt,
        Self::ENotFound,
        Self::EInvalid,
        Self::EIo,
        Self::ELimit,
        Self::EVersion,
        Self::EDirty,
        Self::EWorkspaceApplying,
        Self::EWorkspaceRecovery,
        Self::ECancelled,
        Self::EShallow,
        Self::EHosted,
    ];

    /// The wire form of this code, exactly as the contract spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EStale => "E_STALE",
            Self::ELeaseLost => "E_LEASE_LOST",
            Self::ERequestReused => "E_REQUEST_REUSED",
            Self::EConflicted => "E_CONFLICTED",
            Self::EDivergent => "E_DIVERGENT",
            Self::EObjectFormat => "E_OBJECT_FORMAT",
            Self::ERemoteMoved => "E_REMOTE_MOVED",
            Self::EPushRejected => "E_PUSH_REJECTED",
            Self::EPushUncertain => "E_PUSH_UNCERTAIN",
            Self::EOffline => "E_OFFLINE",
            Self::EUndoConflict => "E_UNDO_CONFLICT",
            Self::EClaimed => "E_CLAIMED",
            Self::EForbidden => "E_FORBIDDEN",
            Self::EPolicy => "E_POLICY",
            Self::EUnsupportedLfs => "E_UNSUPPORTED_LFS",
            Self::EUnsupportedGitCommand => "E_UNSUPPORTED_GIT_COMMAND",
            Self::ECoordinatorUnresponsive => "E_COORDINATOR_UNRESPONSIVE",
            Self::ECapacity => "E_CAPACITY",
            Self::ECorrupt => "E_CORRUPT",
            Self::ENotFound => "E_NOT_FOUND",
            Self::EInvalid => "E_INVALID",
            Self::EIo => "E_IO",
            Self::ELimit => "E_LIMIT",
            Self::EVersion => "E_VERSION",
            Self::EDirty => "E_DIRTY",
            Self::EWorkspaceApplying => "E_WORKSPACE_APPLYING",
            Self::EWorkspaceRecovery => "E_WORKSPACE_RECOVERY",
            Self::ECancelled => "E_CANCELLED",
            Self::EShallow => "E_SHALLOW",
            Self::EHosted => "E_HOSTED",
        }
    }

    /// Native process exit status for this code (0 is reserved for success).
    ///
    /// The contract names five classes: 1 invalid/not-found/version/limit/
    /// cancel/IO; 2 conflict/divergence/dirty/recovery; 3 stale/lease/claim/
    /// forbidden/policy; 4 remote/offline/uncertain/shallow; 5 corruption.
    /// Codes the contract does not list by name take the nearest class:
    /// object-format, unsupported LFS/Git command, capacity, unresponsive
    /// coordinator and hosted failures are class 1 (input, limit, or IO);
    /// undo conflicts are class 2; request-ID reuse is class 3; remote-moved
    /// and push outcomes are class 4. Strict Git commands use the pinned Git
    /// exit contract instead of this map.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::EInvalid
            | Self::ENotFound
            | Self::EVersion
            | Self::ELimit
            | Self::ECancelled
            | Self::EIo
            | Self::EObjectFormat
            | Self::EUnsupportedLfs
            | Self::EUnsupportedGitCommand
            | Self::ECapacity
            | Self::ECoordinatorUnresponsive
            | Self::EHosted => 1,
            Self::EConflicted
            | Self::EDivergent
            | Self::EDirty
            | Self::EWorkspaceApplying
            | Self::EWorkspaceRecovery
            | Self::EUndoConflict => 2,
            Self::EStale
            | Self::ELeaseLost
            | Self::EClaimed
            | Self::EForbidden
            | Self::EPolicy
            | Self::ERequestReused => 3,
            Self::ERemoteMoved
            | Self::EPushRejected
            | Self::EPushUncertain
            | Self::EOffline
            | Self::EShallow => 4,
            Self::ECorrupt => 5,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ErrorCode {
    type Err = CoreModelError;

    /// Parses the exact contract spelling only.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|code| code.as_str() == text)
            .ok_or_else(|| CoreModelError::Invalid {
                what: "error code",
                detail: text.to_owned(),
            })
    }
}

/// The native exit status as a typed value (0 success, 1..=5 per
/// [`ErrorCode::exit_code`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct ExitClass(pub u8);

impl ExitClass {
    pub const OK: Self = Self(0);

    #[must_use]
    pub const fn from_code(code: ErrorCode) -> Self {
        Self(code.exit_code())
    }
}

impl From<ErrorCode> for ExitClass {
    fn from(code: ErrorCode) -> Self {
        Self::from_code(code)
    }
}

/// A code with a stable message and machine-readable fixes.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("{}: {}", .code.as_str(), .message)]
pub struct CoreError {
    pub code: ErrorCode,
    pub message: String,
    pub hints: Vec<String>,
}

impl CoreError {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hints: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hints.push(hint.into());
        self
    }
}

/// Failures of model validation and encoding. Each maps to exactly one
/// closed [`ErrorCode`] through [`CoreModelError::code`].
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CoreModelError {
    /// Malformed or contradictory input rejected at a boundary.
    #[error("invalid {what}: {detail}")]
    Invalid { what: &'static str, detail: String },
    /// A checked counter or fixed-width space is exhausted.
    #[error("capacity exceeded: {0}")]
    Capacity(String),
    /// A named entity does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// A hash width disagrees with the repository's fixed object format.
    #[error("object format mismatch: {0}")]
    ObjectFormat(String),
    /// A schema major/minor this build cannot read.
    #[error("version: {0}")]
    Version(String),
    /// Stored bytes disagree with their own framing or checksums.
    #[error("corrupt: {0}")]
    Corrupt(String),
}

impl CoreModelError {
    /// The closed code this failure reports.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Invalid { .. } => ErrorCode::EInvalid,
            Self::Capacity(_) => ErrorCode::ECapacity,
            Self::NotFound(_) => ErrorCode::ENotFound,
            Self::ObjectFormat(_) => ErrorCode::EObjectFormat,
            Self::Version(_) => ErrorCode::EVersion,
            Self::Corrupt(_) => ErrorCode::ECorrupt,
        }
    }
}

impl From<CoreModelError> for CoreError {
    fn from(err: CoreModelError) -> Self {
        Self::new(err.code(), err.to_string())
    }
}

pub type CoreModelResult<T> = Result<T, CoreModelError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_and_display_forms_are_the_contract_spelling_for_every_code() {
        for code in ErrorCode::ALL {
            let json = sonic_rs::to_string(&code).expect("json");
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            assert_eq!(code.to_string(), code.as_str());
            assert_eq!(sonic_rs::from_str::<ErrorCode>(&json).expect("parse"), code);
            assert_eq!(code.as_str().parse::<ErrorCode>().expect("from_str"), code);
        }
    }

    #[test]
    fn registry_is_closed_unique_and_prefixed() {
        let mut spellings: Vec<&str> = ErrorCode::ALL.iter().map(|code| code.as_str()).collect();
        assert!(spellings.iter().all(|s| s.starts_with("E_")));
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), 30);
    }

    #[test]
    fn unknown_or_variant_spellings_are_rejected() {
        for bad in ["EStale", "e_stale", "E_STALE ", "E_UNKNOWN", "", "STALE"] {
            assert!(bad.parse::<ErrorCode>().is_err(), "accepted {bad:?}");
            let json = sonic_rs::to_string(bad).expect("json");
            assert!(
                sonic_rs::from_str::<ErrorCode>(&json).is_err(),
                "accepted {json}"
            );
        }
    }

    #[test]
    fn exit_classes_follow_the_contract_for_every_listed_code() {
        use ErrorCode::*;
        for code in [EInvalid, ENotFound, EVersion, ELimit, ECancelled, EIo] {
            assert_eq!(code.exit_code(), 1, "{code}");
        }
        for code in [
            EConflicted,
            EDivergent,
            EDirty,
            EWorkspaceRecovery,
            EWorkspaceApplying,
        ] {
            assert_eq!(code.exit_code(), 2, "{code}");
        }
        for code in [EStale, ELeaseLost, EClaimed, EForbidden, EPolicy] {
            assert_eq!(code.exit_code(), 3, "{code}");
        }
        for code in [
            ERemoteMoved,
            EOffline,
            EPushUncertain,
            EPushRejected,
            EShallow,
        ] {
            assert_eq!(code.exit_code(), 4, "{code}");
        }
        assert_eq!(ECorrupt.exit_code(), 5);
        assert!(
            ErrorCode::ALL
                .iter()
                .all(|code| (1..=5).contains(&code.exit_code()))
        );
    }

    #[test]
    fn exit_class_maps_from_codes() {
        assert_eq!(ExitClass::from(ErrorCode::EStale), ExitClass(3));
        assert_eq!(ExitClass::from_code(ErrorCode::ECorrupt), ExitClass(5));
        assert_eq!(ExitClass::OK, ExitClass(0));
    }

    #[test]
    fn model_errors_map_to_one_closed_code_each() {
        let cases = [
            (
                CoreModelError::Invalid {
                    what: "x",
                    detail: "y".into(),
                },
                ErrorCode::EInvalid,
            ),
            (
                CoreModelError::Capacity("full".into()),
                ErrorCode::ECapacity,
            ),
            (CoreModelError::NotFound("n".into()), ErrorCode::ENotFound),
            (
                CoreModelError::ObjectFormat("f".into()),
                ErrorCode::EObjectFormat,
            ),
            (CoreModelError::Version("v".into()), ErrorCode::EVersion),
            (CoreModelError::Corrupt("c".into()), ErrorCode::ECorrupt),
        ];
        for (err, code) in cases {
            let core: CoreError = err.clone().into();
            assert_eq!(core.code, code);
            assert_eq!(err.code(), code);
            assert!(core.to_string().starts_with(code.as_str()));
        }
    }

    #[test]
    fn core_error_display_carries_code_and_hints_survive() {
        let err =
            CoreError::new(ErrorCode::EStale, "plan expired").with_hint("re-run land.prepare");
        assert_eq!(err.to_string(), "E_STALE: plan expired");
        assert_eq!(err.hints, ["re-run land.prepare"]);
    }
}
