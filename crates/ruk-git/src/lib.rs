//! Exact Git object exchange and the strict Git command interpreter.
//!
//! Slice 1 establishes the typed error boundary and the object-identity
//! parsing shared by every later command: hex OIDs validated against the
//! repository hash kind, with each failure mapped to one closed core error
//! code so the executable boundary exits with the native status for that
//! code. No Git commands, transport, or repository operations exist yet;
//! those arrive in later slices against the pinned Git sources.

#![forbid(unsafe_code)]

pub mod export;
pub mod import;
pub mod transport;

use ruk_core::error::{CoreError, ErrorCode};
use ruk_core::ids::{HashKind, Oid};
use thiserror::Error;

/// Failures of the Git compatibility layer.
///
/// Model-level validation keeps its closed [`CoreError`] code; this enum
/// carries the interpreter failures slice 1 can already classify. Every
/// variant maps to exactly one [`ErrorCode`].
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum GitError {
    /// A command family or option outside the strict interpreter.
    #[error("unsupported git command: {command}")]
    Unsupported {
        /// The rejected command or option shape, echoed for diagnostics.
        command: String,
    },
    /// Hex object identity that does not parse to either known width.
    #[error("invalid object id {input:?}: {detail}")]
    InvalidOid {
        /// The rejected input, echoed for diagnostics.
        input: String,
        /// Why parsing failed.
        detail: String,
    },
    /// A well-formed OID of the wrong hash kind for this repository.
    #[error("object format mismatch: {detail}")]
    ObjectFormat {
        /// Which OID clashed with which repository kind.
        detail: String,
    },
    /// Stored bytes disagree with their own framing or declared format.
    #[error("corrupt: {detail}")]
    Corrupt {
        /// What failed validation.
        detail: String,
    },
    /// Filesystem or store I/O failure.
    #[error("io: {detail}")]
    Io {
        /// The failed operation.
        detail: String,
    },
    /// A named object, ref, or row does not exist.
    #[error("not found: {detail}")]
    NotFound {
        /// What is absent.
        detail: String,
    },
    /// Malformed or contradictory input.
    #[error("invalid: {detail}")]
    Invalid {
        /// What is invalid.
        detail: String,
    },
    /// Malformed invocation: the caller must fix argv, the way the oracle's
    /// `usage()`/`fatal()` exits 128. Closed-code mapping stays `EInvalid`;
    /// only the process status differs (see [`GitError::exit_code`]).
    #[error("usage: {detail}")]
    Usage {
        /// What the caller must fix.
        detail: String,
    },
    /// A configured resource limit rejected the request.
    #[error("limit: {detail}")]
    Limit {
        /// The exceeded limit.
        detail: String,
    },
    /// A checked fixed-width space is exhausted.
    #[error("capacity: {detail}")]
    Capacity {
        /// The exhausted space.
        detail: String,
    },
    /// The on-disk or wire format is not one this build reads.
    #[error("version: {detail}")]
    Version {
        /// The rejected format.
        detail: String,
    },
    /// A conditional expectation failed before mutation.
    #[error("stale: {detail}")]
    Stale {
        /// What moved.
        detail: String,
    },
    /// The remote could not be reached.
    #[error("offline: {detail}")]
    Offline {
        /// The failed endpoint or transport.
        detail: String,
    },
    /// The operation needs ancestors above the shallow boundary.
    #[error("shallow: {detail}")]
    Shallow {
        /// The blocked traversal.
        detail: String,
    },
    /// The remote definitively refused the push.
    #[error("push rejected: {detail}")]
    PushRejected {
        /// The remote's refusal.
        detail: String,
    },
    /// The push outcome is unknowable; retrying may duplicate.
    #[error("push uncertain: {detail}")]
    PushUncertain {
        /// Where the outcome was lost.
        detail: String,
    },
    /// The remote moved between negotiation and update.
    #[error("remote moved: {detail}")]
    RemoteMoved {
        /// The displaced expectation.
        detail: String,
    },
    /// The caller cancelled the operation.
    #[error("cancelled: {detail}")]
    Cancelled {
        /// What was in flight.
        detail: String,
    },
}

impl GitError {
    /// The closed core code for this failure.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Unsupported { .. } => ErrorCode::EUnsupportedGitCommand,
            Self::InvalidOid { .. } | Self::Invalid { .. } | Self::Usage { .. } => {
                ErrorCode::EInvalid
            }
            Self::ObjectFormat { .. } => ErrorCode::EObjectFormat,
            Self::Corrupt { .. } => ErrorCode::ECorrupt,
            Self::Io { .. } => ErrorCode::EIo,
            Self::NotFound { .. } => ErrorCode::ENotFound,
            Self::Limit { .. } => ErrorCode::ELimit,
            Self::Capacity { .. } => ErrorCode::ECapacity,
            Self::Version { .. } => ErrorCode::EVersion,
            Self::Stale { .. } => ErrorCode::EStale,
            Self::Offline { .. } => ErrorCode::EOffline,
            Self::Shallow { .. } => ErrorCode::EShallow,
            Self::PushRejected { .. } | Self::PushUncertain { .. } | Self::RemoteMoved { .. } => {
                ErrorCode::EStale
            }
            Self::Cancelled { .. } => ErrorCode::ECancelled,
        }
    }

    /// Native process exit status for this failure.
    ///
    /// Usage errors exit 128 like the oracle's `usage()`/`fatal()`; every
    /// other variant keeps the native 1-5 map through [`GitError::code`].
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if matches!(self, Self::Usage { .. }) {
            return 128;
        }
        self.code().exit_code()
    }

    /// The [`CoreError`] form, preserving the closed code.
    #[must_use]
    pub fn to_core_error(&self) -> CoreError {
        CoreError::new(self.code(), self.to_string())
    }
}

impl From<GitError> for CoreError {
    fn from(err: GitError) -> Self {
        err.to_core_error()
    }
}

impl From<CoreError> for GitError {
    fn from(err: CoreError) -> Self {
        let detail = err.to_string();
        match err.code {
            ErrorCode::ECorrupt => Self::Corrupt { detail },
            ErrorCode::EIo => Self::Io { detail },
            ErrorCode::ENotFound => Self::NotFound { detail },
            ErrorCode::ELimit => Self::Limit { detail },
            ErrorCode::ECapacity => Self::Capacity { detail },
            ErrorCode::EVersion => Self::Version { detail },
            ErrorCode::EStale => Self::Stale { detail },
            ErrorCode::EOffline => Self::Offline { detail },
            ErrorCode::EShallow => Self::Shallow { detail },
            ErrorCode::ECancelled => Self::Cancelled { detail },
            ErrorCode::EObjectFormat => Self::ObjectFormat { detail },
            code => Self::Io {
                detail: format!("{code:?}: {err}"),
            },
        }
    }
}

impl From<ruk_core::store::StoreError> for GitError {
    fn from(err: ruk_core::store::StoreError) -> Self {
        use ruk_core::store::StoreError as SE;
        match err {
            SE::Io(e) => Self::Io {
                detail: e.to_string(),
            },
            SE::Corrupt(detail) => Self::Corrupt { detail },
            SE::NotFound(detail) => Self::NotFound { detail },
            SE::Invalid(detail) => Self::Invalid { detail },
            SE::Limit(detail) => Self::Limit { detail },
            SE::Capacity(detail) => Self::Capacity { detail },
            SE::Version(detail) => Self::Version { detail },
            SE::ObjectFormat(detail) => Self::ObjectFormat { detail },
            SE::StaleFact { table, key } => Self::Stale {
                detail: format!("fact {table} {key} moved"),
            },
            SE::Model(e) => Self::from(CoreError::from(e)),
            other => Self::Io {
                detail: other.to_string(),
            },
        }
    }
}

/// Parses hex into an exact object identity of either known width.
///
/// # Errors
/// [`GitError::InvalidOid`] when the input is not hex of a known width.
pub fn parse_oid(hex: &str) -> Result<Oid, GitError> {
    Oid::from_hex(hex).map_err(|err| GitError::InvalidOid {
        input: hex.to_owned(),
        detail: err.to_string(),
    })
}

/// Requires the OID to match the repository hash kind.
///
/// # Errors
/// [`GitError::ObjectFormat`] when a well-formed OID has the other width.
pub fn require_kind(oid: Oid, kind: HashKind) -> Result<Oid, GitError> {
    if oid.kind() == kind {
        Ok(oid)
    } else {
        Err(GitError::ObjectFormat {
            detail: format!(
                "object {} is {} but repository is {kind}",
                oid.to_hex(),
                oid.kind()
            ),
        })
    }
}

/// Parses hex and requires it to match the repository hash kind.
///
/// # Errors
/// [`GitError::InvalidOid`] on malformed input, [`GitError::ObjectFormat`]
/// on a well-formed OID of the other width.
pub fn parse_oid_for(hex: &str, kind: HashKind) -> Result<Oid, GitError> {
    require_kind(parse_oid(hex)?, kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA1_HEX: &str = "0123456789abcdef0123456789abcdef01234567";
    const SHA256_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn parses_both_known_widths_with_kinds() {
        let sha1 = parse_oid(SHA1_HEX).expect("sha1 parses");
        assert_eq!(sha1.kind(), HashKind::Sha1);
        assert_eq!(sha1.to_hex(), SHA1_HEX);
        let sha256 = parse_oid(SHA256_HEX).expect("sha256 parses");
        assert_eq!(sha256.kind(), HashKind::Sha256);
        assert_eq!(sha256.to_hex(), SHA256_HEX);
    }

    #[test]
    fn malformed_input_is_invalid_with_native_exit() {
        let mangled = SHA1_HEX.replace('a', "g");
        for bad in ["", "xyz", "0123", mangled.as_str()] {
            let err = parse_oid(bad).expect_err("must reject");
            assert_eq!(err.code(), ErrorCode::EInvalid, "{bad:?}");
            assert_eq!(err.exit_code(), ErrorCode::EInvalid.exit_code());
            assert_eq!(CoreError::from(err).code, ErrorCode::EInvalid);
        }
    }

    #[test]
    fn wrong_width_for_repository_is_object_format() {
        let oid = parse_oid(SHA256_HEX).expect("parses width-first");
        let err = require_kind(oid, HashKind::Sha1).expect_err("kind must reject");
        assert_eq!(err.code(), ErrorCode::EObjectFormat);
        assert_eq!(CoreError::from(err).code, ErrorCode::EObjectFormat);
        assert!(require_kind(oid, HashKind::Sha256).is_ok());
    }

    #[test]
    fn combined_parse_enforces_kind() {
        assert!(parse_oid_for(SHA1_HEX, HashKind::Sha1).is_ok());
        let err = parse_oid_for(SHA1_HEX, HashKind::Sha256).expect_err("kind");
        assert_eq!(err.code(), ErrorCode::EObjectFormat);
        let err = parse_oid_for("nope", HashKind::Sha1).expect_err("parse");
        assert_eq!(err.code(), ErrorCode::EInvalid);
    }
}
