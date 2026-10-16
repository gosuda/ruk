//! Exact Git object exchange and the strict Git command interpreter.
//!
//! Slice 1 establishes the typed error boundary and the object-identity
//! parsing shared by every later command: hex OIDs validated against the
//! repository hash kind, with each failure mapped to one closed core error
//! code so the executable boundary exits with the native status for that
//! code. No Git commands, transport, or repository operations exist yet;
//! those arrive in later slices against the pinned Git sources.

#![forbid(unsafe_code)]

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
}

impl GitError {
    /// The closed core code for this failure.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Unsupported { .. } => ErrorCode::EUnsupportedGitCommand,
            Self::InvalidOid { .. } => ErrorCode::EInvalid,
            Self::ObjectFormat { .. } => ErrorCode::EObjectFormat,
        }
    }

    /// Native process exit status for this failure.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
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
