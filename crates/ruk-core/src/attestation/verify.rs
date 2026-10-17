//! SSHSIG verification of attestation statements.
//!
//! [`verify_statement`] is the only way to obtain a [`VerifiedStatement`]. It
//! checks, in order: the canonical payload's object width; the SSHSIG parse
//! (version, key and signature algorithm names, hash name, namespace); the plain
//! `ssh-ed25519` policy; the namespace; the empty reserved field; and the Ed25519
//! signature over the canonical payload using the embedded key. Only after all of
//! those pass does it derive the signer fingerprint from that same verified key.

use sha2::{Digest, Sha256};
use ssh_key::{HashAlg, PublicKey, SshSig};

use crate::error::{CoreError, ErrorCode};
use crate::ids::HashKind;
use crate::protocol::{
    AttestAddArgs, AttestSignature, AttestStatement, SignerFingerprint, StatementDigest,
};

/// The SSHSIG namespace every attestation signature carries.
pub const ATTEST_NAMESPACE: &str = "ruk-attest";

/// A statement whose signature verified in this process.
///
/// The fields are private and [`verify_statement`] is the only constructor, so no
/// caller can fabricate a successful verification. The value keeps the verified
/// armored signature for export and re-verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedStatement {
    statement: AttestStatement,
    signer: SignerFingerprint,
    digest: StatementDigest,
    signature: AttestSignature,
}

impl VerifiedStatement {
    /// The signed statement.
    #[must_use]
    pub fn statement(&self) -> &AttestStatement {
        &self.statement
    }

    /// The `SHA256:` fingerprint of the verified embedded key.
    #[must_use]
    pub fn signer(&self) -> &SignerFingerprint {
        &self.signer
    }

    /// SHA-256 of the canonical payload.
    #[must_use]
    pub fn digest(&self) -> StatementDigest {
        self.digest
    }

    /// The verified armored SSHSIG, retained with the statement.
    #[must_use]
    pub fn signature(&self) -> &AttestSignature {
        &self.signature
    }

    /// The protocol pair that reproduces this statement and its signature.
    #[must_use]
    pub fn to_args(&self) -> AttestAddArgs {
        AttestAddArgs {
            statement: self.statement.clone(),
            signature: self.signature.clone(),
        }
    }
}

/// Verifies one signed statement against the repository's object format.
///
/// # Errors
/// - `E_OBJECT_FORMAT`: the subject's width is not `format`'s.
/// - `E_INVALID`: malformed armor or SSHSIG encoding, a tampered payload or key,
///   or a hash name other than `sha256` or `sha512`.
/// - `E_VERSION`: an SSHSIG version above 1.
/// - `E_POLICY`: a namespace other than `ruk-attest`, a key or signature
///   algorithm other than plain `ssh-ed25519`, or non-empty reserved bytes.
pub fn verify_statement(
    format: HashKind,
    args: &AttestAddArgs,
) -> Result<VerifiedStatement, CoreError> {
    let payload = args.statement.canonical_payload_v1(format)?;
    let signature = args
        .signature
        .as_str()
        .parse::<SshSig>()
        .map_err(|err| ssh_error(&err))?;

    let key = signature.public_key();
    if !key.is_ed25519() {
        return Err(policy("the signing key must be plain ssh-ed25519"));
    }
    if !signature.algorithm().is_ed25519() {
        return Err(policy("the signature algorithm must be ssh-ed25519"));
    }
    if signature.namespace() != ATTEST_NAMESPACE {
        return Err(policy(format!(
            "the signature namespace must be `{ATTEST_NAMESPACE}`"
        )));
    }
    if !signature.reserved().is_empty() {
        return Err(policy("SSHSIG reserved bytes must be empty"));
    }
    PublicKey::from(key.clone())
        .verify(ATTEST_NAMESPACE, &payload, &signature)
        .map_err(|err| ssh_error(&err))?;

    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    let signer = SignerFingerprint::new(fingerprint).map_err(|err| {
        CoreError::new(
            ErrorCode::ECorrupt,
            format!("verified key fingerprint is malformed: {err}"),
        )
    })?;
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&Sha256::digest(&payload));
    Ok(VerifiedStatement {
        statement: args.statement.clone(),
        signer,
        digest: StatementDigest::from_bytes(digest),
        signature: args.signature.clone(),
    })
}

fn policy(detail: impl Into<String>) -> CoreError {
    CoreError::new(ErrorCode::EPolicy, detail)
}

fn ssh_error(err: &ssh_key::Error) -> CoreError {
    let code = match err {
        ssh_key::Error::Version { .. } => ErrorCode::EVersion,
        ssh_key::Error::Namespace
        | ssh_key::Error::AlgorithmUnknown
        | ssh_key::Error::AlgorithmUnsupported { .. } => ErrorCode::EPolicy,
        _ => ErrorCode::EInvalid,
    };
    CoreError::new(code, format!("attestation signature: {err}"))
}
