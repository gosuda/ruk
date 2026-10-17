//! Stored statement rows: the postcard codec, verified reads, and corruption
//! reporting.
//!
//! Every committed row is verified again before it is trusted. A row whose
//! fields, signature, or key disagree is committed damage: it is reported through
//! the store's observer, which latches quarantine, and the caller gets `E_CORRUPT`.

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, ErrorCode};
use crate::ids::Oid;
use crate::protocol::{
    AttestAddArgs, AttestSignature, AttestStatement, SignerFingerprint, StatementDigest,
};
use crate::store::{FactTable, Store, StoreError};

use super::MAX_GROUP_STATEMENTS;
use super::layout::{group_prefix, statement_key};
use super::verify::{VerifiedStatement, verify_statement};
use super::work::{RowScan, Work};

/// The version of the stored row format.
pub(super) const ROW_VERSION: u8 = 1;

/// One stored statement. The signer and digest repeat the key's fields so a row
/// can be checked against its own key.
#[derive(Serialize, Deserialize)]
pub(super) struct StatementRow {
    pub(super) version: u8,
    pub(super) statement: AttestStatement,
    pub(super) signer: SignerFingerprint,
    pub(super) digest: StatementDigest,
    pub(super) signature: AttestSignature,
}

/// Reports committed damage to the store, which latches quarantine, and returns
/// it as `E_CORRUPT`.
pub(super) fn corrupt<T>(store: &Store, detail: impl Into<String>) -> Result<T, CoreError> {
    store
        .observe(Err(StoreError::Corrupt(format!(
            "attestation: {}",
            detail.into()
        ))))
        .map_err(CoreError::from)
}

/// The refusal for a group that exceeds [`MAX_GROUP_STATEMENTS`].
pub(super) fn group_limit() -> CoreError {
    CoreError::new(
        ErrorCode::ELimit,
        format!("a (subject, kind, signer) group holds at most {MAX_GROUP_STATEMENTS} statements"),
    )
}

/// Encodes one verified statement as its stored row.
pub(super) fn encode_row(verified: &VerifiedStatement) -> Result<Vec<u8>, CoreError> {
    let row = StatementRow {
        version: ROW_VERSION,
        statement: verified.statement().clone(),
        signer: verified.signer().clone(),
        digest: verified.digest(),
        signature: verified.signature().clone(),
    };
    crate::store::encode("attestation row", &row).map_err(CoreError::from)
}

/// Decodes one committed row stored under `key` and verifies it again.
pub(super) fn decode_row(
    store: &Store,
    key: &[u8],
    bytes: &[u8],
) -> Result<VerifiedStatement, CoreError> {
    let decoded: Result<StatementRow, StoreError> = crate::store::decode("attestation row", bytes);
    let StatementRow {
        version,
        statement,
        signer,
        digest,
        signature,
    } = store.observe(decoded).map_err(CoreError::from)?;
    if version != ROW_VERSION {
        return corrupt(store, format!("row version {version} is not {ROW_VERSION}"));
    }
    let args = AttestAddArgs {
        statement,
        signature,
    };
    let verified = match verify_statement(store.hash_kind(), &args) {
        Ok(verified) => verified,
        Err(err) => {
            return corrupt(
                store,
                format!("stored statement fails verification: {}", err.message),
            );
        }
    };
    if verified.signer() != &signer || verified.digest() != digest {
        return corrupt(
            store,
            "stored signer or digest disagrees with its verified signature",
        );
    }
    let statement = verified.statement();
    let expected = statement_key(
        &statement.subject,
        statement.kind.as_str(),
        verified.signer().as_str(),
        verified.digest().as_bytes(),
    );
    if expected.as_slice() != key {
        return corrupt(store, "stored row sits under a key that is not its own");
    }
    Ok(verified)
}

/// Reads and verifies the statement stored under exactly this group and digest.
pub(super) fn read_statement(
    store: &Store,
    subject: &Oid,
    kind: &str,
    signer: &str,
    digest: &[u8; 32],
    work: &mut Work<'_>,
) -> Result<Option<VerifiedStatement>, CoreError> {
    let key = statement_key(subject, kind, signer, digest);
    let Some(bytes) = store.fact(FactTable::Attestations, &key)? else {
        return Ok(None);
    };
    work.verify()?;
    decode_row(store, &key, &bytes).map(Some)
}

/// Every stored statement of one group, verified, in digest order.
///
/// # Errors
/// `E_LIMIT` when the group exceeds [`MAX_GROUP_STATEMENTS`] or the call's
/// verification budget; `E_CORRUPT` for a row that fails re-verification.
pub(super) fn load_group(
    store: &Store,
    subject: &Oid,
    kind: &str,
    signer: &str,
    work: &mut Work<'_>,
) -> Result<Vec<VerifiedStatement>, CoreError> {
    let prefix = group_prefix(subject, kind, signer);
    let mut scan = RowScan::new(store, &prefix, None);
    let mut members = Vec::new();
    while let Some(row) = scan.next_row()? {
        work.step()?;
        work.verify()?;
        if members.len() == MAX_GROUP_STATEMENTS {
            return Err(group_limit());
        }
        members.push(decode_row(store, &row.key, &row.value)?);
    }
    Ok(members)
}
