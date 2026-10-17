//! Streamed export and reload of every retained attestation variant.
//!
//! Export walks the order index, which is already in `(kind, signer, digest)`
//! order, and writes one JSON element per statement. Each element is the protocol
//! pair `AttestAddArgs`: the statement and its retained verified signature. Memory
//! is bounded by one scan page and one element, never by the table.
//!
//! Reload is the reverse. The parser applies the protocol's JSON bounds, and every
//! element then goes through [`super::prepare_batch`], which verifies it again. The
//! file is never trusted for its signer, its order, or its statuses.

use std::io::Write;

use crate::error::{CoreError, ErrorCode};
use crate::ids::Oid;
use crate::protocol::{AttestAddArgs, decode_json};
use crate::store::Store;

use super::layout::{ORDER_PREFIX, parse_order_key};
use super::rows::{corrupt, read_statement};
use super::work::{RowScan, Work};
use super::{Checkpoint, MAX_IMPORT_STATEMENTS};

/// What an export wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportSummary {
    /// Statements written, including superseded and ambiguous ones.
    pub statements: u64,
}

/// Streams every retained statement as one JSON array, in `(kind, signer, digest)`
/// order.
///
/// The sink receives output as it is produced. On error it holds a partial array,
/// which the caller discards. The store is never modified.
///
/// No row count refuses an export: each statement is verified once as it is
/// written, and the checkpoint bounds the whole call. A reload is one import, so
/// [`parse_export`] refuses more than [`MAX_IMPORT_STATEMENTS`] elements.
///
/// # Errors
/// `E_IO` for a failed write; `E_CANCELLED` from the checkpoint; `E_CORRUPT` for an
/// index row without a valid statement (latches quarantine); `E_INVALID` if an
/// element cannot be encoded.
pub fn export(
    store: &Store,
    out: &mut dyn Write,
    checkpoint: &Checkpoint<'_>,
) -> Result<ExportSummary, CoreError> {
    let mut work = Work::streaming(checkpoint);
    write_all(out, b"[")?;
    let mut scan = RowScan::new(store, ORDER_PREFIX, None);
    let mut statements = 0_u64;
    while let Some(row) = scan.next_row()? {
        work.step()?;
        let Some(fields) = parse_order_key(&row.key) else {
            return corrupt(store, "order index key is malformed");
        };
        let Ok(subject) = Oid::from_bytes(&row.value) else {
            return corrupt(store, "order index value is not an object id");
        };
        if subject.kind() != store.hash_kind() {
            return corrupt(store, "order index subject has the wrong object format");
        }
        let Some(verified) = read_statement(
            store,
            &subject,
            fields.kind,
            fields.signer,
            &fields.digest,
            &mut work,
        )?
        else {
            return corrupt(
                store,
                "order index row names a statement that is not stored",
            );
        };
        let element = sonic_rs::to_vec(&verified.to_args()).map_err(|err| {
            CoreError::new(
                ErrorCode::EInvalid,
                format!("statement cannot be encoded: {err}"),
            )
        })?;
        if statements > 0 {
            write_all(out, b",")?;
        }
        write_all(out, &element)?;
        statements += 1;
        work.produced(u64::try_from(element.len()).unwrap_or(u64::MAX))?;
    }
    write_all(out, b"]")?;
    Ok(ExportSummary { statements })
}

/// Parses an exported array back into the protocol pairs ready for
/// [`super::prepare_batch`].
///
/// The input must be a JSON array of `AttestAddArgs`. Nesting is bounded by the
/// protocol's decoder before any recursive parse, and the element count is capped
/// at [`MAX_IMPORT_STATEMENTS`].
///
/// # Errors
/// `E_INVALID` for malformed JSON, nesting beyond the protocol bound, or elements
/// that fail the protocol's field validation; `E_LIMIT` for too many elements.
pub fn parse_export(bytes: &[u8]) -> Result<Vec<AttestAddArgs>, CoreError> {
    let statements: Vec<AttestAddArgs> = decode_json(bytes)?;
    if statements.len() > MAX_IMPORT_STATEMENTS {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            format!("an import holds at most {MAX_IMPORT_STATEMENTS} statements"),
        ));
    }
    Ok(statements)
}

fn write_all(out: &mut dyn Write, bytes: &[u8]) -> Result<(), CoreError> {
    out.write_all(bytes)
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("export sink: {err}")))
}
