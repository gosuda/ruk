//! Key layout for attestation rows in the attestations fact table.
//!
//! Two families share the table:
//!
//! - statement rows, subject-major: `0x01 ‖ subject ‖ kind ‖ 0 ‖ signer ‖ 0 ‖ digest`.
//!   One subject's statements, and one group's, are each a single prefix range;
//! - order index rows, `(kind, signer, digest)`-major: `0x02 ‖ kind ‖ 0 ‖ signer ‖ 0 ‖
//!   digest`, whose value is the raw subject. Scanning the family streams every
//!   statement in export order.
//!
//! Kinds never contain NUL, because control characters are refused, and signer
//! fingerprints are ASCII. The NUL terminators therefore keep prefix ordering
//! exact, and a prefix such as `kind ‖ 0` never matches a longer kind. Digests
//! are fixed-width raw bytes at the end of each key.

use crate::ids::Oid;

/// Tag of subject-major statement rows.
pub(super) const STATEMENT_TAG: u8 = 0x01;
/// Tag of `(kind, signer, digest)`-major order index rows.
pub(super) const ORDER_TAG: u8 = 0x02;
/// Every order index row.
pub(super) const ORDER_PREFIX: &[u8] = &[ORDER_TAG];

const TERMINATOR: u8 = 0x00;

fn push_text(key: &mut Vec<u8>, text: &str) {
    key.extend_from_slice(text.as_bytes());
    key.push(TERMINATOR);
}

/// Every statement row of one subject.
pub(super) fn subject_prefix(subject: &Oid) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + subject.as_bytes().len());
    key.push(STATEMENT_TAG);
    key.extend_from_slice(subject.as_bytes());
    key
}

/// The statement rows of one subject and kind.
pub(super) fn subject_kind_prefix(subject: &Oid, kind: &str) -> Vec<u8> {
    let mut key = subject_prefix(subject);
    push_text(&mut key, kind);
    key
}

/// The statement rows of one subject whose kind starts with `prefix`: the
/// subject bytes plus the raw prefix, with no terminator, so the scan
/// covers every longer kind. Kinds cannot contain NUL, so byte order keeps
/// the range exact; per-row checks still confirm the prefix.
pub(super) fn subject_kind_prefix_scan(subject: &Oid, prefix: &str) -> Vec<u8> {
    let mut key = subject_prefix(subject);
    key.extend_from_slice(prefix.as_bytes());
    key
}

/// One `(subject, kind, signer)` group: every statement a signer made about one
/// object for one kind.
pub(super) fn group_prefix(subject: &Oid, kind: &str, signer: &str) -> Vec<u8> {
    let mut key = subject_kind_prefix(subject, kind);
    push_text(&mut key, signer);
    key
}

/// The exact key of one statement row.
pub(super) fn statement_key(subject: &Oid, kind: &str, signer: &str, digest: &[u8; 32]) -> Vec<u8> {
    let mut key = group_prefix(subject, kind, signer);
    key.extend_from_slice(digest);
    key
}

/// True when `key` names a subject-major statement row rather than an order
/// index row or an unknown family.
pub(crate) fn is_statement_key(key: &[u8]) -> bool {
    key.first() == Some(&STATEMENT_TAG)
}

/// True when `key` names an order index row. Index values carry the raw
/// subject, so summaries skip them: the statement row staged beside every
/// index row already reported the identity.
pub(crate) fn is_order_key(key: &[u8]) -> bool {
    key.first() == Some(&ORDER_TAG)
}

/// The order index rows of one kind.
pub(super) fn order_kind_prefix(kind: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + kind.len() + 1);
    key.push(ORDER_TAG);
    push_text(&mut key, kind);
    key
}

/// The order index rows whose kind starts with `prefix`: the tag plus the
/// raw prefix, with no terminator. Per-row checks still confirm the prefix.
pub(super) fn order_kind_prefix_scan(prefix: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + prefix.len());
    key.push(ORDER_TAG);
    key.extend_from_slice(prefix.as_bytes());
    key
}

/// The order index rows of one `(kind, signer)` pair.
pub(super) fn order_group_prefix(kind: &str, signer: &str) -> Vec<u8> {
    let mut key = order_kind_prefix(kind);
    push_text(&mut key, signer);
    key
}

/// The exact key of one order index row.
pub(super) fn order_key(kind: &str, signer: &str, digest: &[u8; 32]) -> Vec<u8> {
    let mut key = order_group_prefix(kind, signer);
    key.extend_from_slice(digest);
    key
}

/// The fields that identify one statement inside a key.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Fields<'a> {
    pub(super) kind: &'a str,
    pub(super) signer: &'a str,
    pub(super) digest: [u8; 32],
}

/// Splits `kind ‖ 0 ‖ signer ‖ 0 ‖ digest`, returning `None` for any other shape.
pub(super) fn split_fields(rest: &[u8]) -> Option<Fields<'_>> {
    let kind_end = rest.iter().position(|byte| *byte == TERMINATOR)?;
    let (kind, rest) = rest.split_at(kind_end);
    let rest = rest.get(1..)?;
    let signer_end = rest.iter().position(|byte| *byte == TERMINATOR)?;
    let (signer, rest) = rest.split_at(signer_end);
    let digest: [u8; 32] = rest.get(1..)?.try_into().ok()?;
    Some(Fields {
        kind: std::str::from_utf8(kind).ok()?,
        signer: std::str::from_utf8(signer).ok()?,
        digest,
    })
}

/// Parses an order index key.
pub(super) fn parse_order_key(key: &[u8]) -> Option<Fields<'_>> {
    match key.split_first() {
        Some((&ORDER_TAG, rest)) => split_fields(rest),
        _ => None,
    }
}

/// Parses a statement row key into its subject bytes and fields, given the
/// repository's object width.
pub(super) fn parse_statement_key(key: &[u8], subject_len: usize) -> Option<(&[u8], Fields<'_>)> {
    match key.split_first() {
        Some((&STATEMENT_TAG, rest)) if rest.len() >= subject_len => {
            let (subject, rest) = rest.split_at(subject_len);
            Some((subject, split_fields(rest)?))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid() -> Oid {
        Oid::from_bytes(&[0xab; 20]).expect("oid")
    }

    #[test]
    fn statement_key_round_trips_through_the_parser() {
        let digest = [0x5c; 32];
        let key = statement_key(&oid(), "review", "SHA256:signer", &digest);
        let (subject, fields) = parse_statement_key(&key, 20).expect("parses");
        assert_eq!(subject, oid().as_bytes());
        assert_eq!(fields.kind, "review");
        assert_eq!(fields.signer, "SHA256:signer");
        assert_eq!(fields.digest, digest);
    }

    #[test]
    fn order_key_round_trips_through_the_parser() {
        let digest = [0x01; 32];
        let key = order_key("ci", "SHA256:x", &digest);
        let fields = parse_order_key(&key).expect("parses");
        assert_eq!(fields.kind, "ci");
        assert_eq!(fields.signer, "SHA256:x");
        assert_eq!(fields.digest, digest);
    }

    #[test]
    fn a_kind_prefix_never_captures_a_longer_kind() {
        let short = subject_kind_prefix(&oid(), "review");
        let longer = statement_key(&oid(), "reviewer", "SHA256:s", &[0; 32]);
        assert!(!longer.starts_with(&short));
        let same = statement_key(&oid(), "review", "SHA256:s", &[0; 32]);
        assert!(same.starts_with(&short));
    }

    #[test]
    fn rows_of_one_kind_sort_by_kind_then_signer_then_digest() {
        let low = order_key("alpha", "SHA256:z", &[0xff; 32]);
        let mid = order_key("beta", "SHA256:a", &[0x00; 32]);
        let high = order_key("beta", "SHA256:b", &[0x00; 32]);
        assert!(low < mid && mid < high);
        let shorter = order_key("be", "SHA256:z", &[0xff; 32]);
        assert!(shorter < mid, "a prefix kind sorts before its extension");
    }

    #[test]
    fn malformed_keys_do_not_parse() {
        assert!(parse_order_key(&[ORDER_TAG, b'a', 0, b'b', 0, 1, 2]).is_none());
        assert!(parse_statement_key(&[STATEMENT_TAG, 1, 2], 20).is_none());
    }
}
