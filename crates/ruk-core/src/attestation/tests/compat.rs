//! Storage compatibility: pre-evidence v1 rows stay readable after the v2
//! upgrade, and an unknown row version is corruption, never a guess.

use crate::attestation::layout::{order_key, statement_key};
use crate::attestation::rows::{decode_row, encode_v1_test_row};
use crate::attestation::{StatementFilter, list, prepare_add, verify_statement};
use crate::error::ErrorCode;
use crate::ids::HashKind;
use crate::protocol::{PageLimit, StatementDigest};
use crate::store::{EventContext, EventSource, FactExpectation, FactMutation, FactTable};

use super::fixtures::{TempStore, apply, key, open, publish_commit, sign, sign_v1, statement};

const T0: &str = "2026-10-17T12:00:00Z";

#[test]
fn v1_stored_rows_decode_and_verify_after_the_v2_upgrade() {
    let temp = TempStore::new("v1-rows-stay-readable");
    let subject = publish_commit(
        &temp.store,
        b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nv1 subject\n",
    );
    let args = sign_v1(&key(0x11), statement(subject, "review", "pass", T0, None));
    let verified = verify_statement(HashKind::Sha1, &args).expect("v1 signature verifies");
    let row_key = statement_key(
        &subject,
        "review",
        verified.signer().as_str(),
        verified.digest().as_bytes(),
    );
    let row_value = encode_v1_test_row(&verified);
    temp.store
        .publish(
            Vec::new(),
            &[
                FactMutation {
                    table: FactTable::Attestations,
                    key: row_key.clone(),
                    expected: FactExpectation::Absent,
                    value: Some(row_value.clone()),
                },
                FactMutation {
                    table: FactTable::Attestations,
                    key: order_key(
                        "review",
                        verified.signer().as_str(),
                        verified.digest().as_bytes(),
                    ),
                    expected: FactExpectation::Absent,
                    value: Some(subject.as_bytes().to_vec()),
                },
            ],
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("publish v1 row");

    let read = decode_row(&temp.store, &row_key, &row_value).expect("v1 row decodes");
    assert!(read.statement().evidence.is_none());
    assert_eq!(read.digest(), verified.digest());

    let filter = StatementFilter {
        include_superseded: true,
        ..StatementFilter::default()
    };
    let page = list(&temp.store, &filter, PageLimit::MAX, None, &open).expect("list a v1 row");
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].payload_digest, verified.digest());
}

#[test]
fn v2_rows_with_evidence_decode_and_list() {
    let temp = TempStore::new("v2-rows-with-evidence");
    let subject = publish_commit(
        &temp.store,
        b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nv2 subject\n",
    );
    let mut evidenced_statement = statement(subject, "ci", "pass", T0, None);
    evidenced_statement.evidence = Some(StatementDigest::from_bytes([7; 32]));
    let args = sign(&key(0x11), evidenced_statement);
    let prepared = prepare_add(&temp.store, &args, &open).expect("prepare");
    assert!(!prepared.mutations.is_empty());
    apply(&temp.store, &prepared);

    let filter = StatementFilter {
        include_superseded: true,
        ..StatementFilter::default()
    };
    let page = list(&temp.store, &filter, PageLimit::MAX, None, &open).expect("list a v2 row");
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].kind.as_str(), "ci");
}

#[test]
fn tampered_row_version_is_corruption_not_a_guess() {
    let temp = TempStore::new("bad-row-version");
    let subject = publish_commit(
        &temp.store,
        b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nversion subject\n",
    );
    let args = sign_v1(&key(0x11), statement(subject, "review", "pass", T0, None));
    let verified = verify_statement(HashKind::Sha1, &args).expect("v1 signature verifies");
    let mut row_value = encode_v1_test_row(&verified);
    row_value[0] = 9;
    let row_key = statement_key(
        &subject,
        "review",
        verified.signer().as_str(),
        verified.digest().as_bytes(),
    );
    let err = decode_row(&temp.store, &row_key, &row_value).expect_err("version 9 is damage");
    assert_eq!(err.code, ErrorCode::ECorrupt);
}
