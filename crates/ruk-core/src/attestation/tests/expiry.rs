//! Expiry-bounded land requirements: a verified live statement that is signed
//! after the requirement's validity bound must not satisfy it.
//!
//! Expiry is an evaluation outcome, never a verification verdict. The same
//! statement reads [`AttestationStatus::Live`] through
//! [`subject_statements`], satisfies the unbounded
//! [`evaluate_requirements`], and fails only the bounded evaluation with
//! [`Gap::Expired`]. A tampered signature is the contrast: it refuses the
//! import with `E_INVALID` before any evaluation runs.

use crate::attestation::query::{
    BoundedRequirement, Gap, RequirementOutcome, evaluate_bounded_requirements,
    evaluate_requirements, subject_statements,
};
use crate::attestation::{prepare_add, prepare_batch};
use crate::error::ErrorCode;
use crate::ids::Oid;
use crate::protocol::{AttestRequirement, AttestationStatus, SignerFingerprint, Timestamp};

use super::fixtures::{
    TempStore, apply, independent_fingerprint, key, kind, open, public_bytes, publish_commit,
    result, sign, statement,
};

const SIGNED_AT: &str = "2026-10-17T12:05:00Z";
const BOUND_BEFORE_SIGNING: &str = "2026-10-17T12:00:00Z";
const BOUND_AFTER_SIGNING: &str = "2026-10-17T12:10:00Z";

/// A store holding one live `review/pass` statement on its commit.
struct ExpiryLab {
    temp: TempStore,
    subject: Oid,
    signer: SignerFingerprint,
}

impl ExpiryLab {
    fn new() -> Self {
        let temp = TempStore::new("expiry");
        let subject = publish_commit(
            &temp.store,
            b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nexpiry subject\n",
        );
        let args = sign(
            &key(0x11),
            statement(subject, "review", "pass", SIGNED_AT, None),
        );
        let prepared =
            prepare_add(&temp.store, &args, &open).expect("a verifiable import prepares");
        apply(&temp.store, &prepared);
        let signer = SignerFingerprint::new(independent_fingerprint(&public_bytes(&key(0x11))))
            .expect("fingerprint");
        Self {
            temp,
            subject,
            signer,
        }
    }

    fn bounded(&self, bound: &str) -> BoundedRequirement {
        BoundedRequirement {
            requirement: AttestRequirement {
                kind: kind("review"),
                result: result("pass"),
            },
            valid_until: Timestamp::parse(bound).expect("bound"),
        }
    }
}

#[test]
fn a_statement_signed_after_the_bound_is_expired_not_missing() {
    let lab = ExpiryLab::new();

    let evaluation = evaluate_bounded_requirements(
        &lab.temp.store,
        &lab.subject,
        &[lab.bounded(BOUND_BEFORE_SIGNING)],
        std::slice::from_ref(&lab.signer),
        &open,
    )
    .expect("expiry evaluates");
    assert!(!evaluation.satisfied);
    assert_eq!(
        evaluation.requirements[0].outcome,
        RequirementOutcome::Unsatisfied {
            gap: Gap::Expired {
                signers: vec![lab.signer.clone()],
            },
        },
        "expired is distinct from NoLiveMatch"
    );

    let live = subject_statements(&lab.temp.store, &lab.subject, None, &open).expect("list");
    assert_eq!(live.len(), 1);
    assert_eq!(
        live[0].status,
        AttestationStatus::Live,
        "expiry never changes stored statuses"
    );
}

#[test]
fn a_statement_signed_before_the_bound_satisfies() {
    let lab = ExpiryLab::new();

    let evaluation = evaluate_bounded_requirements(
        &lab.temp.store,
        &lab.subject,
        &[lab.bounded(BOUND_AFTER_SIGNING)],
        std::slice::from_ref(&lab.signer),
        &open,
    )
    .expect("in-bound evaluates");
    assert!(evaluation.satisfied);
    assert!(
        matches!(
            &evaluation.requirements[0].outcome,
            RequirementOutcome::Satisfied { evidence } if evidence.len() == 1
        ),
        "the statement itself is valid; only the bound refuses it"
    );
}

#[test]
fn legacy_evaluation_ignores_validity_bounds() {
    let lab = ExpiryLab::new();
    let required = [AttestRequirement {
        kind: kind("review"),
        result: result("pass"),
    }];

    let evaluation = evaluate_requirements(
        &lab.temp.store,
        &lab.subject,
        &required,
        std::slice::from_ref(&lab.signer),
        &open,
    )
    .expect("unbounded evaluates");
    assert!(
        evaluation.satisfied,
        "bounded filtering is opt-in; existing callers are unchanged"
    );
}

#[test]
fn a_tampered_statement_is_invalid_not_expired() {
    let lab = ExpiryLab::new();
    let genuine = sign(
        &key(0x11),
        statement(lab.subject, "review", "pass", SIGNED_AT, None),
    );
    let mut tampered = genuine.clone();
    tampered.statement.result = result("fail");

    let refused = prepare_batch(&lab.temp.store, &[tampered], &open).expect_err("tampered");
    assert_eq!(
        refused.code,
        ErrorCode::EInvalid,
        "invalid signatures refuse with an error while expiry is an Ok outcome"
    );
}
