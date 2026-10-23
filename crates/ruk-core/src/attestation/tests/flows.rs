//! Store-backed flows: preparation, CAS, supersession, derived statuses, land
//! requirements, paging, export and reload, cancellation, and quarantine.

use std::cell::Cell;
use std::collections::BTreeSet;

use crate::attestation::{
    Disposition, ExportSummary, Gap, Progress, RequirementOutcome, StatementFilter, attested,
    evaluate_requirements, export, list, parse_export, prepare_add, prepare_batch,
    subject_statements, verify_statement,
};
use crate::error::{CoreError, ErrorCode};
use crate::ids::{HashKind, Oid};
use crate::protocol::{
    AttestRequirement, AttestationRecord, AttestationStatus, PageLimit, SignerFingerprint,
    StatementDigest,
};
use crate::store::{EventContext, EventSource, FactExpectation, FactMutation, FactTable, Store};

use super::fixtures::{
    TempStore, apply, digest_of, independent_fingerprint, key, kind, oid, open, public_bytes,
    publish_blob, publish_commit, result, sign, sign_for, statement,
};

const T0: &str = "2026-10-17T12:00:00Z";
const T1: &str = "2026-10-17T12:05:00Z";
const T2: &str = "2026-10-17T12:10:00Z";
/// Far in the future, and inside the range `Timestamp` parses: the representable
/// maximum is 9999-12-30T22:00:00Z.
const FAR_FUTURE: &str = "9999-12-30T21:00:00Z";

/// Two commits, `a` and `b`, in a fresh store.
struct Lab {
    temp: TempStore,
    a: Oid,
    b: Oid,
}

impl Lab {
    fn new(tag: &str) -> Self {
        let temp = TempStore::new(tag);
        let a = publish_commit(
            &temp.store,
            b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nfirst subject\n",
        );
        let b = publish_commit(
            &temp.store,
            b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nsecond subject\n",
        );
        Self { temp, a, b }
    }

    fn store(&self) -> &Store {
        &self.temp.store
    }

    /// Prepares `args` alone and publishes it.
    fn add(&self, args: &crate::protocol::AttestAddArgs) {
        let prepared = prepare_add(self.store(), args, &open).expect("prepare");
        apply(self.store(), &prepared);
    }
}

fn everything(store: &Store) -> Vec<AttestationRecord> {
    let filter = StatementFilter {
        include_superseded: true,
        ..StatementFilter::default()
    };
    list(store, &filter, PageLimit::MAX, None, &open)
        .expect("list")
        .records
}

fn status_of(records: &[AttestationRecord], digest: StatementDigest) -> AttestationStatus {
    records
        .iter()
        .find(|record| record.payload_digest == digest)
        .expect("record is present")
        .status
}

fn requirement(kind_text: &str, result_text: &str) -> AttestRequirement {
    AttestRequirement {
        kind: kind(kind_text),
        result: result(result_text),
        valid_until: None,
    }
}

fn fingerprint(seed: u8) -> SignerFingerprint {
    let public = public_bytes(&key(seed));
    SignerFingerprint::new(independent_fingerprint(&public)).expect("fingerprint")
}

/// The record of the statement signed by `seed` with `result_text`.
fn find_record<'r>(
    records: &'r [AttestationRecord],
    seed: u8,
    result_text: &str,
) -> &'r AttestationRecord {
    records
        .iter()
        .find(|record| record.signer == fingerprint(seed) && record.result == result(result_text))
        .expect("record is present")
}

/// Five retained statements across two subjects, two kinds, and two signers:
/// a superseded fail, its live pass replacement, an independent pass, a CI pass,
/// and a fail on the second subject.
fn populate(lab: &Lab) {
    let owner = key(0x11);
    let other = key(0x22);
    let fail = sign(&owner, statement(lab.a, "review", "fail", T0, None));
    lab.add(&fail);
    lab.add(&sign(
        &owner,
        statement(lab.a, "review", "pass", T1, Some(digest_of(&fail))),
    ));
    lab.add(&sign(&other, statement(lab.a, "review", "pass", T0, None)));
    lab.add(&sign(&owner, statement(lab.a, "ci", "pass", T0, None)));
    lab.add(&sign(&owner, statement(lab.b, "review", "fail", T0, None)));
}

#[test]
fn single_add_publishes_a_live_statement_and_a_repeat_is_a_duplicate() {
    let lab = Lab::new("single");
    let args = sign(&key(0x11), statement(lab.a, "review", "pass", T0, None));

    let first = prepare_add(lab.store(), &args, &open).expect("prepare");
    assert_eq!(
        first.mutations.len(),
        2,
        "statement row and order index row"
    );
    assert_eq!(first.records[0].disposition, Disposition::Added);
    assert_eq!(first.records[0].record.status, AttestationStatus::Live);
    apply(lab.store(), &first);

    let repeat = prepare_add(lab.store(), &args, &open).expect("prepare repeat");
    assert!(repeat.mutations.is_empty(), "a repeat writes nothing");
    assert_eq!(repeat.records[0].disposition, Disposition::Duplicate);
    assert_eq!(repeat.records[0].record, first.records[0].record);
    assert_eq!(everything(lab.store()).len(), 1);
}

#[test]
fn same_signer_supersession_retires_its_predecessor_and_clears_the_conflict() {
    let lab = Lab::new("supersede");
    let signer = key(0x11);
    let fail = sign(&signer, statement(lab.a, "review", "fail", T0, None));
    lab.add(&fail);
    let fail_digest = digest_of(&fail);

    let pass = sign(
        &signer,
        statement(lab.a, "review", "pass", T1, Some(fail_digest)),
    );
    let prepared = prepare_add(lab.store(), &pass, &open).expect("supersede");
    assert_eq!(
        prepared.mutations.len(),
        3,
        "two rows for the new statement and one guard on the superseded row"
    );
    apply(lab.store(), &prepared);

    let records = everything(lab.store());
    assert_eq!(
        status_of(&records, fail_digest),
        AttestationStatus::Superseded
    );
    assert_eq!(
        status_of(&records, digest_of(&pass)),
        AttestationStatus::Live
    );
    let passing =
        attested(lab.store(), &lab.a, &kind("review"), &result("pass"), &open).expect("attested");
    assert_eq!(passing.len(), 1);
    assert_eq!(passing[0].status, AttestationStatus::Live);
}

#[test]
fn a_conflicting_future_timestamp_never_wins_and_both_statements_stay_ambiguous() {
    let lab = Lab::new("future");
    let signer = key(0x11);
    let pass = sign(&signer, statement(lab.a, "review", "pass", T0, None));
    let future = sign(
        &signer,
        statement(lab.a, "review", "fail", FAR_FUTURE, None),
    );
    lab.add(&pass);
    lab.add(&future);

    let records = everything(lab.store());
    assert_eq!(
        status_of(&records, digest_of(&pass)),
        AttestationStatus::Ambiguous
    );
    assert_eq!(
        status_of(&records, digest_of(&future)),
        AttestationStatus::Ambiguous
    );
    let passing =
        attested(lab.store(), &lab.a, &kind("review"), &result("pass"), &open).expect("attested");
    assert_eq!(passing.len(), 1, "attested exposes the ambiguous match");
    assert_eq!(passing[0].status, AttestationStatus::Ambiguous);

    // A signed supersession of the earlier claim removes the disagreement. The
    // future claim is not promoted by its timestamp; it simply stops conflicting.
    let retire = sign(
        &signer,
        statement(lab.a, "review", "fail", T2, Some(digest_of(&pass))),
    );
    lab.add(&retire);
    let records = everything(lab.store());
    assert_eq!(
        status_of(&records, digest_of(&pass)),
        AttestationStatus::Superseded
    );
    assert_eq!(
        status_of(&records, digest_of(&future)),
        AttestationStatus::Live
    );
    assert_eq!(
        status_of(&records, digest_of(&retire)),
        AttestationStatus::Live
    );
}

#[test]
fn a_different_signer_cannot_supersede_and_the_refusal_writes_nothing() {
    let lab = Lab::new("cross-signer");
    let owner = key(0x11);
    let intruder = key(0x22);
    let original = sign(&owner, statement(lab.a, "review", "fail", T0, None));
    lab.add(&original);

    let usurp = sign(
        &intruder,
        statement(lab.a, "review", "pass", T1, Some(digest_of(&original))),
    );
    let refused = prepare_add(lab.store(), &usurp, &open).expect_err("cross-signer supersession");
    assert_eq!(refused.code, ErrorCode::ENotFound);
    let records = everything(lab.store());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].status, AttestationStatus::Live);
}

#[test]
fn dangling_and_cross_subject_supersession_are_refused() {
    let lab = Lab::new("dangling");
    let signer = key(0x11);
    let dangling = sign(
        &signer,
        statement(
            lab.a,
            "review",
            "pass",
            T0,
            Some(StatementDigest::from_bytes([9; 32])),
        ),
    );
    let refused = prepare_add(lab.store(), &dangling, &open).expect_err("dangling");
    assert_eq!(refused.code, ErrorCode::ENotFound);

    let on_a = sign(&signer, statement(lab.a, "review", "fail", T0, None));
    lab.add(&on_a);
    let cross = sign(
        &signer,
        statement(lab.b, "review", "pass", T1, Some(digest_of(&on_a))),
    );
    let refused = prepare_add(lab.store(), &cross, &open).expect_err("cross subject");
    assert_eq!(refused.code, ErrorCode::ENotFound);
    assert_eq!(everything(lab.store()).len(), 1);
}

#[test]
fn a_batch_resolves_forward_supersession_regardless_of_order() {
    let lab = Lab::new("batch-order");
    let signer = key(0x11);
    let fail = sign(&signer, statement(lab.a, "review", "fail", T0, None));
    // The superseding statement comes first; its target appears later in the batch.
    let pass = sign(
        &signer,
        statement(lab.a, "review", "pass", T1, Some(digest_of(&fail))),
    );

    let prepared = prepare_batch(lab.store(), &[pass.clone(), fail.clone()], &open).expect("batch");
    assert_eq!(
        prepared.mutations.len(),
        4,
        "two statements, two rows each, no guard"
    );
    assert_eq!(prepared.records[0].record.status, AttestationStatus::Live);
    assert_eq!(
        prepared.records[1].record.status,
        AttestationStatus::Superseded
    );
    apply(lab.store(), &prepared);

    let records = everything(lab.store());
    assert_eq!(
        status_of(&records, digest_of(&fail)),
        AttestationStatus::Superseded
    );
    assert_eq!(
        status_of(&records, digest_of(&pass)),
        AttestationStatus::Live
    );
}

#[test]
fn a_batch_adds_each_distinct_statement_once_and_marks_the_repeat() {
    let lab = Lab::new("batch-repeat");
    let args = sign(&key(0x11), statement(lab.a, "ci", "pass", T0, None));
    let prepared = prepare_batch(lab.store(), &[args.clone(), args.clone()], &open).expect("batch");
    assert_eq!(prepared.mutations.len(), 2);
    assert_eq!(prepared.records[0].disposition, Disposition::Added);
    assert_eq!(prepared.records[1].disposition, Disposition::Duplicate);
    apply(lab.store(), &prepared);
    assert_eq!(everything(lab.store()).len(), 1);
}

#[test]
fn one_invalid_member_refuses_the_whole_batch_and_names_its_index() {
    let lab = Lab::new("invalid-member");
    let good = sign(&key(0x11), statement(lab.a, "review", "pass", T0, None));
    let mut bad = good.clone();
    bad.statement.result = result("fail");
    let refused = prepare_batch(lab.store(), &[good, bad], &open).expect_err("refused");
    assert_eq!(refused.code, ErrorCode::EInvalid);
    assert!(
        refused.message.starts_with("statement 1:"),
        "{}",
        refused.message
    );
    assert!(everything(lab.store()).is_empty());
}

#[test]
fn a_subject_must_be_a_stored_commit_of_the_repository_width() {
    let lab = Lab::new("subject");
    let signer = key(0x11);

    let blob = publish_blob(lab.store(), b"not a commit");
    let on_blob = sign(&signer, statement(blob, "review", "pass", T0, None));
    let refused = prepare_add(lab.store(), &on_blob, &open).expect_err("blob subject");
    assert_eq!(refused.code, ErrorCode::EInvalid);

    let absent = oid(0x33);
    let on_absent = sign(&signer, statement(absent, "review", "pass", T0, None));
    let refused = prepare_add(lab.store(), &on_absent, &open).expect_err("absent subject");
    assert_eq!(refused.code, ErrorCode::ENotFound);

    let wide = Oid::from_bytes(&[0x44; 32]).expect("oid");
    let on_wide = sign_for(
        HashKind::Sha256,
        &signer,
        statement(wide, "review", "pass", T0, None),
        crate::attestation::ATTEST_NAMESPACE,
        ssh_key::HashAlg::Sha256,
    );
    let refused = prepare_add(lab.store(), &on_wide, &open).expect_err("wide subject");
    assert_eq!(refused.code, ErrorCode::EObjectFormat);
    assert!(everything(lab.store()).is_empty());
}

#[test]
fn a_prepared_publication_is_refused_when_its_rows_changed_underneath_it() {
    let lab = Lab::new("cas");
    let args = sign(&key(0x11), statement(lab.a, "review", "pass", T0, None));
    let prepared = prepare_add(lab.store(), &args, &open).expect("prepare");
    // A concurrent writer lands the same statement first.
    lab.add(&args);

    let stale = lab
        .store()
        .publish(
            Vec::new(),
            &prepared.mutations,
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect_err("the prepared rows are stale");
    assert_eq!(stale.code(), ErrorCode::EStale);
    assert_eq!(
        everything(lab.store()).len(),
        1,
        "the winning rows stay intact"
    );
}

#[test]
fn a_cancelled_preparation_leaves_the_store_untouched() {
    let lab = Lab::new("cancel");
    let signer = key(0x11);
    let batch = [
        sign(&signer, statement(lab.a, "review", "pass", T0, None)),
        sign(&signer, statement(lab.a, "ci", "pass", T0, None)),
    ];
    let calls = Cell::new(0_u32);
    let revoke_after_first = |_: Progress| -> Result<(), CoreError> {
        calls.set(calls.get() + 1);
        if calls.get() > 1 {
            return Err(CoreError::new(ErrorCode::ECancelled, "admission revoked"));
        }
        Ok(())
    };
    let refused = prepare_batch(lab.store(), &batch, &revoke_after_first).expect_err("cancelled");
    assert_eq!(refused.code, ErrorCode::ECancelled);
    assert!(everything(lab.store()).is_empty());
}

#[test]
fn a_land_requirement_binds_to_the_exact_subject_and_to_named_signers() {
    let lab = Lab::new("land-exact");
    let trusted_key = key(0x22);
    let other_key = key(0x11);
    lab.add(&sign(
        &trusted_key,
        statement(lab.a, "review", "pass", T0, None),
    ));
    lab.add(&sign(
        &other_key,
        statement(lab.b, "review", "pass", T0, None),
    ));
    let required = [requirement("review", "pass")];
    let trusted = [fingerprint(0x22)];

    let met = evaluate_requirements(lab.store(), &lab.a, &required, &trusted, &open)
        .expect("evaluate on a");
    assert!(met.satisfied);
    assert!(matches!(
        &met.requirements[0].outcome,
        RequirementOutcome::Satisfied { evidence } if evidence.len() == 1
    ));

    // The same signer's statement on another object does not satisfy the requirement.
    let elsewhere = evaluate_requirements(lab.store(), &lab.b, &required, &trusted, &open)
        .expect("evaluate on b");
    assert!(!elsewhere.satisfied);
    assert_eq!(
        elsewhere.requirements[0].outcome,
        RequirementOutcome::Unsatisfied {
            gap: Gap::NoLiveMatch
        }
    );

    // A signer that is not named does not count, even when its statement is live.
    let unnamed = [fingerprint(0x11)];
    let not_trusted = evaluate_requirements(lab.store(), &lab.b, &required, &unnamed, &open)
        .expect("evaluate with the other signer");
    assert!(not_trusted.satisfied);
    let not_trusted_on_a = evaluate_requirements(lab.store(), &lab.a, &required, &unnamed, &open)
        .expect("evaluate untrusted on a");
    assert!(!not_trusted_on_a.satisfied);
}

#[test]
fn an_empty_trust_list_cannot_satisfy_a_required_attestation() {
    let lab = Lab::new("empty-trust");
    lab.add(&sign(
        &key(0x22),
        statement(lab.a, "review", "pass", T0, None),
    ));
    let required = [requirement("review", "pass")];

    let refused = evaluate_requirements(lab.store(), &lab.a, &required, &[], &open)
        .expect_err("required attestations need trust");
    assert_eq!(refused.code, ErrorCode::EPolicy);

    let vacuous =
        evaluate_requirements(lab.store(), &lab.a, &[], &[], &open).expect("nothing required");
    assert!(vacuous.satisfied);
}

#[test]
fn a_signers_own_conflict_leaves_its_matching_statement_ambiguous_for_land() {
    let lab = Lab::new("land-ambiguous");
    let signer = key(0x22);
    lab.add(&sign(&signer, statement(lab.a, "review", "pass", T0, None)));
    lab.add(&sign(&signer, statement(lab.a, "review", "fail", T1, None)));
    let required = [requirement("review", "pass")];
    let trusted = [fingerprint(0x22)];

    let evaluation =
        evaluate_requirements(lab.store(), &lab.a, &required, &trusted, &open).expect("evaluate");
    assert!(!evaluation.satisfied);
    assert_eq!(
        evaluation.requirements[0].outcome,
        RequirementOutcome::Unsatisfied {
            gap: Gap::Ambiguous {
                signers: vec![fingerprint(0x22)]
            }
        }
    );
}

#[test]
fn filters_select_by_subject_kind_and_signer_in_export_order() {
    let lab = Lab::new("filters");
    populate(&lab);
    let on_a = StatementFilter {
        subject: Some(lab.a),
        include_superseded: true,
        ..StatementFilter::default()
    };
    let listed = list(lab.store(), &on_a, PageLimit::MAX, None, &open)
        .expect("subject filter")
        .records;
    assert_eq!(listed.len(), 4);
    assert!(listed.iter().all(|record| record.subject == lab.a));

    let by_signer = StatementFilter {
        signer: Some(fingerprint(0x22)),
        include_superseded: true,
        ..StatementFilter::default()
    };
    let signed = list(lab.store(), &by_signer, PageLimit::MAX, None, &open)
        .expect("signer filter")
        .records;
    assert_eq!(signed.len(), 1);
    assert_eq!(signed[0].status, AttestationStatus::Live);

    let all_reviews = subject_statements(lab.store(), &lab.a, Some(&kind("review")), &open)
        .expect("subject statements");
    assert_eq!(all_reviews.len(), 3, "the superseded fail is retained");
    assert_eq!(
        all_reviews
            .iter()
            .filter(|record| record.status == AttestationStatus::Superseded)
            .count(),
        1
    );
}

#[test]
fn kind_prefix_selects_a_kind_family_across_scopes() {
    let lab = Lab::new("kind-prefix");
    let owner = key(0x11);
    lab.add(&sign(&owner, statement(lab.a, "ci/lint", "pass", T0, None)));
    lab.add(&sign(&owner, statement(lab.a, "ci/test", "pass", T0, None)));
    lab.add(&sign(&owner, statement(lab.a, "ci", "pass", T0, None)));
    lab.add(&sign(&owner, statement(lab.a, "review", "pass", T0, None)));
    lab.add(&sign(&owner, statement(lab.b, "ci/lint", "fail", T0, None)));

    let family = StatementFilter {
        kind_prefix: Some(kind("ci/")),
        include_superseded: true,
        ..StatementFilter::default()
    };
    let lint_and_test = list(lab.store(), &family, PageLimit::MAX, None, &open)
        .expect("prefix filter")
        .records;
    assert_eq!(lint_and_test.len(), 3);
    assert!(
        lint_and_test
            .iter()
            .all(|record| record.kind.as_str().starts_with("ci/"))
    );

    let bare = StatementFilter {
        kind_prefix: Some(kind("ci")),
        include_superseded: true,
        ..StatementFilter::default()
    };
    let ci_all = list(lab.store(), &bare, PageLimit::MAX, None, &open)
        .expect("shorter prefix")
        .records;
    assert_eq!(ci_all.len(), 4);

    let disjoint = StatementFilter {
        kind: Some(kind("review")),
        kind_prefix: Some(kind("ci/")),
        include_superseded: true,
        ..StatementFilter::default()
    };
    let none = list(lab.store(), &disjoint, PageLimit::MAX, None, &open)
        .expect("disjoint filters")
        .records;
    assert!(none.is_empty());

    let scoped = StatementFilter {
        subject: Some(lab.a),
        kind_prefix: Some(kind("ci/")),
        include_superseded: true,
        ..StatementFilter::default()
    };
    let on_a = list(lab.store(), &scoped, PageLimit::MAX, None, &open)
        .expect("scoped prefix")
        .records;
    assert_eq!(on_a.len(), 2);
    assert!(on_a.iter().all(|record| record.subject == lab.a));
}

#[test]
fn paged_listing_visits_every_retained_variant_once_and_in_order() {
    let lab = Lab::new("paging");
    populate(&lab);
    let everything_at_once = everything(lab.store());
    assert_eq!(everything_at_once.len(), 5);

    let filter = StatementFilter {
        include_superseded: true,
        ..StatementFilter::default()
    };
    let limit = PageLimit::new(2).expect("limit");
    let mut paged = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let page = list(lab.store(), &filter, limit, after.as_deref(), &open).expect("page");
        paged.extend(page.records);
        match page.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    assert_eq!(paged, everything_at_once);
}

#[test]
fn a_continuation_from_another_scope_is_refused() {
    let lab = Lab::new("scope");
    populate(&lab);
    let page = list(
        lab.store(),
        &StatementFilter::default(),
        PageLimit::new(1).expect("limit"),
        None,
        &open,
    )
    .expect("first page");
    let position = page.next.expect("more rows follow");
    let scoped = StatementFilter {
        subject: Some(lab.b),
        ..StatementFilter::default()
    };
    let refused = list(
        lab.store(),
        &scoped,
        PageLimit::MAX,
        Some(position.as_slice()),
        &open,
    )
    .expect_err("wrong scope");
    assert_eq!(refused.code, ErrorCode::EInvalid);
}

#[test]
fn export_streams_every_variant_and_reload_reproduces_the_same_records() {
    let source = Lab::new("export-source");
    populate(&source);
    let mut bytes = Vec::new();
    let summary: ExportSummary = export(source.store(), &mut bytes, &open).expect("export");
    assert_eq!(summary.statements, 5, "superseded statements are retained");

    let parsed = parse_export(&bytes).expect("parse");
    assert_eq!(parsed.len(), 5);

    let target = Lab::new("export-target");
    let prepared = prepare_batch(target.store(), &parsed, &open).expect("reload");
    assert!(
        prepared
            .records
            .iter()
            .all(|record| record.disposition == Disposition::Added)
    );
    apply(target.store(), &prepared);

    assert_eq!(everything(target.store()), everything(source.store()));
    let mut again = Vec::new();
    export(target.store(), &mut again, &open).expect("re-export");
    assert_eq!(
        again, bytes,
        "export is deterministic and reload is faithful"
    );
}

#[test]
fn export_order_is_kind_then_signer_then_payload_digest() {
    let lab = Lab::new("export-order");
    populate(&lab);
    let mut bytes = Vec::new();
    export(lab.store(), &mut bytes, &open).expect("export");
    let parsed = parse_export(&bytes).expect("parse");
    let sort_keys: Vec<(String, String, [u8; 32])> = parsed
        .iter()
        .map(|args| {
            let verified = verify_statement(HashKind::Sha1, args).expect("verifies");
            (
                args.statement.kind.as_str().to_owned(),
                verified.signer().as_str().to_owned(),
                *verified.digest().as_bytes(),
            )
        })
        .collect();
    assert!(
        sort_keys.windows(2).all(|pair| pair[0] < pair[1]),
        "strictly ordered: {sort_keys:?}"
    );
}

#[test]
fn parsing_an_export_refuses_nesting_beyond_the_protocol_bound() {
    let depth = 200;
    let text = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    let refused = parse_export(text.as_bytes()).expect_err("too deep");
    assert_eq!(refused.code, ErrorCode::EInvalid);
}

#[test]
fn a_stored_row_that_fails_reverification_is_corruption_and_latches_quarantine() {
    use crate::attestation::rows::{ROW_VERSION, StatementRow};

    let lab = Lab::new("corrupt-row");
    let signer = key(0x11);
    let genuine = sign(&signer, statement(lab.a, "review", "pass", T0, None));
    let digest = digest_of(&genuine);
    let signer_text = fingerprint(0x11);

    // A well-formed row whose statement no longer matches its signature.
    let mut tampered = genuine.statement.clone();
    tampered.result = result("fail");
    let row = StatementRow {
        version: ROW_VERSION,
        statement: tampered,
        signer: signer_text.clone(),
        digest,
        signature: genuine.signature.clone(),
    };
    let bytes = crate::store::encode("attestation row", &row).expect("encode row");
    let row_key = crate::attestation::layout::statement_key(
        &lab.a,
        "review",
        signer_text.as_str(),
        digest.as_bytes(),
    );
    lab.store()
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Attestations,
                key: row_key,
                expected: FactExpectation::Absent,
                value: Some(bytes),
            }],
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("plant the unverifiable row");

    let refused = subject_statements(lab.store(), &lab.a, None, &open).expect_err("corrupt");
    assert_eq!(refused.code, ErrorCode::ECorrupt);
    assert!(
        lab.store().quarantine(),
        "committed damage latches quarantine"
    );
}

#[test]
fn one_payload_signed_by_two_signers_keeps_two_live_rows() {
    let lab = Lab::new("two-signers");
    let payload = statement(lab.a, "review", "pass", T0, None);
    let owner = sign(&key(0x11), payload.clone());
    let other = sign(&key(0x22), payload);
    assert_eq!(
        digest_of(&owner),
        digest_of(&other),
        "the signed payload does not name its signer"
    );

    let prepared = prepare_batch(lab.store(), &[owner, other], &open).expect("batch");
    assert_eq!(prepared.mutations.len(), 4, "two rows for each signer");
    assert!(prepared.records.iter().all(|record| {
        record.disposition == Disposition::Added && record.record.status == AttestationStatus::Live
    }));
    apply(lab.store(), &prepared);

    let signers: BTreeSet<SignerFingerprint> = everything(lab.store())
        .into_iter()
        .map(|record| record.signer)
        .collect();
    assert_eq!(
        signers,
        BTreeSet::from([fingerprint(0x11), fingerprint(0x22)])
    );

    let mut exported = Vec::new();
    let summary = export(lab.store(), &mut exported, &open).expect("export");
    assert_eq!(summary.statements, 2);
    assert_eq!(parse_export(&exported).expect("parse").len(), 2);
}

#[test]
fn a_batch_supersession_names_only_its_own_signers_copy_of_a_shared_payload() {
    let lab = Lab::new("shared-batch");
    let payload = statement(lab.a, "review", "fail", T0, None);
    let owner = sign(&key(0x11), payload.clone());
    let other = sign(&key(0x22), payload);
    let other_digest = digest_of(&other);
    let retire = sign(
        &key(0x22),
        statement(lab.a, "review", "pass", T1, Some(other_digest)),
    );

    // The owner's copy comes first. A lookup by digest alone would find that row
    // for the other signer's supersession.
    let prepared = prepare_batch(lab.store(), &[owner, other, retire], &open)
        .expect("the supersession resolves within the superseding signer's group");
    apply(lab.store(), &prepared);

    let records = everything(lab.store());
    assert_eq!(
        find_record(&records, 0x11, "fail").status,
        AttestationStatus::Live
    );
    assert_eq!(
        find_record(&records, 0x22, "fail").status,
        AttestationStatus::Superseded
    );
    let retiring = find_record(&records, 0x22, "pass");
    assert_eq!(retiring.status, AttestationStatus::Live);
    assert_eq!(retiring.supersedes, Some(other_digest));
}

#[test]
fn a_stored_supersession_guards_the_supersedors_own_copy() {
    use crate::attestation::layout::statement_key;

    let lab = Lab::new("shared-stored");
    let payload = statement(lab.a, "review", "fail", T0, None);
    let owner = sign(&key(0x11), payload.clone());
    let other = sign(&key(0x22), payload);
    let other_digest = digest_of(&other);
    let shared = prepare_batch(lab.store(), &[owner, other], &open).expect("shared payload");
    apply(lab.store(), &shared);

    let retire = sign(
        &key(0x22),
        statement(lab.a, "review", "pass", T1, Some(other_digest)),
    );
    let prepared = prepare_add(lab.store(), &retire, &open).expect("supersede the stored copy");
    let guards: Vec<&FactMutation> = prepared
        .mutations
        .iter()
        .filter(|mutation| matches!(mutation.expected, FactExpectation::Value(_)))
        .collect();
    let own_copy = statement_key(
        &lab.a,
        "review",
        fingerprint(0x22).as_str(),
        other_digest.as_bytes(),
    );
    assert_eq!(guards.len(), 1);
    assert_eq!(guards[0].key, own_copy);
}

#[test]
fn a_stored_statement_without_its_order_row_is_corruption() {
    use crate::attestation::layout::statement_key;
    use crate::attestation::rows::encode_row;

    let lab = Lab::new("missing-order");
    let args = sign(&key(0x11), statement(lab.a, "review", "pass", T0, None));
    let verified = verify_statement(HashKind::Sha1, &args).expect("genuine statement");
    let row_key = statement_key(
        &lab.a,
        "review",
        verified.signer().as_str(),
        verified.digest().as_bytes(),
    );
    let row = encode_row(&verified).expect("encode row");
    lab.store()
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::Attestations,
                key: row_key,
                expected: FactExpectation::Absent,
                value: Some(row),
            }],
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("plant the statement row without its order row");

    let refused = prepare_add(lab.store(), &args, &open).expect_err("the order row is missing");
    assert_eq!(refused.code, ErrorCode::ECorrupt);
    assert!(
        lab.store().quarantine(),
        "committed damage latches quarantine"
    );
}
