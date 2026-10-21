//! Bounded queries, derived statuses, and land requirement evaluation.
//!
//! Every answer derives statuses from the complete group of each statement it
//! reports, so `list`, `subject_statements`, `attested`, and `evaluate_requirements`
//! agree. A group is loaded once per call and cached for the call. Each call has
//! a verification budget, and a page scans at most a bounded number of rows.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::capability::{AttestKind, AttestResult};
use crate::error::{CoreError, ErrorCode};
use crate::ids::Oid;
use crate::protocol::{
    AttestRequirement, AttestationRecord, AttestationStatus, PageLimit, SignerFingerprint,
    Timestamp,
};
use crate::store::{FactRow, Store};

use super::layout::{
    ORDER_PREFIX, group_prefix, order_group_prefix, order_kind_prefix, parse_order_key,
    parse_statement_key, subject_kind_prefix, subject_prefix,
};
use super::rows::{corrupt, decode_row, load_group, read_statement};
use super::status;
use super::verify::VerifiedStatement;
use super::work::{RowScan, Work};
use super::{Checkpoint, MAX_LAND_REQUIREMENTS, MAX_SUBJECT_STATEMENTS, MAX_TRUSTED_SIGNERS};

/// Index rows one `list` page may scan before it returns a short page with a
/// continuation position.
const LIST_SCAN_ROWS: usize = 4096;

/// Which statements a [`list`] call returns.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatementFilter {
    /// Only statements about this exact object.
    pub subject: Option<Oid>,
    /// Only statements of this kind.
    pub kind: Option<AttestKind>,
    /// Only statements by this signer.
    pub signer: Option<SignerFingerprint>,
    /// Whether superseded statements are returned, with their status.
    pub include_superseded: bool,
}

/// One page of statements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationPage {
    /// Up to the page limit of records, in `(kind, signer, payload digest)` order.
    pub records: Vec<AttestationRecord>,
    /// The continuation position, or `None` at the end. Pass it back as `after`
    /// with the same filter.
    pub next: Option<Vec<u8>>,
}

/// Why an attestation requirement is not met.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gap {
    /// No trusted signer has a live statement on the exact subject that matches.
    NoLiveMatch,
    /// Trusted signers have matching statements, but each signer's live statements
    /// conflict, so none of them is unambiguous.
    Ambiguous {
        /// The trusted signers whose matching statements are ambiguous.
        signers: Vec<SignerFingerprint>,
    },
    /// Trusted signers have matching live statements, but every match is signed
    /// after the requirement's validity bound, so none of them counts. Only
    /// [`evaluate_bounded_requirements`] reports this gap; the unbounded
    /// [`evaluate_requirements`] never expires a statement. Expired statements
    /// stay live in storage: unlike invalid signatures (which refuse with an
    /// error) expiry is an evaluation outcome, never corruption.
    Expired {
        /// The trusted signers whose matching statements are all expired.
        signers: Vec<SignerFingerprint>,
    },
}

/// One land requirement with the latest signing time it accepts.
///
/// The bound travels with the requirement, mirroring the
/// [`AttestRequirement::valid_until`](crate::protocol::AttestRequirement::valid_until)
/// protocol field: a live match counts only when its signed `signed_at`
/// is at or before the bound. A later-signed match is expired for this
/// requirement. An absent bound never expires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedRequirement {
    /// The kind and result a trusted signer's live statement must carry.
    pub requirement: AttestRequirement,
    /// The latest `signed_at` this requirement accepts, if any. This is
    /// the enforced bound; callers source it from the requirement's own
    /// `valid_until` field.
    pub valid_until: Option<Timestamp>,
}

/// Whether one requirement is met, and by what.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequirementOutcome {
    /// Met by live matching statements from trusted signers, with their verified
    /// signatures retained for the land plan.
    Satisfied {
        /// The live matching statements, in signer and digest order.
        evidence: Vec<VerifiedStatement>,
    },
    /// Not met.
    Unsatisfied {
        /// Why no live matching statement counts.
        gap: Gap,
    },
}

/// One requirement and its outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequirementEvaluation {
    /// The requirement, as given.
    pub requirement: AttestRequirement,
    /// Whether it is met.
    pub outcome: RequirementOutcome,
}

/// The evaluation of every requirement against one exact subject.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LandEvaluation {
    /// The exact object every requirement applies to.
    pub subject: Oid,
    /// Whether every requirement is met. Vacuously true with no requirements.
    pub satisfied: bool,
    /// One entry per requirement, in input order.
    pub requirements: Vec<RequirementEvaluation>,
}

/// The reply record of one verified statement with its derived status.
pub(super) fn record_of(
    verified: &VerifiedStatement,
    status: AttestationStatus,
) -> AttestationRecord {
    let statement = verified.statement();
    AttestationRecord {
        subject: statement.subject,
        kind: statement.kind.clone(),
        result: statement.result.clone(),
        signer: verified.signer().clone(),
        payload_digest: verified.digest(),
        signed_at: statement.signed_at,
        supersedes: statement.supersedes,
        status,
    }
}

/// Lists statements matching `filter`, one bounded page at a time.
///
/// `after` is the `next` position of the previous page for the same filter, or
/// `None` for the first page. `limit` bounds the page; a page may be short when it
/// reaches the call's scan budget, and then `next` is set.
///
/// # Errors
/// `E_INVALID` for a continuation outside the filter's scope; `E_LIMIT` for the
/// verification budget; `E_CORRUPT` for a row that fails re-verification;
/// `E_CANCELLED` from the checkpoint.
pub fn list(
    store: &Store,
    filter: &StatementFilter,
    limit: PageLimit,
    after: Option<&[u8]>,
    checkpoint: &Checkpoint<'_>,
) -> Result<AttestationPage, CoreError> {
    let (source, prefix) = plan(filter);
    if after.is_some_and(|position| !position.starts_with(&prefix)) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "attestation continuation has the wrong scope",
        ));
    }
    let mut work = Work::new(checkpoint);
    let mut scan = RowScan::new(store, &prefix, after);
    let mut groups = HashMap::new();
    let mut records = Vec::new();
    let mut scanned = 0_usize;
    let mut exhausted = false;
    let mut last = None;
    while records.len() < limit.get() && scanned < LIST_SCAN_ROWS {
        let Some(row) = scan.next_row()? else {
            exhausted = true;
            break;
        };
        work.step()?;
        scanned += 1;
        last = Some(scan.position().to_vec());
        let Some(statement) = resolve(store, source, &row, filter, &mut work)? else {
            continue;
        };
        let status = group_status(store, &mut groups, &statement, &mut work)?;
        if filter.include_superseded || status != AttestationStatus::Superseded {
            records.push(record_of(&statement, status));
        }
    }
    let next = if exhausted { None } else { last };
    Ok(AttestationPage { records, next })
}

/// Every retained statement about `subject`, optionally of one kind, with derived
/// statuses, in `(kind, signer, payload digest)` order. Superseded statements are
/// included.
///
/// # Errors
/// `E_LIMIT` when the subject holds more than [`super::MAX_SUBJECT_STATEMENTS`]
/// statements or the call's verification budget; `E_CORRUPT` for a row that fails
/// re-verification; `E_CANCELLED` from the checkpoint.
pub fn subject_statements(
    store: &Store,
    subject: &Oid,
    kind: Option<&AttestKind>,
    checkpoint: &Checkpoint<'_>,
) -> Result<Vec<AttestationRecord>, CoreError> {
    let prefix = match kind {
        Some(kind) => subject_kind_prefix(subject, kind.as_str()),
        None => subject_prefix(subject),
    };
    let mut work = Work::new(checkpoint);
    let mut scan = RowScan::new(store, &prefix, None);
    let mut members = Vec::new();
    while let Some(row) = scan.next_row()? {
        work.step()?;
        work.verify()?;
        if members.len() == MAX_SUBJECT_STATEMENTS {
            return Err(subject_limit());
        }
        members.push(decode_row(store, &row.key, &row.value)?);
    }
    // A subject scan returns whole groups, and rows are ordered by kind then
    // signer, so each group is one contiguous run.
    let mut records = Vec::with_capacity(members.len());
    for run in members.chunk_by(|left, right| {
        left.statement().kind == right.statement().kind && left.signer() == right.signer()
    }) {
        let refs: Vec<&VerifiedStatement> = run.iter().collect();
        let statuses = status::derive(&refs);
        records.extend(
            run.iter()
                .zip(statuses)
                .map(|(member, status)| record_of(member, status)),
        );
    }
    Ok(records)
}

/// Live and ambiguous statements about `subject` of `kind` with `result`.
///
/// The attested revset uses this. It exposes ambiguity and is not land
/// authorization: [`evaluate_requirements`] decides that.
///
/// # Errors
/// As [`subject_statements`].
pub fn attested(
    store: &Store,
    subject: &Oid,
    kind: &AttestKind,
    result: &AttestResult,
    checkpoint: &Checkpoint<'_>,
) -> Result<Vec<AttestationRecord>, CoreError> {
    let records = subject_statements(store, subject, Some(kind), checkpoint)?;
    Ok(records
        .into_iter()
        .filter(|record| record.result == *result && record.status != AttestationStatus::Superseded)
        .collect())
}

/// Evaluates each requirement against the exact `subject` and the explicit
/// `trusted` signers.
///
/// A requirement is met when some trusted signer has a live statement on exactly
/// `subject` with the requirement's kind and result. Another signer's conflicting
/// statement does not negate it; a conflict within one signer's own live
/// statements makes that signer's statements ambiguous and does not count.
/// This form never expires a statement; [`evaluate_bounded_requirements`]
/// enforces per-requirement validity bounds.
///
/// # Errors
/// `E_POLICY` when requirements exist and no trusted signer is named; `E_LIMIT`
/// for more than [`MAX_LAND_REQUIREMENTS`] requirements or [`MAX_TRUSTED_SIGNERS`]
/// signers, or the call's verification budget; `E_CORRUPT` for a row that fails
/// re-verification; `E_CANCELLED` from the checkpoint.
pub fn evaluate_requirements(
    store: &Store,
    subject: &Oid,
    requirements: &[AttestRequirement],
    trusted: &[SignerFingerprint],
    checkpoint: &Checkpoint<'_>,
) -> Result<LandEvaluation, CoreError> {
    let signers = check_land_policy(requirements.len(), trusted)?;
    let mut work = Work::new(checkpoint);
    let mut groups = HashMap::new();
    let mut outcomes = Vec::with_capacity(requirements.len());
    let mut satisfied = true;
    for requirement in requirements {
        let outcome = evaluate_one(
            store,
            subject,
            requirement,
            None,
            &signers,
            &mut groups,
            &mut work,
        )?;
        satisfied &= matches!(outcome, RequirementOutcome::Satisfied { .. });
        outcomes.push(RequirementEvaluation {
            requirement: requirement.clone(),
            outcome,
        });
    }
    Ok(LandEvaluation {
        subject: *subject,
        satisfied,
        requirements: outcomes,
    })
}

/// Evaluates each validity-bounded requirement against the exact `subject`
/// and the explicit `trusted` signers.
///
/// Like [`evaluate_requirements`], except a live match counts only when its
/// signed `signed_at` is at or before the requirement's `valid_until`. A
/// later-signed match is expired for that requirement: with no other outcome
/// the requirement reports [`Gap::Expired`], naming the signers whose matches
/// are all expired. Ambiguity still outranks expiry, and expiry never changes
/// stored statuses: the same statements read [`AttestationStatus::Live`]
/// through [`subject_statements`].
///
/// # Errors
/// As [`evaluate_requirements`].
pub fn evaluate_bounded_requirements(
    store: &Store,
    subject: &Oid,
    requirements: &[BoundedRequirement],
    trusted: &[SignerFingerprint],
    checkpoint: &Checkpoint<'_>,
) -> Result<LandEvaluation, CoreError> {
    let signers = check_land_policy(requirements.len(), trusted)?;
    let mut work = Work::new(checkpoint);
    let mut groups = HashMap::new();
    let mut outcomes = Vec::with_capacity(requirements.len());
    let mut satisfied = true;
    for bounded in requirements {
        let outcome = evaluate_one(
            store,
            subject,
            &bounded.requirement,
            bounded.valid_until,
            &signers,
            &mut groups,
            &mut work,
        )?;
        satisfied &= matches!(outcome, RequirementOutcome::Satisfied { .. });
        outcomes.push(RequirementEvaluation {
            requirement: bounded.requirement.clone(),
            outcome,
        });
    }
    Ok(LandEvaluation {
        subject: *subject,
        satisfied,
        requirements: outcomes,
    })
}

/// Rejects over-limit or trustless land evaluations before any store read.
fn check_land_policy(
    requirement_count: usize,
    trusted: &[SignerFingerprint],
) -> Result<BTreeSet<&SignerFingerprint>, CoreError> {
    if requirement_count > MAX_LAND_REQUIREMENTS {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            format!("a land policy names at most {MAX_LAND_REQUIREMENTS} requirements"),
        ));
    }
    if trusted.len() > MAX_TRUSTED_SIGNERS {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            format!("a land policy trusts at most {MAX_TRUSTED_SIGNERS} signers"),
        ));
    }
    let signers: BTreeSet<&SignerFingerprint> = trusted.iter().collect();
    if requirement_count > 0 && signers.is_empty() {
        return Err(CoreError::new(
            ErrorCode::EPolicy,
            "required attestations need at least one trusted signer",
        ));
    }
    Ok(signers)
}

/// Whether a live match falls after the requirement's validity bound. With no
/// bound every live match counts; the signed `signed_at` is compared only
/// here, never in status derivation.
fn is_expired(member: &VerifiedStatement, valid_until: Option<Timestamp>) -> bool {
    valid_until.is_some_and(|bound| member.statement().signed_at > bound)
}

fn evaluate_one(
    store: &Store,
    subject: &Oid,
    requirement: &AttestRequirement,
    valid_until: Option<Timestamp>,
    signers: &BTreeSet<&SignerFingerprint>,
    groups: &mut HashMap<Vec<u8>, Group>,
    work: &mut Work<'_>,
) -> Result<RequirementOutcome, CoreError> {
    let mut evidence = Vec::new();
    let mut ambiguous: Vec<SignerFingerprint> = Vec::new();
    let mut expired: Vec<SignerFingerprint> = Vec::new();
    for signer in signers {
        let group = group_entry(
            store,
            groups,
            subject,
            requirement.kind.as_str(),
            signer.as_str(),
            work,
        )?;
        for (member, status) in &group.members {
            if member.statement().result != requirement.result {
                continue;
            }
            match status {
                AttestationStatus::Live if is_expired(member, valid_until) => {
                    if !expired.contains(*signer) {
                        expired.push((*signer).clone());
                    }
                }
                AttestationStatus::Live => evidence.push(member.clone()),
                AttestationStatus::Ambiguous => {
                    if !ambiguous.contains(*signer) {
                        ambiguous.push((*signer).clone());
                    }
                }
                AttestationStatus::Superseded => {}
            }
        }
    }
    if !evidence.is_empty() {
        return Ok(RequirementOutcome::Satisfied { evidence });
    }
    let gap = if !ambiguous.is_empty() {
        Gap::Ambiguous { signers: ambiguous }
    } else if !expired.is_empty() {
        Gap::Expired { signers: expired }
    } else {
        Gap::NoLiveMatch
    };
    Ok(RequirementOutcome::Unsatisfied { gap })
}

/// The family a filter scans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    /// Subject-major statement rows.
    Statements,
    /// `(kind, signer, digest)`-major order index rows.
    Order,
}

/// The family a filter scans and the prefix that bounds the scan. Filters that
/// the prefix cannot express are checked per row.
fn plan(filter: &StatementFilter) -> (Source, Vec<u8>) {
    match (&filter.subject, &filter.kind, &filter.signer) {
        (Some(subject), Some(kind), Some(signer)) => (
            Source::Statements,
            group_prefix(subject, kind.as_str(), signer.as_str()),
        ),
        (Some(subject), Some(kind), None) => (
            Source::Statements,
            subject_kind_prefix(subject, kind.as_str()),
        ),
        (Some(subject), None, _) => (Source::Statements, subject_prefix(subject)),
        (None, Some(kind), Some(signer)) => (
            Source::Order,
            order_group_prefix(kind.as_str(), signer.as_str()),
        ),
        (None, Some(kind), None) => (Source::Order, order_kind_prefix(kind.as_str())),
        (None, None, _) => (Source::Order, ORDER_PREFIX.to_vec()),
    }
}

/// The verified statement behind one scanned row, or `None` when the row fails the
/// filter's per-row checks. Key fields are checked before any verification.
fn resolve(
    store: &Store,
    source: Source,
    row: &FactRow,
    filter: &StatementFilter,
    work: &mut Work<'_>,
) -> Result<Option<VerifiedStatement>, CoreError> {
    match source {
        Source::Statements => resolve_statement_row(store, row, filter, work),
        Source::Order => resolve_order_row(store, row, filter, work),
    }
}

fn resolve_statement_row(
    store: &Store,
    row: &FactRow,
    filter: &StatementFilter,
    work: &mut Work<'_>,
) -> Result<Option<VerifiedStatement>, CoreError> {
    let Some((_, fields)) = parse_statement_key(&row.key, store.hash_kind().oid_len()) else {
        return corrupt(store, "statement row key is malformed");
    };
    if filter
        .signer
        .as_ref()
        .is_some_and(|signer| signer.as_str() != fields.signer)
    {
        return Ok(None);
    }
    work.verify()?;
    decode_row(store, &row.key, &row.value).map(Some)
}

fn resolve_order_row(
    store: &Store,
    row: &FactRow,
    filter: &StatementFilter,
    work: &mut Work<'_>,
) -> Result<Option<VerifiedStatement>, CoreError> {
    let Some(fields) = parse_order_key(&row.key) else {
        return corrupt(store, "order index key is malformed");
    };
    if filter
        .signer
        .as_ref()
        .is_some_and(|signer| signer.as_str() != fields.signer)
    {
        return Ok(None);
    }
    let Ok(subject) = Oid::from_bytes(&row.value) else {
        return corrupt(store, "order index value is not an object id");
    };
    if subject.kind() != store.hash_kind() {
        return corrupt(store, "order index subject has the wrong object format");
    }
    match read_statement(
        store,
        &subject,
        fields.kind,
        fields.signer,
        &fields.digest,
        work,
    )? {
        Some(statement) => Ok(Some(statement)),
        None => corrupt(
            store,
            "order index row names a statement that is not stored",
        ),
    }
}

/// The status of one statement within its group.
fn group_status(
    store: &Store,
    groups: &mut HashMap<Vec<u8>, Group>,
    statement: &VerifiedStatement,
    work: &mut Work<'_>,
) -> Result<AttestationStatus, CoreError> {
    let value = statement.statement();
    let group = group_entry(
        store,
        groups,
        &value.subject,
        value.kind.as_str(),
        statement.signer().as_str(),
        work,
    )?;
    match group.status_of(statement.digest().as_bytes()) {
        Some(status) => Ok(status),
        None => corrupt(store, "statement is missing from its own group"),
    }
}

/// The cached group for `(subject, kind, signer)`, loaded on first use.
fn group_entry<'g>(
    store: &Store,
    groups: &'g mut HashMap<Vec<u8>, Group>,
    subject: &Oid,
    kind: &str,
    signer: &str,
    work: &mut Work<'_>,
) -> Result<&'g mut Group, CoreError> {
    let key = group_prefix(subject, kind, signer);
    let group = match groups.entry(key) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => entry.insert(Group::load(store, subject, kind, signer, work)?),
    };
    Ok(group)
}

/// Every stored member of one group with its derived status.
struct Group {
    members: Vec<(VerifiedStatement, AttestationStatus)>,
    position: HashMap<[u8; 32], usize>,
}

impl Group {
    fn load(
        store: &Store,
        subject: &Oid,
        kind: &str,
        signer: &str,
        work: &mut Work<'_>,
    ) -> Result<Self, CoreError> {
        let members = load_group(store, subject, kind, signer, work)?;
        let statuses = {
            let refs: Vec<&VerifiedStatement> = members.iter().collect();
            status::derive(&refs)
        };
        let position: HashMap<[u8; 32], usize> = members
            .iter()
            .enumerate()
            .map(|(index, member)| (*member.digest().as_bytes(), index))
            .collect();
        Ok(Self {
            members: members.into_iter().zip(statuses).collect(),
            position,
        })
    }

    fn status_of(&self, digest: &[u8; 32]) -> Option<AttestationStatus> {
        self.position
            .get(digest)
            .map(|&index| self.members[index].1)
    }
}

fn subject_limit() -> CoreError {
    CoreError::new(
        ErrorCode::ELimit,
        format!("a subject holds at most {MAX_SUBJECT_STATEMENTS} statements"),
    )
}
