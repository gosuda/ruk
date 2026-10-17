//! Exact-CAS preparation of attestation rows for single and batched imports.
//!
//! Preparation never publishes. It verifies every input before any lookup, reads
//! the affected rows, resolves supersession among the batch and the stored rows,
//! derives every post-publication status, and returns fact mutations whose
//! `Absent` and `Value` expectations the store checks at publication. Nothing is
//! visible, and no store state changes, until the caller publishes.
//!
//! Precondition: sole publication-lane ownership with a live object lease
//! covering every subject. The lease keeps subject commits from being collected
//! between the commit-kind check here and publication.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::error::{CoreError, ErrorCode};
use crate::ids::{HashKind, Oid};
use crate::protocol::{AttestAddArgs, AttestationRecord, AttestationStatus, StatementDigest};
use crate::store::{FactExpectation, FactMutation, FactTable, ObjectKind, Store};

use super::layout::{group_prefix, order_key, statement_key};
use super::query::record_of;
use super::rows::{corrupt, decode_row, encode_row, group_limit, load_group, read_statement};
use super::status;
use super::verify::{VerifiedStatement, verify_statement};
use super::work::Work;
use super::{Checkpoint, MAX_GROUP_STATEMENTS, MAX_IMPORT_STATEMENTS};

/// Whether one input statement adds rows or matches rows that already exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// This publication adds the statement's rows.
    Added,
    /// The statement is already stored, or repeats an earlier input of this batch.
    Duplicate,
}

/// The record one input reads as after publication, with its disposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedRecord {
    /// The record, with its status as it will read once the batch is published.
    pub record: AttestationRecord,
    /// Whether this input adds rows or matches existing ones.
    pub disposition: Disposition,
}

/// Fact mutations and per-input records from one preparation.
#[derive(Debug)]
pub struct PreparedAttestations {
    /// Mutations for the attestations table, with exact `Absent` or `Value`
    /// expectations. Empty when every input is already stored.
    pub mutations: Vec<FactMutation>,
    /// One record per input, in input order.
    pub records: Vec<PreparedRecord>,
}

/// Prepares one signed statement. See [`prepare_batch`].
///
/// # Errors
/// Every error of [`prepare_batch`] for a single statement.
pub fn prepare_add(
    store: &Store,
    args: &AttestAddArgs,
    checkpoint: &Checkpoint<'_>,
) -> Result<PreparedAttestations, CoreError> {
    prepare_batch(store, std::slice::from_ref(args), checkpoint)
}

/// Prepares a batch of signed statements for one atomic publication.
///
/// Batch statements may name each other as supersession targets in any order.
/// Identical canonical statements deduplicate, and the first occurrence keeps its
/// signature.
///
/// # Errors
/// - `E_LIMIT`: more than [`MAX_IMPORT_STATEMENTS`] inputs, a group over
///   [`MAX_GROUP_STATEMENTS`], or the call's verification budget.
/// - `E_OBJECT_FORMAT`, `E_INVALID`, `E_VERSION`, `E_POLICY`: verification of
///   any input, reported with its index.
/// - `E_INVALID`: a subject that is not a stored commit, or a cyclic supersession
///   chain within the batch.
/// - `E_NOT_FOUND`: a supersession target that is not a statement of the same
///   subject, kind, and signer, whether dangling or in another group.
/// - `E_CANCELLED`: the checkpoint refused the call.
/// - `E_CORRUPT`: a stored row fails re-verification (latches quarantine).
pub fn prepare_batch(
    store: &Store,
    statements: &[AttestAddArgs],
    checkpoint: &Checkpoint<'_>,
) -> Result<PreparedAttestations, CoreError> {
    if statements.len() > MAX_IMPORT_STATEMENTS {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            format!(
                "an import holds at most {MAX_IMPORT_STATEMENTS} statements, got {}",
                statements.len()
            ),
        ));
    }
    let mut work = Work::new(checkpoint);
    let verified = verify_all(store.hash_kind(), statements, &mut work)?;
    check_subjects(store, &verified)?;
    let batch = Batch::new(verified);
    let existed = stored_flags(store, &batch.unique, &mut work)?;
    let links = Links::resolve(store, &batch, &existed, &mut work)?;
    if status::has_cycle(&links.next) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "supersession among the batch statements is cyclic",
        ));
    }
    let statuses = derive_statuses(store, &batch, &mut work)?;
    let records = build_records(&batch, &existed, &statuses);
    let mutations = build_mutations(&batch.unique, &existed, links.guards, &mut work)?;
    Ok(PreparedAttestations { mutations, records })
}

/// Verifies every input, in input order.
fn verify_all(
    format: HashKind,
    statements: &[AttestAddArgs],
    work: &mut Work<'_>,
) -> Result<Vec<VerifiedStatement>, CoreError> {
    let mut verified = Vec::with_capacity(statements.len());
    for (index, args) in statements.iter().enumerate() {
        work.step()?;
        let statement = verify_statement(format, args).map_err(|mut err| {
            err.message = format!("statement {index}: {}", err.message);
            err
        })?;
        verified.push(statement);
    }
    Ok(verified)
}

/// Every distinct subject must have the repository's width and be a stored
/// commit.
fn check_subjects(store: &Store, verified: &[VerifiedStatement]) -> Result<(), CoreError> {
    let mut checked = HashSet::new();
    for item in verified {
        let subject = item.statement().subject;
        if checked.insert(subject) {
            commit_subject(store, &subject)?;
        }
    }
    Ok(())
}

fn commit_subject(store: &Store, subject: &Oid) -> Result<(), CoreError> {
    subject.expect_kind(store.hash_kind(), "attestation subject")?;
    let object = store.read(*subject)?;
    if object.kind != ObjectKind::Commit {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "attestation subject {subject} is a {:?} object, not a commit",
                object.kind
            ),
        ));
    }
    Ok(())
}

/// The distinct statements of one batch and how each input maps onto them.
struct Batch {
    /// One entry per distinct canonical statement, in first-occurrence order.
    unique: Vec<VerifiedStatement>,
    /// For each input, the `unique` slot it names.
    slot_of: Vec<usize>,
    /// The `unique` slot of each digest.
    slot_by_digest: HashMap<[u8; 32], usize>,
}

impl Batch {
    fn new(verified: Vec<VerifiedStatement>) -> Self {
        let mut unique = Vec::with_capacity(verified.len());
        let mut slot_of = Vec::with_capacity(verified.len());
        let mut slot_by_digest = HashMap::with_capacity(verified.len());
        for item in verified {
            let digest = *item.digest().as_bytes();
            let candidate = unique.len();
            let slot = *slot_by_digest.entry(digest).or_insert(candidate);
            if slot == candidate {
                unique.push(item);
            }
            slot_of.push(slot);
        }
        Self {
            unique,
            slot_of,
            slot_by_digest,
        }
    }
}

/// Whether each distinct statement is already stored. A statement that is not
/// stored must also find its order index row free.
fn stored_flags(
    store: &Store,
    unique: &[VerifiedStatement],
    work: &mut Work<'_>,
) -> Result<Vec<bool>, CoreError> {
    let mut existed = Vec::with_capacity(unique.len());
    for item in unique {
        work.step()?;
        let statement = item.statement();
        let found = read_statement(
            store,
            &statement.subject,
            statement.kind.as_str(),
            item.signer().as_str(),
            item.digest().as_bytes(),
            work,
        )?;
        if found.is_none() {
            order_slot_is_free(store, item)?;
        }
        existed.push(found.is_some());
    }
    Ok(existed)
}

fn order_slot_is_free(store: &Store, item: &VerifiedStatement) -> Result<(), CoreError> {
    let statement = item.statement();
    let key = order_key(
        statement.kind.as_str(),
        item.signer().as_str(),
        item.digest().as_bytes(),
    );
    if store.fact(FactTable::Attestations, &key)?.is_some() {
        return corrupt(
            store,
            "an order index row exists for a statement that is not stored",
        );
    }
    Ok(())
}

/// Supersession links among the batch and the stored rows the batch depends on.
struct Links {
    /// For each `unique` slot, the slot it supersedes, when that statement is in
    /// the batch.
    next: Vec<Option<usize>>,
    /// Stored rows that new statements supersede, by row key. Publication must
    /// still find exactly these bytes.
    guards: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Links {
    fn resolve(
        store: &Store,
        batch: &Batch,
        existed: &[bool],
        work: &mut Work<'_>,
    ) -> Result<Self, CoreError> {
        let mut links = Self {
            next: vec![None; batch.unique.len()],
            guards: BTreeMap::new(),
        };
        for (slot, item) in batch.unique.iter().enumerate() {
            if existed[slot] {
                continue;
            }
            let Some(target) = item.statement().supersedes else {
                continue;
            };
            work.step()?;
            links.link(store, batch, existed, slot, target, work)?;
        }
        Ok(links)
    }

    fn link(
        &mut self,
        store: &Store,
        batch: &Batch,
        existed: &[bool],
        slot: usize,
        target: StatementDigest,
        work: &mut Work<'_>,
    ) -> Result<(), CoreError> {
        let item = &batch.unique[slot];
        let Some(&target_slot) = batch.slot_by_digest.get(target.as_bytes()) else {
            return guard_stored(store, item, target.as_bytes(), &mut self.guards, work);
        };
        if !same_group(item, &batch.unique[target_slot]) {
            return Err(not_in_group());
        }
        self.next[slot] = Some(target_slot);
        if existed[target_slot] {
            guard_stored(store, item, target.as_bytes(), &mut self.guards, work)?;
        }
        Ok(())
    }
}

/// Requires a stored statement of the new statement's group, and records its bytes
/// so publication fails if the row changed or vanished.
fn guard_stored(
    store: &Store,
    item: &VerifiedStatement,
    target: &[u8; 32],
    guards: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    work: &mut Work<'_>,
) -> Result<(), CoreError> {
    let statement = item.statement();
    let key = statement_key(
        &statement.subject,
        statement.kind.as_str(),
        item.signer().as_str(),
        target,
    );
    let Some(bytes) = store.fact(FactTable::Attestations, &key)? else {
        return Err(not_in_group());
    };
    work.verify()?;
    decode_row(store, &key, &bytes)?;
    guards.insert(key, bytes);
    Ok(())
}

fn same_group(left: &VerifiedStatement, right: &VerifiedStatement) -> bool {
    left.statement().subject == right.statement().subject
        && left.statement().kind == right.statement().kind
        && left.signer() == right.signer()
}

fn not_in_group() -> CoreError {
    CoreError::new(
        ErrorCode::ENotFound,
        "supersedes names no statement with the same subject, kind, and signer",
    )
}

/// The status of every distinct statement after publication, computed per group
/// from the stored members and the batch members together.
fn derive_statuses(
    store: &Store,
    batch: &Batch,
    work: &mut Work<'_>,
) -> Result<Vec<AttestationStatus>, CoreError> {
    let mut groups: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
    for (slot, item) in batch.unique.iter().enumerate() {
        let statement = item.statement();
        let key = group_prefix(
            &statement.subject,
            statement.kind.as_str(),
            item.signer().as_str(),
        );
        groups.entry(key).or_default().push(slot);
    }
    let mut statuses = vec![AttestationStatus::Live; batch.unique.len()];
    for slots in groups.values() {
        for (slot, status) in group_statuses(store, batch, slots, work)? {
            statuses[slot] = status;
        }
    }
    Ok(statuses)
}

fn group_statuses(
    store: &Store,
    batch: &Batch,
    slots: &[usize],
    work: &mut Work<'_>,
) -> Result<Vec<(usize, AttestationStatus)>, CoreError> {
    let first = &batch.unique[slots[0]];
    let statement = first.statement();
    let stored = load_group(
        store,
        &statement.subject,
        statement.kind.as_str(),
        first.signer().as_str(),
        work,
    )?;
    let mut present: HashSet<[u8; 32]> = stored
        .iter()
        .map(|member| *member.digest().as_bytes())
        .collect();
    let mut members: Vec<&VerifiedStatement> = stored.iter().collect();
    for &slot in slots {
        let item = &batch.unique[slot];
        if present.insert(*item.digest().as_bytes()) {
            members.push(item);
        }
    }
    if members.len() > MAX_GROUP_STATEMENTS {
        return Err(group_limit());
    }
    let statuses = status::derive(&members);
    let by_digest: HashMap<[u8; 32], AttestationStatus> = members
        .iter()
        .zip(statuses)
        .map(|(member, status)| (*member.digest().as_bytes(), status))
        .collect();
    Ok(slots
        .iter()
        .map(|&slot| (slot, by_digest[batch.unique[slot].digest().as_bytes()]))
        .collect())
}

fn build_records(
    batch: &Batch,
    existed: &[bool],
    statuses: &[AttestationStatus],
) -> Vec<PreparedRecord> {
    let mut seen = vec![false; batch.unique.len()];
    batch
        .slot_of
        .iter()
        .map(|&slot| {
            let disposition = if seen[slot] || existed[slot] {
                Disposition::Duplicate
            } else {
                Disposition::Added
            };
            seen[slot] = true;
            PreparedRecord {
                record: record_of(&batch.unique[slot], statuses[slot]),
                disposition,
            }
        })
        .collect()
}

fn build_mutations(
    unique: &[VerifiedStatement],
    existed: &[bool],
    guards: BTreeMap<Vec<u8>, Vec<u8>>,
    work: &mut Work<'_>,
) -> Result<Vec<FactMutation>, CoreError> {
    let mut mutations = Vec::with_capacity(2 * unique.len() + guards.len());
    for (slot, item) in unique.iter().enumerate() {
        if existed[slot] {
            continue;
        }
        work.produced(2)?;
        mutations.extend(new_rows(item)?);
    }
    for (key, bytes) in guards {
        mutations.push(FactMutation {
            table: FactTable::Attestations,
            key,
            expected: FactExpectation::Value(bytes.clone()),
            value: Some(bytes),
        });
    }
    Ok(mutations)
}

/// The statement row and its order index row, both required to be absent.
fn new_rows(item: &VerifiedStatement) -> Result<[FactMutation; 2], CoreError> {
    let statement = item.statement();
    let kind = statement.kind.as_str();
    let signer = item.signer().as_str();
    let digest = item.digest();
    let row = FactMutation {
        table: FactTable::Attestations,
        key: statement_key(&statement.subject, kind, signer, digest.as_bytes()),
        expected: FactExpectation::Absent,
        value: Some(encode_row(item)?),
    };
    let order = FactMutation {
        table: FactTable::Attestations,
        key: order_key(kind, signer, digest.as_bytes()),
        expected: FactExpectation::Absent,
        value: Some(statement.subject.as_bytes().to_vec()),
    };
    Ok([row, order])
}
