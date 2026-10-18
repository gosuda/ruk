use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::clock::Clock;
use crate::change::{ClaimId, SessionId};
use crate::index::RepoPath;
use crate::protocol::{
    BoundedList, ClaimAcquireArgs, ClaimMode, ClaimRecord, MAX_CLAIM_TTL_SECONDS, MAX_PAGE_SIZE,
    Timestamp, Warning,
};
use crate::store::{FactExpectation, FactMutation, FactPageBudget, FactTable, Store, StoreError};
use crate::{CoreError, ErrorCode, MAX_CONTROL_FRAME_BYTES};

#[cfg(test)]
mod tests;

pub(crate) const CLOCK_KEY: &[u8] = b"T";

#[derive(Serialize, Deserialize)]
struct ClaimRow {
    version: u8,
    created: Timestamp,
    record: ClaimRecord,
}

#[derive(Serialize, Deserialize)]
struct ClockRow {
    version: u8,
    at: Timestamp,
}

pub(crate) struct ClaimClock {
    clock: Clock,
    start_wall: jiff::Timestamp,
    start_mono: Instant,
}

pub(crate) struct ClaimChange {
    pub(crate) record: ClaimRecord,
    pub(crate) facts: Vec<FactMutation>,
    pub(crate) warnings: BoundedList<Warning>,
}

pub(crate) struct ClaimCheck {
    pub(crate) facts: Vec<FactMutation>,
    pub(crate) warnings: BoundedList<Warning>,
}

pub(crate) enum ClaimListing {
    Mine(SessionId),
    AllAuthorized,
}

pub(crate) struct ClaimPage {
    pub(crate) records: Vec<ClaimRecord>,
    pub(crate) next: Option<Vec<u8>>,
}

pub(crate) struct ClaimSweep {
    pub(crate) facts: Vec<FactMutation>,
    pub(crate) next: Option<Vec<u8>>,
}

struct Work {
    bytes: usize,
    rows: usize,
}

impl Work {
    fn new() -> Self {
        Self { bytes: 0, rows: 0 }
    }

    fn charge(&mut self, bytes: usize) -> Result<(), CoreError> {
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(limit)?;
        self.rows = self.rows.checked_add(1).ok_or_else(limit)?;
        if self.bytes > MAX_CONTROL_FRAME_BYTES || self.rows > MAX_PAGE_SIZE {
            return Err(limit());
        }
        Ok(())
    }
}

impl ClaimClock {
    pub(crate) fn open(store: &Store, clock: Clock) -> Result<Self, CoreError> {
        let sample = clock.sample()?;
        let persisted = read_clock(store)?.map(|(_, row)| row.at.instant());
        Ok(Self {
            clock,
            start_wall: persisted.map_or(sample.wall, |at| at.max(sample.wall)),
            start_mono: sample.mono,
        })
    }

    fn now(&self) -> Result<Timestamp, CoreError> {
        let sample = self.clock.sample()?;
        let elapsed = sample
            .mono
            .checked_duration_since(self.start_mono)
            .ok_or_else(|| {
                CoreError::new(ErrorCode::EIo, "claim monotonic clock moved backward")
            })?;
        let elapsed = jiff::SignedDuration::try_from(elapsed)
            .map_err(|err| CoreError::new(ErrorCode::EIo, err.to_string()))?;
        let advanced = self
            .start_wall
            .checked_add(elapsed)
            .map_err(|err| CoreError::new(ErrorCode::EIo, err.to_string()))?;
        Ok(Timestamp::new(advanced.max(sample.wall)))
    }

    fn fence(&self, store: &Store) -> Result<(Timestamp, Vec<FactMutation>), CoreError> {
        let previous = read_clock(store)?;
        let now = self.now()?;
        let at = previous.as_ref().map_or(now, |(_, row)| now.max(row.at));
        if previous.as_ref().is_some_and(|(_, row)| row.at == at) {
            return Ok((at, Vec::new()));
        }
        let expected = previous.map_or(FactExpectation::Absent, |(raw, _)| {
            FactExpectation::Value(raw)
        });
        let value = crate::store::encode("claim clock", &ClockRow { version: 1, at })?;
        Ok((
            at,
            vec![FactMutation {
                table: FactTable::Claims,
                key: CLOCK_KEY.to_vec(),
                expected,
                value: Some(value),
            }],
        ))
    }
}

/// The caller holds sole lane ownership until these facts commit. Current
/// session policy is checked by the caller. Claim-changing batches must not
/// share a publication without a consistent accepted-update overlay.
pub(crate) fn seal_acquire(
    store: &Store,
    clock: &ClaimClock,
    holder: SessionId,
    claim: ClaimId,
    args: ClaimAcquireArgs,
) -> Result<ClaimChange, CoreError> {
    if holder == SessionId::nil() || claim == ClaimId::nil() {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "claim identities must not be nil",
        ));
    }
    let paths = canonical_paths(args.paths)?;
    let (now, mut facts) = clock.fence(store)?;
    let warnings = check_paths(store, holder, &paths, now)?;
    let expires = now
        .instant()
        .checked_add(jiff::SignedDuration::from_secs(i64::from(
            args.ttl.seconds(),
        )))
        .map_err(|err| CoreError::new(ErrorCode::EInvalid, err.to_string()))?;
    let record = ClaimRecord {
        claim,
        holder,
        paths,
        mode: args.mode,
        expires_at: Timestamp::new(expires),
    };
    let row = ClaimRow {
        version: 1,
        created: now,
        record,
    };
    let raw = crate::store::encode("claim", &row)?;
    let keys = row_keys(&row.record)?;
    let mut work = Work::new();
    work.charge(raw.len())?;
    for key in keys {
        work.charge(key.len())?;
        if store.fact(FactTable::Claims, &key)?.is_some() {
            return Err(CoreError::new(
                ErrorCode::EStale,
                "claim identity or index already exists",
            ));
        }
        if key[0] != b'R' {
            facts.push(FactMutation {
                table: FactTable::Claims,
                key,
                expected: FactExpectation::Absent,
                value: Some(Vec::new()),
            });
        }
    }
    facts.push(FactMutation {
        table: FactTable::Claims,
        key: record_key(row.record.claim),
        expected: FactExpectation::Absent,
        value: Some(raw),
    });
    Ok(ClaimChange {
        record: row.record,
        facts,
        warnings,
    })
}

/// The caller holds sole lane ownership through publication. Only the holder
/// can release the claim, including an expired claim.
pub(crate) fn seal_release(
    store: &Store,
    clock: &ClaimClock,
    holder: SessionId,
    claim: ClaimId,
) -> Result<ClaimChange, CoreError> {
    let (raw, row) = read_claim(store, claim)?
        .ok_or_else(|| CoreError::new(ErrorCode::ENotFound, "claim does not exist"))?;
    if row.record.holder != holder {
        return Err(CoreError::new(
            ErrorCode::EForbidden,
            "claim belongs to another session",
        ));
    }
    let (_, mut facts) = clock.fence(store)?;
    remove_record(store, &row, raw, &mut facts)?;
    Ok(ClaimChange {
        record: row.record,
        facts,
        warnings: BoundedList::complete(Vec::new())?,
    })
}

/// Checks claims and captures the clock watermark in the same mutation. The
/// caller must commit these facts with the checked write under sole lane ownership.
pub(crate) fn seal_write(
    store: &Store,
    clock: &ClaimClock,
    holder: SessionId,
    paths: &[RepoPath],
) -> Result<ClaimCheck, CoreError> {
    let (now, facts) = clock.fence(store)?;
    let warnings = check_paths(store, holder, paths, now)?;
    Ok(ClaimCheck { facts, warnings })
}

/// Canonicalizes a claim path set without touching the store: sorts,
/// dedupes, and drops paths already covered by an ancestor.
///
/// Pure, so preparation may call it for its pending reply; sealing stays in
/// the lane.
///
/// # Errors
/// `E_INVALID` when the set is empty.
pub(crate) fn canonical_paths(mut paths: Vec<RepoPath>) -> Result<Vec<RepoPath>, CoreError> {
    if paths.is_empty() {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "claim paths must not be empty",
        ));
    }
    let mut work = Work::new();
    for path in &paths {
        work.charge(path.as_bytes().len())?;
    }
    paths.sort_unstable();
    paths.dedup();
    let mut canonical: Vec<RepoPath> = Vec::with_capacity(paths.len());
    for path in paths {
        let covered = path
            .as_bytes()
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte == b'/')
            .any(|(end, _)| {
                canonical
                    .binary_search_by(|other| other.as_bytes().cmp(&path.as_bytes()[..end]))
                    .is_ok()
            });
        if !covered {
            canonical.push(path);
        }
    }
    Ok(canonical)
}

fn check_paths(
    store: &Store,
    holder: SessionId,
    paths: &[RepoPath],
    now: Timestamp,
) -> Result<BoundedList<Warning>, CoreError> {
    let mut warnings = Vec::new();
    let mut work = Work::new();
    for path in paths {
        work.charge(path.as_bytes().len())?;
        for end in path
            .as_bytes()
            .iter()
            .enumerate()
            .filter_map(|(index, byte)| (*byte == b'/').then_some(index))
            .chain(std::iter::once(path.as_bytes().len()))
        {
            let mut prefix = path_prefix(&path.as_bytes()[..end]);
            prefix.push(0);
            check_range(store, holder, &prefix, path, now, &mut work, &mut warnings)?;
        }
        let mut prefix = path_prefix(path.as_bytes());
        prefix.push(b'/');
        check_range(store, holder, &prefix, path, now, &mut work, &mut warnings)?;
    }
    BoundedList::complete(warnings)
}

fn check_range(
    store: &Store,
    holder: SessionId,
    prefix: &[u8],
    requested: &RepoPath,
    now: Timestamp,
    work: &mut Work,
    warnings: &mut Vec<Warning>,
) -> Result<(), CoreError> {
    work.charge(prefix.len())?;
    let mut after = prefix.to_vec();
    loop {
        let page = store.fact_page(
            FactTable::Claims,
            Some(&after),
            FactPageBudget::new(1, MAX_CONTROL_FRAME_BYTES),
        )?;
        let Some(index) = page.rows.into_iter().next() else {
            return Ok(());
        };
        if !index.key.starts_with(prefix) {
            return Ok(());
        }
        work.charge(
            index
                .key
                .len()
                .checked_add(index.value.len())
                .ok_or_else(limit)?,
        )?;
        let (_, row) = indexed_claim(store, &index.key, &index.value, work)?;
        if row.record.expires_at > now && row.record.holder != holder {
            if row.record.mode == ClaimMode::Enforce {
                return Err(CoreError::new(
                    ErrorCode::EClaimed,
                    "path overlaps another session's enforced claim",
                ));
            }
            let duplicate = warnings.iter().any(|warning| matches!(warning,
                Warning::ClaimAdvisory { path, holder } if path == requested && *holder == row.record.holder));
            if !duplicate {
                work.charge(requested.as_bytes().len())?;
                warnings.push(Warning::ClaimAdvisory {
                    path: requested.clone(),
                    holder: row.record.holder,
                });
            }
        }
        after = index.key;
        if !page.more {
            return Ok(());
        }
    }
}

fn indexed_claim(
    store: &Store,
    key: &[u8],
    value: &[u8],
    work: &mut Work,
) -> Result<(usize, ClaimRow), CoreError> {
    if !value.is_empty() || key.len() < 17 {
        return Err(corrupt(store, "invalid claim index row"));
    }
    let id: [u8; 16] = key[key.len() - 16..]
        .try_into()
        .map_err(|_| corrupt(store, "invalid claim index identity"))?;
    let (raw, row) = read_claim(store, ClaimId::from_bytes(id))?
        .ok_or_else(|| corrupt(store, "claim index names a missing record"))?;
    work.charge(raw.len())?;
    let valid = match key[0] {
        b'H' => key.len() == 33 && key[1..17] == row.record.holder.as_bytes()[..],
        b'P' => {
            key.len() >= 19
                && key[key.len() - 17] == 0
                && row
                    .record
                    .paths
                    .iter()
                    .any(|path| path.as_bytes() == &key[1..key.len() - 17])
        }
        _ => false,
    };
    if !valid {
        return Err(corrupt(store, "claim index disagrees with its record"));
    }
    Ok((raw.len(), row))
}

/// Pages raw claim records without lease binding.
///
/// [`list_page`] calls this after verifying the presented cursor against
/// its leased view. The hosted coordinator's cursor-free first-page read
/// also calls this, with `after` always `None`: the returned page may carry
/// a resume position (`next` is `Some`), and the caller mints a lease-bound
/// continuation cursor for it. Callers verify continuations against the
/// lease before serving them; no caller may serve a non-exhausted raw page
/// as a complete answer.
pub(crate) fn list_page_raw(
    store: &Store,
    clock: &ClaimClock,
    listing: ClaimListing,
    after: Option<&[u8]>,
    budget: FactPageBudget,
) -> Result<ClaimPage, CoreError> {
    validate_budget(budget)?;
    let prefix = match listing {
        ClaimListing::Mine(holder) => holder_prefix(holder),
        ClaimListing::AllAuthorized => vec![b'R'],
    };
    let after = checked_position(&prefix, after)?;
    let page = store.fact_page(FactTable::Claims, Some(after), budget)?;
    let now = clock.now()?;
    let mut records = Vec::new();
    let mut work = Work::new();
    let mut last = None;
    let mut ended = false;
    let mut copied = 0usize;
    let mut byte_limited = false;
    for item in page.rows {
        if !item.key.starts_with(&prefix) {
            ended = true;
            break;
        }
        work.charge(
            item.key
                .len()
                .checked_add(item.value.len())
                .ok_or_else(limit)?,
        )?;
        let (size, row) = if prefix[0] == b'R' {
            (
                item.value.len(),
                decode_claim(store, &item.key, &item.value)?,
            )
        } else {
            indexed_claim(store, &item.key, &item.value, &mut work)?
        };
        if row.record.expires_at > now {
            let next_size = copied.checked_add(size).ok_or_else(limit)?;
            if next_size > budget.bytes {
                if last.is_none() {
                    return Err(limit());
                }
                byte_limited = true;
                break;
            }
            copied = next_size;
            records.push(row.record);
        }
        last = Some(item.key);
    }
    let next = if byte_limited {
        last
    } else if page.more && !ended {
        next_in_prefix(store, &prefix, last)?
    } else {
        None
    };
    Ok(ClaimPage { records, next })
}

/// Selects one bounded raw-record page. Commit all returned index deletions and
/// the clock fence together under sole lane ownership.
pub(crate) fn sweep_page(
    store: &Store,
    clock: &ClaimClock,
    after: Option<&[u8]>,
    budget: FactPageBudget,
) -> Result<ClaimSweep, CoreError> {
    validate_budget(budget)?;
    let after = checked_position(b"R", after)?;
    let page = store.fact_page(FactTable::Claims, Some(after), budget)?;
    let (now, mut facts) = clock.fence(store)?;
    let mut last = None;
    let mut ended = false;
    let mut work = Work::new();
    for item in page.rows {
        if !item.key.starts_with(b"R") {
            ended = true;
            break;
        }
        work.charge(
            item.key
                .len()
                .checked_add(item.value.len())
                .ok_or_else(limit)?,
        )?;
        let row = decode_claim(store, &item.key, &item.value)?;
        last = Some(item.key);
        if row.record.expires_at <= now {
            for key in row_keys(&row.record)? {
                work.charge(key.len())?;
            }
            remove_record(store, &row, item.value, &mut facts)?;
        }
    }
    let next = if page.more && !ended {
        next_in_prefix(store, b"R", last)?
    } else {
        None
    };
    Ok(ClaimSweep { facts, next })
}

fn next_in_prefix(
    store: &Store,
    prefix: &[u8],
    last: Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>, CoreError> {
    let Some(position) = last else {
        return Ok(None);
    };
    let next = store.fact_page(
        FactTable::Claims,
        Some(&position),
        FactPageBudget::new(1, MAX_CONTROL_FRAME_BYTES),
    )?;
    Ok(next
        .rows
        .first()
        .is_some_and(|row| row.key.starts_with(prefix))
        .then_some(position))
}

fn validate_budget(budget: FactPageBudget) -> Result<(), CoreError> {
    if budget.rows == 0
        || budget.rows > MAX_PAGE_SIZE
        || budget.bytes == 0
        || budget.bytes > MAX_CONTROL_FRAME_BYTES
    {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "claim page budget is outside the protocol bounds",
        ));
    }
    Ok(())
}

fn checked_position<'a>(prefix: &'a [u8], after: Option<&'a [u8]>) -> Result<&'a [u8], CoreError> {
    match after {
        Some(position) if position.starts_with(prefix) => Ok(position),
        Some(_) => Err(CoreError::new(
            ErrorCode::EInvalid,
            "claim continuation has the wrong scope",
        )),
        None => Ok(prefix),
    }
}

fn remove_record(
    store: &Store,
    row: &ClaimRow,
    raw: Vec<u8>,
    facts: &mut Vec<FactMutation>,
) -> Result<(), CoreError> {
    for key in row_keys(&row.record)?
        .into_iter()
        .filter(|key| key[0] != b'R')
    {
        let value = store
            .fact(FactTable::Claims, &key)?
            .ok_or_else(|| corrupt(store, "claim record is missing an index"))?;
        if !value.is_empty() {
            return Err(corrupt(store, "claim index value is not empty"));
        }
        facts.push(FactMutation {
            table: FactTable::Claims,
            key,
            expected: FactExpectation::Value(value),
            value: None,
        });
    }
    facts.push(FactMutation {
        table: FactTable::Claims,
        key: record_key(row.record.claim),
        expected: FactExpectation::Value(raw),
        value: None,
    });
    Ok(())
}

fn row_keys(record: &ClaimRecord) -> Result<Vec<Vec<u8>>, CoreError> {
    let mut work = Work::new();
    let mut keys = Vec::with_capacity(record.paths.len().checked_add(2).ok_or_else(limit)?);
    keys.push(record_key(record.claim));
    let mut holder = holder_prefix(record.holder);
    holder.extend_from_slice(record.claim.as_bytes());
    keys.push(holder);
    for path in &record.paths {
        work.charge(path.as_bytes().len().checked_add(18).ok_or_else(limit)?)?;
        let mut key = path_prefix(path.as_bytes());
        key.push(0);
        key.extend_from_slice(record.claim.as_bytes());
        keys.push(key);
    }
    Ok(keys)
}

fn record_key(claim: ClaimId) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(b'R');
    key.extend_from_slice(claim.as_bytes());
    key
}

fn holder_prefix(holder: SessionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(b'H');
    key.extend_from_slice(holder.as_bytes());
    key
}

fn path_prefix(path: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(path.len() + 1);
    key.push(b'P');
    key.extend_from_slice(path);
    key
}

/// Reads one stored claim record without sealing anything.
///
/// Read-only, so preparation may call it to predict its pending reply; the
/// lane re-reads authoritatively at commit time.
pub(crate) fn read_record(
    store: &Store,
    claim: ClaimId,
) -> Result<Option<ClaimRecord>, CoreError> {
    Ok(read_claim(store, claim)?.map(|(_, row)| row.record))
}

fn read_claim(store: &Store, claim: ClaimId) -> Result<Option<(Vec<u8>, ClaimRow)>, CoreError> {
    let key = record_key(claim);
    store
        .fact(FactTable::Claims, &key)?
        .map(|raw| decode_claim(store, &key, &raw).map(|row| (raw, row)))
        .transpose()
}

fn decode_claim(store: &Store, key: &[u8], raw: &[u8]) -> Result<ClaimRow, CoreError> {
    let row: ClaimRow = store.observe(crate::store::decode("claim", raw))?;
    if row.version != 1
        || key != record_key(row.record.claim)
        || row.record.claim == ClaimId::nil()
        || row.record.holder == SessionId::nil()
        || row.created >= row.record.expires_at
    {
        return Err(corrupt(store, "invalid claim record"));
    }
    let maximum = row
        .created
        .instant()
        .checked_add(jiff::SignedDuration::from_secs(i64::from(
            MAX_CLAIM_TTL_SECONDS,
        )))
        .map_err(|_| corrupt(store, "claim lifetime overflows"))?;
    if row.record.expires_at.instant() > maximum {
        return Err(corrupt(store, "claim lifetime exceeds one hour"));
    }
    let mut previous: Option<&RepoPath> = None;
    for path in &row.record.paths {
        if previous.is_some_and(|prior| prior >= path) {
            return Err(corrupt(store, "claim paths are not canonical"));
        }
        let redundant = path
            .as_bytes()
            .iter()
            .enumerate()
            .filter(|(_, byte)| **byte == b'/')
            .any(|(end, _)| {
                row.record
                    .paths
                    .binary_search_by(|other| other.as_bytes().cmp(&path.as_bytes()[..end]))
                    .is_ok()
            });
        if redundant {
            return Err(corrupt(store, "claim contains a redundant descendant"));
        }
        previous = Some(path);
    }
    if previous.is_none() {
        return Err(corrupt(store, "claim has no paths"));
    }
    Ok(row)
}

fn read_clock(store: &Store) -> Result<Option<(Vec<u8>, ClockRow)>, CoreError> {
    store
        .fact(FactTable::Claims, CLOCK_KEY)?
        .map(|raw| {
            let row: ClockRow = store.observe(crate::store::decode("claim clock", &raw))?;
            if row.version != 1 {
                return Err(corrupt(store, "invalid claim clock version"));
            }
            Ok((raw, row))
        })
        .transpose()
}

fn limit() -> CoreError {
    CoreError::new(
        ErrorCode::ELimit,
        "claim lookup or result exceeds its bounded work budget",
    )
}

fn corrupt(store: &Store, detail: &str) -> CoreError {
    let _ = store.observe::<()>(Err(StoreError::Corrupt(detail.to_owned())));
    CoreError::new(ErrorCode::ECorrupt, detail)
}

/// How one lane operation seals against concurrent claim changes.
///
/// Named operations replace a boolean flag: each variant selects the seal
/// function the lane runs before mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClaimSealKind {
    /// Checks paths and fences the claim clock without creating a record.
    Write,
    /// Creates a claim record.
    Acquire,
    /// Removes a claim record.
    Release,
}

/// One seal envelope per lane mutation.
///
/// The lane builds the envelope before mutation with
/// [`ClaimSealEnvelope::for_mutation`], publishes the envelope facts
/// atomically with the operation on settle, and drops them on abort.
/// Path-carrying operations cover their declared paths; operations without
/// declared paths seal the claim clock only until the lane threads
/// change-ID-scoped keys through.
#[derive(Debug)]
pub(crate) struct ClaimSealEnvelope {
    /// Which seal function produced this envelope.
    pub(crate) kind: ClaimSealKind,
    /// Facts the lane publishes with the operation on settle.
    pub(crate) facts: Vec<FactMutation>,
    /// Advisory warnings for the operation reply.
    pub(crate) warnings: BoundedList<Warning>,
    /// The acquired or released record, when the envelope changed a claim.
    pub(crate) record: Option<ClaimRecord>,
}

impl ClaimSealEnvelope {
    /// Seals a write of `paths` for `holder`.
    ///
    /// Non-empty sets pass through `canonical_paths`; the empty set seals the
    /// claim clock only.
    ///
    /// # Errors
    /// `E_CLAIMED` on an enforced overlap, `E_CORRUPT` on a damaged index,
    /// `E_INVALID` on an uncanonical path set, `E_LIMIT` past the work budget.
    pub(crate) fn for_write(
        store: &Store,
        clock: &ClaimClock,
        holder: SessionId,
        paths: &[RepoPath],
    ) -> Result<Self, CoreError> {
        let canonical;
        let sealed: &[RepoPath] = if paths.is_empty() {
            paths
        } else {
            canonical = canonical_paths(paths.to_vec())?;
            canonical.as_slice()
        };
        let check = seal_write(store, clock, holder, sealed)?;
        Ok(Self {
            kind: ClaimSealKind::Write,
            facts: check.facts,
            warnings: check.warnings,
            record: None,
        })
    }

    /// Seals a claim acquisition of `claim` for `holder`.
    ///
    /// # Errors
    /// `E_CLAIMED` on an enforced overlap, `E_STALE` when the claim identity
    /// or an index already exists, `E_INVALID` on bad identities, paths, or
    /// lifetimes, `E_LIMIT` past the work budget.
    pub(crate) fn for_acquire(
        store: &Store,
        clock: &ClaimClock,
        holder: SessionId,
        claim: ClaimId,
        args: ClaimAcquireArgs,
    ) -> Result<Self, CoreError> {
        let change = seal_acquire(store, clock, holder, claim, args)?;
        Ok(Self {
            kind: ClaimSealKind::Acquire,
            facts: change.facts,
            warnings: change.warnings,
            record: Some(change.record),
        })
    }

    /// Seals a claim release of `claim` for `holder`.
    ///
    /// # Errors
    /// `E_NOT_FOUND` for an unknown claim, `E_FORBIDDEN` for another
    /// holder's claim, `E_CORRUPT` on a damaged record.
    pub(crate) fn for_release(
        store: &Store,
        clock: &ClaimClock,
        holder: SessionId,
        claim: ClaimId,
    ) -> Result<Self, CoreError> {
        let change = seal_release(store, clock, holder, claim)?;
        Ok(Self {
            kind: ClaimSealKind::Release,
            facts: change.facts,
            warnings: change.warnings,
            record: Some(change.record),
        })
    }

    /// Declares the path set one request seals.
    ///
    /// Write operations name their edit paths, resolve names its path,
    /// recovery names its discarded paths; every other operation declares no
    /// paths and seals the claim clock only.
    #[must_use]
    pub(crate) fn mutation_paths(request: &crate::protocol::Request) -> Vec<RepoPath> {
        match request {
            crate::protocol::Request::Write(inner) => inner
                .args
                .edits
                .iter()
                .map(|edit| edit.path.clone())
                .collect(),
            crate::protocol::Request::Resolve(inner) => vec![inner.args.path.clone()],
            crate::protocol::Request::WsRecover(inner) => match &inner.args.action {
                crate::protocol::RecoverAction::Resume => Vec::new(),
                crate::protocol::RecoverAction::Abort => Vec::new(),
                crate::protocol::RecoverAction::Discard { paths } => paths.clone(),
            },
            _ => Vec::new(),
        }
    }

    /// Seals one lane mutation for `holder`.
    ///
    /// Claim acquire operations seal a fresh record, claim release operations
    /// seal the named record's removal, and every other operation seals its
    /// declared paths. The lane publishes the envelope facts with the
    /// operation on settle and drops them on abort; see [`ClaimSealGuard`].
    /// The sealed record and advisory warnings report back through
    /// [`ClaimSealEnvelope::settle`]; the lane writes them into the
    /// precomputed reply, whose claim id preparation minted.
    ///
    /// `prepared_claim` is the claim id preparation minted for an acquire
    /// (kept stable across the prepare-to-commit window so the sealed record
    /// matches the precomputed reply); `None` mints one here for callers
    /// with no prepared reply. Release operations ignore it: the record key
    /// comes from the request args.
    ///
    /// # Errors
    /// Forwards `E_CLAIMED`, `E_CORRUPT`, `E_INVALID`, `E_LIMIT`,
    /// `E_NOT_FOUND`, `E_FORBIDDEN`, and `E_STALE` from the underlying seal.
    pub(crate) fn for_mutation(
        store: &Store,
        clock: &ClaimClock,
        holder: SessionId,
        request: &crate::protocol::Request,
        prepared_claim: Option<ClaimId>,
    ) -> Result<Self, CoreError> {
        match request {
            crate::protocol::Request::ClaimAcquire(inner) => Self::for_acquire(
                store,
                clock,
                holder,
                prepared_claim.unwrap_or_else(ClaimId::generate),
                inner.args.clone(),
            ),
            crate::protocol::Request::ClaimRelease(inner) => {
                Self::for_release(store, clock, holder, inner.args.claim)
            }
            _ => {
                let paths = Self::mutation_paths(request);
                Self::for_write(store, clock, holder, &paths)
            }
        }
    }

    /// Settles the envelope into lane publication parts.
    ///
    /// The lane publishes the facts atomically with the operation and reports
    /// the warnings and the changed record on the reply.
    #[must_use]
    pub(crate) fn settle(self) -> (Vec<FactMutation>, BoundedList<Warning>, Option<ClaimRecord>) {
        let Self {
            facts,
            warnings,
            record,
            kind: _,
        } = self;
        (facts, warnings, record)
    }

    /// Aborts the envelope without publication.
    ///
    /// Dropping the envelope aborts the same way; this spelling names the
    /// abort at the lane failure site.
    pub(crate) fn abort(self) {}
}

/// RAII seal guard releasing on settle and on abort.
///
/// The lane holds the guard across mutation: [`ClaimSealGuard::settle`]
/// publishes on success, while [`ClaimSealGuard::abort`] and [`Drop`] discard
/// on failure, so a seal never survives its operation either way.
#[derive(Debug)]
pub(crate) struct ClaimSealGuard {
    /// The held envelope until settle or abort.
    envelope: Option<ClaimSealEnvelope>,
}

impl ClaimSealGuard {
    /// Holds `envelope` until settle or abort.
    #[must_use]
    pub(crate) fn new(envelope: ClaimSealEnvelope) -> Self {
        Self {
            envelope: Some(envelope),
        }
    }

    /// Settles the held envelope into lane publication parts.
    ///
    /// # Errors
    /// `E_INVALID` when the guard no longer holds its envelope; construction
    /// plus the consuming signatures make that unreachable in the lane.
    pub(crate) fn settle(
        mut self,
    ) -> Result<(Vec<FactMutation>, BoundedList<Warning>, Option<ClaimRecord>), CoreError> {
        match self.envelope.take() {
            Some(envelope) => Ok(envelope.settle()),
            None => Err(CoreError::new(
                ErrorCode::EInvalid,
                "claim seal guard no longer holds its envelope",
            )),
        }
    }

    /// Aborts the held envelope without publication.
    ///
    /// Dropping the guard aborts the same way; this spelling names the abort
    /// at the lane failure site.
    pub(crate) fn abort(mut self) {
        let _ = self.envelope.take();
    }

    /// Borrows the held envelope, when still held.
    #[must_use]
    pub(crate) fn envelope(&self) -> Option<&ClaimSealEnvelope> {
        self.envelope.as_ref()
    }
}

impl Drop for ClaimSealGuard {
    fn drop(&mut self) {
        let _ = self.envelope.take();
    }
}

/// Maps a wire holder filter to the internal listing for `viewer`.
///
/// `Mine` lists the viewer's own claims; `Any` lists every session's claims
/// and needs `read_intents.claims` at authorization.
#[must_use]
pub(crate) fn listing_for_filter(
    filter: crate::protocol::ClaimHolderFilter,
    viewer: SessionId,
) -> ClaimListing {
    match filter {
        crate::protocol::ClaimHolderFilter::Mine => ClaimListing::Mine(viewer),
        crate::protocol::ClaimHolderFilter::Any => ClaimListing::AllAuthorized,
    }
}

/// Authorizes a claim listing against the viewer's negotiated capabilities.
///
/// A session always reads its own claims; reading another holder's claims or
/// the whole table needs `read_intents.claims`.
///
/// # Errors
/// `E_FORBIDDEN` for another session's claims without `read_intents.claims`.
pub(crate) fn authorize_claim_listing(
    caps: &crate::capability::Capabilities,
    viewer: SessionId,
    listing: &ClaimListing,
) -> Result<(), CoreError> {
    match listing {
        ClaimListing::Mine(holder) => {
            if *holder == viewer {
                Ok(())
            } else {
                caps.authorize_read(crate::capability::ReadAccess::PrivateClaims)
            }
        }
        ClaimListing::AllAuthorized => {
            caps.authorize_read(crate::capability::ReadAccess::PrivateClaims)
        }
    }
}

/// Authorizes one `claim.list` request and resolves its listing.
///
/// Binds the `ClaimListArgs.holder` schema row to the internal listing and
/// enforces `authorize_read` before any page is served.
///
/// # Errors
/// `E_FORBIDDEN` for `Any` without `read_intents.claims`.
pub(crate) fn authorize_claim_list_args(
    caps: &crate::capability::Capabilities,
    viewer: SessionId,
    args: &crate::protocol::ClaimListArgs,
) -> Result<ClaimListing, CoreError> {
    let listing = listing_for_filter(args.holder, viewer);
    authorize_claim_listing(caps, viewer, &listing)?;
    Ok(listing)
}

/// Authorizes a provenance read against the viewer's negotiated capabilities.
///
/// A session always reads its own provenance; reading another session's
/// commit or session provenance needs `read_intents.provenance`.
///
/// # Errors
/// `E_FORBIDDEN` for another session's provenance without
/// `read_intents.provenance`.
pub(crate) fn authorize_provenance_read(
    caps: &crate::capability::Capabilities,
    viewer: SessionId,
    owner: SessionId,
) -> Result<(), CoreError> {
    if viewer == owner {
        Ok(())
    } else {
        caps.authorize_read(crate::capability::ReadAccess::PrivateProvenance)
    }
}

/// One leased claim page read.
///
/// Groups the values that travel together from a `claim.list` handler into
/// the lease-bound view: the store, the claim clock, the lease registry, the
/// authorized listing, the presented cursor with its expected binding, the
/// sampled instant, and the page budget.
pub(crate) struct LeasedClaimPage<'a> {
    /// The store holding the claim facts.
    pub(crate) store: &'a Store,
    /// The claim clock fencing the read instant.
    pub(crate) clock: &'a ClaimClock,
    /// The registry verifying the cursor binding.
    pub(crate) leases: &'a super::leases::LeaseRegistry,
    /// The authorized listing; see [`authorize_claim_list_args`].
    pub(crate) listing: ClaimListing,
    /// The presented cursor carrying the resume position.
    pub(crate) cursor: &'a crate::protocol::PageCursor,
    /// The binding the request must match.
    pub(crate) want: &'a super::leases::CursorWant,
    /// The parent-sampled monotonic instant.
    pub(crate) now: Instant,
    /// The page budget bounding the read.
    pub(crate) budget: FactPageBudget,
}

/// Lists one claim page bound to an immutable leased view.
///
/// `AllAuthorized` is valid only after current `read_intents.claims`
/// authorization; authorize first with [`authorize_claim_list_args`]. The
/// cursor is verified against its expected binding before any row is read:
/// binding mismatch is `E_FORBIDDEN`, correct binding on expired authority is
/// `E_LEASE_LOST`. The caller mints the next protocol cursor with
/// [`next_claim_cursor`].
///
/// # Errors
/// `E_FORBIDDEN` on cursor mismatch or a continuation outside the listing
/// scope; `E_LEASE_LOST` on expired authority; `E_LIMIT` past the page budget.
pub(crate) fn list_page(
    read: LeasedClaimPage<'_>,
) -> Result<(ClaimPage, super::leases::LeaseBinding), CoreError> {
    let LeasedClaimPage {
        store,
        clock,
        leases,
        listing,
        cursor,
        want,
        now,
        budget,
    } = read;
    let binding = leases.check_claim_page_cursor(cursor, want, now)?;
    let position = cursor.position.as_bytes();
    let after = if position.is_empty() {
        None
    } else {
        Some(position)
    };
    let page = list_page_raw(store, clock, listing, after, budget)?;
    Ok((page, binding))
}

/// Mints the next protocol cursor preserving the lease binding.
///
/// Carries the store, view, query, and lease of the served page onto the
/// opaque resume position, so the next `claim.list` page stays bound to the
/// same immutable leased view. Absent position ends the listing.
///
/// Binds the `ClaimListReply.claims.next` schema row to the lease.
#[must_use]
pub(crate) fn next_claim_cursor(
    cursor: &crate::protocol::PageCursor,
    next: Option<Vec<u8>>,
) -> Option<crate::protocol::PageCursor> {
    match next {
        Some(position) => Some(crate::protocol::PageCursor {
            store: cursor.store,
            view: cursor.view,
            query: cursor.query,
            lease: cursor.lease,
            position: crate::ByteString::from(position),
        }),
        None => None,
    }
}
