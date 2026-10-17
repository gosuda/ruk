use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::clock::Clock;
use crate::change::{ClaimId, SessionId};
use crate::index::RepoPath;
use crate::protocol::{
    BoundedList, ClaimAcquireArgs, ClaimMode, ClaimRecord, MAX_CLAIM_TTL_SECONDS,
    MAX_PAGE_SIZE, Timestamp, Warning,
};
use crate::store::{FactExpectation, FactMutation, FactPageBudget, FactTable, Store, StoreError};
use crate::{CoreError, ErrorCode, MAX_CONTROL_FRAME_BYTES};

#[cfg(test)]
mod tests;

const CLOCK_KEY: &[u8] = b"T";

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
        let elapsed = sample.mono.checked_duration_since(self.start_mono).ok_or_else(|| {
            CoreError::new(ErrorCode::EIo, "claim monotonic clock moved backward")
        })?;
        let elapsed = jiff::SignedDuration::try_from(elapsed)
            .map_err(|err| CoreError::new(ErrorCode::EIo, err.to_string()))?;
        let advanced = self.start_wall.checked_add(elapsed)
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
        let expected = previous.map_or(FactExpectation::Absent, |(raw, _)| FactExpectation::Value(raw));
        let value = crate::store::encode("claim clock", &ClockRow { version: 1, at })?;
        Ok((at, vec![FactMutation {
            table: FactTable::Claims,
            key: CLOCK_KEY.to_vec(),
            expected,
            value: Some(value),
        }]))
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
        return Err(CoreError::new(ErrorCode::EInvalid, "claim identities must not be nil"));
    }
    let paths = canonical_paths(args.paths)?;
    let (now, mut facts) = clock.fence(store)?;
    let warnings = check_paths(store, holder, &paths, now)?;
    let expires = now.instant().checked_add(jiff::SignedDuration::from_secs(i64::from(args.ttl.seconds())))
        .map_err(|err| CoreError::new(ErrorCode::EInvalid, err.to_string()))?;
    let record = ClaimRecord { claim, holder, paths, mode: args.mode, expires_at: Timestamp::new(expires) };
    let row = ClaimRow { version: 1, created: now, record };
    let raw = crate::store::encode("claim", &row)?;
    let keys = row_keys(&row.record)?;
    let mut work = Work::new();
    work.charge(raw.len())?;
    for key in keys {
        work.charge(key.len())?;
        if store.fact(FactTable::Claims, &key)?.is_some() {
            return Err(CoreError::new(ErrorCode::EStale, "claim identity or index already exists"));
        }
        if key[0] != b'R' {
            facts.push(FactMutation { table: FactTable::Claims, key, expected: FactExpectation::Absent, value: Some(Vec::new()) });
        }
    }
    facts.push(FactMutation {
        table: FactTable::Claims,
        key: record_key(row.record.claim),
        expected: FactExpectation::Absent,
        value: Some(raw),
    });
    Ok(ClaimChange { record: row.record, facts, warnings })
}

/// The caller holds sole lane ownership through publication. Only the holder
/// can release the claim, including an expired claim.
pub(crate) fn seal_release(
    store: &Store,
    clock: &ClaimClock,
    holder: SessionId,
    claim: ClaimId,
) -> Result<ClaimChange, CoreError> {
    let (raw, row) = read_claim(store, claim)?.ok_or_else(|| {
        CoreError::new(ErrorCode::ENotFound, "claim does not exist")
    })?;
    if row.record.holder != holder {
        return Err(CoreError::new(ErrorCode::EForbidden, "claim belongs to another session"));
    }
    let (_, mut facts) = clock.fence(store)?;
    remove_record(store, &row, raw, &mut facts)?;
    Ok(ClaimChange { record: row.record, facts, warnings: BoundedList::complete(Vec::new())? })
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

fn canonical_paths(mut paths: Vec<RepoPath>) -> Result<Vec<RepoPath>, CoreError> {
    if paths.is_empty() {
        return Err(CoreError::new(ErrorCode::EInvalid, "claim paths must not be empty"));
    }
    let mut work = Work::new();
    for path in &paths { work.charge(path.as_bytes().len())?; }
    paths.sort_unstable();
    paths.dedup();
    let mut canonical: Vec<RepoPath> = Vec::with_capacity(paths.len());
    for path in paths {
        let covered = path.as_bytes().iter().enumerate().filter(|(_, byte)| **byte == b'/')
            .any(|(end, _)| canonical.binary_search_by(|other| other.as_bytes().cmp(&path.as_bytes()[..end])).is_ok());
        if !covered { canonical.push(path); }
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
        for end in path.as_bytes().iter().enumerate().filter_map(|(index, byte)| (*byte == b'/').then_some(index))
            .chain(std::iter::once(path.as_bytes().len())) {
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
        let page = store.fact_page(FactTable::Claims, Some(&after), FactPageBudget::new(1, MAX_CONTROL_FRAME_BYTES))?;
        let Some(index) = page.rows.into_iter().next() else { return Ok(()); };
        if !index.key.starts_with(prefix) { return Ok(()); }
        work.charge(index.key.len().checked_add(index.value.len()).ok_or_else(limit)?)?;
        let (_, row) = indexed_claim(store, &index.key, &index.value, work)?;
        if row.record.expires_at > now && row.record.holder != holder {
            if row.record.mode == ClaimMode::Enforce {
                return Err(CoreError::new(ErrorCode::EClaimed, "path overlaps another session's enforced claim"));
            }
            let duplicate = warnings.iter().any(|warning| matches!(warning,
                Warning::ClaimAdvisory { path, holder } if path == requested && *holder == row.record.holder));
            if !duplicate {
                work.charge(requested.as_bytes().len())?;
                warnings.push(Warning::ClaimAdvisory { path: requested.clone(), holder: row.record.holder });
            }
        }
        after = index.key;
        if !page.more { return Ok(()); }
    }
}

fn indexed_claim(store: &Store, key: &[u8], value: &[u8], work: &mut Work) -> Result<(usize, ClaimRow), CoreError> {
    if !value.is_empty() || key.len() < 17 {
        return Err(corrupt(store, "invalid claim index row"));
    }
    let id: [u8; 16] = key[key.len() - 16..].try_into().map_err(|_| corrupt(store, "invalid claim index identity"))?;
    let (raw, row) = read_claim(store, ClaimId::from_bytes(id))?
        .ok_or_else(|| corrupt(store, "claim index names a missing record"))?;
    work.charge(raw.len())?;
    let valid = match key[0] {
        b'H' => key.len() == 33 && key[1..17] == row.record.holder.as_bytes()[..],
        b'P' => key.len() >= 19 && key[key.len() - 17] == 0
            && row.record.paths.iter().any(|path| path.as_bytes() == &key[1..key.len() - 17]),
        _ => false,
    };
    if !valid { return Err(corrupt(store, "claim index disagrees with its record")); }
    Ok((raw.len(), row))
}

/// AllAuthorized is valid only after current read_intents.claims authorization.
/// The caller binds the returned position to an immutable leased view.
pub(crate) fn list_page(
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
        if !item.key.starts_with(&prefix) { ended = true; break; }
        work.charge(item.key.len().checked_add(item.value.len()).ok_or_else(limit)?)?;
        let (size, row) = if prefix[0] == b'R' {
            (item.value.len(), decode_claim(store, &item.key, &item.value)?)
        } else {
            indexed_claim(store, &item.key, &item.value, &mut work)?
        };
        if row.record.expires_at > now {
            let next_size = copied.checked_add(size).ok_or_else(limit)?;
            if next_size > budget.bytes {
                if last.is_none() { return Err(limit()); }
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
        if !item.key.starts_with(b"R") { ended = true; break; }
        work.charge(item.key.len().checked_add(item.value.len()).ok_or_else(limit)?)?;
        let row = decode_claim(store, &item.key, &item.value)?;
        last = Some(item.key);
        if row.record.expires_at <= now {
            for key in row_keys(&row.record)? { work.charge(key.len())?; }
            remove_record(store, &row, item.value, &mut facts)?;
        }
    }
    let next = if page.more && !ended { next_in_prefix(store, b"R", last)? } else { None };
    Ok(ClaimSweep { facts, next })
}

fn next_in_prefix(store: &Store, prefix: &[u8], last: Option<Vec<u8>>) -> Result<Option<Vec<u8>>, CoreError> {
    let Some(position) = last else { return Ok(None); };
    let next = store.fact_page(FactTable::Claims, Some(&position), FactPageBudget::new(1, MAX_CONTROL_FRAME_BYTES))?;
    Ok(next.rows.first().is_some_and(|row| row.key.starts_with(prefix)).then_some(position))
}

fn validate_budget(budget: FactPageBudget) -> Result<(), CoreError> {
    if budget.rows == 0 || budget.rows > MAX_PAGE_SIZE || budget.bytes == 0 || budget.bytes > MAX_CONTROL_FRAME_BYTES {
        return Err(CoreError::new(ErrorCode::EInvalid, "claim page budget is outside the protocol bounds"));
    }
    Ok(())
}

fn checked_position<'a>(prefix: &'a [u8], after: Option<&'a [u8]>) -> Result<&'a [u8], CoreError> {
    match after {
        Some(position) if position.starts_with(prefix) => Ok(position),
        Some(_) => Err(CoreError::new(ErrorCode::EInvalid, "claim continuation has the wrong scope")),
        None => Ok(prefix),
    }
}

fn remove_record(store: &Store, row: &ClaimRow, raw: Vec<u8>, facts: &mut Vec<FactMutation>) -> Result<(), CoreError> {
    for key in row_keys(&row.record)?.into_iter().filter(|key| key[0] != b'R') {
        let value = store.fact(FactTable::Claims, &key)?
            .ok_or_else(|| corrupt(store, "claim record is missing an index"))?;
        if !value.is_empty() { return Err(corrupt(store, "claim index value is not empty")); }
        facts.push(FactMutation { table: FactTable::Claims, key, expected: FactExpectation::Value(value), value: None });
    }
    facts.push(FactMutation { table: FactTable::Claims, key: record_key(row.record.claim), expected: FactExpectation::Value(raw), value: None });
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

fn read_claim(store: &Store, claim: ClaimId) -> Result<Option<(Vec<u8>, ClaimRow)>, CoreError> {
    let key = record_key(claim);
    store.fact(FactTable::Claims, &key)?.map(|raw| {
        decode_claim(store, &key, &raw).map(|row| (raw, row))
    }).transpose()
}

fn decode_claim(store: &Store, key: &[u8], raw: &[u8]) -> Result<ClaimRow, CoreError> {
    let row: ClaimRow = store.observe(crate::store::decode("claim", raw))?;
    if row.version != 1 || key != record_key(row.record.claim)
        || row.record.claim == ClaimId::nil() || row.record.holder == SessionId::nil()
        || row.created >= row.record.expires_at {
        return Err(corrupt(store, "invalid claim record"));
    }
    let maximum = row.created.instant().checked_add(jiff::SignedDuration::from_secs(i64::from(MAX_CLAIM_TTL_SECONDS)))
        .map_err(|_| corrupt(store, "claim lifetime overflows"))?;
    if row.record.expires_at.instant() > maximum {
        return Err(corrupt(store, "claim lifetime exceeds one hour"));
    }
    let mut previous: Option<&RepoPath> = None;
    for path in &row.record.paths {
        if previous.is_some_and(|prior| prior >= path) { return Err(corrupt(store, "claim paths are not canonical")); }
        let redundant = path.as_bytes().iter().enumerate().filter(|(_, byte)| **byte == b'/')
            .any(|(end, _)| row.record.paths.binary_search_by(|other| other.as_bytes().cmp(&path.as_bytes()[..end])).is_ok());
        if redundant { return Err(corrupt(store, "claim contains a redundant descendant")); }
        previous = Some(path);
    }
    if previous.is_none() { return Err(corrupt(store, "claim has no paths")); }
    Ok(row)
}

fn read_clock(store: &Store) -> Result<Option<(Vec<u8>, ClockRow)>, CoreError> {
    store.fact(FactTable::Claims, CLOCK_KEY)?.map(|raw| {
        let row: ClockRow = store.observe(crate::store::decode("claim clock", &raw))?;
        if row.version != 1 { return Err(corrupt(store, "invalid claim clock version")); }
        Ok((raw, row))
    }).transpose()
}

fn limit() -> CoreError {
    CoreError::new(ErrorCode::ELimit, "claim lookup or result exceeds its bounded work budget")
}

fn corrupt(store: &Store, detail: &str) -> CoreError {
    let _ = store.observe::<()>(Err(StoreError::Corrupt(detail.to_owned())));
    CoreError::new(ErrorCode::ECorrupt, detail)
}
