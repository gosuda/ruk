use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::MAX_CONTROL_FRAME_BYTES;
use crate::bytes::ByteString;
use crate::change::OperationId;
use crate::conflict::Signature;
use crate::error::{CoreError, CoreModelError, ErrorCode};
use crate::ids::{HashKind, Oid};
use crate::index::reject_null_oid;
use crate::merge::Merge;
use crate::protocol::Timestamp;
use crate::refdata::{
    RefChange, RefError, RefExpect, RefName, RefRead, RefTarget, RefTransaction, RefUpdate,
};
use crate::store::{FactExpectation, FactMutation, FactPageBudget, FactTable, Store, StoreError};

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct StoreRefs<'a> {
    store: &'a Store,
}

impl<'a> StoreRefs<'a> {
    #[must_use]
    pub const fn new(store: &'a Store) -> Self {
        Self { store }
    }
}

impl<'a> RefRead for StoreRefs<'a> {
    fn get(&self, name: &RefName) -> Result<Option<RefTarget>, CoreError> {
        let raw = self.store.fact(FactTable::Refs, name.as_bytes())?;
        match raw {
            Some(bytes) => decode_stored_target(self.store, name, &bytes).map(Some),
            None => Ok(None),
        }
    }

    fn seek(&self, lower: &[u8]) -> Result<Option<(RefName, RefTarget)>, CoreError> {
        if let Some(bytes) = self.store.fact(FactTable::Refs, lower)? {
            let name = RefName::new(lower).map_err(|err| {
                corrupt_store(self.store, format!("stored ref key is invalid: {err}"))
            })?;
            let target = decode_stored_target(self.store, &name, &bytes)?;
            return Ok(Some((name, target)));
        }

        let after = if lower.is_empty() { None } else { Some(lower) };
        let budget = FactPageBudget::new(1, MAX_CONTROL_FRAME_BYTES);
        let page = self.store.fact_page(FactTable::Refs, after, budget)?;
        if page.rows.is_empty() {
            return Ok(None);
        }
        let row = &page.rows[0];
        let name = RefName::new(row.key.as_slice()).map_err(|err| {
            corrupt_store(self.store, format!("stored ref key is invalid: {err}"))
        })?;
        let target = decode_stored_target(self.store, &name, &row.value)?;
        Ok(Some((name, target)))
    }
}

fn corrupt_store(store: &Store, detail: impl Into<String>) -> CoreError {
    let msg = detail.into();
    let _ = store.observe(Err::<(), _>(StoreError::Corrupt(msg.clone())));
    CoreError::new(ErrorCode::ECorrupt, msg)
}

fn decode_stored_target(
    store: &Store,
    name: &RefName,
    bytes: &[u8],
) -> Result<RefTarget, CoreError> {
    let res: Result<RefTarget, StoreError> = (|| {
        let target: RefTarget = crate::store::decode("ref target", bytes)?;
        target
            .validate(store.hash_kind())
            .map_err(|err| StoreError::Corrupt(format!("ref {name} has invalid target: {err}")))?;
        Ok(target)
    })();
    store.observe(res).map_err(CoreError::from)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RefEntry {
    pub name: RefName,
    pub target: RefTarget,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RefPage {
    pub entries: Vec<RefEntry>,
    pub more: bool,
}

/// One page of refs under `prefix`, seeking inclusively at the prefix
/// when `after` is absent and exclusively after `after` otherwise, so
/// single-ref resolve and prefix listings never scan the namespace.
pub fn page_refs_prefixed(
    store: &Store,
    prefix: &[u8],
    after: Option<&RefName>,
    limit: usize,
) -> Result<RefPage, CoreError> {
    if limit == 0 {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "ref page limit must be non-zero",
        ));
    }
    if let Some(cursor) = after
        && !cursor.as_bytes().starts_with(prefix)
    {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "ref page cursor must stay under its prefix",
        ));
    }
    let max_rows = limit.min(1000);
    let budget = FactPageBudget::new(max_rows, MAX_CONTROL_FRAME_BYTES);
    let page = store.fact_page_prefixed(
        FactTable::Refs,
        after.map(RefName::as_bytes),
        prefix,
        budget,
    )?;
    let mut entries = Vec::with_capacity(page.rows.len());
    for row in page.rows {
        let name = RefName::new(row.key)
            .map_err(|err| corrupt_store(store, format!("stored ref key is invalid: {err}")))?;
        let target = decode_stored_target(store, &name, &row.value)?;
        entries.push(RefEntry { name, target });
    }
    Ok(RefPage {
        entries,
        more: page.more,
    })
}

pub fn page_refs(store: &Store, after: Option<&[u8]>, limit: usize) -> Result<RefPage, CoreError> {
    if limit == 0 {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "ref page limit must be non-zero",
        ));
    }
    let max_rows = limit.min(1000);
    let budget = FactPageBudget::new(max_rows, MAX_CONTROL_FRAME_BYTES);
    let page = store.fact_page(FactTable::Refs, after, budget)?;
    let mut entries = Vec::with_capacity(page.rows.len());
    for row in page.rows {
        let name = RefName::new(row.key)
            .map_err(|err| corrupt_store(store, format!("stored ref key is invalid: {err}")))?;
        let target = decode_stored_target(store, &name, &row.value)?;
        entries.push(RefEntry { name, target });
    }
    Ok(RefPage {
        entries,
        more: page.more,
    })
}

#[derive(Clone, Debug)]
pub struct PreparedRefUpdate {
    pub update: RefUpdate,
    pub before_bytes: Option<Vec<u8>>,
    pub before_target: Option<RefTarget>,
    pub mutation: FactMutation,
}

impl PreparedRefUpdate {
    #[must_use]
    pub fn to_reflog_record(
        &self,
        operation: OperationId,
        old_oid: Option<Oid>,
        new_oid: Option<Oid>,
        committer: Signature,
        message: ByteString,
    ) -> ReflogRecord {
        ReflogRecord {
            operation,
            old_oid,
            new_oid,
            committer,
            message,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PreparedRefTransaction {
    pub updates: Vec<PreparedRefUpdate>,
    pub mutations: Vec<FactMutation>,
}

impl PreparedRefTransaction {
    #[must_use]
    pub fn updates(&self) -> &[PreparedRefUpdate] {
        &self.updates
    }

    #[must_use]
    pub fn mutations(&self) -> &[FactMutation] {
        &self.mutations
    }

    #[must_use]
    pub fn into_mutations(self) -> Vec<FactMutation> {
        self.mutations
    }
}

/// Prepares a checked [`RefTransaction`] into exact `Value`/`Absent`
/// [`FactMutation`]s against `store`.
///
/// # Precondition (SOLE LANE OWNERSHIP)
/// This API MUST be called under sole lane ownership (e.g. exclusive repository
/// coordinator lock). It is NOT safe against a concurrently racing store:
/// [`RefTransaction::check`] validates directory/file collisions and symbolic
/// chains using range reads (`seek`) that simple touched-key point CAS cannot
/// protect. Revalidation with accepted batch overlays or separate conflicting
/// batches is required if lane ownership is released or if batching occurs.
/// This method does NOT publish directly to the store.
pub fn prepare_checked_transaction(
    store: &Store,
    transaction: &RefTransaction,
) -> Result<PreparedRefTransaction, CoreError> {
    let updates = transaction.updates();
    let mut prepared_updates = Vec::with_capacity(updates.len());
    let mut mutations = Vec::with_capacity(updates.len());

    for update in updates {
        let freeze_guards = tag_freeze_guards(store, &[&update.name])?;
        let name_bytes = update.name.as_bytes();
        let current_bytes = store.fact(FactTable::Refs, name_bytes)?;

        let (before_target, expected) = match &current_bytes {
            Some(bytes) => {
                let target = decode_stored_target(store, &update.name, bytes)?;
                (Some(target), FactExpectation::Value(bytes.clone()))
            }
            None => (None, FactExpectation::Absent),
        };

        let holds = match &update.expected {
            RefExpect::Any => true,
            RefExpect::Absent => before_target.is_none(),
            RefExpect::Present(want) => before_target.as_ref() == Some(want),
        };
        if !holds {
            return Err(RefError::Stale {
                name: update.name.clone(),
            }
            .into());
        }

        let new_value = match &update.change {
            RefChange::Set(target) => {
                target.validate(store.hash_kind())?;
                let encoded = crate::store::encode("ref target", target)?;
                Some(encoded)
            }
            RefChange::Delete => None,
        };

        let key = name_bytes.to_vec();
        let row_pair_len = key
            .len()
            .saturating_add(new_value.as_ref().map_or(0, |v| v.len()));
        if row_pair_len > MAX_CONTROL_FRAME_BYTES {
            return Err(CoreError::new(
                ErrorCode::ELimit,
                format!("ref mutation for {} exceeds 16 MiB bound", update.name),
            ));
        }

        let mutation = FactMutation {
            table: FactTable::Refs,
            key,
            expected,
            value: new_value,
        };

        prepared_updates.push(PreparedRefUpdate {
            update: update.clone(),
            before_bytes: current_bytes,
            before_target,
            mutation: mutation.clone(),
        });
        mutations.push(mutation);
        mutations.extend(freeze_guards);
    }

    Ok(PreparedRefTransaction {
        updates: prepared_updates,
        mutations,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RefConflictEntry {
    pub name: RefName,
    pub conflict: Merge<Option<Oid>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RefConflictPage {
    pub entries: Vec<RefConflictEntry>,
    pub more: bool,
}

fn decode_stored_conflict(
    store: &Store,
    name: &RefName,
    bytes: &[u8],
) -> Result<Merge<Option<Oid>>, CoreError> {
    let res: Result<Merge<Option<Oid>>, StoreError> = (|| {
        let conflict: Merge<Option<Oid>> = crate::store::decode("ref conflict", bytes)?;
        for oid in conflict.adds().chain(conflict.removes()).flatten() {
            reject_null_oid(*oid, "ref conflict")?;
            oid.expect_kind(store.hash_kind(), "ref conflict")?;
        }
        if conflict.is_resolved() {
            return Err(StoreError::Corrupt(format!(
                "ref conflict for {name} is stored with resolved state"
            )));
        }
        Ok(conflict)
    })();
    store.observe(res).map_err(CoreError::from)
}

pub fn get_ref_conflict(
    store: &Store,
    name: &RefName,
) -> Result<Option<Merge<Option<Oid>>>, CoreError> {
    let raw = store.fact(FactTable::RefConflicts, name.as_bytes())?;
    match raw {
        Some(bytes) => decode_stored_conflict(store, name, &bytes).map(Some),
        None => Ok(None),
    }
}

pub fn prepare_set_ref_conflict(
    store: &Store,
    name: &RefName,
    conflict: &Merge<Option<Oid>>,
) -> Result<FactMutation, CoreError> {
    for oid in conflict.adds().chain(conflict.removes()).flatten() {
        reject_null_oid(*oid, "ref conflict")?;
        oid.expect_kind(store.hash_kind(), "ref conflict")?;
    }
    if conflict.is_resolved() {
        return Err(CoreModelError::Invalid {
            what: "ref conflict",
            detail: format!("conflict for {name} must be unresolved, found 1 term"),
        }
        .into());
    }

    let encoded = crate::store::encode("ref conflict", conflict)?;
    let key = name.as_bytes().to_vec();
    if key.len().saturating_add(encoded.len()) > MAX_CONTROL_FRAME_BYTES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            format!("ref conflict mutation for {name} exceeds 16 MiB bound"),
        ));
    }

    let current = store.fact(FactTable::RefConflicts, name.as_bytes())?;
    let expected = current.map_or(FactExpectation::Absent, FactExpectation::Value);

    Ok(FactMutation {
        table: FactTable::RefConflicts,
        key,
        expected,
        value: Some(encoded),
    })
}

pub fn prepare_clear_ref_conflict(
    store: &Store,
    name: &RefName,
) -> Result<FactMutation, CoreError> {
    let current = store.fact(FactTable::RefConflicts, name.as_bytes())?;
    let expected = current.map_or(FactExpectation::Absent, FactExpectation::Value);
    Ok(FactMutation {
        table: FactTable::RefConflicts,
        key: name.as_bytes().to_vec(),
        expected,
        value: None,
    })
}

/// Checks the stored conflict against `expected` and lowers its clearing to
/// an exact fact in a single read.
///
/// The one read keeps the terms check and the clear expectation on the same
/// bytes; the lane's point compare-and-swap on the returned fact covers the
/// gap between preparation and publication.
///
/// # Errors
/// `E_STALE` when no conflict exists or its terms differ from `expected`;
/// `E_CORRUPT` for a damaged row.
pub fn prepare_clear_ref_conflict_checked(
    store: &Store,
    name: &RefName,
    expected: &Merge<Option<Oid>>,
) -> Result<FactMutation, CoreError> {
    let key = name.as_bytes().to_vec();
    let Some(bytes) = store.fact(FactTable::RefConflicts, name.as_bytes())? else {
        return Err(CoreError::new(
            ErrorCode::EStale,
            format!("ref `{name}` has no conflict to resolve"),
        ));
    };
    let conflict = decode_stored_conflict(store, name, &bytes)?;
    if &conflict != expected {
        return Err(CoreError::new(
            ErrorCode::EStale,
            format!("ref `{name}` conflict terms changed since the caller read them"),
        ));
    }
    Ok(FactMutation {
        table: FactTable::RefConflicts,
        key,
        expected: FactExpectation::Value(bytes),
        value: None,
    })
}

pub fn page_ref_conflicts(
    store: &Store,
    after: Option<&[u8]>,
    limit: usize,
) -> Result<RefConflictPage, CoreError> {
    if limit == 0 {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "ref conflict page limit must be non-zero",
        ));
    }
    let max_rows = limit.min(1000);
    let budget = FactPageBudget::new(max_rows, MAX_CONTROL_FRAME_BYTES);
    let page = store.fact_page(FactTable::RefConflicts, after, budget)?;
    let mut entries = Vec::with_capacity(page.rows.len());
    for row in page.rows {
        let name = RefName::new(row.key).map_err(|err| {
            corrupt_store(store, format!("stored ref conflict key is invalid: {err}"))
        })?;
        let conflict = decode_stored_conflict(store, &name, &row.value)?;
        entries.push(RefConflictEntry { name, conflict });
    }
    Ok(RefConflictPage {
        entries,
        more: page.more,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReflogKey {
    pub name: RefName,
    pub operation: OperationId,
    pub ordinal: u64,
}

impl ReflogKey {
    #[must_use]
    pub fn new(name: RefName, operation: OperationId, ordinal: u64) -> Self {
        Self {
            name,
            operation,
            ordinal,
        }
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let name_bytes = self.name.as_bytes();
        let mut key = Vec::with_capacity(name_bytes.len() + 1 + 8 + 8);
        key.extend_from_slice(name_bytes);
        key.push(0x00);
        key.extend_from_slice(&self.operation.0.to_be_bytes());
        key.extend_from_slice(&self.ordinal.to_be_bytes());
        key
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CoreModelError> {
        let nul_pos =
            bytes
                .iter()
                .position(|&b| b == 0x00)
                .ok_or_else(|| CoreModelError::Invalid {
                    what: "reflog key",
                    detail: "missing NUL delimiter".to_owned(),
                })?;
        let name_bytes = &bytes[..nul_pos];
        let suffix = &bytes[nul_pos + 1..];
        if suffix.len() != 16 {
            return Err(CoreModelError::Invalid {
                what: "reflog key",
                detail: format!(
                    "expected 16-byte operation/ordinal suffix, got {}",
                    suffix.len()
                ),
            });
        }
        let name = RefName::new(name_bytes)?;
        let mut op_bytes = [0_u8; 8];
        let mut ord_bytes = [0_u8; 8];
        op_bytes.copy_from_slice(&suffix[..8]);
        ord_bytes.copy_from_slice(&suffix[8..]);
        let operation = OperationId(u64::from_be_bytes(op_bytes));
        let ordinal = u64::from_be_bytes(ord_bytes);
        Ok(Self {
            name,
            operation,
            ordinal,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReflogRecord {
    pub operation: OperationId,
    pub old_oid: Option<Oid>,
    pub new_oid: Option<Oid>,
    pub committer: Signature,
    pub message: ByteString,
}

impl ReflogRecord {
    pub fn validate(&self, kind: HashKind) -> Result<(), CoreModelError> {
        if self.old_oid.is_none() && self.new_oid.is_none() {
            return Err(CoreModelError::Invalid {
                what: "reflog record",
                detail: "old_oid and new_oid cannot both be None".to_owned(),
            });
        }
        if let Some(oid) = self.old_oid {
            reject_null_oid(oid, "reflog old_oid")?;
            oid.expect_kind(kind, "reflog old_oid")?;
        }
        if let Some(oid) = self.new_oid {
            reject_null_oid(oid, "reflog new_oid")?;
            oid.expect_kind(kind, "reflog new_oid")?;
        }
        validate_signature(&self.committer, "reflog committer")?;
        Ok(())
    }
}

fn validate_signature(sig: &Signature, what: &'static str) -> Result<(), CoreModelError> {
    for (field, bytes) in [("name", &sig.name), ("email", &sig.email)] {
        if bytes
            .as_bytes()
            .iter()
            .any(|&b| matches!(b, b'<' | b'>' | b'\n' | 0))
        {
            return Err(CoreModelError::Invalid {
                what,
                detail: format!("{field} contains <, >, newline, or NUL"),
            });
        }
    }
    let rendered = sig.render();
    Signature::parse(&rendered).map_err(|err| CoreModelError::Invalid {
        what,
        detail: format!("signature is not canonical: {err}"),
    })?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReflogEntry {
    pub key: ReflogKey,
    pub record: ReflogRecord,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReflogPage {
    pub entries: Vec<ReflogEntry>,
    pub more: bool,
}

fn decode_stored_reflog(
    store: &Store,
    key: &ReflogKey,
    bytes: &[u8],
) -> Result<ReflogRecord, CoreError> {
    let res: Result<ReflogRecord, StoreError> = (|| {
        let record: ReflogRecord = crate::store::decode("reflog entry", bytes)?;
        record.validate(store.hash_kind()).map_err(|err| {
            StoreError::Corrupt(format!("reflog entry at {key:?} is invalid: {err}"))
        })?;
        Ok(record)
    })();
    store.observe(res).map_err(CoreError::from)
}

pub fn prepare_append_reflog(
    store: &Store,
    key: &ReflogKey,
    record: &ReflogRecord,
) -> Result<FactMutation, CoreError> {
    record.validate(store.hash_kind())?;
    if record.operation != key.operation {
        return Err(CoreModelError::Invalid {
            what: "reflog record",
            detail: format!(
                "record operation {} does not match key operation {}",
                record.operation.0, key.operation.0
            ),
        }
        .into());
    }

    let key_bytes = key.encode();
    let value_bytes = crate::store::encode("reflog entry", record)?;
    if key_bytes.len().saturating_add(value_bytes.len()) > MAX_CONTROL_FRAME_BYTES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "reflog row pair exceeds 16 MiB bound",
        ));
    }

    Ok(FactMutation {
        table: FactTable::Reflogs,
        key: key_bytes,
        expected: FactExpectation::Absent,
        value: Some(value_bytes),
    })
}

pub fn get_reflog(store: &Store, key: &ReflogKey) -> Result<Option<ReflogRecord>, CoreError> {
    let key_bytes = key.encode();
    let raw = store.fact(FactTable::Reflogs, &key_bytes)?;
    match raw {
        Some(bytes) => decode_stored_reflog(store, key, &bytes).map(Some),
        None => Ok(None),
    }
}

pub fn page_reflogs(
    store: &Store,
    name: &RefName,
    after_key: Option<&ReflogKey>,
    limit: usize,
) -> Result<ReflogPage, CoreError> {
    if limit == 0 {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "reflog page limit must be non-zero",
        ));
    }
    let max_rows = limit.min(1000);
    let mut prefix = name.as_bytes().to_vec();
    prefix.push(0x00);

    let after_bytes = match after_key {
        Some(key) => {
            if key.name != *name {
                return Err(CoreError::new(
                    ErrorCode::EInvalid,
                    format!(
                        "cursor ref name {} does not match requested ref {name}",
                        key.name
                    ),
                ));
            }
            key.encode()
        }
        None => prefix.clone(),
    };

    let budget = FactPageBudget::new(max_rows + 1, MAX_CONTROL_FRAME_BYTES);
    let page = store.fact_page(FactTable::Reflogs, Some(&after_bytes), budget)?;

    let mut entries = Vec::with_capacity(page.rows.len().min(max_rows));
    let mut more = false;

    for (idx, row) in page.rows.into_iter().enumerate() {
        if !row.key.starts_with(&prefix) {
            break;
        }
        if idx == max_rows {
            more = true;
            break;
        }
        let key = ReflogKey::decode(&row.key)
            .map_err(|err| corrupt_store(store, format!("reflog key corrupt: {err}")))?;
        let record = decode_stored_reflog(store, &key, &row.value)?;
        entries.push(ReflogEntry { key, record });
    }

    Ok(ReflogPage { entries, more })
}

/// One frozen release tag: the `ReleasedTags` row at key
/// `refs/tags/<name>`, written when its release publishes and removed on
/// delete, discard, compensation, or repair. The freeze gate (a later row)
/// refuses every tag mutation path while a live marker exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReleasedTagMarker {
    /// The release that owns the freeze.
    pub owner_release_id: String,
    /// The tag target the freeze pins.
    pub target_oid: Oid,
    /// Wall time the freeze was written.
    pub frozen_at: Timestamp,
}

fn is_tag_name(name: &RefName) -> bool {
    name.as_bytes().starts_with(b"refs/tags/")
}

fn frozen_refusal(name: &RefName, owner: &str) -> CoreError {
    CoreError::new(
        ErrorCode::EForbidden,
        format!("tag `{name}` is frozen by release `{owner}`"),
    )
}

fn decode_stored_marker(store: &Store, bytes: &[u8]) -> Result<ReleasedTagMarker, CoreError> {
    let res: Result<ReleasedTagMarker, StoreError> = (|| {
        let marker: ReleasedTagMarker = crate::store::decode("released tag marker", bytes)?;
        reject_null_oid(marker.target_oid, "released tag marker")?;
        marker
            .target_oid
            .expect_kind(store.hash_kind(), "released tag marker")?;
        Ok(marker)
    })();
    store.observe(res).map_err(CoreError::from)
}

/// The released-tag marker that freezes `name`, if one is stored.
///
/// # Errors
/// `E_CORRUPT` for a damaged row.
pub fn released_tag_marker(
    store: &Store,
    name: &RefName,
) -> Result<Option<ReleasedTagMarker>, CoreError> {
    match store.fact(FactTable::ReleasedTags, name.as_bytes())? {
        Some(bytes) => decode_stored_marker(store, &bytes).map(Some),
        None => Ok(None),
    }
}

/// Refuses `name` while a live released-tag marker freezes it.
///
/// # Errors
/// `E_FORBIDDEN` naming the owning release; `E_CORRUPT` for a damaged row.
pub fn check_tag_unfrozen(store: &Store, name: &RefName) -> Result<(), CoreError> {
    match released_tag_marker(store, name)? {
        Some(marker) => Err(frozen_refusal(name, &marker.owner_release_id)),
        None => Ok(()),
    }
}

/// Freeze guards for the tag names among `names`. Each tag name is checked
/// with [`check_tag_unfrozen`], then gets an `Absent` guard on its marker
/// row, so a marker written between this check and the publish fails that
/// publish with `E_STALE`. The guard removes nothing: an absent row removes
/// as a no-op, and a present row is the stale case. Names outside
/// `refs/tags/` produce no guard.
///
/// # Errors
/// As [`check_tag_unfrozen`].
pub fn tag_freeze_guards(
    store: &Store,
    names: &[&RefName],
) -> Result<Vec<FactMutation>, CoreError> {
    let mut guards = Vec::new();
    for &name in names {
        if !is_tag_name(name) {
            continue;
        }
        check_tag_unfrozen(store, name)?;
        guards.push(FactMutation {
            table: FactTable::ReleasedTags,
            key: name.as_bytes().to_vec(),
            expected: FactExpectation::Absent,
            value: None,
        });
    }
    Ok(guards)
}

/// Lowers a freeze of `name` to a create-if-absent CAS on its marker row.
///
/// An identical row (same owner and target) makes a retry a rewrite of the
/// same bytes guarded by those bytes, so a row cleared between the check and
/// the publish still fails it. Any other row refuses: a retry must not move
/// the pinned target, and another release must not take the tag over.
///
/// # Errors
/// `E_INVALID` for a name outside `refs/tags/`; `E_FORBIDDEN` naming the
/// existing owner when the row belongs to another release or pins another
/// target; `E_LIMIT` when the row exceeds the bound; `E_CORRUPT` for a
/// damaged row.
pub fn prepare_release_freeze(
    store: &Store,
    name: &RefName,
    marker: &ReleasedTagMarker,
) -> Result<FactMutation, CoreError> {
    if !is_tag_name(name) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!("a released tag must live under refs/tags/, got `{name}`"),
        ));
    }
    reject_null_oid(marker.target_oid, "released tag marker")?;
    marker
        .target_oid
        .expect_kind(store.hash_kind(), "released tag marker")?;
    let key = name.as_bytes().to_vec();
    let Some(bytes) = store.fact(FactTable::ReleasedTags, name.as_bytes())? else {
        let encoded = crate::store::encode("released tag marker", marker)?;
        if key.len().saturating_add(encoded.len()) > MAX_CONTROL_FRAME_BYTES {
            return Err(CoreError::new(
                ErrorCode::ELimit,
                format!("released tag marker for {name} exceeds 16 MiB bound"),
            ));
        }
        return Ok(FactMutation {
            table: FactTable::ReleasedTags,
            key,
            expected: FactExpectation::Absent,
            value: Some(encoded),
        });
    };
    let stored = decode_stored_marker(store, &bytes)?;
    if stored.owner_release_id != marker.owner_release_id {
        return Err(CoreError::new(
            ErrorCode::EForbidden,
            format!(
                "tag `{name}` is already frozen by release `{}`",
                stored.owner_release_id
            ),
        ));
    }
    if stored.target_oid != marker.target_oid {
        return Err(CoreError::new(
            ErrorCode::EForbidden,
            format!(
                "tag `{name}` is already frozen by release `{}` at a different target",
                stored.owner_release_id
            ),
        ));
    }
    Ok(FactMutation {
        table: FactTable::ReleasedTags,
        key: name.as_bytes().to_vec(),
        expected: FactExpectation::Value(bytes.clone()),
        value: Some(bytes),
    })
}

/// Lowers a clear of `name` to an owner-checked removal of its marker row.
///
/// No row is a no-op success guarded by absence: a row written between the
/// check and the publish fails that publish with `E_STALE`. A present row is
/// removed under its exact bytes, so a rewrite fails the publish the same way.
///
/// # Errors
/// `E_FORBIDDEN` naming the frozen owner when `owner` does not hold the row;
/// `E_CORRUPT` for a damaged row.
pub fn prepare_release_unfreeze(
    store: &Store,
    name: &RefName,
    owner: &str,
) -> Result<FactMutation, CoreError> {
    let Some(bytes) = store.fact(FactTable::ReleasedTags, name.as_bytes())? else {
        return Ok(FactMutation {
            table: FactTable::ReleasedTags,
            key: name.as_bytes().to_vec(),
            expected: FactExpectation::Absent,
            value: None,
        });
    };
    let stored = decode_stored_marker(store, &bytes)?;
    if stored.owner_release_id != owner {
        return Err(CoreError::new(
            ErrorCode::EForbidden,
            format!(
                "tag `{name}` is frozen by release `{}`, not `{owner}`",
                stored.owner_release_id
            ),
        ));
    }
    Ok(FactMutation {
        table: FactTable::ReleasedTags,
        key: name.as_bytes().to_vec(),
        expected: FactExpectation::Value(bytes),
        value: None,
    })
}

/// Every object id named by any reflog record in the store, old and new.
///
/// Collection roots pin these: a store object referenced by an op record
/// must not be pruned. Key or body damage fails as corruption, the same
/// way [`page_reflogs`] fails it.
pub fn all_reflog_oids(store: &Store) -> Result<Vec<Oid>, CoreError> {
    let mut out = Vec::new();
    let mut after: Option<Vec<u8>> = None;
    loop {
        let page = store.fact_page(
            FactTable::Reflogs,
            after.as_deref(),
            FactPageBudget::new(1024, MAX_CONTROL_FRAME_BYTES),
        )?;
        if page.rows.is_empty() {
            return Ok(out);
        }
        for row in &page.rows {
            let key = ReflogKey::decode(&row.key)
                .map_err(|err| corrupt_store(store, format!("reflog key corrupt: {err}")))?;
            let record = decode_stored_reflog(store, &key, &row.value)?;
            out.extend(record.old_oid);
            out.extend(record.new_oid);
        }
        if !page.more {
            return Ok(out);
        }
        after = page.rows.last().map(|row| row.key.clone());
    }
}
