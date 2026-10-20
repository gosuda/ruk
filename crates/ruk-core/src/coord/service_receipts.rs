//! Durable git-stream receipts: idempotent replay for receive-pack.
//!
//! Each mutating receive-pack execution writes one [`ServiceReceipt`] row
//! keyed `(peer uid, canonical repository, request_id)`. A retry that
//! reuses its request id replays the stored report instead of
//! re-executing: same digest returns the stored outcome, a different
//! digest is refused as `E_REQUEST_REUSED` (M8: the keying must include
//! uid and repository, or a cross-tenant replay returns another tenant's report).
//! Rows older than [`SERVICE_RECEIPT_RETENTION_SECONDS`] prune through
//! the shared retention sweep.

use crate::error::CoreError;
use crate::store::{
    EventContext, EventSource, FactExpectation, FactMutation, FactTable, Store, decode, encode,
};

/// Durable receipt row version. The table was born in the census
/// revision, so version 1 is the only version on disk; the field keeps
/// the row forward-compatible.
pub const SERVICE_RECEIPT_VERSION: u32 = 1;

/// Receipt retention: seven days, swept by the shared retention pass
/// alongside (but counted separately from) the event horizon.
pub const SERVICE_RECEIPT_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;

/// One completed receive-pack execution, replayable by request id.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServiceReceipt {
    /// Row version; must equal [`SERVICE_RECEIPT_VERSION`].
    pub version: u32,
    /// Daemon-side digest over parsed commands and effective limits.
    pub digest: String,
    /// Native exit status of the run (zero on success).
    pub exit_code: i32,
    /// Response bytes sent after the run (receive-pack status report).
    pub output: Vec<u8>,
    /// Contract spelling of the failing error code, if the run failed.
    pub error_code: Option<String>,
    /// Failing error message, if the run failed.
    pub error_message: Option<String>,
    /// Wall-clock milliseconds when the run completed.
    pub at: u64,
}

/// Builds the composite receipt key. NUL separators are unambiguous:
/// user ids are fixed width and neither repositories nor request ids
/// contain NUL bytes.
pub(crate) fn service_receipt_key(peer_uid: u32, repository: &[u8], request_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + 1 + repository.len() + 1 + request_id.len());
    key.extend_from_slice(&peer_uid.to_be_bytes());
    key.push(0);
    key.extend_from_slice(repository);
    key.push(0);
    key.extend_from_slice(request_id.as_bytes());
    key
}

fn decode_receipt(bytes: &[u8]) -> Result<(ServiceReceipt, Vec<u8>), CoreError> {
    let receipt: ServiceReceipt = decode("service receipt", bytes)
        .map_err(|err| CoreError::new(err.code(), err.to_string()))?;
    Ok((receipt, bytes.to_vec()))
}

/// Reads one receipt row, if present.
pub fn lookup_service_receipt(
    store: &Store,
    peer_uid: u32,
    repository: &[u8],
    request_id: &str,
) -> Result<Option<(ServiceReceipt, Vec<u8>)>, CoreError> {
    let key = service_receipt_key(peer_uid, repository, request_id);
    let raw = store
        .fact(FactTable::ServiceReceipts, &key)
        .map_err(|err| CoreError::new(err.code(), err.to_string()))?;
    raw.map(|bytes| decode_receipt(&bytes)).transpose()
}

/// Writes one receipt row, expecting absence. A concurrent same-request
/// execution fails loudly as stale instead of silently winning; the
/// caller re-reads the winner's row and replays it.
pub fn store_service_receipt(
    store: &Store,
    peer_uid: u32,
    repository: &[u8],
    request_id: &str,
    receipt: &ServiceReceipt,
) -> Result<(), crate::store::StoreError> {
    let value = encode("service receipt", receipt)?;
    let mutation = FactMutation {
        table: FactTable::ServiceReceipts,
        key: service_receipt_key(peer_uid, repository, request_id),
        expected: FactExpectation::Absent,
        value: Some(value),
    };
    store
        .publish(
            Vec::new(),
            &[mutation],
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .map(|_| ())
}

/// One bounded sweep page over old receipts.
pub(crate) struct ServiceReceiptSweep {
    /// Receipt rows scanned in this page.
    pub(crate) examined: usize,
    /// Exact Value-expected deletions for expired rows in this page.
    pub(crate) deletions: Vec<FactMutation>,
    /// Resume key for the next pass: the last key of a full page, or
    /// `None` when the page ended the keyspace. Receipt keys order by
    /// (uid, repository, request id), not by time, so a pass that always
    /// restarted from the first key could reread one fresh page forever
    /// while stale rows behind it never prune; rotation defeats that.
    pub(crate) next_after: Option<Vec<u8>>,
}

/// Collects receipt rows older than `cutoff_millis` starting after
/// `after`. Each pass scans one bounded page and resumes where the
/// previous pass stopped, so every row is eventually examined no
/// matter how the keys distribute over time.
pub(crate) fn sweep_service_receipts_page(
    store: &Store,
    cutoff_millis: u64,
    limit: usize,
    after: Option<&[u8]>,
) -> Result<ServiceReceiptSweep, CoreError> {
    use crate::store::FactPageBudget;
    let page = store
        .fact_page(
            FactTable::ServiceReceipts,
            after,
            FactPageBudget::new(limit, usize::MAX),
        )
        .map_err(|err| CoreError::new(err.code(), err.to_string()))?;
    let mut sweep = ServiceReceiptSweep {
        examined: page.rows.len(),
        deletions: Vec::new(),
        next_after: None,
    };
    for row in &page.rows {
        let (receipt, raw) = decode_receipt(&row.value)?;
        if receipt.at < cutoff_millis {
            sweep.deletions.push(FactMutation {
                table: FactTable::ServiceReceipts,
                key: row.key.clone(),
                expected: FactExpectation::Value(raw),
                value: None,
            });
        }
    }
    if page.more {
        sweep.next_after = page.rows.last().map(|row| row.key.clone());
    }
    Ok(sweep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::HashKind;
    use crate::store::PreparationBudget;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    fn temp_store(tag: &str) -> (PathBuf, Store) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "ruk-receipt-{tag}-{}-{}-{nanos}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        let store_dir = dir.join("store");
        std::fs::create_dir_all(&dir).expect("create the test parent directory");
        let budget = Arc::new(PreparationBudget::reference_defaults());
        let store = Store::create(&store_dir, HashKind::Sha1, budget).expect("create store");
        (dir, store)
    }

    fn receipt(digest: &str, at: u64) -> ServiceReceipt {
        ServiceReceipt {
            version: SERVICE_RECEIPT_VERSION,
            digest: digest.to_string(),
            exit_code: 0,
            output: b"ok refs/heads/main\n".to_vec(),
            error_code: None,
            error_message: None,
            at,
        }
    }

    #[test]
    fn service_receipts_isolate_peer_uids() {
        let (_dir, store) = temp_store("isolation");
        let repo = b"/srv/ruk/repo";
        store_service_receipt(&store, 1000, repo, "req-1", &receipt("aaa", 10))
            .expect("store uid 1000");
        store_service_receipt(&store, 1001, repo, "req-1", &receipt("bbb", 10))
            .expect("store uid 1001");
        let (first, _) = lookup_service_receipt(&store, 1000, repo, "req-1")
            .expect("lookup")
            .expect("uid 1000 row exists");
        let (second, _) = lookup_service_receipt(&store, 1001, repo, "req-1")
            .expect("lookup")
            .expect("uid 1001 row exists");
        assert_eq!(first.digest, "aaa");
        assert_eq!(second.digest, "bbb");
        assert!(
            lookup_service_receipt(&store, 1002, repo, "req-1")
                .expect("lookup")
                .is_none(),
            "an unknown uid misses"
        );
        assert!(
            lookup_service_receipt(&store, 1000, repo, "req-2")
                .expect("lookup")
                .is_none(),
            "an unknown request id misses"
        );
    }

    #[test]
    fn service_receipts_isolate_repositories() {
        let (_dir, store) = temp_store("repo-isolation");
        store_service_receipt(
            &store,
            1000,
            b"/srv/ruk/alpha",
            "req-1",
            &receipt("aaa", 10),
        )
        .expect("store alpha");
        store_service_receipt(&store, 1000, b"/srv/ruk/beta", "req-1", &receipt("bbb", 10))
            .expect("store beta");
        let (first, _) = lookup_service_receipt(&store, 1000, b"/srv/ruk/alpha", "req-1")
            .expect("lookup")
            .expect("alpha row exists");
        let (second, _) = lookup_service_receipt(&store, 1000, b"/srv/ruk/beta", "req-1")
            .expect("lookup")
            .expect("beta row exists");
        assert_eq!(first.digest, "aaa");
        assert_eq!(second.digest, "bbb");
        assert!(
            lookup_service_receipt(&store, 1000, b"/srv/ruk/gamma", "req-1")
                .expect("lookup")
                .is_none(),
            "an unknown repository misses"
        );
    }

    #[test]
    fn service_receipts_survive_reopen() {
        let (dir, store) = temp_store("reopen");
        let repo = b"/srv/ruk/repo";
        store_service_receipt(&store, 1000, repo, "req-1", &receipt("aaa", 10)).expect("store");
        drop(store);
        let budget = Arc::new(PreparationBudget::reference_defaults());
        let store = Store::open(&dir.join("store"), budget).expect("reopen");
        let (found, _) = lookup_service_receipt(&store, 1000, repo, "req-1")
            .expect("lookup")
            .expect("the receipt survives reopen");
        assert_eq!(found.digest, "aaa");
        assert_eq!(found.output, b"ok refs/heads/main\n");
    }

    #[test]
    fn service_receipts_sweep_rotates_pages() {
        let (_dir, store) = temp_store("rotate");
        let repo = b"/srv/ruk/repo";
        for (id, at) in [("a", 1_000), ("b", 1_000), ("c", 9_000)] {
            store_service_receipt(&store, 1000, repo, id, &receipt("aaa", at)).expect("store");
        }
        let first = sweep_service_receipts_page(&store, 5_000, 2, None).expect("sweep");
        assert_eq!(first.examined, 2);
        assert_eq!(first.deletions.len(), 2);
        let after = first.next_after.clone().expect("a full page resumes");
        let second = sweep_service_receipts_page(&store, 5_000, 2, Some(&after)).expect("sweep");
        assert_eq!(second.examined, 1);
        assert!(second.deletions.is_empty());
        assert!(second.next_after.is_none(), "the last page wraps");
    }

    #[test]
    fn service_receipts_sweep_prunes_old() {
        let (_dir, store) = temp_store("sweep");
        let repo = b"/srv/ruk/repo";
        store_service_receipt(&store, 1000, repo, "old", &receipt("aaa", 1_000))
            .expect("store old");
        store_service_receipt(&store, 1000, repo, "new", &receipt("bbb", 9_000))
            .expect("store new");
        let sweep = sweep_service_receipts_page(&store, 5_000, 100, None).expect("sweep");
        assert_eq!(sweep.examined, 2);
        assert_eq!(sweep.deletions.len(), 1);
        store
            .publish(
                Vec::new(),
                &sweep.deletions,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish sweep");
        assert!(
            lookup_service_receipt(&store, 1000, repo, "old")
                .expect("lookup")
                .is_none()
        );
        assert!(
            lookup_service_receipt(&store, 1000, repo, "new")
                .expect("lookup")
                .is_some()
        );
    }
}
