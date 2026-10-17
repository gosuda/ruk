//! Batch accumulation and candidate grouping for the publication lane.
//!
//! Enforces bounded group commit: linger at most 2ms, aggregate at most 64 requests
//! and at most 64 MiB of prepared publication bytes. Large single transactions
//! (>64 MiB) commit as their own dedicated single-item batches. Overlapping touched
//! keys or semantic ref/claim dependencies are separated into sequential batches.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use tokio::sync::oneshot;

use crate::coord::cancel::Cancel;
use crate::coord::lane::candidate::{InternalCandidate, MutationCandidate};
use crate::coord::rows;
use crate::error::CoreError;
use crate::protocol::Reply;
use crate::refdata::RefName;
use crate::store::types::FactTable;

/// Maximum requests aggregated into a single group commit batch.
pub(crate) const MAX_BATCH_REQUESTS: usize = 64;

/// Ordinary group aggregation cap in prepared publication bytes (64 MiB).
///
/// This is not a single-transaction limit: one larger allowed transaction
/// commits as its own dedicated single-item batch.
pub(crate) const MAX_BATCH_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum duration to linger waiting for additional requests when forming a batch.
pub(crate) const MAX_BATCH_LINGER: Duration = Duration::from_millis(2);

/// One queued item submitted to the publication lane.
pub(crate) enum BatchItem {
    Mutation {
        candidate: Box<MutationCandidate>,
        reply_tx: Option<oneshot::Sender<Result<Reply, CoreError>>>,
    },
    Internal {
        candidate: Box<InternalCandidate>,
        reply_tx: Option<oneshot::Sender<Result<(), CoreError>>>,
    },
}

impl BatchItem {
    /// Returns the prepared publication bytes of this item.
    #[must_use]
    pub(crate) fn prepared_bytes(&self) -> u64 {
        match self {
            Self::Mutation { candidate, .. } => candidate.prepared_bytes,
            Self::Internal { candidate, .. } => candidate.prepared_bytes,
        }
    }

    /// Returns a reference to the cancellation observer for this item.
    #[must_use]
    pub(crate) fn cancel(&self) -> &Cancel {
        match self {
            Self::Mutation { candidate, .. } => &candidate.cancel,
            Self::Internal { candidate, .. } => &candidate.cancel,
        }
    }

    /// Returns `true` if any fact mutation or seal-time read in this item touches a key in `touched`.
    #[must_use]
    pub(crate) fn has_key_conflict(&self, touched: &HashMap<FactTable, HashSet<Vec<u8>>>) -> bool {
        let facts = match self {
            Self::Mutation { candidate, .. } => &candidate.facts,
            Self::Internal { candidate, .. } => &candidate.facts,
        };

        let has_fact_conflict = facts.iter().any(|f| {
            touched
                .get(&f.table)
                .is_some_and(|keys| keys.contains(f.key.as_slice()))
        });
        if has_fact_conflict {
            return true;
        }

        let Self::Mutation { candidate, .. } = self else {
            return false;
        };

        if let Some(fence) = candidate.workspace_fence {
            let ws_key = rows::workspace_key(fence.id);
            let has_ws_conflict = touched
                .get(&FactTable::Workspaces)
                .is_some_and(|keys| keys.contains(&ws_key[..]));
            if has_ws_conflict {
                return true;
            }
        }

        let r_key = rows::receipt_key(candidate.session.id(), candidate.request_id);
        touched
            .get(&FactTable::Receipts)
            .is_some_and(|keys| keys.contains(&r_key[..]))
    }

    /// Returns `true` if this item mutates or references refs.
    #[must_use]
    pub(crate) fn touches_refs(&self) -> bool {
        let Self::Mutation { candidate, .. } = self else {
            return false;
        };

        candidate.ref_transaction.is_some()
            || !candidate.ref_dependencies.is_empty()
            || candidate.facts.iter().any(|f| f.table == FactTable::Refs)
    }

    /// Returns `true` if this item mutates or checks claims.
    #[must_use]
    pub(crate) fn touches_claims(&self) -> bool {
        let facts = match self {
            Self::Mutation { candidate, .. } => &candidate.facts,
            Self::Internal { candidate, .. } => &candidate.facts,
        };

        facts.iter().any(|f| f.table == FactTable::Claims)
    }

    /// Completes the item with a pre-publication error.
    pub(crate) fn fail(self, err: CoreError) {
        match self {
            Self::Mutation { reply_tx, .. } => {
                if let Some(tx) = reply_tx {
                    let _ = tx.send(Err(err));
                }
            }
            Self::Internal { reply_tx, .. } => {
                if let Some(tx) = reply_tx {
                    let _ = tx.send(Err(err));
                }
            }
        }
    }
}

/// Accumulates items for one bounded group commit batch.
pub(crate) struct BatchAccumulator {
    items: Vec<BatchItem>,
    total_bytes: u64,
    touched_keys: HashMap<FactTable, HashSet<Vec<u8>>>,
    has_refs: bool,
    has_claims: bool,
    is_large_single_tx: bool,
}

impl BatchAccumulator {
    /// Creates an empty batch accumulator.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            items: Vec::with_capacity(MAX_BATCH_REQUESTS),
            total_bytes: 0,
            touched_keys: HashMap::new(),
            has_refs: false,
            has_claims: false,
            is_large_single_tx: false,
        }
    }

    /// Returns the number of items currently in the batch.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` if the batch has no items.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns `true` if the batch cannot admit any further items and should be sealed.
    #[must_use]
    pub(crate) fn is_full(&self) -> bool {
        self.is_large_single_tx
            || self.items.len() >= MAX_BATCH_REQUESTS
            || self.total_bytes >= MAX_BATCH_BYTES
    }

    /// Checks whether `item` can be admitted into the current batch.
    #[must_use]
    pub(crate) fn can_admit(&self, item: &BatchItem) -> bool {
        if self.items.is_empty() {
            return true;
        }

        if self.is_large_single_tx {
            return false;
        }

        if self.items.len() >= MAX_BATCH_REQUESTS {
            return false;
        }

        let item_bytes = item.prepared_bytes();
        if item_bytes > MAX_BATCH_BYTES {
            return false;
        }

        let Some(next_total) = self.total_bytes.checked_add(item_bytes) else {
            return false;
        };
        if next_total > MAX_BATCH_BYTES {
            return false;
        }

        if item.has_key_conflict(&self.touched_keys) {
            return false;
        }

        if item.touches_refs() && self.has_refs {
            return false;
        }

        if item.touches_claims() && self.has_claims {
            return false;
        }

        true
    }

    /// Admits `item` into the batch, updating tracking sets and byte counters.
    ///
    /// # Panics
    /// Panics if called when `can_admit(item)` is false.
    pub(crate) fn add(&mut self, item: BatchItem) {
        assert!(
            self.can_admit(&item),
            "item cannot be admitted into current batch"
        );

        let item_bytes = item.prepared_bytes();
        if self.items.is_empty() && item_bytes > MAX_BATCH_BYTES {
            self.is_large_single_tx = true;
        }

        self.total_bytes = self.total_bytes.saturating_add(item_bytes);

        match &item {
            BatchItem::Mutation { candidate, .. } => {
                for fact in &candidate.facts {
                    self.touched_keys
                        .entry(fact.table)
                        .or_default()
                        .insert(fact.key.clone());
                    if fact.table == FactTable::Refs {
                        self.has_refs = true;
                    }
                    if fact.table == FactTable::Claims {
                        self.has_claims = true;
                    }
                }
                if candidate.ref_transaction.is_some() || !candidate.ref_dependencies.is_empty() {
                    self.has_refs = true;
                }
                if let Some(fence) = candidate.workspace_fence {
                    self.touched_keys
                        .entry(FactTable::Workspaces)
                        .or_default()
                        .insert(rows::workspace_key(fence.id).to_vec());
                }
                self.touched_keys
                    .entry(FactTable::Receipts)
                    .or_default()
                    .insert(
                        rows::receipt_key(candidate.session.id(), candidate.request_id).to_vec(),
                    );
            }
            BatchItem::Internal { candidate, .. } => {
                for fact in &candidate.facts {
                    self.touched_keys
                        .entry(fact.table)
                        .or_default()
                        .insert(fact.key.clone());
                    if fact.table == FactTable::Claims {
                        self.has_claims = true;
                    }
                }
            }
        }

        self.items.push(item);
    }

    /// Consumes the accumulator and returns the collected items.
    #[must_use]
    pub(crate) fn drain(self) -> Vec<BatchItem> {
        self.items
    }
}
