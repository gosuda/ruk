//! Git object exchange: the fetch and push client half.
//!
//! # Invariant
//!
//! Git protocol bytes travel on the wire; Ruk store facts stay off it.
//! Objects leave a store only as canonical Git object bytes read back
//! verified through [`Store::read`], and enter one only through
//! [`Store::prepare`] followed by one atomic [`Store::publish`] together
//! with the ref, tracking, promisor and shallow facts they justify. Raw
//! native segment records never reach a wire, and nothing here starts a
//! system Git process: the pack, negotiation and status grammars are owned
//! in-process.
//!
//! # Staging boundary (quarantine)
//!
//! [`Store`] exposes no separate quarantine directory: a [`PreparedObject`]
//! is a verified, spooled object that is invisible to every reader until a
//! publication commits it. Received packs are therefore staged as a list of
//! prepared objects ([`pack::StagedPack`]), connectivity is verified against
//! that staging plus committed objects, and only then does one publication
//! make objects and ref deltas visible together. Dropping the staging
//! releases its spools; nothing was published.
//!
//! # Layout
//!
//! - [`pktline`]: pkt-line framing and side-band demultiplexing.
//! - [`refadv`]: protocol v0/v1 advertisements and v2 `ls-refs`.
//! - [`pack`]: pack ingest into staging, pack emission, delta codecs.
//! - [`hooks`]: receive-pack hook phases over quarantine staging.
//! - [`fetch`]: fetch negotiation, verification, publication, prefetch.
//! - [`push`]: send-pack client, report-status, push plans.
//! - [`serve`]: the `upload-pack`/`receive-pack` server halves (protocol v0).
//! - [`proc_receive`]: AGit `refs/for/` diversion to the `proc-receive` hook.
//! - [`dumb`]: dumb-HTTP `info/refs` text and loose objects.
//! - [`archive`]: the `upload-archive` server half (streaming tar).
//! - [`session`]: the transport seam and the local native transport.
//! - [`net`]: remote URL parsing plus the SSH, git-daemon and smart-http
//!   transports (dumb-http stays the one HTTP named gap).
//! - [`smart_http`]: stateless upload-pack/receive-pack over HTTP(S).
//!
//! Later slices add an HTTPS adapter behind [`session::Transport`]; SSH
//! and git-daemon streams already feed the owned wire clients directly,
//! and smart-http POSTs feed the same ingest and report halves over a
//! framing-decoding response reader.

pub mod archive;
pub mod credentials;
pub mod dumb;
pub mod dumb_http;
pub mod fetch;
pub mod hooks;
pub mod http;
pub mod lfs;
pub mod mirror;
pub mod net;
pub mod pack;
pub mod pktline;
pub mod private;
pub mod proto_v2;
pub mod proc_receive;
pub mod push;
pub mod refadv;
pub mod serve;
pub mod session;
pub mod smart_http;

#[cfg(test)]
#[path = "tests/notes_roundtrip.rs"]
mod notes_roundtrip_tests;
#[cfg(test)]
#[path = "tests/private_exclusion.rs"]
mod private_exclusion_tests;
#[cfg(test)]
#[path = "tests/push_persistence.rs"]
mod push_persistence_tests;

use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use ruk_core::error::ErrorCode;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefName, RefTarget};
use ruk_core::store::types::ObjectKind;
use ruk_core::store::{FactExpectation, FactMutation, FactTable, PreparedObject, Store};

use crate::GitError;

/// The agent string sent in every negotiated capability list.
pub const AGENT: &str = concat!("ruk/", env!("CARGO_PKG_VERSION"));

/// Deadline and cancellation shared by every long transfer step.
///
/// Checked between packets, pack entries and prefetch batches; a tripped
/// interrupt is [`GitError::Cancelled`] and publishes nothing.
#[derive(Clone, Debug, Default)]
pub struct Interrupt {
    deadline: Option<Instant>,
    cancel: Option<Arc<AtomicBool>>,
}

impl Interrupt {
    /// An interrupt that never trips.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Trips once `deadline` has passed.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Trips once `flag` is set.
    #[must_use]
    pub fn with_cancel(mut self, flag: Arc<AtomicBool>) -> Self {
        self.cancel = Some(flag);
        self
    }

    /// Fails when cancelled or past the deadline.
    ///
    /// # Errors
    /// [`GitError::Cancelled`] naming `what` was interrupted.
    pub fn check(&self, what: &str) -> Result<(), GitError> {
        if self
            .cancel
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::SeqCst))
        {
            return Err(GitError::Cancelled {
                detail: format!("{what} was cancelled"),
            });
        }
        if self.deadline.is_some_and(|at| Instant::now() >= at) {
            return Err(GitError::Cancelled {
                detail: format!("{what} passed its deadline"),
            });
        }
        Ok(())
    }
}

/// A missing object a promisor remote can supply, keyed by the missing OID
/// in [`FactTable::Promisor`].
///
/// Value layout, versioned: `01 | remote_len:u32 LE | remote | filter`.
/// Manual encoding: the row must stay readable without new dependencies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromisorRow {
    /// The remote name the object can be fetched from.
    pub remote: Vec<u8>,
    /// The filter spec that omitted it, such as `blob:none`.
    pub filter: Vec<u8>,
}

impl PromisorRow {
    /// Encodes the row value.
    ///
    /// # Errors
    /// [`GitError::Limit`] when the remote name exceeds the 16 MiB control bound.
    pub fn encode(&self) -> Result<Vec<u8>, GitError> {
        if self.remote.len() > ruk_core::MAX_CONTROL_FRAME_BYTES {
            return Err(GitError::Limit {
                detail: "promisor remote name exceeds the control bound".to_owned(),
            });
        }
        let mut out = Vec::with_capacity(5 + self.remote.len() + self.filter.len());
        out.push(1);
        // The bound above keeps the length inside u32, so the cast is exact.
        out.extend_from_slice(&(self.remote.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.remote);
        out.extend_from_slice(&self.filter);
        Ok(out)
    }

    /// Decodes a stored row value; malformed stored bytes are corrupt.
    ///
    /// # Errors
    /// [`GitError::Corrupt`] for a bad version, truncation, or a remote
    /// name past the control bound.
    pub fn decode(bytes: &[u8]) -> Result<Self, GitError> {
        let corrupt = |why: &str| GitError::Corrupt {
            detail: format!("stored promisor row is malformed: {why}"),
        };
        let [version, rest @ ..] = bytes else {
            return Err(corrupt("empty"));
        };
        if *version != 1 {
            return Err(corrupt("unknown version"));
        }
        if rest.len() < 4 {
            return Err(corrupt("truncated remote length"));
        }
        let remote_len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        if remote_len > ruk_core::MAX_CONTROL_FRAME_BYTES {
            return Err(corrupt("remote length past the control bound"));
        }
        let rest = &rest[4..];
        if rest.len() < remote_len {
            return Err(corrupt("truncated remote name"));
        }
        Ok(Self {
            remote: rest[..remote_len].to_vec(),
            filter: rest[remote_len..].to_vec(),
        })
    }
}

/// Key of a shallow boundary row: the raw boundary commit OID bytes with an
/// empty value. Byte-identical to the sibling `import::refs::shallow_key`;
/// the parent consolidates the two definitions.
#[must_use]
pub fn shallow_key(oid: Oid) -> Vec<u8> {
    oid.as_bytes().to_vec()
}

/// Key of a remote-observation row: `source NUL ref-name`. Byte-identical to
/// the sibling `import::refs::observation_key`; the parent consolidates.
#[must_use]
pub fn observation_key(source: &[u8], name: &RefName) -> Vec<u8> {
    let mut key = Vec::with_capacity(source.len() + 1 + name.as_bytes().len());
    key.extend_from_slice(source);
    key.push(0);
    key.extend_from_slice(name.as_bytes());
    key
}

/// Encodes a remote-observation value: `00 | raw oid` for a direct target,
/// `01 | ref-name` for a symbolic one. Byte-identical to the sibling
/// `import::refs::encode_observation`.
#[must_use]
pub fn encode_observation(target: &RefTarget) -> Vec<u8> {
    match target {
        RefTarget::Direct(oid) => {
            let mut out = Vec::with_capacity(1 + oid.as_bytes().len());
            out.push(0);
            out.extend_from_slice(oid.as_bytes());
            out
        }
        RefTarget::Symbolic(name) => {
            let mut out = Vec::with_capacity(1 + name.as_bytes().len());
            out.push(1);
            out.extend_from_slice(name.as_bytes());
            out
        }
    }
}

/// Decodes a stored observation value.
///
/// # Errors
/// [`GitError::Corrupt`] for malformed bytes, [`GitError::ObjectFormat`]
/// for a direct target of the other width.
pub fn decode_observation(bytes: &[u8], kind: HashKind) -> Result<RefTarget, GitError> {
    let corrupt = |why: &str| GitError::Corrupt {
        detail: format!("stored remote observation is malformed: {why}"),
    };
    let [tag, rest @ ..] = bytes else {
        return Err(corrupt("empty"));
    };
    match tag {
        0 => {
            let oid = Oid::from_bytes(rest).map_err(|_| corrupt("bad oid bytes"))?;
            if oid.kind() != kind {
                return Err(GitError::ObjectFormat {
                    detail: format!(
                        "stored observation is {} but the store is {kind}",
                        oid.kind()
                    ),
                });
            }
            Ok(RefTarget::Direct(oid))
        }
        1 => RefName::new(rest.to_vec())
            .map(RefTarget::Symbolic)
            .map_err(|err| corrupt(&err.to_string())),
        _ => Err(corrupt("unknown tag")),
    }
}

/// Reads the promisor row for `oid`, if the object is promised.
///
/// # Errors
/// Store failures; a malformed row is [`GitError::Corrupt`].
pub fn promisor_row(store: &Store, oid: Oid) -> Result<Option<PromisorRow>, GitError> {
    store
        .fact(FactTable::Promisor, oid.as_bytes())?
        .map(|bytes| PromisorRow::decode(&bytes))
        .transpose()
}

/// Whether `oid` is a recorded shallow boundary: a row keyed by
/// [`shallow_key`] with an empty value.
///
/// # Errors
/// Store failures.
pub fn is_shallow(store: &Store, oid: Oid) -> Result<bool, GitError> {
    Ok(store.fact(FactTable::Shallow, &shallow_key(oid))?.is_some())
}

/// Insertion of one shallow boundary row.
pub(crate) fn shallow_insert(oid: Oid) -> FactMutation {
    FactMutation {
        table: FactTable::Shallow,
        key: shallow_key(oid),
        expected: FactExpectation::Any,
        value: Some(Vec::new()),
    }
}

/// Removal of one shallow boundary row (an `unshallow` answer).
pub(crate) fn shallow_remove(oid: Oid) -> FactMutation {
    FactMutation {
        table: FactTable::Shallow,
        key: shallow_key(oid),
        expected: FactExpectation::Any,
        value: None,
    }
}

/// Insert-or-replace mutation of one promisor row.
pub(crate) fn promisor_mutation(oid: Oid, row: &PromisorRow) -> Result<FactMutation, GitError> {
    Ok(FactMutation {
        table: FactTable::Promisor,
        key: oid.as_bytes().to_vec(),
        expected: FactExpectation::Any,
        value: Some(row.encode()?),
    })
}

/// Removal of the promisor row of an object that is now present.
pub(crate) fn promisor_clear(oid: Oid) -> FactMutation {
    FactMutation {
        table: FactTable::Promisor,
        key: oid.as_bytes().to_vec(),
        expected: FactExpectation::Any,
        value: None,
    }
}

/// Whether the store holds `oid`.
///
/// The store surface has no locator-only probe, so this performs a verified
/// read and discards the bytes: a have-probe costs a full read. A cheaper
/// presence probe is a store-owned addition; callers here bound how many
/// probes they make.
///
/// # Errors
/// Store failures other than absence.
pub fn has_object(store: &Store, oid: Oid) -> Result<bool, GitError> {
    match store.read(oid) {
        Ok(_) => Ok(true),
        Err(err) if err.code() == ErrorCode::ENotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

/// Reads one verified object, refusing bodies larger than `max_bytes`
/// before buffering them.
///
/// # Errors
/// Store failures, and [`GitError::Limit`] above `max_bytes`.
pub fn read_object(
    store: &Store,
    oid: Oid,
    max_bytes: u64,
) -> Result<(ObjectKind, Vec<u8>), GitError> {
    let mut read = store.read(oid)?;
    let len = read.bytes.len();
    if len > max_bytes {
        return Err(GitError::Limit {
            detail: format!("object {oid} has {len} bytes, above the {max_bytes}-byte limit"),
        });
    }
    let capacity = usize::try_from(len).map_err(|_| GitError::Limit {
        detail: format!("object {oid} does not fit in memory"),
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    read.bytes
        .read_to_end(&mut bytes)
        .map_err(|err| GitError::Io {
            detail: format!("reading object {oid}: {err}"),
        })?;
    Ok((read.kind, bytes))
}

/// Prepares canonical Git object bytes into staging and checks the store's
/// identity against the announced one, when given.
pub(crate) fn stage_object(
    store: &Store,
    kind: ObjectKind,
    bytes: &[u8],
    expected: Option<Oid>,
) -> Result<PreparedObject, GitError> {
    let len = u64::try_from(bytes.len()).map_err(|_| GitError::Limit {
        detail: "object length does not fit in 64 bits".to_owned(),
    })?;
    let prepared = store.prepare(kind, len, bytes, None)?;
    if let Some(want) = expected
        && prepared.oid() != want
    {
        return Err(GitError::Corrupt {
            detail: format!(
                "received object hashes to {} but was announced as {want}",
                prepared.oid()
            ),
        });
    }
    Ok(prepared)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promisor_row_round_trips_and_rejects_garbage() {
        let row = PromisorRow {
            remote: b"origin".to_vec(),
            filter: b"blob:none".to_vec(),
        };
        let bytes = row.encode().expect("encode");
        assert_eq!(PromisorRow::decode(&bytes).expect("decode"), row);
        for bad in [
            &b""[..],
            &b"\x02"[..],
            &b"\x01\x03"[..],
            &b"\x01\x09\x00\x00\x00ab"[..],
        ] {
            assert!(PromisorRow::decode(bad).is_err(), "{bad:?} must fail");
        }
    }

    #[test]
    fn observation_round_trips() {
        let oid = Oid::from_hex("1111111111111111111111111111111111111111").expect("hex");
        let direct = RefTarget::Direct(oid);
        assert_eq!(
            decode_observation(&encode_observation(&direct), HashKind::Sha1).expect("decode"),
            direct
        );
        let sym = RefTarget::Symbolic(RefName::new(b"refs/heads/main".to_vec()).expect("name"));
        assert_eq!(
            decode_observation(&encode_observation(&sym), HashKind::Sha1).expect("decode"),
            sym
        );
        assert!(decode_observation(b"", HashKind::Sha1).is_err());
        assert!(decode_observation(b"\x02x", HashKind::Sha1).is_err());
    }
}
