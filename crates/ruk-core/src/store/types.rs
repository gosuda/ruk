//! Shared durable-store value types frozen for the whole wave.
//!
//! These types are the integration surface between the store owner and its
//! leaf modules (segments, preparation, metadata, durability). The wire
//! literals here are byte contracts: segment framing stores the
//! discriminants of [`ObjectKind`] and [`Encoding`] directly, so their
//! `repr(u8)` values never drift.
//!
//! Ownership notes:
//! - [`PreparedObject`] is produced only by [`crate::store::Store::prepare`]
//!   and consumed only by publication. Its fields are private; consumers
//!   cannot fabricate trusted prepared bytes.
//! - [`ObjectLocation`], [`SegmentManifest`] and the generation counter are
//!   publication-owned metadata: normal commands never write them outside
//!   the single publication transaction.
//! - [`FactTable`] enumerates every approved mutable fact table except the
//!   publication-owned objects/segments/generation tables.

use crate::change::{OperationId, SessionId, StoreId};
use crate::ids::{HashKind, Oid};
use crate::refdata::{RefName, RefTarget};
use crate::store::spool::Spool;
use serde::de::{self, Deserialize, Deserializer};

/// Storage-domain object kind. Segment records store this discriminant
/// directly.
///
/// `Conflict` covers native conflict records hashed as their exact
/// `conflict-v1` framed bytes; Git Blob/Tree/Commit/Tag are hashed with the
/// canonical Git object header over their payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ObjectKind {
    Blob = 1,
    Tree = 2,
    Commit = 3,
    Tag = 4,
    Conflict = 5,
}

impl ObjectKind {
    /// The object-kind byte for this kind.
    #[must_use]
    pub const fn to_repr(self) -> u8 {
        self as u8
    }

    /// Parses the wire byte. Rejects every other value.
    #[must_use]
    pub const fn from_repr(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Blob),
            2 => Some(Self::Tree),
            3 => Some(Self::Commit),
            4 => Some(Self::Tag),
            5 => Some(Self::Conflict),
            _ => None,
        }
    }

    /// Lowercase name used in canonical Git object headers
    /// (`<name> <len>\0`). Conflicts are never hashed through this.
    #[must_use]
    pub const fn git_header_name(self) -> Option<&'static str> {
        match self {
            Self::Blob => Some("blob"),
            Self::Tree => Some("tree"),
            Self::Commit => Some("commit"),
            Self::Tag => Some("tag"),
            Self::Conflict => None,
        }
    }

    /// Serializes as the u8 wire discriminant for persisted records
    /// (path form for serde `serialize_with`).
    pub(crate) fn serialize_repr<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.to_repr(), s)
    }

    /// Deserializes the u8 wire discriminant for persisted records.
    pub(crate) fn deserialize_repr<'de, D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let byte = u8::deserialize(d)?;
        ObjectKind::from_repr(byte).ok_or_else(|| {
            de::Error::invalid_value(de::Unexpected::Unsigned(byte.into()), &"1..=5")
        })
    }
}

/// Encoded payload form. Segment record flags store this discriminant
/// directly; only the values 0, 1 and 3 exist and every other flag byte is
/// corrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Encoding {
    Raw = 0,
    Zstd = 1,
    /// Zstd-compressed canonical Git delta stream over a known local
    /// predecessor (flags bits 0 and 1 both set).
    Delta = 3,
}

impl Encoding {
    /// The flag byte for this encoding.
    #[must_use]
    pub const fn to_repr(self) -> u8 {
        self as u8
    }

    /// Parses the wire flag byte. Accepts exactly 0, 1 and 3.
    #[must_use]
    pub const fn from_repr(flags: u8) -> Option<Self> {
        match flags {
            0 => Some(Self::Raw),
            1 => Some(Self::Zstd),
            3 => Some(Self::Delta),
            _ => None,
        }
    }
}

/// Where a published object lives, and everything a reader needs to decode
/// and verify it. Stored postcard-encoded in the objects table; the kind
/// and encoding discriminants are the wire bytes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObjectLocation {
    #[serde(
        serialize_with = "ObjectKind::serialize_repr",
        deserialize_with = "ObjectKind::deserialize_repr"
    )]
    pub kind: ObjectKind,
    /// Decoded payload length in bytes.
    pub decoded_len: u64,
    /// Segment id.
    pub segment: u64,
    /// Record start offset inside the segment file.
    pub offset: u64,
    /// Total record length including the 10-byte header.
    pub record_len: u64,
    /// Locator generation that published this row.
    pub generation: u64,
    /// Delta base digest when the record is a delta.
    pub base: Option<Oid>,
    /// Delta chain depth (0 for non-delta records).
    pub depth: u8,
}

/// Mutable per-segment state, postcard-encoded in the segments table.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SegmentManifest {
    pub id: u64,
    /// Inclusive end of the durable, committed prefix. Includes the seal
    /// footer when sealed.
    pub committed_end: u64,
    /// End of record bytes, excluding any seal footer.
    pub records_end: u64,
    pub sealed: bool,
    pub retired: bool,
    pub generation: u64,
}

/// Trusted prepared bytes produced by [`crate::store::Store::prepare`] and
/// consumed only by publication. Fields are private: nothing outside
/// preparation/publication can fabricate a prepared object.
#[derive(Debug)]
pub struct PreparedObject {
    pub(crate) oid: Oid,
    pub(crate) kind: ObjectKind,
    pub(crate) decoded_len: u64,
    pub(crate) encoding: Encoding,
    pub(crate) payload: Spool,
    /// CRC32C over the exact stored payload bytes.
    pub(crate) payload_crc: u32,
    pub(crate) base: Option<Oid>,
    pub(crate) depth: u8,
}

impl PreparedObject {
    /// The verified object identity.
    #[must_use]
    pub fn oid(&self) -> Oid {
        self.oid
    }

    #[must_use]
    pub fn kind(&self) -> ObjectKind {
        self.kind
    }

    #[must_use]
    pub fn decoded_len(&self) -> u64 {
        self.decoded_len
    }

    #[must_use]
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    /// Delta base when this object was prepared as a delta.
    #[must_use]
    pub fn base(&self) -> Option<Oid> {
        self.base
    }

    /// Delta chain depth (0 for non-delta).
    #[must_use]
    pub fn depth(&self) -> u8 {
        self.depth
    }
}

/// A verified, decoded object read. Fields are public: the bytes were
/// already verified against the object identity before this value exists.
#[derive(Debug)]
pub struct ReadObject {
    pub kind: ObjectKind,
    pub bytes: Spool,
    /// Delta chain depth of the stored record (0 for non-delta).
    pub depth: u8,
}

/// One ref event this publication emitted, locating the operation the
/// batch performed on its ref.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefEvent {
    /// The ref whose mutation the event records.
    pub name: Vec<u8>,
    /// The event sequence assigned under the writer lock.
    pub seq: u64,
}

/// Durable outcome of one publication.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Publication {
    /// Every object identity in the batch, including compatible duplicates
    /// that were already stored.
    pub objects: Vec<Oid>,
    /// Metadata generation that committed this batch.
    pub generation: u64,
    /// One entry per `Refs` fact the batch carried, in fact order.
    pub ref_events: Vec<RefEvent>,
}

/// The approved mutable fact tables. Closed: a new table arrives only with
/// a schema revision. Each variant maps to one redb table with the exact
/// census name; the key and value are raw bytes, and typed records are
/// postcard-encoded by their owners.
///
/// Publication owns objects/segments/generation; they are deliberately not
/// expressible here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FactTable {
    Refs,
    RefConflicts,
    RemoteObservations,
    Changes,
    ImportedChanges,
    ChangeHistory,
    Commits,
    Ops,
    OpHead,
    Workspaces,
    Claims,
    WsIndex,
    WsStatus,
    WsDirs,
    Receipts,
    Sessions,
    Attestations,
    PushPlans,
    LandPlans,
    PublishedHeads,
    Leases,
    WsApply,
    Reflogs,
    Promisor,
    Shallow,
    Pins,
    LfsObjects,
    Events,
    EventHead,
    ServiceReceipts,
    RepoMeta,
    ReleasedTags,
}

impl FactTable {
    /// Every table, in schema order.
    pub const ALL: [Self; 32] = [
        Self::Refs,
        Self::RefConflicts,
        Self::RemoteObservations,
        Self::Changes,
        Self::ImportedChanges,
        Self::ChangeHistory,
        Self::Commits,
        Self::Ops,
        Self::OpHead,
        Self::Workspaces,
        Self::Claims,
        Self::WsIndex,
        Self::WsStatus,
        Self::WsDirs,
        Self::Receipts,
        Self::Sessions,
        Self::Attestations,
        Self::PushPlans,
        Self::LandPlans,
        Self::PublishedHeads,
        Self::Leases,
        Self::WsApply,
        Self::Reflogs,
        Self::Promisor,
        Self::Shallow,
        Self::Pins,
        Self::LfsObjects,
        Self::Events,
        Self::EventHead,
        Self::ServiceReceipts,
        Self::RepoMeta,
        Self::ReleasedTags,
    ];

    /// The exact on-disk table name from the core census.
    #[must_use]
    pub const fn table_name(self) -> &'static str {
        match self {
            Self::Refs => "refs",
            Self::RefConflicts => "ref_conflicts",
            Self::RemoteObservations => "remote_observations",
            Self::Changes => "changes",
            Self::ImportedChanges => "imported_changes",
            Self::ChangeHistory => "change_history",
            Self::Commits => "commits",
            Self::Ops => "ops",
            Self::OpHead => "op_head",
            Self::Workspaces => "workspaces",
            Self::Claims => "claims",
            Self::WsIndex => "ws_index",
            Self::WsStatus => "ws_status",
            Self::WsDirs => "ws_dirs",
            Self::Receipts => "receipts",
            Self::Sessions => "sessions",
            Self::Attestations => "attestations",
            Self::PushPlans => "push_plans",
            Self::LandPlans => "land_plans",
            Self::PublishedHeads => "published_heads",
            Self::Leases => "leases",
            Self::WsApply => "ws_apply",
            Self::Reflogs => "reflogs",
            Self::Promisor => "promisor",
            Self::Shallow => "shallow",
            Self::Pins => "pins",
            Self::LfsObjects => "lfs_objects",
            Self::Events => "events",
            Self::EventHead => "event_head",
            Self::ServiceReceipts => "service_receipts",
            Self::RepoMeta => "repo_meta",
            Self::ReleasedTags => "released_tags",
        }
    }
}

/// What published one batch of ref mutations: the lane, the receive-pack
/// path, a local command, or a lifecycle importer. Recorded on every ref
/// event; never an authorization input.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub enum EventSource {
    ReceivePack,
    Lane,
    LocalPush,
    Fork,
    Import,
    Land,
}

/// Per-event attribution for one publication: the lane fills every field,
/// every other publisher leaves the ones it does not have empty.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventContext {
    /// The lane operation that moved the ref, if any.
    pub operation: Option<OperationId>,
    /// The idempotency key that moved the ref, if any.
    pub request_id: Option<String>,
    /// The session that moved the ref, if any.
    pub session: Option<SessionId>,
    /// Provenance the invoking call declared; recorded, never authorized on.
    pub on_behalf_of: Option<String>,
}

/// One ref event: the `Events` row at the big-endian sequence key, naming
/// the ref mutation that committed under the writer lock.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoreEvent {
    /// The mutated ref name.
    pub name: Vec<u8>,
    /// The ref target before the batch, absent for creates.
    pub old: Option<Vec<u8>>,
    /// The ref target after the batch, absent for deletes.
    pub new: Option<Vec<u8>>,
    /// Unix millis the batch committed.
    pub at: u64,
    /// What published the batch.
    pub source: EventSource,
    /// The lane operation that moved the ref, if any.
    pub operation: Option<OperationId>,
    /// The idempotency key that moved the ref, if any.
    pub request_id: Option<String>,
    /// The session that moved the ref, if any.
    pub session: Option<SessionId>,
    /// Provenance the invoking call declared; recorded, never authorized on.
    /// Appended last so older rows decode through [`StoreEventV1`].
    /// Never surfaced in `TailedEvent`.
    #[serde(default)]
    pub on_behalf_of: Option<String>,
}

/// Pre-provenance ref event: the [`StoreEvent`] shape before the trailing
/// `on_behalf_of` field. Decode-only outside tests, for rows written before
/// provenance existed.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct StoreEventV1 {
    pub name: Vec<u8>,
    pub old: Option<Vec<u8>>,
    pub new: Option<Vec<u8>>,
    pub at: u64,
    pub source: EventSource,
    pub operation: Option<OperationId>,
    pub request_id: Option<String>,
    pub session: Option<SessionId>,
}

/// Decodes one event ref-target cell: the postcard `RefTarget` stored in
/// an event's `old`/`new` bytes.
pub fn decode_event_target(raw: &[u8]) -> Result<RefTarget, crate::store::StoreError> {
    crate::store::decode("event target", raw)
}

/// Decodes one `Events` row: the current shape first, then the
/// pre-provenance shape with `on_behalf_of` absent.
pub fn decode_store_event(raw: &[u8]) -> Result<StoreEvent, crate::store::StoreError> {
    if let Ok(event) = crate::store::decode("event", raw) {
        return Ok(event);
    }
    let old: StoreEventV1 = crate::store::decode("event", raw)?;
    Ok(StoreEvent {
        name: old.name,
        old: old.old,
        new: old.new,
        at: old.at,
        source: old.source,
        operation: old.operation,
        request_id: old.request_id,
        session: old.session,
        on_behalf_of: None,
    })
}

/// The `EventHead` row: the event sequence horizon. `head` is the last
/// assigned sequence (zero with no events); `oldest` is the oldest
/// retained sequence, or `head + 1` when retention pruned everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EventHeadRow {
    /// The last assigned event sequence.
    pub head: u64,
    /// The oldest retained event sequence.
    pub oldest: u64,
}

/// The `EventHead` row key.
pub const EVENT_HEAD_KEY: &[u8] = b"head";

/// The `RepoMeta` row: repository-level metadata written once at init.
/// `repo.init` persists the default branch here; `policy.set` extends the
/// row with the landing policy, bumping `policy_generation` every write.
/// Stores predating the policy fields decode through [`RepoMetaRowV0`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RepoMetaRow {
    /// The default branch name recorded at init.
    pub default_branch: RefName,
    /// Attestation predicates every landing candidate must carry.
    /// Empty means landing is unconstrained.
    #[serde(default)]
    pub land_requirements: Vec<crate::protocol::AttestRequirement>,
    /// Signers trusted to meet the landing requirements.
    #[serde(default)]
    pub trusted_signers: Vec<crate::protocol::SignerFingerprint>,
    /// How many `policy.set` writes this row has seen.
    #[serde(default)]
    pub policy_generation: u64,
}

/// Pre-policy repository metadata: the [`RepoMetaRow`] shape before the
/// trailing landing-policy fields. Decode-only, for stores written before
/// `policy.set` existed; they read back with an empty policy at
/// generation zero.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub(crate) struct RepoMetaRowV0 {
    pub default_branch: RefName,
}

/// The `RepoMeta` row key.
pub const REPO_META_KEY: &[u8] = b"meta";

/// Conditional application of one fact mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactExpectation {
    /// No condition.
    Any,
    /// The key must not exist before this mutation.
    Absent,
    /// The current value must equal these bytes exactly.
    Value(Vec<u8>),
}

/// One conditional mutation of a fact row: insert or replace when
/// `value` is `Some`, remove when it is `None`.
#[derive(Clone, Debug)]
pub struct FactMutation {
    pub table: FactTable,
    pub key: Vec<u8>,
    pub expected: FactExpectation,
    pub value: Option<Vec<u8>>,
}

/// The store format record: the object format and the store's immutable
/// identity. One copy lives in [`crate::store::Store`]; there is no legacy
/// reader and no implicit upgrade: only this canonical three-line v1 marker
/// is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreFormat {
    pub kind: HashKind,
    pub id: StoreId,
}

impl StoreFormat {
    /// Exact format-file bytes:
    /// `ruk-store 1\nobject-format <kind>\nstore-id <id>\n`.
    ///
    /// The identity renders in its canonical lowercase hyphenated form.
    ///
    /// # Preconditions
    /// The caller supplies a non-nil identity: [`StoreFormat::from_bytes`]
    /// and [`crate::store::Store::create`] enforce that at their
    /// boundaries, while this method renders the value it is given.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        format!(
            "ruk-store 1\nobject-format {}\nstore-id {}\n",
            self.kind.format_name(),
            self.id
        )
        .into_bytes()
    }

    /// Parses exact format-file bytes. Only the canonical three-line v1
    /// spelling with a non-nil canonical store identity is accepted. The
    /// earlier two-line v1 marker is rejected, never upgraded.
    ///
    /// # Errors
    /// [`crate::store::StoreError::Version`] on any other content.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::store::StoreError> {
        let text = core::str::from_utf8(bytes)
            .map_err(|_| crate::store::StoreError::Version("format file is not UTF-8".into()))?;
        parse_format_text(text)
    }
}

/// Parses the three exact LF-terminated lines, rejecting every other shape:
/// a non-UTF-8 precheck runs in [`StoreFormat::from_bytes`], then any CR
/// byte, a missing final newline, a wrong store line, unknown kind, a
/// missing or malformed store identity, and any extra line.
fn parse_format_text(text: &str) -> Result<StoreFormat, crate::store::StoreError> {
    if text.is_empty() {
        return Err(crate::store::StoreError::Version(
            "empty format file".into(),
        ));
    }
    if text.contains('\r') {
        return Err(crate::store::StoreError::Version(
            "format file contains a carriage return".into(),
        ));
    }
    let Some(body) = text.strip_suffix('\n') else {
        return Err(crate::store::StoreError::Version(
            "format file does not end with a newline".into(),
        ));
    };
    let mut lines = body.split('\n');
    let store_line = lines.next().unwrap_or_default();
    if store_line != "ruk-store 1" {
        return Err(crate::store::StoreError::Version(format!(
            "unsupported store line: {store_line}"
        )));
    }
    let kind_line = lines
        .next()
        .ok_or_else(|| crate::store::StoreError::Version("missing object-format line".into()))?;
    let kind_text = kind_line.strip_prefix("object-format ").ok_or_else(|| {
        crate::store::StoreError::Version(format!("bad object-format line: {kind_line}"))
    })?;
    let kind: HashKind = kind_text
        .parse()
        .map_err(|_| crate::store::StoreError::Version(format!("unknown kind {kind_text}")))?;
    let id_line = lines
        .next()
        .ok_or_else(|| crate::store::StoreError::Version("missing store-id line".into()))?;
    let id_text = id_line.strip_prefix("store-id ").ok_or_else(|| {
        crate::store::StoreError::Version(format!("bad store-id line: {id_line}"))
    })?;
    let id = parse_store_identity(id_text)?;
    if lines.next().is_some() {
        return Err(crate::store::StoreError::Version(
            "trailing content in format file".into(),
        ));
    }
    Ok(StoreFormat { kind, id })
}

/// Parses one store identity: the canonical [`StoreId`] spelling only, and
/// never the nil identity. [`StoreId`]'s `FromStr` accepts only the exact
/// 36-character lowercase hyphenated form, so a successful parse is already
/// canonical.
fn parse_store_identity(text: &str) -> Result<StoreId, crate::store::StoreError> {
    let id: StoreId = text
        .parse()
        .map_err(|_| crate::store::StoreError::Version(format!("malformed store id: {text}")))?;
    if id == StoreId::nil() {
        return Err(crate::store::StoreError::Version("nil store id".into()));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::StoreError;

    /// A fixed canonical identity for pure parser fixtures.
    fn fixed_id() -> StoreId {
        StoreId::from_bytes([
            0x2f, 0x9c, 0x32, 0x11, 0xa4, 0x5b, 0x4c, 0x7d, 0x9e, 0x01, 0x55, 0xaa, 0x0b, 0x33,
            0xcc, 0xdd,
        ])
    }

    fn marker(kind: HashKind) -> Vec<u8> {
        StoreFormat {
            kind,
            id: fixed_id(),
        }
        .to_bytes()
    }

    fn assert_version(what: &str, bytes: &[u8]) {
        match StoreFormat::from_bytes(bytes) {
            Err(StoreError::Version(_)) => {}
            other => panic!("{what}: expected a Version refusal, got {other:?}"),
        }
    }

    #[test]
    fn writes_and_parses_the_exact_three_line_marker() {
        let sha1 = StoreFormat {
            kind: HashKind::Sha1,
            id: fixed_id(),
        };
        assert_eq!(
            sha1.to_bytes(),
            b"ruk-store 1\nobject-format sha1\nstore-id 2f9c3211-a45b-4c7d-9e01-55aa0b33ccdd\n"
        );
        assert_eq!(
            StoreFormat::from_bytes(&sha1.to_bytes()).expect("sha1"),
            sha1
        );
        let sha256 = StoreFormat {
            kind: HashKind::Sha256,
            id: fixed_id(),
        };
        assert_eq!(
            sha256.to_bytes(),
            b"ruk-store 1\nobject-format sha256\nstore-id 2f9c3211-a45b-4c7d-9e01-55aa0b33ccdd\n"
        );
        assert_eq!(
            StoreFormat::from_bytes(&sha256.to_bytes()).expect("sha256"),
            sha256
        );
    }

    #[test]
    fn rejects_the_earlier_two_line_marker() {
        assert_version("two-line sha1", b"ruk-store 1\nobject-format sha1\n");
        assert_version("two-line sha256", b"ruk-store 1\nobject-format sha256\n");
    }

    #[test]
    fn rejects_missing_and_mistyped_lines() {
        assert_version("empty", b"");
        assert_version(
            "wrong store line",
            b"ruk-store 2\nobject-format sha1\nstore-id 2f9c3211-a45b-4c7d-9e01-55aa0b33ccdd\n",
        );
        assert_version(
            "unknown kind",
            b"ruk-store 1\nobject-format md5\nstore-id 2f9c3211-a45b-4c7d-9e01-55aa0b33ccdd\n",
        );
        assert_version(
            "kind with extra words",
            b"ruk-store 1\nobject-format sha1 extra\nstore-id 2f9c3211-a45b-4c7d-9e01-55aa0b33ccdd\n",
        );
        assert_version("no store-id line", b"ruk-store 1\nobject-format sha1");
        assert_version("bare prefix", b"ruk-store");
    }

    #[test]
    fn rejects_carriage_returns_and_a_missing_final_newline() {
        assert_version(
            "CRLF endings",
            b"ruk-store 1\r\nobject-format sha1\r\nstore-id 2f9c3211-a45b-4c7d-9e01-55aa0b33ccdd\r\n",
        );
        let mut with_cr = marker(HashKind::Sha1);
        with_cr.push(b'\r');
        assert_version("lone CR after the marker", &with_cr);
        let full = marker(HashKind::Sha1);
        assert_version("missing final newline", &full[..full.len() - 1]);
    }

    #[test]
    fn rejects_extra_lines_and_trailing_content() {
        let mut extra = marker(HashKind::Sha1);
        extra.extend_from_slice(b"extra fourth line\n");
        assert_version("a fourth line", &extra);
        let mut blank = marker(HashKind::Sha1);
        blank.push(b'\n');
        assert_version("a trailing blank line", &blank);
    }

    #[test]
    fn rejects_nil_and_noncanonical_identities() {
        let nil =
            b"ruk-store 1\nobject-format sha1\nstore-id 00000000-0000-0000-0000-000000000000\n";
        assert_version("nil identity", nil);
        assert_version(
            "uppercase identity",
            b"ruk-store 1\nobject-format sha1\nstore-id 2F9C3211-A45B-4C7D-9E01-55AA0B33CCDD\n",
        );
        assert_version(
            "unhyphenated identity",
            b"ruk-store 1\nobject-format sha1\nstore-id 2f9c3211a45b4c7d9e0155aa0b33ccdd\n",
        );
        assert_version(
            "braced identity",
            b"ruk-store 1\nobject-format sha1\nstore-id {2f9c3211-a45b-4c7d-9e01-55aa0b33ccdd}\n",
        );
        assert_version(
            "empty identity",
            b"ruk-store 1\nobject-format sha1\nstore-id \n",
        );
        assert_version(
            "truncated identity",
            b"ruk-store 1\nobject-format sha1\nstore-id 2f9c3211-a45b\n",
        );
        assert_version(
            "identity with extra words",
            b"ruk-store 1\nobject-format sha1\nstore-id 2f9c3211-a45b-4c7d-9e01-55aa0b33ccdd extra\n",
        );
    }

    #[test]
    fn rejects_non_utf8_and_foreign_content() {
        let mut bad = marker(HashKind::Sha1);
        bad[3] = 0xFF;
        assert_version("non-UTF-8 byte", &bad);
        assert_version("foreign content", b"not a store marker\n");
    }

    fn sample_event() -> StoreEvent {
        StoreEvent {
            name: b"refs/heads/main".to_vec(),
            old: None,
            new: Some(b"tip".to_vec()),
            at: 1_000,
            source: EventSource::ReceivePack,
            operation: None,
            request_id: Some("req-1".to_string()),
            session: None,
            on_behalf_of: Some("agent-x".to_string()),
        }
    }

    #[test]
    fn event_decode_reads_current_provenance() {
        let event = sample_event();
        let raw = crate::store::encode("event", &event).expect("encode");
        let back = decode_store_event(&raw).expect("decode");
        assert_eq!(back, event);
    }

    #[test]
    fn event_decode_falls_back_to_pre_provenance_rows() {
        let event = sample_event();
        let old = StoreEventV1 {
            name: event.name.clone(),
            old: event.old.clone(),
            new: event.new.clone(),
            at: event.at,
            source: event.source,
            operation: event.operation,
            request_id: event.request_id.clone(),
            session: event.session,
        };
        let raw = crate::store::encode("event", &old).expect("encode v1");
        assert!(
            crate::store::decode::<StoreEvent>("event", &raw).is_err(),
            "pre-provenance bytes must not decode as the current shape"
        );
        let back = decode_store_event(&raw).expect("fallback decodes");
        assert_eq!(back.on_behalf_of, None);
        assert_eq!(back.name, event.name);
        assert_eq!(back.request_id, event.request_id);
    }
}
