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

use crate::ids::{HashKind, Oid};
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

/// Durable outcome of one publication.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Publication {
    /// Every object identity in the batch, including compatible duplicates
    /// that were already stored.
    pub objects: Vec<Oid>,
    /// Metadata generation that committed this batch.
    pub generation: u64,
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
}

impl FactTable {
    /// Every table, in schema order.
    pub const ALL: [Self; 26] = [
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
        }
    }
}

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

/// The store format record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreFormat {
    pub kind: HashKind,
}

impl StoreFormat {
    /// Exact format-file bytes: `ruk-store 1\nobject-format <kind>\n`.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        format!("ruk-store 1\nobject-format {}\n", self.kind.format_name()).into_bytes()
    }

    /// Parses exact format-file bytes. Only the canonical spelling.
    ///
    /// # Errors
    /// [`crate::store::StoreError::Version`] on any other content.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::store::StoreError> {
        let text = core::str::from_utf8(bytes)
            .map_err(|_| crate::store::StoreError::Version("format file is not UTF-8".into()))?;
        parse_format_text(text)
    }
}

/// Parses the two canonical lines; rejects trailing content.
fn parse_format_text(text: &str) -> Result<StoreFormat, crate::store::StoreError> {
    let mut lines = text.lines();
    let store_line = lines
        .next()
        .ok_or_else(|| crate::store::StoreError::Version("empty format file".into()))?;
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
    if lines.next().is_some() {
        return Err(crate::store::StoreError::Version(
            "trailing content in format file".into(),
        ));
    }
    Ok(StoreFormat { kind })
}
