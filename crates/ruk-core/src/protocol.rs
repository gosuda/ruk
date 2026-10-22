//! The core protocol: versioned request/reply schemas for every native
//! method, plus the framing, paging, and inline-size bounds that make them
//! safe to accept from an untrusted peer.
//!
//! Control frames are length-prefixed JSON (a 4-byte big-endian length, then
//! at most [`MAX_CONTROL_FRAME_BYTES`] bytes). Bulk bytes never travel in a
//! control frame: a read reply points at a stream ([`ByteSource::Streamed`])
//! and a write that exceeds [`MAX_INLINE_EDIT_BYTES`] references a staged
//! object ([`StagedObject`]); the data frames themselves belong to the
//! transport layer.
//!
//! # Wire discipline
//!
//! * Every enum uses serde's default external tagging, and no type uses
//!   `flatten`, `untagged`, or `skip_serializing_if`. Non-schema replies are
//!   stored durably in receipts through postcard, which cannot decode
//!   self-describing shapes; the digest input is postcard too. Schema reply
//!   documents have no binary postcard form: they travel in JSON frames.
//! * Only a major-version mismatch is rejected on version grounds: once a
//!   frame passes the size, JSON syntax, and nesting checks and carries a
//!   readable `schema_version`, [`decode_request`] fails `E_VERSION` before
//!   interpreting the rest of the body. A newer minor is accepted: readers
//!   ignore unknown optional fields.
//! * Every mutation carries a `request_id` (the [`Mutation`] wrapper makes
//!   its absence unrepresentable) and its expected stamps inside `args`, so
//!   the idempotency digest ([`Request::digest_input_v1`]) covers each
//!   expected stamp exactly once and never the request id.
//! * [`Request::validate`] enforces the cross-field invariants the types
//!   cannot (uniqueness, namespaces, file/directory collisions). Object-format
//!   width of an `Oid` is checked where the object is resolved, not here.

use core::fmt;
use core::hash::Hash;
use core::num::NonZeroU32;
use std::borrow::Cow;
use std::collections::HashSet;

use schemars::generate::SchemaSettings;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, DeserializeOwned, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sonic_rs::{from_slice, to_vec};
use thiserror::Error;

use crate::MAX_CONTROL_FRAME_BYTES;
use crate::bytes::ByteString;
use crate::capability::{AttestKind, AttestResult, Capabilities, RefPattern, bounded_text};
use crate::change::{
    ChangeId, ClaimId, LeaseId, OperationId, PlanId, RequestId, SessionId, StoreId, WorkspaceId,
};
use crate::commit::{CommitRecord, ProvenanceClaims};
use crate::conflict::Signature;
use crate::error::{CoreError, CoreModelError, ErrorCode};
use crate::heads::Head;
use crate::ids::{HashKind, Oid, hex_byte, hex_val};
use crate::index::RepoPath;
use crate::merge::Merge;
use crate::merge::composed::{MergeMode, MergeReport};
use crate::refdata::{RefExpect, RefName, RefTarget};
use crate::refs::RefEntry;
use crate::store::types::EventSource;
use crate::workspace::{HeadRef, Scope, WorkspaceStamp, WorkspaceState};

/// Major protocol/schema version implemented by this build.
pub const SCHEMA_MAJOR: u32 = 1;

/// Minor schema version within the current major; increments are additive.
/// Minor 1 appends the `git.commit` lane method for per-repository commit
/// batching. Minor 2 appends the hosted forge methods (`repo.stat`,
/// `tree`, `refs.list`, `compare`, `search`, `archive`, `events.tail`,
/// `repo.init`, `repo.delete`, `repo.rename`, `repo.fork`, `remote.refs`,
/// `claim.renew`, `policy.set`) and the `Admin` method kind; older readers
/// refuse its frames as unknown methods.
pub const SCHEMA_MINOR: u32 = 2;

/// Bytes in a control-frame length prefix.
pub const FRAME_PREFIX_BYTES: usize = 4;

/// Maximum decoded size of one inline write edit.
pub const MAX_INLINE_EDIT_BYTES: usize = 1024 * 1024;

/// Rows in a page when the request names no limit.
pub const DEFAULT_PAGE_SIZE: usize = 100;

/// Largest accepted page limit; more is rejected, never clamped.
pub const MAX_PAGE_SIZE: usize = 1000;

/// Longest claim lifetime in seconds (one hour).
pub const MAX_CLAIM_TTL_SECONDS: u32 = 3600;

/// Longest accepted revset text.
pub const MAX_REVSET_BYTES: usize = 64 * 1024;

/// Longest accepted opaque cursor position.
pub const MAX_CURSOR_POSITION_BYTES: usize = 4096;

/// Version of the request-digest codec; a codec change needs a new version.
pub const REQUEST_DIGEST_VERSION: u8 = 1;

const DIGEST_DOMAIN_V1: &[u8] = b"ruk-request-digest-v1";
const ATTEST_PAYLOAD_DOMAIN_V1: &[u8] = b"ruk-attest-payload-v1";
const ATTEST_PAYLOAD_DOMAIN_V2: &[u8] = b"ruk-attest-payload-v2";

fn invalid(detail: impl Into<String>) -> CoreError {
    CoreError::new(ErrorCode::EInvalid, detail)
}

fn limit_exceeded(detail: impl Into<String>) -> CoreError {
    CoreError::new(ErrorCode::ELimit, detail)
}

fn model_invalid(what: &'static str, detail: impl Into<String>) -> CoreModelError {
    CoreModelError::Invalid {
        what,
        detail: detail.into(),
    }
}

/// Why a bounded text field was refused.
#[derive(Debug, Error)]
enum FieldError {
    #[error("NUL bytes are not allowed")]
    Nul,
    #[error("control characters are not allowed")]
    Control,
    #[error("character {0:?} is not allowed")]
    Character(char),
    #[error("{0}")]
    Shape(&'static str),
}

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

/// The schema version carried by every request and reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct SchemaVersion {
    pub major: u32,
    pub minor: u32,
}

impl SchemaVersion {
    /// This build's schema version.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            major: SCHEMA_MAJOR,
            minor: SCHEMA_MINOR,
        }
    }

    /// True when this build can read the version: the major matches. A newer
    /// minor is readable because minor additions only add optional fields.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        self.major == SCHEMA_MAJOR
    }
}

/// Validates a peer-provided schema version.
///
/// # Errors
/// [`CoreModelError::Version`] (`E_VERSION`) on an unsupported major.
pub fn validate_schema_version(version: SchemaVersion) -> Result<(), CoreModelError> {
    if version.is_supported() {
        return Ok(());
    }
    Err(CoreModelError::Version(format!(
        "schema major {} is not supported; this build speaks major {SCHEMA_MAJOR}",
        version.major
    )))
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

/// An RFC 3339 UTC instant. The text form must end in `Z`: an offset form is
/// refused so every stored and signed timestamp has one spelling per instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(jiff::Timestamp);

impl Timestamp {
    /// Wraps an instant.
    #[must_use]
    pub const fn new(instant: jiff::Timestamp) -> Self {
        Self(instant)
    }

    /// The wrapped instant.
    #[must_use]
    pub const fn instant(self) -> jiff::Timestamp {
        self.0
    }

    /// Parses `YYYY-MM-DDTHH:MM:SS[.fraction]Z`.
    ///
    /// # Errors
    /// Text that is not an RFC 3339 instant in UTC.
    pub fn parse(text: &str) -> Result<Self, CoreModelError> {
        if !text.ends_with('Z') {
            return Err(model_invalid(
                "timestamp",
                "must be RFC 3339 UTC ending in `Z`",
            ));
        }
        text.parse::<jiff::Timestamp>()
            .map(Self)
            .map_err(|err| model_invalid("timestamp", err.to_string()))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            return serializer.collect_str(&self.0);
        }
        (self.0.as_second(), self.0.subsec_nanosecond()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let text = String::deserialize(deserializer)?;
            return Self::parse(&text).map_err(de::Error::custom);
        }
        let (seconds, nanos) = <(i64, i32)>::deserialize(deserializer)?;
        jiff::Timestamp::new(seconds, nanos)
            .map(Self)
            .map_err(de::Error::custom)
    }
}

impl JsonSchema for Timestamp {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("Timestamp")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "format": "date-time",
            "description": "RFC 3339 instant in UTC; the text ends in `Z`."
        })
    }
}

// ---------------------------------------------------------------------------
// Fixed-width digests and secrets
// ---------------------------------------------------------------------------

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(hex_byte(*byte));
    }
    out
}

fn decode_hex32(text: &str, what: &'static str) -> Result<[u8; 32], CoreModelError> {
    let raw = text.as_bytes();
    if raw.len() != 64 {
        return Err(model_invalid(
            what,
            format!("expected 64 lowercase hex characters, got {}", raw.len()),
        ));
    }
    let mut out = [0_u8; 32];
    // The length check above leaves no remainder.
    let (pairs, _) = raw.as_chunks::<2>();
    for (slot, [high, low]) in out.iter_mut().zip(pairs) {
        let (Some(high), Some(low)) = (hex_val(*high), hex_val(*low)) else {
            return Err(model_invalid(what, "expected lowercase hex characters"));
        };
        *slot = (high << 4) | low;
    }
    Ok(out)
}

/// Defines a 32-byte value with a 64-character lowercase-hex JSON form and a
/// raw-bytes binary form.
macro_rules! fixed_hex {
    (
        $(#[$meta:meta])*
        $name:ident, $schema:literal, $doc:literal, redact: $redact:literal
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Width in bytes.
            pub const LEN: usize = 32;

            /// Wraps exactly 32 bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// The raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Lowercase hex rendering.
            #[must_use]
            pub fn to_hex(&self) -> String {
                encode_hex(&self.0)
            }

            /// Parses 64 lowercase hex characters.
            ///
            /// # Errors
            /// Wrong length, uppercase, or non-hex input.
            pub fn from_hex(text: &str) -> Result<Self, CoreModelError> {
                decode_hex32(text, $schema).map(Self)
            }

            /// Equality that does not stop at the first differing byte.
            #[must_use]
            pub fn ct_eq(&self, other: &Self) -> bool {
                let mut difference = 0_u8;
                for (left, right) in self.0.iter().zip(other.0.iter()) {
                    difference |= left ^ right;
                }
                difference == 0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if $redact {
                    write!(f, "{}(<redacted>)", $schema)
                } else {
                    write!(f, "{}({})", $schema, self.to_hex())
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&self.to_hex())
                } else {
                    serializer.serialize_bytes(&self.0)
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct HexVisitor;

                impl Visitor<'_> for HexVisitor {
                    type Value = $name;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str(concat!("a ", $schema, " (64 lowercase hex characters)"))
                    }

                    fn visit_str<E: de::Error>(self, text: &str) -> Result<$name, E> {
                        $name::from_hex(text).map_err(E::custom)
                    }

                    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<$name, E> {
                        let array: [u8; 32] = bytes
                            .try_into()
                            .map_err(|_| E::custom("expected exactly 32 bytes"))?;
                        Ok($name(array))
                    }
                }

                if deserializer.is_human_readable() {
                    deserializer.deserialize_str(HexVisitor)
                } else {
                    deserializer.deserialize_bytes(HexVisitor)
                }
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                Cow::Borrowed($schema)
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "pattern": "^[0-9a-f]{64}$",
                    "description": $doc
                })
            }
        }
    };
}

fixed_hex! {
    /// SHA-256 over the versioned request-digest input (see
    /// [`Request::digest_input_v1`]).
    RequestDigest,
    "RequestDigest",
    "SHA-256 request digest: 64 lowercase hex characters.",
    redact: false
}

fixed_hex! {
    /// Digest binding a page cursor to the query that produced it.
    QueryDigest,
    "QueryDigest",
    "SHA-256 digest of the canonical query: 64 lowercase hex characters.",
    redact: false
}

fixed_hex! {
    /// SHA-256 over an attestation's canonical payload.
    StatementDigest,
    "StatementDigest",
    "SHA-256 digest of a canonical attestation payload: 64 lowercase hex characters.",
    redact: false
}

fixed_hex! {
    /// The random 32-byte secret that lets a client resume a session. It
    /// appears only in the reply to `session.open`; Debug output redacts it.
    ReconnectSecret,
    "ReconnectSecret",
    "Session reconnect secret: 64 lowercase hex characters. Never logged.",
    redact: true
}

// ---------------------------------------------------------------------------
// Paging
// ---------------------------------------------------------------------------

/// A validated page limit in `1..=`[`MAX_PAGE_SIZE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct PageLimit(u16);

impl PageLimit {
    /// The limit used when a request names none.
    pub const DEFAULT: Self = Self(100);

    /// The largest accepted limit.
    pub const MAX: Self = Self(1000);

    /// Validates a row count.
    ///
    /// # Errors
    /// Zero, or more than [`MAX_PAGE_SIZE`]: an over-large page is refused,
    /// not clamped, so a client never believes it received what it asked for.
    pub fn new(rows: u32) -> Result<Self, CoreModelError> {
        match u16::try_from(rows) {
            Ok(rows) if rows >= 1 && usize::from(rows) <= MAX_PAGE_SIZE => Ok(Self(rows)),
            _ => Err(model_invalid(
                "page limit",
                format!("{rows} is outside 1..={MAX_PAGE_SIZE}"),
            )),
        }
    }

    /// The limit as a row count.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0 as usize
    }
}

impl TryFrom<u32> for PageLimit {
    type Error = CoreModelError;

    fn try_from(rows: u32) -> Result<Self, Self::Error> {
        Self::new(rows)
    }
}

impl From<PageLimit> for u32 {
    fn from(limit: PageLimit) -> Self {
        Self::from(limit.0)
    }
}

impl JsonSchema for PageLimit {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("PageLimit")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "integer",
            "minimum": 1,
            "maximum": MAX_PAGE_SIZE,
            "default": DEFAULT_PAGE_SIZE,
            "description": "Rows per page; above the maximum is rejected, not clamped."
        })
    }
}

/// Binds a page cursor to the store, view, query, and lease it came from. A
/// server rejects a cursor whose binding differs from the request it
/// arrives with, and a cursor stops working when its lease expires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PageCursor {
    pub store: StoreId,
    pub view: OperationId,
    pub query: QueryDigest,
    pub lease: LeaseId,
    /// Opaque resume position, at most [`MAX_CURSOR_POSITION_BYTES`].
    pub position: ByteString,
}

/// The paging part of a read request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PageRequest {
    /// Rows wanted; absent means [`DEFAULT_PAGE_SIZE`].
    #[serde(default)]
    pub limit: Option<PageLimit>,
    /// Where the previous page stopped; absent starts at the beginning.
    #[serde(default)]
    pub cursor: Option<PageCursor>,
}

impl PageRequest {
    /// The number of rows to return.
    #[must_use]
    pub fn effective_limit(&self) -> usize {
        self.limit.map_or(DEFAULT_PAGE_SIZE, PageLimit::get)
    }
}

/// One page of rows and the cursor for the next one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Present while more rows remain.
    pub next: Option<PageCursor>,
}

impl<T> Page<T> {
    /// Builds a page.
    ///
    /// # Errors
    /// `E_LIMIT` when `items` exceeds [`MAX_PAGE_SIZE`].
    pub fn new(items: Vec<T>, next: Option<PageCursor>) -> Result<Self, CoreError> {
        if items.len() > MAX_PAGE_SIZE {
            return Err(limit_exceeded(format!(
                "a page holds at most {MAX_PAGE_SIZE} rows, got {}",
                items.len()
            )));
        }
        Ok(Self { items, next })
    }
}

/// A revision naming one commit: either a ref resolved at read time or a
/// literal object id. Reads that accept revisions (tree, compare, archive,
/// blame) take this shape instead of free-form strings.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CommitRev {
    Ref(RefName),
    Commit(Oid),
}

/// One stateless keyset page: rows plus the opaque position to resume
/// after. Unlike [`Page`], the cursor binds no 30-second lease: the caller
/// passes `next_after` back as the next request's `after`, so forge reads
/// never hold lease state for pagination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct KeysetPage<T> {
    pub items: Vec<T>,
    /// The last returned key as raw bytes: a ref name for `refs.list`, an
    /// entry name for `tree`. Absent when the listing is exhausted.
    #[serde(default)]
    pub next_after: Option<ByteString>,
}

impl<T> KeysetPage<T> {
    /// Builds a page.
    ///
    /// # Errors
    /// `E_LIMIT` when `items` exceeds [`MAX_PAGE_SIZE`].
    pub fn new(items: Vec<T>, next_after: Option<ByteString>) -> Result<Self, CoreError> {
        if items.len() > MAX_PAGE_SIZE {
            return Err(limit_exceeded(format!(
                "a keyset page holds at most {MAX_PAGE_SIZE} rows, got {}",
                items.len()
            )));
        }
        Ok(Self { items, next_after })
    }
}

/// A bounded excerpt of a collection too large to return whole: at most
/// [`MAX_PAGE_SIZE`] items, the true total, and whether anything was left out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BoundedList<T> {
    pub total: u64,
    pub items: Vec<T>,
    pub truncated: bool,
}

impl<T> BoundedList<T> {
    /// A list holding all of its `items`.
    ///
    /// # Errors
    /// `E_LIMIT` when `items` exceeds [`MAX_PAGE_SIZE`].
    pub fn complete(items: Vec<T>) -> Result<Self, CoreError> {
        let total = u64::try_from(items.len()).unwrap_or(u64::MAX);
        Self::excerpt(items, total)
    }

    /// An excerpt of a collection with `total` members.
    ///
    /// # Errors
    /// `E_LIMIT` when `items` exceeds [`MAX_PAGE_SIZE`]; `E_INVALID` when
    /// `total` is smaller than the number of items.
    pub fn excerpt(items: Vec<T>, total: u64) -> Result<Self, CoreError> {
        if items.len() > MAX_PAGE_SIZE {
            return Err(limit_exceeded(format!(
                "a bounded list holds at most {MAX_PAGE_SIZE} items, got {}",
                items.len()
            )));
        }
        let held = u64::try_from(items.len()).unwrap_or(u64::MAX);
        if total < held {
            return Err(invalid("total is smaller than the number of items"));
        }
        Ok(Self {
            total,
            truncated: total > held,
            items,
        })
    }
}

// ---------------------------------------------------------------------------
// Bulk bytes
// ---------------------------------------------------------------------------

/// Bytes carried inside a control frame: at most [`MAX_INLINE_EDIT_BYTES`]
/// once decoded (a hex-form payload counts its decoded bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InlineBytes(ByteString);

impl InlineBytes {
    /// Validates the size.
    ///
    /// # Errors
    /// More than [`MAX_INLINE_EDIT_BYTES`] bytes; upload a staged object and
    /// reference it instead of splitting the file.
    pub fn new(bytes: ByteString) -> Result<Self, CoreModelError> {
        if bytes.len() > MAX_INLINE_EDIT_BYTES {
            return Err(model_invalid(
                "inline edit",
                format!(
                    "{} bytes exceeds the {MAX_INLINE_EDIT_BYTES}-byte inline limit; \
                     stage the object and reference it",
                    bytes.len()
                ),
            ));
        }
        Ok(Self(bytes))
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Unwraps the bytes.
    #[must_use]
    pub fn into_inner(self) -> ByteString {
        self.0
    }
}

impl Serialize for InlineBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for InlineBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = ByteString::deserialize(deserializer)?;
        Self::new(bytes).map_err(de::Error::custom)
    }
}

impl JsonSchema for InlineBytes {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("InlineBytes")
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let mut schema = generator.subschema_for::<ByteString>();
        schema.insert(
            "description".to_owned(),
            "At most 1 MiB once decoded; larger content is a staged object."
                .to_owned()
                .into(),
        );
        schema
    }
}

/// A reference to bytes uploaded ahead of the request that uses them. The
/// lease keeps the object alive until the request lands or the lease expires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StagedObject {
    pub lease: LeaseId,
    /// Git blob identity of the staged bytes.
    pub oid: Oid,
    pub size: u64,
}

/// Correlates a reply with the raw data frames that carry its bulk bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct StreamId(pub u64);

/// Where a read reply's bytes are: in the frame, or on a stream.
/// Producers must use `Streamed` for any body that would push the
/// reply past [`MAX_CONTROL_FRAME_BYTES`]; the transport layer writes
/// exactly `size` bytes on `stream` after the reply frame, and the
/// caller correlates them by stream id. No served read produces one
/// yet: every served page fits the control bound with room to spare,
/// and the first bulk-body producer owns the delivery half.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ByteSource {
    Inline { data: ByteString },
    Streamed { stream: StreamId, size: u64 },
}

/// Content to write: inline when small, staged when large.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Content {
    Inline { data: InlineBytes },
    Staged { object: StagedObject },
}

// ---------------------------------------------------------------------------
// Text-valued fields
// ---------------------------------------------------------------------------

fn no_nul(text: &str) -> Result<(), FieldError> {
    if text.contains('\0') {
        return Err(FieldError::Nul);
    }
    Ok(())
}

fn no_controls(text: &str) -> Result<(), FieldError> {
    if text.chars().any(char::is_control) {
        return Err(FieldError::Control);
    }
    Ok(())
}

fn remote_name_chars(text: &str) -> Result<(), FieldError> {
    let bad = text
        .chars()
        .find(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')));
    match bad {
        Some(ch) => Err(FieldError::Character(ch)),
        None => Ok(()),
    }
}

const FINGERPRINT_PREFIX: &str = "SHA256:";
const FINGERPRINT_BYTES: usize = 50;

fn fingerprint_shape(text: &str) -> Result<(), FieldError> {
    let Some(body) = text.strip_prefix(FINGERPRINT_PREFIX) else {
        return Err(FieldError::Shape("must start with `SHA256:`"));
    };
    if text.len() != FINGERPRINT_BYTES {
        return Err(FieldError::Shape(
            "must be `SHA256:` plus 43 base64 characters",
        ));
    }
    let bad = body
        .chars()
        .find(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/')));
    match bad {
        Some(ch) => Err(FieldError::Character(ch)),
        None => Ok(()),
    }
}

const SIGNATURE_BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const SIGNATURE_END: &str = "-----END SSH SIGNATURE-----";

fn armored_signature(text: &str) -> Result<(), FieldError> {
    if !text.is_ascii() {
        return Err(FieldError::Shape("must be ASCII armor"));
    }
    if !text.starts_with(SIGNATURE_BEGIN) || !text.trim_end().ends_with(SIGNATURE_END) {
        return Err(FieldError::Shape("must be an armored SSH signature"));
    }
    Ok(())
}

bounded_text! {
    /// A revset expression; parsed and evaluated by the revset engine.
    pub struct RevsetText {
        schema: "RevsetText",
        max: MAX_REVSET_BYTES,
        doc: "Revset expression text: 1..=65536 bytes without NUL.",
        check: no_nul,
    }
}

bounded_text! {
    /// The name of a configured remote.
    pub struct RemoteName {
        schema: "RemoteName",
        max: 128,
        doc: "Remote name: 1..=128 ASCII letters, digits, `.`, `_`, or `-`.",
        check: remote_name_chars,
    }
}

bounded_text! {
    /// An explicit remote location (URL or local path).
    pub struct RemoteUrl {
        schema: "RemoteUrl",
        max: 2048,
        doc: "Remote URL or local path: 1..=2048 bytes without control characters.",
        check: no_controls,
    }
}

bounded_text! {
    /// An SSH key fingerprint in `SHA256:<base64>` form.
    pub struct SignerFingerprint {
        schema: "SignerFingerprint",
        max: FINGERPRINT_BYTES,
        doc: "SSH key fingerprint: `SHA256:` plus 43 base64 characters.",
        check: fingerprint_shape,
    }
}

bounded_text! {
    /// An armored SSH signature over an attestation payload.
    pub struct AttestSignature {
        schema: "AttestSignature",
        max: 8192,
        doc: "Armored SSH signature (namespace `ruk-attest`, ed25519), at most 8192 bytes.",
        check: armored_signature,
    }
}

/// How long a claim lasts: `1..=`[`MAX_CLAIM_TTL_SECONDS`] seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct ClaimTtl(u32);

impl ClaimTtl {
    /// Validates a lifetime in seconds.
    ///
    /// # Errors
    /// Zero, or longer than one hour.
    pub fn new(seconds: u32) -> Result<Self, CoreModelError> {
        if seconds == 0 || seconds > MAX_CLAIM_TTL_SECONDS {
            return Err(model_invalid(
                "claim ttl",
                format!("{seconds} is outside 1..={MAX_CLAIM_TTL_SECONDS} seconds"),
            ));
        }
        Ok(Self(seconds))
    }

    /// The lifetime in seconds.
    #[must_use]
    pub const fn seconds(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for ClaimTtl {
    type Error = CoreModelError;

    fn try_from(seconds: u32) -> Result<Self, Self::Error> {
        Self::new(seconds)
    }
}

impl From<ClaimTtl> for u32 {
    fn from(ttl: ClaimTtl) -> Self {
        ttl.0
    }
}

impl JsonSchema for ClaimTtl {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("ClaimTtl")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "integer",
            "minimum": 1,
            "maximum": MAX_CLAIM_TTL_SECONDS,
            "description": "Claim lifetime in seconds, at most one hour."
        })
    }
}

/// An author or tagger identity a caller supplies. Both fields are refused
/// when they could break a commit header line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IdentityClaim {
    pub name: String,
    pub email: String,
}

/// Where the identity recorded on a new commit came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySource {
    OperationOverride,
    SessionClaim,
    RukConfig,
    GitConfig,
    /// The committer preserved from the rewritten commit: rewrites keep the
    /// original signatures instead of synthesizing new ones.
    Preserved,
}

/// The exact identity an operation recorded, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EffectiveIdentity {
    pub name: String,
    pub email: String,
    pub source: IdentitySource,
}

// ---------------------------------------------------------------------------
// Shared structures
// ---------------------------------------------------------------------------

/// The store and operation snapshot a read was served from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ViewInfo {
    pub store: StoreId,
    pub view: OperationId,
}

/// A workspace and the stamp the caller believes it holds. The lease epoch is
/// checked before the sequence, so a fenced holder learns `E_LEASE_LOST`
/// rather than a misleading `E_STALE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct WorkspaceBinding {
    pub workspace: WorkspaceId,
    pub expected: WorkspaceStamp,
}

/// A native change, optionally pinned to one of its heads. With a head, the
/// head is an expectation (it must still be a current head of the change) and
/// the way to choose among divergent heads. Without one, the change must have
/// exactly one current head or the call fails `E_DIVERGENT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ChangeRef {
    pub change: ChangeId,
    #[serde(default)]
    pub head: Option<Head>,
}

/// A change and the exact head it resolved to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ChangeHead {
    pub change: ChangeId,
    pub head: Head,
}

/// One change's head before and after a rewrite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct HeadRewrite {
    pub change: ChangeId,
    pub old: Head,
    pub new: Head,
}

/// Which paths an operation touches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathSelection {
    /// Every path.
    All,
    /// These paths; each selects itself and everything below it.
    Paths(Vec<RepoPath>),
}

/// A tree to read: a commit, a change, or a workspace's working copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RevisionRef {
    Head { head: Head },
    Change { change: ChangeRef },
    Workspace { workspace: WorkspaceId },
}

/// The merge driver choice for a logical operation. Absent resolves through
/// configuration to `syntax`; the effective mode and language-set version
/// come back on the reply, and one resolved mode applies to the whole
/// rewrite.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct MergeSelection {
    #[serde(default)]
    pub mode: Option<MergeMode>,
}

/// A remote: a configured name or an explicit location.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RemoteSpec {
    Named { name: RemoteName },
    Url { url: RemoteUrl },
}

/// The workspace stamp a mutation produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ResultingStamp {
    pub workspace: WorkspaceId,
    pub stamp: WorkspaceStamp,
}

/// The durable receipt of a mutation. A request that repeats an existing
/// `(session, request_id)` with the same digest is answered from the receipt
/// (`replayed`); a different digest fails `E_REQUEST_REUSED`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptRef {
    pub session: SessionId,
    pub request_id: RequestId,
    pub digest: RequestDigest,
    pub replayed: bool,
    /// Receipts replay their original reply until this instant.
    pub retained_until: Timestamp,
}

/// Something the caller should know that did not fail the operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Warning {
    /// An advise-mode claim held by another session overlaps this write.
    ClaimAdvisory { path: RepoPath, holder: SessionId },
    /// A snapshot of a published head started a new change instead of
    /// rewriting the published one.
    PublishedChangeForked {
        published: ChangeId,
        forked: ChangeId,
    },
    /// A push is uncertain, so this head is held as possibly published.
    PotentiallyPublished { change: ChangeId, head: Head },
}

/// The driver that produced a path's merged content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MergeDriver {
    Text,
    Syntax,
    Union,
    Binary,
}

/// A recorded driver decision for one path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DriverDecision {
    pub driver: MergeDriver,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub grammar_version: Option<String>,
}

/// Who wrote a path and how its content was merged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PathProvenance {
    pub path: RepoPath,
    pub session: SessionId,
    #[serde(default)]
    pub driver: Option<DriverDecision>,
}

/// The common header of every mutation reply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MutationOutcome {
    pub receipt: ReceiptRef,
    /// The operation that recorded the mutation. Absent when no operation-tracked
    /// state changed.
    pub operation: Option<OperationId>,
    pub heads: BoundedList<ChangeHead>,
    pub stamps: BoundedList<ResultingStamp>,
    pub warnings: BoundedList<Warning>,
    /// Effective merge mode, language-set version, and structured notices for
    /// any operation that merged content.
    pub merge: Option<MergeReport>,
    pub provenance: BoundedList<PathProvenance>,
    /// The identity recorded on any commit the operation created.
    pub identity: Option<EffectiveIdentity>,
}

/// A mutation request: its idempotency key half and its typed arguments. The
/// digest covers `args` (including every expected stamp) and never
/// `request_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Mutation<T> {
    pub request_id: RequestId,
    pub args: T,
}

// ---------------------------------------------------------------------------
// Session and schema methods
// ---------------------------------------------------------------------------

/// `session.open`: authenticates the caller's OS or service principal (the
/// request names no principal) and negotiates capabilities.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionOpenArgs {
    #[serde(default)]
    pub identity: Option<IdentityClaim>,
    #[serde(default)]
    pub claims: ProvenanceClaims,
    /// The subset wanted; absent asks for the principal's whole policy. A
    /// request beyond the policy fails `E_FORBIDDEN`.
    #[serde(default)]
    pub capabilities: Option<Capabilities>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionOpenReply {
    pub session: SessionId,
    pub reconnect_secret: ReconnectSecret,
    /// The authenticated principal, as determined by the server.
    pub principal: String,
    pub capabilities: Capabilities,
    pub idle_expires_at: Timestamp,
}

/// `session.resume`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionResumeArgs {
    pub session: SessionId,
    pub reconnect_secret: ReconnectSecret,
}

/// What a resumed session may still do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionAuthority {
    /// Full authority until the idle expiry.
    Active { idle_expires_at: Timestamp },
    /// Write authority has expired; receipt lookup remains until the horizon.
    ReceiptsOnly { receipts_until: Timestamp },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionResumeReply {
    pub session: SessionId,
    pub authority: SessionAuthority,
    pub capabilities: Capabilities,
}

/// How a method is invoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MethodKind {
    /// Callable with or without a session.
    Anonymous,
    /// Establishes a session; must not carry one.
    Bootstrap,
    /// Requires a session; never mutates (except an autosnapshot of a
    /// workspace named in the request).
    Read,
    /// Requires a session; carries a request id and a receipt.
    Mutation,
    /// Dispatched before any coordinator call and gated by the daemon's
    /// `admin_uids`; takes no session and no receipt.
    Admin,
}

/// `schema`: the versioned schemas of the protocol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SchemaArgs {
    /// Restrict the document to one method; absent returns the whole model.
    #[serde(default)]
    pub method: Option<Method>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MethodDescriptor {
    pub method: Method,
    pub kind: MethodKind,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SchemaReply {
    pub schema_version: SchemaVersion,
    pub methods: Vec<MethodDescriptor>,
    pub document: Schema,
}

// ---------------------------------------------------------------------------
// Workspace methods
// ---------------------------------------------------------------------------

/// The kind and starting point of a new workspace. The kind is fixed for the
/// workspace's lifetime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceInit {
    /// A native workspace on a new current change over `parents`. No parents
    /// is a root change.
    Native { parents: Vec<Head> },
    /// A Git-compatible workspace with this HEAD (an unborn symbolic HEAD is
    /// allowed).
    GitCompat { head: HeadRef },
}

/// `ws.new`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsNewArgs {
    /// Host directory to materialize into.
    pub root: ByteString,
    pub init: WorkspaceInit,
    /// The cone scope; absent means the full tree.
    #[serde(default)]
    pub scope: Option<Scope>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsNewReply {
    pub outcome: MutationOutcome,
    pub workspace: WorkspaceId,
    pub state: WorkspaceState,
}

/// `ws.scope`: replaces the scope with the full new value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsScopeArgs {
    pub binding: WorkspaceBinding,
    pub scope: Scope,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsScopeReply {
    pub outcome: MutationOutcome,
    pub state: WorkspaceState,
}

/// `ws.take`: fences the current holder by advancing the lease epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsTakeArgs {
    pub workspace: WorkspaceId,
    /// When present the take only succeeds from exactly this stamp; absent
    /// seizes the workspace from whoever holds it.
    #[serde(default)]
    pub expected: Option<WorkspaceStamp>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsTakeReply {
    pub outcome: MutationOutcome,
    pub state: WorkspaceState,
}

/// `ws.drop`: unregisters the workspace; user files are never deleted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsDropArgs {
    pub binding: WorkspaceBinding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsDropReply {
    pub outcome: MutationOutcome,
}

/// How to finish an interrupted materialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecoverAction {
    /// Apply the remaining transitions to the recorded target.
    Resume,
    /// Restore paths still matching the target or preimage; keep external
    /// edits and report them as unresolved.
    Abort,
    /// Explicitly overwrite these externally changed paths.
    Discard { paths: Vec<RepoPath> },
}

/// `ws.recover`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsRecoverArgs {
    pub binding: WorkspaceBinding,
    pub action: RecoverAction,
}

/// What recovery did with one path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecoverDisposition {
    Completed,
    Restored,
    PreservedExternal,
    Unresolved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecoverPath {
    pub path: RepoPath,
    pub disposition: RecoverDisposition,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WsRecoverReply {
    pub outcome: MutationOutcome,
    pub state: WorkspaceState,
    pub paths: BoundedList<RecoverPath>,
}

// ---------------------------------------------------------------------------
// Working-copy methods
// ---------------------------------------------------------------------------

/// `snapshot`: records the workspace's current content as its change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotArgs {
    pub binding: WorkspaceBinding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotReply {
    pub outcome: MutationOutcome,
    pub change: ChangeHead,
    /// Paths whose content differed; zero means no operation was recorded.
    pub changed_paths: u64,
    pub state: WorkspaceState,
}

/// What one explicit edit does to its path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EditAction {
    /// Create or replace a file with this content.
    Put {
        content: Content,
        #[serde(default)]
        executable: bool,
    },
    /// Create or replace a symbolic link.
    Symlink { target: ByteString },
    /// Remove the file or link at this path.
    Delete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WriteEdit {
    pub path: RepoPath,
    pub action: EditAction,
}

/// `write`: one atomic change from explicit edits. Inline content is at most
/// 1 MiB per edit; larger content is staged and referenced. A path is never
/// split across edits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WriteArgs {
    pub binding: WorkspaceBinding,
    pub edits: Vec<WriteEdit>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WriteReply {
    pub outcome: MutationOutcome,
    pub change: ChangeHead,
    pub applied: u64,
    pub state: WorkspaceState,
}

// ---------------------------------------------------------------------------
// Change methods
// ---------------------------------------------------------------------------

/// `new`: creates one native change on the supplied parents (none is a root
/// change; conflicted and merge parents are allowed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NewArgs {
    pub parents: Vec<Head>,
    pub description: ByteString,
    #[serde(default)]
    pub identity: Option<IdentityClaim>,
    /// When present, the workspace switches to the new change.
    #[serde(default)]
    pub workspace: Option<WorkspaceBinding>,
}

/// `git.commit`: records one concrete commit with a caller-staged tree and
/// caller-supplied identities, plus one branch move applied atomically on
/// the lane. Unlike `new` (which mints an empty-tree change), every commit
/// input arrives stored and validated; the lane stages nothing but the
/// commit object itself.
///
/// A retried submission whose commit already landed and whose ref already
/// holds it skips the ref transaction, so the lane replays the stored reply
/// (same session, same request id) or succeeds idempotently instead of
/// failing its own compare-and-swap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GitCommitArgs {
    pub tree: Oid,
    pub parents: Vec<Head>,
    pub author: Signature,
    pub committer: Signature,
    pub message: ByteString,
    /// Change to extend, when the caller resolved one. Absent keeps the
    /// stable by-OID mapping, exactly like `ops::prepare_new` with no id.
    #[serde(default)]
    pub change_id: Option<ChangeId>,
    /// The earlier head this commit rewrites for an amend-style rewrite.
    /// `prepare_new` requires it to be a current head of `change_id`.
    #[serde(default)]
    pub predecessor: Option<Head>,
    /// Branch move to apply atomically with the commit. Absent leaves refs
    /// alone; detached-HEAD advances have no producer on this path.
    #[serde(default)]
    pub ref_update: Option<GitCommitRefUpdate>,
}

/// One branch move bundled with a `git.commit`: the ref, the target the
/// caller saw, and a `Set` to the created commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GitCommitRefUpdate {
    pub name: RefName,
    pub expected: RefExpect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NewReply {
    pub outcome: MutationOutcome,
    pub created: ChangeHead,
    pub state: Option<WorkspaceState>,
}

/// The reply shared by methods that rewrite changes and re-derive their
/// descendants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RewriteReply {
    pub outcome: MutationOutcome,
    pub rewrites: BoundedList<HeadRewrite>,
    pub abandoned: BoundedList<ChangeId>,
    /// Changes whose rewritten head is conflicted.
    pub conflicted: BoundedList<ChangeHead>,
}

/// `describe`: rewrites a change's description.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DescribeArgs {
    pub target: ChangeRef,
    pub description: ByteString,
    #[serde(default)]
    pub identity: Option<IdentityClaim>,
    /// Workspaces whose checked-out change may be rewritten, with the stamps
    /// the caller expects.
    #[serde(default)]
    pub workspaces: Vec<WorkspaceBinding>,
}

/// `edit`: checks a change out into a workspace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EditArgs {
    pub binding: WorkspaceBinding,
    pub target: ChangeRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EditReply {
    pub outcome: MutationOutcome,
    pub state: WorkspaceState,
}

/// Where the selected paths of a `split` go.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SplitPlacement {
    /// The selected paths become a new parent of the remainder.
    SelectedFirst,
    /// The selected paths become a new child of the remainder.
    SelectedSecond,
}

/// `split`: partitions one change into two. The unselected remainder keeps the
/// source change's identity; the selection becomes a new change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SplitArgs {
    pub source: ChangeRef,
    /// Must name paths; `all` would leave nothing to split.
    pub paths: PathSelection,
    pub placement: SplitPlacement,
    /// Description of the new change.
    pub description: ByteString,
    #[serde(default)]
    pub identity: Option<IdentityClaim>,
    #[serde(default)]
    pub merge: MergeSelection,
    #[serde(default)]
    pub workspaces: Vec<WorkspaceBinding>,
}

/// `squash`: moves selected path changes from `source` into `destination`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SquashArgs {
    pub source: ChangeRef,
    pub destination: ChangeRef,
    pub paths: PathSelection,
    /// New description for the destination; absent keeps it.
    #[serde(default)]
    pub description: Option<ByteString>,
    /// Keep the source change even if it ends up empty.
    #[serde(default)]
    pub keep_empty: bool,
    #[serde(default)]
    pub identity: Option<IdentityClaim>,
    #[serde(default)]
    pub merge: MergeSelection,
    #[serde(default)]
    pub workspaces: Vec<WorkspaceBinding>,
}

/// Which changes a `rebase` moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RebaseScope {
    /// Each source and all of its descendants.
    SourceAndDescendants,
    /// Only the sources; their descendants are re-parented onto the sources'
    /// old parents.
    RevisionsOnly,
}

/// `rebase`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RebaseArgs {
    pub sources: Vec<ChangeRef>,
    pub scope: RebaseScope,
    /// The new parents; at least one.
    pub onto: Vec<Head>,
    #[serde(default)]
    pub merge: MergeSelection,
    /// Keep changes that become empty.
    #[serde(default)]
    pub keep_empty: bool,
    #[serde(default)]
    pub workspaces: Vec<WorkspaceBinding>,
}

/// `abandon`: removes changes from active state; descendants are re-parented.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AbandonArgs {
    pub targets: Vec<ChangeRef>,
    #[serde(default)]
    pub merge: MergeSelection,
    #[serde(default)]
    pub workspaces: Vec<WorkspaceBinding>,
}

/// How one conflicted path is resolved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// Explicit content.
    Supplied {
        content: Content,
        #[serde(default)]
        executable: bool,
    },
    /// Take one side: the zero-based index among the conflict's add terms.
    Side { index: u32 },
    /// Collapse sides that made the same change (the one opt-in lossy
    /// collapse).
    AcceptSame,
}

/// `resolve`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolveArgs {
    pub target: ChangeRef,
    pub path: RepoPath,
    pub resolution: Resolution,
    #[serde(default)]
    pub workspaces: Vec<WorkspaceBinding>,
}

/// A path that is still conflicted after a resolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RemainingConflict {
    pub path: RepoPath,
    /// Number of terms in the conflict (odd).
    pub terms: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolveReply {
    pub outcome: MutationOutcome,
    pub change: ChangeHead,
    pub remaining: BoundedList<RemainingConflict>,
}

/// `revert`: a new change applying the reverse of `target`'s delta.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RevertArgs {
    pub target: ChangeRef,
    /// Parents of the new change; at least one.
    pub onto: Vec<Head>,
    /// For a merge commit: the one-based parent whose side is kept.
    #[serde(default)]
    pub mainline: Option<NonZeroU32>,
    #[serde(default)]
    pub description: Option<ByteString>,
    #[serde(default)]
    pub identity: Option<IdentityClaim>,
    #[serde(default)]
    pub merge: MergeSelection,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RevertReply {
    pub outcome: MutationOutcome,
    pub created: ChangeHead,
}

// ---------------------------------------------------------------------------
// Bookmarks and tags
// ---------------------------------------------------------------------------

/// What a bookmark points at. A conflicted head cannot become a Git ref.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BookmarkTarget {
    Commit { oid: Oid },
    Change { change: ChangeRef },
}

/// `bookmark.set`: `name` is a full `refs/heads/` ref name. `expected` is the
/// old value the update is conditional on (`Absent` to create); an
/// unconditional `Any` is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BookmarkSetArgs {
    pub name: RefName,
    pub target: BookmarkTarget,
    pub expected: RefExpect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BookmarkSetReply {
    pub outcome: MutationOutcome,
    pub name: RefName,
    pub target: Oid,
}

/// `bookmark.delete`: `expected` must be `Present`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BookmarkDeleteArgs {
    pub name: RefName,
    pub expected: RefExpect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BookmarkDeleteReply {
    pub outcome: MutationOutcome,
}

/// The decision that resolves a conflicted native bookmark.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BookmarkResolution {
    Set { oid: Oid },
    Delete,
}

/// `bookmark.resolve`: `expected_terms` are the conflict terms the caller
/// saw; the resolution publishes a ref and removes the conflict atomically.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BookmarkResolveArgs {
    pub name: RefName,
    pub expected_terms: Merge<Option<Oid>>,
    pub resolution: BookmarkResolution,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BookmarkResolveReply {
    pub outcome: MutationOutcome,
}

/// An annotated tag's message and optional tagger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TagAnnotation {
    #[serde(default)]
    pub tagger: Option<IdentityClaim>,
    pub message: ByteString,
}

/// `tag.set`: `name` is a full `refs/tags/` ref name. With an annotation the
/// tag is a real Git tag object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TagSetArgs {
    pub name: RefName,
    pub target: Oid,
    #[serde(default)]
    pub annotation: Option<TagAnnotation>,
    pub expected: RefExpect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TagSetReply {
    pub outcome: MutationOutcome,
    pub name: RefName,
    /// The ref's new value (the tag object for an annotated tag).
    pub target: RefTarget,
}

/// `tag.delete`: `expected` must be `Present`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TagDeleteArgs {
    pub name: RefName,
    pub expected: RefExpect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TagDeleteReply {
    pub outcome: MutationOutcome,
}

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

/// Whether an overlapping write fails or only warns.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimMode {
    /// Overlapping writes by other sessions fail `E_CLAIMED`.
    #[default]
    Enforce,
    /// Overlapping writes succeed with a warning.
    Advise,
}

/// `claim.acquire`: each path claims itself and everything below it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClaimAcquireArgs {
    pub paths: Vec<RepoPath>,
    pub ttl: ClaimTtl,
    #[serde(default)]
    pub mode: ClaimMode,
}

/// A held claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClaimRecord {
    pub claim: ClaimId,
    pub holder: SessionId,
    pub paths: Vec<RepoPath>,
    pub mode: ClaimMode,
    pub expires_at: Timestamp,
    /// Provenance the acquiring invocation declared; never an
    /// authorization input.
    #[serde(default)]
    pub on_behalf_of: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClaimAcquireReply {
    pub outcome: MutationOutcome,
    pub claim: ClaimRecord,
}

/// `claim.release`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClaimReleaseArgs {
    pub claim: ClaimId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClaimReleaseReply {
    pub outcome: MutationOutcome,
    pub released: ClaimRecord,
}

/// Whose claims to list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClaimHolderFilter {
    /// This session's claims.
    #[default]
    Mine,
    /// Every session's claims; needs `read_intents.claims`.
    Any,
}

/// `claim.list`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClaimListArgs {
    #[serde(default)]
    pub holder: ClaimHolderFilter,
    #[serde(default)]
    pub page: PageRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClaimListReply {
    pub view: ViewInfo,
    pub claims: Page<ClaimRecord>,
}

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

/// What a signer attests about one exact object.
///
/// `evidence` is appended last so the postcard encoding of every earlier
/// field is unchanged; stored v1 rows decode through the versioned fallback
/// in `attestation::rows`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AttestStatement {
    pub subject: Oid,
    pub kind: AttestKind,
    pub result: AttestResult,
    /// A claim, never an ordering authority.
    pub signed_at: Timestamp,
    /// The earlier statement this one explicitly supersedes.
    #[serde(default)]
    pub supersedes: Option<StatementDigest>,
    /// The SHA-256 of an external blob this statement binds, such as a CI
    /// log. `None` and `Some(zero)` differ on the wire: absence encodes as an
    /// empty field, presence as exactly 32 bytes.
    #[serde(default)]
    pub evidence: Option<StatementDigest>,
}

/// `attest.add`: the signature is over [`AttestStatement::canonical_payload_v2`]
/// in namespace `ruk-attest`; private keys never reach the coordinator.
/// Statements without evidence signed over
/// [`AttestStatement::canonical_payload_v1`] stay verifiable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AttestAddArgs {
    pub statement: AttestStatement,
    pub signature: AttestSignature,
}

/// Whether a verified statement currently counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Live,
    Superseded,
    /// The same signer has conflicting live results for the same kind.
    Ambiguous,
}

/// A verified, stored attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AttestationRecord {
    pub subject: Oid,
    pub kind: AttestKind,
    pub result: AttestResult,
    pub signer: SignerFingerprint,
    pub payload_digest: StatementDigest,
    pub signed_at: Timestamp,
    pub supersedes: Option<StatementDigest>,
    pub status: AttestationStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AttestAddReply {
    pub outcome: MutationOutcome,
    pub record: AttestationRecord,
}

/// `attest.list`.
///
/// `kind` selects one exact kind; `kind_prefix` selects every kind starting
/// with the prefix, for CI dashboards scanning `ci/` verdicts. Both set
/// filters combine: a statement matches when its kind equals `kind` and
/// starts with `kind_prefix`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AttestListArgs {
    #[serde(default)]
    pub subject: Option<Oid>,
    #[serde(default)]
    pub kind: Option<AttestKind>,
    #[serde(default)]
    pub signer: Option<SignerFingerprint>,
    #[serde(default)]
    pub include_superseded: bool,
    #[serde(default)]
    pub page: PageRequest,
    /// Only kinds starting with this prefix. Appended last so the postcard
    /// encoding of every earlier field is unchanged; the field is optional,
    /// so older JSON without it decodes to no prefix filter.
    #[serde(default)]
    pub kind_prefix: Option<AttestKind>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AttestListReply {
    pub view: ViewInfo,
    pub records: Page<AttestationRecord>,
}

// ---------------------------------------------------------------------------
// Transport and publication
// ---------------------------------------------------------------------------

/// Which remote refs a fetch brings in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FetchRefs {
    AllBranches,
    Patterns(Vec<RefPattern>),
}

/// Which objects a fetch transfers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FetchFilter {
    /// Omit blobs (`blob:none`); the native default.
    #[default]
    BlobNone,
    Full,
}

/// `fetch`: stages verified objects, then publishes the requested ref and
/// tracking deltas atomically.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FetchArgs {
    pub remote: RemoteSpec,
    pub refs: FetchRefs,
    #[serde(default)]
    pub depth: Option<NonZeroU32>,
    #[serde(default)]
    pub filter: FetchFilter,
}

/// One ref's movement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RefDelta {
    pub name: RefName,
    pub old: Option<RefTarget>,
    pub new: Option<RefTarget>,
}

/// A bookmark left unresolved by a three-way tracking merge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RefConflictNote {
    pub name: RefName,
    pub terms: Merge<Option<Oid>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FetchReply {
    pub outcome: MutationOutcome,
    pub updates: BoundedList<RefDelta>,
    pub conflicts: BoundedList<RefConflictNote>,
    /// The store now has shallow boundaries.
    pub shallow: bool,
}

/// The remote value a push update is conditional on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RemoteExpect {
    /// The ref must not exist.
    Absent,
    /// The ref must currently be this object.
    Present { oid: Oid },
}

/// What a push update sends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PushSource {
    Commit { oid: Oid },
    Change { change: ChangeRef },
    Delete,
}

/// One remote ref update. Forcing a non-fast-forward still compares the
/// remote's advertised old value; `expected_old` absent means that advertised
/// value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PushUpdate {
    pub remote_ref: RefName,
    pub source: PushSource,
    #[serde(default)]
    pub expected_old: Option<RemoteExpect>,
    #[serde(default)]
    pub force: bool,
}

/// Whether the remote applies the updates all-or-nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PushAtomicity {
    #[default]
    Atomic,
    NonAtomic,
}

/// `push`: persists a `Prepared` plan, then sends. A crash after
/// transmission could have begun leaves the plan `Uncertain`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PushArgs {
    pub remote: RemoteSpec,
    pub updates: Vec<PushUpdate>,
    #[serde(default)]
    pub atomicity: PushAtomicity,
}

/// A push plan's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PushState {
    Prepared,
    Sending,
    Confirmed,
    Rejected,
    Uncertain,
}

/// The outcome of one pushed ref.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PushRefStatus {
    /// The remote applied the update; `new` is absent for a deletion.
    Confirmed {
        new: Option<Oid>,
    },
    Rejected {
        reason: String,
    },
    Uncertain,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PushRefOutcome {
    pub remote_ref: RefName,
    pub status: PushRefStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PushReply {
    pub outcome: MutationOutcome,
    pub plan: PlanId,
    pub state: PushState,
    pub refs: BoundedList<PushRefOutcome>,
}

/// `push.reconcile`: observes the remote's current refs for an uncertain plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PushReconcileArgs {
    pub plan: PlanId,
}

/// What observation found for one ref; observation is not causal proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileVerdict {
    EqualNew,
    EqualOld,
    Moved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReconcileObservation {
    pub remote_ref: RefName,
    /// The remote's current value; absent when the ref does not exist.
    pub observed: Option<Oid>,
    pub verdict: ReconcileVerdict,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PushReconcileReply {
    pub outcome: MutationOutcome,
    pub plan: PlanId,
    pub state: PushState,
    pub observations: BoundedList<ReconcileObservation>,
}

/// `land.prepare`: freezes an exact candidate; it never moves a ref.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LandPrepareArgs {
    pub change: ChangeRef,
    /// Where to push the landed candidate; absent means this store.
    /// A present remote refuses: the transport push leg is not served yet.
    #[serde(default)]
    pub remote: Option<RemoteSpec>,
    /// The target ref to land onto, e.g. `refs/heads/main`.
    pub target: RefName,
    #[serde(default)]
    pub merge: MergeSelection,
}

/// An attestation the land policy requires before execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AttestRequirement {
    pub kind: AttestKind,
    pub result: AttestResult,
    /// The latest `signed_at` this requirement accepts; absent never
    /// expires. A later-signed match reports `Gap::Expired`.
    #[serde(default)]
    pub valid_until: Option<Timestamp>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LandPrepareReply {
    pub outcome: MutationOutcome,
    pub plan: PlanId,
    /// The exact commit that will be pushed.
    pub candidate: Oid,
    /// The target tip the candidate was rebased onto.
    pub base: Oid,
    /// Plans expire after one hour unless executed.
    pub expires_at: Timestamp,
    pub policy_generation: u64,
    /// What must be signed for the candidate before `land.execute`.
    pub requirements: Vec<AttestRequirement>,
}

/// `land.execute`: pushes the stored candidate bytes; never rebuilds one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LandExecuteArgs {
    pub plan: PlanId,
    /// The exact candidate the caller reviewed and attested; a mismatch with
    /// the stored plan fails `E_STALE`.
    pub candidate: Oid,
}

/// The local state after a remote landing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LandLocalState {
    /// Local state was published.
    Published,
    /// The remote landed, but later local changes conflict with recording it.
    /// The confirmed remote result is reported, not lost or retried.
    ConflictingLocalChange,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LandExecuteReply {
    pub outcome: MutationOutcome,
    pub plan: PlanId,
    pub remote: PushRefOutcome,
    pub local: LandLocalState,
}

// ---------------------------------------------------------------------------
// Operation log, pins
// ---------------------------------------------------------------------------

/// `undo`: appends the inverse of `operation`, all-or-nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UndoArgs {
    pub operation: OperationId,
}

/// How many keys an undo restored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UndoSummary {
    pub refs: u64,
    pub changes: u64,
    pub workspaces: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UndoReply {
    pub outcome: MutationOutcome,
    pub undone: OperationId,
    pub restored: UndoSummary,
}

/// `op.log`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OpLogArgs {
    /// Only operations by this session.
    #[serde(default)]
    pub session: Option<SessionId>,
    /// Paging state; absent starts at the newest operation.
    #[serde(default)]
    pub page: PageRequest,
    /// Ascending cursor: only operations strictly after this id, oldest
    /// first. Absent keeps the newest-first walk.
    #[serde(default)]
    pub after: Option<OperationId>,
}

/// One ref moved by an operation: the ref name plus its before and after
/// targets. Recorded for lane (op-sourced) mutations from the operation's
/// own ref deltas, so orchestration readers need no stream walk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OpRefDelta {
    pub name: RefName,
    pub before: Option<RefTarget>,
    pub after: Option<RefTarget>,
}

/// One attestation an operation recorded: the attested kind and subject.
/// Recorded for lane (op-sourced) mutations from the operation's own
/// attestation rows, so proof lists read subjects without a stream walk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OpAttestationSubject {
    pub kind: AttestKind,
    pub subject: Oid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OperationEntry {
    pub id: OperationId,
    pub parent: Option<OperationId>,
    pub session: Option<SessionId>,
    pub method: Method,
    pub committed_at: Timestamp,
    /// The operation this one inverts, if it is an undo.
    pub undoes: Option<OperationId>,
    /// Provenance the invoking call declared; never an authorization input.
    #[serde(default)]
    pub on_behalf_of: Option<String>,
    /// Per-op ref deltas, in delta order within the operation.
    #[serde(default)]
    pub ref_deltas: Vec<OpRefDelta>,
    /// Attested (kind, subject) pairs this operation recorded, deduplicated.
    #[serde(default)]
    pub attestation_subjects: Vec<OpAttestationSubject>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OpLogReply {
    pub view: ViewInfo,
    /// The oldest operation still retained; older ones were pruned.
    pub oldest_retained: Option<OperationId>,
    pub entries: Page<OperationEntry>,
}

/// `op.prune`: applies the repository's retention policy; there is no
/// separate per-call policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OpPruneArgs {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OpPruneReply {
    pub outcome: MutationOutcome,
    pub pruned: u64,
    pub oldest_retained: Option<OperationId>,
}

/// `pin`: an explicit garbage-collection root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PinArgs {
    pub head: Head,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PinReply {
    pub outcome: MutationOutcome,
}

/// `unpin`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UnpinArgs {
    pub head: Head,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UnpinReply {
    pub outcome: MutationOutcome,
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// Whether a workspace read snapshots first.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotPolicy {
    /// Snapshot a native workspace before reading (the default).
    #[default]
    Auto,
    /// Read without snapshotting (`--no-snapshot`).
    Skip,
}

/// `status`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StatusArgs {
    #[serde(default)]
    pub workspace: Option<WorkspaceId>,
    #[serde(default)]
    pub snapshot: SnapshotPolicy,
    #[serde(default)]
    pub page: PageRequest,
}

/// How a path differs from its parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathChangeKind {
    Added,
    Modified,
    Deleted,
    ModeChanged,
    TypeChanged,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PathStatus {
    pub path: RepoPath,
    pub change: PathChangeKind,
    pub conflicted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StatusReply {
    pub view: ViewInfo,
    pub workspace: Option<WorkspaceState>,
    pub change: Option<ChangeHead>,
    /// A materialization is in progress: the directory is not a complete
    /// snapshot.
    pub applying: bool,
    /// The operation of the autosnapshot this read performed, if any.
    pub snapshot_operation: Option<OperationId>,
    pub paths: Page<PathStatus>,
}

/// `log`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LogArgs {
    pub revset: RevsetText,
    #[serde(default)]
    pub page: PageRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CommitSummary {
    pub change: Option<ChangeId>,
    pub head: Head,
    pub parents: Vec<Head>,
    pub author: Signature,
    pub committer: Signature,
    /// First line of the message.
    pub subject: ByteString,
    pub conflicted: bool,
    pub divergent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LogReply {
    pub view: ViewInfo,
    pub entries: Page<CommitSummary>,
}

/// `query`: evaluates a revset to changes. An ambiguous prefix is an error
/// with candidates, never an arbitrary pick.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueryArgs {
    pub revset: RevsetText,
    #[serde(default)]
    pub page: PageRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueryMatch {
    pub change: ChangeId,
    /// More than one head means the change is divergent.
    pub heads: Vec<Head>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueryReply {
    pub view: ViewInfo,
    pub matches: Page<QueryMatch>,
}

/// `diff`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DiffArgs {
    pub left: RevisionRef,
    pub right: RevisionRef,
    pub paths: PathSelection,
    #[serde(default)]
    pub page: PageRequest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    Added,
    Deleted,
    Modified,
    Renamed,
}

/// One side of a file diff.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DiffBlob {
    pub oid: Oid,
    pub executable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiffBody {
    Unified { patch: ByteSource },
    Binary,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileDiff {
    pub path: RepoPath,
    pub old_path: Option<RepoPath>,
    pub kind: DiffKind,
    pub old: Option<DiffBlob>,
    pub new: Option<DiffBlob>,
    pub conflicted: bool,
    pub body: DiffBody,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DiffReply {
    pub view: ViewInfo,
    pub files: Page<FileDiff>,
}

/// What `show` looks at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShowTarget {
    Head { head: Head },
    Change { change: ChangeRef },
    Object { oid: Oid },
}

/// `show`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShowArgs {
    pub target: ShowTarget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Blob,
    Tree,
    Commit,
    Tag,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShowBody {
    Commit {
        change: Option<ChangeId>,
        head: Head,
        record: Box<CommitRecord>,
    },
    Object {
        oid: Oid,
        kind: ObjectKind,
        size: u64,
        content: ByteSource,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShowReply {
    pub view: ViewInfo,
    pub body: ShowBody,
}

/// What a tree entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Tree,
    Regular,
    Executable,
    Symlink,
    Gitlink,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TreeEntry {
    /// A single path component.
    pub name: ByteString,
    pub oid: Oid,
    pub kind: EntryKind,
    /// Stored object length for blobs; absent for trees and gitlinks.
    #[serde(default)]
    pub size: Option<u64>,
}

/// One side of a conflicted file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileTerm {
    pub oid: Oid,
    pub executable: bool,
}

/// `file`: a file, link, gitlink, directory listing, or conflict at a path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileArgs {
    pub at: RevisionRef,
    /// The path to read; absent is the root directory.
    #[serde(default)]
    pub path: Option<RepoPath>,
    /// Paging for a directory listing.
    #[serde(default)]
    pub page: PageRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileBody {
    Blob {
        oid: Oid,
        executable: bool,
        size: u64,
        content: ByteSource,
    },
    Symlink {
        target: ByteString,
    },
    Gitlink {
        commit: Oid,
    },
    Directory {
        entries: Page<TreeEntry>,
    },
    /// The path is conflicted; the terms are the original algebra, not a
    /// marker rendering.
    Conflict {
        terms: Merge<Option<FileTerm>>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileReply {
    pub view: ViewInfo,
    pub body: FileBody,
}

/// A one-based inclusive line range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LineRange {
    pub start: u32,
    pub end: u32,
}

/// `blame`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BlameArgs {
    pub at: RevisionRef,
    pub path: RepoPath,
    #[serde(default)]
    pub lines: Option<LineRange>,
    #[serde(default)]
    pub page: PageRequest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BlameHunk {
    pub start_line: u32,
    pub line_count: u32,
    pub head: Head,
    pub change: Option<ChangeId>,
    pub original_path: RepoPath,
    pub author: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BlameReply {
    pub view: ViewInfo,
    pub hunks: Page<BlameHunk>,
}

// ---------------------------------------------------------------------------
// Errors on the wire
// ---------------------------------------------------------------------------

/// A machine-readable remedy attached to an error. Callers act on these, never
/// on message text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Fix {
    /// Re-read the state and retry with fresh expected stamps and a new
    /// request id.
    RefreshExpected { workspace: Option<WorkspaceId> },
    /// Take the workspace (advancing its lease epoch) before mutating it.
    TakeWorkspace { workspace: WorkspaceId },
    /// The request id was used with different arguments; use a new one.
    NewRequestId,
    /// Finish or abort the interrupted materialization first.
    RecoverWorkspace { workspace: WorkspaceId },
    /// Reconcile the uncertain push plan before publishing again.
    ReconcilePush { plan: PlanId },
    /// The change is divergent; name one of its heads.
    SelectHead { change: ChangeId, heads: Vec<Head> },
    /// Resolve the conflicts first.
    ResolveConflicts { change: ChangeId },
    /// The cursor's view or lease expired; restart the query.
    RestartQuery,
    /// The prepared plan is stale; prepare a new one.
    PrepareLandAgain,
    /// Fetch the missing objects, then retry.
    FetchObjects,
    /// A claim blocks the write until this instant.
    WaitUntil { until: Timestamp },
}

/// Structured data attached to an error whose outcome the caller needs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorDetail {
    /// A rejected or uncertain push: the durable plan and per-ref outcomes.
    Push {
        plan: PlanId,
        state: PushState,
        refs: BoundedList<PushRefOutcome>,
    },
}

/// The error body of a failed request. Callers branch on `code`.
///
/// The daemon's IPC `Error` frame carries this body. The trailing fields
/// default so a payload written before they existed still decodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ErrorReply {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default)]
    pub hints: Vec<String>,
    #[serde(default)]
    pub fixes: Vec<Fix>,
    #[serde(default)]
    pub detail: Option<ErrorDetail>,
}

impl ErrorReply {
    /// The wire form of a core error, with no fixes or detail attached.
    #[must_use]
    pub fn from_core(error: &CoreError) -> Self {
        Self {
            code: error.code,
            message: error.message.clone(),
            hints: error.hints.clone(),
            fixes: Vec::new(),
            detail: None,
        }
    }

    /// Adds a machine-readable fix.
    #[must_use]
    pub fn with_fix(mut self, fix: Fix) -> Self {
        self.fixes.push(fix);
        self
    }

    /// Attaches structured detail.
    #[must_use]
    pub fn with_detail(mut self, detail: ErrorDetail) -> Self {
        self.detail = Some(detail);
        self
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Cross-field invariants of a request that its types cannot express.
pub trait Validate {
    /// Checks the invariants.
    ///
    /// # Errors
    /// `E_INVALID` naming the violated invariant.
    fn validate(&self) -> Result<(), CoreError> {
        Ok(())
    }
}

/// Implements [`Validate`] with no extra invariants.
macro_rules! no_invariants {
    ($($ty:ty),+ $(,)?) => {
        $(impl Validate for $ty {})+
    };
}

impl<T> Validate for KeysetPage<T> {}

no_invariants!(
    SchemaArgs,
    CommitRev,
    RepoStatArgs,
    TreeArgs,
    RefsListArgs,
    CompareArgs,
    ArchiveArgs,
    RemoteRefsArgs,
    ClaimRenewArgs,
    PolicySetArgs,
    SessionResumeArgs,
    WsScopeArgs,
    WsTakeArgs,
    WsDropArgs,
    SnapshotArgs,
    EditArgs,
    ClaimReleaseArgs,
    PushReconcileArgs,
    LandPrepareArgs,
    LandExecuteArgs,
    UndoArgs,
    OpPruneArgs,
    PinArgs,
    UnpinArgs,
    ShowArgs,
    AttestAddArgs,
);

fn show_bytes(bytes: &[u8]) -> String {
    bytes.escape_ascii().to_string()
}

fn require_nonempty<T>(what: &str, items: &[T]) -> Result<(), CoreError> {
    if items.is_empty() {
        return Err(invalid(format!("{what} must not be empty")));
    }
    Ok(())
}

fn require_unique<'a, T, I>(what: &str, items: I) -> Result<(), CoreError>
where
    T: Hash + Eq + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let mut seen = HashSet::new();
    for item in items {
        if !seen.insert(item) {
            return Err(invalid(format!("duplicate {what}")));
        }
    }
    Ok(())
}

fn require_namespace(what: &str, name: &RefName, prefix: &[u8]) -> Result<(), CoreError> {
    if name.as_bytes().starts_with(prefix) {
        return Ok(());
    }
    Err(invalid(format!(
        "{what} must name a ref under `{}`, got `{}`",
        show_bytes(prefix),
        show_bytes(name.as_bytes())
    )))
}

fn reject_unconditional(what: &str, expected: &RefExpect) -> Result<(), CoreError> {
    if matches!(expected, RefExpect::Any) {
        return Err(invalid(format!(
            "{what} needs the expected old value; an unconditional `any` is not accepted"
        )));
    }
    Ok(())
}

/// A create-or-update must state its old value (`Absent` creates).
fn require_conditional(what: &str, expected: &RefExpect) -> Result<(), CoreError> {
    reject_unconditional(what, expected)
}

/// A delete must expect the ref to exist.
fn require_existing(what: &str, expected: &RefExpect) -> Result<(), CoreError> {
    reject_unconditional(what, expected)?;
    if matches!(expected, RefExpect::Absent) {
        return Err(invalid(format!(
            "{what} cannot expect the ref to be absent"
        )));
    }
    Ok(())
}

fn validate_bindings(bindings: &[WorkspaceBinding]) -> Result<(), CoreError> {
    require_unique("workspace binding", bindings.iter().map(|b| &b.workspace))
}

fn validate_some<T: Validate>(value: Option<&T>) -> Result<(), CoreError> {
    value.map_or(Ok(()), Validate::validate)
}

fn ident_field(what: &str, text: &str) -> Result<(), CoreError> {
    if text.is_empty() || text.len() > 256 {
        return Err(invalid(format!("{what} must be 1..=256 bytes")));
    }
    if text
        .chars()
        .any(|ch| ch.is_control() || matches!(ch, '<' | '>'))
    {
        return Err(invalid(format!(
            "{what} contains a control character, `<`, or `>`"
        )));
    }
    Ok(())
}

impl Validate for IdentityClaim {
    fn validate(&self) -> Result<(), CoreError> {
        ident_field("identity name", &self.name)?;
        ident_field("identity email", &self.email)
    }
}

impl Validate for PageRequest {
    fn validate(&self) -> Result<(), CoreError> {
        match &self.cursor {
            Some(cursor) if cursor.position.len() > MAX_CURSOR_POSITION_BYTES => Err(invalid(
                format!("cursor position exceeds {MAX_CURSOR_POSITION_BYTES} bytes"),
            )),
            _ => Ok(()),
        }
    }
}

impl Validate for PathSelection {
    fn validate(&self) -> Result<(), CoreError> {
        match self {
            Self::All => Ok(()),
            Self::Paths(paths) => {
                require_nonempty("path selection", paths)?;
                require_unique("selected path", paths)
            }
        }
    }
}

impl<T: Validate> Validate for Mutation<T> {
    fn validate(&self) -> Result<(), CoreError> {
        self.args.validate()
    }
}

impl Validate for SessionOpenArgs {
    fn validate(&self) -> Result<(), CoreError> {
        validate_some(self.identity.as_ref())
    }
}

impl Validate for WsNewArgs {
    fn validate(&self) -> Result<(), CoreError> {
        if self.root.is_empty() || self.root.as_bytes().contains(&0) {
            return Err(invalid(
                "workspace root must be non-empty and contain no NUL",
            ));
        }
        match &self.init {
            WorkspaceInit::Native { parents } => require_unique("parent", parents),
            WorkspaceInit::GitCompat { .. } => Ok(()),
        }
    }
}

impl Validate for WsRecoverArgs {
    fn validate(&self) -> Result<(), CoreError> {
        match &self.action {
            RecoverAction::Discard { paths } => {
                require_nonempty("discard paths", paths)?;
                require_unique("discard path", paths)
            }
            RecoverAction::Resume | RecoverAction::Abort => Ok(()),
        }
    }
}

impl Validate for WriteEdit {
    fn validate(&self) -> Result<(), CoreError> {
        match &self.action {
            EditAction::Symlink { target }
                if target.is_empty() || target.as_bytes().contains(&0) =>
            {
                Err(invalid(
                    "a symlink target must be non-empty and contain no NUL",
                ))
            }
            EditAction::Put { .. } | EditAction::Symlink { .. } | EditAction::Delete => Ok(()),
        }
    }
}

/// The directories above `bytes`, shortest first (`a/b/c` yields `a`, `a/b`).
fn parent_prefixes(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'/')
        .map(move |(index, _)| &bytes[..index])
}

/// An edit may not lie below a path another edit writes as a file or link.
/// Deleting a path while writing beneath it is the file-to-directory
/// transition and stays allowed.
fn require_no_file_parent_collision(edits: &[WriteEdit]) -> Result<(), CoreError> {
    let written: HashSet<&[u8]> = edits
        .iter()
        .filter(|edit| !matches!(edit.action, EditAction::Delete))
        .map(|edit| edit.path.as_bytes())
        .collect();
    for edit in edits {
        let bytes = edit.path.as_bytes();
        if parent_prefixes(bytes).any(|parent| written.contains(parent)) {
            return Err(invalid(format!(
                "edit path `{}` lies below another edit that writes a file or link there",
                show_bytes(bytes)
            )));
        }
    }
    Ok(())
}

impl Validate for WriteArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_nonempty("edits", &self.edits)?;
        require_unique("edit path", self.edits.iter().map(|edit| &edit.path))?;
        require_no_file_parent_collision(&self.edits)?;
        self.edits.iter().try_for_each(Validate::validate)
    }
}

impl Validate for GitCommitArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_unique("parent", &self.parents)?;
        if self.message.as_bytes().contains(&0) {
            return Err(invalid("commit message carries NUL"));
        }
        if let Some(ref_update) = &self.ref_update {
            require_conditional("git.commit ref", &ref_update.expected)?;
        }
        Ok(())
    }
}

impl Validate for NewArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_unique("parent", &self.parents)?;
        validate_some(self.identity.as_ref())
    }
}

impl Validate for DescribeArgs {
    fn validate(&self) -> Result<(), CoreError> {
        validate_some(self.identity.as_ref())?;
        validate_bindings(&self.workspaces)
    }
}

impl Validate for SplitArgs {
    fn validate(&self) -> Result<(), CoreError> {
        if matches!(self.paths, PathSelection::All) {
            return Err(invalid(
                "split needs named paths; `all` leaves nothing to split",
            ));
        }
        self.paths.validate()?;
        validate_some(self.identity.as_ref())?;
        validate_bindings(&self.workspaces)
    }
}

impl Validate for SquashArgs {
    fn validate(&self) -> Result<(), CoreError> {
        if self.source.change == self.destination.change {
            return Err(invalid("squash source and destination are the same change"));
        }
        self.paths.validate()?;
        validate_some(self.identity.as_ref())?;
        validate_bindings(&self.workspaces)
    }
}

impl Validate for RebaseArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_nonempty("rebase sources", &self.sources)?;
        require_unique(
            "rebase source",
            self.sources.iter().map(|source| &source.change),
        )?;
        require_nonempty("rebase destination parents", &self.onto)?;
        require_unique("destination parent", &self.onto)?;
        validate_bindings(&self.workspaces)
    }
}

impl Validate for AbandonArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_nonempty("abandon targets", &self.targets)?;
        require_unique(
            "abandon target",
            self.targets.iter().map(|target| &target.change),
        )?;
        validate_bindings(&self.workspaces)
    }
}

impl Validate for ResolveArgs {
    fn validate(&self) -> Result<(), CoreError> {
        validate_bindings(&self.workspaces)
    }
}

impl Validate for RevertArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_nonempty("revert parents", &self.onto)?;
        require_unique("revert parent", &self.onto)?;
        validate_some(self.identity.as_ref())
    }
}

impl Validate for BookmarkSetArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_namespace("a bookmark", &self.name, b"refs/heads/")?;
        require_conditional("bookmark.set", &self.expected)
    }
}

impl Validate for BookmarkDeleteArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_namespace("a bookmark", &self.name, b"refs/heads/")?;
        require_existing("bookmark.delete", &self.expected)
    }
}

impl Validate for BookmarkResolveArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_namespace("a bookmark", &self.name, b"refs/heads/")
    }
}

impl Validate for TagSetArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_namespace("a tag", &self.name, b"refs/tags/")?;
        require_conditional("tag.set", &self.expected)?;
        validate_some(self.annotation.as_ref().and_then(|a| a.tagger.as_ref()))
    }
}

impl Validate for TagDeleteArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_namespace("a tag", &self.name, b"refs/tags/")?;
        require_existing("tag.delete", &self.expected)
    }
}

impl Validate for ClaimAcquireArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_nonempty("claim paths", &self.paths)?;
        require_unique("claim path", &self.paths)
    }
}

impl Validate for ClaimListArgs {
    fn validate(&self) -> Result<(), CoreError> {
        self.page.validate()
    }
}

impl Validate for AttestListArgs {
    fn validate(&self) -> Result<(), CoreError> {
        self.page.validate()
    }
}

impl Validate for OpLogArgs {
    fn validate(&self) -> Result<(), CoreError> {
        self.page.validate()
    }
}

impl Validate for FetchArgs {
    fn validate(&self) -> Result<(), CoreError> {
        match &self.refs {
            FetchRefs::Patterns(patterns) => require_nonempty("fetch patterns", patterns),
            FetchRefs::AllBranches => Ok(()),
        }
    }
}

impl Validate for PushUpdate {
    fn validate(&self) -> Result<(), CoreError> {
        let deleting = matches!(self.source, PushSource::Delete);
        if deleting && matches!(self.expected_old, Some(RemoteExpect::Absent)) {
            return Err(invalid(format!(
                "pushing a deletion of `{}` cannot expect the ref to be absent",
                show_bytes(self.remote_ref.as_bytes())
            )));
        }
        Ok(())
    }
}

impl Validate for PushArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_nonempty("push updates", &self.updates)?;
        require_unique(
            "pushed ref",
            self.updates.iter().map(|update| &update.remote_ref),
        )?;
        self.updates.iter().try_for_each(Validate::validate)
    }
}

impl Validate for StatusArgs {
    fn validate(&self) -> Result<(), CoreError> {
        self.page.validate()
    }
}

impl Validate for LogArgs {
    fn validate(&self) -> Result<(), CoreError> {
        self.page.validate()
    }
}

impl Validate for QueryArgs {
    fn validate(&self) -> Result<(), CoreError> {
        self.page.validate()
    }
}

impl Validate for DiffArgs {
    fn validate(&self) -> Result<(), CoreError> {
        self.paths.validate()?;
        self.page.validate()
    }
}

impl Validate for FileArgs {
    fn validate(&self) -> Result<(), CoreError> {
        self.page.validate()
    }
}

impl Validate for BlameArgs {
    fn validate(&self) -> Result<(), CoreError> {
        if let Some(lines) = self.lines
            && (lines.start == 0 || lines.end < lines.start)
        {
            return Err(invalid(
                "line range is one-based and must not end before it starts",
            ));
        }
        self.page.validate()
    }
}

// ---------------------------------------------------------------------------
// Hosted forge methods (minor 2)
// ---------------------------------------------------------------------------

/// `repo.stat`: store identity, object format, default branch, quarantine
/// latch, and the event horizon. Served from the store head; counts no
/// refs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoStatArgs {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoStatReply {
    pub view: ViewInfo,
    pub store_id: StoreId,
    pub object_format: HashKind,
    #[serde(default)]
    pub default_branch: Option<RefName>,
    /// Whether committed corruption latched quarantine in this session.
    pub quarantined: bool,
    /// The oldest retained event sequence.
    pub oldest: u64,
    /// The last assigned event sequence.
    pub head: u64,
}

/// `tree`: one directory listing with stateless keyset paging.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TreeArgs {
    pub rev: CommitRev,
    /// The directory to list; absent is the root.
    #[serde(default)]
    pub path: Option<RepoPath>,
    #[serde(default)]
    pub limit: Option<PageLimit>,
    /// Resume after this entry name; absent starts at the beginning.
    #[serde(default)]
    pub after: Option<ByteString>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TreeReply {
    pub view: ViewInfo,
    pub entries: KeysetPage<TreeEntry>,
}

/// `refs.list`: ref names and targets with prefix and inclusive-start
/// seek. Covers single-ref resolve, so no separate `ref.get` exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RefsListArgs {
    /// Only names starting with these bytes; absent lists every ref.
    #[serde(default)]
    pub prefix: Option<ByteString>,
    /// Resume after this name; absent starts at `prefix` (inclusive).
    #[serde(default)]
    pub after: Option<RefName>,
    #[serde(default)]
    pub limit: Option<PageLimit>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RefsListReply {
    pub view: ViewInfo,
    pub refs: KeysetPage<RefEntry>,
    /// The event head the page was read under. Read before the page so it
    /// never runs ahead of the events the page reflects.
    pub as_of: u64,
}

/// `compare`: merge bases plus bounded ahead/behind counts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CompareArgs {
    pub base: CommitRev,
    pub head: CommitRev,
    #[serde(default)]
    pub limit: Option<PageLimit>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CompareReply {
    pub view: ViewInfo,
    pub bases: Vec<Oid>,
    pub ahead: u64,
    pub behind: u64,
    /// False when the walk exhausted its budget: counts are lower bounds.
    pub exact: bool,
}

/// `search`: minimal contract; the dedicated search row defines budgets,
/// pools, and lease cursors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SearchArgs {
    pub pattern: String,
    #[serde(default)]
    pub limit: Option<PageLimit>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SearchHit {
    pub path: RepoPath,
    pub line: u64,
    pub excerpt: ByteString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SearchReply {
    pub view: ViewInfo,
    pub hits: Vec<SearchHit>,
    pub truncated: bool,
}

/// The archive payloads the daemon streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveFormat {
    Tar,
    Zip,
}

/// `archive`: metadata for the streamed payload; bytes ride `Stdout`
/// frames under the reply window, never the control frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArchiveArgs {
    pub rev: CommitRev,
    #[serde(default)]
    pub format: Option<ArchiveFormat>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArchiveReply {
    pub view: ViewInfo,
    pub commit: Oid,
    pub format: ArchiveFormat,
    pub content_type: String,
}

/// Longest `events.tail` wait: the only ref feed long-polls instead of
/// holding a subscription.
pub const MAX_TAIL_WAIT_MS: u32 = 30_000;

/// `events.tail`: ref events strictly after `after`, long-polled. The
/// only ref feed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EventsTailArgs {
    pub after: u64,
    #[serde(default)]
    pub limit: Option<PageLimit>,
    /// Long-poll milliseconds; absent returns immediately.
    #[serde(default)]
    pub wait_ms: Option<u32>,
    /// Only events whose ref name starts with these bytes.
    #[serde(default)]
    pub prefix: Option<ByteString>,
}

/// One ref event carried by `events.tail`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TailedEvent {
    pub seq: u64,
    pub name: ByteString,
    #[serde(default)]
    pub old: Option<RefTarget>,
    #[serde(default)]
    pub new: Option<RefTarget>,
    pub at: u64,
    pub source: EventSource,
    #[serde(default)]
    pub operation: Option<OperationId>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub session: Option<SessionId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EventsTailReply {
    pub view: ViewInfo,
    pub events: Vec<TailedEvent>,
    /// The last assigned sequence at reply time.
    pub head: u64,
    /// The oldest retained sequence at reply time.
    pub oldest: u64,
    /// True when `after + 1` predates `oldest`: the caller missed events
    /// and must resnapshot from `refs.list` with `as_of`.
    pub expired: bool,
}

/// `remote.refs`: advertised refs of an explicit remote URL, never stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RemoteRefsArgs {
    pub url: RemoteUrl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RemoteRefsReply {
    pub view: ViewInfo,
    pub refs: Vec<RefEntry>,
}

/// `claim.renew`: extends one held claim by a fresh lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ClaimRenewArgs {
    pub claim: ClaimId,
    pub ttl: ClaimTtl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClaimRenewReply {
    pub outcome: MutationOutcome,
    pub claim: ClaimRecord,
}

/// `policy.set`: replaces the landing policy of the repository.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicySetArgs {
    pub requirements: Vec<AttestRequirement>,
    pub trusted_signers: Vec<SignerFingerprint>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicySetReply {
    pub outcome: MutationOutcome,
    pub generation: u64,
}

/// `repo.init`: creates one repository store under a configured root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoInitArgs {
    pub root: String,
    pub path: String,
    #[serde(default)]
    pub object_format: Option<HashKind>,
    #[serde(default)]
    pub default_branch: Option<RefName>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoInitReply {
    pub path: String,
    pub store_id: StoreId,
    pub object_format: HashKind,
    pub default_branch: RefName,
}

/// `repo.delete`: tombstones one repository; a purge job removes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoDeleteArgs {
    pub repo: String,
    pub confirm_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoDeleteReply {
    pub deleted_path: String,
}

/// `repo.rename`: moves one repository within its root; the store id is
/// unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoRenameArgs {
    pub repo: String,
    pub new_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoRenameReply {
    pub path: String,
    pub previous_path: String,
}

/// Which refs a fork copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ForkRefs {
    All,
    DefaultAndTags,
    None,
}

/// `repo.fork`: copies one repository to a fresh store id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoForkArgs {
    pub source: String,
    pub path: String,
    #[serde(default)]
    pub refs: Option<ForkRefs>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RepoForkReply {
    pub path: String,
    pub store_id: StoreId,
    pub refs_copied: u64,
}

fn require_nonempty_text(what: &str, text: &str) -> Result<(), CoreError> {
    if text.is_empty() {
        return Err(invalid(format!("{what} must not be empty")));
    }
    Ok(())
}

impl Validate for SearchArgs {
    fn validate(&self) -> Result<(), CoreError> {
        let bytes = self.pattern.len();
        if bytes == 0 || bytes > 4096 {
            return Err(invalid(format!(
                "search pattern is 1..=4096 bytes, got {bytes}"
            )));
        }
        Ok(())
    }
}

impl Validate for EventsTailArgs {
    fn validate(&self) -> Result<(), CoreError> {
        if let Some(wait_ms) = self.wait_ms
            && wait_ms > MAX_TAIL_WAIT_MS
        {
            return Err(limit_exceeded(format!(
                "tail wait is at most {MAX_TAIL_WAIT_MS} ms, got {wait_ms}"
            )));
        }
        Ok(())
    }
}

impl Validate for RepoInitArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_nonempty_text("init root", &self.root)?;
        require_nonempty_text("init path", &self.path)
    }
}

impl Validate for RepoDeleteArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_nonempty_text("delete repo", &self.repo)?;
        require_nonempty_text("delete confirm path", &self.confirm_path)
    }
}

impl Validate for RepoRenameArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_nonempty_text("rename repo", &self.repo)?;
        require_nonempty_text("rename new path", &self.new_path)
    }
}

impl Validate for RepoForkArgs {
    fn validate(&self) -> Result<(), CoreError> {
        require_nonempty_text("fork source", &self.source)?;
        require_nonempty_text("fork path", &self.path)
    }
}

// ---------------------------------------------------------------------------
// The method table
// ---------------------------------------------------------------------------

/// Whether a method needs, forbids, or tolerates a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionRule {
    Forbidden,
    Optional,
    Required,
}

impl MethodKind {
    const fn session_rule(self) -> SessionRule {
        match self {
            Self::Anonymous | Self::Admin => SessionRule::Optional,
            Self::Bootstrap => SessionRule::Forbidden,
            Self::Read | Self::Mutation => SessionRule::Required,
        }
    }
}

/// The postcard encoding of a mutation's arguments (never its request id).
macro_rules! digest_args {
    (Mutation, $params:expr) => {
        Some(postcard::to_allocvec(&$params.args))
    };
    (Admin, $params:expr) => {{
        let _ = &$params;
        None
    }};
    ($kind:ident, $params:expr) => {{
        let _ = &$params;
        None
    }};
}

/// The request id of a mutation.
macro_rules! request_id_of {
    (Mutation, $params:expr) => {
        Some($params.request_id)
    };
    (Admin, $params:expr) => {{
        let _ = &$params;
        None
    }};
    ($kind:ident, $params:expr) => {{
        let _ = &$params;
        None
    }};
}

/// The outcome of a mutation reply.
macro_rules! outcome_of {
    (Mutation, $result:expr) => {
        Some(&$result.outcome)
    };
    (Anonymous, $result:expr) => {{
        let _ = &$result;
        None
    }};
    (Bootstrap, $result:expr) => {{
        let _ = &$result;
        None
    }};
    (Read, $result:expr) => {{
        let _ = &$result;
        None
    }};
    (Admin, $result:expr) => {{
        let _ = &$result;
        None
    }};
}

/// Mutable access to the outcome of a mutation reply.
macro_rules! outcome_of_mut {
    (Mutation, $result:expr) => {
        Some(&mut $result.outcome)
    };
    (Anonymous, $result:expr) => {{
        let _ = $result;
        None
    }};
    (Bootstrap, $result:expr) => {{
        let _ = $result;
        None
    }};
    (Read, $result:expr) => {{
        let _ = $result;
        None
    }};
    (Admin, $result:expr) => {{
        let _ = $result;
        None
    }};
}

/// One table of `(variant, wire name, kind, parameters, result)` generates the
/// method enum, the request and reply enums, and the schema entries, so the
/// four can never disagree about which methods exist.
///
/// # Append-only order within v1
/// Within v1, `method_table!` entries must only be appended to the end of the
/// table. Durable v1 formats (such as receipt rows and operation headers)
/// serialize enum variants using postcard, which encodes enum discriminants
/// as their positional declaration index (varint). Reordering, removing, or
/// inserting variants before the end alters discriminant indices and breaks
/// durable v1 storage compatibility.
macro_rules! method_table {
    ($($variant:ident, $name:literal, $kind:ident, $params:ty, $result:ty;)+) => {
        /// Every native method.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
        pub enum Method {
            $(#[serde(rename = $name)] $variant,)+
        }

        impl Method {
            /// Every method, in table order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// The method's wire name.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }

            /// How the method is invoked.
            #[must_use]
            pub const fn kind(self) -> MethodKind {
                match self {
                    $(Self::$variant => MethodKind::$kind,)+
                }
            }

            /// True for methods that carry a request id and a receipt.
            #[must_use]
            pub const fn is_mutation(self) -> bool {
                matches!(self.kind(), MethodKind::Mutation)
            }
        }

        /// A method call and its parameters.
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        pub enum Request {
            $(#[serde(rename = $name)] $variant(Box<$params>),)+
        }

        impl Request {
            /// The method being called.
            #[must_use]
            pub const fn method(&self) -> Method {
                match self {
                    $(Self::$variant(_) => Method::$variant,)+
                }
            }

            /// The request id of a mutation; reads and bootstrap calls have none.
            #[must_use]
            pub fn request_id(&self) -> Option<RequestId> {
                match self {
                    $(Self::$variant(params) => request_id_of!($kind, params),)+
                }
            }

            /// Checks the invariants the argument types cannot express.
            ///
            /// # Errors
            /// `E_INVALID` naming the violated invariant.
            pub fn validate(&self) -> Result<(), CoreError> {
                match self {
                    $(Self::$variant(params) => Validate::validate(&**params),)+
                }
            }

            /// The bytes a mutation's idempotency digest hashes with SHA-256
            /// (digest version [`REQUEST_DIGEST_VERSION`]), or `None` for a call
            /// that has no receipt. Layout: three length-prefixed fields (a
            /// 4-byte big-endian length each): the domain separator, the method
            /// name, and the postcard encoding of the arguments. The request id
            /// is excluded, and every expected stamp appears once, inside the
            /// arguments. Reordering or inserting fields or enum variants of an
            /// argument type changes this encoding and therefore needs a new
            /// digest version.
            ///
            /// # Errors
            /// `E_INVALID` when the arguments cannot be encoded.
            pub fn digest_input_v1(&self) -> Result<Option<Vec<u8>>, CoreError> {
                let args = match self {
                    $(Self::$variant(params) => digest_args!($kind, params),)+
                };
                let Some(args) = args else {
                    return Ok(None);
                };
                let args = args.map_err(|err| {
                    invalid(format!("request arguments are not encodable: {err}"))
                })?;
                let mut input = Vec::with_capacity(args.len() + 64);
                push_field(&mut input, DIGEST_DOMAIN_V1)?;
                push_field(&mut input, self.method().as_str().as_bytes())?;
                push_field(&mut input, &args)?;
                Ok(Some(input))
            }
        }

        /// A successful method result.
        #[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
        pub enum Reply {
            $(#[serde(rename = $name)] $variant(Box<$result>),)+
        }

        impl Reply {
            /// The method this reply answers.
            #[must_use]
            pub const fn method(&self) -> Method {
                match self {
                    $(Self::$variant(_) => Method::$variant,)+
                }
            }

            /// The outcome of a mutation reply, or `None` for reads and bootstrap methods.
            #[must_use]
            pub fn outcome(&self) -> Option<&MutationOutcome> {
                match self {
                    $(Self::$variant(result) => outcome_of!($kind, result),)+
                }
            }

            /// Mutable access to the outcome of a mutation reply, or `None` for reads and bootstrap methods.
            #[must_use]
            pub fn outcome_mut(&mut self) -> Option<&mut MutationOutcome> {
                match self {
                    $(Self::$variant(result) => outcome_of_mut!($kind, result),)+
                }
            }
        }

        fn method_entries(generator: &mut SchemaGenerator) -> Vec<Schema> {
            vec![$(
                json_schema!({
                    "method": $name,
                    "kind": MethodKind::$kind,
                    "params": generator.subschema_for::<$params>(),
                    "result": generator.subschema_for::<$result>(),
                }),
            )+]
        }

        fn method_params_result(
            method: Method,
            generator: &mut SchemaGenerator,
        ) -> (Schema, Schema) {
            match method {
                $(Method::$variant => (
                    generator.subschema_for::<$params>(),
                    generator.subschema_for::<$result>(),
                ),)+
            }
        }
    };
}

method_table! {
    Schema, "schema", Anonymous, SchemaArgs, SchemaReply;
    SessionOpen, "session.open", Bootstrap, SessionOpenArgs, SessionOpenReply;
    SessionResume, "session.resume", Bootstrap, SessionResumeArgs, SessionResumeReply;
    WsNew, "ws.new", Mutation, Mutation<WsNewArgs>, WsNewReply;
    WsScope, "ws.scope", Mutation, Mutation<WsScopeArgs>, WsScopeReply;
    WsTake, "ws.take", Mutation, Mutation<WsTakeArgs>, WsTakeReply;
    WsDrop, "ws.drop", Mutation, Mutation<WsDropArgs>, WsDropReply;
    WsRecover, "ws.recover", Mutation, Mutation<WsRecoverArgs>, WsRecoverReply;
    Snapshot, "snapshot", Mutation, Mutation<SnapshotArgs>, SnapshotReply;
    Write, "write", Mutation, Mutation<WriteArgs>, WriteReply;
    New, "new", Mutation, Mutation<NewArgs>, NewReply;
    Describe, "describe", Mutation, Mutation<DescribeArgs>, RewriteReply;
    Edit, "edit", Mutation, Mutation<EditArgs>, EditReply;
    Split, "split", Mutation, Mutation<SplitArgs>, RewriteReply;
    Squash, "squash", Mutation, Mutation<SquashArgs>, RewriteReply;
    Rebase, "rebase", Mutation, Mutation<RebaseArgs>, RewriteReply;
    Abandon, "abandon", Mutation, Mutation<AbandonArgs>, RewriteReply;
    Resolve, "resolve", Mutation, Mutation<ResolveArgs>, ResolveReply;
    Revert, "revert", Mutation, Mutation<RevertArgs>, RevertReply;
    BookmarkSet, "bookmark.set", Mutation, Mutation<BookmarkSetArgs>, BookmarkSetReply;
    BookmarkDelete, "bookmark.delete", Mutation, Mutation<BookmarkDeleteArgs>, BookmarkDeleteReply;
    BookmarkResolve, "bookmark.resolve", Mutation, Mutation<BookmarkResolveArgs>, BookmarkResolveReply;
    TagSet, "tag.set", Mutation, Mutation<TagSetArgs>, TagSetReply;
    TagDelete, "tag.delete", Mutation, Mutation<TagDeleteArgs>, TagDeleteReply;
    ClaimAcquire, "claim.acquire", Mutation, Mutation<ClaimAcquireArgs>, ClaimAcquireReply;
    ClaimRelease, "claim.release", Mutation, Mutation<ClaimReleaseArgs>, ClaimReleaseReply;
    ClaimList, "claim.list", Read, ClaimListArgs, ClaimListReply;
    AttestAdd, "attest.add", Mutation, Mutation<AttestAddArgs>, AttestAddReply;
    AttestList, "attest.list", Read, AttestListArgs, AttestListReply;
    Fetch, "fetch", Mutation, Mutation<FetchArgs>, FetchReply;
    Push, "push", Mutation, Mutation<PushArgs>, PushReply;
    PushReconcile, "push.reconcile", Mutation, Mutation<PushReconcileArgs>, PushReconcileReply;
    LandPrepare, "land.prepare", Mutation, Mutation<LandPrepareArgs>, LandPrepareReply;
    LandExecute, "land.execute", Mutation, Mutation<LandExecuteArgs>, LandExecuteReply;
    Undo, "undo", Mutation, Mutation<UndoArgs>, UndoReply;
    OpLog, "op.log", Read, OpLogArgs, OpLogReply;
    OpPrune, "op.prune", Mutation, Mutation<OpPruneArgs>, OpPruneReply;
    Pin, "pin", Mutation, Mutation<PinArgs>, PinReply;
    Unpin, "unpin", Mutation, Mutation<UnpinArgs>, UnpinReply;
    Status, "status", Read, StatusArgs, StatusReply;
    Log, "log", Read, LogArgs, LogReply;
    Diff, "diff", Read, DiffArgs, DiffReply;
    Show, "show", Read, ShowArgs, ShowReply;
    File, "file", Read, FileArgs, FileReply;
    Blame, "blame", Read, BlameArgs, BlameReply;
    Query, "query", Read, QueryArgs, QueryReply;
    GitCommit, "git.commit", Mutation, Mutation<GitCommitArgs>, NewReply;
    RepoStat, "repo.stat", Read, RepoStatArgs, RepoStatReply;
    Tree, "tree", Read, TreeArgs, TreeReply;
    RefsList, "refs.list", Read, RefsListArgs, RefsListReply;
    Compare, "compare", Read, CompareArgs, CompareReply;
    Search, "search", Read, SearchArgs, SearchReply;
    Archive, "archive", Read, ArchiveArgs, ArchiveReply;
    EventsTail, "events.tail", Read, EventsTailArgs, EventsTailReply;
    RepoInit, "repo.init", Admin, RepoInitArgs, RepoInitReply;
    RepoDelete, "repo.delete", Admin, RepoDeleteArgs, RepoDeleteReply;
    RepoRename, "repo.rename", Admin, RepoRenameArgs, RepoRenameReply;
    RepoFork, "repo.fork", Admin, RepoForkArgs, RepoForkReply;
    RemoteRefs, "remote.refs", Read, RemoteRefsArgs, RemoteRefsReply;
    ClaimRenew, "claim.renew", Mutation, Mutation<ClaimRenewArgs>, ClaimRenewReply;
    PolicySet, "policy.set", Mutation, Mutation<PolicySetArgs>, PolicySetReply;
}

// ---------------------------------------------------------------------------
// Envelopes and codecs
// ---------------------------------------------------------------------------

/// A request on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RequestEnvelope {
    pub schema_version: SchemaVersion,
    /// The authenticated session. Required by reads and mutations, optional
    /// for `schema`, forbidden for `session.open` and `session.resume`.
    #[serde(default)]
    pub session: Option<SessionId>,
    pub request: Request,
}

impl RequestEnvelope {
    /// Checks the version, the session rule of the method, and the method's
    /// own invariants.
    ///
    /// # Errors
    /// `E_VERSION` for an unsupported major; `E_INVALID` otherwise.
    pub fn validate(&self) -> Result<(), CoreError> {
        validate_schema_version(self.schema_version)?;
        let method = self.request.method();
        match (method.kind().session_rule(), self.session) {
            (SessionRule::Required, None) => Err(invalid(format!(
                "method `{}` requires a session",
                method.as_str()
            ))),
            (SessionRule::Forbidden, Some(_)) => Err(invalid(format!(
                "method `{}` establishes a session and must not carry one",
                method.as_str()
            ))),
            _ => self.request.validate(),
        }
    }
}

/// A reply on the wire.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReplyEnvelope {
    pub schema_version: SchemaVersion,
    /// The request this answers, when the request was readable far enough to
    /// have one.
    #[serde(default)]
    pub request_id: Option<RequestId>,
    pub body: ReplyBody,
}

/// A reply is a result or an error, never both.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReplyBody {
    Success(Reply),
    Failure(ErrorReply),
}

impl ReplyEnvelope {
    /// A successful reply at this build's schema version.
    #[must_use]
    pub const fn success(request_id: Option<RequestId>, reply: Reply) -> Self {
        Self {
            schema_version: SchemaVersion::current(),
            request_id,
            body: ReplyBody::Success(reply),
        }
    }

    /// A failed reply at this build's schema version.
    #[must_use]
    pub const fn failure(request_id: Option<RequestId>, error: ErrorReply) -> Self {
        Self {
            schema_version: SchemaVersion::current(),
            request_id,
            body: ReplyBody::Failure(error),
        }
    }
}

fn push_field(out: &mut Vec<u8>, field: &[u8]) -> Result<(), CoreError> {
    let length = u32::try_from(field.len())
        .map_err(|_| limit_exceeded("a framed field exceeds the 4 GiB length prefix"))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// Maximum open arrays/objects accepted in one untrusted JSON document; the
/// root value counts. Sonic's recursive ignored-field and DOM parsers have
/// no depth control, so nesting is bounded before they run.
pub const MAX_JSON_NESTING: usize = 128;

/// Validates that `bytes` holds at most [`MAX_JSON_NESTING`] open JSON
/// containers at any point, before a recursive parser touches the input.
///
/// The scan is allocation-free and quote/escape-aware; it counts opening
/// and closing delimiters outside strings and never underflows on malformed
/// closers (a stray `}` or `]` is left for the real parser to reject).
/// Full syntax validation stays with sonic.
///
/// # Errors
/// `E_INVALID` when the nesting bound is exceeded.
pub fn check_json_nesting(bytes: &[u8]) -> Result<(), CoreError> {
    scan_json_depth(bytes).map(|_| ())
}

fn scan_json_depth(bytes: &[u8]) -> Result<usize, CoreError> {
    let mut depth: usize = 0;
    let mut deepest: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_JSON_NESTING {
                    return Err(invalid(format!(
                        "input nests more than {MAX_JSON_NESTING} levels; \
                         the bound protects the recursive parser"
                    )));
                }
                deepest = deepest.max(depth);
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(deepest)
}

/// Parses `bytes` as one JSON document into `T` with sonic, after bounding
/// the document's nesting.
///
/// The input is scanned once under the [`check_json_nesting`] rule, then
/// parsed with stack room for the scanned depth: a thread that lacks it gets
/// an extra stack segment for the duration of the call. No byte-length limit
/// applies and no protocol version is inspected.
///
/// # Preconditions
/// The stack provision covers sonic's parser. Recursion inside a custom
/// `Deserialize` implementation of `T` is outside it.
///
/// # Errors
/// `E_INVALID` when the input nests more than [`MAX_JSON_NESTING`] levels, is
/// not valid JSON, or does not match `T`; the message is the diagnostic.
///
/// # Panics
/// When the operating system refuses the extra stack segment.
pub fn decode_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CoreError> {
    let depth = scan_json_depth(bytes)?;
    with_parse_stack(depth, || from_slice(bytes)).map_err(|err| invalid(err.to_string()))
}

const PARSE_STACK_BASE: usize = 128 * 1024;
const PARSE_STACK_PER_CONTAINER: usize = 128 * 1024;

/// Runs `parse` with stack room for `depth` open containers, which
/// `scan_json_depth` bounds by [`MAX_JSON_NESTING`]. The reserve is a policy
/// of 128 KiB plus 128 KiB per container, more than twice the 53,760 bytes per
/// container measured in a debug build, not an exact frame size. A thread that
/// already has the reserve keeps its own stack; otherwise `parse` runs on a
/// new segment of twice the reserve.
fn with_parse_stack<R>(depth: usize, parse: impl FnOnce() -> R) -> R {
    let reserve = PARSE_STACK_BASE + depth * PARSE_STACK_PER_CONTAINER;
    stacker::maybe_grow(reserve, 2 * reserve, parse)
}

fn version_probe(bytes: &[u8]) -> Result<(), CoreError> {
    #[derive(Deserialize)]
    struct Probe {
        schema_version: SchemaVersion,
    }
    let probe: Probe =
        from_slice(bytes).map_err(|err| invalid(format!("malformed control frame: {err}")))?;
    validate_schema_version(probe.schema_version)?;
    Ok(())
}

fn decode_envelope<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CoreError> {
    if bytes.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(limit_exceeded(format!(
            "a control frame is at most {MAX_CONTROL_FRAME_BYTES} bytes, got {}",
            bytes.len()
        )));
    }
    let depth = scan_json_depth(bytes)?;
    with_parse_stack(depth, || -> Result<T, CoreError> {
        version_probe(bytes)?;
        from_slice(bytes).map_err(|err| invalid(format!("invalid message: {err}")))
    })
}

fn encode_envelope<T: Serialize>(value: &T) -> Result<Vec<u8>, CoreError> {
    let bytes = to_vec(value).map_err(|err| invalid(format!("message is not encodable: {err}")))?;
    if bytes.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(limit_exceeded(format!(
            "message is {} bytes; a control frame holds at most {MAX_CONTROL_FRAME_BYTES}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Decodes and validates one request frame body. The frame size, JSON syntax,
/// and nesting bound are checked first; the version is then checked before
/// the rest of the body is interpreted, so a well-formed frame from an
/// unsupported major fails `E_VERSION` whatever its shape.
///
/// # Errors
/// `E_LIMIT` above [`MAX_CONTROL_FRAME_BYTES`], `E_VERSION` for an
/// unsupported major, `E_INVALID` for anything malformed, nested deeper than
/// [`MAX_JSON_NESTING`], or violating a request invariant.
pub fn decode_request(bytes: &[u8]) -> Result<RequestEnvelope, CoreError> {
    let envelope: RequestEnvelope = decode_envelope(bytes)?;
    envelope.validate()?;
    Ok(envelope)
}

/// Encodes a request frame body.
///
/// # Errors
/// `E_LIMIT` when the encoding exceeds [`MAX_CONTROL_FRAME_BYTES`].
pub fn encode_request(envelope: &RequestEnvelope) -> Result<Vec<u8>, CoreError> {
    encode_envelope(envelope)
}

/// Decodes one reply frame body.
///
/// # Errors
/// As for [`decode_request`], without the request invariants.
pub fn decode_reply(bytes: &[u8]) -> Result<ReplyEnvelope, CoreError> {
    decode_envelope(bytes)
}

/// Encodes a reply frame body.
///
/// # Errors
/// `E_LIMIT` when the reply exceeds [`MAX_CONTROL_FRAME_BYTES`]; the server
/// must paginate or stream instead.
pub fn encode_reply(envelope: &ReplyEnvelope) -> Result<Vec<u8>, CoreError> {
    encode_envelope(envelope)
}

/// Prefixes `payload` with its 4-byte big-endian length.
///
/// # Errors
/// `E_LIMIT` when `payload` exceeds [`MAX_CONTROL_FRAME_BYTES`].
pub fn frame_control(payload: &[u8]) -> Result<Vec<u8>, CoreError> {
    if payload.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(limit_exceeded(format!(
            "a control frame is at most {MAX_CONTROL_FRAME_BYTES} bytes, got {}",
            payload.len()
        )));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| limit_exceeded("a control frame length does not fit the prefix"))?;
    let mut framed = Vec::with_capacity(FRAME_PREFIX_BYTES + payload.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(payload);
    Ok(framed)
}

/// Reads a control-frame length prefix and rejects an over-large frame before
/// any buffer is allocated for it.
///
/// # Errors
/// `E_LIMIT` when the announced length exceeds [`MAX_CONTROL_FRAME_BYTES`].
pub fn control_frame_len(prefix: [u8; FRAME_PREFIX_BYTES]) -> Result<usize, CoreError> {
    let announced = u32::from_be_bytes(prefix);
    match usize::try_from(announced) {
        Ok(length) if length <= MAX_CONTROL_FRAME_BYTES => Ok(length),
        _ => Err(limit_exceeded(format!(
            "a control frame is at most {MAX_CONTROL_FRAME_BYTES} bytes, the prefix announces {announced}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Attestation payload
// ---------------------------------------------------------------------------

impl AttestStatement {
    /// The canonical v1 payload that is signed (namespace `ruk-attest`):
    /// seven length-prefixed fields (4-byte big-endian length each) in this
    /// order: domain separator, object format name, exact OID bytes, kind,
    /// result, UTC timestamp text, and the superseded statement digest (empty
    /// when the statement supersedes nothing; otherwise exactly 32 bytes, so
    /// absence and presence cannot be confused). Length prefixes make the
    /// field boundaries unambiguous: `("a", "bc")` and `("ab", "c")` differ.
    ///
    /// Only evidenceless statements have a v1 payload: v1 cannot bind
    /// evidence, so signing one would silently drop it. New signatures cover
    /// [`Self::canonical_payload_v2`]; v1 stays verifiable for old ones.
    ///
    /// # Errors
    /// `E_OBJECT_FORMAT` when the subject's width is not `format`'s.
    /// `E_INVALID` when the statement carries evidence, which v1 cannot bind.
    pub fn canonical_payload_v1(&self, format: HashKind) -> Result<Vec<u8>, CoreError> {
        if self.evidence.is_some() {
            return Err(invalid(
                "an attestation carrying evidence has no v1 payload: sign the v2 payload",
            ));
        }
        if self.subject.kind() != format {
            return Err(CoreError::new(
                ErrorCode::EObjectFormat,
                format!(
                    "attestation subject is a {} object but the repository is {format}",
                    self.subject.kind()
                ),
            ));
        }
        let timestamp = self.signed_at.to_string();
        let superseded: &[u8] = match &self.supersedes {
            Some(digest) => digest.as_bytes(),
            None => &[],
        };
        let fields: [&[u8]; 7] = [
            ATTEST_PAYLOAD_DOMAIN_V1,
            format.format_name().as_bytes(),
            self.subject.as_bytes(),
            self.kind.as_str().as_bytes(),
            self.result.as_str().as_bytes(),
            timestamp.as_bytes(),
            superseded,
        ];
        let mut payload = Vec::with_capacity(128);
        for field in fields {
            push_field(&mut payload, field)?;
        }
        Ok(payload)
    }

    /// The canonical v2 payload that is signed (namespace `ruk-attest`):
    /// eight length-prefixed fields (4-byte big-endian length each) in this
    /// order: the v2 domain separator, object format name, exact OID bytes,
    /// kind, result, UTC timestamp text, the superseded statement digest,
    /// and the bound evidence digest. Either digest field is empty when
    /// absent and exactly 32 bytes when present, so absence and presence
    /// cannot be confused and `None` differs from a zero digest.
    ///
    /// # Errors
    /// `E_OBJECT_FORMAT` when the subject's width is not `format`'s.
    pub fn canonical_payload_v2(&self, format: HashKind) -> Result<Vec<u8>, CoreError> {
        if self.subject.kind() != format {
            return Err(CoreError::new(
                ErrorCode::EObjectFormat,
                format!(
                    "attestation subject is a {} object but the repository is {format}",
                    self.subject.kind()
                ),
            ));
        }
        let timestamp = self.signed_at.to_string();
        let superseded: &[u8] = match &self.supersedes {
            Some(digest) => digest.as_bytes(),
            None => &[],
        };
        let evidence: &[u8] = match &self.evidence {
            Some(digest) => digest.as_bytes(),
            None => &[],
        };
        let fields: [&[u8]; 8] = [
            ATTEST_PAYLOAD_DOMAIN_V2,
            format.format_name().as_bytes(),
            self.subject.as_bytes(),
            self.kind.as_str().as_bytes(),
            self.result.as_str().as_bytes(),
            timestamp.as_bytes(),
            superseded,
            evidence,
        ];
        let mut payload = Vec::with_capacity(160);
        for field in fields {
            push_field(&mut payload, field)?;
        }
        Ok(payload)
    }
}

// ---------------------------------------------------------------------------
// Model document
// ---------------------------------------------------------------------------

const JSON_SCHEMA_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// The model document `ruk model` prints: limits, framing, the error
/// registry, the root request and reply types, every method's parameter and
/// result schema, and the shared definitions they reference.
///
/// The `schema` method result carries one document with an object or
/// boolean root; schema documents decode from JSON frames only and have no
/// binary postcard form.
#[must_use]
pub fn model_schema_json() -> Schema {
    let mut generator = SchemaSettings::draft2020_12().into_generator();
    let request = generator.subschema_for::<RequestEnvelope>();
    let reply = generator.subschema_for::<ReplyEnvelope>();
    let capabilities = generator.subschema_for::<Capabilities>();
    let methods = method_entries(&mut generator);
    let definitions = generator.take_definitions(true);
    let error_codes: Vec<Schema> = ErrorCode::ALL
        .iter()
        .map(|code| json_schema!({ "code": code.as_str(), "exit_status": code.exit_code() }))
        .collect();
    json_schema!({
        "$schema": JSON_SCHEMA_DIALECT,
        "title": "Ruk core protocol",
        "schema_version": SchemaVersion::current(),
        "supported_majors": [SCHEMA_MAJOR],
        "object_formats": [HashKind::Sha1.format_name(), HashKind::Sha256.format_name()],
        "default_object_format": HashKind::DEFAULT.format_name(),
        "limits": {
            "control_frame_bytes": MAX_CONTROL_FRAME_BYTES,
            "inline_edit_bytes": MAX_INLINE_EDIT_BYTES,
            "page_default": DEFAULT_PAGE_SIZE,
            "page_max": MAX_PAGE_SIZE,
            "claim_ttl_seconds": MAX_CLAIM_TTL_SECONDS,
        },
        "framing": {
            "length_prefix_bytes": FRAME_PREFIX_BYTES,
            "byte_order": "big_endian",
            "encoding": "json",
        },
        "request_digest_version": REQUEST_DIGEST_VERSION,
        "error_codes": error_codes,
        "request": request,
        "reply": reply,
        "capabilities": capabilities,
        "methods": methods,
        "$defs": definitions,
    })
}

/// The schema document restricted to one method: its parameter and result
/// schemas and the definitions they reference.
#[must_use]
pub fn method_schema_json(method: Method) -> Schema {
    let mut generator = SchemaSettings::draft2020_12().into_generator();
    let (params, result) = method_params_result(method, &mut generator);
    let definitions = generator.take_definitions(true);
    json_schema!({
        "$schema": JSON_SCHEMA_DIALECT,
        "schema_version": SchemaVersion::current(),
        "method": method.as_str(),
        "kind": method.kind(),
        "params": params,
        "result": result,
        "$defs": definitions,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::commit::Provenance;
    use sonic_rs::Value;
    use sonic_rs::json;
    use sonic_rs::{JsonContainerTrait as _, JsonValueMutTrait as _, JsonValueTrait as _};

    fn session() -> SessionId {
        "11111111-1111-4111-8111-111111111111"
            .parse()
            .expect("session id")
    }

    fn request_id(n: u8) -> RequestId {
        format!("{n:08x}-2222-4222-8222-222222222222")
            .parse()
            .expect("request id")
    }

    fn workspace() -> WorkspaceId {
        "33333333-3333-4333-8333-333333333333"
            .parse()
            .expect("workspace id")
    }

    fn oid(n: u8) -> Oid {
        Oid::from_hex(&format!("{n:02x}").repeat(20)).expect("oid")
    }

    fn head(n: u8) -> Head {
        Head::Git { oid: oid(n) }
    }

    fn path(text: &str) -> RepoPath {
        RepoPath::new(text).expect("path")
    }

    fn name(text: &str) -> RefName {
        RefName::new(text).expect("ref name")
    }

    fn stamp(sequence: u64) -> WorkspaceStamp {
        WorkspaceStamp {
            sequence,
            lease_epoch: 1,
        }
    }

    fn binding(sequence: u64) -> WorkspaceBinding {
        WorkspaceBinding {
            workspace: workspace(),
            expected: stamp(sequence),
        }
    }

    fn timestamp(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("timestamp")
    }

    fn envelope(request: Request) -> RequestEnvelope {
        RequestEnvelope {
            schema_version: SchemaVersion::current(),
            session: Some(session()),
            request,
        }
    }

    fn mutation<T>(n: u8, args: T) -> Box<Mutation<T>> {
        Box::new(Mutation {
            request_id: request_id(n),
            args,
        })
    }

    fn pin_request() -> Request {
        Request::Pin(mutation(1, PinArgs { head: head(1) }))
    }

    fn log_request(page: PageRequest) -> Request {
        Request::Log(Box::new(LogArgs {
            revset: RevsetText::new("@").expect("revset"),
            page,
        }))
    }

    fn put(text: &str, data: &[u8]) -> WriteEdit {
        WriteEdit {
            path: path(text),
            action: EditAction::Put {
                content: Content::Inline {
                    data: InlineBytes::new(ByteString::from(data)).expect("inline"),
                },
                executable: false,
            },
        }
    }

    fn delete(text: &str) -> WriteEdit {
        WriteEdit {
            path: path(text),
            action: EditAction::Delete,
        }
    }

    fn write_request(edits: Vec<WriteEdit>) -> Request {
        Request::Write(mutation(
            1,
            WriteArgs {
                binding: binding(4),
                edits,
            },
        ))
    }

    fn to_frame(value: &Value) -> Vec<u8> {
        sonic_rs::to_vec(value).expect("json")
    }

    fn model_value() -> Value {
        let bytes = sonic_rs::to_vec(&model_schema_json()).expect("render model");
        sonic_rs::from_slice(&bytes).expect("parse model")
    }

    fn single_method_value() -> Value {
        let bytes = sonic_rs::to_vec(&method_schema_json(Method::Write)).expect("render method");
        sonic_rs::from_slice(&bytes).expect("parse method")
    }

    fn fails(bytes: &[u8]) -> ErrorCode {
        decode_request(bytes).expect_err("must fail").code
    }

    fn invalid_code(result: Result<(), CoreError>) -> ErrorCode {
        result.expect_err("must fail").code
    }

    // ----- versions and framing -------------------------------------------

    #[test]
    fn unsupported_major_fails_version_before_the_body_is_read() {
        for major in [0_u32, 2, 99] {
            let frame = json!({
                "schema_version": { "major": major, "minor": 0 },
                "request": { "not": "a request" },
            });
            assert_eq!(
                fails(&to_frame(&frame)),
                ErrorCode::EVersion,
                "major {major}"
            );
        }
        assert!(SchemaVersion::current().is_supported());
        assert!(validate_schema_version(SchemaVersion { major: 2, minor: 0 }).is_err());
    }

    #[test]
    fn newer_minor_and_unknown_fields_are_accepted() {
        let original = envelope(pin_request());
        let mut value = sonic_rs::to_value(&original).expect("value");
        value["schema_version"]["minor"] = json!(99);
        value["future_envelope_field"] = json!({ "anything": [1, 2] });
        value["request"]["pin"]["args"]["future_arg"] = json!(true);
        let decoded = decode_request(&to_frame(&value)).expect("decode");
        assert_eq!(decoded.request, original.request);
    }

    #[test]
    fn malformed_frames_are_invalid_rather_than_panics() {
        let deep = "[".repeat(10_000);
        let cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"not json".to_vec(),
            b"[]".to_vec(),
            b"{}".to_vec(),
            deep.into_bytes(),
            to_frame(&json!({ "schema_version": { "major": 1, "minor": 0 } })),
            to_frame(&json!({
                "schema_version": { "major": 1, "minor": 0 },
                "request": { "no.such.method": {} },
            })),
            to_frame(&json!({
                "schema_version": { "major": 1, "minor": 0 },
                "session": session().to_string(),
                "request": { "pin": { "request_id": "not-a-uuid", "args": {} } },
            })),
        ];
        for case in cases {
            assert_eq!(
                fails(&case),
                ErrorCode::EInvalid,
                "{:?}",
                String::from_utf8_lossy(&case[..case.len().min(40)])
            );
        }
    }

    #[test]
    fn frames_above_the_control_limit_fail_before_parsing() {
        let oversized = vec![b' '; MAX_CONTROL_FRAME_BYTES + 1];
        assert_eq!(fails(&oversized), ErrorCode::ELimit);
        // Exactly at the limit the frame is read; whitespace is merely invalid JSON.
        let at_limit = vec![b' '; MAX_CONTROL_FRAME_BYTES];
        assert_eq!(fails(&at_limit), ErrorCode::EInvalid);
    }

    #[test]
    fn length_prefix_is_big_endian_and_bounded() {
        assert_eq!(
            frame_control(b"{}").expect("frame"),
            [0, 0, 0, 2, b'{', b'}']
        );
        assert_eq!(control_frame_len([0, 0, 0, 2]).expect("len"), 2);
        let at = u32::try_from(MAX_CONTROL_FRAME_BYTES)
            .expect("fits")
            .to_be_bytes();
        assert_eq!(
            control_frame_len(at).expect("limit"),
            MAX_CONTROL_FRAME_BYTES
        );
        let over = u32::try_from(MAX_CONTROL_FRAME_BYTES + 1)
            .expect("fits")
            .to_be_bytes();
        assert_eq!(
            control_frame_len(over).expect_err("over").code,
            ErrorCode::ELimit
        );
        assert_eq!(
            control_frame_len(u32::MAX.to_be_bytes())
                .expect_err("huge")
                .code,
            ErrorCode::ELimit
        );
        let payload = vec![0_u8; MAX_CONTROL_FRAME_BYTES + 1];
        assert_eq!(
            frame_control(&payload).expect_err("over").code,
            ErrorCode::ELimit
        );
    }

    // ----- sessions and request ids ---------------------------------------

    #[test]
    fn session_rules_follow_the_method_kind() {
        let mut read = envelope(log_request(PageRequest::default()));
        assert!(read.validate().is_ok());
        read.session = None;
        assert_eq!(invalid_code(read.validate()), ErrorCode::EInvalid);

        let mut write = envelope(pin_request());
        write.session = None;
        assert_eq!(invalid_code(write.validate()), ErrorCode::EInvalid);

        let mut open = envelope(Request::SessionOpen(Box::default()));
        assert_eq!(invalid_code(open.validate()), ErrorCode::EInvalid);
        open.session = None;
        assert!(open.validate().is_ok());

        let mut schema = envelope(Request::Schema(Box::default()));
        assert!(schema.validate().is_ok());
        schema.session = None;
        assert!(schema.validate().is_ok());
    }

    #[test]
    fn a_mutation_without_a_request_id_cannot_be_decoded() {
        let mut value = sonic_rs::to_value(&envelope(pin_request())).expect("value");
        value["request"]["pin"]
            .as_object_mut()
            .expect("params object")
            .remove(&"request_id");
        assert_eq!(fails(&to_frame(&value)), ErrorCode::EInvalid);
        assert_eq!(pin_request().request_id(), Some(request_id(1)));
        assert_eq!(log_request(PageRequest::default()).request_id(), None);
    }

    #[test]
    fn admin_methods_take_no_session_and_no_receipt() {
        for method in [
            Method::RepoInit,
            Method::RepoDelete,
            Method::RepoRename,
            Method::RepoFork,
        ] {
            assert_eq!(method.kind(), MethodKind::Admin);
            assert!(!method.is_mutation());
        }
        let request = Request::RepoInit(Box::new(RepoInitArgs {
            root: "default".to_string(),
            path: "acme/hello".to_string(),
            object_format: None,
            default_branch: None,
        }));
        assert_eq!(request.request_id(), None);
        assert_eq!(
            request.digest_input_v1().expect("digestable"),
            None,
            "admin calls leave no digest for receipts"
        );
        let mut reply = Reply::RepoInit(Box::new(RepoInitReply {
            path: "acme/hello".to_string(),
            store_id: StoreId::generate(),
            object_format: HashKind::Sha1,
            default_branch: name("refs/heads/main"),
        }));
        assert_eq!(reply.outcome(), None);
        assert!(reply.outcome_mut().is_none());

        let bare = RequestEnvelope {
            schema_version: SchemaVersion::current(),
            session: None,
            request,
        };
        assert!(bare.validate().is_ok());
        let mut carried = bare.clone();
        carried.session = Some(session());
        assert!(carried.validate().is_ok());

        let forbidden = Request::PolicySet(mutation(
            1,
            PolicySetArgs {
                requirements: Vec::new(),
                trusted_signers: Vec::new(),
            },
        ));
        assert_eq!(forbidden.request_id(), Some(request_id(1)));
        assert!(forbidden.digest_input_v1().expect("digestable").is_some());
    }

    // ----- paging and inline bounds ---------------------------------------

    #[test]
    fn page_limits_default_to_100_and_reject_out_of_range() {
        assert_eq!(PageRequest::default().effective_limit(), DEFAULT_PAGE_SIZE);
        assert_eq!(PageLimit::new(1).expect("min").get(), 1);
        assert_eq!(PageLimit::new(1000).expect("max").get(), MAX_PAGE_SIZE);
        // 65_636 would wrap to 100 under a truncating cast.
        for bad in [0_u32, 1001, 65_636, u32::MAX] {
            assert!(PageLimit::new(bad).is_err(), "{bad}");
        }
        for bad in ["0", "1001", "-1", "1.5", "\"100\""] {
            assert!(sonic_rs::from_str::<PageLimit>(bad).is_err(), "{bad}");
        }
        let page: PageRequest = sonic_rs::from_str("{\"limit\":1000}").expect("page");
        assert_eq!(page.effective_limit(), MAX_PAGE_SIZE);
        for limit in [0, 1001] {
            let mut value =
                sonic_rs::to_value(&envelope(log_request(PageRequest::default()))).expect("value");
            value["request"]["log"]["page"]["limit"] = json!(limit);
            assert_eq!(
                fails(&to_frame(&value)),
                ErrorCode::EInvalid,
                "limit {limit}"
            );
        }
    }

    #[test]
    fn commit_rev_uses_single_key_ref_or_commit_objects() {
        let by_ref = CommitRev::Ref(name("refs/heads/main"));
        let wire = sonic_rs::to_value(&by_ref).expect("json");
        assert_eq!(wire, json!({"ref": "refs/heads/main"}));
        let back: CommitRev = sonic_rs::from_value(&wire).expect("parse");
        assert_eq!(back, by_ref);

        let by_id = CommitRev::Commit(oid(9));
        let wire = sonic_rs::to_value(&by_id).expect("json");
        assert_eq!(wire, json!({"commit": "09".repeat(20)}));
        let back: CommitRev = sonic_rs::from_value(&wire).expect("parse");
        assert_eq!(back, by_id);

        assert!(sonic_rs::from_str::<CommitRev>("{\"REF\": \"refs/heads/main\"}").is_err());
        assert!(by_ref.validate().is_ok());
        assert!(by_id.validate().is_ok());
    }

    #[test]
    fn keyset_pages_are_stateless_and_bounded() {
        let page = KeysetPage::new(vec![1_u32, 2], Some(ByteString::from("ff00"))).expect("page");
        assert_eq!(page.next_after, Some(ByteString::from("ff00")));
        let wire = sonic_rs::to_value(&page).expect("json");
        assert_eq!(wire, json!({"items": [1, 2], "next_after": "ff00"}));
        let back: KeysetPage<u32> = sonic_rs::from_value(&wire).expect("parse");
        assert_eq!(back, page);

        let terminal = KeysetPage::new(vec![1_u32], None).expect("terminal");
        let wire = sonic_rs::to_value(&terminal).expect("json");
        assert_eq!(wire["next_after"], json!(null));
        assert!(terminal.validate().is_ok());

        let over = (0..=MAX_PAGE_SIZE).collect::<Vec<_>>();
        assert_eq!(
            KeysetPage::new(over, None).expect_err("cap").code,
            ErrorCode::ELimit
        );
    }

    #[test]
    fn shared_scalars_keep_their_wire_contracts() {
        let utf8 = ByteString::from("refs/heads/main");
        assert_eq!(
            sonic_rs::to_value(&utf8).expect("json"),
            json!("refs/heads/main")
        );
        let raw = ByteString::new(vec![0xff, 0xfe]);
        assert_eq!(
            sonic_rs::to_value(&raw).expect("json"),
            json!({"hex": "fffe"})
        );
        let back: ByteString = sonic_rs::from_value(&json!({"hex": "fffe"})).expect("parse");
        assert_eq!(back, raw);

        let direct = RefTarget::Direct(oid(3));
        assert_eq!(
            sonic_rs::to_value(&direct).expect("json"),
            json!({"direct": "03".repeat(20)})
        );
        let symbolic = RefTarget::Symbolic(name("refs/heads/main"));
        assert_eq!(
            sonic_rs::to_value(&symbolic).expect("json"),
            json!({"symbolic": "refs/heads/main"})
        );
        assert!(sonic_rs::from_str::<RefTarget>("{\"Direct\": \"00\"}").is_err());
    }

    #[test]
    fn events_tail_bounds_reject_over_limit_and_wait() {
        let args = EventsTailArgs {
            after: 0,
            limit: Some(PageLimit::new(1000).expect("max page")),
            wait_ms: Some(MAX_TAIL_WAIT_MS),
            prefix: None,
        };
        assert!(args.validate().is_ok());

        let over_wait = EventsTailArgs {
            wait_ms: Some(MAX_TAIL_WAIT_MS + 1),
            ..args.clone()
        };
        assert_eq!(
            invalid_code(over_wait.validate()),
            ErrorCode::ELimit,
            "wait past 30000 ms is refused, not clamped"
        );

        assert!(PageLimit::new(1001).is_err());
        let over_limit: Result<EventsTailArgs, _> =
            sonic_rs::from_str("{\"after\":0,\"limit\":1001}");
        assert!(over_limit.is_err(), "limit 1001 never decodes");
        let at_limit: EventsTailArgs =
            sonic_rs::from_str("{\"after\":0,\"limit\":1000}").expect("limit 1000 decodes");
        assert!(at_limit.validate().is_ok());
    }

    #[test]
    fn oversized_cursor_positions_are_invalid() {
        let cursor = |len: usize| PageCursor {
            store: StoreId::generate(),
            view: OperationId(1),
            query: QueryDigest::from_bytes([1; 32]),
            lease: LeaseId::generate(),
            position: ByteString::new(vec![7; len]),
        };
        let page = |len: usize| PageRequest {
            limit: None,
            cursor: Some(cursor(len)),
        };
        assert!(
            log_request(page(MAX_CURSOR_POSITION_BYTES))
                .validate()
                .is_ok()
        );
        assert_eq!(
            invalid_code(log_request(page(MAX_CURSOR_POSITION_BYTES + 1)).validate()),
            ErrorCode::EInvalid
        );
    }

    #[test]
    fn bounded_collections_enforce_their_caps_and_report_truncation() {
        assert!(Page::new((0..=MAX_PAGE_SIZE).collect::<Vec<_>>(), None).is_err());
        assert!(Page::new((0..MAX_PAGE_SIZE).collect::<Vec<_>>(), None).is_ok());
        let cut = BoundedList::excerpt(vec![1, 2, 3], 10).expect("excerpt");
        assert!(cut.truncated);
        assert_eq!(cut.total, 10);
        assert!(!BoundedList::complete(vec![1]).expect("complete").truncated);
        assert!(BoundedList::excerpt(vec![1, 2, 3], 2).is_err());
        let over = (0..=MAX_PAGE_SIZE).collect::<Vec<_>>();
        assert_eq!(
            BoundedList::excerpt(over, 5000).expect_err("cap").code,
            ErrorCode::ELimit
        );
    }

    #[test]
    fn large_mutation_outcome_is_a_truncated_excerpt_that_fits_the_frame() {
        let total = 150_000_u64;
        let retained_count = u64::try_from(MAX_PAGE_SIZE).expect("page cap fits in u64");
        let retained_stamps: Vec<ResultingStamp> = (0..retained_count)
            .map(|sequence| ResultingStamp {
                workspace: workspace(),
                stamp: stamp(sequence),
            })
            .collect();
        let retained_warnings: Vec<Warning> = (0..MAX_PAGE_SIZE)
            .map(|_| Warning::ClaimAdvisory {
                path: path("src/lib.rs"),
                holder: session(),
            })
            .collect();
        let mut outcome = sample_outcome();
        outcome.stamps = BoundedList::excerpt(retained_stamps, total).expect("stamps excerpt");
        outcome.warnings =
            BoundedList::excerpt(retained_warnings, total).expect("warnings excerpt");
        assert_eq!(outcome.stamps.items.len(), MAX_PAGE_SIZE);
        assert_eq!(outcome.stamps.total, total);
        assert!(outcome.stamps.truncated);
        assert_eq!(outcome.warnings.items.len(), MAX_PAGE_SIZE);
        assert_eq!(outcome.warnings.total, total);
        assert!(outcome.warnings.truncated);
        let reply = Reply::WsDrop(Box::new(WsDropReply { outcome }));
        let envelope = ReplyEnvelope::success(Some(request_id(1)), reply);
        let bytes = encode_reply(&envelope).expect("bounded outcome must fit the frame");
        assert!(bytes.len() <= MAX_CONTROL_FRAME_BYTES);
        assert_eq!(decode_reply(&bytes).expect("decode"), envelope);
    }

    #[test]
    fn inline_edits_are_capped_at_one_mebibyte_of_decoded_bytes() {
        let content =
            |data: Value| sonic_rs::from_value::<Content>(&json!({ "inline": { "data": data } }));
        assert!(content(json!("a".repeat(MAX_INLINE_EDIT_BYTES))).is_ok());
        assert!(content(json!("a".repeat(MAX_INLINE_EDIT_BYTES + 1))).is_err());
        // The hex form is measured in decoded bytes, not characters.
        assert!(content(json!({ "hex": "00".repeat(MAX_INLINE_EDIT_BYTES) })).is_ok());
        assert!(content(json!({ "hex": "00".repeat(MAX_INLINE_EDIT_BYTES + 1) })).is_err());
        assert!(InlineBytes::new(ByteString::new(vec![0; MAX_INLINE_EDIT_BYTES + 1])).is_err());
        // Larger content is staged, and a staged reference has no inline cap.
        let staged = Content::Staged {
            object: StagedObject {
                lease: LeaseId::generate(),
                oid: oid(1),
                size: 10 * 1024 * 1024,
            },
        };
        let json = sonic_rs::to_string(&staged).expect("json");
        assert_eq!(sonic_rs::from_str::<Content>(&json).expect("parse"), staged);
    }

    // ----- request invariants ---------------------------------------------

    #[test]
    fn write_requests_reject_duplicate_colliding_and_empty_edits() {
        let check = |edits: Vec<WriteEdit>| write_request(edits).validate();
        assert!(check(vec![put("a.txt", b"x"), put("b/c.txt", b"y")]).is_ok());
        assert!(check(vec![]).is_err());
        assert!(check(vec![put("a", b"1"), put("a", b"2")]).is_err());
        assert!(check(vec![put("a", b"1"), delete("a")]).is_err());
        assert!(check(vec![put("a", b"1"), put("a/b", b"2")]).is_err());
        assert!(check(vec![put("a/b", b"2"), put("a", b"1")]).is_err());
        assert!(check(vec![put("a/b/c", b"2"), put("a", b"1")]).is_err());
        // Replacing a file with a directory in one atomic write is allowed.
        assert!(check(vec![delete("a"), put("a/b", b"2")]).is_ok());
        // A shared string prefix is not a shared directory.
        assert!(check(vec![put("ab", b"1"), put("a/b", b"2")]).is_ok());
        let empty_link = WriteEdit {
            path: path("link"),
            action: EditAction::Symlink {
                target: ByteString::default(),
            },
        };
        assert!(check(vec![empty_link]).is_err());
        let nul_link = WriteEdit {
            path: path("link"),
            action: EditAction::Symlink {
                target: ByteString::new(vec![b'a', 0, b'b']),
            },
        };
        assert!(check(vec![nul_link]).is_err());
    }

    #[test]
    fn ref_updates_need_their_namespace_and_a_stated_old_value() {
        let present = RefExpect::Present(RefTarget::Direct(oid(2)));
        let set = |ref_name: &str, expected: RefExpect| {
            Request::BookmarkSet(mutation(
                1,
                BookmarkSetArgs {
                    name: name(ref_name),
                    target: BookmarkTarget::Commit { oid: oid(1) },
                    expected,
                },
            ))
            .validate()
        };
        assert!(set("refs/heads/main", RefExpect::Absent).is_ok());
        assert!(set("refs/heads/main", present.clone()).is_ok());
        assert!(set("refs/heads/main", RefExpect::Any).is_err());
        assert!(set("refs/tags/v1", RefExpect::Absent).is_err());

        let delete_bookmark = |ref_name: &str, expected: RefExpect| {
            Request::BookmarkDelete(mutation(
                1,
                BookmarkDeleteArgs {
                    name: name(ref_name),
                    expected,
                },
            ))
            .validate()
        };
        assert!(delete_bookmark("refs/heads/main", present.clone()).is_ok());
        assert!(delete_bookmark("refs/heads/main", RefExpect::Absent).is_err());
        assert!(delete_bookmark("refs/heads/main", RefExpect::Any).is_err());

        let tag = |ref_name: &str, expected: RefExpect| {
            Request::TagSet(mutation(
                1,
                TagSetArgs {
                    name: name(ref_name),
                    target: oid(1),
                    annotation: None,
                    expected,
                },
            ))
            .validate()
        };
        assert!(tag("refs/tags/v1", RefExpect::Absent).is_ok());
        assert!(tag("refs/heads/v1", RefExpect::Absent).is_err());
        assert!(tag("refs/tags/v1", RefExpect::Any).is_err());

        let delete_tag = |expected: RefExpect| {
            Request::TagDelete(mutation(
                1,
                TagDeleteArgs {
                    name: name("refs/tags/v1"),
                    expected,
                },
            ))
            .validate()
        };
        assert!(delete_tag(present).is_ok());
        assert!(delete_tag(RefExpect::Absent).is_err());
    }

    #[test]
    fn collection_arguments_reject_empty_and_duplicate_members() {
        let change = ChangeId::from_bytes([7; 16]);
        let target = ChangeRef { change, head: None };
        let rebase = |sources: Vec<ChangeRef>, onto: Vec<Head>| {
            Request::Rebase(mutation(
                1,
                RebaseArgs {
                    sources,
                    scope: RebaseScope::SourceAndDescendants,
                    onto,
                    merge: MergeSelection::default(),
                    keep_empty: false,
                    workspaces: Vec::new(),
                },
            ))
            .validate()
        };
        assert!(rebase(vec![target], vec![head(1)]).is_ok());
        assert!(rebase(vec![], vec![head(1)]).is_err());
        assert!(rebase(vec![target], vec![]).is_err());
        assert!(rebase(vec![target, target], vec![head(1)]).is_err());
        assert!(rebase(vec![target], vec![head(1), head(1)]).is_err());

        let squash = |source: ChangeRef, destination: ChangeRef| {
            Request::Squash(mutation(
                1,
                SquashArgs {
                    source,
                    destination,
                    paths: PathSelection::All,
                    description: None,
                    keep_empty: false,
                    identity: None,
                    merge: MergeSelection::default(),
                    workspaces: Vec::new(),
                },
            ))
            .validate()
        };
        let other = ChangeRef {
            change: ChangeId::from_bytes([8; 16]),
            head: None,
        };
        assert!(squash(target, other).is_ok());
        assert!(squash(target, target).is_err());

        let split = |paths: PathSelection| {
            Request::Split(mutation(
                1,
                SplitArgs {
                    source: target,
                    paths,
                    placement: SplitPlacement::SelectedFirst,
                    description: ByteString::from("part"),
                    identity: None,
                    merge: MergeSelection::default(),
                    workspaces: Vec::new(),
                },
            ))
            .validate()
        };
        assert!(split(PathSelection::Paths(vec![path("a")])).is_ok());
        assert!(split(PathSelection::All).is_err());
        assert!(split(PathSelection::Paths(vec![])).is_err());
        assert!(split(PathSelection::Paths(vec![path("a"), path("a")])).is_err());

        let describe = |workspaces: Vec<WorkspaceBinding>| {
            Request::Describe(mutation(
                1,
                DescribeArgs {
                    target,
                    description: ByteString::from("d"),
                    identity: None,
                    workspaces,
                },
            ))
            .validate()
        };
        assert!(describe(vec![binding(1)]).is_ok());
        assert!(describe(vec![binding(1), binding(2)]).is_err());
    }

    #[test]
    fn push_updates_must_be_unique_and_self_consistent() {
        let update =
            |ref_name: &str, source: PushSource, expected: Option<RemoteExpect>| PushUpdate {
                remote_ref: name(ref_name),
                source,
                expected_old: expected,
                force: false,
            };
        let push = |updates: Vec<PushUpdate>| {
            Request::Push(mutation(
                1,
                PushArgs {
                    remote: RemoteSpec::Named {
                        name: RemoteName::new("origin").expect("remote"),
                    },
                    updates,
                    atomicity: PushAtomicity::default(),
                },
            ))
            .validate()
        };
        let main = |expected| {
            update(
                "refs/heads/main",
                PushSource::Commit { oid: oid(1) },
                expected,
            )
        };
        assert!(push(vec![main(None)]).is_ok());
        assert!(push(vec![main(Some(RemoteExpect::Absent))]).is_ok());
        assert!(push(vec![]).is_err());
        assert!(push(vec![main(None), main(None)]).is_err());
        let delete_expecting_absent = update(
            "refs/heads/gone",
            PushSource::Delete,
            Some(RemoteExpect::Absent),
        );
        assert!(push(vec![delete_expecting_absent]).is_err());
        let delete_existing = update(
            "refs/heads/gone",
            PushSource::Delete,
            Some(RemoteExpect::Present { oid: oid(2) }),
        );
        assert!(push(vec![delete_existing]).is_ok());
        assert_eq!(PushAtomicity::default(), PushAtomicity::Atomic);
    }

    #[test]
    fn claim_lifetimes_are_between_one_second_and_one_hour() {
        assert!(ClaimTtl::new(1).is_ok());
        assert!(ClaimTtl::new(MAX_CLAIM_TTL_SECONDS).is_ok());
        assert!(ClaimTtl::new(0).is_err());
        assert!(ClaimTtl::new(MAX_CLAIM_TTL_SECONDS + 1).is_err());
        assert!(sonic_rs::from_str::<ClaimTtl>("3600").is_ok());
        assert!(sonic_rs::from_str::<ClaimTtl>("3601").is_err());
        let acquire = |paths: Vec<RepoPath>| {
            Request::ClaimAcquire(mutation(
                1,
                ClaimAcquireArgs {
                    paths,
                    ttl: ClaimTtl::new(60).expect("ttl"),
                    mode: ClaimMode::default(),
                },
            ))
            .validate()
        };
        assert!(acquire(vec![path("src")]).is_ok());
        assert!(acquire(vec![]).is_err());
        assert!(acquire(vec![path("src"), path("src")]).is_err());
        assert_eq!(ClaimMode::default(), ClaimMode::Enforce);
    }

    #[test]
    fn identity_claims_cannot_forge_header_lines() {
        let claim = |name: &str, email: &str| IdentityClaim {
            name: name.to_owned(),
            email: email.to_owned(),
        };
        assert!(claim("Ada Lovelace", "ada@example.org").validate().is_ok());
        for (name, email) in [
            ("a\nparent 0000", "e@x"),
            ("a", "e@x>\ncommitter x"),
            ("a<b", "e@x"),
            ("a", "e>x"),
            ("", "e@x"),
            ("a", ""),
            ("a\0b", "e@x"),
            ("a", "e\r@x"),
        ] {
            assert!(claim(name, email).validate().is_err(), "{name:?} {email:?}");
        }
        let forged = Request::New(mutation(
            1,
            NewArgs {
                parents: vec![],
                description: ByteString::from("m"),
                identity: Some(claim("a\nb", "e@x")),
                workspace: None,
            },
        ));
        assert!(forged.validate().is_err());
    }

    #[test]
    fn session_claims_and_commit_provenance_share_one_claim_grammar() {
        let open = |claims: Value| {
            let mut value = sonic_rs::to_value(&RequestEnvelope {
                session: None,
                ..envelope(Request::SessionOpen(Box::default()))
            })
            .expect("value");
            value["request"]["session.open"]["claims"] = claims;
            to_frame(&value)
        };
        let kept = |claims: Value| {
            sonic_rs::from_value::<Provenance>(&json!({ "session": session(), "claims": claims }))
        };
        let one = |key: &str, value: &str| {
            sonic_rs::to_value(&BTreeMap::from([(key, value)])).expect("claims")
        };

        // Printable-ASCII keys a looser commit-side grammar once admitted, and
        // values no claim may carry: neither path accepts any of them.
        for (key, value) in [
            ("Agent", "x"),
            ("agent:id", "x"),
            ("a/b", "x"),
            ("task id", "x"),
            ("agent", "two\nlines"),
            ("agent", "bell\u{7}"),
        ] {
            assert_eq!(
                fails(&open(one(key, value))),
                ErrorCode::EInvalid,
                "session.open {key:?}"
            );
            assert!(kept(one(key, value)).is_err(), "provenance {key:?}");
        }

        // What a session may declare, a commit record keeps through serde.
        let declared =
            || json!({ "agent": "claude", "task.id": "42", "run_2-b": "ü x; y", "k": "" });
        let Request::SessionOpen(args) =
            decode_request(&open(declared())).expect("admitted").request
        else {
            panic!("expected session.open");
        };
        let payload = format!(
            "tree {}\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n\nm\n",
            oid(1)
        )
        .into_bytes();
        let record = CommitRecord::import_git(
            payload,
            HashKind::Sha1,
            ChangeId::from_bytes([7; 16]),
            Some(Provenance::new(session(), args.claims)),
        )
        .expect("record");
        let packed = postcard::to_allocvec(&record).expect("postcard");
        let expected: BTreeMap<String, String> =
            sonic_rs::from_value(&declared()).expect("claims map");
        for back in [
            sonic_rs::from_slice::<CommitRecord>(&sonic_rs::to_vec(&record).expect("json"))
                .expect("json back"),
            postcard::from_bytes::<CommitRecord>(&packed).expect("postcard back"),
        ] {
            assert_eq!(
                back.provenance().map(|kept| kept.claims().as_map()),
                Some(&expected)
            );
            assert_eq!(back, record);
        }
    }

    #[test]
    fn requested_capabilities_are_validated_when_a_session_opens() {
        let mut value = sonic_rs::to_value(&RequestEnvelope {
            session: None,
            ..envelope(Request::SessionOpen(Box::default()))
        })
        .expect("value");
        value["request"]["session.open"]["capabilities"] = json!({ "push_refs": ["not-a-ref"] });
        assert_eq!(fails(&to_frame(&value)), ErrorCode::EInvalid);
        value["request"]["session.open"]["capabilities"] =
            json!({ "write_changes": "own", "push_refs": ["refs/heads/agent/**"] });
        let decoded = decode_request(&to_frame(&value)).expect("valid capabilities");
        let Request::SessionOpen(args) = decoded.request else {
            panic!("expected session.open");
        };
        assert_eq!(
            args.capabilities.and_then(|caps| caps.write_changes),
            Some(crate::capability::WriteScope::Own)
        );
    }

    // ----- digest and attestation payload ---------------------------------

    #[test]
    fn digest_input_ignores_the_request_id_and_covers_stamps_and_method() {
        let snapshot = |n: u8, sequence: u64| {
            Request::Snapshot(mutation(
                n,
                SnapshotArgs {
                    binding: binding(sequence),
                },
            ))
        };
        let input = |request: &Request| {
            request
                .digest_input_v1()
                .expect("encodable")
                .expect("a mutation has a digest")
        };
        assert_eq!(input(&snapshot(1, 4)), input(&snapshot(2, 4)));
        assert_ne!(input(&snapshot(1, 4)), input(&snapshot(1, 5)));
        let fenced = Request::Snapshot(mutation(
            1,
            SnapshotArgs {
                binding: WorkspaceBinding {
                    workspace: workspace(),
                    expected: WorkspaceStamp {
                        sequence: 4,
                        lease_epoch: 2,
                    },
                },
            },
        ));
        assert_ne!(input(&snapshot(1, 4)), input(&fenced));

        // The same arguments under a different method are a different request.
        let unpin = Request::Unpin(mutation(1, UnpinArgs { head: head(1) }));
        assert_ne!(input(&pin_request()), input(&unpin));

        // The first field is the length-prefixed domain separator.
        let domain_len = u32::try_from(DIGEST_DOMAIN_V1.len())
            .expect("fits")
            .to_be_bytes();
        let pinned = input(&pin_request());
        assert_eq!(&pinned[..4], &domain_len);
        assert_eq!(&pinned[4..4 + DIGEST_DOMAIN_V1.len()], DIGEST_DOMAIN_V1);

        // Reads and bootstrap calls have no receipt, hence no digest.
        assert!(
            log_request(PageRequest::default())
                .digest_input_v1()
                .expect("ok")
                .is_none()
        );
        let open = Request::SessionOpen(Box::default());
        assert!(open.digest_input_v1().expect("ok").is_none());
    }

    fn statement(kind: &str, result: &str) -> AttestStatement {
        AttestStatement {
            subject: oid(7),
            kind: AttestKind::new(kind).expect("kind"),
            result: AttestResult::new(result).expect("result"),
            signed_at: timestamp("2026-10-17T12:00:00Z"),
            supersedes: None,
            evidence: None,
        }
    }

    fn split_fields(payload: &[u8]) -> Vec<Vec<u8>> {
        let mut fields = Vec::new();
        let mut rest = payload;
        while !rest.is_empty() {
            let (prefix, tail) = rest.split_at(4);
            let length = usize::try_from(u32::from_be_bytes(prefix.try_into().expect("4 bytes")))
                .expect("fits");
            let (field, tail) = tail.split_at(length);
            fields.push(field.to_vec());
            rest = tail;
        }
        fields
    }

    #[test]
    fn attestation_payload_has_seven_unambiguous_length_prefixed_fields() {
        let payload = statement("a", "bc")
            .canonical_payload_v1(HashKind::Sha1)
            .expect("payload");
        let fields = split_fields(&payload);
        assert_eq!(fields.len(), 7);
        assert_eq!(fields[0], ATTEST_PAYLOAD_DOMAIN_V1);
        assert_eq!(fields[1], b"sha1");
        assert_eq!(fields[2], oid(7).as_bytes());
        assert_eq!(fields[3], b"a");
        assert_eq!(fields[4], b"bc");
        assert_eq!(fields[5], b"2026-10-17T12:00:00Z");
        assert!(fields[6].is_empty());

        // Moving a character across the kind/result boundary changes the payload.
        let shifted = statement("ab", "c")
            .canonical_payload_v1(HashKind::Sha1)
            .expect("payload");
        assert_ne!(payload, shifted);

        // Presence of a superseded digest is distinguishable from absence and
        // the digest itself is covered.
        let supersede = |byte: u8| {
            let mut with = statement("a", "bc");
            with.supersedes = Some(StatementDigest::from_bytes([byte; 32]));
            with.canonical_payload_v1(HashKind::Sha1).expect("payload")
        };
        assert_ne!(payload, supersede(1));
        assert_ne!(supersede(1), supersede(2));
        assert_eq!(split_fields(&supersede(1))[6], vec![1_u8; 32]);

        let mut later = statement("a", "bc");
        later.signed_at = timestamp("2026-10-17T12:00:01Z");
        assert_ne!(
            payload,
            later.canonical_payload_v1(HashKind::Sha1).expect("payload")
        );
    }

    #[test]
    fn attestation_payload_rejects_a_subject_of_the_wrong_object_format() {
        let err = statement("a", "b")
            .canonical_payload_v1(HashKind::Sha256)
            .expect_err("a sha1 subject in a sha256 repository");
        assert_eq!(err.code, ErrorCode::EObjectFormat);
    }

    #[test]
    fn attestation_payload_v2_has_eight_fields_and_binds_evidence() {
        let plain = statement("a", "bc");
        let payload = plain.canonical_payload_v2(HashKind::Sha1).expect("payload");
        let fields = split_fields(&payload);
        assert_eq!(fields.len(), 8);
        assert_eq!(fields[0], ATTEST_PAYLOAD_DOMAIN_V2);
        assert_eq!(fields[1], b"sha1");
        assert_eq!(fields[2], oid(7).as_bytes());
        assert_eq!(fields[3], b"a");
        assert_eq!(fields[4], b"bc");
        assert_eq!(fields[5], b"2026-10-17T12:00:00Z");
        assert!(fields[6].is_empty());
        assert!(fields[7].is_empty());

        // The domain bump alone separates the versions: the same statement
        // signs different bytes under v1 and v2.
        let v1 = plain
            .canonical_payload_v1(HashKind::Sha1)
            .expect("v1 payload");
        assert_ne!(v1, payload);

        // Evidence is covered: one byte changes the payload.
        let digest = |byte: u8| StatementDigest::from_bytes([byte; 32]);
        let bound = |evidence: Option<StatementDigest>| {
            let mut with = statement("a", "bc");
            with.evidence = evidence;
            with.canonical_payload_v2(HashKind::Sha1).expect("payload")
        };
        assert_ne!(payload, bound(Some(digest(1))));
        assert_ne!(bound(Some(digest(1))), bound(Some(digest(2))));
        // Absence and a zero digest are distinct on the wire.
        assert_eq!(split_fields(&bound(Some(digest(0))))[7], vec![0_u8; 32]);
        assert_ne!(payload, bound(Some(digest(0))));
    }

    #[test]
    fn attestation_payload_v2_rejects_a_subject_of_the_wrong_object_format() {
        let err = statement("a", "b")
            .canonical_payload_v2(HashKind::Sha256)
            .expect_err("a sha1 subject in a sha256 repository");
        assert_eq!(err.code, ErrorCode::EObjectFormat);
    }

    #[test]
    fn attestation_payload_v1_refuses_a_statement_carrying_evidence() {
        let mut with = statement("a", "b");
        with.evidence = Some(StatementDigest::from_bytes([9; 32]));
        let err = with
            .canonical_payload_v1(HashKind::Sha1)
            .expect_err("v1 cannot bind evidence");
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn attestation_text_and_signatures_are_shape_checked() {
        assert!(SignerFingerprint::new(format!("SHA256:{}", "A".repeat(43))).is_ok());
        for bad in [
            format!("SHA256:{}", "A".repeat(42)),
            format!("SHA256:{}", "A".repeat(44)),
            format!("MD5:{}", "A".repeat(43)),
            format!("SHA256:{}!", "A".repeat(42)),
        ] {
            assert!(SignerFingerprint::new(bad.clone()).is_err(), "{bad}");
        }
        let armor = format!("{SIGNATURE_BEGIN}\nAAAA\n{SIGNATURE_END}\n");
        assert!(AttestSignature::new(armor).is_ok());
        for bad in [
            "AAAA".to_owned(),
            format!("{SIGNATURE_BEGIN}\nAAAA"),
            format!("{SIGNATURE_BEGIN}\n\u{e9}\n{SIGNATURE_END}"),
        ] {
            assert!(AttestSignature::new(bad.clone()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn attest_add_accepts_long_kind_and_result_below_frame_cap() {
        let kind = "k".repeat(300);
        let result = "r".repeat(300);
        let signature = AttestSignature::new(format!("{SIGNATURE_BEGIN}\nAAAA\n{SIGNATURE_END}\n"))
            .expect("signature");
        let args = AttestAddArgs {
            statement: statement(&kind, &result),
            signature,
        };
        let original = envelope(Request::AttestAdd(mutation(1, args)));
        let bytes = encode_request(&original).expect("long attest.add must fit the frame");
        assert!(bytes.len() <= MAX_CONTROL_FRAME_BYTES);
        assert_eq!(decode_request(&bytes).expect("decode"), original);
    }

    // ----- primitives -----------------------------------------------------

    #[test]
    fn timestamps_are_utc_only_and_round_trip() {
        let ts = timestamp("2026-10-17T12:00:00Z");
        assert_eq!(ts.to_string(), "2026-10-17T12:00:00Z");
        assert_eq!(
            sonic_rs::to_string(&ts).expect("json"),
            "\"2026-10-17T12:00:00Z\""
        );
        for bad in [
            "2026-10-17T12:00:00+02:00",
            "2026-10-17T12:00:00",
            "yesterdayZ",
            "",
            "2026-13-40T00:00:00Z",
        ] {
            assert!(Timestamp::parse(bad).is_err(), "{bad}");
            assert!(
                sonic_rs::from_value::<Timestamp>(&json!(bad)).is_err(),
                "{bad}"
            );
        }
        let fine = timestamp("2026-10-17T12:00:00.123456789Z");
        let packed = postcard::to_allocvec(&fine).expect("postcard");
        assert_eq!(
            postcard::from_bytes::<Timestamp>(&packed).expect("unpack"),
            fine
        );
        assert!(ts < fine);
    }

    #[test]
    fn digests_are_strict_lowercase_hex_and_secrets_do_not_print() {
        let digest = RequestDigest::from_bytes([0xab; 32]);
        assert_eq!(
            sonic_rs::to_string(&digest).expect("json"),
            format!("\"{}\"", "ab".repeat(32))
        );
        let packed = postcard::to_allocvec(&digest).expect("postcard");
        assert_eq!(
            postcard::from_bytes::<RequestDigest>(&packed).expect("unpack"),
            digest
        );
        for bad in [
            "ab".repeat(31),
            "AB".repeat(32),
            "zz".repeat(32),
            "ab".repeat(33),
            String::new(),
        ] {
            assert!(RequestDigest::from_hex(&bad).is_err(), "{bad}");
            assert!(
                sonic_rs::from_value::<RequestDigest>(&json!(bad)).is_err(),
                "{bad}"
            );
        }

        let secret = ReconnectSecret::from_bytes([0x5a; 32]);
        assert!(!format!("{secret:?}").contains("5a5a"));
        let reply = SessionOpenReply {
            session: session(),
            reconnect_secret: secret,
            principal: "agent".to_owned(),
            capabilities: Capabilities::default(),
            idle_expires_at: timestamp("2026-10-18T12:00:00Z"),
        };
        assert!(!format!("{reply:?}").contains("5a5a"));
        assert!(secret.ct_eq(&ReconnectSecret::from_bytes([0x5a; 32])));
        let mut other = [0x5a_u8; 32];
        other[31] = 0x5b;
        assert!(!secret.ct_eq(&ReconnectSecret::from_bytes(other)));
    }

    // ----- round trips ----------------------------------------------------

    fn sample_outcome() -> MutationOutcome {
        MutationOutcome {
            receipt: ReceiptRef {
                session: session(),
                request_id: request_id(1),
                digest: RequestDigest::from_bytes([9; 32]),
                replayed: false,
                retained_until: timestamp("2026-10-24T12:00:00Z"),
            },
            operation: Some(OperationId(3)),
            heads: BoundedList::complete(vec![ChangeHead {
                change: ChangeId::from_bytes([7; 16]),
                head: head(5),
            }])
            .expect("heads"),
            stamps: BoundedList::complete(vec![ResultingStamp {
                workspace: workspace(),
                stamp: stamp(5),
            }])
            .expect("stamps"),
            warnings: BoundedList::complete(vec![Warning::ClaimAdvisory {
                path: path("src/lib.rs"),
                holder: session(),
            }])
            .expect("warnings"),
            merge: None,
            provenance: BoundedList::complete(vec![PathProvenance {
                path: path("src/lib.rs"),
                session: session(),
                driver: Some(DriverDecision {
                    driver: MergeDriver::Syntax,
                    language: Some("rust".to_owned()),
                    grammar_version: Some("0.24.2".to_owned()),
                }),
            }])
            .expect("provenance"),
            identity: Some(EffectiveIdentity {
                name: "Ada".to_owned(),
                email: "ada@example.org".to_owned(),
                source: IdentitySource::SessionClaim,
            }),
        }
    }

    #[test]
    fn typed_requests_round_trip_through_json_and_postcard() {
        let claims =
            ProvenanceClaims::new(BTreeMap::from([("agent".to_owned(), "claude".to_owned())]))
                .expect("claims");
        let capabilities = Capabilities {
            write_changes: Some(crate::capability::WriteScope::Own),
            push_refs: vec![RefPattern::parse("refs/heads/agent/**").expect("pattern")],
            ..Capabilities::default()
        };
        let open = RequestEnvelope {
            session: None,
            ..envelope(Request::SessionOpen(Box::new(SessionOpenArgs {
                identity: Some(IdentityClaim {
                    name: "Ada".to_owned(),
                    email: "ada@example.org".to_owned(),
                }),
                claims,
                capabilities: Some(capabilities),
            })))
        };
        let push = Request::Push(mutation(
            9,
            PushArgs {
                remote: RemoteSpec::Url {
                    url: RemoteUrl::new("https://example.org/r.git").expect("url"),
                },
                updates: vec![PushUpdate {
                    remote_ref: name("refs/heads/main"),
                    source: PushSource::Commit { oid: oid(3) },
                    expected_old: Some(RemoteExpect::Present { oid: oid(2) }),
                    force: true,
                }],
                atomicity: PushAtomicity::NonAtomic,
            },
        ));
        let terms: Merge<Option<Oid>> =
            sonic_rs::from_value(&json!([oid(1).to_hex(), null, oid(2).to_hex()]))
                .expect("conflict terms");
        let resolve_bookmark = Request::BookmarkResolve(mutation(
            4,
            BookmarkResolveArgs {
                name: name("refs/heads/main"),
                expected_terms: terms,
                resolution: BookmarkResolution::Set { oid: oid(1) },
            },
        ));
        let schema = Request::Schema(Box::new(SchemaArgs {
            method: Some(Method::Write),
        }));
        let requests = vec![
            envelope(write_request(vec![put("a", b"\xff\x00"), delete("b")])),
            open,
            envelope(push),
            envelope(resolve_bookmark),
            envelope(schema),
            envelope(log_request(PageRequest {
                limit: Some(PageLimit::new(250).expect("limit")),
                cursor: None,
            })),
        ];
        for original in requests {
            let json = encode_request(&original).expect("encode");
            assert_eq!(decode_request(&json).expect("decode"), original);
            let packed = postcard::to_allocvec(&original).expect("postcard");
            let unpacked: RequestEnvelope = postcard::from_bytes(&packed).expect("unpack");
            assert_eq!(unpacked, original);
        }
    }

    #[test]
    fn mutation_replies_round_trip_through_json_and_postcard_for_receipts() {
        let record = ClaimRecord {
            claim: ClaimId::generate(),
            holder: session(),
            paths: vec![path("src")],
            mode: ClaimMode::Advise,
            expires_at: timestamp("2026-10-17T13:00:00Z"),
            on_behalf_of: None,
        };
        let release = Reply::ClaimRelease(Box::new(ClaimReleaseReply {
            outcome: sample_outcome(),
            released: record.clone(),
        }));
        let list = Reply::ClaimList(Box::new(ClaimListReply {
            view: ViewInfo {
                store: StoreId::generate(),
                view: OperationId(9),
            },
            claims: Page::new(
                vec![record],
                Some(PageCursor {
                    store: StoreId::generate(),
                    view: OperationId(9),
                    query: QueryDigest::from_bytes([3; 32]),
                    lease: LeaseId::generate(),
                    position: ByteString::from("src"),
                }),
            )
            .expect("page"),
        }));
        for reply in [release, list] {
            let envelope = ReplyEnvelope::success(Some(request_id(1)), reply);
            let json = encode_reply(&envelope).expect("encode");
            assert_eq!(decode_reply(&json).expect("decode"), envelope);
            let packed = postcard::to_allocvec(&envelope).expect("postcard");
            let unpacked: ReplyEnvelope = postcard::from_bytes(&packed).expect("unpack");
            assert_eq!(unpacked, envelope);
        }
    }

    fn schema_success(document: Schema) -> ReplyEnvelope {
        ReplyEnvelope::success(
            Some(request_id(1)),
            Reply::Schema(Box::new(SchemaReply {
                schema_version: SchemaVersion::current(),
                methods: Vec::new(),
                document,
            })),
        )
    }

    #[test]
    fn schema_documents_accept_object_and_boolean_roots() {
        for text in [r#"{"type":"object"}"#, "true", "false"] {
            let document: Schema = decode_json(text.as_bytes()).expect("schema root");
            let envelope = schema_success(document);
            let bytes = encode_reply(&envelope).expect("encode");
            assert_eq!(decode_reply(&bytes).expect("decode"), envelope);
        }
    }

    #[test]
    fn schema_documents_reject_scalar_roots() {
        for text in [b"[]" as &[u8], b"\"x\"", b"1", b"null"] {
            assert!(
                decode_json::<Schema>(text).is_err(),
                "{}",
                text.escape_ascii()
            );
        }
        let template = sonic_rs::to_value(&schema_success(json_schema!(true))).expect("template");
        for root in [json!([]), json!("x"), json!(1), json!(null)] {
            let mut frame = template.clone();
            frame["body"]["success"]["schema"]["document"] = root;
            assert_eq!(
                decode_reply(&to_frame(&frame))
                    .expect_err("scalar root")
                    .code,
                ErrorCode::EInvalid
            );
        }
    }

    /// Internally tagged, so serde buffers `document` through its private
    /// `Content` and replays it into [`Schema`]. The real externally
    /// tagged `Reply` does not buffer; these carriers stand in for
    /// containers that do (internally tagged, untagged, flatten).
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum TaggedSchema {
        Schema { document: Schema },
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(untagged)]
    enum UntaggedSchema {
        Schema { document: Schema },
        Other { count: u32 },
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct FlattenedSchema {
        name: String,
        #[serde(flatten)]
        document: Schema,
    }

    #[test]
    fn schema_replays_through_tagged_untagged_and_flattened_carriers() {
        let object: Schema =
            decode_json(br#"{"type":"object","properties":{"path":{"type":"string"}}}"#)
                .expect("object schema");
        let tagged = TaggedSchema::Schema {
            document: object.clone(),
        };
        let wire = sonic_rs::to_vec(&tagged).expect("encode tagged");
        assert_eq!(
            sonic_rs::from_slice::<TaggedSchema>(&wire).expect("tagged replay"),
            tagged
        );
        assert_eq!(
            decode_json::<TaggedSchema>(&wire).expect("checked tagged"),
            tagged
        );

        let untagged = UntaggedSchema::Schema {
            document: object.clone(),
        };
        let wire = sonic_rs::to_vec(&untagged).expect("encode untagged");
        assert_eq!(
            sonic_rs::from_slice::<UntaggedSchema>(&wire).expect("untagged replay"),
            untagged
        );
        assert_eq!(
            decode_json::<UntaggedSchema>(&wire).expect("checked untagged"),
            untagged
        );
        let other = UntaggedSchema::Other { count: 7 };
        let wire = sonic_rs::to_vec(&other).expect("encode other");
        assert_eq!(
            decode_json::<UntaggedSchema>(&wire).expect("checked other"),
            other
        );

        let flat = FlattenedSchema {
            name: "write".to_owned(),
            document: object.clone(),
        };
        let wire = sonic_rs::to_vec(&flat).expect("encode flattened");
        assert_eq!(
            sonic_rs::from_slice::<FlattenedSchema>(&wire).expect("flattened replay"),
            flat
        );
        assert_eq!(
            decode_json::<FlattenedSchema>(&wire).expect("checked flattened"),
            flat
        );

        let boolean: Schema = decode_json(b"true").expect("boolean schema");
        let wire = sonic_rs::to_vec(&TaggedSchema::Schema {
            document: boolean.clone(),
        })
        .expect("encode tagged bool");
        assert_eq!(
            decode_json::<TaggedSchema>(&wire).expect("tagged bool"),
            TaggedSchema::Schema { document: boolean }
        );
    }

    #[test]
    fn nesting_guard_rejects_deep_unknown_fields_at_the_codec() {
        let original = envelope(pin_request());
        let mut base = sonic_rs::to_string(&original).expect("json");
        assert!(base.ends_with('}'));
        base.pop();

        // Root container counts as depth 1; 127 nested containers inside an
        // unknown field reach exactly depth 128 and genuinely decode.
        let mut valid_128 = base.clone();
        valid_128.push_str(&format!(
            ",\"future\":{}{}}}",
            "[".repeat(MAX_JSON_NESTING - 1),
            "]".repeat(MAX_JSON_NESTING - 1)
        ));
        let decoded = decode_request(valid_128.as_bytes()).expect("genuinely valid 128 decode");
        assert_eq!(decoded.request, original.request);

        // 128 nested containers inside the root reach depth 129 and are rejected
        // with E_INVALID before the recursive sonic parser touches them.
        let mut over_129 = base.clone();
        over_129.push_str(&format!(
            ",\"future\":{}{}}}",
            "[".repeat(MAX_JSON_NESTING),
            "]".repeat(MAX_JSON_NESTING)
        ));
        assert_eq!(fails(over_129.as_bytes()), ErrorCode::EInvalid);

        // An unclosed deep unknown field past 128 is likewise rejected at the boundary.
        let mut unclosed = base.clone();
        unclosed.push_str(&format!(",\"future\":{}", "[".repeat(MAX_JSON_NESTING)));
        assert_eq!(fails(unclosed.as_bytes()), ErrorCode::EInvalid);

        // Quoted and escaped brackets inside strings do not count as structure;
        // premature closers do not underflow the counter.
        let mut quoted = base;
        quoted.push_str(&format!(
            ",\"junk\":\"\\\"}}}}}}[[[]]\\\\\\\\\",\"bracket_string\":\"{}\"}}",
            "[".repeat(MAX_JSON_NESTING + 50)
        ));
        let decoded_quoted = decode_request(quoted.as_bytes()).expect("quoted brackets ignored");
        assert_eq!(decoded_quoted.request, original.request);
    }

    #[test]
    fn nesting_guard_holds_as_a_public_boundary() {
        assert!(check_json_nesting(b"{}").is_ok());
        let ok = format!(
            "{}{}",
            "[".repeat(MAX_JSON_NESTING),
            "]".repeat(MAX_JSON_NESTING)
        );
        assert!(check_json_nesting(ok.as_bytes()).is_ok());
        let over = format!(
            "{}{}",
            "[".repeat(MAX_JSON_NESTING + 1),
            "]".repeat(MAX_JSON_NESTING + 1)
        );
        assert_eq!(
            invalid_code(check_json_nesting(over.as_bytes())),
            ErrorCode::EInvalid
        );
        let unclosed = "[".repeat(MAX_JSON_NESTING);
        assert!(check_json_nesting(unclosed.as_bytes()).is_ok());
        let stray = b"]]]}{".repeat(40);
        assert!(
            check_json_nesting(stray.as_slice()).is_ok(),
            "closers never underflow"
        );
        let quoted = b"{\"a\":\"}}]]}{[[\"}";
        assert!(check_json_nesting(quoted.as_slice()).is_ok());
        let escaped = b"{\"a\":\"edge\\\\\\\"case\"}";
        assert!(check_json_nesting(escaped.as_slice()).is_ok());
    }

    fn nested_objects(depth: usize, innermost: &str) -> String {
        let wrappers = depth - 1;
        format!(
            "{}{innermost}{}",
            "{\"a\":".repeat(wrappers),
            "}".repeat(wrappers)
        )
    }

    #[test]
    fn object_nesting_holds_the_bound_through_every_decoder() {
        let at_bound = nested_objects(MAX_JSON_NESTING, "{}");
        let document: Schema = decode_json(at_bound.as_bytes()).expect("128 objects");
        let rendered = sonic_rs::to_vec(&document).expect("render");
        assert_eq!(rendered, at_bound.into_bytes());
        assert_eq!(decode_json::<Schema>(&rendered).expect("reparse"), document);

        let over = nested_objects(MAX_JSON_NESTING + 1, "{}");
        assert_eq!(
            invalid_code(decode_json::<Schema>(over.as_bytes()).map(drop)),
            ErrorCode::EInvalid
        );

        let original = envelope(pin_request());
        let mut base = sonic_rs::to_string(&original).expect("json");
        base.pop();
        let future = nested_objects(MAX_JSON_NESTING - 1, "{}");
        let framed = format!("{base},\"future\":{future}}}");
        let decoded = decode_request(framed.as_bytes()).expect("128 objects in a frame");
        assert_eq!(decoded.request, original.request);
        let future_over = nested_objects(MAX_JSON_NESTING, "{}");
        let framed_over = format!("{base},\"future\":{future_over}}}");
        assert_eq!(fails(framed_over.as_bytes()), ErrorCode::EInvalid);
    }

    #[test]
    fn deep_duplicate_keys_collapse_identically_through_every_decoder() {
        // The envelope holds four containers around the document
        // (root/body/success/schema), so a depth-124 payload totals 128.
        let duplicated = nested_objects(MAX_JSON_NESTING - 4, r#"{"k":1,"z":0,"k":2}"#);
        let collapsed = nested_objects(MAX_JSON_NESTING - 4, r#"{"k":2,"z":0}"#);

        let direct: Schema = decode_json(duplicated.as_bytes()).expect("direct");
        let wanted: Schema = decode_json(collapsed.as_bytes()).expect("collapsed");
        assert_eq!(direct, wanted);

        let template = sonic_rs::to_string(&schema_success(json_schema!(true))).expect("template");
        let marker = r#""document":true"#;
        let at = template.find(marker).expect("document slot");
        let mut frame = template;
        frame.replace_range(
            at..at + marker.len(),
            &format!(r#""document":{duplicated}"#),
        );
        let decoded = decode_reply(frame.as_bytes()).expect("envelope");
        let ReplyBody::Success(Reply::Schema(reply)) = decoded.body else {
            panic!("expected a schema reply");
        };
        assert_eq!(reply.document, wanted);
    }

    #[test]
    fn decode_json_reports_syntax_and_type_failures_as_invalid() {
        assert_eq!(
            decode_json::<Vec<u32>>(b"[1,2]").expect("decode"),
            vec![1, 2]
        );
        for bad in [&b"[1,"[..], &b"{\"a\":1}"[..], &b"[-1]"[..]] {
            assert_eq!(
                invalid_code(decode_json::<Vec<u32>>(bad).map(drop)),
                ErrorCode::EInvalid,
                "{}",
                bad.escape_ascii()
            );
        }
    }

    #[test]
    fn error_replies_use_contract_codes_and_survive_both_encodings() {
        let reply = ErrorReply::from_core(
            &CoreError::new(ErrorCode::EStale, "stamp moved").with_hint("re-read"),
        )
        .with_fix(Fix::RefreshExpected {
            workspace: Some(workspace()),
        })
        .with_fix(Fix::NewRequestId)
        .with_detail(ErrorDetail::Push {
            plan: PlanId::generate(),
            state: PushState::Uncertain,
            refs: BoundedList::complete(vec![PushRefOutcome {
                remote_ref: name("refs/heads/main"),
                status: PushRefStatus::Uncertain,
            }])
            .expect("refs"),
        });
        let wire = sonic_rs::to_value(&reply).expect("json");
        assert_eq!(wire.get("code").and_then(Value::as_str), Some("E_STALE"));
        assert_eq!(
            wire.get("fixes")
                .and_then(Value::as_array)
                .and_then(|fixes| fixes.get(1))
                .and_then(Value::as_str),
            Some("new_request_id")
        );
        assert_eq!(
            wire.get("hints")
                .and_then(Value::as_array)
                .and_then(|hints| hints.first())
                .and_then(Value::as_str),
            Some("re-read")
        );
        let envelope = ReplyEnvelope::failure(Some(request_id(1)), reply);
        let json = encode_reply(&envelope).expect("encode");
        assert_eq!(decode_reply(&json).expect("decode"), envelope);
        let packed = postcard::to_allocvec(&envelope).expect("postcard");
        assert_eq!(
            postcard::from_bytes::<ReplyEnvelope>(&packed).expect("unpack"),
            envelope
        );

        let mut future = sonic_rs::to_value(&envelope).expect("value");
        future["schema_version"]["major"] = json!(SCHEMA_MAJOR + 1);
        assert_eq!(
            decode_reply(&to_frame(&future))
                .expect_err("future major")
                .code,
            ErrorCode::EVersion
        );
    }

    // ----- the model document ---------------------------------------------

    fn collect_refs(value: &Value, out: &mut Vec<String>) {
        match (value.as_object(), value.as_array()) {
            (Some(map), _) => {
                out.extend(map.get(&"$ref").and_then(Value::as_str).map(str::to_owned));
                map.iter().for_each(|(_, child)| collect_refs(child, out));
            }
            (None, Some(items)) => items.iter().for_each(|item| collect_refs(item, out)),
            _ => {}
        }
    }

    fn untyped_member(map: &sonic_rs::Object) -> Option<String> {
        let permissive = |key: &str| map.get(&key).and_then(Value::as_bool) == Some(true);
        if permissive("additionalProperties") || permissive("items") {
            return Some("additionalProperties or items accepts any value".to_owned());
        }
        let members = map.get(&"properties")?.as_object()?;
        members
            .iter()
            .find(|(_, schema)| schema.as_bool() == Some(true))
            .map(|(key, _)| format!("property `{key}` accepts any value"))
    }

    fn find_untyped(value: &Value) -> Option<String> {
        match (value.as_object(), value.as_array()) {
            (Some(map), _) => untyped_member(map)
                .or_else(|| map.iter().find_map(|(_, child)| find_untyped(child))),
            (None, Some(items)) => items.iter().find_map(find_untyped),
            _ => None,
        }
    }

    fn resolve<'a>(defs: &'a Value, schema: &Value) -> &'a Value {
        let reference = schema
            .get("$ref")
            .and_then(Value::as_str)
            .expect("a $ref schema");
        let name = reference
            .strip_prefix("#/$defs/")
            .expect("a local reference");
        defs.get(name).expect("a referenced definition")
    }

    #[test]
    fn model_document_references_resolve_and_describe_every_method() {
        let doc = model_value();
        let defs = doc["$defs"].as_object().expect("definitions");
        let mut references = Vec::new();
        collect_refs(&doc, &mut references);
        assert!(!references.is_empty());
        for reference in &references {
            let target = reference
                .strip_prefix("#/$defs/")
                .unwrap_or_else(|| panic!("unexpected reference form {reference}"));
            assert!(defs.contains_key(&target), "dangling reference {reference}");
        }
        assert_eq!(doc["request"]["$ref"], "#/$defs/RequestEnvelope");
        assert_eq!(doc["reply"]["$ref"], "#/$defs/ReplyEnvelope");

        let methods = doc["methods"].as_array().expect("methods");
        assert_eq!(methods.len(), Method::ALL.len());
        for (entry, method) in methods.iter().zip(Method::ALL) {
            assert_eq!(entry["method"], method.as_str());
            assert_eq!(
                entry["kind"],
                sonic_rs::to_value(&method.kind()).expect("kind")
            );
        }
        assert_eq!(
            doc["schema_version"],
            json!({ "major": SCHEMA_MAJOR, "minor": SCHEMA_MINOR })
        );
        assert_eq!(doc["supported_majors"], json!([SCHEMA_MAJOR]));
    }

    #[test]
    fn model_document_publishes_the_limits_and_the_closed_error_registry() {
        let doc = model_value();
        assert_eq!(doc["limits"]["control_frame_bytes"], 16 * 1024 * 1024);
        assert_eq!(doc["limits"]["inline_edit_bytes"], 1024 * 1024);
        assert_eq!(doc["limits"]["page_default"], 100);
        assert_eq!(doc["limits"]["page_max"], 1000);
        assert_eq!(doc["limits"]["claim_ttl_seconds"], 3600);
        assert_eq!(doc["framing"]["length_prefix_bytes"], 4);
        let registry = doc["error_codes"].as_array().expect("error codes");
        assert_eq!(registry.len(), ErrorCode::ALL.len());
        for (entry, code) in registry.iter().zip(ErrorCode::ALL) {
            assert_eq!(entry["code"], code.as_str());
            assert_eq!(entry["exit_status"], code.exit_code());
        }
        let capability_fields = doc["$defs"]["Capabilities"]["properties"]
            .as_object()
            .expect("capability properties");
        for field in [
            "write_changes",
            "push_refs",
            "land",
            "claim_paths",
            "undo",
            "attest",
            "read_intents",
        ] {
            assert!(capability_fields.contains_key(&field), "{field}");
        }
    }

    #[test]
    fn mutation_methods_carry_request_ids_and_outcomes_and_reads_carry_views() {
        let doc = model_value();
        let defs = &doc["$defs"];
        for entry in doc["methods"].as_array().expect("methods") {
            let method: Method =
                sonic_rs::from_value(entry.get("method").expect("method")).expect("method");
            let params = resolve(defs, &entry["params"]);
            let result = resolve(defs, &entry["result"]);
            let has_request_id = params
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|properties| properties.contains_key(&"request_id"));
            assert_eq!(has_request_id, method.is_mutation(), "{}", method.as_str());
            let result_fields = result["properties"].as_object().expect("result fields");
            match method.kind() {
                MethodKind::Mutation => {
                    assert!(
                        result_fields.contains_key(&"outcome"),
                        "{}",
                        method.as_str()
                    );
                }
                MethodKind::Read => {
                    assert!(result_fields.contains_key(&"view"), "{}", method.as_str());
                }
                MethodKind::Anonymous | MethodKind::Bootstrap | MethodKind::Admin => {}
            }
        }
    }

    #[test]
    fn schema_admits_no_untyped_json_except_the_schema_itself() {
        let doc = model_value();
        let defs = doc["$defs"].as_object().expect("definitions");
        for (name, schema) in defs {
            if name == "Schema" {
                continue;
            }
            assert_eq!(find_untyped(schema), None, "{name}");
        }
    }

    #[test]
    fn single_method_document_is_self_contained() {
        let doc = single_method_value();
        assert_eq!(doc["method"], "write");
        assert_eq!(doc["kind"], "mutation");
        let defs = doc["$defs"].as_object().expect("definitions");
        let mut references = Vec::new();
        collect_refs(&doc, &mut references);
        for reference in &references {
            let target = reference.strip_prefix("#/$defs/").expect("local reference");
            assert!(defs.contains_key(&target), "dangling reference {reference}");
        }
        assert!(defs.contains_key(&"WriteArgs"));
        assert!(!defs.contains_key(&"BlameArgs"));
    }

    #[test]
    fn method_table_is_consistent_and_covers_the_contract() {
        let mut names = HashSet::new();
        for method in Method::ALL {
            assert!(
                names.insert(method.as_str()),
                "duplicate {}",
                method.as_str()
            );
            let wire = sonic_rs::to_value(&method).expect("json");
            assert_eq!(wire, json!(method.as_str()));
            let back: Method = sonic_rs::from_value(&wire).expect("parse");
            assert_eq!(&back, method);
            assert_eq!(method.is_mutation(), method.kind() == MethodKind::Mutation);
        }
        let required = [
            "schema",
            "session.open",
            "session.resume",
            "ws.new",
            "ws.scope",
            "ws.take",
            "ws.drop",
            "ws.recover",
            "snapshot",
            "write",
            "new",
            "describe",
            "edit",
            "split",
            "squash",
            "rebase",
            "abandon",
            "resolve",
            "revert",
            "bookmark.set",
            "bookmark.delete",
            "bookmark.resolve",
            "tag.set",
            "tag.delete",
            "claim.acquire",
            "claim.release",
            "claim.list",
            "attest.add",
            "attest.list",
            "fetch",
            "push",
            "push.reconcile",
            "land.prepare",
            "land.execute",
            "undo",
            "op.log",
            "op.prune",
            "pin",
            "unpin",
            "status",
            "log",
            "diff",
            "show",
            "file",
            "blame",
            "query",
            "git.commit",
            "repo.stat",
            "tree",
            "refs.list",
            "compare",
            "search",
            "archive",
            "events.tail",
            "repo.init",
            "repo.delete",
            "repo.rename",
            "repo.fork",
            "remote.refs",
            "claim.renew",
            "policy.set",
        ];
        for method in required {
            assert!(names.contains(method), "missing method {method}");
        }
        assert_eq!(names.len(), required.len(), "methods beyond the contract");
        // Order is part of the contract: a method's position in the table is
        // its discriminant, so a reordered row changes the wire.
        assert!(
            Method::ALL
                .iter()
                .copied()
                .map(Method::as_str)
                .eq(required.iter().copied()),
            "method table order differs from the contract order"
        );
    }
}
