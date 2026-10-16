//! The commit record: one logical commit in its single canonical byte form.
//!
//! A [`CommitRecord`] carries a change ID, the tree terms, ordered tagged
//! parents, an optional trusted native predecessor, the author and committer,
//! the byte message, the extra headers, and session provenance. Its byte
//! form is decided by one rule: a Git commit exists exactly when the tree is
//! a singleton and every parent is a Git commit (zero parents is valid).
//! Anything else is a native record in the `conflict-v1` encoding, so a
//! conflicted commit never needs a placeholder tree and a descendant of a
//! native conflicted parent stays native even if its own tree simplifies to
//! a singleton.
//!
//! # Byte authority
//!
//! * An imported Git commit keeps its exact payload. The record exposes the
//!   payload bytes it was given: extra headers are neither sorted nor
//!   normalized, repeated headers (several `mergetag`) and multi-line values
//!   (`gpgsig`) survive, and identity lines, headers, and message may be
//!   non-UTF-8. The structured accessors are a read-only view of those
//!   bytes, so they cannot disagree with them.
//! * A natively created record is validated by the `conflict-v1` model (one
//!   validation and one canonical ordering for both forms), then rendered:
//!   extra headers are sorted bytewise by name then value, structural header
//!   names and a repeated `change-id` are rejected, and the native
//!   `change-id` header carries the change ID. An exportable record renders
//!   as a Git commit payload; any other as a `conflict-v1` frame.
//!
//! The change ID is local metadata. A usable `change-id` header (exactly one,
//! 32 reverse-hex characters) must agree with it; an imported commit without
//! one gets its ID from the caller, which owns the stable by-OID mapping.
//! The predecessor is never read from imported bytes: a remote-controlled
//! claim is not trusted supersession evidence, so only
//! [`CommitRecord::create`] accepts one.
//!
//! # Limits
//!
//! Imported structure follows `git fsck`: `tree`, `parent`*, `author`,
//! `committer`, then extra headers, a blank line, and the message; no NUL in
//! the header block; object IDs are hex of the repository's width, read
//! case-insensitively as Git reads them. Identity lines and extra headers are
//! otherwise unchecked, so a commit Git can traverse but `fsck` would flag
//! for its identity still imports, and a dangling continuation line is
//! ignored as Git ignores it. A payload that breaks the structural order is
//! rejected, not repaired. A
//! natively created record additionally needs canonical [`Signature`]s, so
//! an imported identity that is not canonical cannot be carried into a native
//! commit ([`CommitRecord::author`] reports it explicitly).
//!
//! The serialized form is the metadata plus the canonical bytes, and every
//! deserialization re-parses and re-validates them.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ops::Range;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize, Serializer};

use crate::bytes::ByteString;
use crate::change::{ChangeId, SessionId};
use crate::conflict::{ConflictRecord, ConflictRecordInput, ExtraHeader, Signature};
use crate::error::CoreModelError;
use crate::heads::Head;
use crate::ids::{HashKind, Oid};
use crate::merge::Merge;

/// Name of the native header that carries the change ID.
const CHANGE_ID_HEADER: &[u8] = b"change-id";

/// Most claims one [`ProvenanceClaims`] may hold. Engineering defaults, like
/// the two limits below; they bound untrusted session claims, not a Git
/// format rule.
pub const MAX_PROVENANCE_CLAIMS: usize = 32;

/// Longest claim key in bytes.
pub const MAX_PROVENANCE_KEY_BYTES: usize = 64;

/// Longest claim value in bytes.
pub const MAX_PROVENANCE_VALUE_BYTES: usize = 256;

fn invalid(what: &'static str, detail: impl Into<String>) -> CoreModelError {
    CoreModelError::Invalid {
        what,
        detail: detail.into(),
    }
}

/// Unverified identity and provenance claims: what a session declares, and
/// the snapshot a commit keeps of what that session's policy admitted. They
/// are recorded as claims, never as authenticated facts.
///
/// This type is the one place the claim grammar is checked, so a claim set a
/// session may declare is exactly one a commit may keep. At most
/// [`MAX_PROVENANCE_CLAIMS`] entries; keys are
/// 1..=[`MAX_PROVENANCE_KEY_BYTES`] bytes of lowercase ASCII letters, digits,
/// `.`, `_`, `-`; values are at most [`MAX_PROVENANCE_VALUE_BYTES`] bytes with
/// no control characters. The serialized form is a plain string-to-string
/// map, and every deserialization re-validates it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "BTreeMap<String, String>")]
pub struct ProvenanceClaims(BTreeMap<String, String>);

fn is_claim_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_PROVENANCE_KEY_BYTES
        && key.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_claim_value(value: &str) -> bool {
    value.len() <= MAX_PROVENANCE_VALUE_BYTES && !value.chars().any(char::is_control)
}

impl ProvenanceClaims {
    /// Validates a claim set.
    ///
    /// # Errors
    /// More than [`MAX_PROVENANCE_CLAIMS`] entries; a key outside the grammar
    /// above; a value longer than [`MAX_PROVENANCE_VALUE_BYTES`] or containing
    /// a control character.
    pub fn new(claims: BTreeMap<String, String>) -> Result<Self, CoreModelError> {
        if claims.len() > MAX_PROVENANCE_CLAIMS {
            return Err(invalid(
                "provenance claims",
                format!(
                    "{} claims exceed the limit of {MAX_PROVENANCE_CLAIMS}",
                    claims.len()
                ),
            ));
        }
        for (key, value) in &claims {
            if !is_claim_key(key) {
                return Err(invalid(
                    "provenance claim key",
                    format!(
                        "expected 1..={MAX_PROVENANCE_KEY_BYTES} bytes of a-z, 0-9, '.', '_', '-'"
                    ),
                ));
            }
            if !is_claim_value(value) {
                return Err(invalid(
                    "provenance claim value",
                    format!(
                        "claim {key}: at most {MAX_PROVENANCE_VALUE_BYTES} bytes, no control characters"
                    ),
                ));
            }
        }
        Ok(Self(claims))
    }

    /// The claims.
    #[must_use]
    pub const fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    /// Unwraps the claims.
    #[must_use]
    pub fn into_map(self) -> BTreeMap<String, String> {
        self.0
    }
}

impl TryFrom<BTreeMap<String, String>> for ProvenanceClaims {
    type Error = CoreModelError;

    fn try_from(claims: BTreeMap<String, String>) -> Result<Self, Self::Error> {
        Self::new(claims)
    }
}

impl Serialize for ProvenanceClaims {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl JsonSchema for ProvenanceClaims {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("ProvenanceClaims")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        let key_pattern = format!("^[a-z0-9._-]{{1,{MAX_PROVENANCE_KEY_BYTES}}}$");
        json_schema!({
            "type": "object",
            "maxProperties": MAX_PROVENANCE_CLAIMS,
            "propertyNames": { "pattern": key_pattern },
            "additionalProperties": { "type": "string", "maxLength": MAX_PROVENANCE_VALUE_BYTES },
            "description": "Unverified claims: lowercase keys, string values without control characters."
        })
    }
}

/// Who created a commit: the authenticated session and the identity claims
/// the session's policy admitted when the commit was made.
///
/// The claims are a snapshot, so the commit stays attributable after the
/// session row has expired. Provenance is metadata stored beside the commit's
/// canonical bytes, never inside them: no claim becomes a Git header or part
/// of a `conflict-v1` frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Provenance {
    session: SessionId,
    claims: ProvenanceClaims,
}

impl Provenance {
    /// Pairs a session with claims that [`ProvenanceClaims::new`] already
    /// admitted.
    #[must_use]
    pub const fn new(session: SessionId, claims: ProvenanceClaims) -> Self {
        Self { session, claims }
    }

    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub const fn claims(&self) -> &ProvenanceClaims {
        &self.claims
    }
}

/// Everything needed to create a native commit.
///
/// `extra_headers` must not include `change-id`; it is derived from
/// `change_id`. `parents` are ordered and distinct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct NativeCommitInput {
    pub change_id: ChangeId,
    pub tree: Merge<Oid>,
    pub parents: Vec<Head>,
    /// The earlier head of this change that this commit rewrites, as known
    /// to the local store.
    pub predecessor: Option<Head>,
    pub author: Signature,
    pub committer: Signature,
    pub extra_headers: Vec<ExtraHeader>,
    pub message: ByteString,
    pub provenance: Option<Provenance>,
}

/// An exportable commit: the exact Git payload plus a read-only layout of it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct GitCommit {
    payload: ByteString,
    tree: Merge<Oid>,
    parents: Vec<Head>,
    author: Range<usize>,
    committer: Range<usize>,
    headers: Vec<ExtraHeader>,
    /// Offset of the message; equals the payload length when the payload has
    /// no message separator.
    message_start: usize,
}

/// The unvalidated shape of a Git commit payload, borrowing from it.
struct GitSplit<'a> {
    tree: &'a [u8],
    parents: Vec<&'a [u8]>,
    author: Range<usize>,
    committer: Range<usize>,
    headers: Vec<ExtraHeader>,
    message_start: usize,
}

/// Iterates the LF-terminated lines of a header block as `(offset, line)`.
fn block_lines(block: &[u8]) -> impl Iterator<Item = (usize, &[u8])> {
    let mut position = 0;
    core::iter::from_fn(move || {
        if position >= block.len() {
            return None;
        }
        let end = block[position..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(block.len(), |at| position + at);
        let item = (position, &block[position..end]);
        position = end + 1;
        Some(item)
    })
}

/// Splits a Git commit payload without interpreting object IDs.
fn split_git(payload: &[u8]) -> Result<GitSplit<'_>, CoreModelError> {
    // The header block runs through the first blank line, or is the whole
    // payload when there is no message separator.
    let (block_len, message_start) = match payload.windows(2).position(|pair| pair == b"\n\n") {
        Some(at) => (at + 1, at + 2),
        None => (payload.len(), payload.len()),
    };
    let block = &payload[..block_len];
    if block.contains(&0) {
        return Err(invalid("commit payload", "NUL byte in the header block"));
    }
    if !block.ends_with(b"\n") {
        return Err(invalid("commit payload", "unterminated header block"));
    }

    let mut lines = block_lines(block).peekable();
    let tree = lines
        .next()
        .and_then(|(_, line)| line.strip_prefix(b"tree "))
        .ok_or_else(|| invalid("commit payload", "expected a tree line first"))?;
    let mut parents = Vec::new();
    while let Some(hex) = lines
        .peek()
        .map(|&(_, line)| line)
        .and_then(|line| line.strip_prefix(b"parent "))
    {
        parents.push(hex);
        lines.next();
    }
    let mut identity = |prefix: &[u8], what: &'static str| {
        lines
            .next()
            .and_then(|(offset, line)| {
                line.strip_prefix(prefix)
                    .map(|_| offset + prefix.len()..offset + line.len())
            })
            .ok_or_else(|| invalid("commit payload", format!("expected {what} line")))
    };
    let author = identity(b"author ", "an author")?;
    let committer = identity(b"committer ", "a committer")?;

    let headers = collect_headers(lines.map(|(_, line)| line));
    Ok(GitSplit {
        tree,
        parents,
        author,
        committer,
        headers,
        message_start,
    })
}

/// Reads extra header lines as Git does: a line starting with a space
/// continues the previous header's value (joined with a newline), and a header
/// line with no space is a name with an empty value. A continuation with no
/// header to continue is ignored, as Git ignores it; the payload keeps it.
fn collect_headers<'a>(lines: impl Iterator<Item = &'a [u8]>) -> Vec<ExtraHeader> {
    let mut headers: Vec<ExtraHeader> = Vec::new();
    for line in lines {
        match (line.strip_prefix(b" "), headers.last_mut()) {
            (Some(continuation), Some(last)) => {
                let mut value = core::mem::take(&mut last.value).into_bytes();
                value.push(b'\n');
                value.extend_from_slice(continuation);
                last.value = ByteString::new(value);
            }
            (Some(_), None) => {}
            (None, _) => {
                let space = line.iter().position(|&byte| byte == b' ');
                let (name, value) = space.map_or((line, &line[line.len()..]), |at| {
                    (&line[..at], &line[at + 1..])
                });
                headers.push(ExtraHeader {
                    name: ByteString::from(name),
                    value: ByteString::from(value),
                });
            }
        }
    }
    headers
}

fn parse_oid(hex: &[u8], kind: HashKind, what: &str) -> Result<Oid, CoreModelError> {
    // Git reads the hex of `tree` and `parent` lines case-insensitively; `Oid`
    // text is lowercase only. The payload keeps its original spelling.
    let oid = if hex.iter().any(u8::is_ascii_uppercase) {
        Oid::from_bytes_hex(&hex.to_ascii_lowercase())?
    } else {
        Oid::from_bytes_hex(hex)?
    };
    oid.expect_kind(kind, what)?;
    Ok(oid)
}

/// The change ID a commit's headers declare, if exactly one usable
/// `change-id` header exists.
fn usable_change_id(headers: &[ExtraHeader]) -> Option<ChangeId> {
    let mut found = headers
        .iter()
        .filter(|header| header.name.as_bytes() == CHANGE_ID_HEADER);
    let only = found.next()?;
    if found.next().is_some() {
        return None;
    }
    ChangeId::from_reverse_hex(only.value.to_utf8()?).ok()
}

impl GitCommit {
    fn parse(payload: Vec<u8>, kind: HashKind) -> Result<Self, CoreModelError> {
        let GitSplit {
            tree,
            parents,
            author,
            committer,
            headers,
            message_start,
        } = split_git(&payload)?;
        let tree = Merge::resolved(parse_oid(tree, kind, "tree")?);
        let parents = parents
            .into_iter()
            .map(|hex| parse_oid(hex, kind, "parent").map(|oid| Head::Git { oid }))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            payload: ByteString::new(payload),
            tree,
            parents,
            author,
            committer,
            headers,
            message_start,
        })
    }

    fn render(record: &ConflictRecord, tree: &Oid) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"tree ");
        out.extend_from_slice(tree.to_hex().as_bytes());
        out.push(b'\n');
        for parent in record.parents() {
            if let Head::Git { oid } = parent {
                out.extend_from_slice(b"parent ");
                out.extend_from_slice(oid.to_hex().as_bytes());
                out.push(b'\n');
            }
        }
        out.extend_from_slice(b"author ");
        out.extend_from_slice(&record.author().render());
        out.push(b'\n');
        out.extend_from_slice(b"committer ");
        out.extend_from_slice(&record.committer().render());
        out.push(b'\n');
        for header in record.extra_headers() {
            out.extend_from_slice(header.name.as_bytes());
            for (index, line) in header
                .value
                .as_bytes()
                .split(|&byte| byte == b'\n')
                .enumerate()
            {
                out.extend_from_slice(if index == 0 { &b" "[..] } else { &b"\n "[..] });
                out.extend_from_slice(line);
            }
            out.push(b'\n');
        }
        out.push(b'\n');
        out.extend_from_slice(record.message().as_bytes());
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Body {
    Git(GitCommit),
    Native(ConflictRecord),
}

impl Body {
    fn extra_headers(&self) -> &[ExtraHeader] {
        match self {
            Self::Git(git) => &git.headers,
            Self::Native(native) => native.extra_headers(),
        }
    }
}

fn is_exportable(record: &ConflictRecord) -> bool {
    record.trees().as_resolved().is_some() && record.parents().iter().all(Head::is_git)
}

/// One logical commit in its canonical form. See the module documentation.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(try_from = "CommitRecordWire")]
pub struct CommitRecord {
    kind: HashKind,
    change_id: ChangeId,
    predecessor: Option<Head>,
    provenance: Option<Provenance>,
    body: Body,
}

impl CommitRecord {
    /// Creates a native commit.
    ///
    /// The record is a Git commit when `tree` is a singleton and every
    /// parent is a Git commit, and a native `conflict-v1` record otherwise.
    ///
    /// # Errors
    /// `ObjectFormat` for an object ID of the wrong width. `Invalid` for a
    /// duplicate parent, a NUL byte in the message (Git forbids it), a
    /// non-canonical signature, a malformed or structural extra header, a
    /// caller-supplied `change-id` header, or a NUL in a header value.
    pub fn create(input: NativeCommitInput, kind: HashKind) -> Result<Self, CoreModelError> {
        if input.message.as_bytes().contains(&0) {
            return Err(invalid("commit message", "contains a NUL byte"));
        }
        for (index, parent) in input.parents.iter().enumerate() {
            if input.parents[..index].contains(parent) {
                return Err(invalid(
                    "commit parents",
                    format!("duplicate parent at {index}"),
                ));
            }
        }
        let mut extra_headers = input.extra_headers;
        extra_headers.push(ExtraHeader {
            name: ByteString::from(CHANGE_ID_HEADER),
            value: ByteString::from(input.change_id.to_reverse_hex()),
        });
        let record = ConflictRecord::from_input(
            &ConflictRecordInput {
                trees: input.tree.iter().copied().collect(),
                parents: input.parents,
                author: input.author,
                committer: input.committer,
                extra_headers,
                message: input.message,
            },
            kind,
        )?;
        let git_payload = record
            .trees()
            .as_resolved()
            .filter(|_| is_exportable(&record))
            .map(|tree| GitCommit::render(&record, tree));
        let body = match git_payload {
            Some(payload) => Body::Git(GitCommit::parse(payload, kind)?),
            None => Body::Native(record),
        };
        Self::assemble(
            kind,
            input.change_id,
            input.predecessor,
            input.provenance,
            body,
        )
    }

    /// Imports a Git commit payload (the bytes after `commit <len>\0`),
    /// keeping it byte-for-byte.
    ///
    /// `change_id` must equal [`Self::git_header_change_id`] when the payload
    /// has a usable header; otherwise it is the caller's stable local mapping
    /// for this object. The record has no predecessor: a remote cannot assert
    /// one.
    ///
    /// # Errors
    /// `Invalid` for a payload that breaks the structure in the module
    /// documentation or a `change_id` that disagrees with the header;
    /// `ObjectFormat` for an object ID of the wrong width.
    pub fn import_git(
        payload: Vec<u8>,
        kind: HashKind,
        change_id: ChangeId,
        provenance: Option<Provenance>,
    ) -> Result<Self, CoreModelError> {
        let git = GitCommit::parse(payload, kind)?;
        Self::assemble(kind, change_id, None, provenance, Body::Git(git))
    }

    /// The change ID a Git payload's headers declare, or `None` when the
    /// payload is malformed or has no single well-formed `change-id` header.
    #[must_use]
    pub fn git_header_change_id(payload: &[u8]) -> Option<ChangeId> {
        usable_change_id(&split_git(payload).ok()?.headers)
    }

    fn assemble(
        kind: HashKind,
        change_id: ChangeId,
        predecessor: Option<Head>,
        provenance: Option<Provenance>,
        body: Body,
    ) -> Result<Self, CoreModelError> {
        if let Some(predecessor) = &predecessor {
            predecessor.validate(kind)?;
        }
        match (usable_change_id(body.extra_headers()), &body) {
            (Some(declared), _) if declared != change_id => {
                return Err(invalid(
                    "change id",
                    format!("{change_id} disagrees with the commit's change-id header {declared}"),
                ));
            }
            (None, Body::Native(_)) => {
                return Err(invalid(
                    "commit record",
                    "a native record needs one usable change-id header",
                ));
            }
            _ => {}
        }
        Ok(Self {
            kind,
            change_id,
            predecessor,
            provenance,
            body,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> HashKind {
        self.kind
    }

    #[must_use]
    pub const fn change_id(&self) -> ChangeId {
        self.change_id
    }

    /// The tree terms. A singleton for every exportable record.
    #[must_use]
    pub const fn tree(&self) -> &Merge<Oid> {
        match &self.body {
            Body::Git(git) => &git.tree,
            Body::Native(native) => native.trees(),
        }
    }

    /// The ordered parents.
    #[must_use]
    pub fn parents(&self) -> &[Head] {
        match &self.body {
            Body::Git(git) => &git.parents,
            Body::Native(native) => native.parents(),
        }
    }

    /// The trusted local predecessor of a native rewrite.
    #[must_use]
    pub const fn predecessor(&self) -> Option<Head> {
        self.predecessor
    }

    #[must_use]
    pub const fn provenance(&self) -> Option<&Provenance> {
        self.provenance.as_ref()
    }

    /// The author line bytes after `author `, exactly as stored.
    #[must_use]
    pub fn author_ident(&self) -> Cow<'_, [u8]> {
        match &self.body {
            Body::Git(git) => Cow::Borrowed(&git.payload.as_bytes()[git.author.clone()]),
            Body::Native(native) => Cow::Owned(native.author().render()),
        }
    }

    /// The committer line bytes after `committer `, exactly as stored.
    #[must_use]
    pub fn committer_ident(&self) -> Cow<'_, [u8]> {
        match &self.body {
            Body::Git(git) => Cow::Borrowed(&git.payload.as_bytes()[git.committer.clone()]),
            Body::Native(native) => Cow::Owned(native.committer().render()),
        }
    }

    /// The author as a structured signature.
    ///
    /// # Errors
    /// An imported identity that is not in the canonical `name <email>
    /// timestamp tz` spelling; [`Self::author_ident`] still has its bytes.
    pub fn author(&self) -> Result<Signature, CoreModelError> {
        match &self.body {
            Body::Git(_) => Signature::parse(&self.author_ident()),
            Body::Native(native) => Ok(native.author().clone()),
        }
    }

    /// The committer as a structured signature; see [`Self::author`].
    ///
    /// # Errors
    /// As [`Self::author`].
    pub fn committer(&self) -> Result<Signature, CoreModelError> {
        match &self.body {
            Body::Git(_) => Signature::parse(&self.committer_ident()),
            Body::Native(native) => Ok(native.committer().clone()),
        }
    }

    /// Every extra header in stored order (the payload's own order for an
    /// imported commit, canonical order for a native one). Includes
    /// `change-id` when present.
    #[must_use]
    pub fn extra_headers(&self) -> &[ExtraHeader] {
        self.body.extra_headers()
    }

    /// The message bytes. Empty for an imported payload with no separator.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        match &self.body {
            Body::Git(git) => &git.payload.as_bytes()[git.message_start..],
            Body::Native(native) => native.message().as_bytes(),
        }
    }

    /// True exactly when a Git commit object exists for this record: a
    /// singleton tree and only Git parents.
    #[must_use]
    pub const fn is_exportable(&self) -> bool {
        matches!(self.body, Body::Git(_))
    }

    /// The exact Git commit payload, or `None` for a native record. Exporting
    /// a native record would need a placeholder tree, which is not allowed.
    #[must_use]
    pub fn git_payload(&self) -> Option<&[u8]> {
        match &self.body {
            Body::Git(git) => Some(git.payload.as_bytes()),
            Body::Native(_) => None,
        }
    }

    /// The `conflict-v1` record of a native commit, or `None` for a Git one.
    #[must_use]
    pub const fn native_record(&self) -> Option<&ConflictRecord> {
        match &self.body {
            Body::Git(_) => None,
            Body::Native(native) => Some(native),
        }
    }

    /// The record's identity: the Git OID of its payload, or the native key
    /// of its `conflict-v1` frame.
    ///
    /// # Errors
    /// SHA-1 collision detection refusing the input.
    pub fn head(&self) -> Result<Head, CoreModelError> {
        match &self.body {
            Body::Git(git) => self
                .kind
                .hash_git_object("commit", git.payload.as_bytes())
                .map(|oid| Head::Git { oid }),
            Body::Native(native) => native.key().map(|key| Head::Conflicted { key }),
        }
    }
}

/// The canonical bytes a record is stored and transferred as.
#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
enum Encoded {
    /// A Git commit payload.
    Git(ByteString),
    /// A framed `conflict-v1` record.
    Native(ByteString),
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum EncodedRef<'a> {
    Git(&'a ByteString),
    Native(&'a ByteString),
}

/// The serialized form: metadata plus canonical bytes.
#[derive(Deserialize, JsonSchema)]
struct CommitRecordWire {
    kind: HashKind,
    change_id: ChangeId,
    predecessor: Option<Head>,
    provenance: Option<Provenance>,
    encoded: Encoded,
}

#[derive(Serialize)]
struct WireRef<'a> {
    kind: HashKind,
    change_id: ChangeId,
    predecessor: Option<Head>,
    provenance: Option<&'a Provenance>,
    encoded: EncodedRef<'a>,
}

impl TryFrom<CommitRecordWire> for CommitRecord {
    type Error = CoreModelError;

    fn try_from(wire: CommitRecordWire) -> Result<Self, Self::Error> {
        let body = match wire.encoded {
            Encoded::Git(payload) => Body::Git(GitCommit::parse(payload.into_bytes(), wire.kind)?),
            Encoded::Native(frame) => {
                let record = ConflictRecord::decode(frame.as_bytes(), wire.kind)?;
                if is_exportable(&record) {
                    return Err(invalid(
                        "commit record",
                        "an exportable commit must be encoded as a Git payload",
                    ));
                }
                Body::Native(record)
            }
        };
        Self::assemble(
            wire.kind,
            wire.change_id,
            wire.predecessor,
            wire.provenance,
            body,
        )
    }
}

impl Serialize for CommitRecord {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let frame;
        let encoded = match &self.body {
            Body::Git(git) => EncodedRef::Git(&git.payload),
            Body::Native(native) => {
                frame = ByteString::new(native.encode());
                EncodedRef::Native(&frame)
            }
        };
        WireRef {
            kind: self.kind,
            change_id: self.change_id,
            predecessor: self.predecessor,
            provenance: self.provenance.as_ref(),
            encoded,
        }
        .serialize(serializer)
    }
}

impl JsonSchema for CommitRecord {
    fn schema_name() -> Cow<'static, str> {
        "CommitRecord".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::CommitRecord").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        CommitRecordWire::json_schema(generator)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::conflict::TzOffset;
    use crate::ids::CommitKey;

    const KINDS: [HashKind; 2] = [HashKind::Sha1, HashKind::Sha256];

    fn oid(kind: HashKind, fill: u8) -> Oid {
        Oid::from_bytes(&[fill; 32][..kind.oid_len()]).expect("oid")
    }

    fn key(kind: HashKind, fill: u8) -> CommitKey {
        CommitKey::from_bytes(&[fill; 32][..kind.oid_len()]).expect("key")
    }

    fn git(kind: HashKind, fill: u8) -> Head {
        Head::Git {
            oid: oid(kind, fill),
        }
    }

    fn sig(name: &str, timestamp: i64, offset: &str) -> Signature {
        Signature {
            name: name.into(),
            email: format!("{}@example.test", name.to_lowercase()).into(),
            timestamp,
            offset: TzOffset::parse(offset.as_bytes()).expect("offset"),
        }
    }

    fn header(name: &str, value: &str) -> ExtraHeader {
        ExtraHeader {
            name: name.into(),
            value: value.into(),
        }
    }

    fn change(fill: u8) -> ChangeId {
        ChangeId::from_bytes([fill; 16])
    }

    fn claims(pairs: &[(&str, &str)]) -> Result<ProvenanceClaims, CoreModelError> {
        ProvenanceClaims::new(
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
        )
    }

    type Mutation = Box<dyn Fn(&mut NativeCommitInput)>;

    /// Boxes a mutation; the `Fn` bound gives the closure its higher-ranked
    /// `&mut` signature, which a bare `Box::new(|i| ..)` in a `vec!` would not.
    fn mutation(change: impl Fn(&mut NativeCommitInput) + 'static) -> Mutation {
        Box::new(change)
    }

    fn input(kind: HashKind) -> NativeCommitInput {
        NativeCommitInput {
            change_id: change(7),
            tree: Merge::resolved(oid(kind, 1)),
            parents: vec![git(kind, 2)],
            predecessor: None,
            author: sig("Ann", 1_700_000_000, "+0900"),
            committer: sig("Cy", 1_700_000_001, "-0000"),
            extra_headers: vec![],
            message: "subject\n\nbody\n".into(),
            provenance: None,
        }
    }

    fn conflicted_tree(kind: HashKind) -> Merge<Oid> {
        Merge::try_from_vec(vec![oid(kind, 1), oid(kind, 2), oid(kind, 3)]).expect("terms")
    }

    /// A Git payload that exercises every byte-fidelity case at once.
    fn awkward_payload(kind: HashKind) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(format!("tree {}\n", oid(kind, 1)).as_bytes());
        out.extend_from_slice(format!("parent {}\n", oid(kind, 2)).as_bytes());
        out.extend_from_slice(format!("parent {}\n", oid(kind, 3)).as_bytes());
        out.extend_from_slice(b"author Zo\xebl <z@example.test> 1 +0000\n");
        out.extend_from_slice(b"committer C <c@example.test> 2 +0100\n");
        out.extend_from_slice(b"zzz sorts-last-but-comes-first\n");
        out.extend_from_slice(b"mergetag object abc\n type commit\n \n tag v1\n");
        out.extend_from_slice(b"aaa sorts-first-but-comes-later\n");
        out.extend_from_slice(b"mergetag second\n");
        out.extend_from_slice(b"gpgsig -----BEGIN-----\n data\xff\n -----END-----\n");
        out.extend_from_slice(b"encoding ISO-8859-1\n");
        out.extend_from_slice(b"\nsubject \xe9\xe8\n\nbody, no trailing newline \xff");
        out
    }

    fn import(kind: HashKind, payload: &[u8]) -> Result<CommitRecord, CoreModelError> {
        CommitRecord::import_git(payload.to_vec(), kind, change(9), None)
    }

    fn json_round_trip(record: &CommitRecord) -> CommitRecord {
        let json = serde_json::to_string(record).expect("serialize");
        serde_json::from_str(&json).expect("deserialize")
    }

    fn postcard_round_trip(record: &CommitRecord) -> CommitRecord {
        let bytes = postcard::to_allocvec(record).expect("serialize");
        postcard::from_bytes(&bytes).expect("deserialize")
    }

    #[test]
    fn imported_payload_is_kept_byte_for_byte() {
        for kind in KINDS {
            let payload = awkward_payload(kind);
            let record = import(kind, &payload).expect("import");

            assert_eq!(record.git_payload(), Some(payload.as_slice()));
            assert!(record.is_exportable());
            assert_eq!(
                record.head().expect("head"),
                Head::Git {
                    oid: kind.hash_git_object("commit", &payload).expect("hash"),
                }
            );
            // Headers keep payload order: unsorted, repeated, multi-line.
            let headers: Vec<(&[u8], &[u8])> = record
                .extra_headers()
                .iter()
                .map(|h| (h.name.as_bytes(), h.value.as_bytes()))
                .collect();
            let expected: Vec<(&[u8], &[u8])> = vec![
                (b"zzz", b"sorts-last-but-comes-first"),
                (b"mergetag", b"object abc\ntype commit\n\ntag v1"),
                (b"aaa", b"sorts-first-but-comes-later"),
                (b"mergetag", b"second"),
                (b"gpgsig", b"-----BEGIN-----\ndata\xff\n-----END-----"),
                (b"encoding", b"ISO-8859-1"),
            ];
            assert_eq!(headers, expected);
            assert_eq!(record.parents(), [git(kind, 2), git(kind, 3)]);
            assert_eq!(record.tree().as_resolved(), Some(&oid(kind, 1)));
            assert_eq!(
                record.author_ident().as_ref(),
                b"Zo\xebl <z@example.test> 1 +0000"
            );
            assert_eq!(record.author().expect("author").name.as_bytes(), b"Zo\xebl");
            assert_eq!(record.committer().expect("committer").timestamp, 2);
            assert_eq!(
                record.message(),
                b"subject \xe9\xe8\n\nbody, no trailing newline \xff"
            );
            assert_eq!(record.predecessor(), None);
        }
    }

    #[test]
    fn imported_payload_survives_both_codecs_exactly() {
        for kind in KINDS {
            let payload = awkward_payload(kind);
            let record = import(kind, &payload).expect("import");
            for back in [json_round_trip(&record), postcard_round_trip(&record)] {
                assert_eq!(back.git_payload(), Some(payload.as_slice()));
                assert_eq!(back, record);
            }
        }
    }

    #[test]
    fn imported_payload_without_message_separator_is_preserved() {
        let kind = HashKind::Sha1;
        let mut payload = Vec::new();
        payload.extend_from_slice(format!("tree {}\n", oid(kind, 1)).as_bytes());
        payload.extend_from_slice(b"author A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n");
        let record = import(kind, &payload).expect("import");
        assert_eq!(record.git_payload(), Some(payload.as_slice()));
        assert_eq!(record.message(), b"");
        assert!(record.parents().is_empty());
        assert_eq!(json_round_trip(&record), record);
    }

    #[test]
    fn imported_non_canonical_identity_is_kept_and_reported() {
        let kind = HashKind::Sha1;
        let mut payload = Vec::new();
        payload.extend_from_slice(format!("tree {}\n", oid(kind, 1)).as_bytes());
        payload.extend_from_slice(b"author nobody 0 +0000\ncommitter C <c@x> 07 +0000\n\nm");
        let record = import(kind, &payload).expect("import");
        assert_eq!(record.author_ident().as_ref(), b"nobody 0 +0000");
        assert!(record.author().is_err());
        assert!(record.committer().is_err());
        assert_eq!(record.git_payload(), Some(payload.as_slice()));
    }

    #[test]
    fn import_rejects_every_structural_violation() {
        let kind = HashKind::Sha1;
        let tree = format!("tree {}\n", oid(kind, 1));
        let parent = format!("parent {}\n", oid(kind, 2));
        let ids = "author A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n";
        let wide = format!("tree {}\n", oid(HashKind::Sha256, 1));
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", vec![]),
            ("no tree", ids.as_bytes().to_vec()),
            ("author before tree", format!("{ids}{tree}\nm").into_bytes()),
            ("parent before tree", format!("{parent}{tree}{ids}\nm").into_bytes()),
            ("parent after author", format!("{tree}author A <a@x> 1 +0000\n{parent}committer A <a@x> 1 +0000\n\nm").into_bytes()),
            ("no author", format!("{tree}committer A <a@x> 1 +0000\n\nm").into_bytes()),
            ("no committer", format!("{tree}author A <a@x> 1 +0000\n\nm").into_bytes()),
            ("committer first", format!("{tree}committer A <a@x> 1 +0000\nauthor A <a@x> 1 +0000\n\nm").into_bytes()),
            ("wide tree in a sha1 repo", format!("{wide}{ids}\nm").into_bytes()),
            ("tree line with trailing space", format!("tree {} \n{ids}\nm", oid(kind, 1)).into_bytes()),
            (
                "second author line",
                format!(
                    "{tree}author A <a@x> 1 +0000\nauthor B <b@x> 1 +0000\ncommitter A <a@x> 1 +0000\n\nm"
                )
                .into_bytes(),
            ),
            ("short tree", format!("tree abcd\n{ids}\nm").into_bytes()),
            ("NUL in headers", format!("{tree}{ids}x\0 y\n\nm").into_bytes()),
            ("unterminated headers", format!("{tree}{ids}x y").into_bytes()),
        ];
        for (name, payload) in cases {
            assert!(import(kind, &payload).is_err(), "{name} must be rejected");
        }
        // NUL is only forbidden in the header block.
        let ok = format!("{tree}{ids}\nmessage\0with nul");
        assert!(import(kind, ok.as_bytes()).is_ok());
    }

    #[test]
    fn import_accepts_what_git_reads_and_keeps_the_bytes() {
        let kind = HashKind::Sha1;
        // Git reads object hex case-insensitively; the payload keeps its spelling.
        let upper = oid(kind, 0xab).to_hex().to_uppercase();
        let ids = "author A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n";
        let payload = format!("tree {upper}\nparent {upper}\n{ids}\nm").into_bytes();
        let record = import(kind, &payload).expect("uppercase hex imports");
        assert_eq!(record.git_payload(), Some(payload.as_slice()));
        assert_eq!(record.tree().as_resolved(), Some(&oid(kind, 0xab)));
        assert_eq!(record.parents(), [git(kind, 0xab)]);

        // Git ignores a continuation line that has no header to continue.
        let dangling = format!("tree {}\n{ids} dangling\nx y\n z\n\nm", oid(kind, 1)).into_bytes();
        let record = import(kind, &dangling).expect("dangling continuation imports");
        assert_eq!(record.git_payload(), Some(dangling.as_slice()));
        let headers: Vec<(&[u8], &[u8])> = record
            .extra_headers()
            .iter()
            .map(|h| (h.name.as_bytes(), h.value.as_bytes()))
            .collect();
        let expected: Vec<(&[u8], &[u8])> = vec![(b"x", b"y\nz")];
        assert_eq!(headers, expected);
    }

    #[test]
    fn change_id_header_and_record_must_agree() {
        let kind = HashKind::Sha1;
        let declared = change(5);
        let base = format!(
            "tree {}\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n",
            oid(kind, 1)
        );
        let with = |headers: &str| format!("{base}{headers}\nm").into_bytes();
        let good = with(&format!("change-id {}\n", declared.to_reverse_hex()));

        assert_eq!(CommitRecord::git_header_change_id(&good), Some(declared));
        assert!(CommitRecord::import_git(good.clone(), kind, declared, None).is_ok());
        assert!(CommitRecord::import_git(good, kind, change(6), None).is_err());

        // Unusable headers declare nothing, so any local mapping is accepted
        // and the bytes are still kept.
        let twice = with(&format!(
            "change-id {0}\nchange-id {0}\n",
            declared.to_reverse_hex()
        ));
        let short = with("change-id zzzz\n");
        let upper = with(&format!(
            "change-id {}\n",
            declared.to_reverse_hex().to_uppercase()
        ));
        let folded = with(&format!("change-id {}\n x\n", declared.to_reverse_hex()));
        for payload in [twice, short, upper, folded] {
            assert_eq!(CommitRecord::git_header_change_id(&payload), None);
            let record = CommitRecord::import_git(payload.clone(), kind, change(6), None)
                .expect("unusable header imports");
            assert_eq!(record.git_payload(), Some(payload.as_slice()));
            assert_eq!(record.change_id(), change(6));
        }
        assert_eq!(CommitRecord::git_header_change_id(b"not a commit"), None);
    }

    #[test]
    fn native_exportable_record_renders_a_canonical_git_payload() {
        for kind in KINDS {
            let mut native = input(kind);
            native.extra_headers = vec![
                header("zeta", "1"),
                header("mergetag", "l1\nl2"),
                header("alpha", "2"),
            ];
            native.parents = vec![git(kind, 4), git(kind, 2)];
            let record = CommitRecord::create(native, kind).expect("create");

            let expected = format!(
                "tree {}\nparent {}\nparent {}\n\
                 author Ann <ann@example.test> 1700000000 +0900\n\
                 committer Cy <cy@example.test> 1700000001 -0000\n\
                 alpha 2\nchange-id {}\nmergetag l1\n l2\nzeta 1\n\n\
                 subject\n\nbody\n",
                oid(kind, 1),
                oid(kind, 4),
                oid(kind, 2),
                change(7).to_reverse_hex(),
            );
            assert_eq!(record.git_payload(), Some(expected.as_bytes()));
            assert!(record.is_exportable());
            assert!(record.native_record().is_none());
            assert_eq!(
                record.parents(),
                [git(kind, 4), git(kind, 2)],
                "parent order kept"
            );
            let names: Vec<&[u8]> = record
                .extra_headers()
                .iter()
                .map(|h| h.name.as_bytes())
                .collect();
            assert_eq!(names, [&b"alpha"[..], b"change-id", b"mergetag", b"zeta"]);
            assert_eq!(record.change_id(), change(7));
            assert_eq!(
                record.head().expect("head"),
                Head::Git {
                    oid: kind
                        .hash_git_object("commit", expected.as_bytes())
                        .expect("hash")
                }
            );

            // What Ruk exports is exactly what an importer reads back.
            let reread = CommitRecord::import_git(expected.into_bytes(), kind, change(7), None)
                .expect("re-import");
            assert_eq!(reread.git_payload(), record.git_payload());
            assert_eq!(reread.extra_headers(), record.extra_headers());
            assert_eq!(reread.message(), record.message());
        }
    }

    #[test]
    fn zero_parents_is_a_valid_exportable_commit() {
        let kind = HashKind::Sha1;
        let mut native = input(kind);
        native.parents = vec![];
        let record = CommitRecord::create(native, kind).expect("root commit");
        assert!(record.is_exportable());
        assert!(record.parents().is_empty());
    }

    #[test]
    fn a_conflicted_tree_is_native_with_its_terms_and_no_placeholder() {
        for kind in KINDS {
            let mut native = input(kind);
            native.tree = conflicted_tree(kind);
            native.extra_headers = vec![header("zeta", "1"), header("alpha", "2")];
            let record = CommitRecord::create(native, kind).expect("create");

            assert!(!record.is_exportable());
            assert_eq!(record.git_payload(), None);
            assert_eq!(
                record.tree().as_slice(),
                [oid(kind, 1), oid(kind, 2), oid(kind, 3)]
            );
            let native = record.native_record().expect("native record");
            let frame = native.encode();
            assert!(frame.starts_with(b"conflict-v1 "));
            assert_eq!(
                ConflictRecord::decode(&frame, kind).expect("decode"),
                *native
            );
            assert_eq!(
                record.head().expect("head"),
                Head::Conflicted {
                    key: native.key().expect("key")
                }
            );
            let names: Vec<&[u8]> = record
                .extra_headers()
                .iter()
                .map(|h| h.name.as_bytes())
                .collect();
            assert_eq!(names, [&b"alpha"[..], b"change-id", b"zeta"]);
        }
    }

    #[test]
    fn a_native_parent_keeps_a_singleton_tree_native() {
        for kind in KINDS {
            let mut native = input(kind);
            native.parents = vec![git(kind, 2), Head::Conflicted { key: key(kind, 9) }];
            let record = CommitRecord::create(native, kind).expect("create");
            assert_eq!(record.tree().as_resolved(), Some(&oid(kind, 1)));
            assert!(!record.is_exportable());
            assert_eq!(record.parents()[1], Head::Conflicted { key: key(kind, 9) });
            assert!(matches!(
                record.head().expect("head"),
                Head::Conflicted { .. }
            ));
        }
    }

    #[test]
    fn create_rejects_inputs_that_would_corrupt_either_form() {
        let kind = HashKind::Sha1;
        let mutations: Vec<(&str, Mutation)> = vec![
            (
                "duplicate parent",
                mutation(move |i| i.parents = vec![git(kind, 2), git(kind, 2)]),
            ),
            (
                "duplicate native parent",
                mutation(move |i| {
                    i.parents = vec![
                        Head::Conflicted { key: key(kind, 2) },
                        Head::Conflicted { key: key(kind, 2) },
                    ];
                }),
            ),
            (
                "NUL in message",
                mutation(|i| i.message = ByteString::from(&b"a\0b"[..])),
            ),
            (
                "wide tree",
                mutation(|i| i.tree = Merge::resolved(oid(HashKind::Sha256, 1))),
            ),
            (
                "wide parent",
                mutation(|i| i.parents = vec![git(HashKind::Sha256, 2)]),
            ),
            (
                "wide native parent",
                mutation(|i| {
                    i.parents = vec![Head::Conflicted {
                        key: key(HashKind::Sha256, 2),
                    }]
                }),
            ),
            (
                "wide predecessor",
                mutation(|i| i.predecessor = Some(git(HashKind::Sha256, 5))),
            ),
            (
                "caller change-id header",
                mutation(|i| i.extra_headers = vec![header("change-id", "x")]),
            ),
            (
                "tree header",
                mutation(|i| i.extra_headers = vec![header("tree", "x")]),
            ),
            (
                "parent header",
                mutation(|i| i.extra_headers = vec![header("parent", "x")]),
            ),
            (
                "author header",
                mutation(|i| i.extra_headers = vec![header("author", "x")]),
            ),
            (
                "committer header",
                mutation(|i| i.extra_headers = vec![header("committer", "x")]),
            ),
            (
                "header name with space",
                mutation(|i| i.extra_headers = vec![header("a b", "x")]),
            ),
            (
                "empty header name",
                mutation(|i| i.extra_headers = vec![header("", "x")]),
            ),
            (
                "NUL in header value",
                mutation(|i| i.extra_headers = vec![header("a", "x\0")]),
            ),
            (
                "angle bracket in name",
                mutation(|i| i.author.name = "A<b".into()),
            ),
            (
                "newline in email",
                mutation(|i| i.committer.email = "a\n@x".into()),
            ),
        ];
        for (name, mutate) in mutations {
            let mut native = input(kind);
            mutate(&mut native);
            assert!(
                CommitRecord::create(native, kind).is_err(),
                "{name} must be rejected"
            );
        }
        // The same checks hold on the native form.
        let mut native = input(kind);
        native.tree = conflicted_tree(kind);
        native.message = ByteString::from(&b"a\0b"[..]);
        assert!(CommitRecord::create(native, kind).is_err());
    }

    #[test]
    fn native_provenance_and_predecessor_are_kept() {
        let kind = HashKind::Sha1;
        let provenance = Provenance::new(
            SessionId::generate(),
            claims(&[("agent", "reviewer")]).expect("claims"),
        );
        let mut native = input(kind);
        native.predecessor = Some(git(kind, 5));
        native.provenance = Some(provenance.clone());
        let record = CommitRecord::create(native, kind).expect("create");
        assert_eq!(record.predecessor(), Some(git(kind, 5)));
        assert_eq!(record.provenance(), Some(&provenance));
        for back in [json_round_trip(&record), postcard_round_trip(&record)] {
            assert_eq!(back, record);
            assert_eq!(back.predecessor(), Some(git(kind, 5)));
        }
    }

    #[test]
    fn imports_never_carry_a_predecessor() {
        let kind = HashKind::Sha1;
        let record = import(kind, &awkward_payload(kind)).expect("import");
        assert_eq!(record.predecessor(), None);
    }

    #[test]
    fn provenance_bounds_untrusted_claims() {
        let session = SessionId::generate();
        assert!(claims(&[("model", "x y z")]).is_ok());
        assert!(claims(&[("task.id", "42"), ("run_2", "v"), ("a-b", "")]).is_ok());
        assert!(ProvenanceClaims::default().as_map().is_empty());
        for bad_key in ["", "has space", "Agent", "agent:id", "a/b", "tab\tkey"] {
            assert!(claims(&[(bad_key, "v")]).is_err(), "{bad_key:?}");
        }
        assert!(claims(&[("k", "line\nbreak")]).is_err());
        let key_limit = "k".repeat(MAX_PROVENANCE_KEY_BYTES);
        assert!(claims(&[(key_limit.as_str(), "v")]).is_ok());
        let long_key = "k".repeat(MAX_PROVENANCE_KEY_BYTES + 1);
        assert!(claims(&[(long_key.as_str(), "v")]).is_err());
        let value_limit = "v".repeat(MAX_PROVENANCE_VALUE_BYTES);
        assert!(claims(&[("k", value_limit.as_str())]).is_ok());
        let long_value = "v".repeat(MAX_PROVENANCE_VALUE_BYTES + 1);
        assert!(claims(&[("k", long_value.as_str())]).is_err());
        let many = |count: usize| -> BTreeMap<String, String> {
            (0..count)
                .map(|i| (format!("k{i}"), String::new()))
                .collect()
        };
        assert!(ProvenanceClaims::new(many(MAX_PROVENANCE_CLAIMS)).is_ok());
        assert!(ProvenanceClaims::new(many(MAX_PROVENANCE_CLAIMS + 1)).is_err());
        // Deserialization is the same single check, not a second grammar.
        for bad in ["{\"\":\"v\"}", "{\"Bad\":\"x\"}", "{\"k\":1}"] {
            let json = format!("{{\"session\":\"{session}\",\"claims\":{bad}}}");
            assert!(serde_json::from_str::<Provenance>(&json).is_err(), "{bad}");
            assert!(
                serde_json::from_str::<ProvenanceClaims>(bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn only_admitted_claims_can_be_kept_by_a_commit_record() {
        let kind = HashKind::Sha1;
        let admitted = claims(&[
            ("agent", "reviewer"),
            ("task.id", "42"),
            ("run_2-b", "ü x; y"),
        ])
        .expect("admitted");
        // Each claim the old commit grammar (printable ASCII keys) let in but
        // the session grammar refuses, plus values no claim may carry.
        let refused = [
            ("Agent", "x"),
            ("agent:id", "x"),
            ("a/b", "x"),
            ("task id", "x"),
            ("agent", "two\nlines"),
            ("agent", "bell\u{7}"),
        ];
        for conflicted in [false, true] {
            let mut native = input(kind);
            if conflicted {
                native.tree = conflicted_tree(kind);
            }
            native.provenance = Some(Provenance::new(SessionId::generate(), admitted.clone()));
            let record = CommitRecord::create(native, kind).expect("create");
            assert_eq!(record.is_exportable(), !conflicted);
            for back in [json_round_trip(&record), postcard_round_trip(&record)] {
                assert_eq!(back.provenance().map(Provenance::claims), Some(&admitted));
                assert_eq!(back, record);
            }
            for (key, value) in refused {
                assert!(claims(&[(key, value)]).is_err(), "{key:?}");
                let mut forged = serde_json::to_value(&record).expect("value");
                forged["provenance"]["claims"] =
                    serde_json::to_value(BTreeMap::from([(key, value)])).expect("claims");
                assert!(
                    serde_json::from_value::<CommitRecord>(forged).is_err(),
                    "{key:?}"
                );
            }
        }
    }

    #[test]
    fn deserialization_revalidates_the_canonical_bytes() {
        let kind = HashKind::Sha1;
        let exportable = CommitRecord::create(input(kind), kind).expect("exportable");
        let mut native_input = input(kind);
        native_input.tree = conflicted_tree(kind);
        let native = CommitRecord::create(native_input, kind).expect("native");

        let value = |record: &CommitRecord| serde_json::to_value(record).expect("value");

        // Wrong change ID for the header inside the bytes.
        let mut forged = value(&exportable);
        forged["change_id"] = serde_json::to_value(change(8)).expect("id");
        assert!(serde_json::from_value::<CommitRecord>(forged).is_err());

        // A hash kind that does not match the bytes.
        let mut forged = value(&exportable);
        forged["kind"] = serde_json::json!("sha256");
        assert!(serde_json::from_value::<CommitRecord>(forged).is_err());

        // A native frame for a commit that has a Git form.
        let frame = ConflictRecord::from_input(
            &ConflictRecordInput {
                trees: vec![oid(kind, 1)],
                parents: vec![git(kind, 2)],
                author: sig("Ann", 1, "+0000"),
                committer: sig("Ann", 1, "+0000"),
                extra_headers: vec![header("change-id", &change(7).to_reverse_hex())],
                message: "m".into(),
            },
            kind,
        )
        .expect("frame input")
        .encode();
        let mut forged = value(&exportable);
        forged["encoded"] = serde_json::json!({ "native": ByteString::from(frame) });
        assert!(serde_json::from_value::<CommitRecord>(forged).is_err());

        // A tampered native frame (length no longer matches).
        let mut frame = native.native_record().expect("native").encode();
        frame.push(b'x');
        let mut forged = value(&native);
        forged["encoded"] = serde_json::json!({ "native": ByteString::from(frame) });
        assert!(serde_json::from_value::<CommitRecord>(forged).is_err());

        // A predecessor of the wrong width.
        let mut forged = value(&exportable);
        forged["predecessor"] = serde_json::to_value(git(HashKind::Sha256, 5)).expect("head");
        assert!(serde_json::from_value::<CommitRecord>(forged).is_err());

        // The untouched values still decode.
        assert_eq!(json_round_trip(&exportable), exportable);
        assert_eq!(json_round_trip(&native), native);
        assert_eq!(postcard_round_trip(&native), native);
    }

    fn head_strategy(kind: HashKind) -> impl Strategy<Value = Head> {
        prop_oneof![
            (1_u8..=255).prop_map(move |fill| git(kind, fill)),
            (1_u8..=255).prop_map(move |fill| Head::Conflicted {
                key: key(kind, fill)
            }),
        ]
    }

    fn input_strategy(kind: HashKind) -> impl Strategy<Value = NativeCommitInput> {
        let tree = (0_usize..3)
            .prop_flat_map(|extra| proptest::collection::vec(1_u8..=255, 2 * extra + 1))
            .prop_map(move |fills| {
                Merge::try_from_vec(
                    fills
                        .into_iter()
                        .map(|fill| oid(kind, fill))
                        .collect::<Vec<_>>(),
                )
                .expect("odd terms")
            });
        let parents = proptest::collection::vec(head_strategy(kind), 0..5).prop_map(|heads| {
            let mut distinct: Vec<Head> = Vec::new();
            for head in heads {
                if !distinct.contains(&head) {
                    distinct.push(head);
                }
            }
            distinct
        });
        let value = proptest::collection::vec(proptest::char::range('a', 'z'), 0..8)
            .prop_map(|chars| chars.into_iter().collect::<String>());
        let headers = proptest::collection::btree_map(0_usize..4, value, 0..4).prop_map(|map| {
            let names = ["alpha", "beta", "x-note", "zeta"];
            // Reverse so the generated order is not already sorted.
            map.into_iter()
                .rev()
                .map(|(i, v)| header(names[i], &v))
                .collect::<Vec<_>>()
        });
        let message = proptest::collection::vec(1_u8..=255, 0..24);
        (any::<[u8; 16]>(), tree, parents, headers, message).prop_map(
            |(change_bytes, tree, parents, extra_headers, message)| NativeCommitInput {
                change_id: ChangeId::from_bytes(change_bytes),
                tree,
                parents,
                predecessor: None,
                author: sig("Ann", 1_700_000_000, "+0900"),
                committer: sig("Cy", 1_700_000_001, "-0000"),
                extra_headers,
                message: ByteString::new(message),
                provenance: None,
            },
        )
    }

    proptest! {
        #[test]
        fn a_git_commit_exists_exactly_for_singleton_trees_with_git_parents(
            native in input_strategy(HashKind::Sha1),
        ) {
            let kind = HashKind::Sha1;
            let expect_git = native.tree.is_resolved() && native.parents.iter().all(Head::is_git);
            let message = native.message.clone();
            let parents = native.parents.clone();
            let change_id = native.change_id;
            let record = CommitRecord::create(native, kind).expect("valid input");

            prop_assert_eq!(record.is_exportable(), expect_git);
            prop_assert_eq!(record.git_payload().is_some(), expect_git);
            prop_assert_eq!(record.native_record().is_some(), !expect_git);
            prop_assert_eq!(matches!(record.head().expect("head"), Head::Git { .. }), expect_git);
            prop_assert_eq!(record.parents(), parents.as_slice());
            prop_assert_eq!(record.message(), message.as_bytes());
            prop_assert_eq!(record.change_id(), change_id);
            // Canonical order, with exactly one change-id header.
            prop_assert!(record.extra_headers().windows(2).all(|pair| pair[0] <= pair[1]));
            let ids = record
                .extra_headers()
                .iter()
                .filter(|h| h.name.as_bytes() == CHANGE_ID_HEADER)
                .count();
            prop_assert_eq!(ids, 1);

            prop_assert_eq!(&json_round_trip(&record), &record);
            prop_assert_eq!(&postcard_round_trip(&record), &record);

            if let Some(payload) = record.git_payload() {
                let reread = CommitRecord::import_git(payload.to_vec(), kind, change_id, None)
                    .expect("exported payload imports");
                prop_assert_eq!(reread.git_payload(), Some(payload));
                prop_assert_eq!(reread.tree(), record.tree());
                prop_assert_eq!(reread.parents(), record.parents());
                prop_assert_eq!(reread.extra_headers(), record.extra_headers());
                prop_assert_eq!(reread.message(), record.message());
                prop_assert_eq!(reread.author_ident(), record.author_ident());
            }
        }

        #[test]
        fn imports_never_reorder_or_rewrite_header_bytes(
            names in proptest::collection::vec(0_usize..4, 0..6),
            message in proptest::collection::vec(any::<u8>(), 0..24),
        ) {
            let kind = HashKind::Sha1;
            let pool = ["zeta", "alpha", "mergetag", "alpha"];
            let mut payload = format!(
                "tree {}\nauthor A <a@x> 1 +0000\ncommitter A <a@x> 1 +0000\n",
                oid(kind, 1)
            )
            .into_bytes();
            for (position, name) in names.iter().enumerate() {
                payload.extend_from_slice(format!("{} v{position}\n", pool[*name]).as_bytes());
            }
            payload.push(b'\n');
            payload.extend_from_slice(&message);

            let record = import(kind, &payload).expect("import");
            prop_assert_eq!(record.git_payload(), Some(payload.as_slice()));
            prop_assert_eq!(record.message(), message.as_slice());
            let seen: Vec<&[u8]> = record.extra_headers().iter().map(|h| h.name.as_bytes()).collect();
            let wanted: Vec<&[u8]> = names.iter().map(|i| pool[*i].as_bytes()).collect();
            prop_assert_eq!(seen, wanted);
            prop_assert_eq!(&postcard_round_trip(&record), &record);
        }
    }
}
