//! Native conflict record: the `conflict-v1` byte format, its validated
//! in-memory form, and its identity.
//!
//! # Framing
//!
//! ```text
//! conflict-v1 <decimal payload length>\0<payload>
//! payload := "trees" (" " <hex oid>)+ "\n"
//!            ("parent " <hex oid> "\n" | "parent conflict " <hex key> "\n")*
//!            "author " <ident> "\n"
//!            "committer " <ident> "\n"
//!            (<name> " " <first value line> "\n" (" " <value line> "\n")*)*
//!            "\n"
//!            <message bytes, verbatim to the end of the payload>
//! ident   := <name> " <" <email> "> " <decimal timestamp> " " ("+"|"-") 4*DIGIT
//! ```
//!
//! The length is the byte length of the payload, so it is the same count the
//! segment framing stores. Hex is lowercase and exactly as wide as the
//! repository's object format. Extra headers follow Git's header grammar: a
//! value containing newlines continues on lines that start with one space.
//! The message is the exact byte string; its character encoding is whatever
//! the record's `encoding` header (if any) declares, as for a Git commit.
//!
//! # Identity
//!
//! The record's [`CommitKey`] is the object hash of the *whole framed
//! record* under the repository's hash kind:
//!
//! `key = H_kind("conflict-v1 " || decimal(len(payload)) || 0x00 || payload)`
//!
//! That is Git's object hashing with object type `conflict-v1`, so a key has
//! the same width as the repository's OIDs (20 bytes SHA-1, 32 bytes SHA-256)
//! and cannot equal a Git object id for the same bytes.
//!
//! # Canonical form
//!
//! Records are created natively, so the format has exactly one spelling:
//! extra headers are sorted bytewise by name then value at creation;
//! structural header names are rejected as extra headers; `change-id` may
//! appear at most once. [`ConflictRecord::decode`] accepts only that spelling
//! and re-checks that `encode(decode(bytes)) == bytes`, so a stored record
//! and its key can never disagree. Imported Git commit payloads are a
//! different object: they stay byte-authoritative in the commit record and
//! are never routed through this encoder.

use core::fmt;
use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bytes::ByteString;
use crate::error::CoreModelError;
use crate::heads::Head;
use crate::ids::{CommitKey, HashKind, Oid};
use crate::merge::Merge;

/// The format tag that opens every framed record.
pub const FORMAT_TAG: &str = "conflict-v1";

/// Header names the record encodes structurally. They can never be extra
/// headers: a payload line that begins with one of them in the extra-header
/// section is a duplicate of a reserved header and is rejected.
const STRUCTURAL_HEADERS: [&[u8]; 5] = [b"tree", b"trees", b"parent", b"author", b"committer"];

/// Native headers that identify the commit and so may appear at most once.
const UNIQUE_HEADERS: [&[u8]; 1] = [b"change-id"];

fn invalid(what: &'static str, detail: impl Into<String>) -> CoreModelError {
    CoreModelError::Invalid {
        what,
        detail: detail.into(),
    }
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A Git timezone offset exactly as written: a sign and four digits.
///
/// The sign is kept separately so `-0000` and `+0000` stay distinct, as they
/// are in Git ident lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TzOffset {
    negative: bool,
    hhmm: u16,
}

impl TzOffset {
    pub const UTC: Self = Self {
        negative: false,
        hhmm: 0,
    };

    /// # Errors
    /// Rejects values that do not fit four decimal digits.
    pub fn new(negative: bool, hhmm: u16) -> Result<Self, CoreModelError> {
        if hhmm > 9999 {
            return Err(invalid("timezone offset", hhmm.to_string()));
        }
        Ok(Self { negative, hhmm })
    }

    /// Parses `[+-]DDDD`.
    ///
    /// # Errors
    /// Rejects any other shape.
    pub fn parse(text: &[u8]) -> Result<Self, CoreModelError> {
        let bad = || invalid("timezone offset", lossy(text));
        let [sign, digits @ ..] = text else {
            return Err(bad());
        };
        let negative = match *sign {
            b'+' => false,
            b'-' => true,
            _ => return Err(bad()),
        };
        if digits.len() != 4 || !digits.iter().all(u8::is_ascii_digit) {
            return Err(bad());
        }
        let hhmm = digits
            .iter()
            .fold(0_u16, |acc, digit| acc * 10 + u16::from(digit - b'0'));
        Ok(Self { negative, hhmm })
    }

    #[must_use]
    pub const fn is_negative(self) -> bool {
        self.negative
    }

    /// The four digits as an integer (`0130` is 130).
    #[must_use]
    pub const fn hhmm(self) -> u16 {
        self.hhmm
    }
}

impl fmt::Display for TzOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{:04}",
            if self.negative { '-' } else { '+' },
            self.hhmm
        )
    }
}

impl Serialize for TzOffset {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TzOffset {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(text.as_bytes()).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for TzOffset {
    fn schema_name() -> Cow<'static, str> {
        "TzOffset".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::TzOffset").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "Git timezone offset: sign and four digits, e.g. +0100 or -0000.",
            "type": "string",
            "pattern": "^[+-][0-9]{4}$"
        })
    }
}

/// An author or committer identity line.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Signature {
    /// Name bytes: no `<`, `>`, newline, or NUL.
    pub name: ByteString,
    /// Email bytes: no `<`, `>`, newline, or NUL.
    pub email: ByteString,
    /// Unix seconds; negative values are pre-1970.
    pub timestamp: i64,
    pub offset: TzOffset,
}

impl Signature {
    fn check(&self, what: &'static str) -> Result<(), CoreModelError> {
        for (field, bytes) in [("name", &self.name), ("email", &self.email)] {
            if bytes
                .as_bytes()
                .iter()
                .any(|b| matches!(b, b'<' | b'>' | b'\n' | 0))
            {
                return Err(invalid(
                    what,
                    format!("{field} contains <, >, newline, or NUL"),
                ));
            }
        }
        Ok(())
    }

    fn render_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.name.as_bytes());
        out.extend_from_slice(b" <");
        out.extend_from_slice(self.email.as_bytes());
        out.extend_from_slice(b"> ");
        out.extend_from_slice(self.timestamp.to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.offset.to_string().as_bytes());
    }

    /// The ident bytes after the `author `/`committer ` prefix.
    #[must_use]
    pub fn render(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.render_into(&mut out);
        out
    }

    /// Parses the canonical ident grammar `name <email> timestamp tz`.
    ///
    /// # Errors
    /// Rejects every non-canonical spelling (missing or doubled separators,
    /// leading zeros or a `+` in the timestamp, malformed offset).
    pub fn parse(line: &[u8]) -> Result<Self, CoreModelError> {
        let bad = |why: &str| invalid("signature", format!("{why}: {}", lossy(line)));
        let (rest, tz) = rsplit_space(line).ok_or_else(|| bad("missing timezone"))?;
        let (rest, stamp) = rsplit_space(rest).ok_or_else(|| bad("missing timestamp"))?;
        let rest = rest
            .strip_suffix(b">")
            .ok_or_else(|| bad("missing closing '>'"))?;
        let lt = rest
            .iter()
            .position(|&b| b == b'<')
            .ok_or_else(|| bad("missing '<'"))?;
        let name = rest[..lt]
            .strip_suffix(b" ")
            .ok_or_else(|| bad("missing space before '<'"))?;
        let stamp_text = core::str::from_utf8(stamp).map_err(|_| bad("non-UTF-8 timestamp"))?;
        let timestamp: i64 = stamp_text
            .parse()
            .map_err(|_| bad("timestamp is not an integer"))?;
        if timestamp.to_string() != stamp_text {
            return Err(bad("non-canonical timestamp"));
        }
        let signature = Self {
            name: ByteString::from(name),
            email: ByteString::from(&rest[lt + 1..]),
            timestamp,
            offset: TzOffset::parse(tz)?,
        };
        signature.check("signature")?;
        Ok(signature)
    }
}

fn rsplit_space(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = line.iter().rposition(|&b| b == b' ')?;
    Some((&line[..at], &line[at + 1..]))
}

/// An extra commit header. Exact bytes; a multi-line value is carried with
/// embedded newlines and written with Git continuation lines.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct ExtraHeader {
    /// Non-empty; no space, newline, or NUL; not a structural header name.
    pub name: ByteString,
    /// No NUL.
    pub value: ByteString,
}

impl ExtraHeader {
    fn check(&self) -> Result<(), CoreModelError> {
        let name = self.name.as_bytes();
        let bad_name = name.is_empty() || name.iter().any(|b| matches!(b, b' ' | b'\n' | 0));
        if bad_name {
            return Err(invalid("extra header name", lossy(name)));
        }
        if STRUCTURAL_HEADERS.contains(&name) {
            return Err(invalid("reserved header", lossy(name)));
        }
        if self.value.as_bytes().contains(&0) {
            return Err(invalid(
                "extra header value",
                format!("{} contains NUL", lossy(name)),
            ));
        }
        Ok(())
    }

    fn render_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.name.as_bytes());
        for (index, line) in self.value.as_bytes().split(|&b| b == b'\n').enumerate() {
            out.push(if index == 0 { b' ' } else { b'\n' });
            if index > 0 {
                out.push(b' ');
            }
            out.extend_from_slice(line);
        }
        out.push(b'\n');
    }

    fn parse(line: &[u8]) -> Result<Self, CoreModelError> {
        let space = line.iter().position(|&b| b == b' ').ok_or_else(|| {
            invalid(
                "extra header",
                format!("no value separator: {}", lossy(line)),
            )
        })?;
        Ok(Self {
            name: ByteString::from(&line[..space]),
            value: ByteString::from(&line[space + 1..]),
        })
    }
}

fn check_headers(headers: &[ExtraHeader]) -> Result<(), CoreModelError> {
    for header in headers {
        header.check()?;
    }
    for unique in UNIQUE_HEADERS {
        let count = headers
            .iter()
            .filter(|h| h.name.as_bytes() == unique)
            .count();
        if count > 1 {
            return Err(invalid("duplicate header", lossy(unique)));
        }
    }
    Ok(())
}

/// The unvalidated, serializable description of a conflict record: what a
/// caller supplies (JSON on the CLI). [`ConflictRecord::from_input`] is the
/// validation boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConflictRecordInput {
    /// Conflict tree terms (odd count): real Git tree OIDs of the
    /// repository's hash kind.
    pub trees: Vec<Oid>,
    /// Ordered parents. A parent that is itself a native conflict is
    /// `Head::Conflicted`; every other parent is a Git commit.
    pub parents: Vec<Head>,
    pub author: Signature,
    pub committer: Signature,
    /// Sorted bytewise by name then value at creation.
    #[serde(default)]
    pub extra_headers: Vec<ExtraHeader>,
    /// Commit message bytes.
    pub message: ByteString,
}

/// A validated native conflict record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictRecord {
    kind: HashKind,
    trees: Merge<Oid>,
    parents: Vec<Head>,
    author: Signature,
    committer: Signature,
    extra_headers: Vec<ExtraHeader>,
    message: ByteString,
}

impl ConflictRecord {
    /// Validates `input` for a repository of hash kind `kind`, sorting the
    /// extra headers into canonical order.
    ///
    /// # Errors
    /// `ObjectFormat` for any digest of the wrong width; `Invalid` for an
    /// even or empty tree list, malformed signatures, or malformed or
    /// duplicate reserved headers.
    pub fn from_input(input: &ConflictRecordInput, kind: HashKind) -> Result<Self, CoreModelError> {
        let mut extra_headers = input.extra_headers.clone();
        extra_headers.sort();
        Self::assemble(
            kind,
            input.trees.clone(),
            input.parents.clone(),
            input.author.clone(),
            input.committer.clone(),
            extra_headers,
            input.message.clone(),
        )
    }

    fn assemble(
        kind: HashKind,
        trees: Vec<Oid>,
        parents: Vec<Head>,
        author: Signature,
        committer: Signature,
        extra_headers: Vec<ExtraHeader>,
        message: ByteString,
    ) -> Result<Self, CoreModelError> {
        let trees = Merge::try_from_vec(trees).map_err(|_| {
            invalid(
                "conflict trees",
                "expected an odd, non-zero number of terms",
            )
        })?;
        for tree in &trees {
            tree.expect_kind(kind, "tree")?;
        }
        for parent in &parents {
            parent.validate(kind)?;
        }
        author.check("author")?;
        committer.check("committer")?;
        check_headers(&extra_headers)?;
        Ok(Self {
            kind,
            trees,
            parents,
            author,
            committer,
            extra_headers,
            message,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> HashKind {
        self.kind
    }

    /// The conflict tree terms in the native algebra type.
    #[must_use]
    pub const fn trees(&self) -> &Merge<Oid> {
        &self.trees
    }

    #[must_use]
    pub fn parents(&self) -> &[Head] {
        &self.parents
    }

    #[must_use]
    pub const fn author(&self) -> &Signature {
        &self.author
    }

    #[must_use]
    pub const fn committer(&self) -> &Signature {
        &self.committer
    }

    /// Extra headers in canonical (sorted) order.
    #[must_use]
    pub fn extra_headers(&self) -> &[ExtraHeader] {
        &self.extra_headers
    }

    #[must_use]
    pub const fn message(&self) -> &ByteString {
        &self.message
    }

    /// The input form that reproduces this record.
    #[must_use]
    pub fn to_input(&self) -> ConflictRecordInput {
        ConflictRecordInput {
            trees: self.trees.iter().copied().collect(),
            parents: self.parents.clone(),
            author: self.author.clone(),
            committer: self.committer.clone(),
            extra_headers: self.extra_headers.clone(),
            message: self.message.clone(),
        }
    }

    /// The payload bytes (everything after the framing header).
    #[must_use]
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"trees");
        for tree in &self.trees {
            out.push(b' ');
            out.extend_from_slice(tree.to_hex().as_bytes());
        }
        out.push(b'\n');
        for parent in &self.parents {
            match parent {
                Head::Git { oid } => {
                    out.extend_from_slice(b"parent ");
                    out.extend_from_slice(oid.to_hex().as_bytes());
                }
                Head::Conflicted { key } => {
                    out.extend_from_slice(b"parent conflict ");
                    out.extend_from_slice(key.to_hex().as_bytes());
                }
            }
            out.push(b'\n');
        }
        out.extend_from_slice(b"author ");
        self.author.render_into(&mut out);
        out.push(b'\n');
        out.extend_from_slice(b"committer ");
        self.committer.render_into(&mut out);
        out.push(b'\n');
        for header in &self.extra_headers {
            header.render_into(&mut out);
        }
        out.push(b'\n');
        out.extend_from_slice(self.message.as_bytes());
        out
    }

    /// The full framed bytes: `conflict-v1 <len>\0` then the payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let payload = self.encode_payload();
        let mut out = Vec::with_capacity(payload.len() + FORMAT_TAG.len() + 24);
        out.extend_from_slice(FORMAT_TAG.as_bytes());
        out.push(b' ');
        out.extend_from_slice(payload.len().to_string().as_bytes());
        out.push(0);
        out.extend_from_slice(&payload);
        out
    }

    /// The record's native identity: the repository-kind hash of
    /// [`Self::encode`] (see the module docs).
    ///
    /// # Errors
    /// SHA-1 collision detection refusing the input.
    pub fn key(&self) -> Result<CommitKey, CoreModelError> {
        CommitKey::of_framed_record(self.kind, &self.encode())
    }

    /// Decodes framed bytes. Only the canonical spelling is accepted.
    ///
    /// # Errors
    /// `Invalid` for a bad header, length mismatch, malformed or reordered
    /// sections, unsorted extra headers, or any non-canonical spelling;
    /// `ObjectFormat` for digests of the wrong width.
    pub fn decode(bytes: &[u8], kind: HashKind) -> Result<Self, CoreModelError> {
        let payload = split_frame(bytes)?;
        let record = Self::decode_payload(payload, kind)?;
        if !record
            .extra_headers
            .windows(2)
            .all(|pair| pair[0] <= pair[1])
        {
            return Err(invalid(
                "conflict record",
                "extra headers are not in canonical order",
            ));
        }
        if record.encode() != bytes {
            return Err(invalid("conflict record", "non-canonical encoding"));
        }
        Ok(record)
    }

    fn decode_payload(payload: &[u8], kind: HashKind) -> Result<Self, CoreModelError> {
        let mut rest = payload;
        let line = next_line(&mut rest, "trees")?;
        let trees = parse_trees(line)?;

        let mut parents = Vec::new();
        let author = loop {
            let line = next_line(&mut rest, "author")?;
            if let Some(hex) = line.strip_prefix(b"parent conflict ") {
                parents.push(Head::Conflicted {
                    key: CommitKey::from_hex_bytes(hex)?,
                });
            } else if let Some(hex) = line.strip_prefix(b"parent ") {
                parents.push(Head::Git {
                    oid: Oid::from_bytes_hex(hex)?,
                });
            } else {
                break line
                    .strip_prefix(b"author ")
                    .ok_or_else(|| invalid("conflict record", "expected an author line"))?;
            }
        };
        let author = Signature::parse(author)?;
        let committer = next_line(&mut rest, "committer")?
            .strip_prefix(b"committer ")
            .ok_or_else(|| invalid("conflict record", "expected a committer line"))?;
        let committer = Signature::parse(committer)?;

        let mut extra_headers: Vec<ExtraHeader> = Vec::new();
        loop {
            let line = next_line(&mut rest, "blank line before the message")?;
            if line.is_empty() {
                break;
            }
            let Some(continuation) = line.strip_prefix(b" ") else {
                extra_headers.push(ExtraHeader::parse(line)?);
                continue;
            };
            let last = extra_headers
                .last_mut()
                .ok_or_else(|| invalid("extra header", "continuation line without a header"))?;
            let mut value = core::mem::take(&mut last.value).into_bytes();
            value.push(b'\n');
            value.extend_from_slice(continuation);
            last.value = ByteString::new(value);
        }

        Self::assemble(
            kind,
            trees,
            parents,
            author,
            committer,
            extra_headers,
            ByteString::from(rest),
        )
    }
}

/// Splits `conflict-v1 <len>\0<payload>`, checking tag and canonical length.
fn split_frame(bytes: &[u8]) -> Result<&[u8], CoreModelError> {
    let bad = |why: String| invalid("conflict frame", why);
    let nul = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| bad("missing NUL after the length".to_owned()))?;
    let (header, payload) = (&bytes[..nul], &bytes[nul + 1..]);
    let tag = format!("{FORMAT_TAG} ");
    let digits = header
        .strip_prefix(tag.as_bytes())
        .ok_or_else(|| bad(format!("bad tag {:?}", lossy(header))))?;
    let text = core::str::from_utf8(digits).map_err(|_| bad("non-UTF-8 length".to_owned()))?;
    let declared: usize = text
        .parse()
        .map_err(|_| bad(format!("bad length {text:?}")))?;
    if declared.to_string() != text {
        return Err(bad(format!("non-canonical length {text:?}")));
    }
    if declared != payload.len() {
        return Err(bad(format!(
            "declared {declared} payload bytes but found {}",
            payload.len()
        )));
    }
    Ok(payload)
}

/// Takes one newline-terminated line off `rest`.
fn next_line<'a>(rest: &mut &'a [u8], expected: &str) -> Result<&'a [u8], CoreModelError> {
    let at = rest
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| invalid("conflict record", format!("truncated before {expected}")))?;
    let line = &rest[..at];
    *rest = &rest[at + 1..];
    Ok(line)
}

fn parse_trees(line: &[u8]) -> Result<Vec<Oid>, CoreModelError> {
    let terms = line.strip_prefix(b"trees ").ok_or_else(|| {
        invalid(
            "conflict record",
            "expected a trees line with at least one term",
        )
    })?;
    terms
        .split(|&b| b == b' ')
        .map(Oid::from_bytes_hex)
        .collect()
}

#[cfg(test)]
mod tests;
