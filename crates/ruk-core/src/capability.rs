//! Capability grammar: what an authenticated principal's session may do.
//!
//! A [`Capabilities`] value has seven fields (`write_changes`, `push_refs`,
//! `land`, `claim_paths`, `undo`, `attest`, `read_intents`). The same type
//! serves as the principal's *policy ceiling* and as the *requested* subset a
//! session asks for in `session.open`. [`Capabilities::negotiate`] returns the
//! effective set: the requested subset of the ceiling, or an `E_FORBIDDEN`
//! failure naming the first field that exceeds it. Excess is never silently
//! truncated, because a caller that proceeds on a narrower grant than it
//! asked for acts on an authority it does not know it lacks.
//!
//! Every field defaults to "no authority", so a document that omits a field
//! (including one added by a later minor version) grants nothing for it.
//!
//! # Pattern grammar
//!
//! [`RefPattern`] and [`PathPattern`] share one grammar over `/`-separated
//! segments:
//!
//! * a literal segment matches exactly itself;
//! * `*` matches exactly one segment (never part of a segment: `a*b` is
//!   rejected, not interpreted);
//! * `**` is allowed only as the final segment and matches zero or more
//!   remaining segments, so `src/**` matches `src` and everything below it.
//!
//! Names have at least one segment, so a bare `**` matches what `*/**`
//! matches: both are "any name".
//!
//! Because wildcards are whole segments and the segment alphabet is
//! unbounded, "pattern `P` matches every name pattern `Q` matches" is decided
//! exactly by [`RefPattern::covers`]/[`PathPattern::covers`] without
//! enumerating names.
//!
//! # Union coverage
//!
//! A request is within a policy when every requested pattern is covered by
//! the *union* of the policy's patterns, not necessarily by one member:
//! `refs/heads/*` plus `refs/heads/*/*/**` together cover `refs/heads/*/**`,
//! and `src` plus `src/*/**` together cover `src/**`. The decision is exact
//! and never enumerates names:
//!
//! 1. Fix a name length. At that length each pattern matches a box: every
//!    position is one literal or any segment. Name the request's free
//!    positions by a segment that no policy pattern spells. A member matches
//!    that name only if it is a wildcard at every free position and agrees
//!    with the request's literals elsewhere, and such a member then matches
//!    every request name of that length. Finitely many literals never cover
//!    a free position, so at one length the union covers the request exactly
//!    when a single compatible member admits that length.
//! 2. A request admits one length (no `**`) or every length from its
//!    minimum up (`**`). A compatible member admits one length or every
//!    length from its minimum up. The union therefore covers the request
//!    exactly when each length the request admits is admitted by some
//!    compatible member.
//! 3. Beyond the longest compatible fixed-length member only `**` members
//!    can match, and their admitted lengths form one tail. The deep tail is
//!    decided by the smallest compatible `**` member; the lengths between
//!    the request's minimum and that member's minimum are checked one by
//!    one, at most one per segment of the longest pattern.
//!
//! A depth gap (no member admits some length), a literal gap (no compatible
//! member at a length), and a missing tail (no compatible `**` member for a
//! request with `**`) all deny.
//!
//! # Write scope
//!
//! The specification names the scopes `Own`, `Session`, and `All` without
//! defining `Own`. This crate orders them `Own < Session < All` and
//! interprets them as: `Own` mutates only the change checked out in a
//! workspace the session holds; `Session` additionally mutates any change
//! this session created; `All` mutates any change. The ordering is the part
//! the type enforces; the per-method authorization map belongs to the
//! coordinator.
//!
//! # Reads
//!
//! Ordinary object and history reads are never gated by capabilities
//! ([`ReadAccess::Objects`] always authorizes). `read_intents` gates only the
//! private provenance and claim details of other sessions.

use core::fmt;
use core::str::FromStr;
use std::borrow::Cow;
use std::collections::BTreeSet;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::error::{CoreError, CoreModelError, ErrorCode};
use crate::index::RepoPath;
use crate::refdata::RefName;

/// Longest accepted pattern text, in bytes.
pub const MAX_PATTERN_BYTES: usize = 1024;

/// Defines a validated, length-bounded UTF-8 string newtype with string wire
/// form and a matching JSON schema.
macro_rules! bounded_text {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            schema: $schema:literal,
            max: $max:expr,
            doc: $doc:literal,
            check: $check:path $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        $vis struct $name(String);

        impl $name {
            /// Longest accepted value, in bytes.
            pub const MAX_BYTES: usize = $max;

            /// Validates and wraps `text`.
            ///
            /// # Errors
            /// Empty or over-long text, or text the type's grammar rejects.
            pub fn new(text: impl Into<String>) -> Result<Self, $crate::error::CoreModelError> {
                let text = text.into();
                if text.is_empty() || text.len() > Self::MAX_BYTES {
                    return Err($crate::error::CoreModelError::Invalid {
                        what: $schema,
                        detail: format!(
                            "length {} is outside 1..={} bytes",
                            text.len(),
                            Self::MAX_BYTES
                        ),
                    });
                }
                $check(&text).map_err(|reason| $crate::error::CoreModelError::Invalid {
                    what: $schema,
                    detail: reason.to_string(),
                })?;
                Ok(Self(text))
            }

            /// The validated text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = <String as ::serde::Deserialize>::deserialize(deserializer)?;
                Self::new(text).map_err(<D::Error as ::serde::de::Error>::custom)
            }
        }

        impl ::schemars::JsonSchema for $name {
            fn schema_name() -> ::std::borrow::Cow<'static, str> {
                ::std::borrow::Cow::Borrowed($schema)
            }

            fn json_schema(_generator: &mut ::schemars::SchemaGenerator) -> ::schemars::Schema {
                ::schemars::json_schema!({
                    "type": "string",
                    "minLength": 1,
                    "maxLength": $max,
                    "description": $doc
                })
            }
        }
    };
}
pub(crate) use bounded_text;

/// Why attestation text was refused.
#[derive(Debug, Error)]
enum TextError {
    #[error("control characters are not allowed")]
    ControlCharacter,
}

fn printable_text(text: &str) -> Result<(), TextError> {
    if text.chars().any(char::is_control) {
        return Err(TextError::ControlCharacter);
    }
    Ok(())
}

bounded_text! {
    /// An attestation kind such as `review` or `ci`: non-empty UTF-8 with no
    /// control characters, at most [`crate::MAX_CONTROL_FRAME_BYTES`] bytes.
    pub struct AttestKind {
        schema: "AttestKind",
        max: crate::MAX_CONTROL_FRAME_BYTES,
        doc: "Attestation kind: non-empty UTF-8 with no control characters, at most one control frame (16777216 bytes).",
        check: printable_text,
    }
}

bounded_text! {
    /// An attestation result such as `approved` or `pass`: non-empty UTF-8
    /// with no control characters, at most [`crate::MAX_CONTROL_FRAME_BYTES`]
    /// bytes.
    pub struct AttestResult {
        schema: "AttestResult",
        max: crate::MAX_CONTROL_FRAME_BYTES,
        doc: "Attestation result: non-empty UTF-8 with no control characters, at most one control frame (16777216 bytes).",
        check: printable_text,
    }
}

/// Why pattern text was refused.
#[derive(Debug, Error)]
enum PatternError {
    #[error("pattern is empty")]
    Empty,
    #[error("pattern is {len} bytes; the limit is {limit}")]
    TooLong { len: usize, limit: usize },
    #[error("empty segment at position {index}")]
    EmptySegment { index: usize },
    #[error("`**` is only allowed as the final segment")]
    MisplacedDeep,
    #[error("segment `{segment}` mixes literal text with `*`; a wildcard must be a whole segment")]
    MixedWildcard { segment: String },
    #[error("invalid literal segment: {0}")]
    Literal(CoreModelError),
    #[error(
        "a ref pattern must start with the literal segment `refs` and name at least one \
         further segment"
    )]
    NotRefRooted,
}

/// Validates one literal segment against its namespace's grammar.
type CheckLiteral = fn(&str) -> Result<(), PatternError>;

/// One `/`-separated pattern segment.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Segment {
    Literal(String),
    Any,
}

/// One classified segment of pattern text.
enum Parsed {
    Segment(Segment),
    Deep,
}

fn parse_segment(
    part: &str,
    index: usize,
    last: usize,
    check_literal: CheckLiteral,
) -> Result<Parsed, PatternError> {
    match part {
        "" => Err(PatternError::EmptySegment { index }),
        "**" if index == last => Ok(Parsed::Deep),
        "**" => Err(PatternError::MisplacedDeep),
        "*" => Ok(Parsed::Segment(Segment::Any)),
        literal if literal.contains('*') => Err(PatternError::MixedWildcard {
            segment: literal.to_owned(),
        }),
        literal => {
            check_literal(literal)?;
            Ok(Parsed::Segment(Segment::Literal(literal.to_owned())))
        }
    }
}

/// The shared segment-pattern shape behind [`RefPattern`] and
/// [`PathPattern`]: leading segments plus an optional trailing `**`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Shape {
    segments: Vec<Segment>,
    deep: bool,
}

impl Shape {
    fn parse(text: &str, check_literal: CheckLiteral) -> Result<Self, PatternError> {
        if text.is_empty() {
            return Err(PatternError::Empty);
        }
        if text.len() > MAX_PATTERN_BYTES {
            return Err(PatternError::TooLong {
                len: text.len(),
                limit: MAX_PATTERN_BYTES,
            });
        }
        let parts: Vec<&str> = text.split('/').collect();
        let last = parts.len() - 1;
        let mut segments = Vec::with_capacity(parts.len());
        let mut deep = false;
        for (index, part) in parts.iter().enumerate() {
            match parse_segment(part, index, last, check_literal)? {
                Parsed::Segment(segment) => segments.push(segment),
                Parsed::Deep => deep = true,
            }
        }
        Ok(Self { segments, deep })
    }

    /// True when `name` (a `/`-separated byte name with no empty segment)
    /// is in this pattern's language.
    fn matches(&self, name: &[u8]) -> bool {
        if name.is_empty() {
            return false;
        }
        let mut parts = name.split(|byte| *byte == b'/');
        for segment in &self.segments {
            let Some(part) = parts.next() else {
                return false;
            };
            if part.is_empty() {
                return false;
            }
            if let Segment::Literal(literal) = segment
                && literal.as_bytes() != part
            {
                return false;
            }
        }
        if self.deep {
            parts.all(|part| !part.is_empty())
        } else {
            parts.next().is_none()
        }
    }

    /// Fewest segments in a name this shape matches. Names are nonempty, so
    /// a bare `**` still needs one segment and is the same language as
    /// `*/**`.
    fn min_len(&self) -> usize {
        self.segments.len().max(usize::from(self.deep))
    }

    /// The literal this shape demands at `position`, or `None` when it
    /// accepts any segment there (`*`, or past the leading segments).
    fn literal_at(&self, position: usize) -> Option<&str> {
        match self.segments.get(position) {
            Some(Segment::Literal(literal)) => Some(literal.as_str()),
            _ => None,
        }
    }

    /// True when every literal `self` demands is demanded by `other` at the
    /// same position. Where `other` accepts any segment, `self` must too:
    /// no literal covers a free position.
    fn literals_fit(&self, other: &Self) -> bool {
        self.segments
            .iter()
            .enumerate()
            .all(|(position, segment)| match segment {
                Segment::Any => true,
                Segment::Literal(literal) => other.literal_at(position) == Some(literal.as_str()),
            })
    }

    /// True when every name `other` matches is also matched by `self`.
    fn covers(&self, other: &Self) -> bool {
        let lengths = if self.deep {
            other.min_len() >= self.min_len()
        } else {
            !other.deep && other.min_len() == self.min_len()
        };
        lengths && self.literals_fit(other)
    }

    /// True when every name `self` matches is matched by at least one of
    /// `members`; see the module docs for why this is exact.
    ///
    /// Only members whose literals fit `self` can contribute, and each
    /// contributes its admitted lengths: one length without `**`, every
    /// length from its minimum up with it. `self` is covered exactly when
    /// every length it admits is contributed. Past the longest fixed length
    /// only `**` members remain, so the tail is decided by the smallest one
    /// and the lengths below it are checked individually.
    fn covered_by_union<'a>(&self, members: impl IntoIterator<Item = &'a Self>) -> bool {
        let mut fixed = BTreeSet::new();
        let mut tail_from: Option<usize> = None;
        for member in members
            .into_iter()
            .filter(|member| member.literals_fit(self))
        {
            let len = member.min_len();
            if member.deep {
                tail_from = Some(tail_from.map_or(len, |held| held.min(len)));
            } else {
                fixed.insert(len);
            }
        }
        let first = self.min_len();
        if self.deep {
            tail_from.is_some_and(|tail| (first..tail).all(|len| fixed.contains(&len)))
        } else {
            fixed.contains(&first) || tail_from.is_some_and(|tail| tail <= first)
        }
    }
}

impl fmt::Display for Shape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for segment in &self.segments {
            if !first {
                f.write_str("/")?;
            }
            first = false;
            match segment {
                Segment::Literal(literal) => f.write_str(literal)?,
                Segment::Any => f.write_str("*")?,
            }
        }
        if self.deep {
            if !first {
                f.write_str("/")?;
            }
            f.write_str("**")?;
        }
        Ok(())
    }
}

/// Internal access to the shared shape for generic subset checks.
trait Pattern: fmt::Display {
    fn shape(&self) -> &Shape;
}

fn ref_literal(segment: &str) -> Result<(), PatternError> {
    RefName::new(format!("refs/{segment}"))
        .map(|_| ())
        .map_err(PatternError::Literal)
}

fn path_literal(segment: &str) -> Result<(), PatternError> {
    RepoPath::new(segment)
        .map(|_| ())
        .map_err(PatternError::Literal)
}

fn parse_ref_pattern(text: &str) -> Result<Shape, PatternError> {
    let shape = Shape::parse(text, ref_literal)?;
    let rooted = matches!(shape.segments.first(), Some(Segment::Literal(first)) if first == "refs");
    if !rooted || shape.segments.len() + usize::from(shape.deep) < 2 {
        return Err(PatternError::NotRefRooted);
    }
    Ok(shape)
}

fn parse_path_pattern(text: &str) -> Result<Shape, PatternError> {
    Shape::parse(text, path_literal)
}

/// Defines a pattern newtype over [`Shape`] with its string wire form.
macro_rules! pattern_type {
    (
        $(#[$meta:meta])*
        $name:ident, $schema:literal, $doc:literal, $parse:path
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name(Shape);

        impl $name {
            /// Parses pattern text.
            ///
            /// # Errors
            /// Text outside the pattern grammar.
            pub fn parse(text: &str) -> Result<Self, CoreModelError> {
                $parse(text).map(Self).map_err(|reason| CoreModelError::Invalid {
                    what: $schema,
                    detail: reason.to_string(),
                })
            }

            /// True when `name` (raw bytes, `/`-separated) is in this pattern's language.
            #[must_use]
            pub fn matches(&self, name: &[u8]) -> bool {
                self.0.matches(name)
            }

            /// True when every name `other` matches is also matched by `self`.
            #[must_use]
            pub fn covers(&self, other: &Self) -> bool {
                self.0.covers(&other.0)
            }
        }

        impl Pattern for $name {
            fn shape(&self) -> &Shape {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = CoreModelError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::parse(text)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                Self::parse(&text).map_err(<D::Error as serde::de::Error>::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                Cow::Borrowed($schema)
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_PATTERN_BYTES,
                    "description": $doc
                })
            }
        }
    };
}

pattern_type! {
    /// A full-ref-name pattern such as `refs/heads/agent/**`. The first
    /// segment is the literal `refs`; see the module docs for the grammar.
    RefPattern,
    "RefPattern",
    "Full ref name pattern: literal segments, whole-segment `*`, and a trailing `**` (zero or more segments). Starts with `refs`.",
    parse_ref_pattern
}

pattern_type! {
    /// A repository path pattern such as `src/**`; see the module docs for
    /// the grammar. Literal segments obey the repository path grammar.
    PathPattern,
    "PathPattern",
    "Repository path pattern: literal segments, whole-segment `*`, and a trailing `**` (zero or more segments).",
    parse_path_pattern
}

/// The shape of the subtree rooted at `path`: `path/**`. A claim scope is a
/// subtree, so authorizing it needs the whole subtree covered, not only
/// `path` itself.
fn subtree_shape(path: &RepoPath) -> Shape {
    // A non-UTF-8 component equals no (UTF-8) literal segment, so it is
    // modelled as a wildcard: only a pattern wildcard covers it. That makes
    // the modelled subtree wider than the real one, which can only refuse
    // authority, never grant it.
    let segments = path
        .as_bytes()
        .split(|byte| *byte == b'/')
        .map(|part| {
            core::str::from_utf8(part)
                .map_or(Segment::Any, |text| Segment::Literal(text.to_owned()))
        })
        .collect();
    Shape {
        segments,
        deep: true,
    }
}

/// Which changes `write_changes` lets a session mutate; ordered
/// `Own < Session < All` (see the module docs for the interpretation).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum WriteScope {
    /// Only the change checked out in a workspace this session holds.
    Own,
    /// Additionally, any change this session created.
    Session,
    /// Any change.
    All,
}

/// Which operations `undo` may invert; ordered `Session < All`.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum UndoScope {
    /// Only operations performed by the same session.
    Session,
    /// Any operation.
    All,
}

/// Access to other sessions' private provenance and claim details.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ReadIntents {
    /// May read other sessions' private provenance claims.
    #[serde(default)]
    pub provenance: bool,
    /// May read other sessions' private claim details.
    #[serde(default)]
    pub claims: bool,
}

/// What a read needs, for [`Capabilities::authorize_read`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReadAccess {
    /// Ordinary object, history, diff, and status reads. Never gated here;
    /// the host's visibility policy still applies to every object read.
    Objects,
    /// Another session's private provenance.
    PrivateProvenance,
    /// Another session's private claim details.
    PrivateClaims,
}

/// The capability set of a session or the policy ceiling of a principal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Capabilities {
    /// Change-mutation authority; `None` is read-only.
    #[serde(default)]
    pub write_changes: Option<WriteScope>,
    /// Remote refs this session may push.
    #[serde(default)]
    pub push_refs: Vec<RefPattern>,
    /// Target refs this session may land into.
    #[serde(default)]
    pub land: Vec<RefPattern>,
    /// Path subtrees this session may claim.
    #[serde(default)]
    pub claim_paths: Vec<PathPattern>,
    /// Undo authority; `None` forbids undo.
    #[serde(default)]
    pub undo: Option<UndoScope>,
    /// Attestation kinds this session may record. A grant ending in `/`
    /// is a namespace prefix (for example `ci/` covers `ci/build`); any
    /// other grant matches exactly, so `ci` never covers `ci/build`.
    #[serde(default)]
    pub attest: Vec<AttestKind>,
    /// Private provenance/claim read access.
    #[serde(default)]
    pub read_intents: ReadIntents,
}

fn forbidden(field: &str, detail: String) -> CoreError {
    CoreError::new(
        ErrorCode::EForbidden,
        format!("capability `{field}` is not granted: {detail}"),
    )
    .with_hint("request a subset of the principal's capabilities")
}

/// True when every name `wanted` matches is matched by some pattern in
/// `ceiling`: by one member (the common case, decided without allocating) or
/// else by their union.
fn covered_by<P: Pattern>(wanted: &Shape, ceiling: &[P]) -> bool {
    ceiling.iter().any(|allowed| allowed.shape().covers(wanted))
        || wanted.covered_by_union(ceiling.iter().map(Pattern::shape))
}

/// True when an `attest` grant covers `kind`: an exact grant, or a
/// namespace grant (trailing `/`) that prefixes the kind. A grant without
/// a trailing slash never crosses into longer kinds, so a `ci` grant
/// cannot smuggle `ci/build` or `cix` past the ceiling.
fn attest_grant_covers(grant: &AttestKind, kind: &AttestKind) -> bool {
    grant == kind || (grant.as_str().ends_with('/') && kind.as_str().starts_with(grant.as_str()))
}

fn first_uncovered<'a, P: Pattern>(requested: &'a [P], ceiling: &[P]) -> Option<&'a P> {
    requested
        .iter()
        .find(|wanted| !covered_by(wanted.shape(), ceiling))
}

fn check_patterns<P: Pattern>(
    field: &str,
    requested: &[P],
    ceiling: &[P],
) -> Result<(), CoreError> {
    match first_uncovered(requested, ceiling) {
        None => Ok(()),
        Some(pattern) => Err(forbidden(
            field,
            format!("pattern `{pattern}` is not covered by the principal's policy"),
        )),
    }
}

impl Capabilities {
    /// Succeeds when every authority in `self` is within `ceiling`. Each
    /// requested ref or path pattern must be covered by the union of the
    /// ceiling's patterns (see the module docs).
    ///
    /// # Errors
    /// `E_FORBIDDEN` naming the first field that exceeds the ceiling.
    pub fn check_within(&self, ceiling: &Self) -> Result<(), CoreError> {
        if let Some(wanted) = self.write_changes
            && ceiling.write_changes.is_none_or(|allowed| wanted > allowed)
        {
            return Err(forbidden(
                "write_changes",
                format!(
                    "`{wanted:?}` exceeds the policy ({:?})",
                    ceiling.write_changes
                ),
            ));
        }
        check_patterns("push_refs", &self.push_refs, &ceiling.push_refs)?;
        check_patterns("land", &self.land, &ceiling.land)?;
        check_patterns("claim_paths", &self.claim_paths, &ceiling.claim_paths)?;
        if let Some(wanted) = self.undo
            && ceiling.undo.is_none_or(|allowed| wanted > allowed)
        {
            return Err(forbidden(
                "undo",
                format!("`{wanted:?}` exceeds the policy ({:?})", ceiling.undo),
            ));
        }
        if let Some(kind) = self.attest.iter().find(|kind| {
            !ceiling
                .attest
                .iter()
                .any(|allowed| attest_grant_covers(allowed, kind))
        }) {
            return Err(forbidden(
                "attest",
                format!("kind `{kind}` is not in the principal's policy"),
            ));
        }
        if self.read_intents.provenance && !ceiling.read_intents.provenance {
            return Err(forbidden(
                "read_intents",
                "private provenance is not in the principal's policy".to_owned(),
            ));
        }
        if self.read_intents.claims && !ceiling.read_intents.claims {
            return Err(forbidden(
                "read_intents",
                "private claims are not in the principal's policy".to_owned(),
            ));
        }
        Ok(())
    }

    /// The effective capabilities for a session: `requested` when it is a
    /// subset of `ceiling`, the whole `ceiling` when nothing was requested.
    ///
    /// # Errors
    /// `E_FORBIDDEN` when `requested` exceeds `ceiling`; nothing is
    /// truncated.
    pub fn negotiate(ceiling: &Self, requested: Option<&Self>) -> Result<Self, CoreError> {
        match requested {
            None => Ok(ceiling.clone()),
            Some(wanted) => {
                wanted.check_within(ceiling)?;
                Ok(wanted.clone())
            }
        }
    }

    /// Succeeds when `write_changes` reaches at least `needed`.
    ///
    /// # Errors
    /// `E_FORBIDDEN` when the session has no write authority or too little.
    pub fn require_write(&self, needed: WriteScope) -> Result<(), CoreError> {
        match self.write_changes {
            Some(held) if held >= needed => Ok(()),
            held => Err(forbidden(
                "write_changes",
                format!("`{needed:?}` is required; the session holds {held:?}"),
            )),
        }
    }

    /// Succeeds when `name` matches a `push_refs` pattern.
    ///
    /// # Errors
    /// `E_FORBIDDEN` otherwise.
    pub fn require_push(&self, name: &RefName) -> Result<(), CoreError> {
        if self.push_refs.iter().any(|p| p.matches(name.as_bytes())) {
            return Ok(());
        }
        Err(forbidden(
            "push_refs",
            format!(
                "no pattern matches {:?}",
                name.as_bytes().escape_ascii().to_string()
            ),
        ))
    }

    /// Succeeds when `name` matches a `land` pattern.
    ///
    /// # Errors
    /// `E_FORBIDDEN` otherwise.
    pub fn require_land(&self, name: &RefName) -> Result<(), CoreError> {
        if self.land.iter().any(|p| p.matches(name.as_bytes())) {
            return Ok(());
        }
        Err(forbidden(
            "land",
            format!(
                "no pattern matches {:?}",
                name.as_bytes().escape_ascii().to_string()
            ),
        ))
    }

    /// Succeeds when the subtree rooted at `path` is within the union of the
    /// `claim_paths` patterns.
    ///
    /// # Errors
    /// `E_FORBIDDEN` otherwise.
    pub fn require_claim(&self, path: &RepoPath) -> Result<(), CoreError> {
        if covered_by(&subtree_shape(path), &self.claim_paths) {
            return Ok(());
        }
        Err(forbidden(
            "claim_paths",
            format!(
                "no pattern covers the subtree {:?}",
                path.as_bytes().escape_ascii().to_string()
            ),
        ))
    }

    /// Succeeds when `undo` reaches at least `needed`.
    ///
    /// # Errors
    /// `E_FORBIDDEN` when undo is not granted or too narrow.
    pub fn require_undo(&self, needed: UndoScope) -> Result<(), CoreError> {
        match self.undo {
            Some(held) if held >= needed => Ok(()),
            held => Err(forbidden(
                "undo",
                format!("`{needed:?}` is required; the session holds {held:?}"),
            )),
        }
    }

    /// Succeeds when `kind` is in `attest`, exactly or under a namespace
    /// grant (a granted `ci/` covers `ci/build`).
    ///
    /// # Errors
    /// `E_FORBIDDEN` otherwise.
    pub fn require_attest(&self, kind: &AttestKind) -> Result<(), CoreError> {
        if self
            .attest
            .iter()
            .any(|granted| attest_grant_covers(granted, kind))
        {
            return Ok(());
        }
        Err(forbidden("attest", format!("kind `{kind}` is not granted")))
    }

    /// Authorizes a read. [`ReadAccess::Objects`] always succeeds: ordinary
    /// reads are not gated by `read_intents`.
    ///
    /// # Errors
    /// `E_FORBIDDEN` for private provenance or claim details without the
    /// matching `read_intents` flag.
    pub fn authorize_read(&self, access: ReadAccess) -> Result<(), CoreError> {
        match access {
            ReadAccess::Objects => Ok(()),
            ReadAccess::PrivateProvenance if self.read_intents.provenance => Ok(()),
            ReadAccess::PrivateClaims if self.read_intents.claims => Ok(()),
            ReadAccess::PrivateProvenance => Err(forbidden(
                "read_intents",
                "private provenance requires `read_intents.provenance`".to_owned(),
            )),
            ReadAccess::PrivateClaims => Err(forbidden(
                "read_intents",
                "private claims require `read_intents.claims`".to_owned(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(text: &str) -> RefPattern {
        RefPattern::parse(text).unwrap_or_else(|err| panic!("{text}: {err}"))
    }

    fn pp(text: &str) -> PathPattern {
        PathPattern::parse(text).unwrap_or_else(|err| panic!("{text}: {err}"))
    }

    fn name(text: &str) -> RefName {
        RefName::new(text).expect("ref name")
    }

    fn path(text: &str) -> RepoPath {
        RepoPath::new(text).expect("repo path")
    }

    fn code(result: Result<(), CoreError>) -> ErrorCode {
        result.expect_err("expected failure").code
    }

    #[test]
    fn ref_patterns_reject_everything_outside_the_grammar() {
        for bad in [
            "",
            "refs",
            "heads/x",
            "refs//x",
            "refs/heads/",
            "/refs/heads/x",
            "refs/he*ds/x",
            "refs/heads/x*",
            "refs/**/x",
            "refs/heads/**/",
            "refs/../x",
            "refs/heads/topic.lock",
            "refs/heads/a b",
            "refs/heads/a\nb",
        ] {
            assert!(RefPattern::parse(bad).is_err(), "accepted {bad:?}");
        }
        let long = format!("refs/{}", "a".repeat(MAX_PATTERN_BYTES));
        assert!(RefPattern::parse(&long).is_err());
        for good in [
            "refs/heads/*",
            "refs/heads/**",
            "refs/**",
            "refs/tags/v1",
            "refs/*",
        ] {
            assert!(RefPattern::parse(good).is_ok(), "rejected {good:?}");
        }
    }

    #[test]
    fn path_patterns_reject_unsafe_literals_and_misplaced_wildcards() {
        for bad in [
            "", "/a", "a/", "a//b", "a/**/b", "a/./b", "../x", "a/..", ".git/**", "src/*.rs",
            "a\0b",
        ] {
            assert!(PathPattern::parse(bad).is_err(), "accepted {bad:?}");
        }
        for good in ["**", "src/**", "docs/*/index.md", "a", "*"] {
            assert!(PathPattern::parse(good).is_ok(), "rejected {good:?}");
        }
    }

    #[test]
    fn patterns_render_canonically_and_round_trip_through_json() {
        for text in ["refs/heads/agent/**", "refs/heads/*/x", "refs/**"] {
            let parsed = rp(text);
            assert_eq!(parsed.to_string(), text);
            let json = sonic_rs::to_string(&parsed).expect("json");
            assert_eq!(json, format!("\"{text}\""));
            let back: RefPattern = sonic_rs::from_str(&json).expect("parse");
            assert_eq!(back, parsed);
        }
        assert!(sonic_rs::from_str::<RefPattern>("\"refs/heads/a*b\"").is_err());
        assert!(sonic_rs::from_str::<PathPattern>("7").is_err());
    }

    #[test]
    fn single_star_is_one_segment_and_double_star_is_zero_or_more() {
        let star = rp("refs/heads/*");
        assert!(star.matches(b"refs/heads/main"));
        assert!(!star.matches(b"refs/heads/feature/x"));
        assert!(!star.matches(b"refs/heads"));
        assert!(!star.matches(b"refs/heads/"));
        let deep = rp("refs/heads/**");
        assert!(deep.matches(b"refs/heads"));
        assert!(deep.matches(b"refs/heads/a"));
        assert!(deep.matches(b"refs/heads/a/b/c"));
        assert!(!deep.matches(b"refs/tags/a"));
        assert!(!deep.matches(b"refs/headsx/a"));
        assert!(!deep.matches(b"refs/heads//a"));
        let mid = rp("refs/heads/*/tip");
        assert!(mid.matches(b"refs/heads/x/tip"));
        assert!(!mid.matches(b"refs/heads/x/y/tip"));
        // Non-UTF-8 names are matched bytewise; a wildcard accepts them and a
        // literal never does.
        assert!(star.matches(b"refs/heads/\xff\xfe"));
        assert!(!rp("refs/heads/main").matches(b"refs/heads/ma\xffn"));
        assert!(!deep.matches(b""));
    }

    fn extend_all<T: Clone>(prefixes: &[Vec<T>], alphabet: &[T]) -> Vec<Vec<T>> {
        prefixes
            .iter()
            .flat_map(|prefix| {
                alphabet.iter().map(move |item| {
                    let mut next = prefix.clone();
                    next.push(item.clone());
                    next
                })
            })
            .collect()
    }

    /// Every sequence over `alphabet` with length `0..=max_len`.
    fn sequences<T: Clone>(alphabet: &[T], max_len: usize) -> Vec<Vec<T>> {
        let mut all: Vec<Vec<T>> = vec![Vec::new()];
        let mut frontier: Vec<Vec<T>> = vec![Vec::new()];
        for _ in 0..max_len {
            frontier = extend_all(&frontier, alphabet);
            all.extend(frontier.iter().cloned());
        }
        all
    }

    /// Every pattern with at most `max_segments` leading segments over
    /// `literals` and `*`, plus the deep flag, minus the empty non-deep
    /// shape.
    fn shapes_over(literals: &[&str], max_segments: usize) -> Vec<Shape> {
        let mut alphabet: Vec<Segment> = literals
            .iter()
            .map(|literal| Segment::Literal((*literal).to_owned()))
            .collect();
        alphabet.push(Segment::Any);
        sequences(&alphabet, max_segments)
            .into_iter()
            .flat_map(|segments| {
                [false, true].map(|deep| Shape {
                    segments: segments.clone(),
                    deep,
                })
            })
            .filter(|shape| !shape.segments.is_empty() || shape.deep)
            .collect()
    }

    fn all_shapes() -> Vec<Shape> {
        shapes_over(&["a", "b"], 3)
    }

    fn all_names() -> Vec<Vec<u8>> {
        sequences(&["a", "b", "c"], 5)
            .into_iter()
            .filter(|parts| !parts.is_empty())
            .map(|parts| parts.join("/").into_bytes())
            .collect()
    }

    #[test]
    fn covers_agrees_with_matching_on_all_small_patterns() {
        // `c` appears in no pattern, so it stands for an arbitrary segment:
        // `covers` must hold exactly when matching is containment over the
        // bounded name universe (witnesses of non-containment have at most
        // four segments).
        let shapes = all_shapes();
        let names = all_names();
        for p in &shapes {
            for q in &shapes {
                let contained = names.iter().all(|n| !q.matches(n) || p.matches(n));
                assert_eq!(p.covers(q), contained, "P={p} Q={q}");
            }
        }
    }

    /// True when the union of `ceiling` leaves part of `wanted` uncovered.
    fn uncovered<P: Pattern>(wanted: &P, ceiling: &[P]) -> bool {
        first_uncovered(core::slice::from_ref(wanted), ceiling).is_some()
    }

    /// Every multiset of three items, in index order.
    fn triples<T: Copy>(items: &[T]) -> impl Iterator<Item = [T; 3]> + '_ {
        items.iter().enumerate().flat_map(move |(i, &first)| {
            items
                .iter()
                .enumerate()
                .skip(i)
                .flat_map(move |(j, &second)| {
                    items[j..].iter().map(move |&third| [first, second, third])
                })
        })
    }

    /// Checks every request in `entries` (shape and the mask of names it
    /// matches) against the union of `members`.
    fn assert_union_matches(entries: &[(&Shape, u128)], members: [(&Shape, u128); 3]) {
        let union = members
            .iter()
            .fold(0_u128, |union, &(_, mask)| union | mask);
        let shapes = members.map(|(shape, _)| shape);
        for &(wanted, mask) in entries {
            assert_eq!(
                wanted.covered_by_union(shapes),
                mask & !union == 0,
                "Q={wanted} members={} | {} | {}",
                shapes[0],
                shapes[1],
                shapes[2]
            );
        }
    }

    #[test]
    fn union_cover_agrees_with_matching_over_every_small_union() {
        // `c` appears in no pattern, so it stands for every segment a pattern
        // cannot name. Witnesses of non-coverage have at most
        // `max_segments + 1` segments; the universe goes one past that. Names
        // are bits of a mask, so containment in a union is mask algebra.
        for (literals, max_segments) in [(&["a", "b"][..], 2), (&["a"][..], 3)] {
            let shapes = shapes_over(literals, max_segments);
            let mut alphabet = literals.to_vec();
            alphabet.push("c");
            let names: Vec<Vec<u8>> = sequences(&alphabet, max_segments + 2)
                .into_iter()
                .filter(|parts| !parts.is_empty())
                .map(|parts| parts.join("/").into_bytes())
                .collect();
            assert!(names.len() <= 128, "{} names", names.len());
            let entries: Vec<(&Shape, u128)> = shapes
                .iter()
                .map(|shape| {
                    let mask = names
                        .iter()
                        .enumerate()
                        .filter(|(_, name)| shape.matches(name))
                        .fold(0_u128, |mask, (index, _)| mask | (1_u128 << index));
                    (shape, mask)
                })
                .collect();
            for members in triples(&entries) {
                assert_union_matches(&entries, members);
            }
        }
    }

    #[test]
    fn any_name_is_covered_only_through_every_depth() {
        // Names have at least one segment: `**` and `*/**` are one language.
        assert!(pp("**").covers(&pp("*/**")));
        assert!(pp("*/**").covers(&pp("**")));
        // `**` is depth one, depth two, and depth three or more, in any order.
        let any = pp("**");
        assert!(!uncovered(&any, &[pp("*"), pp("*/*"), pp("*/*/*/**")]));
        assert!(!uncovered(&any, &[pp("*/*/*/**"), pp("*/*"), pp("*")]));
        // A missing depth, a missing tail, or a tail starting too deep all deny.
        assert!(uncovered(&any, &[pp("*/*"), pp("*/*/*/**")]));
        assert!(uncovered(&any, &[pp("*"), pp("*/*/*/**")]));
        assert!(uncovered(&any, &[pp("*"), pp("*/*"), pp("*/*/*")]));
        assert!(uncovered(&any, &[pp("*"), pp("*/*"), pp("*/*/*/*/**")]));
    }

    #[test]
    fn finite_literals_never_cover_a_free_position() {
        // Any number of literals leaves a segment no literal names.
        let wanted = rp("refs/heads/*");
        let literals = [
            rp("refs/heads/a"),
            rp("refs/heads/b"),
            rp("refs/heads/main"),
        ];
        assert!(uncovered(&wanted, &literals));
        // One wildcard member covers it, whatever else is listed.
        assert!(!uncovered(
            &wanted,
            &[rp("refs/heads/a"), rp("refs/heads/*")]
        ));
        // A free position in the request needs a wildcard at that same
        // position: `a/*` and `*/b` together do not cover `*/*`.
        assert!(uncovered(&pp("*/*"), &[pp("a/*"), pp("*/b")]));
    }

    #[test]
    fn claim_authorization_uses_the_union_of_patterns() {
        let split = Capabilities {
            claim_paths: vec![pp("src"), pp("src/*/**")],
            ..Capabilities::default()
        };
        assert!(split.require_claim(&path("src")).is_ok());
        assert!(split.require_claim(&path("src/a")).is_ok());
        assert!(split.require_claim(&path("src/a/b/c")).is_ok());
        assert_eq!(
            code(split.require_claim(&path("docs"))),
            ErrorCode::EForbidden
        );
        // Without the literal branch, `src` itself is outside the claim.
        let deep_only = Capabilities {
            claim_paths: vec![pp("src/*/**")],
            ..Capabilities::default()
        };
        assert_eq!(
            code(deep_only.require_claim(&path("src"))),
            ErrorCode::EForbidden
        );
        // `src/a/**` leaves the rest of `src` unclaimable.
        let narrow = Capabilities {
            claim_paths: vec![pp("src"), pp("src/a/**")],
            ..Capabilities::default()
        };
        assert!(narrow.require_claim(&path("src/a")).is_ok());
        assert_eq!(
            code(narrow.require_claim(&path("src"))),
            ErrorCode::EForbidden
        );
    }

    #[test]
    fn covers_is_reflexive_and_wildcards_only_widen() {
        let a = rp("refs/heads/agent/**");
        assert!(a.covers(&a));
        assert!(rp("refs/heads/**").covers(&a));
        assert!(!a.covers(&rp("refs/heads/**")));
        assert!(rp("refs/heads/*").covers(&rp("refs/heads/main")));
        assert!(!rp("refs/heads/*").covers(&rp("refs/heads/**")));
        assert!(!rp("refs/heads/*").covers(&rp("refs/heads/a/b")));
        assert!(rp("refs/**").covers(&rp("refs/heads/*/x")));
    }

    #[test]
    fn claim_authorization_covers_whole_subtrees() {
        let caps = Capabilities {
            claim_paths: vec![pp("src/**")],
            ..Capabilities::default()
        };
        assert!(caps.require_claim(&path("src")).is_ok());
        assert!(caps.require_claim(&path("src/a/b.rs")).is_ok());
        assert_eq!(
            code(caps.require_claim(&path("srcx"))),
            ErrorCode::EForbidden
        );
        assert_eq!(
            code(caps.require_claim(&path("docs/a"))),
            ErrorCode::EForbidden
        );
        // `src/*` matches only depth-two paths; a subtree claim on `src/a`
        // would reach deeper, so it is not covered.
        let shallow = Capabilities {
            claim_paths: vec![pp("src/*")],
            ..Capabilities::default()
        };
        assert_eq!(
            code(shallow.require_claim(&path("src/a"))),
            ErrorCode::EForbidden
        );
        let wild = Capabilities {
            claim_paths: vec![pp("**")],
            ..Capabilities::default()
        };
        assert!(wild.require_claim(&path("anything/at/all")).is_ok());
    }

    fn policy() -> Capabilities {
        Capabilities {
            write_changes: Some(WriteScope::Session),
            push_refs: vec![rp("refs/heads/agent/**"), rp("refs/notes/ruk-attest")],
            land: vec![rp("refs/heads/main")],
            claim_paths: vec![pp("src/**")],
            undo: Some(UndoScope::Session),
            attest: vec![AttestKind::new("review").expect("kind")],
            read_intents: ReadIntents {
                provenance: true,
                claims: false,
            },
        }
    }

    #[test]
    fn negotiation_returns_requested_subset_or_the_whole_ceiling() {
        let ceiling = policy();
        assert_eq!(
            Capabilities::negotiate(&ceiling, None).expect("all"),
            ceiling
        );
        let narrow = Capabilities {
            write_changes: Some(WriteScope::Own),
            push_refs: vec![rp("refs/heads/agent/feature/*")],
            attest: vec![AttestKind::new("review").expect("kind")],
            ..Capabilities::default()
        };
        assert_eq!(
            Capabilities::negotiate(&ceiling, Some(&narrow)).expect("subset"),
            narrow
        );
        assert_eq!(
            Capabilities::negotiate(&ceiling, Some(&Capabilities::default())).expect("none"),
            Capabilities::default()
        );
    }

    #[test]
    fn excess_requests_fail_forbidden_naming_the_field_and_never_truncate() {
        let ceiling = policy();
        let cases = [
            (
                Capabilities {
                    write_changes: Some(WriteScope::All),
                    ..Capabilities::default()
                },
                "write_changes",
            ),
            (
                // Overlaps the policy but is wider: not clipped to the overlap.
                Capabilities {
                    push_refs: vec![rp("refs/heads/**")],
                    ..Capabilities::default()
                },
                "push_refs",
            ),
            (
                Capabilities {
                    push_refs: vec![rp("refs/heads/agent/a"), rp("refs/heads/main")],
                    ..Capabilities::default()
                },
                "push_refs",
            ),
            (
                Capabilities {
                    land: vec![rp("refs/heads/*")],
                    ..Capabilities::default()
                },
                "land",
            ),
            (
                Capabilities {
                    claim_paths: vec![pp("**")],
                    ..Capabilities::default()
                },
                "claim_paths",
            ),
            (
                Capabilities {
                    undo: Some(UndoScope::All),
                    ..Capabilities::default()
                },
                "undo",
            ),
            (
                Capabilities {
                    attest: vec![AttestKind::new("ci").expect("kind")],
                    ..Capabilities::default()
                },
                "attest",
            ),
            (
                Capabilities {
                    read_intents: ReadIntents {
                        provenance: false,
                        claims: true,
                    },
                    ..Capabilities::default()
                },
                "read_intents",
            ),
        ];
        for (requested, field) in cases {
            let err =
                Capabilities::negotiate(&ceiling, Some(&requested)).expect_err("excess must fail");
            assert_eq!(err.code, ErrorCode::EForbidden, "{field}");
            assert!(err.message.contains(field), "{field}: {}", err.message);
        }
        // A ceiling with no authority at all grants nothing, including undo.
        let none = Capabilities::default();
        assert_eq!(
            code(
                Capabilities {
                    undo: Some(UndoScope::Session),
                    ..Capabilities::default()
                }
                .check_within(&none)
            ),
            ErrorCode::EForbidden
        );
    }

    #[test]
    fn authorization_predicates_follow_the_effective_set() {
        let caps = policy();
        assert!(caps.require_write(WriteScope::Own).is_ok());
        assert!(caps.require_write(WriteScope::Session).is_ok());
        assert_eq!(
            code(caps.require_write(WriteScope::All)),
            ErrorCode::EForbidden
        );
        assert_eq!(
            code(Capabilities::default().require_write(WriteScope::Own)),
            ErrorCode::EForbidden
        );
        assert!(caps.require_push(&name("refs/heads/agent/x/y")).is_ok());
        assert!(caps.require_push(&name("refs/notes/ruk-attest")).is_ok());
        assert_eq!(
            code(caps.require_push(&name("refs/heads/main"))),
            ErrorCode::EForbidden
        );
        assert!(caps.require_land(&name("refs/heads/main")).is_ok());
        assert_eq!(
            code(caps.require_land(&name("refs/heads/dev"))),
            ErrorCode::EForbidden
        );
        assert!(caps.require_undo(UndoScope::Session).is_ok());
        assert_eq!(
            code(caps.require_undo(UndoScope::All)),
            ErrorCode::EForbidden
        );
        let review = AttestKind::new("review").expect("kind");
        let ci = AttestKind::new("ci").expect("kind");
        assert!(caps.require_attest(&review).is_ok());
        assert_eq!(code(caps.require_attest(&ci)), ErrorCode::EForbidden);
    }

    #[test]
    fn attest_namespace_grants_cover_kinds_without_crossing_namespaces() {
        let kind = |text: &str| AttestKind::new(text).expect("kind");
        let granted = |texts: &[&str]| Capabilities {
            attest: texts.iter().map(|text| kind(text)).collect(),
            ..Capabilities::default()
        };
        let namespaced = granted(&["ci/", "review"]);
        assert!(namespaced.require_attest(&kind("ci/build")).is_ok());
        assert!(namespaced.require_attest(&kind("ci/")).is_ok());
        assert!(namespaced.require_attest(&kind("review")).is_ok());
        for denied in ["ci", "cix", "ci2/build", "model/review"] {
            assert_eq!(
                code(namespaced.require_attest(&kind(denied))),
                ErrorCode::EForbidden,
                "{denied} must not ride the ci/ namespace"
            );
        }
        let exact = granted(&["ci"]);
        assert!(exact.require_attest(&kind("ci")).is_ok());
        assert_eq!(
            code(exact.require_attest(&kind("ci/build"))),
            ErrorCode::EForbidden,
            "a grant without a trailing slash never prefixes"
        );
        let ceiling = granted(&["ci/"]);
        assert!(granted(&["ci/build"]).check_within(&ceiling).is_ok());
        assert!(granted(&["ci/"]).check_within(&ceiling).is_ok());
        assert_eq!(
            code(granted(&["ci/"]).check_within(&granted(&["ci/build"]))),
            ErrorCode::EForbidden,
            "a narrower ceiling cannot cover a wider request"
        );
        assert_eq!(
            code(granted(&["review"]).check_within(&ceiling)),
            ErrorCode::EForbidden
        );
    }

    #[test]
    fn ordinary_reads_are_never_gated_by_read_intents() {
        let none = Capabilities::default();
        assert!(none.authorize_read(ReadAccess::Objects).is_ok());
        assert_eq!(
            code(none.authorize_read(ReadAccess::PrivateProvenance)),
            ErrorCode::EForbidden
        );
        assert_eq!(
            code(none.authorize_read(ReadAccess::PrivateClaims)),
            ErrorCode::EForbidden
        );
        let caps = policy();
        assert!(caps.authorize_read(ReadAccess::PrivateProvenance).is_ok());
        assert_eq!(
            code(caps.authorize_read(ReadAccess::PrivateClaims)),
            ErrorCode::EForbidden
        );
    }

    #[test]
    fn scope_orderings_are_the_documented_lattices() {
        assert!(WriteScope::Own < WriteScope::Session && WriteScope::Session < WriteScope::All);
        assert!(UndoScope::Session < UndoScope::All);
    }

    #[test]
    fn json_shape_defaults_to_no_authority_and_rejects_invalid_members() {
        let empty: Capabilities = sonic_rs::from_str("{}").expect("empty");
        assert_eq!(empty, Capabilities::default());
        assert!(empty.write_changes.is_none() && empty.undo.is_none());
        // Unknown fields (a later minor version) are ignored and grant nothing.
        let future: Capabilities =
            sonic_rs::from_str("{\"write_changes\":\"own\",\"future_power\":true}")
                .expect("future");
        assert_eq!(future.write_changes, Some(WriteScope::Own));
        assert!(future.push_refs.is_empty());
        for bad in [
            "{\"write_changes\":\"root\"}",
            "{\"undo\":\"own\"}",
            "{\"push_refs\":[\"heads/x\"]}",
            "{\"claim_paths\":[\"a/**/b\"]}",
            "{\"attest\":[\"\"]}",
            "{\"attest\":[\"a\\nb\"]}",
            "{\"read_intents\":{\"provenance\":\"yes\"}}",
        ] {
            assert!(
                sonic_rs::from_str::<Capabilities>(bad).is_err(),
                "accepted {bad}"
            );
        }
        let round = policy();
        let json = sonic_rs::to_string(&round).expect("json");
        let back: Capabilities = sonic_rs::from_str(&json).expect("parse");
        assert_eq!(back, round);
    }

    #[test]
    fn attest_text_is_bounded_by_the_control_frame_in_bytes() {
        let limit = crate::MAX_CONTROL_FRAME_BYTES;
        assert_eq!(AttestKind::MAX_BYTES, limit);
        assert_eq!(AttestResult::MAX_BYTES, limit);
        // Valid UTF-8 beyond a few hundred bytes is ordinary, through the
        // constructor and the wire alike.
        let long = "approved \u{2713} ".repeat(100);
        assert!(long.len() > 256);
        assert!(AttestKind::new(long.as_str()).is_ok());
        assert!(AttestResult::new(long.as_str()).is_ok());
        let wire = sonic_rs::to_string(&long).expect("json");
        assert!(sonic_rs::from_str::<AttestKind>(&wire).is_ok());
        assert!(sonic_rs::from_str::<AttestResult>(&wire).is_ok());
        // The boundary is the frame size exactly.
        assert!(AttestKind::new("a".repeat(limit)).is_ok());
        assert!(AttestKind::new("a".repeat(limit + 1)).is_err());
        // It counts bytes, not characters: 3-byte characters fill all but one
        // byte of the limit.
        let wide = "\u{2713}".repeat(limit / 3);
        assert_eq!(wide.len(), limit - 1);
        assert!(AttestResult::new(format!("{wide}a")).is_ok());
        assert!(AttestResult::new(format!("{wide}ab")).is_err());
        // Content rules are unchanged.
        assert!(AttestKind::new("").is_err());
        assert!(AttestResult::new("").is_err());
        assert!(AttestResult::new("pass\u{7f}").is_err());
        assert!(AttestResult::new("approved \u{2713}").is_ok());
    }

    #[test]
    fn attest_schemas_publish_the_validator_bound() {
        let mut generator = SchemaGenerator::default();
        for (schema, max) in [
            (
                <AttestKind as JsonSchema>::json_schema(&mut generator),
                AttestKind::MAX_BYTES,
            ),
            (
                <AttestResult as JsonSchema>::json_schema(&mut generator),
                AttestResult::MAX_BYTES,
            ),
        ] {
            assert_eq!(
                schema.to_value()["maxLength"].as_u64(),
                Some(u64::try_from(max).expect("fits u64"))
            );
        }
    }

    #[test]
    fn negotiation_accepts_ref_union_cover_for_push_refs() {
        // Policy splits `refs/heads/*/**` by depth: exactly one segment via
        // `refs/heads/*`, two-or-more via `refs/heads/*/*/**`. Neither branch
        // alone covers the request; their union does.
        let one = rp("refs/heads/*");
        let two_plus = rp("refs/heads/*/*/**");
        let wanted = rp("refs/heads/*/**");
        assert!(!one.covers(&wanted));
        assert!(!two_plus.covers(&wanted));
        // Name-level exactness over a bounded universe: every bounded name the
        // request matches is matched by exactly the union of the branches.
        for suffix in sequences(&["a", "b"], 4) {
            if suffix.is_empty() {
                continue;
            }
            let full = format!("refs/heads/{}", suffix.join("/"));
            let bytes = full.as_bytes();
            assert_eq!(
                wanted.matches(bytes),
                one.matches(bytes) || two_plus.matches(bytes),
                "mismatch on {full}"
            );
        }
        // Concrete witnesses pin each branch: depth one via `*`, deeper via
        // `*/*/**` (including a deep tail past the bounded scan).
        for witness in [
            "refs/heads/main",
            "refs/heads/a/b",
            "refs/heads/a/b/c/d/e/f",
        ] {
            assert!(
                wanted.matches(witness.as_bytes()),
                "request misses {witness}"
            );
        }
        assert!(one.matches(b"refs/heads/main"));
        assert!(!two_plus.matches(b"refs/heads/main"));
        assert!(!one.matches(b"refs/heads/a/b"));
        assert!(two_plus.matches(b"refs/heads/a/b"));
        assert!(two_plus.matches(b"refs/heads/a/b/c/d/e/f"));

        let ceiling = Capabilities {
            push_refs: vec![one, two_plus],
            ..Capabilities::default()
        };
        let requested = Capabilities {
            push_refs: vec![wanted],
            ..Capabilities::default()
        };
        assert_eq!(
            Capabilities::negotiate(&ceiling, Some(&requested))
                .expect("split-depth union must negotiate"),
            requested
        );
    }

    #[test]
    fn negotiation_accepts_ref_union_cover_for_land() {
        // Same depth-split union as push_refs, exercised through `land` so the
        // generic subset check cannot fix one field only.
        let one = rp("refs/heads/*");
        let two_plus = rp("refs/heads/*/*/**");
        let wanted = rp("refs/heads/*/**");
        assert!(!one.covers(&wanted));
        assert!(!two_plus.covers(&wanted));
        for suffix in sequences(&["a", "b"], 4) {
            if suffix.is_empty() {
                continue;
            }
            let full = format!("refs/heads/{}", suffix.join("/"));
            let bytes = full.as_bytes();
            assert_eq!(
                wanted.matches(bytes),
                one.matches(bytes) || two_plus.matches(bytes),
                "mismatch on {full}"
            );
        }
        assert!(wanted.matches(b"refs/heads/main"));
        assert!(wanted.matches(b"refs/heads/a/b"));
        assert!(wanted.matches(b"refs/heads/a/b/c/d/e/f"));

        let ceiling = Capabilities {
            land: vec![one, two_plus],
            ..Capabilities::default()
        };
        let requested = Capabilities {
            land: vec![wanted],
            ..Capabilities::default()
        };
        assert_eq!(
            Capabilities::negotiate(&ceiling, Some(&requested))
                .expect("split-depth union must negotiate"),
            requested
        );
    }

    #[test]
    fn negotiation_accepts_path_union_cover_for_claim_paths() {
        // Policy splits `src/**` into the literal `src` plus `src/*/**`.
        // Neither branch alone covers the request; their union does.
        let here = pp("src");
        let below = pp("src/*/**");
        let wanted = pp("src/**");
        assert!(!here.covers(&wanted));
        assert!(!below.covers(&wanted));
        // `src` itself comes only from the literal branch.
        assert!(wanted.matches(b"src"));
        assert!(here.matches(b"src"));
        assert!(!below.matches(b"src"));
        // Every bounded name below `src` comes only from the deep branch.
        for suffix in sequences(&["a", "b"], 3) {
            if suffix.is_empty() {
                continue;
            }
            let full = format!("src/{}", suffix.join("/"));
            let bytes = full.as_bytes();
            assert!(wanted.matches(bytes), "request misses {full}");
            assert!(below.matches(bytes), "deep branch misses {full}");
            assert!(!here.matches(bytes), "literal branch overreaches {full}");
        }
        // Concrete witnesses pin each branch, including a deep tail.
        for witness in ["src", "src/a", "src/a/b/c/d"] {
            assert!(
                wanted.matches(witness.as_bytes()),
                "request misses {witness}"
            );
        }

        let ceiling = Capabilities {
            claim_paths: vec![here, below],
            ..Capabilities::default()
        };
        let requested = Capabilities {
            claim_paths: vec![wanted],
            ..Capabilities::default()
        };
        assert_eq!(
            Capabilities::negotiate(&ceiling, Some(&requested))
                .expect("literal-plus-deep union must negotiate"),
            requested
        );
    }

    #[test]
    fn negotiation_denies_union_gaps_with_witnesses() {
        // `push_refs` missing the deep branch: `refs/heads/a/b` is in the
        // request but in no policy branch.
        let ceiling = Capabilities {
            push_refs: vec![rp("refs/heads/*")],
            ..Capabilities::default()
        };
        let requested = Capabilities {
            push_refs: vec![rp("refs/heads/*/**")],
            ..Capabilities::default()
        };
        assert!(requested.push_refs[0].matches(b"refs/heads/a/b"));
        assert!(
            !ceiling
                .push_refs
                .iter()
                .any(|pattern| pattern.matches(b"refs/heads/a/b"))
        );
        let gap_found = sequences(&["a", "b"], 4)
            .iter()
            .filter(|suffix| !suffix.is_empty())
            .any(|suffix| {
                let full = format!("refs/heads/{}", suffix.join("/"));
                let bytes = full.as_bytes();
                requested.push_refs[0].matches(bytes)
                    && !ceiling
                        .push_refs
                        .iter()
                        .any(|pattern| pattern.matches(bytes))
            });
        assert!(gap_found, "bounded scan must expose the depth gap");
        let err = Capabilities::negotiate(&ceiling, Some(&requested)).expect_err("gap must deny");
        assert_eq!(err.code, ErrorCode::EForbidden);
        assert!(err.message.contains("push_refs"), "{}", err.message);

        // `land` with the deep branch under the wrong literal: `refs/tags`
        // contributes nothing to a `refs/heads` request.
        let ceiling = Capabilities {
            land: vec![rp("refs/heads/*"), rp("refs/tags/*/*/**")],
            ..Capabilities::default()
        };
        let requested = Capabilities {
            land: vec![rp("refs/heads/*/**")],
            ..Capabilities::default()
        };
        assert!(requested.land[0].matches(b"refs/heads/a/b"));
        assert!(
            !ceiling
                .land
                .iter()
                .any(|pattern| pattern.matches(b"refs/heads/a/b"))
        );
        let err = Capabilities::negotiate(&ceiling, Some(&requested)).expect_err("gap must deny");
        assert_eq!(err.code, ErrorCode::EForbidden);
        assert!(err.message.contains("land"), "{}", err.message);

        // `claim_paths` missing the literal branch: `src` itself is uncovered.
        let ceiling = Capabilities {
            claim_paths: vec![pp("src/*/**")],
            ..Capabilities::default()
        };
        let requested = Capabilities {
            claim_paths: vec![pp("src/**")],
            ..Capabilities::default()
        };
        assert!(requested.claim_paths[0].matches(b"src"));
        assert!(
            !ceiling
                .claim_paths
                .iter()
                .any(|pattern| pattern.matches(b"src"))
        );
        let err = Capabilities::negotiate(&ceiling, Some(&requested)).expect_err("gap must deny");
        assert_eq!(err.code, ErrorCode::EForbidden);
        assert!(err.message.contains("claim_paths"), "{}", err.message);

        // `claim_paths` missing the deep branch: `src/a` is uncovered.
        let ceiling = Capabilities {
            claim_paths: vec![pp("src")],
            ..Capabilities::default()
        };
        let requested = Capabilities {
            claim_paths: vec![pp("src/**")],
            ..Capabilities::default()
        };
        assert!(requested.claim_paths[0].matches(b"src/a"));
        assert!(
            !ceiling
                .claim_paths
                .iter()
                .any(|pattern| pattern.matches(b"src/a"))
        );
        let err = Capabilities::negotiate(&ceiling, Some(&requested)).expect_err("gap must deny");
        assert_eq!(err.code, ErrorCode::EForbidden);
        assert!(err.message.contains("claim_paths"), "{}", err.message);
    }
}
