//! Named refs: the byte-safe [`RefName`], [`RefTarget`], and the model-level
//! rules every ref write and every symbolic resolution must satisfy.
//!
//! `refs` (full byte refname -> `Direct(Oid) | Symbolic(refname)`) is the one
//! resolved named-ref authority (core contract, "Ref and workspace
//! authority"). A store implements [`RefRead`] over its ordered key space; the
//! rules here run against that interface, so they hold for one ref or for a
//! million without loading the namespace:
//!
//! * [`RefName`] is Git's `check_refname_format` grammar plus the `refs/`
//!   namespace, on exact bytes.
//! * [`RefTransaction::check`] decides one atomic update set: expected-old
//!   (CAS) values, directory/file collisions, and symbolic cycles and depth,
//!   all against the state the transaction would produce, so renaming `a` to
//!   `a/b` in one transaction is legal and creating both is not.
//! * [`resolve`] follows symbolic chains with Git's bound and detects cycles.
//!
//! `HEAD` and the sequencer pseudo-refs are not entries of this namespace;
//! `HEAD` is a workspace field ([`crate::workspace::HeadRef`]).
//! `ref_conflicts`, reflogs, and per-ref update generations belong to the
//! store.

use core::fmt;
use std::borrow::{Borrow, Cow};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::bytes::ByteString;
use crate::error::{CoreError, CoreModelError, ErrorCode};
use crate::ids::{HashKind, Oid};
use crate::index::{byte_string_schema, reject_null_oid, show_bytes};

/// The most symbolic links a resolution may follow.
///
/// Git's `SYMREF_MAXDEPTH` is 5 and counts every ref *read*, including the
/// terminal one (`refs.c:refs_resolve_ref_unsafe`), so at most 4 links can be
/// followed before the terminal read. `HEAD -> a -> b -> c -> d` is 4 links;
/// one more fails.
pub const MAX_SYMREF_LINKS: usize = 4;

// ---------------------------------------------------------------------------
// RefName
// ---------------------------------------------------------------------------

/// A full ref name as exact bytes, e.g. `refs/heads/main`.
///
/// The grammar is `check_refname_format(name, 0)` from the pinned `refs.c`,
/// restricted to the `refs/` namespace: every byte is allowed except ASCII
/// control characters (including NUL and DEL), space, `~ ^ : ? * [ \`;
/// components are non-empty, do not begin with `.`, do not end with `.lock`,
/// and contain neither `..` nor `@{`; the name does not end with `.` or `/`.
/// Bytes above 0x7f are allowed, so non-UTF-8 names are legal and exact.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RefName(ByteString);

impl RefName {
    /// Validates and wraps `bytes`.
    ///
    /// # Errors
    /// [`CoreModelError::Invalid`] naming the first violated rule.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, CoreModelError> {
        let bytes = bytes.into();
        check_ref_name(&bytes)?;
        Ok(Self(ByteString::new(bytes)))
    }

    /// The exact name bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The UTF-8 view when the name is valid UTF-8.
    #[must_use]
    pub fn to_utf8(&self) -> Option<&str> {
        self.0.to_utf8()
    }

    /// Proper directory prefixes that could themselves be refs: every prefix
    /// ending before a `/` that still has two components. A prefix that is not
    /// a valid name (it ends in `.`) cannot exist as a ref and is skipped.
    fn ancestors(&self) -> impl Iterator<Item = RefName> {
        let bytes = self.as_bytes();
        bytes
            .iter()
            .enumerate()
            .filter(|&(index, &byte)| byte == b'/' && index > "refs".len())
            .filter_map(move |(index, _)| RefName::new(&bytes[..index]).ok())
    }
}

impl Borrow<[u8]> for RefName {
    /// Consistent with the derived `Eq`/`Ord`/`Hash` (all bytewise), so an
    /// ordered map of names can be sought by slice without allocating.
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for RefName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_bytes().escape_ascii())
    }
}

impl Serialize for RefName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RefName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = ByteString::deserialize(deserializer)?;
        Self::new(bytes.into_bytes()).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for RefName {
    fn schema_name() -> Cow<'static, str> {
        "RefName".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::RefName").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        byte_string_schema(
            generator,
            "Full Git ref name under `refs/` (git check-ref-format rules). A JSON string when \
             valid UTF-8, otherwise {\"hex\": lowercase hex}.",
        )
    }
}

fn is_forbidden_ref_byte(byte: u8) -> bool {
    byte < 0x20
        || byte == 0x7f
        || matches!(byte, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
}

fn check_ref_name(bytes: &[u8]) -> Result<(), CoreModelError> {
    let bad = |reason: &str| CoreModelError::Invalid {
        what: "ref name",
        detail: format!("{reason}: {}", show_bytes(bytes)),
    };
    if !bytes.starts_with(b"refs/") {
        return Err(bad("must start with `refs/`"));
    }
    if let Some(&byte) = bytes.iter().find(|&&byte| is_forbidden_ref_byte(byte)) {
        return Err(bad(&format!("forbidden byte 0x{byte:02x}")));
    }
    if bytes.ends_with(b".") {
        return Err(bad("ends with `.`"));
    }
    for component in bytes.split(|&byte| byte == b'/') {
        if component.is_empty() {
            return Err(bad(
                "empty component (empty name, trailing, or doubled `/`)",
            ));
        }
        if component.starts_with(b".") {
            return Err(bad("component begins with `.`"));
        }
        if component.ends_with(b".lock") {
            return Err(bad("component ends with `.lock`"));
        }
        if component.windows(2).any(|pair| pair == b"..") {
            return Err(bad("contains `..`"));
        }
        if component.windows(2).any(|pair| pair == b"@{") {
            return Err(bad("contains `@{`"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RefTarget and updates
// ---------------------------------------------------------------------------

/// What a ref stores: an object id, or the name of another ref.
///
/// A direct target is never the null id and is not guaranteed to exist as an
/// object; objects are the store's concern. A symbolic target need not exist
/// either: that is an unborn branch.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RefTarget {
    Direct(Oid),
    Symbolic(RefName),
}

impl RefTarget {
    /// Checks the target against the repository hash kind.
    ///
    /// # Errors
    /// [`CoreModelError::Invalid`] for a null id; [`CoreModelError::ObjectFormat`]
    /// for an id of the other width.
    pub fn validate(&self, kind: HashKind) -> Result<(), CoreModelError> {
        match self {
            Self::Direct(oid) => {
                reject_null_oid(*oid, "ref target")?;
                oid.expect_kind(kind, "ref target")
            }
            Self::Symbolic(_) => Ok(()),
        }
    }
}

impl<'de> Deserialize<'de> for RefTarget {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "lowercase")]
        enum Raw {
            Direct(Oid),
            Symbolic(RefName),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Direct(oid) => reject_null_oid(oid, "ref target")
                .map(Self::Direct)
                .map_err(serde::de::Error::custom),
            Raw::Symbolic(name) => Ok(Self::Symbolic(name)),
        }
    }
}

/// The value a caller expects a ref to hold before an update (compare and
/// swap). `Absent` is the wire's all-zero expected-old.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RefExpect {
    /// No expectation.
    Any,
    /// The ref must not exist.
    Absent,
    /// The ref must exist and hold exactly this target (compared unresolved:
    /// a symbolic ref holds a name, not what it points at).
    Present(RefTarget),
}

/// What an update does to a ref. A distinct variant rather than an optional
/// target, so an omitted field can never mean delete.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RefChange {
    Set(RefTarget),
    Delete,
}

/// One ref's part of a transaction.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct RefUpdate {
    pub name: RefName,
    pub expected: RefExpect,
    pub change: RefChange,
}

impl RefUpdate {
    fn validate(&self, kind: HashKind) -> Result<(), CoreModelError> {
        if let RefExpect::Present(target) = &self.expected {
            target.validate(kind)?;
        }
        match &self.change {
            RefChange::Set(target) => target.validate(kind),
            RefChange::Delete => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a ref operation was refused.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum RefError {
    /// A malformed name, target, or hash width.
    #[error(transparent)]
    Invalid(#[from] CoreModelError),
    #[error("ref {name} is updated twice in one transaction")]
    DuplicateUpdate { name: RefName },
    /// The stored value differs from the expected old value.
    #[error("ref {name} does not hold the expected value")]
    Stale { name: RefName },
    /// A name is a directory prefix of another ref (or the reverse).
    #[error("ref {name} collides with ref {existing}")]
    Collision { name: RefName, existing: RefName },
    #[error("symbolic ref {name} would form a cycle")]
    Cycle { name: RefName },
    #[error("symbolic ref {name} would exceed {} links", MAX_SYMREF_LINKS)]
    TooDeep { name: RefName },
    /// The store could not answer a read; carried through untouched.
    #[error("{0}")]
    Read(CoreError),
}

impl RefError {
    /// The closed code this refusal reports.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Invalid(inner) => inner.code(),
            Self::DuplicateUpdate { .. }
            | Self::Collision { .. }
            | Self::Cycle { .. }
            | Self::TooDeep { .. } => ErrorCode::EInvalid,
            Self::Stale { .. } => ErrorCode::EStale,
            Self::Read(inner) => inner.code,
        }
    }
}

impl From<RefError> for CoreError {
    fn from(err: RefError) -> Self {
        match err {
            RefError::Read(inner) => inner,
            other => Self::new(other.code(), other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// The two reads the ref rules need from an ordered ref store.
///
/// Both are single-key or single-seek operations (O(log B) on redb), never a
/// scan, which is what lets collision checks hold at one million branches.
pub trait RefRead {
    /// The stored target of exactly `name`.
    ///
    /// # Errors
    /// A store failure, as a [`CoreError`] (`E_IO`, `E_CORRUPT`, ...).
    fn get(&self, name: &RefName) -> Result<Option<RefTarget>, CoreError>;

    /// The ref with the least name bytewise `>= lower`, if any.
    ///
    /// # Errors
    /// A store failure, as a [`CoreError`].
    fn seek(&self, lower: &[u8]) -> Result<Option<(RefName, RefTarget)>, CoreError>;
}

/// An in-memory ref set: the reference semantics every store must match, and
/// the namespace of scratch repositories.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RefMap(BTreeMap<RefName, RefTarget>);

impl RefMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// All refs in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&RefName, &RefTarget)> {
        self.0.iter()
    }

    /// Validates and applies one atomic update set. On any error the map is
    /// unchanged.
    ///
    /// # Errors
    /// See [`RefTransaction::new`] and [`RefTransaction::check`].
    pub fn apply(&mut self, kind: HashKind, updates: Vec<RefUpdate>) -> Result<(), RefError> {
        let transaction = RefTransaction::new(kind, updates)?;
        transaction.check(&*self)?;
        for update in transaction.into_updates() {
            match update.change {
                RefChange::Set(target) => {
                    self.0.insert(update.name, target);
                }
                RefChange::Delete => {
                    self.0.remove(&update.name);
                }
            }
        }
        Ok(())
    }
}

impl RefRead for RefMap {
    fn get(&self, name: &RefName) -> Result<Option<RefTarget>, CoreError> {
        Ok(self.0.get(name).cloned())
    }

    fn seek(&self, lower: &[u8]) -> Result<Option<(RefName, RefTarget)>, CoreError> {
        Ok(self
            .0
            .range::<[u8], _>((Bound::Included(lower), Bound::Unbounded))
            .next()
            .map(|(name, target)| (name.clone(), target.clone())))
    }
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

/// One atomic set of ref updates, validated for everything that needs no
/// store: unique names, hash widths, non-null ids. Store-dependent rules are
/// [`Self::check`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefTransaction {
    updates: Vec<RefUpdate>,
}

/// The transaction's own effect on each name, probed by bytes.
type Overlay<'a> = BTreeMap<&'a [u8], &'a RefUpdate>;

impl RefTransaction {
    /// # Errors
    /// [`RefError::DuplicateUpdate`] when a name appears twice;
    /// [`RefError::Invalid`] for a null id or a width other than `kind`.
    pub fn new(kind: HashKind, updates: Vec<RefUpdate>) -> Result<Self, RefError> {
        {
            let mut seen: BTreeSet<&RefName> = BTreeSet::new();
            for update in &updates {
                if !seen.insert(&update.name) {
                    return Err(RefError::DuplicateUpdate {
                        name: update.name.clone(),
                    });
                }
                update.validate(kind)?;
            }
        }
        Ok(Self { updates })
    }

    #[must_use]
    pub fn updates(&self) -> &[RefUpdate] {
        &self.updates
    }

    #[must_use]
    pub fn into_updates(self) -> Vec<RefUpdate> {
        self.updates
    }

    /// Decides whether the transaction may be applied to `refs`.
    ///
    /// Expected values are compared with the stored state. Collisions and
    /// symbolic chains are judged against the state *after* the transaction,
    /// so a rename (`delete a`, `set a/b`) passes while `set a` with `set a/b`
    /// fails. Only refs the transaction sets are checked: deletions cannot
    /// collide, and an unchanged ref was valid before.
    ///
    /// Symbolic chains are checked forward from each new link (cycle and
    /// depth). A cycle needs the new link, so the forward check is complete
    /// for cycles; chains pointing *at* a ref whose own chain grew are
    /// re-checked by [`resolve`], which enforces the same bound on read.
    ///
    /// # Errors
    /// [`RefError::Stale`], [`RefError::Collision`], [`RefError::Cycle`],
    /// [`RefError::TooDeep`], or [`RefError::Read`] from the store.
    pub fn check<R: RefRead>(&self, refs: &R) -> Result<(), RefError> {
        let overlay: Overlay<'_> = self
            .updates
            .iter()
            .map(|update| (update.name.as_bytes(), update))
            .collect();
        for update in &self.updates {
            let stored = refs.get(&update.name).map_err(RefError::Read)?;
            let holds = match &update.expected {
                RefExpect::Any => true,
                RefExpect::Absent => stored.is_none(),
                RefExpect::Present(want) => stored.as_ref() == Some(want),
            };
            if !holds {
                return Err(RefError::Stale {
                    name: update.name.clone(),
                });
            }
            let RefChange::Set(target) = &update.change else {
                continue;
            };
            check_collisions(refs, &overlay, &update.name)?;
            if let RefTarget::Symbolic(next) = target {
                check_symbolic(refs, &overlay, &update.name, next)?;
            }
        }
        Ok(())
    }
}

/// The target `name` would hold once the transaction applies.
fn final_target<R: RefRead>(
    refs: &R,
    overlay: &Overlay<'_>,
    name: &RefName,
) -> Result<Option<RefTarget>, RefError> {
    match overlay.get(name.as_bytes()) {
        Some(update) => Ok(match &update.change {
            RefChange::Set(target) => Some(target.clone()),
            RefChange::Delete => None,
        }),
        None => refs.get(name).map_err(RefError::Read),
    }
}

/// A ref may not be a directory prefix of another ref. Both directions are
/// judged on the post-transaction state.
fn check_collisions<R: RefRead>(
    refs: &R,
    overlay: &Overlay<'_>,
    name: &RefName,
) -> Result<(), RefError> {
    for ancestor in name.ancestors() {
        if final_target(refs, overlay, &ancestor)?.is_some() {
            return Err(RefError::Collision {
                name: name.clone(),
                existing: ancestor,
            });
        }
    }
    let mut directory = name.as_bytes().to_vec();
    directory.push(b'/');
    // Stored refs below `name/`: each seek skips only refs this transaction
    // deletes, so the loop is bounded by the transaction size.
    let mut cursor = directory.clone();
    while let Some((found, _)) = refs.seek(&cursor).map_err(RefError::Read)? {
        if !found.as_bytes().starts_with(&directory) {
            break;
        }
        let deleted = overlay
            .get(found.as_bytes())
            .is_some_and(|update| matches!(update.change, RefChange::Delete));
        if !deleted {
            return Err(RefError::Collision {
                name: name.clone(),
                existing: found,
            });
        }
        cursor = found.as_bytes().to_vec();
        cursor.push(0);
    }
    // Refs this transaction creates below `name/`.
    for (key, update) in
        overlay.range::<[u8], _>((Bound::Included(directory.as_slice()), Bound::Unbounded))
    {
        if !key.starts_with(&directory) {
            break;
        }
        if matches!(update.change, RefChange::Set(_)) {
            return Err(RefError::Collision {
                name: name.clone(),
                existing: update.name.clone(),
            });
        }
    }
    Ok(())
}

/// Follows the chain a new link `name -> target` would create.
fn check_symbolic<R: RefRead>(
    refs: &R,
    overlay: &Overlay<'_>,
    name: &RefName,
    target: &RefName,
) -> Result<(), RefError> {
    let mut seen = vec![name.clone()];
    let mut links = 1_usize;
    let mut current = target.clone();
    loop {
        if seen.contains(&current) {
            return Err(RefError::Cycle { name: name.clone() });
        }
        seen.push(current.clone());
        match final_target(refs, overlay, &current)? {
            Some(RefTarget::Symbolic(next)) => {
                links += 1;
                if links > MAX_SYMREF_LINKS {
                    return Err(RefError::TooDeep { name: name.clone() });
                }
                current = next;
            }
            Some(RefTarget::Direct(_)) | None => return Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Where a symbolic chain ends.
///
/// `oid` is `None` when the terminal ref does not exist: an unborn branch (or
/// a name that was never a ref). Whether that is an error is the caller's
/// decision; Git also returns the terminal name in that case so a commit can
/// create it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedRef {
    pub terminal: RefName,
    pub oid: Option<Oid>,
}

/// Resolves `name` through symbolic links.
///
/// # Errors
/// [`RefError::Cycle`], [`RefError::TooDeep`] (more than [`MAX_SYMREF_LINKS`]
/// links), or [`RefError::Read`].
pub fn resolve<R: RefRead>(refs: &R, name: &RefName) -> Result<ResolvedRef, RefError> {
    resolve_from(refs, name, 0)
}

/// [`resolve`] when `links_used` links were already followed to reach `start`
/// (a symbolic `HEAD` has used one).
pub(crate) fn resolve_from<R: RefRead>(
    refs: &R,
    start: &RefName,
    links_used: usize,
) -> Result<ResolvedRef, RefError> {
    let mut seen = vec![start.clone()];
    let mut links = links_used;
    let mut current = start.clone();
    loop {
        match refs.get(&current).map_err(RefError::Read)? {
            None => {
                return Ok(ResolvedRef {
                    terminal: current,
                    oid: None,
                });
            }
            Some(RefTarget::Direct(oid)) => {
                return Ok(ResolvedRef {
                    terminal: current,
                    oid: Some(oid),
                });
            }
            Some(RefTarget::Symbolic(next)) => {
                links += 1;
                if seen.contains(&next) {
                    return Err(RefError::Cycle {
                        name: start.clone(),
                    });
                }
                if links > MAX_SYMREF_LINKS {
                    return Err(RefError::TooDeep {
                        name: start.clone(),
                    });
                }
                seen.push(next.clone());
                current = next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn name(text: &str) -> RefName {
        RefName::new(text).expect("valid ref name")
    }

    fn oid(n: u8) -> Oid {
        Oid::from_hex(&format!("{:040x}", u16::from(n) + 1)).expect("oid")
    }

    fn direct(n: u8) -> RefTarget {
        RefTarget::Direct(oid(n))
    }

    fn sym(text: &str) -> RefTarget {
        RefTarget::Symbolic(name(text))
    }

    fn set(text: &str, target: RefTarget) -> RefUpdate {
        RefUpdate {
            name: name(text),
            expected: RefExpect::Any,
            change: RefChange::Set(target),
        }
    }

    fn delete(text: &str) -> RefUpdate {
        RefUpdate {
            name: name(text),
            expected: RefExpect::Any,
            change: RefChange::Delete,
        }
    }

    /// Builds a map without validation, to model stored states the write path
    /// would refuse (corruption, or chains that grew after a write).
    fn raw_map(entries: &[(&str, RefTarget)]) -> RefMap {
        RefMap(
            entries
                .iter()
                .map(|(text, target)| (name(text), target.clone()))
                .collect(),
        )
    }

    fn map_of(updates: Vec<RefUpdate>) -> RefMap {
        let mut map = RefMap::new();
        map.apply(HashKind::Sha1, updates)
            .expect("setup transaction");
        map
    }

    // ---- RefName ---------------------------------------------------------

    #[test]
    fn grammar_accepts_what_git_accepts() {
        for ok in [
            &b"refs/heads/main"[..],
            b"refs/tags/v1.0.0",
            b"refs/heads/feature/a/b/c",
            b"refs/stash",
            b"refs/pull/12/head",
            b"refs/heads/@",
            b"refs/heads/a@b",
            b"refs/heads/a{b",
            b"refs/heads/a}b",
            b"refs/heads/-dash",
            b"refs/heads/a.b",
            b"refs/heads/a.locked",
            b"refs/a./b",
            b"refs/heads/\xc3\xa4",
            b"refs/heads/\xff\xfe",
            b"refs/heads/!\"#$%&'()+,;<=>]_`|",
        ] {
            assert!(RefName::new(ok).is_ok(), "rejected {}", show_bytes(ok));
        }
    }

    #[test]
    fn grammar_rejects_what_git_rejects() {
        for bad in [
            &b""[..],
            b"refs",
            b"refs/",
            b"HEAD",
            b"heads/main",
            b"refs//heads",
            b"refs/heads//x",
            b"refs/heads/",
            b"/refs/heads/x",
            b"refs/heads/.hidden",
            b"refs/.hidden/x",
            b"refs/heads/a.lock",
            b"refs/a.lock/b",
            b"refs/heads/a..b",
            b"refs/heads/..",
            b"refs/heads/a@{b",
            b"refs/heads/a b",
            b"refs/heads/a\tb",
            b"refs/heads/a~1",
            b"refs/heads/a^",
            b"refs/heads/a:b",
            b"refs/heads/a?",
            b"refs/heads/a*",
            b"refs/heads/a[0]",
            b"refs/heads/a\\b",
            b"refs/heads/a\x01",
            b"refs/heads/a\x7f",
            b"refs/heads/a\0b",
            b"refs/heads/a.",
            b"refs/heads/a\n",
        ] {
            let err = RefName::new(bad).expect_err(&show_bytes(bad));
            assert!(
                matches!(
                    err,
                    CoreModelError::Invalid {
                        what: "ref name",
                        ..
                    }
                ),
                "{err:?}"
            );
        }
    }

    #[test]
    fn name_error_text_is_bounded() {
        let mut bad = b"refs/".to_vec();
        bad.extend(std::iter::repeat_n(b'x', 1 << 20));
        bad.push(b' ');
        let text = RefName::new(bad).expect_err("space").to_string();
        assert!(text.len() < 400, "{} bytes", text.len());
    }

    #[test]
    fn ancestors_are_the_proper_directory_prefixes() {
        let n = name("refs/heads/a/b/c");
        let found: Vec<String> = n.ancestors().map(|a| a.to_string()).collect();
        assert_eq!(found, ["refs/heads", "refs/heads/a", "refs/heads/a/b"]);
        assert_eq!(name("refs/stash").ancestors().count(), 0);
        // `refs/x./y`'s prefix `refs/x.` is not a legal name and is skipped.
        let skipped: Vec<String> = name("refs/x./y/z")
            .ancestors()
            .map(|a| a.to_string())
            .collect();
        assert_eq!(skipped, ["refs/x./y"]);
    }

    #[test]
    fn names_serialize_as_strings_or_hex_and_round_trip() {
        let plain = name("refs/heads/\u{e4}");
        let json = sonic_rs::to_string(&plain).expect("json");
        assert_eq!(json, "\"refs/heads/\u{e4}\"");
        assert_eq!(sonic_rs::from_str::<RefName>(&json).expect("parse"), plain);

        let binary = RefName::new(&b"refs/heads/\xff\xfe"[..]).expect("valid");
        assert!(binary.to_utf8().is_none());
        let value = sonic_rs::to_value(&binary).expect("value");
        {
            use sonic_rs::JsonValueTrait;
            assert!(value.is_object(), "{value}");
        }
        assert_eq!(
            sonic_rs::from_value::<RefName>(&value).expect("parse"),
            binary
        );
        for original in [plain, binary] {
            let bytes = postcard::to_allocvec(&original).expect("encode");
            assert_eq!(
                postcard::from_bytes::<RefName>(&bytes).expect("decode"),
                original
            );
        }
    }

    #[test]
    fn deserialization_validates_names() {
        for bad in [
            "\"HEAD\"",
            "\"refs/heads/a b\"",
            "\"refs/heads/a..b\"",
            "{\"hex\":\"\"}",
            "{\"hex\":\"726566732f6100\"}",
            "7",
        ] {
            assert!(
                sonic_rs::from_str::<RefName>(bad).is_err(),
                "accepted {bad}"
            );
        }
        let raw = postcard::to_allocvec(&ByteString::new(b"refs/a.lock".to_vec())).expect("encode");
        assert!(postcard::from_bytes::<RefName>(&raw).is_err());
    }

    // ---- RefTarget -------------------------------------------------------

    #[test]
    fn target_wire_forms_are_externally_tagged() {
        let json = sonic_rs::to_string(&direct(0)).expect("json");
        assert_eq!(json, format!("{{\"direct\":\"{:040x}\"}}", 1));
        let json = sonic_rs::to_string(&sym("refs/heads/main")).expect("json");
        assert_eq!(json, "{\"symbolic\":\"refs/heads/main\"}");
        for target in [
            direct(3),
            sym("refs/heads/x"),
            RefTarget::Symbolic(RefName::new(&b"refs/\xff"[..]).expect("name")),
        ] {
            let json = sonic_rs::to_string(&target).expect("json");
            assert_eq!(
                sonic_rs::from_str::<RefTarget>(&json).expect("parse"),
                target
            );
            let bytes = postcard::to_allocvec(&target).expect("encode");
            assert_eq!(
                postcard::from_bytes::<RefTarget>(&bytes).expect("decode"),
                target
            );
        }
    }

    #[test]
    fn target_deserialization_rejects_malformed_values() {
        let null = "0".repeat(40);
        for bad in [
            format!("{{\"direct\":\"{null}\"}}"),
            "{\"direct\":\"abc\"}".to_owned(),
            "{\"symbolic\":\"HEAD\"}".to_owned(),
            "{\"symbolic\":\"refs/a b\"}".to_owned(),
            "{\"tree\":\"refs/a\"}".to_owned(),
            format!("{{\"direct\":\"{:040x}\",\"symbolic\":\"refs/a\"}}", 1),
            "\"direct\"".to_owned(),
            "{}".to_owned(),
        ] {
            assert!(
                sonic_rs::from_str::<RefTarget>(&bad).is_err(),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn update_wire_form_cannot_express_delete_by_omission() {
        let missing_change = "{\"name\":\"refs/a\",\"expected\":\"any\"}";
        assert!(sonic_rs::from_str::<RefUpdate>(missing_change).is_err());
        let missing_expected = "{\"name\":\"refs/a\",\"change\":\"delete\"}";
        assert!(sonic_rs::from_str::<RefUpdate>(missing_expected).is_err());
        let ok = "{\"name\":\"refs/a\",\"expected\":\"absent\",\"change\":\"delete\"}";
        assert_eq!(
            sonic_rs::from_str::<RefUpdate>(ok).expect("parse").change,
            RefChange::Delete
        );
    }

    // ---- Transaction: validation, CAS ------------------------------------

    #[test]
    fn transaction_rejects_duplicates_wrong_width_and_null() {
        let dup = RefTransaction::new(
            HashKind::Sha1,
            vec![set("refs/a", direct(0)), delete("refs/a")],
        );
        assert!(matches!(dup, Err(RefError::DuplicateUpdate { .. })));

        let sha256 = Oid::from_hex(&format!("{:064x}", 5)).expect("sha256 oid");
        let wrong = RefTransaction::new(
            HashKind::Sha1,
            vec![set("refs/a", RefTarget::Direct(sha256))],
        );
        assert!(matches!(
            wrong,
            Err(RefError::Invalid(CoreModelError::ObjectFormat(_)))
        ));
        let right = RefTransaction::new(
            HashKind::Sha256,
            vec![set("refs/a", RefTarget::Direct(sha256))],
        );
        assert!(right.is_ok());

        let null = RefTarget::Direct(HashKind::Sha1.zero_oid());
        let null_set = RefTransaction::new(HashKind::Sha1, vec![set("refs/a", null.clone())]);
        assert!(matches!(
            null_set,
            Err(RefError::Invalid(CoreModelError::Invalid { .. }))
        ));
        let null_expect = RefUpdate {
            name: name("refs/a"),
            expected: RefExpect::Present(null),
            change: RefChange::Delete,
        };
        assert!(RefTransaction::new(HashKind::Sha1, vec![null_expect]).is_err());
    }

    #[test]
    fn expected_old_values_are_compared_unresolved() {
        let mut map = map_of(vec![
            set("refs/heads/main", direct(0)),
            set("refs/heads/alias", sym("refs/heads/main")),
        ]);
        let update = |ref_name: &str, expected: RefExpect| RefUpdate {
            name: name(ref_name),
            expected,
            change: RefChange::Set(direct(9)),
        };
        // Absent fails on an existing ref and passes on a missing one.
        let err = map.apply(
            HashKind::Sha1,
            vec![update("refs/heads/main", RefExpect::Absent)],
        );
        assert!(matches!(err, Err(RefError::Stale { .. })));
        assert!(
            map.apply(
                HashKind::Sha1,
                vec![update("refs/heads/new", RefExpect::Absent)]
            )
            .is_ok()
        );
        // Present compares the stored target: the alias holds a name.
        let wrong = update("refs/heads/alias", RefExpect::Present(direct(0)));
        assert!(matches!(
            map.apply(HashKind::Sha1, vec![wrong]),
            Err(RefError::Stale { .. })
        ));
        let right = update(
            "refs/heads/alias",
            RefExpect::Present(sym("refs/heads/main")),
        );
        assert!(map.apply(HashKind::Sha1, vec![right]).is_ok());
        let stale = update("refs/heads/main", RefExpect::Present(direct(1)));
        let err = map.apply(HashKind::Sha1, vec![stale]).expect_err("stale");
        assert_eq!(err.code(), ErrorCode::EStale);
    }

    #[test]
    fn a_stale_update_blocks_the_whole_transaction() {
        let mut map = map_of(vec![set("refs/a", direct(0))]);
        let before = map.clone();
        let stale = RefUpdate {
            name: name("refs/a"),
            expected: RefExpect::Present(direct(7)),
            change: RefChange::Delete,
        };
        let err = map.apply(HashKind::Sha1, vec![set("refs/b", direct(1)), stale]);
        assert!(err.is_err());
        assert_eq!(map, before, "no update of a failed transaction may apply");
    }

    // ---- Transaction: collisions -----------------------------------------

    #[test]
    fn a_ref_cannot_live_below_another_ref() {
        let mut map = map_of(vec![set("refs/heads/a", direct(0))]);
        let err = map
            .apply(HashKind::Sha1, vec![set("refs/heads/a/b", direct(1))])
            .expect_err("below a ref");
        assert!(
            matches!(&err, RefError::Collision { existing, .. } if existing.as_bytes() == b"refs/heads/a")
        );
        assert_eq!(err.code(), ErrorCode::EInvalid);
        let deep = map.apply(HashKind::Sha1, vec![set("refs/heads/a/b/c/d", direct(1))]);
        assert!(matches!(deep, Err(RefError::Collision { .. })));
    }

    #[test]
    fn a_ref_cannot_sit_above_other_refs() {
        let mut map = map_of(vec![set("refs/heads/a/b/c", direct(0))]);
        for above in ["refs/heads/a/b", "refs/heads/a", "refs/heads"] {
            let err = map
                .apply(HashKind::Sha1, vec![set(above, direct(1))])
                .expect_err(above);
            assert!(
                matches!(&err, RefError::Collision { existing, .. } if existing.as_bytes() == b"refs/heads/a/b/c"),
                "{above}: {err:?}"
            );
        }
    }

    #[test]
    fn prefix_sharing_names_that_are_not_directories_do_not_collide() {
        // `ab` and `a-b` share bytes with `a` but are not under `a/`.
        let mut map = map_of(vec![set("refs/heads/a", direct(0))]);
        assert!(
            map.apply(
                HashKind::Sha1,
                vec![
                    set("refs/heads/ab", direct(1)),
                    set("refs/heads/a-b", direct(2)),
                    set("refs/heads/a.b", direct(3))
                ]
            )
            .is_ok()
        );
        assert_eq!(map.len(), 4);
    }

    #[test]
    fn rename_to_a_child_is_legal_in_one_transaction() {
        let mut map = map_of(vec![set("refs/heads/a", direct(0))]);
        let update = |expected| RefUpdate {
            name: name("refs/heads/a"),
            expected,
            change: RefChange::Delete,
        };
        let moved = vec![
            update(RefExpect::Present(direct(0))),
            set("refs/heads/a/b", direct(0)),
        ];
        map.apply(HashKind::Sha1, moved)
            .expect("delete a, create a/b");
        assert!(map.get(&name("refs/heads/a")).expect("get").is_none());
        assert_eq!(
            map.get(&name("refs/heads/a/b")).expect("get"),
            Some(direct(0))
        );
        // And back: delete a/b, create a.
        map.apply(
            HashKind::Sha1,
            vec![delete("refs/heads/a/b"), set("refs/heads/a", direct(1))],
        )
        .expect("reverse");
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn a_transaction_cannot_create_both_a_ref_and_its_child() {
        let mut map = RefMap::new();
        let err = map.apply(
            HashKind::Sha1,
            vec![
                set("refs/heads/a", direct(0)),
                set("refs/heads/a/b", direct(1)),
            ],
        );
        assert!(matches!(err, Err(RefError::Collision { .. })));
        let reversed = map.apply(
            HashKind::Sha1,
            vec![
                set("refs/heads/a/b", direct(1)),
                set("refs/heads/a", direct(0)),
            ],
        );
        assert!(matches!(reversed, Err(RefError::Collision { .. })));
        assert!(map.is_empty());
    }

    #[test]
    fn deleting_only_some_descendants_does_not_clear_the_collision() {
        let mut map = map_of(vec![
            set("refs/heads/a/x", direct(0)),
            set("refs/heads/a/y", direct(1)),
            set("refs/heads/a/z/w", direct(2)),
        ]);
        let partial = vec![
            delete("refs/heads/a/x"),
            delete("refs/heads/a/y"),
            set("refs/heads/a", direct(3)),
        ];
        let err = map
            .apply(HashKind::Sha1, partial)
            .expect_err("a/z/w remains");
        assert!(
            matches!(&err, RefError::Collision { existing, .. } if existing.as_bytes() == b"refs/heads/a/z/w")
        );
        let all = vec![
            delete("refs/heads/a/x"),
            delete("refs/heads/a/y"),
            delete("refs/heads/a/z/w"),
            set("refs/heads/a", direct(3)),
        ];
        map.apply(HashKind::Sha1, all)
            .expect("every descendant deleted");
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn modifying_a_descendant_does_not_free_the_directory() {
        let mut map = map_of(vec![set("refs/heads/a/x", direct(0))]);
        let err = map.apply(
            HashKind::Sha1,
            vec![
                set("refs/heads/a/x", direct(1)),
                set("refs/heads/a", direct(2)),
            ],
        );
        assert!(matches!(err, Err(RefError::Collision { .. })));
    }

    #[test]
    fn seek_skips_many_deleted_descendants_without_scanning_unrelated_refs() {
        let mut updates: Vec<RefUpdate> = (0..50_u8)
            .map(|i| set(&format!("refs/heads/d/{i:03}"), direct(i % 5)))
            .collect();
        updates.extend((0..20_u8).map(|i| set(&format!("refs/other/{i:03}"), direct(i % 5))));
        let mut map = map_of(updates);
        let mut rename: Vec<RefUpdate> = (0..50_u8)
            .map(|i| delete(&format!("refs/heads/d/{i:03}")))
            .collect();
        rename.push(set("refs/heads/d", direct(1)));
        map.apply(HashKind::Sha1, rename)
            .expect("all descendants deleted, parent created");
        assert_eq!(map.len(), 21);
    }

    // ---- Transaction: symbolic cycles and depth --------------------------

    #[test]
    fn a_symbolic_ref_cannot_point_at_itself_or_close_a_loop() {
        let mut map = RefMap::new();
        let selfref = map.apply(HashKind::Sha1, vec![set("refs/a", sym("refs/a"))]);
        assert!(matches!(selfref, Err(RefError::Cycle { .. })));

        map.apply(HashKind::Sha1, vec![set("refs/a", sym("refs/b"))])
            .expect("dangling is legal (unborn)");
        let closing = map.apply(HashKind::Sha1, vec![set("refs/b", sym("refs/a"))]);
        assert!(matches!(closing, Err(RefError::Cycle { .. })));
        assert_eq!(map.len(), 1, "the failed write changed nothing");

        map.apply(HashKind::Sha1, vec![set("refs/c", sym("refs/a"))])
            .expect("a chain, not a loop");
        let long_loop = map.apply(HashKind::Sha1, vec![set("refs/b", sym("refs/c"))]);
        assert!(matches!(long_loop, Err(RefError::Cycle { .. })));
    }

    #[test]
    fn two_links_of_one_transaction_can_close_a_loop_together() {
        let mut map = RefMap::new();
        let err = map.apply(
            HashKind::Sha1,
            vec![set("refs/a", sym("refs/b")), set("refs/b", sym("refs/a"))],
        );
        assert!(matches!(err, Err(RefError::Cycle { .. })));
        assert!(map.is_empty());
        // The same two links are fine when one is retargeted away in the transaction.
        let ok = map.apply(
            HashKind::Sha1,
            vec![set("refs/a", sym("refs/b")), set("refs/b", direct(0))],
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn retargeting_the_end_of_a_chain_back_to_its_start_is_a_cycle() {
        let mut map = map_of(vec![
            set("refs/a", sym("refs/b")),
            set("refs/b", sym("refs/c")),
            set("refs/c", direct(0)),
        ]);
        let err = map.apply(HashKind::Sha1, vec![set("refs/c", sym("refs/a"))]);
        assert!(matches!(err, Err(RefError::Cycle { .. })));
        // Pointing it at a fresh ref is fine.
        assert!(
            map.apply(HashKind::Sha1, vec![set("refs/c", sym("refs/fresh"))])
                .is_ok()
        );
    }

    #[test]
    fn chains_may_have_four_links_and_not_five() {
        let mut map = RefMap::new();
        // l4 -> l3 -> l2 -> l1 -> direct: build from the end.
        map.apply(HashKind::Sha1, vec![set("refs/end", direct(0))])
            .expect("end");
        map.apply(HashKind::Sha1, vec![set("refs/l1", sym("refs/end"))])
            .expect("1 link");
        map.apply(HashKind::Sha1, vec![set("refs/l2", sym("refs/l1"))])
            .expect("2 links");
        map.apply(HashKind::Sha1, vec![set("refs/l3", sym("refs/l2"))])
            .expect("3 links");
        map.apply(HashKind::Sha1, vec![set("refs/l4", sym("refs/l3"))])
            .expect("4 links");
        let five = map.apply(HashKind::Sha1, vec![set("refs/l5", sym("refs/l4"))]);
        assert!(matches!(&five, Err(RefError::TooDeep { .. })), "{five:?}");
        assert_eq!(five.expect_err("too deep").code(), ErrorCode::EInvalid);
        assert_eq!(
            resolve(&map, &name("refs/l4")).expect("resolves").oid,
            Some(oid(0))
        );
    }

    // ---- Resolution ------------------------------------------------------

    #[test]
    fn resolve_follows_chains_to_the_terminal_ref() {
        let map = raw_map(&[
            ("refs/heads/main", direct(4)),
            ("refs/heads/alias", sym("refs/heads/main")),
            ("refs/heads/alias2", sym("refs/heads/alias")),
        ]);
        let through = resolve(&map, &name("refs/heads/alias2")).expect("resolve");
        assert_eq!(
            through,
            ResolvedRef {
                terminal: name("refs/heads/main"),
                oid: Some(oid(4))
            }
        );
        let direct_ref = resolve(&map, &name("refs/heads/main")).expect("resolve");
        assert_eq!(direct_ref.terminal, name("refs/heads/main"));
    }

    #[test]
    fn resolve_reports_an_absent_terminal_as_unborn_not_an_error() {
        let map = raw_map(&[("refs/heads/alias", sym("refs/heads/unborn"))]);
        let unborn = resolve(&map, &name("refs/heads/alias")).expect("resolve");
        assert_eq!(
            unborn,
            ResolvedRef {
                terminal: name("refs/heads/unborn"),
                oid: None
            }
        );
        let missing = resolve(&map, &name("refs/heads/never")).expect("resolve");
        assert_eq!(missing.oid, None);
        assert_eq!(missing.terminal, name("refs/heads/never"));
    }

    #[test]
    fn resolve_detects_stored_cycles_and_overlong_chains() {
        let looped = raw_map(&[
            ("refs/a", sym("refs/b")),
            ("refs/b", sym("refs/c")),
            ("refs/c", sym("refs/a")),
        ]);
        assert!(matches!(
            resolve(&looped, &name("refs/a")),
            Err(RefError::Cycle { .. })
        ));
        let selfref = raw_map(&[("refs/a", sym("refs/a"))]);
        assert!(matches!(
            resolve(&selfref, &name("refs/a")),
            Err(RefError::Cycle { .. })
        ));

        let deep = raw_map(&[
            ("refs/s0", sym("refs/s1")),
            ("refs/s1", sym("refs/s2")),
            ("refs/s2", sym("refs/s3")),
            ("refs/s3", sym("refs/s4")),
            ("refs/s4", sym("refs/s5")),
            ("refs/s5", direct(0)),
        ]);
        assert!(matches!(
            resolve(&deep, &name("refs/s0")),
            Err(RefError::TooDeep { .. })
        ));
        // Four links from s1 reach s5; the bound is on links, not on chain length from the top.
        assert_eq!(
            resolve(&deep, &name("refs/s1")).expect("4 links").oid,
            Some(oid(0))
        );
        // A chain that grew after a write is caught on read.
        assert!(resolve_from(&deep, &name("refs/s1"), 1).is_err());
    }

    #[test]
    fn store_read_failures_pass_through_unchanged() {
        struct Broken;
        impl RefRead for Broken {
            fn get(&self, _: &RefName) -> Result<Option<RefTarget>, CoreError> {
                Err(CoreError::new(ErrorCode::ECorrupt, "page checksum"))
            }
            fn seek(&self, _: &[u8]) -> Result<Option<(RefName, RefTarget)>, CoreError> {
                Err(CoreError::new(ErrorCode::EIo, "read failed"))
            }
        }
        let err = resolve(&Broken, &name("refs/a")).expect_err("broken store");
        assert!(matches!(err, RefError::Read(_)));
        let core: CoreError = err.into();
        assert_eq!(
            (core.code, core.message.as_str()),
            (ErrorCode::ECorrupt, "page checksum")
        );
        let tx = RefTransaction::new(HashKind::Sha1, vec![set("refs/a", direct(0))]).expect("tx");
        assert!(matches!(tx.check(&Broken), Err(RefError::Read(_))));
    }

    #[test]
    fn ref_errors_map_to_closed_codes() {
        let n = name("refs/a");
        assert_eq!(
            RefError::Stale { name: n.clone() }.code(),
            ErrorCode::EStale
        );
        assert_eq!(
            RefError::Cycle { name: n.clone() }.code(),
            ErrorCode::EInvalid
        );
        assert_eq!(
            RefError::Invalid(CoreModelError::ObjectFormat("x".into())).code(),
            ErrorCode::EObjectFormat
        );
        let core: CoreError = RefError::Stale { name: n }.into();
        assert_eq!(core.code, ErrorCode::EStale);
    }

    // ---- Model-based property --------------------------------------------

    const NAMES: [&str; 7] = [
        "refs/h",
        "refs/h/a",
        "refs/h/a/b",
        "refs/h/a/b/c",
        "refs/h/ab",
        "refs/h/b",
        "refs/t/a",
    ];

    #[derive(Clone, Debug)]
    enum Op {
        Delete(usize),
        Direct(usize, u8),
        Symbolic(usize, usize),
    }

    impl Op {
        fn index(&self) -> usize {
            match self {
                Self::Delete(i) | Self::Direct(i, _) | Self::Symbolic(i, _) => *i,
            }
        }

        fn update(&self) -> RefUpdate {
            match self {
                Self::Delete(i) => delete(NAMES[*i]),
                Self::Direct(i, n) => set(NAMES[*i], direct(*n)),
                Self::Symbolic(i, t) => set(NAMES[*i], sym(NAMES[*t])),
            }
        }

        fn is_symbolic(&self) -> bool {
            matches!(self, Self::Symbolic(..))
        }
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        let n = NAMES.len();
        prop_oneof![
            (0..n).prop_map(Op::Delete),
            (0..n, 0_u8..3).prop_map(|(i, o)| Op::Direct(i, o)),
            (0..n, 0..n).prop_map(|(i, t)| Op::Symbolic(i, t)),
        ]
    }

    fn collides(above: &[u8], below: &[u8]) -> bool {
        below.len() > above.len() && below.starts_with(above) && below[above.len()] == b'/'
    }

    fn has_collision(names: &BTreeMap<RefName, RefTarget>) -> bool {
        names
            .keys()
            .any(|a| names.keys().any(|b| collides(a.as_bytes(), b.as_bytes())))
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(1024))]

        /// Against a brute-force oracle over the final state: an applied
        /// transaction never leaves a directory/file collision or a cycle, a
        /// collision in the final state is always refused, and a refused
        /// transaction changes nothing.
        #[test]
        fn prop_transactions_keep_the_namespace_collision_free_and_acyclic(
            transactions in prop::collection::vec(prop::collection::vec(op_strategy(), 1..4), 1..20),
        ) {
            let mut map = RefMap::new();
            for ops in transactions {
                let mut seen = BTreeSet::new();
                let ops: Vec<Op> = ops.into_iter().filter(|op| seen.insert(op.index())).collect();
                let updates: Vec<RefUpdate> = ops.iter().map(Op::update).collect();
                let before = map.clone();
                let mut expected = before.0.clone();
                for update in &updates {
                    match &update.change {
                        RefChange::Set(target) => { expected.insert(update.name.clone(), target.clone()); }
                        RefChange::Delete => { expected.remove(&update.name); }
                    }
                }
                let collision_expected = has_collision(&expected);
                let any_symbolic = ops.iter().any(Op::is_symbolic);
                match map.apply(HashKind::Sha1, updates) {
                    Ok(()) => {
                        prop_assert!(!collision_expected);
                        prop_assert_eq!(&map.0, &expected);
                        for ref_name in map.0.keys() {
                            let cyclic = matches!(resolve(&map, ref_name), Err(RefError::Cycle { .. }));
                            prop_assert!(!cyclic, "{} is cyclic", ref_name);
                        }
                    }
                    Err(err) => {
                        prop_assert_eq!(&map, &before);
                        let allowed = matches!(
                            err,
                            RefError::Collision { .. } | RefError::Cycle { .. } | RefError::TooDeep { .. }
                        );
                        prop_assert!(allowed, "unexpected {err:?}");
                        if matches!(err, RefError::Collision { .. }) {
                            prop_assert!(collision_expected);
                        }
                        // Without symbolic links the only possible refusal is a collision.
                        prop_assert!(collision_expected || any_symbolic);
                    }
                }
            }
        }
    }
}
