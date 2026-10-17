//! GitCompat index rows and the byte-safe repository path.
//!
//! A GitCompat index maps `(path, stage 0..=3)` to `{oid, mode, stat,
//! flags}` (core contract, "Ref and workspace authority"). This module owns
//! the typed row, the per-path aggregate that makes stage-zero exclusivity a
//! property of the type, the row delta a store must apply when a path moves
//! between merged and unmerged, and the checked generation counter.
//!
//! Everything here is model-level: no table, transaction, or file is touched.
//! A store applies [`row_delta`] and [`IndexGeneration::next`] inside its one
//! metadata transaction.
//!
//! Wire forms: paths are byte strings in the crate's [`ByteString`] form (a
//! JSON string when valid UTF-8, otherwise `{"hex": ..}`; raw bytes in
//! postcard). Enums are externally tagged so postcard, which cannot decode
//! internally tagged enums, stores them with the same derives that JSON uses.
//! No field uses `skip_serializing_if`: postcard is positional and would
//! desynchronize.

use std::borrow::{Borrow, Cow};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bytes::ByteString;
use crate::error::CoreModelError;
use crate::ids::{HashKind, Oid};

/// Renders untrusted bytes for an error message: escaped and bounded, so a
/// hostile 16 MiB name cannot become a 16 MiB error.
pub(crate) fn show_bytes(bytes: &[u8]) -> String {
    const LIMIT: usize = 128;
    let shown = &bytes[..bytes.len().min(LIMIT)];
    let mut text = shown.escape_ascii().to_string();
    if bytes.len() > LIMIT {
        text.push_str("...");
    }
    text
}

/// Rejects the all-zero object id, which names no object. Git never stores it
/// in a ref or an index entry (it is the wire spelling of "absent").
pub(crate) fn reject_null_oid(oid: Oid, what: &'static str) -> Result<Oid, CoreModelError> {
    if oid == oid.kind().zero_oid() {
        return Err(CoreModelError::Invalid {
            what,
            detail: "the null object id names no object".to_owned(),
        });
    }
    Ok(oid)
}

/// The [`ByteString`] schema with a type-specific description.
pub(crate) fn byte_string_schema(generator: &mut SchemaGenerator, description: &str) -> Schema {
    let mut schema = ByteString::json_schema(generator);
    schema.insert("description".to_owned(), description.into());
    schema
}

// ---------------------------------------------------------------------------
// RepoPath
// ---------------------------------------------------------------------------

/// A repository-relative path as exact bytes.
///
/// Git paths are byte strings; nothing here assumes UTF-8. Construction
/// enforces the traversal-safety subset of Git's `verify_path`
/// (`read-cache.c`): the path is non-empty, has no NUL, no empty component
/// (leading, trailing, or doubled `/`), no `.` or `..` component, and no
/// component that names the repository metadata directory `.git` (ASCII
/// case-insensitively, with the NTFS spellings `git~1`, trailing dots/spaces,
/// and `:` streams, and the HFS+ ignorable-codepoint spellings).
///
/// `\` is an ordinary byte, as on Linux, except that it also separates NTFS
/// names for the `.git` check, exactly as Git's `is_ntfs_dotgit` treats it.
/// Windows drive prefixes and the mode-dependent `.gitmodules` symlink rule
/// belong to checkout and index-add, which see the platform and the mode.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepoPath(ByteString);

impl RepoPath {
    /// Validates and wraps `bytes`.
    ///
    /// # Errors
    /// [`CoreModelError::Invalid`] naming the first violated rule.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, CoreModelError> {
        let bytes = bytes.into();
        check_repo_path(&bytes)?;
        Ok(Self(ByteString::new(bytes)))
    }

    /// The exact path bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// The UTF-8 view when the path is valid UTF-8.
    #[must_use]
    pub fn to_utf8(&self) -> Option<&str> {
        self.0.to_utf8()
    }

    /// The containing directory, or `None` for an entry in the repository
    /// root.
    #[must_use]
    pub fn parent(&self) -> Option<&[u8]> {
        let bytes = self.as_bytes();
        bytes
            .iter()
            .rposition(|&byte| byte == b'/')
            .map(|index| &bytes[..index])
    }

    /// The final component.
    #[must_use]
    pub fn file_name(&self) -> &[u8] {
        let bytes = self.as_bytes();
        match bytes.iter().rposition(|&byte| byte == b'/') {
            Some(index) => &bytes[index + 1..],
            None => bytes,
        }
    }

    /// The components, root first.
    pub fn components(&self) -> impl Iterator<Item = &[u8]> {
        self.as_bytes().split(|&byte| byte == b'/')
    }
}

impl Borrow<[u8]> for RepoPath {
    /// Consistent with the derived `Eq`/`Ord`/`Hash`: all are bytewise, so
    /// ordered sets of paths can be probed by slice without allocating.
    fn borrow(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Serialize for RepoPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RepoPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = ByteString::deserialize(deserializer)?;
        Self::new(bytes.into_bytes()).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for RepoPath {
    fn schema_name() -> Cow<'static, str> {
        "RepoPath".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::RepoPath").into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        byte_string_schema(
            generator,
            "Repository-relative path bytes: `/`-separated, no empty, `.`, `..`, or `.git` \
             component, no NUL. A JSON string when valid UTF-8, otherwise {\"hex\": lowercase hex}.",
        )
    }
}

fn check_repo_path(bytes: &[u8]) -> Result<(), CoreModelError> {
    let bad = |reason: &str| CoreModelError::Invalid {
        what: "repository path",
        detail: format!("{reason}: {}", show_bytes(bytes)),
    };
    if bytes.is_empty() {
        return Err(bad("empty"));
    }
    if bytes.contains(&0) {
        return Err(bad("contains NUL"));
    }
    for component in bytes.split(|&byte| byte == b'/') {
        if component.is_empty() {
            return Err(bad("empty component (leading, trailing, or doubled `/`)"));
        }
        if component == b"." || component == b".." {
            return Err(bad("`.` or `..` component"));
        }
        if is_dot_git(component) {
            return Err(bad("component names the repository metadata directory"));
        }
    }
    Ok(())
}

/// Git's `is_ntfs_dotgit` per backslash-separated segment, or `is_hfs_dotgit`.
fn is_dot_git(component: &[u8]) -> bool {
    component.split(|&byte| byte == b'\\').any(is_ntfs_dot_git) || is_hfs_dot_git(component)
}

fn is_git_letters(g: u8, i: u8, t: u8) -> bool {
    g.eq_ignore_ascii_case(&b'g') && i.eq_ignore_ascii_case(&b'i') && t.eq_ignore_ascii_case(&b't')
}

/// `.git` or the NTFS short name `git~1`, followed only by spaces and dots
/// until the end or an alternate-data-stream `:` (`path.c:is_ntfs_dotgit`).
fn is_ntfs_dot_git(name: &[u8]) -> bool {
    let rest = match name {
        [b'.', g, i, t, rest @ ..] if is_git_letters(*g, *i, *t) => rest,
        [g, i, t, b'~', b'1', rest @ ..] if is_git_letters(*g, *i, *t) => rest,
        _ => return false,
    };
    for &byte in rest {
        match byte {
            b':' => return true,
            b'.' | b' ' => {}
            _ => return false,
        }
    }
    true
}

/// HFS+ ignores some code points when comparing names, so `.g\u{200c}it` is
/// `.git` there (`utf8.c:is_hfs_dot_generic`). Invalid UTF-8 cannot match.
fn is_hfs_dot_git(name: &[u8]) -> bool {
    let Ok(text) = core::str::from_utf8(name) else {
        return false;
    };
    let mut chars = text.chars().filter(|&c| !is_hfs_ignorable(c));
    chars.next() == Some('.')
        && "git".chars().all(|want| {
            chars
                .next()
                .is_some_and(|got| got.is_ascii() && got.to_ascii_lowercase() == want)
        })
        && chars.next().is_none()
}

fn is_hfs_ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{200c}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{206a}'..='\u{206f}' | '\u{feff}'
    )
}

// ---------------------------------------------------------------------------
// Stage, FileMode, stat, flags
// ---------------------------------------------------------------------------

/// An index stage: `Zero` is a normal entry; `Base`, `Ours`, `Theirs` are the
/// stages 1, 2, 3 of an unmerged path. Serializes as the integer 0..=3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Stage {
    Zero,
    Base,
    Ours,
    Theirs,
}

impl Stage {
    /// Every stage in index order.
    pub const ALL: [Self; 4] = [Self::Zero, Self::Base, Self::Ours, Self::Theirs];

    /// The Git stage number.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Zero => 0,
            Self::Base => 1,
            Self::Ours => 2,
            Self::Theirs => 3,
        }
    }

    /// Parses a stage number.
    ///
    /// # Errors
    /// [`CoreModelError::Invalid`] for anything above 3.
    pub fn from_u8(value: u8) -> Result<Self, CoreModelError> {
        match value {
            0 => Ok(Self::Zero),
            1 => Ok(Self::Base),
            2 => Ok(Self::Ours),
            3 => Ok(Self::Theirs),
            other => Err(CoreModelError::Invalid {
                what: "index stage",
                detail: format!("{other} is not in 0..=3"),
            }),
        }
    }
}

impl Serialize for Stage {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for Stage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u8::deserialize(deserializer)?;
        Self::from_u8(value).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for Stage {
    fn schema_name() -> Cow<'static, str> {
        "Stage".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::Stage").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "Index stage: 0 normal, 1 base, 2 ours, 3 theirs.",
            "type": "integer",
            "enum": [0, 1, 2, 3]
        })
    }
}

/// The four modes a Git index entry can carry.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FileMode {
    /// `100644`
    Regular,
    /// `100755`
    Executable,
    /// `120000`
    Symlink,
    /// `160000`: the oid names a commit in another repository.
    Gitlink,
}

impl FileMode {
    /// The canonical Git mode.
    #[must_use]
    pub const fn octal(self) -> u32 {
        match self {
            Self::Regular => 0o100_644,
            Self::Executable => 0o100_755,
            Self::Symlink => 0o120_000,
            Self::Gitlink => 0o160_000,
        }
    }

    /// Normalizes a raw mode the way Git's `create_ce_mode` does for regular
    /// files (any owner-exec bit means `100755`, otherwise `100644`) and
    /// accepts symlink and gitlink type bits. A directory or unknown type is
    /// rejected rather than coerced.
    ///
    /// # Errors
    /// [`CoreModelError::Invalid`] for a type Git cannot index.
    pub fn from_octal(mode: u32) -> Result<Self, CoreModelError> {
        match mode & 0o170_000 {
            0o100_000 if mode & 0o100 != 0 => Ok(Self::Executable),
            0o100_000 => Ok(Self::Regular),
            0o120_000 => Ok(Self::Symlink),
            0o160_000 => Ok(Self::Gitlink),
            _ => Err(CoreModelError::Invalid {
                what: "file mode",
                detail: format!("{mode:o} is not an indexable mode"),
            }),
        }
    }
}

/// A timestamp as the filesystem reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct StatTime {
    pub secs: i64,
    /// Nanoseconds within the second; must be below 1e9.
    pub nanos: u32,
}

/// The stat tuple Git's racy-clean check compares (`statinfo.h`), kept at full
/// width. Truncation to Git's 32-bit fields is the strict interpreter's
/// concern when it compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct StatData {
    pub ctime: StatTime,
    pub mtime: StatTime,
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
}

impl StatData {
    /// # Errors
    /// [`CoreModelError::Invalid`] when a nanosecond field is not below 1e9.
    pub fn validate(&self) -> Result<(), CoreModelError> {
        for (what, time) in [("ctime", self.ctime), ("mtime", self.mtime)] {
            if time.nanos >= 1_000_000_000 {
                return Err(CoreModelError::Invalid {
                    what: "stat time",
                    detail: format!("{what} nanos {} is not below 1e9", time.nanos),
                });
            }
        }
        Ok(())
    }
}

/// Per-entry flags Git persists in the index.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct IndexFlags {
    /// `CE_VALID` (`update-index --assume-unchanged`).
    #[serde(default)]
    pub assume_unchanged: bool,
    /// `CE_INTENT_TO_ADD` (`add -N`): the row holds the empty blob and only
    /// reserves the path. Valid at stage 0 only.
    #[serde(default)]
    pub intent_to_add: bool,
    /// `CE_SKIP_WORKTREE` (sparse checkout).
    #[serde(default)]
    pub skip_worktree: bool,
}

// ---------------------------------------------------------------------------
// IndexEntry
// ---------------------------------------------------------------------------

/// One index row's value.
///
/// An entry always carries an object id: adding a path records the bytes the
/// worktree held at that moment, never the name alone. [`Self::for_blob`]
/// derives the id from the content; a caller that streamed a large file
/// supplies the id it computed to [`Self::new`]. The one name-only state Git
/// has, intent-to-add, is explicit: the empty blob plus the flag.
///
/// Invariants that need no repository context are enforced at construction
/// and deserialization: the id is not null, stat nanoseconds are below 1e9,
/// and an intent-to-add row holds exactly the empty blob. Width against the
/// repository hash kind is [`Self::validate`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct IndexEntry {
    oid: Oid,
    mode: FileMode,
    /// `None` when the row was never matched against a worktree file
    /// (`update-index --cacheinfo`, `read-tree`): Git then stores zeros.
    #[serde(default)]
    stat: Option<StatData>,
    #[serde(default)]
    flags: IndexFlags,
}

impl IndexEntry {
    /// Builds a validated entry.
    ///
    /// # Errors
    /// [`CoreModelError::Invalid`] for a null id, an out-of-range stat time,
    /// or an intent-to-add row that does not hold the empty blob.
    pub fn new(
        oid: Oid,
        mode: FileMode,
        stat: Option<StatData>,
        flags: IndexFlags,
    ) -> Result<Self, CoreModelError> {
        reject_null_oid(oid, "index entry")?;
        if let Some(stat) = &stat {
            stat.validate()?;
        }
        if flags.intent_to_add && oid != oid.kind().hash_git_object("blob", b"")? {
            return Err(CoreModelError::Invalid {
                what: "index entry",
                detail: "an intent-to-add row must hold the empty blob".to_owned(),
            });
        }
        Ok(Self {
            oid,
            mode,
            stat,
            flags,
        })
    }

    /// The row `git add` records for a file whose current bytes are
    /// `content` (a symlink's content is its target).
    ///
    /// # Errors
    /// [`CoreModelError::Invalid`] for [`FileMode::Gitlink`], which records a
    /// commit id and has no blob content, or on a SHA-1 collision attack input.
    pub fn for_blob(
        kind: HashKind,
        mode: FileMode,
        content: &[u8],
        stat: Option<StatData>,
    ) -> Result<Self, CoreModelError> {
        if mode == FileMode::Gitlink {
            return Err(CoreModelError::Invalid {
                what: "index entry",
                detail: "a gitlink records a commit id, not blob content".to_owned(),
            });
        }
        let oid = kind.hash_git_object("blob", content)?;
        Self::new(oid, mode, stat, IndexFlags::default())
    }

    /// The row `git add -N` records: the empty blob plus the intent flag.
    ///
    /// # Errors
    /// [`CoreModelError::Invalid`] for [`FileMode::Gitlink`].
    pub fn intent_to_add(
        kind: HashKind,
        mode: FileMode,
        stat: Option<StatData>,
    ) -> Result<Self, CoreModelError> {
        if mode == FileMode::Gitlink {
            return Err(CoreModelError::Invalid {
                what: "index entry",
                detail: "a gitlink cannot be an intent-to-add row".to_owned(),
            });
        }
        let oid = kind.hash_git_object("blob", b"")?;
        let flags = IndexFlags {
            intent_to_add: true,
            ..IndexFlags::default()
        };
        Self::new(oid, mode, stat, flags)
    }

    #[must_use]
    pub const fn oid(&self) -> Oid {
        self.oid
    }

    #[must_use]
    pub const fn mode(&self) -> FileMode {
        self.mode
    }

    #[must_use]
    pub const fn stat(&self) -> Option<StatData> {
        self.stat
    }

    #[must_use]
    pub const fn flags(&self) -> IndexFlags {
        self.flags
    }

    /// Checks the id width against the repository's fixed object format.
    ///
    /// # Errors
    /// [`CoreModelError::ObjectFormat`] on a width mismatch.
    pub fn validate(&self, kind: HashKind) -> Result<(), CoreModelError> {
        self.oid.expect_kind(kind, "index entry")
    }
}

impl<'de> Deserialize<'de> for IndexEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            oid: Oid,
            mode: FileMode,
            #[serde(default)]
            stat: Option<StatData>,
            #[serde(default)]
            flags: IndexFlags,
        }
        let raw = Raw::deserialize(deserializer)?;
        Self::new(raw.oid, raw.mode, raw.stat, raw.flags).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Per-path aggregate
// ---------------------------------------------------------------------------

/// The stage 1, 2, and 3 entries of an unmerged path, at least one present.
///
/// Absent stages are meaningful: a modify/delete conflict has no `theirs`, an
/// add/add conflict has no `base`. Intent-to-add is stage-zero only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct UnmergedStages {
    base: Option<IndexEntry>,
    ours: Option<IndexEntry>,
    theirs: Option<IndexEntry>,
}

impl UnmergedStages {
    /// # Errors
    /// [`CoreModelError::Invalid`] when no stage is present or a row is
    /// intent-to-add.
    pub fn new(
        base: Option<IndexEntry>,
        ours: Option<IndexEntry>,
        theirs: Option<IndexEntry>,
    ) -> Result<Self, CoreModelError> {
        if base.is_none() && ours.is_none() && theirs.is_none() {
            return Err(CoreModelError::Invalid {
                what: "unmerged index entry",
                detail: "none of stages 1, 2, 3 is present".to_owned(),
            });
        }
        for entry in [&base, &ours, &theirs].into_iter().flatten() {
            if entry.flags().intent_to_add {
                return Err(CoreModelError::Invalid {
                    what: "unmerged index entry",
                    detail: "intent-to-add is only valid at stage 0".to_owned(),
                });
            }
        }
        Ok(Self { base, ours, theirs })
    }

    #[must_use]
    pub const fn base(&self) -> Option<&IndexEntry> {
        self.base.as_ref()
    }

    #[must_use]
    pub const fn ours(&self) -> Option<&IndexEntry> {
        self.ours.as_ref()
    }

    #[must_use]
    pub const fn theirs(&self) -> Option<&IndexEntry> {
        self.theirs.as_ref()
    }
}

impl<'de> Deserialize<'de> for UnmergedStages {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            base: Option<IndexEntry>,
            ours: Option<IndexEntry>,
            theirs: Option<IndexEntry>,
        }
        let raw = Raw::deserialize(deserializer)?;
        Self::new(raw.base, raw.ours, raw.theirs).map_err(serde::de::Error::custom)
    }
}

/// Every row of one path. Stage zero and stages 1..=3 cannot both exist: the
/// two variants are the only shapes, so exclusivity holds by construction and
/// for every deserialized value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathEntries {
    /// The single stage-zero row.
    Merged(IndexEntry),
    /// The applicable base/ours/theirs rows, no stage zero. Boxed: conflicts
    /// are cold, so the indirection keeps the hot merged case at one
    /// `IndexEntry` with no allocation on merged paths.
    Unmerged(Box<UnmergedStages>),
}

impl PathEntries {
    /// Assembles the rows a table scan returned for one path.
    ///
    /// # Errors
    /// [`CoreModelError::Invalid`] for no rows, two rows at one stage, or a
    /// stage-zero row alongside stages 1..=3 (a corrupt table, not a state to
    /// repair silently).
    pub fn from_rows(
        rows: impl IntoIterator<Item = (Stage, IndexEntry)>,
    ) -> Result<Self, CoreModelError> {
        let mut slots: [Option<IndexEntry>; 4] = [None, None, None, None];
        for (stage, entry) in rows {
            let slot = &mut slots[usize::from(stage.as_u8())];
            if slot.is_some() {
                return Err(CoreModelError::Invalid {
                    what: "index rows",
                    detail: format!("two rows at stage {}", stage.as_u8()),
                });
            }
            *slot = Some(entry);
        }
        let [zero, base, ours, theirs] = slots;
        match zero {
            Some(entry) => {
                if base.is_some() || ours.is_some() || theirs.is_some() {
                    return Err(CoreModelError::Invalid {
                        what: "index rows",
                        detail: "stage 0 cannot coexist with stages 1-3".to_owned(),
                    });
                }
                Ok(Self::Merged(entry))
            }
            None => UnmergedStages::new(base, ours, theirs)
                .map(|stages| Self::Unmerged(Box::new(stages))),
        }
    }

    /// The row at `stage`, if present.
    #[must_use]
    pub fn stage(&self, stage: Stage) -> Option<&IndexEntry> {
        match (self, stage) {
            (Self::Merged(entry), Stage::Zero) => Some(entry),
            (Self::Unmerged(unmerged), Stage::Base) => unmerged.base(),
            (Self::Unmerged(unmerged), Stage::Ours) => unmerged.ours(),
            (Self::Unmerged(unmerged), Stage::Theirs) => unmerged.theirs(),
            (Self::Merged(_), _) | (Self::Unmerged(_), Stage::Zero) => None,
        }
    }

    /// The present rows in stage order.
    pub fn rows(&self) -> impl Iterator<Item = (Stage, &IndexEntry)> {
        Stage::ALL
            .into_iter()
            .filter_map(move |stage| self.stage(stage).map(|entry| (stage, entry)))
    }

    #[must_use]
    pub const fn is_unmerged(&self) -> bool {
        matches!(self, Self::Unmerged(_))
    }

    /// Checks every row's id width against the repository hash kind.
    ///
    /// # Errors
    /// [`CoreModelError::ObjectFormat`] on the first mismatch.
    pub fn validate(&self, kind: HashKind) -> Result<(), CoreModelError> {
        self.rows().try_for_each(|(_, entry)| entry.validate(kind))
    }
}

/// The ordered table key of one row. `Ord` is Git's index order: path, then
/// stage.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct IndexKey {
    pub path: RepoPath,
    pub stage: Stage,
}

/// The exact row keys a store must touch to move one path between two
/// [`PathEntries`] states. Unchanged rows appear in neither list, so a
/// resolve deletes stages 1..=3 and puts stage 0 in the same transaction and
/// can never leave stage zero beside an unmerged stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowDelta<'a> {
    pub delete: Vec<Stage>,
    pub put: Vec<(Stage, &'a IndexEntry)>,
}

/// Computes the [`RowDelta`] from `before` (what the table holds, `None` for
/// an absent path) to `after` (`None` removes the path).
#[must_use]
pub fn row_delta<'a>(before: Option<&PathEntries>, after: Option<&'a PathEntries>) -> RowDelta<'a> {
    let mut delta = RowDelta {
        delete: Vec::new(),
        put: Vec::new(),
    };
    for stage in Stage::ALL {
        let old = before.and_then(|entries| entries.stage(stage));
        let new = after.and_then(|entries| entries.stage(stage));
        match (old, new) {
            (Some(_), None) => delta.delete.push(stage),
            (_, Some(entry)) if old != Some(entry) => delta.put.push((stage, entry)),
            _ => {}
        }
    }
    delta
}

// ---------------------------------------------------------------------------
// IndexGeneration
// ---------------------------------------------------------------------------

/// The per-workspace index generation. Every index mutation bumps it in the
/// same transaction as the rows; overflow fails instead of wrapping.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(transparent)]
pub struct IndexGeneration(pub u64);

impl IndexGeneration {
    /// The following generation.
    ///
    /// # Errors
    /// [`CoreModelError::Capacity`] at `u64::MAX`; the value never wraps.
    pub fn next(self) -> Result<Self, CoreModelError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| CoreModelError::Capacity("index generation exhausted".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO_BLOB_SHA1: &str = "ce013625030ba8dba906f756967f9e9ca394464a";
    const EMPTY_BLOB_SHA1: &str = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";
    const EMPTY_BLOB_SHA256: &str =
        "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813";

    fn path(text: &str) -> RepoPath {
        RepoPath::new(text).expect("valid path")
    }

    fn blob(content: &[u8]) -> IndexEntry {
        IndexEntry::for_blob(HashKind::Sha1, FileMode::Regular, content, None).expect("entry")
    }

    fn stat(nanos: u32) -> StatData {
        StatData {
            ctime: StatTime {
                secs: 1_700_000_000,
                nanos,
            },
            mtime: StatTime {
                secs: 1_700_000_001,
                nanos,
            },
            dev: 64_768,
            ino: 9_001,
            uid: 1000,
            gid: 1000,
            size: 6,
        }
    }

    // ---- RepoPath ---------------------------------------------------------

    #[test]
    fn accepts_ordinary_and_non_utf8_paths() {
        for ok in [
            &b"a"[..],
            b"dir/file.txt",
            b"a/b/c/d",
            b".gitignore",
            b".github/workflows/ci.yml",
            b"foo.git",
            b"git~2",
            b"dir with space/\xc3\xa4.txt",
            b"\xff\xfe/\x01\x7f",
            b"back\\slash",
            b".gitmodules",
            b"...",
        ] {
            assert!(RepoPath::new(ok).is_ok(), "rejected {}", show_bytes(ok));
        }
    }

    #[test]
    fn rejects_unsafe_paths() {
        for bad in [
            &b""[..],
            b"/abs",
            b"trailing/",
            b"a//b",
            b"a/./b",
            b"a/../b",
            b"..",
            b".",
            b"nul\0byte",
            b".git",
            b".GIT",
            b"a/.Git/hooks/x",
            b"x/.git",
            b"git~1",
            b"GIT~1",
            b".git.",
            b".git ",
            b".git. .",
            b".git::$INDEX_ALLOCATION",
            b"a\\.git",
            b".git\\x",
            "dir/.g\u{200c}it".as_bytes(),
            "\u{feff}.git".as_bytes(),
        ] {
            let err = RepoPath::new(bad).expect_err(&show_bytes(bad));
            assert!(
                matches!(
                    err,
                    CoreModelError::Invalid {
                        what: "repository path",
                        ..
                    }
                ),
                "{err:?}"
            );
        }
    }

    #[test]
    fn dot_git_lookalikes_that_git_allows_stay_allowed() {
        for ok in [
            ".gi",
            ".gitx",
            "x.git/y",
            ".git-hooks",
            "git~12",
            "git~",
            ".gi\u{200c}x",
        ] {
            assert!(RepoPath::new(ok).is_ok(), "rejected {ok}");
        }
    }

    #[test]
    fn path_error_text_is_bounded() {
        let huge = vec![b'a'; 1 << 20];
        let mut bad = huge;
        bad.extend_from_slice(b"//");
        let err = RepoPath::new(bad).expect_err("double slash").to_string();
        assert!(err.len() < 400, "unbounded error text: {} bytes", err.len());
    }

    #[test]
    fn path_parts_follow_the_slash_structure() {
        let nested = path("a/bb/ccc");
        assert_eq!(nested.parent(), Some(&b"a/bb"[..]));
        assert_eq!(nested.file_name(), b"ccc");
        assert_eq!(
            nested.components().collect::<Vec<_>>(),
            [&b"a"[..], b"bb", b"ccc"]
        );
        let top = path("top");
        assert_eq!(top.parent(), None);
        assert_eq!(top.file_name(), b"top");
    }

    #[test]
    fn path_order_and_slice_probing_are_bytewise() {
        let mut sorted = vec![path("b"), path("a/b"), path("a-b"), path("a")];
        sorted.sort();
        let order: Vec<&[u8]> = sorted.iter().map(RepoPath::as_bytes).collect();
        // `-` (0x2d) sorts before `/` (0x2f): "a-b" precedes "a/b".
        assert_eq!(order, [&b"a"[..], b"a-b", b"a/b", b"b"]);
        let set: std::collections::BTreeSet<RepoPath> = sorted.into_iter().collect();
        assert!(set.contains(&b"a/b"[..]));
        assert!(!set.contains(&b"a/"[..]));
    }

    #[test]
    fn utf8_path_serializes_as_a_string_and_round_trips() {
        let original = path("dir/\u{e4}.txt");
        let json = sonic_rs::to_string(&original).expect("json");
        assert_eq!(json, "\"dir/\u{e4}.txt\"");
        assert_eq!(
            sonic_rs::from_str::<RepoPath>(&json).expect("parse"),
            original
        );
    }

    #[test]
    fn non_utf8_path_survives_json_and_postcard_exactly() {
        let original = RepoPath::new(&b"dir/\xff\xfe\x00z"[..]).expect_err("NUL is invalid");
        assert!(matches!(original, CoreModelError::Invalid { .. }));
        let original = RepoPath::new(&b"dir/\xff\xfez"[..]).expect("valid");
        assert!(original.to_utf8().is_none());
        let json = sonic_rs::to_value(&original).expect("value");
        {
            use sonic_rs::JsonValueTrait;
            assert!(
                json.is_object(),
                "non-UTF-8 must use the hex object: {json}"
            );
        }
        let back: RepoPath = sonic_rs::from_value(&json).expect("parse");
        assert_eq!(back.as_bytes(), original.as_bytes());
        let bytes = postcard::to_allocvec(&original).expect("encode");
        let back: RepoPath = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(back, original);
    }

    #[test]
    fn deserialization_validates_paths_in_every_form() {
        for bad in [
            "\"\"",
            "\"../escape\"",
            "\"a//b\"",
            "\"a/.git/config\"",
            "{\"hex\":\"\"}",
            "{\"hex\":\"2e2e\"}",
            "{\"hex\":\"612f00\"}",
            "{\"hex\":\"zz\"}",
            "42",
            "null",
        ] {
            assert!(
                sonic_rs::from_str::<RepoPath>(bad).is_err(),
                "accepted {bad}"
            );
        }
        // Postcard carries raw bytes, so the same rule must reject there too.
        let raw = postcard::to_allocvec(&ByteString::new(b"x/../y".to_vec())).expect("encode");
        assert!(postcard::from_bytes::<RepoPath>(&raw).is_err());
    }

    // ---- Stage and FileMode ----------------------------------------------

    #[test]
    fn stage_is_an_integer_zero_to_three() {
        for stage in Stage::ALL {
            let json = sonic_rs::to_string(&stage).expect("json");
            assert_eq!(json, stage.as_u8().to_string());
            assert_eq!(sonic_rs::from_str::<Stage>(&json).expect("parse"), stage);
            let bytes = postcard::to_allocvec(&stage).expect("encode");
            assert_eq!(
                postcard::from_bytes::<Stage>(&bytes).expect("decode"),
                stage
            );
        }
        for bad in ["4", "255", "-1", "\"1\"", "1.5", "null"] {
            assert!(sonic_rs::from_str::<Stage>(bad).is_err(), "accepted {bad}");
        }
        assert!(Stage::from_u8(4).is_err());
    }

    #[test]
    fn stage_order_is_git_order() {
        assert!(
            Stage::Zero < Stage::Base && Stage::Base < Stage::Ours && Stage::Ours < Stage::Theirs
        );
        let a0 = IndexKey {
            path: path("a"),
            stage: Stage::Zero,
        };
        let a3 = IndexKey {
            path: path("a"),
            stage: Stage::Theirs,
        };
        let b0 = IndexKey {
            path: path("b"),
            stage: Stage::Zero,
        };
        assert!(a0 < a3 && a3 < b0);
    }

    #[test]
    fn file_mode_normalizes_like_git() {
        assert_eq!(
            FileMode::from_octal(0o100_644).expect("mode"),
            FileMode::Regular
        );
        assert_eq!(
            FileMode::from_octal(0o100_664).expect("mode"),
            FileMode::Regular
        );
        assert_eq!(
            FileMode::from_octal(0o100_755).expect("mode"),
            FileMode::Executable
        );
        assert_eq!(
            FileMode::from_octal(0o100_700).expect("mode"),
            FileMode::Executable
        );
        assert_eq!(
            FileMode::from_octal(0o120_000).expect("mode"),
            FileMode::Symlink
        );
        assert_eq!(
            FileMode::from_octal(0o160_000).expect("mode"),
            FileMode::Gitlink
        );
        for bad in [0o040_000, 0o040_755, 0, 0o140_000, 0o010_000] {
            assert!(FileMode::from_octal(bad).is_err(), "accepted {bad:o}");
        }
        for mode in [
            FileMode::Regular,
            FileMode::Executable,
            FileMode::Symlink,
            FileMode::Gitlink,
        ] {
            assert_eq!(
                FileMode::from_octal(mode.octal()).expect("round trip"),
                mode
            );
        }
    }

    // ---- IndexEntry ------------------------------------------------------

    #[test]
    fn add_records_the_content_not_the_name() {
        let entry = blob(b"hello\n");
        assert_eq!(entry.oid().to_hex(), HELLO_BLOB_SHA1);
        // Different bytes at the same path are a different row value.
        assert_ne!(blob(b"hello!\n").oid(), entry.oid());
        let sha256 =
            IndexEntry::for_blob(HashKind::Sha256, FileMode::Regular, b"", None).expect("entry");
        assert_eq!(sha256.oid().to_hex(), EMPTY_BLOB_SHA256);
        assert!(IndexEntry::for_blob(HashKind::Sha1, FileMode::Gitlink, b"", None).is_err());
    }

    #[test]
    fn symlink_content_is_its_target_bytes() {
        let link = IndexEntry::for_blob(HashKind::Sha1, FileMode::Symlink, b"../target", None)
            .expect("entry");
        let file = IndexEntry::for_blob(HashKind::Sha1, FileMode::Regular, b"../target", None)
            .expect("entry");
        assert_eq!(link.oid(), file.oid());
        assert_ne!(link.mode(), file.mode());
    }

    #[test]
    fn intent_to_add_is_the_empty_blob_plus_the_flag() {
        let ita = IndexEntry::intent_to_add(HashKind::Sha1, FileMode::Regular, None).expect("ita");
        assert_eq!(ita.oid().to_hex(), EMPTY_BLOB_SHA1);
        assert!(ita.flags().intent_to_add);
        // A flagged row holding any other content is a lie about the path.
        let flags = IndexFlags {
            intent_to_add: true,
            ..IndexFlags::default()
        };
        let hello = blob(b"hello\n");
        assert!(IndexEntry::new(hello.oid(), FileMode::Regular, None, flags).is_err());
        assert!(IndexEntry::intent_to_add(HashKind::Sha1, FileMode::Gitlink, None).is_err());
    }

    #[test]
    fn entry_rejects_null_oid_and_bad_stat_time() {
        let null = HashKind::Sha1.zero_oid();
        assert!(IndexEntry::new(null, FileMode::Regular, None, IndexFlags::default()).is_err());
        let ok = blob(b"x").oid();
        assert!(
            IndexEntry::new(
                ok,
                FileMode::Regular,
                Some(stat(999_999_999)),
                IndexFlags::default()
            )
            .is_ok()
        );
        let err = IndexEntry::new(
            ok,
            FileMode::Regular,
            Some(stat(1_000_000_000)),
            IndexFlags::default(),
        );
        assert!(matches!(
            err,
            Err(CoreModelError::Invalid {
                what: "stat time",
                ..
            })
        ));
    }

    #[test]
    fn entry_validate_checks_the_repository_hash_kind() {
        let sha1 = blob(b"x");
        assert!(sha1.validate(HashKind::Sha1).is_ok());
        assert!(matches!(
            sha1.validate(HashKind::Sha256),
            Err(CoreModelError::ObjectFormat(_))
        ));
    }

    #[test]
    fn entry_deserialization_enforces_the_same_invariants() {
        let null = "0".repeat(40);
        let bad = [
            format!("{{\"oid\":\"{null}\",\"mode\":\"regular\"}}"),
            format!(
                "{{\"oid\":\"{HELLO_BLOB_SHA1}\",\"mode\":\"regular\",\"flags\":{{\"intent_to_add\":true}}}}"
            ),
            format!("{{\"oid\":\"{HELLO_BLOB_SHA1}\",\"mode\":\"tree\"}}"),
            format!("{{\"oid\":\"{HELLO_BLOB_SHA1}\"}}"),
            "{\"mode\":\"regular\"}".to_owned(),
            format!(
                "{{\"oid\":\"{HELLO_BLOB_SHA1}\",\"mode\":\"regular\",\"stat\":{{\"ctime\":{{\"secs\":0,\"nanos\":1000000000}},\"mtime\":{{\"secs\":0,\"nanos\":0}},\"dev\":0,\"ino\":0,\"uid\":0,\"gid\":0,\"size\":0}}}}"
            ),
        ];
        for text in bad {
            assert!(
                sonic_rs::from_str::<IndexEntry>(&text).is_err(),
                "accepted {text}"
            );
        }
        let minimal = format!("{{\"oid\":\"{HELLO_BLOB_SHA1}\",\"mode\":\"executable\"}}");
        let entry: IndexEntry = sonic_rs::from_str(&minimal).expect("defaults fill stat and flags");
        assert_eq!(entry.stat(), None);
        assert_eq!(entry.flags(), IndexFlags::default());
        assert_eq!(entry.mode(), FileMode::Executable);
    }

    // ---- PathEntries -----------------------------------------------------

    #[test]
    fn stage_zero_excludes_every_other_stage() {
        let e = blob(b"x");
        for extra in [Stage::Base, Stage::Ours, Stage::Theirs] {
            let err = PathEntries::from_rows([(Stage::Zero, e.clone()), (extra, e.clone())]);
            assert!(matches!(
                err,
                Err(CoreModelError::Invalid {
                    what: "index rows",
                    ..
                })
            ));
        }
        assert!(
            PathEntries::from_rows([(Stage::Zero, e.clone()), (Stage::Zero, e.clone())]).is_err()
        );
        assert!(PathEntries::from_rows([(Stage::Ours, e.clone()), (Stage::Ours, e)]).is_err());
        assert!(PathEntries::from_rows(std::iter::empty()).is_err());
    }

    #[test]
    fn every_nonempty_subset_of_stages_one_to_three_is_a_valid_unmerged_path() {
        let rows: Vec<(Stage, IndexEntry)> = [Stage::Base, Stage::Ours, Stage::Theirs]
            .into_iter()
            .map(|stage| (stage, blob(&[stage.as_u8()])))
            .collect();
        for mask in 1_u8..8 {
            let picked: Vec<(Stage, IndexEntry)> = rows
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, row)| row.clone())
                .collect();
            let entries = PathEntries::from_rows(picked.clone()).expect("unmerged subset");
            assert!(entries.is_unmerged());
            assert!(entries.stage(Stage::Zero).is_none());
            let back: Vec<(Stage, IndexEntry)> = entries
                .rows()
                .map(|(stage, entry)| (stage, entry.clone()))
                .collect();
            assert_eq!(back, picked);
        }
    }

    #[test]
    fn merged_path_has_exactly_one_stage_zero_row() {
        let e = blob(b"x");
        let merged = PathEntries::from_rows([(Stage::Zero, e.clone())]).expect("merged");
        assert!(!merged.is_unmerged());
        assert_eq!(merged.rows().count(), 1);
        assert_eq!(merged.stage(Stage::Zero), Some(&e));
        assert!(merged.stage(Stage::Ours).is_none());
    }

    #[test]
    fn intent_to_add_is_stage_zero_only() {
        let ita = IndexEntry::intent_to_add(HashKind::Sha1, FileMode::Regular, None).expect("ita");
        assert!(PathEntries::from_rows([(Stage::Zero, ita.clone())]).is_ok());
        for stage in [Stage::Base, Stage::Ours, Stage::Theirs] {
            assert!(
                PathEntries::from_rows([(stage, ita.clone())]).is_err(),
                "ita at {stage:?}"
            );
        }
    }

    #[test]
    fn path_entries_validate_every_row_against_the_hash_kind() {
        let sha256 =
            IndexEntry::for_blob(HashKind::Sha256, FileMode::Regular, b"x", None).expect("entry");
        let mixed = PathEntries::from_rows([(Stage::Ours, blob(b"x")), (Stage::Theirs, sha256)])
            .expect("rows");
        assert!(matches!(
            mixed.validate(HashKind::Sha1),
            Err(CoreModelError::ObjectFormat(_))
        ));
        assert!(matches!(
            mixed.validate(HashKind::Sha256),
            Err(CoreModelError::ObjectFormat(_))
        ));
    }

    #[test]
    fn path_entries_wire_forms_reject_malformed_shapes() {
        let entry = format!("{{\"oid\":\"{HELLO_BLOB_SHA1}\",\"mode\":\"regular\"}}");
        let good_merged = format!("{{\"merged\":{entry}}}");
        let good_unmerged = format!("{{\"unmerged\":{{\"ours\":{entry},\"theirs\":null}}}}");
        assert!(sonic_rs::from_str::<PathEntries>(&good_merged).is_ok());
        assert!(sonic_rs::from_str::<PathEntries>(&good_unmerged).is_ok());
        for bad in [
            "{\"unmerged\":{}}".to_owned(),
            "{\"unmerged\":{\"base\":null,\"ours\":null,\"theirs\":null}}".to_owned(),
            format!("{{\"merged\":{entry},\"unmerged\":{{\"ours\":{entry}}}}}"),
            format!("{{\"unmerged\":{entry}}}"),
            "{\"stage_zero\":{}}".to_owned(),
            "\"merged\"".to_owned(),
        ] {
            assert!(
                sonic_rs::from_str::<PathEntries>(&bad).is_err(),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn path_entries_round_trip_in_json_and_postcard() {
        let with_stat =
            IndexEntry::for_blob(HashKind::Sha1, FileMode::Executable, b"run", Some(stat(7)))
                .expect("entry");
        let unmerged = PathEntries::from_rows([
            (Stage::Base, blob(b"base")),
            (Stage::Theirs, with_stat.clone()),
        ])
        .expect("unmerged");
        for value in [PathEntries::Merged(with_stat), unmerged] {
            let json = sonic_rs::to_string(&value).expect("json");
            assert_eq!(
                sonic_rs::from_str::<PathEntries>(&json).expect("parse"),
                value
            );
            let bytes = postcard::to_allocvec(&value).expect("encode");
            assert_eq!(
                postcard::from_bytes::<PathEntries>(&bytes).expect("decode"),
                value
            );
        }
    }

    #[test]
    fn resolving_deletes_unmerged_rows_and_puts_stage_zero() {
        let unmerged = PathEntries::from_rows([
            (Stage::Base, blob(b"b")),
            (Stage::Ours, blob(b"o")),
            (Stage::Theirs, blob(b"t")),
        ])
        .expect("unmerged");
        let resolved = PathEntries::Merged(blob(b"merged"));
        let delta = row_delta(Some(&unmerged), Some(&resolved));
        assert_eq!(delta.delete, [Stage::Base, Stage::Ours, Stage::Theirs]);
        assert_eq!(
            delta.put,
            [(Stage::Zero, resolved.stage(Stage::Zero).expect("row"))]
        );
    }

    #[test]
    fn conflicting_a_merged_path_deletes_stage_zero() {
        let merged = PathEntries::Merged(blob(b"m"));
        let unmerged =
            PathEntries::from_rows([(Stage::Ours, blob(b"o")), (Stage::Theirs, blob(b"t"))])
                .expect("unmerged");
        let delta = row_delta(Some(&merged), Some(&unmerged));
        assert_eq!(delta.delete, [Stage::Zero]);
        assert_eq!(
            delta
                .put
                .iter()
                .map(|(stage, _)| *stage)
                .collect::<Vec<_>>(),
            [Stage::Ours, Stage::Theirs]
        );
    }

    #[test]
    fn unchanged_rows_are_not_touched_and_removal_deletes_all() {
        let before =
            PathEntries::from_rows([(Stage::Ours, blob(b"o")), (Stage::Theirs, blob(b"t"))])
                .expect("before");
        let after =
            PathEntries::from_rows([(Stage::Ours, blob(b"o")), (Stage::Theirs, blob(b"t2"))])
                .expect("after");
        let delta = row_delta(Some(&before), Some(&after));
        assert!(delta.delete.is_empty());
        assert_eq!(
            delta
                .put
                .iter()
                .map(|(stage, _)| *stage)
                .collect::<Vec<_>>(),
            [Stage::Theirs]
        );
        assert!(row_delta(Some(&before), Some(&before)).put.is_empty());
        assert_eq!(
            row_delta(Some(&before), None).delete,
            [Stage::Ours, Stage::Theirs]
        );
        let created = row_delta(None, Some(&after));
        assert!(created.delete.is_empty() && created.put.len() == 2);
        assert_eq!(
            row_delta(None, None),
            RowDelta {
                delete: vec![],
                put: vec![]
            }
        );
    }

    // ---- IndexGeneration -------------------------------------------------

    #[test]
    fn generation_counts_and_refuses_to_wrap() {
        assert_eq!(
            IndexGeneration::default().next().expect("next"),
            IndexGeneration(1)
        );
        assert_eq!(
            IndexGeneration(u64::MAX - 1).next().expect("next"),
            IndexGeneration(u64::MAX)
        );
        assert!(matches!(
            IndexGeneration(u64::MAX).next(),
            Err(CoreModelError::Capacity(_))
        ));
        assert_eq!(sonic_rs::to_string(&IndexGeneration(7)).expect("json"), "7");
    }
}
