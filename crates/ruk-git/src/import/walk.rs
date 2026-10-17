//! Closure walk: every object a ref tip reaches, emitted closure-first.
//!
//! The walker holds no object payload. It traverses depth-first in post
//! order over an explicit stack (linear histories never recurse): an object
//! is emitted only after every object it links to is emitted. That order is
//! the promotion guarantee: at any batch boundary every already published
//! object is closure-complete, because parents, trees, entries, and tag
//! targets always publish before the object that points at them.
//!
//! Blobs are emitted on entry. Everything else is emitted on exit after its
//! unseen links are pushed; the object is reread at exit if it was not held.
//! Missing objects are [`GitError::NotFound`] naming the missing OID and
//! its referrer, never a silent skip.

use std::collections::HashSet;

use ruk_core::ids::{HashKind, Oid};
use ruk_core::store::ObjectKind;

use crate::GitError;
use crate::import::objects::{
    Body, Location, SourceObject, SourceObjects, corrupt, header_name, verify,
};

/// Outgoing links of one object, in emission order.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ObjectLinks {
    /// Ordered `(oid, expected kind)` pairs. A consumer that dereferences
    /// them must find every one: a missing link is a named error.
    pub links: Vec<Link>,
}

/// One outgoing link: the identity plus the kind the referrer requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Link {
    pub oid: Oid,
    pub kind: ObjectKind,
}

/// Reads `payload` as `kind` and returns every object it links to.
///
/// Tree entries are returned in stored order with their required kind; a
/// gitlink (mode `160000`) is a foreign submodule commit and is never
/// followed or verified. Unsorted or duplicate entries are tolerated, as
/// Git reads them (only fsck complains); every entry's object is still
/// imported. Tag targets keep their declared kind.
///
/// # Errors
/// [`GitError::Corrupt`] for a payload that does not parse under `hash`.
pub fn object_links(
    kind: ObjectKind,
    payload: &[u8],
    hash: HashKind,
) -> Result<ObjectLinks, GitError> {
    let gix = hash.gix();
    match kind {
        ObjectKind::Blob => Ok(ObjectLinks::default()),
        ObjectKind::Commit => {
            let parsed = gix_object::CommitRef::from_bytes(payload, gix)
                .map_err(|err| corrupt(format!("commit payload: {err}")))?;
            let mut links = Vec::with_capacity(parsed.parents.len() + 1);
            links.push(Link {
                oid: hex_to_oid(&parsed.tree().to_hex().to_string(), hash)?,
                kind: ObjectKind::Tree,
            });
            for parent in parsed.parents() {
                links.push(Link {
                    oid: hex_to_oid(&parent.to_hex().to_string(), hash)?,
                    kind: ObjectKind::Commit,
                });
            }
            Ok(ObjectLinks { links })
        }
        ObjectKind::Tree => {
            let parsed = gix_object::TreeRef::from_bytes(payload, gix)
                .map_err(|err| corrupt(format!("tree payload: {err}")))?;
            let mut links = Vec::with_capacity(parsed.entries.len());
            for entry in &parsed.entries {
                if entry.mode.is_commit() {
                    continue;
                }
                let want = if entry.mode.is_tree() {
                    ObjectKind::Tree
                } else {
                    ObjectKind::Blob
                };
                links.push(Link {
                    oid: hex_to_oid(&entry.oid.to_hex().to_string(), hash)?,
                    kind: want,
                });
            }
            Ok(ObjectLinks { links })
        }
        ObjectKind::Tag => {
            let parsed = gix_object::TagRef::from_bytes(payload, gix)
                .map_err(|err| corrupt(format!("tag payload: {err}")))?;
            let kind = match parsed.target_kind {
                gix_object::Kind::Blob => ObjectKind::Blob,
                gix_object::Kind::Tree => ObjectKind::Tree,
                gix_object::Kind::Commit => ObjectKind::Commit,
                gix_object::Kind::Tag => ObjectKind::Tag,
            };
            let oid = hex_to_oid(&parsed.target().to_hex().to_string(), hash)?;
            Ok(ObjectLinks {
                links: vec![Link { oid, kind }],
            })
        }
        ObjectKind::Conflict => Err(GitError::Invalid {
            detail: "native conflict records are not Git objects".to_owned(),
        }),
    }
}

fn hex_to_oid(hex: &str, hash: HashKind) -> Result<Oid, GitError> {
    crate::parse_oid_for(hex, hash)
}

/// Total payload bytes held in exit frames before the walker falls back to
/// rereading an object at exit.
pub(crate) const EXIT_HOLD_BYTES: u64 = 64 << 20;

/// One object the closure walk emits; the object's closure was already
/// emitted (or is empty) when this is handed to the batcher.
#[derive(Debug)]
pub(crate) enum Emit {
    Memory { oid: Oid, object: SourceObject },
    Stream { oid: Oid },
}

#[derive(Debug)]
enum Frame {
    Enter {
        oid: Oid,
        kind: Option<ObjectKind>,
        referrer: Option<Oid>,
    },
    Exit {
        oid: Oid,
        object: Option<SourceObject>,
    },
}

/// Tracks which objects were already expanded: pack entries by their
/// position, loose objects by identity. `contains` answers without marking
/// so the walk can plan children before expansion.
#[derive(Debug, Default)]
pub(crate) struct Seen {
    packed: Vec<Vec<u64>>,
    loose: HashSet<Oid>,
}

impl Seen {
    fn program(sizes: impl Iterator<Item = u32>) -> Self {
        let packed = sizes
            .map(|size| vec![0_u64; size.div_ceil(64) as usize])
            .collect();
        Self {
            packed,
            loose: HashSet::new(),
        }
    }

    fn contains(&self, location: Location, oid: Oid) -> bool {
        match location {
            Location::Pack { pack, index } => self
                .packed
                .get(pack)
                .and_then(|words| words.get(index as usize / 64))
                .is_some_and(|word| *word & (1_u64 << (index % 64)) != 0),
            Location::Loose { .. } => self.loose.contains(&oid),
        }
    }

    fn mark(&mut self, location: Location, oid: Oid) {
        match location {
            Location::Pack { pack, index } => {
                if let Some(word) = self
                    .packed
                    .get_mut(pack)
                    .and_then(|words| words.get_mut(index as usize / 64))
                {
                    *word |= 1_u64 << (index % 64);
                }
            }
            Location::Loose { .. } => {
                self.loose.insert(oid);
            }
        }
    }
}

/// Depth-first post-order closure traversal with a bounded work stack.
///
/// `seen` marks an object when it is expanded (not when first pushed), so a
/// second push of an object that is still above its own exit frame skips
/// itself only after the pending frame emits it: descendants can never
/// depend on an ancestor (content addressing forbids reference cycles), so
/// skipping an already-seen pop is always safe and every emission follows
/// its full closure.
#[derive(Debug)]
pub(crate) struct Walker {
    hash: HashKind,
    stack: Vec<Frame>,
    seen: Seen,
    held: u64,
    max_frontier: usize,
}

impl Walker {
    pub(crate) fn new(source: &SourceObjects, max_frontier: usize) -> Self {
        Self {
            hash: source.hash_kind(),
            stack: Vec::new(),
            seen: Seen::program(source.pack_sizes()),
            held: 0,
            max_frontier,
        }
    }

    /// Seeds the walk with `(oid, expected kind, referrer)` tips; `None`
    /// kind accepts whatever the source holds.
    pub(crate) fn seed(
        &mut self,
        tips: impl Iterator<Item = (Oid, Option<ObjectKind>, Option<Oid>)>,
    ) -> Result<(), GitError> {
        for (oid, kind, referrer) in tips {
            self.push(Frame::Enter {
                oid,
                kind,
                referrer,
            })?;
        }
        Ok(())
    }

    fn push(&mut self, frame: Frame) -> Result<(), GitError> {
        if self.stack.len() >= self.max_frontier {
            return Err(GitError::Limit {
                detail: format!("import frontier exceeds {} entries", self.max_frontier),
            });
        }
        self.stack.push(frame);
        Ok(())
    }

    /// Returns the next object whose closure is complete.
    pub(crate) fn next(
        &mut self,
        source: &SourceObjects,
        progress: &crate::import::progress::ImportProgress,
    ) -> Result<Option<Emit>, GitError> {
        while let Some(frame) = self.stack.pop() {
            if progress.is_cancelled() {
                return Err(GitError::Cancelled {
                    detail: "import cancelled".to_owned(),
                });
            }
            match frame {
                Frame::Enter {
                    oid,
                    kind,
                    referrer,
                } => {
                    let Some(location) = source.locate(oid)? else {
                        return Err(missing(oid, referrer));
                    };
                    if self.seen.contains(location, oid) {
                        continue;
                    }
                    match source.read(oid, location)? {
                        Body::Memory(object) => {
                            check_kind(oid, object.kind, kind, referrer)?;
                            self.seen.mark(location, oid);
                            progress.object_read(
                                u64::try_from(object.payload.len()).unwrap_or(u64::MAX),
                            );
                            if object.kind == ObjectKind::Blob {
                                return Ok(Some(Emit::Memory { oid, object }));
                            }
                            if let Some(emit) = self.expand(source, oid, object, referrer)? {
                                return Ok(Some(emit));
                            }
                        }
                        Body::Stream(stream) => {
                            check_kind(oid, ObjectKind::Blob, kind, referrer)?;
                            self.seen.mark(location, oid);
                            progress.object_read(stream.size());
                            return Ok(Some(Emit::Stream { oid }));
                        }
                    }
                }
                Frame::Exit { oid, object } => {
                    if let Some(object) = object {
                        let size = u64::try_from(object.payload.len()).unwrap_or(u64::MAX);
                        self.held = self.held.saturating_sub(size);
                        return Ok(Some(Emit::Memory { oid, object }));
                    }
                    let object = source.read_in_memory(oid)?;
                    verify(oid, &object, source.hash_kind())?;
                    return Ok(Some(Emit::Memory { oid, object }));
                }
            }
        }
        Ok(None)
    }

    /// Hands the object to the batcher when its closure is already known;
    /// otherwise pushes unseen children under an exit frame that holds the
    /// payload while the 64 MiB budget allows, rereading it when not.
    fn expand(
        &mut self,
        source: &SourceObjects,
        oid: Oid,
        object: SourceObject,
        _referrer: Option<Oid>,
    ) -> Result<Option<Emit>, GitError> {
        let links = object_links(object.kind, &object.payload, self.hash)?;
        let mut pending: Vec<Link> = Vec::new();
        for link in links.links {
            let Some(location) = source.locate(link.oid)? else {
                return Err(missing(link.oid, Some(oid)));
            };
            if !self.seen.contains(location, link.oid) {
                pending.push(link);
            }
        }
        if pending.is_empty() {
            return Ok(Some(Emit::Memory { oid, object }));
        }
        let size = u64::try_from(object.payload.len()).unwrap_or(u64::MAX);
        let held = if size <= EXIT_HOLD_BYTES.saturating_sub(self.held) {
            self.held += size;
            Some(object)
        } else {
            None
        };
        self.push(Frame::Exit { oid, object: held })?;
        for link in pending.into_iter().rev() {
            self.push(Frame::Enter {
                oid: link.oid,
                kind: Some(link.kind),
                referrer: Some(oid),
            })?;
        }
        Ok(None)
    }
}

/// Shallow-commit marker: parents of these OIDs are legitimate source
/// boundaries and are not traversed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShallowSet {
    oids: Vec<Oid>,
}

impl ShallowSet {
    /// Every boundary OID, in file order.
    pub fn oids(&self) -> impl Iterator<Item = Oid> + '_ {
        self.oids.iter().copied()
    }

    /// Parses a Git `shallow` file: one hex OID per line.
    ///
    /// # Errors
    /// [`GitError::Io`] when the file cannot be read.
    pub fn read_shallow_file(git_dir: &std::path::Path, hash: HashKind) -> Result<Self, GitError> {
        use std::io::BufRead as _;
        let path = git_dir.join("shallow");
        let file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => {
                return Err(GitError::Io {
                    detail: format!("cannot open {}: {err}", path.display()),
                });
            }
        };
        let mut set = Self::default();
        for line in std::io::BufReader::new(file).lines() {
            let line = line.map_err(|err| GitError::Io {
                detail: format!("cannot read {}: {err}", path.display()),
            })?;
            let text = line.trim();
            if text.is_empty() {
                continue;
            }
            let oid = crate::parse_oid_for(text, hash)?;
            if !set.oids.contains(&oid) {
                set.oids.push(oid);
            }
        }
        Ok(set)
    }
}

fn missing(oid: Oid, referrer: Option<Oid>) -> GitError {
    GitError::NotFound {
        detail: match referrer {
            Some(from) => format!("object {oid} referenced by {from} is missing from the source"),
            None => format!("object {oid} is missing from the source"),
        },
    }
}

fn check_kind(
    oid: Oid,
    actual: ObjectKind,
    want: Option<ObjectKind>,
    referrer: Option<Oid>,
) -> Result<(), GitError> {
    let Some(want) = want else { return Ok(()) };
    if actual == want {
        return Ok(());
    }
    let name = header_name(actual).unwrap_or("unknown");
    Err(corrupt(match referrer {
        Some(from) => {
            format!("object {oid} referenced by {from} is a {name}, not the expected kind")
        }
        None => format!("object {oid} is a {name}, not the expected kind"),
    }))
}
