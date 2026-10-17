//! Read-only access to a source Git object database.
//!
//! Objects come from three places, searched in a fixed order so a lookup is
//! deterministic: every pack (`objects/pack/*.idx`, pack data v2/v3 and
//! index v1/v2 through [`gix_pack`]), then loose zlib objects, first in the
//! repository's own `objects` directory and then in its alternates (Git's
//! nesting bound of five). Nothing here writes to the source.
//!
//! Every object is verified against its OID before it leaves this module:
//! in-memory objects are re-hashed as `<kind> <len>\0payload` with the
//! repository hash kind, and streamed loose blobs are verified by the OID
//! [`Store::prepare`] derives from exactly the bytes it stored.

use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

use flate2::read::ZlibDecoder;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::store::{ObjectKind, PreparedObject, Store, StoreError};

use crate::GitError;

/// Loose blobs above this decoded size stream into the store instead of
/// being buffered.
pub(crate) const STREAM_THRESHOLD: u64 = 1 << 20;
/// Git's alternates nesting bound (`sha1-file.c`: depth 5).
const MAX_ALTERNATE_DEPTH: usize = 5;
/// `<kind> <decimal u64>\0` never exceeds this.
const MAX_LOOSE_HEADER: usize = 32;
/// Largest config or alternates file read while opening a source.
const MAX_SMALL_FILE: u64 = 1 << 20;

pub(crate) fn corrupt(detail: impl Into<String>) -> GitError {
    GitError::Corrupt {
        detail: detail.into(),
    }
}

pub(crate) fn io_error(what: &str, path: &Path, err: &io::Error) -> GitError {
    GitError::Io {
        detail: format!("{what} {}: {err}", path.display()),
    }
}

/// Converts a gix object id into an exact Ruk OID of the repository kind.
pub(crate) fn oid_from_gix(id: &gix_hash::ObjectId, kind: HashKind) -> Result<Oid, GitError> {
    let oid = Oid::from_bytes(id.as_slice()).map_err(|err| corrupt(err.to_string()))?;
    crate::require_kind(oid, kind)
}

pub(crate) const fn object_kind(kind: gix_object::Kind) -> ObjectKind {
    match kind {
        gix_object::Kind::Blob => ObjectKind::Blob,
        gix_object::Kind::Tree => ObjectKind::Tree,
        gix_object::Kind::Commit => ObjectKind::Commit,
        gix_object::Kind::Tag => ObjectKind::Tag,
    }
}

/// The Git header name of an object kind; native conflicts have none.
pub(crate) fn header_name(kind: ObjectKind) -> Result<&'static str, GitError> {
    kind.git_header_name().ok_or_else(|| GitError::Invalid {
        detail: "native conflict records are not Git objects".to_owned(),
    })
}

/// Detects the source repository's object format from `config`
/// (`extensions.objectFormat`; absent means SHA-1, as in Git).
///
/// # Errors
/// [`GitError::ObjectFormat`] for an unknown format name, [`GitError::Io`]
/// when the config cannot be read.
pub fn source_hash_kind(git_dir: &Path) -> Result<HashKind, GitError> {
    let path = git_dir.join("config");
    let text = match read_small(&path)? {
        Some(bytes) => bytes,
        None => return Ok(HashKind::Sha1),
    };
    let mut in_extensions = false;
    for raw in text.split(|&byte| byte == b'\n') {
        let line = raw.trim_ascii();
        if line.is_empty() || line.starts_with(b"#") || line.starts_with(b";") {
            continue;
        }
        if line.starts_with(b"[") {
            let end = line.iter().position(|&b| b == b']').unwrap_or(line.len());
            let section = line[1..end].trim_ascii();
            in_extensions = section.eq_ignore_ascii_case(b"extensions");
            continue;
        }
        if !in_extensions {
            continue;
        }
        let Some(eq) = line.iter().position(|&b| b == b'=') else {
            continue;
        };
        if !line[..eq]
            .trim_ascii()
            .eq_ignore_ascii_case(b"objectformat")
        {
            continue;
        }
        let value = line[eq + 1..].trim_ascii();
        return if value.eq_ignore_ascii_case(b"sha1") {
            Ok(HashKind::Sha1)
        } else if value.eq_ignore_ascii_case(b"sha256") {
            Ok(HashKind::Sha256)
        } else {
            Err(GitError::ObjectFormat {
                detail: format!(
                    "source repository declares unknown object format {:?}",
                    String::from_utf8_lossy(value)
                ),
            })
        };
    }
    Ok(HashKind::Sha1)
}

/// Reads a small optional file; `None` when it does not exist.
fn read_small(path: &Path) -> Result<Option<Vec<u8>>, GitError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(io_error("cannot open", path, &err)),
    };
    let mut bytes = Vec::new();
    file.take(MAX_SMALL_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| io_error("cannot read", path, &err))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SMALL_FILE {
        return Err(GitError::Limit {
            detail: format!("{} exceeds {MAX_SMALL_FILE} bytes", path.display()),
        });
    }
    Ok(Some(bytes))
}

/// Where one object lives in the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Location {
    /// Entry `index` of pack `pack` (in [`SourceObjects`] order).
    Pack { pack: usize, index: u32 },
    /// A loose object under object directory `dir`.
    Loose { dir: usize },
}

/// A verified object held in memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceObject {
    pub kind: ObjectKind,
    pub payload: Vec<u8>,
}

/// A large loose blob, positioned at its first payload byte.
pub struct LooseStream {
    size: u64,
    decoder: ZlibDecoder<BufReader<File>>,
}

impl fmt::Debug for LooseStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LooseStream")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// An object as read from the source.
#[derive(Debug)]
pub enum Body {
    /// Fully decoded; the OID is verified by [`SourceObjects::read`].
    Memory(SourceObject),
    /// A loose blob above [`STREAM_THRESHOLD`]; verified by
    /// [`LooseStream::stage`].
    Stream(LooseStream),
}

/// The object database of one source repository.
pub struct SourceObjects {
    kind: HashKind,
    loose_dirs: Vec<PathBuf>,
    packs: Vec<gix_pack::Bundle>,
    max_object_bytes: u64,
}

impl fmt::Debug for SourceObjects {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceObjects")
            .field("kind", &self.kind)
            .field("loose_dirs", &self.loose_dirs)
            .field("packs", &self.packs.len())
            .finish()
    }
}

impl SourceObjects {
    /// Opens the object database of `git_dir` (a bare repository or a
    /// `.git` directory) for a store of hash `kind`.
    ///
    /// # Errors
    /// [`GitError::ObjectFormat`] when the source format differs from
    /// `kind`; [`GitError::Invalid`] when `git_dir` has no `objects`
    /// directory or an alternate cannot be resolved; [`GitError::Corrupt`]
    /// for an unreadable pack or index; [`GitError::Limit`] for alternates
    /// nested deeper than Git allows.
    pub fn open(git_dir: &Path, kind: HashKind, max_object_bytes: u64) -> Result<Self, GitError> {
        let source_kind = source_hash_kind(git_dir)?;
        if source_kind != kind {
            return Err(GitError::ObjectFormat {
                detail: format!(
                    "source repository {} uses {source_kind} but the store is {kind}",
                    git_dir.display()
                ),
            });
        }
        let primary = git_dir.join("objects");
        if !primary.is_dir() {
            return Err(GitError::Invalid {
                detail: format!("{} is not a Git directory: no objects/", git_dir.display()),
            });
        }
        let mut loose_dirs = Vec::new();
        let mut visited = HashSet::new();
        collect_object_dirs(&primary, 0, &mut loose_dirs, &mut visited)?;

        let alloc_limit = usize::try_from(max_object_bytes).unwrap_or(usize::MAX);
        let mut packs = Vec::new();
        for dir in &loose_dirs {
            for idx in pack_indexes(&dir.join("pack"))? {
                let index = gix_pack::index::File::at(&idx, kind.gix())
                    .map_err(|err| corrupt(format!("pack index {}: {err}", idx.display())))?;
                let data_path = idx.with_extension("pack");
                let pack = gix_pack::data::File::at(&data_path, kind.gix())
                    .map_err(|err| corrupt(format!("pack {}: {err}", data_path.display())))?
                    .with_alloc_limit_bytes(Some(alloc_limit));
                packs.push(gix_pack::Bundle { pack, index });
            }
        }
        Ok(Self {
            kind,
            loose_dirs,
            packs,
            max_object_bytes,
        })
    }

    #[must_use]
    pub fn hash_kind(&self) -> HashKind {
        self.kind
    }

    /// Number of entries in each pack, in search order.
    pub(crate) fn pack_sizes(&self) -> impl Iterator<Item = u32> + '_ {
        self.packs.iter().map(|bundle| bundle.index.num_objects())
    }

    /// Finds `oid`: packs first, then loose directories.
    ///
    /// # Errors
    /// [`GitError::Io`] when a loose path cannot be inspected.
    pub fn locate(&self, oid: Oid) -> Result<Option<Location>, GitError> {
        let id = oid.to_gix();
        for (pack, bundle) in self.packs.iter().enumerate() {
            if let Some(index) = bundle.index.lookup(id) {
                return Ok(Some(Location::Pack { pack, index }));
            }
        }
        for (dir, root) in self.loose_dirs.iter().enumerate() {
            let path = loose_path(root, oid);
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_file() => return Ok(Some(Location::Loose { dir })),
                Ok(_) => return Err(corrupt(format!("{} is not a regular file", path.display()))),
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(io_error("cannot inspect", &path, &err)),
            }
        }
        Ok(None)
    }

    /// Reads the object at `location`, which must be where `oid` was found.
    /// In-memory objects are verified here.
    ///
    /// # Errors
    /// [`GitError::Corrupt`] for undecodable data or a hash mismatch;
    /// [`GitError::Limit`] for an object above the size limit.
    pub fn read(&self, oid: Oid, location: Location) -> Result<Body, GitError> {
        let object = match location {
            Location::Pack { pack, index } => self.read_packed(oid, pack, index)?,
            Location::Loose { dir } => match self.open_loose(oid, dir)? {
                LooseOpen::Memory(object) => object,
                LooseOpen::Stream(stream) => return Ok(Body::Stream(stream)),
            },
        };
        verify(oid, &object, self.kind)?;
        Ok(Body::Memory(object))
    }

    /// Reads `oid` fully into memory, wherever it lives; streams are
    /// buffered under the size limit.
    ///
    /// # Errors
    /// As [`Self::read`], plus [`GitError::NotFound`] when absent.
    pub fn read_in_memory(&self, oid: Oid) -> Result<SourceObject, GitError> {
        let location = self.locate(oid)?.ok_or_else(|| GitError::NotFound {
            detail: format!("object {oid} is missing from the source"),
        })?;
        match self.read(oid, location)? {
            Body::Memory(object) => Ok(object),
            Body::Stream(mut stream) => {
                let mut payload = Vec::new();
                let size = stream.size;
                read_exact_payload(&mut stream.decoder, size, &mut payload)
                    .map_err(|err| corrupt(format!("loose object {oid}: {err}")))?;
                ensure_eof(&mut stream.decoder, oid)?;
                let object = SourceObject {
                    kind: ObjectKind::Blob,
                    payload,
                };
                verify(oid, &object, self.kind)?;
                Ok(object)
            }
        }
    }

    fn read_packed(&self, oid: Oid, pack: usize, index: u32) -> Result<SourceObject, GitError> {
        let bundle = self
            .packs
            .get(pack)
            .ok_or_else(|| corrupt(format!("pack {pack} for {oid} is not open")))?;
        let mut payload = Vec::new();
        let mut inflate = Default::default();
        let kind = {
            let (data, _location) = bundle
                .get_object_by_index(
                    index,
                    &mut payload,
                    &mut inflate,
                    &mut gix_pack::cache::Never,
                )
                .map_err(|err| corrupt(format!("packed object {oid}: {err}")))?;
            object_kind(data.kind)
        };
        if u64::try_from(payload.len()).unwrap_or(u64::MAX) > self.max_object_bytes {
            return Err(GitError::Limit {
                detail: format!("object {oid} exceeds {} bytes", self.max_object_bytes),
            });
        }
        Ok(SourceObject { kind, payload })
    }

    fn open_loose(&self, oid: Oid, dir: usize) -> Result<LooseOpen, GitError> {
        let root = self
            .loose_dirs
            .get(dir)
            .ok_or_else(|| corrupt(format!("object directory {dir} for {oid} is not open")))?;
        let path = loose_path(root, oid);
        let file = File::open(&path).map_err(|err| io_error("cannot open", &path, &err))?;
        let mut decoder = ZlibDecoder::new(BufReader::new(file));
        let mut header = Vec::with_capacity(MAX_LOOSE_HEADER);
        loop {
            let mut byte = [0_u8; 1];
            let read = decoder
                .read(&mut byte)
                .map_err(|err| corrupt(format!("loose object {oid}: {err}")))?;
            if read == 0 {
                return Err(corrupt(format!("loose object {oid}: truncated header")));
            }
            header.push(byte[0]);
            if byte[0] == 0 {
                break;
            }
            if header.len() >= MAX_LOOSE_HEADER {
                return Err(corrupt(format!("loose object {oid}: header too long")));
            }
        }
        let (kind, size, consumed) = gix_object::decode::loose_header(&header)
            .map_err(|err| corrupt(format!("loose object {oid}: {err}")))?;
        if consumed != header.len() {
            return Err(corrupt(format!("loose object {oid}: malformed header")));
        }
        if size > self.max_object_bytes {
            return Err(GitError::Limit {
                detail: format!("object {oid} exceeds {} bytes", self.max_object_bytes),
            });
        }
        let kind = object_kind(kind);
        if kind == ObjectKind::Blob && size > STREAM_THRESHOLD {
            return Ok(LooseOpen::Stream(LooseStream { size, decoder }));
        }
        let mut payload = Vec::new();
        read_exact_payload(&mut decoder, size, &mut payload)
            .map_err(|err| corrupt(format!("loose object {oid}: {err}")))?;
        ensure_eof(&mut decoder, oid)?;
        Ok(LooseOpen::Memory(SourceObject { kind, payload }))
    }
}

#[derive(Debug)]
enum LooseOpen {
    Memory(SourceObject),
    Stream(LooseStream),
}

impl LooseStream {
    /// Decoded payload length declared by the loose header.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Stages the blob into `store` in one streaming pass and verifies the
    /// OID the store derived from the exact bytes against `oid`.
    ///
    /// # Errors
    /// [`GitError::Corrupt`] for a zlib error, a length that disagrees with
    /// the header, trailing data, or an OID mismatch; store admission
    /// failures as their own codes.
    pub fn stage(mut self, store: &Store, oid: Oid) -> Result<PreparedObject, GitError> {
        let mut tap = ErrorTap {
            inner: (&mut self.decoder).take(self.size),
            error: None,
        };
        let prepared = store.prepare(ObjectKind::Blob, self.size, &mut tap, None);
        if let Some(detail) = tap.error {
            return Err(corrupt(format!("loose object {oid}: {detail}")));
        }
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(StoreError::Invalid(detail)) => {
                return Err(corrupt(format!("loose object {oid}: {detail}")));
            }
            Err(err) => return Err(err.into()),
        };
        ensure_eof(&mut self.decoder, oid)?;
        if prepared.oid() != oid {
            return Err(corrupt(format!(
                "object {oid} hashes to {}",
                prepared.oid()
            )));
        }
        Ok(prepared)
    }
}

/// Remembers the first source read error so it is reported as source
/// corruption rather than as the store's length complaint.
#[derive(Debug)]
struct ErrorTap<R> {
    inner: R,
    error: Option<String>,
}

impl<R: Read> Read for ErrorTap<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf).inspect_err(|err| {
            if self.error.is_none() {
                self.error = Some(err.to_string());
            }
        })
    }
}

fn read_exact_payload(reader: &mut impl Read, size: u64, out: &mut Vec<u8>) -> io::Result<()> {
    let expected = usize::try_from(size)
        .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "object too large"))?;
    out.clear();
    out.try_reserve_exact(expected)
        .map_err(|err| io::Error::new(io::ErrorKind::OutOfMemory, err))?;
    reader.take(size).read_to_end(out)?;
    if out.len() != expected {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("payload has {} of {expected} declared bytes", out.len()),
        ));
    }
    Ok(())
}

fn ensure_eof(reader: &mut impl Read, oid: Oid) -> Result<(), GitError> {
    let mut extra = [0_u8; 1];
    match reader.read(&mut extra) {
        Ok(0) => Ok(()),
        Ok(_) => Err(corrupt(format!(
            "loose object {oid}: data after the declared payload"
        ))),
        Err(err) => Err(corrupt(format!("loose object {oid}: {err}"))),
    }
}

/// Re-hashes an in-memory object and requires its identity to be `oid`.
pub(crate) fn verify(oid: Oid, object: &SourceObject, kind: HashKind) -> Result<(), GitError> {
    let actual = kind
        .hash_git_object(header_name(object.kind)?, &object.payload)
        .map_err(|err| corrupt(format!("object {oid}: {err}")))?;
    if actual == oid {
        Ok(())
    } else {
        Err(corrupt(format!("object {oid} hashes to {actual}")))
    }
}

fn loose_path(root: &Path, oid: Oid) -> PathBuf {
    let hex = oid.to_hex();
    root.join(&hex[..2]).join(&hex[2..])
}

/// Collects `objects` and its alternates depth-first, skipping a directory
/// already visited (Git does the same for duplicate alternates).
fn collect_object_dirs(
    dir: &Path,
    depth: usize,
    out: &mut Vec<PathBuf>,
    visited: &mut HashSet<PathBuf>,
) -> Result<(), GitError> {
    let canonical = fs::canonicalize(dir).map_err(|err| GitError::Invalid {
        detail: format!("object directory {}: {err}", dir.display()),
    })?;
    if !visited.insert(canonical.clone()) {
        return Ok(());
    }
    out.push(canonical.clone());
    let Some(text) = read_small(&canonical.join("info").join("alternates"))? else {
        return Ok(());
    };
    for raw in text.split(|&byte| byte == b'\n') {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        if line.starts_with(b"\"") {
            return Err(GitError::Invalid {
                detail: format!(
                    "quoted alternate path in {} is not supported",
                    canonical.display()
                ),
            });
        }
        if depth + 1 > MAX_ALTERNATE_DEPTH {
            return Err(GitError::Limit {
                detail: format!(
                    "alternates of {} nest deeper than {MAX_ALTERNATE_DEPTH}",
                    canonical.display()
                ),
            });
        }
        let text = std::str::from_utf8(line).map_err(|_| GitError::Invalid {
            detail: format!("non-UTF-8 alternate path in {}", canonical.display()),
        })?;
        let alternate = canonical.join(text);
        collect_object_dirs(&alternate, depth + 1, out, visited)?;
    }
    Ok(())
}

/// The `*.idx` files of a pack directory in name order.
fn pack_indexes(dir: &Path) -> Result<Vec<PathBuf>, GitError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(io_error("cannot list", dir, &err)),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| io_error("cannot list", dir, &err))?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "idx") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}
