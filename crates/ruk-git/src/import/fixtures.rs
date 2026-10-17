//! Programmatic source-repo fixtures: loose objects, hand-written packs,
//! refs, and config built with flate2 and [`gix_hash`], never the git CLI.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::store::Store;

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// A scratch source repository plus its store, cleaned up on drop.
pub(crate) struct Fixture {
    pub(crate) dir: PathBuf,
    pub(crate) git_dir: PathBuf,
    pub(crate) hash: HashKind,
    store_dir: PathBuf,
}

impl Fixture {
    pub(crate) fn sha1() -> Self {
        Self::new(HashKind::Sha1)
    }

    pub(crate) fn new(hash: HashKind) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "ruk-git-import-{}-{id}",
            std::process::id()
        ));
        let git_dir = dir.join("src.git");
        fs::create_dir_all(git_dir.join("objects").join("pack")).expect("fixture dirs");
        fs::create_dir_all(git_dir.join("refs").join("heads")).expect("fixture refs");
        fs::create_dir_all(git_dir.join("refs").join("tags")).expect("fixture tags");
        let store_dir = dir.join("store");
        Self {
            dir,
            git_dir,
            hash,
            store_dir,
        }
    }

    pub(crate) fn store(&self) -> Store {
        Store::create(
            &self.store_dir,
            self.hash,
            Arc::new(ruk_core::PreparationBudget::default()),
        )
        .expect("fixture store")
    }

    pub(crate) fn oid(&self, kind: &str, payload: &[u8]) -> Oid {
        self.hash.hash_git_object(kind, payload).expect("fixture hash")
    }

    /// Writes one loose object; returns its OID.
    pub(crate) fn loose(&self, kind: &str, payload: &[u8]) -> Oid {
        let oid = self.oid(kind, payload);
        let hex = oid.to_hex();
        let dir = self.git_dir.join("objects").join(&hex[..2]);
        fs::create_dir_all(&dir).expect("loose dir");
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        write!(encoder, "{kind} {}\0", payload.len()).expect("header");
        encoder.write_all(payload).expect("payload");
        let bytes = encoder.finish().expect("deflate");
        fs::write(dir.join(&hex[2..]), bytes).expect("loose object");
        oid
    }

    /// Writes raw (possibly corrupt) loose bytes at the loose path of `oid`.
    pub(crate) fn loose_raw(&self, oid: Oid, bytes: &[u8]) {
        let hex = oid.to_hex();
        let dir = self.git_dir.join("objects").join(&hex[..2]);
        fs::create_dir_all(&dir).expect("loose dir");
        fs::write(dir.join(&hex[2..]), bytes).expect("raw loose");
    }

    pub(crate) fn blob(&self, content: &[u8]) -> Oid {
        self.loose("blob", content)
    }

    /// Builds a binary tree payload from `(is_tree, name, oid)` entries,
    /// sorted in Git order.
    pub(crate) fn tree_payload(entries: &[(bool, &[u8], Oid)]) -> Vec<u8> {
        let mut sorted: Vec<_> = entries.to_vec();
        sorted.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
        let mut payload = Vec::new();
        for (is_tree, name, oid) in &sorted {
            let mode = if *is_tree { "40000" } else { "100644" };
            payload.extend_from_slice(mode.as_bytes());
            payload.push(b' ');
            payload.extend_from_slice(name);
            payload.push(0x00);
            payload.extend_from_slice(oid.as_bytes());
        }
        payload
    }

    /// Builds a binary tree payload and writes it loose.
    pub(crate) fn tree(&self, entries: &[(bool, &[u8], Oid)]) -> (Vec<u8>, Oid) {
        let payload = Self::tree_payload(entries);
        let oid = self.loose("tree", &payload);
        (payload, oid)
    }

    pub(crate) fn commit_payload(
        tree: Oid,
        parents: &[Oid],
        extra: &[u8],
        message: &[u8],
    ) -> Vec<u8> {
        let mut payload = format!("tree {}\n", tree.to_hex()).into_bytes();
        for parent in parents {
            payload.extend_from_slice(format!("parent {}\n", parent.to_hex()).as_bytes());
        }
        payload.extend_from_slice(b"author Fixture <fixture@example.com> 1700000000 +0000\n");
        payload.extend_from_slice(
            b"committer Fixture <fixture@example.com> 1700000000 +0000\n",
        );
        payload.extend_from_slice(extra);
        payload.push(b'\n');
        payload.extend_from_slice(message);
        payload
    }

    pub(crate) fn commit(
        &self,
        tree: Oid,
        parents: &[Oid],
        extra: &[u8],
        message: &[u8],
    ) -> (Vec<u8>, Oid) {
        let payload = Self::commit_payload(tree, parents, extra, message);
        let oid = self.loose("commit", &payload);
        (payload, oid)
    }

    pub(crate) fn tag_payload(target: Oid, kind: &str, name: &[u8]) -> Vec<u8> {
        format!(
            "object {}\ntype {kind}\ntag {}\ntagger Fixture <fixture@example.com> 1700000000 +0000\n\nannotated\n",
            target.to_hex(),
            String::from_utf8_lossy(name)
        )
        .into_bytes()
    }

    pub(crate) fn tag(&self, target: Oid, kind: &str, name: &[u8]) -> (Vec<u8>, Oid) {
        let payload = Self::tag_payload(target, kind, name);
        let oid = self.loose("tag", &payload);
        (payload, oid)
    }

    pub(crate) fn write_ref(&self, name: &str, oid: Oid) {
        let path = self.git_dir.join(name);
        fs::create_dir_all(path.parent().expect("ref parent")).expect("ref dirs");
        fs::write(path, format!("{}\n", oid.to_hex())).expect("ref");
    }

    pub(crate) fn write_packed_refs(&self, lines: &[String]) {
        let mut text = String::from("# pack-refs with: peeled fully-peeled sorted \n");
        for line in lines {
            text.push_str(line);
            text.push('\n');
        }
        fs::write(self.git_dir.join("packed-refs"), text).expect("packed-refs");
    }

    pub(crate) fn write_head(&self, text: &str) {
        fs::write(self.git_dir.join("HEAD"), text).expect("HEAD");
    }

    pub(crate) fn write_config(&self, text: &str) {
        fs::write(self.git_dir.join("config"), text).expect("config");
    }

    pub(crate) fn write_shallow(&self, oids: &[Oid]) {
        let mut text = String::new();
        for oid in oids {
            text.push_str(&oid.to_hex());
            text.push('\n');
        }
        fs::write(self.git_dir.join("shallow"), text).expect("shallow");
    }

    /// Writes `objects` as one pack (`pack-*.pack` + `.idx` in `format`)
    /// and returns the OIDs in input order.
    pub(crate) fn pack(&self, objects: &[PackObject], format: IndexFormat) -> Vec<Oid> {
        let version = if self.hash == HashKind::Sha256 { 3 } else { 2 };
        let mut pack = b"PACK".to_vec();
        pack.extend_from_slice(&(version as u32).to_be_bytes());
        pack.extend_from_slice(&(objects.len() as u32).to_be_bytes());
        let mut oids = Vec::with_capacity(objects.len());
        let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(objects.len());
        let mut metas: Vec<PackMeta> = Vec::new();
        for object in objects {
            let oid = self.oid(object.kind_name(), &object.payload);
            oids.push(oid);
            payloads.push(object.payload.clone());
            let start = pack.len();
            match &object.body {
                PackBody::Full => {
                    pack.extend_from_slice(&entry_header(object.kind, object.payload.len()));
                    pack.extend_from_slice(&deflate(&object.payload));
                }
                PackBody::OfsDelta { base } => {
                    let position = metas
                        .iter()
                        .position(|meta| meta.oid == *base)
                        .expect("delta base precedes");
                    let distance = pack.len() as u64 - metas[position].offset;
                    let delta = encode_delta(&payloads[position], &object.payload);
                    pack.extend_from_slice(&entry_header(6, delta.len()));
                    append_ofs_offset(&mut pack, distance);
                    pack.extend_from_slice(&deflate(&delta));
                }
            }
            metas.push(PackMeta {
                oid,
                offset: start as u64,
                crc: crc32(&pack[start..]),
            });
        }
        let trailer_len = self.hash.oid_len();
        let mut hasher = gix_hash::hasher(self.hash.gix());
        hasher.update(&pack);
        let checksum = hasher.try_finalize().expect("checksum");
        let pack_checksum = checksum.as_slice()[..trailer_len].to_vec();
        pack.extend_from_slice(&pack_checksum);
        let stem = format!("pack-{:05}", NEXT_ID.fetch_add(1, Ordering::SeqCst) % 100000);
        let dir = self.git_dir.join("objects").join("pack");
        fs::write(dir.join(format!("{stem}.pack")), &pack).expect("pack file");
        let index = match format {
            IndexFormat::V1 => encode_idx_v1(&metas, self.hash, &pack_checksum),
            IndexFormat::V2 => encode_idx_v2(&metas, self.hash, &pack_checksum),
        };
        fs::write(dir.join(format!("{stem}.idx")), &index).expect("idx file");
        oids
    }

    pub(crate) fn request<'a>(
        &'a self,
        operation: u64,
        source: &'a [u8],
    ) -> crate::import::ImportRequest<'a> {
        use ruk_core::conflict::Signature;
        use ruk_core::conflict::TzOffset;
        crate::import::ImportRequest {
            git_dir: &self.git_dir,
            observation_source: source,
            operation: ruk_core::change::OperationId(operation),
            committer: Signature {
                name: "import".into(),
                email: "import@example.com".into(),
                timestamp: 1_700_000_000,
                offset: TzOffset::new(false, 0).expect("offset"),
            },
            message: "import".into(),
            limits: crate::import::ImportLimits::default(),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn sort_key(entry: &(bool, &[u8], Oid)) -> Vec<u8> {
    let mut key = entry.1.to_vec();
    if entry.0 {
        key.push(b'/');
    }
    key
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexFormat {
    V1,
    V2,
}

/// One pack member: `kind_name` is `blob`/`tree`/`commit`/`tag`.
pub(crate) struct PackObject {
    pub(crate) kind: u8,
    pub(crate) payload: Vec<u8>,
    pub(crate) body: PackBody,
}

pub(crate) enum PackBody {
    Full,
    OfsDelta { base: Oid },
}

impl PackObject {
    pub(crate) fn full(kind: u8, payload: Vec<u8>) -> Self {
        Self {
            kind,
            payload,
            body: PackBody::Full,
        }
    }

    pub(crate) fn kind_name(&self) -> &'static str {
        match self.kind {
            1 => "commit",
            2 => "tree",
            3 => "blob",
            4 => "tag",
            _ => unreachable!("fixture kind"),
        }
    }

}

struct PackMeta {
    oid: Oid,
    offset: u64,
    crc: u32,
}

/// A pack type-and-size header: 3 type bits and 4 size bits, then 7-bit
/// size continuations with the MSB set on every byte but the last.
fn entry_header(git_type: u8, mut size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut byte = (git_type << 4) | ((size & 0x0f) as u8);
    size >>= 4;
    if size != 0 {
        byte |= 0x80;
    }
    out.push(byte);
    while size != 0 {
        byte = (size & 0x7f) as u8;
        size >>= 7;
        if size != 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }
    out
}

fn deflate(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).expect("deflate");
    encoder.finish().expect("finish")
}

/// Minimal delta: base/result sizes then literal inserts of the result.
fn encode_delta(_base: &[u8], result: &[u8]) -> Vec<u8> {
    fn varint(mut value: usize, out: &mut Vec<u8>) {
        let mut bytes = [0_u8; 16];
        let mut len = 0;
        bytes[0] = (value & 0x7f) as u8;
        value >>= 7;
        while value != 0 {
            len += 1;
            bytes[len] = ((value & 0x7f) as u8) | 0x80;
            value >>= 7;
        }
        while len > 0 {
            out.push(bytes[len]);
            len -= 1;
        }
        out.push(bytes[0]);
    }
    let mut delta = Vec::new();
    varint(_base.len(), &mut delta);
    varint(result.len(), &mut delta);
    for chunk in result.chunks(100) {
        delta.push(chunk.len() as u8);
        delta.extend_from_slice(chunk);
    }
    delta
}

/// Git's OFS_DELTA distance encoding: 7-bit groups, most significant
/// first, every byte but the last carrying the MSB, with the biased
/// continuation the pack decoder inverts.
fn append_ofs_offset(out: &mut Vec<u8>, distance: u64) {
    let mut groups = vec![(distance & 0x7f) as u8];
    let mut value = distance >> 7;
    while value != 0 {
        value -= 1;
        groups.push((value & 0x7f) as u8);
        value >>= 7;
    }
    let groups: Vec<u8> = groups.into_iter().rev().collect();
    let count = groups.len();
    for (index, group) in groups.into_iter().enumerate() {
        out.push(if index + 1 == count { group } else { group | 0x80 });
    }
}

fn encode_idx_v2(metas: &[PackMeta], hash: HashKind, pack_checksum: &[u8]) -> Vec<u8> {
    let mut sorted: Vec<&PackMeta> = metas.iter().collect();
    sorted.sort_by(|a, b| a.oid.as_bytes().cmp(b.oid.as_bytes()));
    let mut fanout = [0_u32; 256];
    for meta in &sorted {
        fanout[meta.oid.as_bytes()[0] as usize] += 1;
    }
    let mut running = 0_u32;
    for slot in fanout.iter_mut() {
        running += *slot;
        *slot = running;
    }
    let mut index = b"\xfftOc\0\0\0\x02".to_vec();
    for slot in fanout {
        index.extend_from_slice(&slot.to_be_bytes());
    }
    for meta in &sorted {
        index.extend_from_slice(meta.oid.as_bytes());
    }
    for meta in &sorted {
        index.extend_from_slice(&meta.crc.to_be_bytes());
    }
    for meta in &sorted {
        index.extend_from_slice(&(meta.offset as u32).to_be_bytes());
    }
    let pack_len = hash.oid_len();
    index.extend_from_slice(pack_checksum);
    debug_assert_eq!(pack_checksum.len(), pack_len);
    let mut hasher = gix_hash::hasher(hash.gix());
    hasher.update(&index);
    let checksum = hasher.try_finalize().expect("checksum");
    index.extend_from_slice(&checksum.as_slice()[..pack_len]);
    index
}

fn encode_idx_v1(metas: &[PackMeta], hash: HashKind, pack_checksum: &[u8]) -> Vec<u8> {
    let mut sorted: Vec<&PackMeta> = metas.iter().collect();
    sorted.sort_by(|a, b| a.oid.as_bytes().cmp(b.oid.as_bytes()));
    let mut fanout = [0_u32; 256];
    for meta in &sorted {
        fanout[meta.oid.as_bytes()[0] as usize] += 1;
    }
    let mut running = 0_u32;
    for slot in fanout.iter_mut() {
        running += *slot;
        *slot = running;
    }
    let mut index = Vec::new();
    for slot in fanout {
        index.extend_from_slice(&slot.to_be_bytes());
    }
    // V1 entries are sorted offset+oid pairs, one per object; there are
    // no CRCs (that table is V2-only).
    for meta in &sorted {
        index.extend_from_slice(&(meta.offset as u32).to_be_bytes());
        index.extend_from_slice(meta.oid.as_bytes());
    }
    let pack_len = hash.oid_len();
    index.extend_from_slice(pack_checksum);
    debug_assert_eq!(pack_checksum.len(), pack_len);
    let mut hasher = gix_hash::hasher(hash.gix());
    hasher.update(&index);
    let checksum = hasher.try_finalize().expect("checksum");
    index.extend_from_slice(&checksum.as_slice()[..pack_len]);
    index
}

/// Bitwise IEEE CRC-32; fixtures are tiny so speed does not matter.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Reads one stored object fully.
pub(crate) fn read_object(store: &Store, oid: Oid) -> (ruk_core::store::ObjectKind, Vec<u8>) {
    use std::io::Read as _;
    let object = store.read(oid).expect("stored object");
    let mut bytes = Vec::new();
    let mut spool = object.bytes;
    spool.read_to_end(&mut bytes).expect("spool");
    (object.kind, bytes)
}

pub(crate) fn observation(
    store: &Store,
    source: &[u8],
    name: &str,
) -> Option<ruk_core::refdata::RefTarget> {
    use ruk_core::refdata::RefName;
    let name = RefName::new(name.as_bytes().to_vec()).expect("name");
    let key = crate::import::refs::observation_key(source, &name);
    let bytes = store
        .fact(ruk_core::store::FactTable::RemoteObservations, &key)
        .expect("fact")?;
    Some(
        crate::import::refs::decode_observation(&bytes, store.hash_kind()).expect("decode"),
    )
}
