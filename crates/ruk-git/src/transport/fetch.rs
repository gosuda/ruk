//! Fetch negotiation, closure verification, tracking merge and prefetch.
//!
//! The wire core is [`receive`]: read the advertisement, send wants with
//! the caller's haves, accept the pack, verify its closure, and return the
//! staging. Protocol v0/v1 speaks `want/have/done`; v2 speaks
//! `command=fetch` with sections. Both accept full and thin packs.
//!
//! What lands in the store, and when:
//!
//! 1. Objects stage invisibly through [`StagedPack`].
//! 2. [`verify_closure`] walks every wanted tip over staged plus committed
//!    objects. Committed objects are not descended: their closures were
//!    verified when published. Missing blobs under an active filter become
//!    promisor rows; missing parents past a shallow boundary are design,
//!    not damage; anything else is [`GitError::Corrupt`].
//! 3. [`publish_fetch`] publishes staged objects together with the
//!    caller-supplied fact mutations (ref deltas prepared by the lane that
//!    owns ref CAS, observations, promisor and shallow rows) in one
//!    [`Store::publish`].
//!
//! Native tracking merge is the pure [`plan_tracking`]: three-way
//! local/last-observed/new. Unresolved cases stay as data for the caller to
//! record through `refs::prepare_set_ref_conflict`; this module never
//! invents a merged ref value.
//!
//! [`prefetch`] completes promisor-missing closures in bounded batches of
//! [`PREFETCH_BATCH`] OIDs over a [`Reconnectable`], continuing under
//! deadline/cancellation with no cap on the batch count.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};

use ruk_core::ids::{HashKind, Oid};
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTarget, RefUpdate};
use ruk_core::store::types::ObjectKind;
use ruk_core::store::{FactMutation, Store};

use super::pack::{IngestLimits, Links, StagedPack, ingest_pack, object_links};
use super::pktline::{self, PktReader, RemoteMessages, SidebandReader, send};
use super::private::PrivateFilter;
use super::refadv::{self, Advertisement, Capabilities, Initial};
use super::session::Duplex;
use super::{
    Interrupt, PromisorRow, has_object, promisor_clear, promisor_mutation, promisor_row,
    read_object, shallow_insert, shallow_remove,
};
use crate::GitError;

/// OIDs requested per prefetch connection.
pub const PREFETCH_BATCH: usize = 1000;
/// Largest object pulled through a closure walk.
const WALK_OBJECT_BYTES: u64 = 512 << 20;

/// A partial-clone filter the client asks the server to apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filter {
    /// Omit all blobs; missing blobs become promisor rows.
    BlobNone,
}

impl Filter {
    /// The wire spec.
    #[must_use]
    pub fn spec(self) -> &'static str {
        match self {
            Self::BlobNone => "blob:none",
        }
    }

    /// Whether `kind` may be omitted under this filter.
    #[must_use]
    pub fn omits(self, kind: ObjectKind) -> bool {
        match self {
            Self::BlobNone => kind == ObjectKind::Blob,
        }
    }
}

/// What to fetch over one connection.
#[derive(Clone, Debug)]
pub struct FetchWireRequest {
    /// Advertised tips to download.
    pub wants: Vec<Oid>,
    /// Authorized local tips to offer as haves (private closures never
    /// enter this list; the caller owns authorization).
    pub haves: Vec<Oid>,
    /// Partial-clone filter, native default `blob:none`.
    pub filter: Option<Filter>,
    /// Shallow depth (`deepen`); `None` is a complete fetch.
    pub depth: Option<u32>,
    /// Known local shallow boundaries to report to the server.
    pub shallow: Vec<Oid>,
    /// Whether to run `ls-refs` first and return ref names (v2 only).
    pub list_refs: bool,
    /// Ref prefixes for `ls-refs`.
    pub ref_prefixes: Vec<Vec<u8>>,
}

impl FetchWireRequest {
    /// A complete native fetch: blob-less by default.
    #[must_use]
    pub fn native(wants: Vec<Oid>, haves: Vec<Oid>) -> Self {
        Self {
            wants,
            haves,
            filter: Some(Filter::BlobNone),
            depth: None,
            shallow: Vec::new(),
            list_refs: false,
            ref_prefixes: Vec::new(),
        }
    }
}

/// What one wire exchange produced.
#[derive(Debug)]
pub struct ReceivedPack {
    /// Staged objects, invisible until published.
    pub staged: StagedPack,
    /// Server-declared shallow boundaries (`shallow` lines).
    pub shallow: Vec<Oid>,
    /// Boundaries the server lifted (`unshallow` lines).
    pub unshallow: Vec<Oid>,
    /// Filter or depth the server could not honor, applied as warnings.
    pub warnings: Vec<String>,
    /// Progress text gathered from side-band 2.
    pub progress: RemoteMessages,
    /// Ref rows from v2 `ls-refs`, when requested.
    pub refs: Vec<refadv::AdvertisedRef>,
}

/// Receives one pack over `stream`: reads the advertisement, negotiates,
/// ingests and returns the staging without publishing anything.
///
/// # Errors
/// Grammar failures are [`GitError::Corrupt`]; see [`ingest_pack`] for
/// pack errors and [`verify_closure`] for the verification that must
/// follow before publication.
pub fn receive<R: Read + Write>(
    stream: R,
    kind: HashKind,
    store: &Store,
    req: &FetchWireRequest,
    limits: IngestLimits,
    interrupt: &Interrupt,
) -> Result<ReceivedPack, GitError> {
    if req.wants.is_empty() {
        return Err(GitError::Invalid {
            detail: "fetch needs at least one want".to_owned(),
        });
    }
    let mut pkt = PktReader::new(stream, interrupt.clone());
    match refadv::read_initial(&mut pkt, kind)? {
        Initial::Refs(adv) => receive_v0(&mut pkt, adv, kind, store, req, limits, interrupt),
        Initial::V2(caps) => receive_v2(&mut pkt, caps, kind, store, req, limits, interrupt),
    }
}

fn server_sideband(caps: &Capabilities) -> Option<usize> {
    if caps.has("side-band-64k") {
        Some(super::pktline::LARGE_PACKET_MAX)
    } else if caps.has("side-band") {
        Some(super::pktline::SMALL_SIDEBAND_MAX)
    } else {
        None
    }
}

fn receive_v0<R: Read + Write>(
    pkt: &mut PktReader<R>,
    adv: Advertisement,
    kind: HashKind,
    store: &Store,
    req: &FetchWireRequest,
    limits: IngestLimits,
    interrupt: &Interrupt,
) -> Result<ReceivedPack, GitError> {
    let caps = &adv.capabilities;
    let mut warnings = Vec::new();
    let filter = match req.filter {
        Some(filter) if caps.has("filter") => Some(filter),
        Some(filter) => {
            warnings.push(format!(
                "server lacks filter; fetched full objects instead of {}",
                filter.spec()
            ));
            None
        }
        None => None,
    };
    let depth = match req.depth {
        Some(depth) if caps.has("shallow") => Some(depth),
        Some(_) => {
            warnings.push("server lacks shallow; fetched complete history".to_owned());
            None
        }
        None => None,
    };
    let mut out = Vec::new();
    let mut caps_list = vec!["multi_ack_detailed", "thin-pack", "ofs-delta"];
    if server_sideband(caps).is_some() {
        caps_list.push(if caps.has("side-band-64k") {
            "side-band-64k"
        } else {
            "side-band"
        });
    }
    if filter.is_some() {
        caps_list.push("filter");
    }
    if caps.has("object-format") {
        caps_list.push(match kind {
            HashKind::Sha1 => "object-format=sha1",
            HashKind::Sha256 => "object-format=sha256",
        });
    }
    caps_list.push("agent=ruk");
    for (index, want) in req.wants.iter().enumerate() {
        let mut line = format!("want {want}");
        if index == 0 {
            line.push(' ');
            line.push_str(&caps_list.join(" "));
        }
        line.push('\n');
        pktline::encode_data(&mut out, line.as_bytes())?;
    }
    for oid in &req.shallow {
        pktline::encode_data(&mut out, format!("shallow {oid}\n").as_bytes())?;
    }
    if let Some(depth) = depth {
        pktline::encode_data(&mut out, format!("deepen {depth}\n").as_bytes())?;
    }
    if let Some(filter) = filter {
        pktline::encode_data(&mut out, format!("filter {}\n", filter.spec()).as_bytes())?;
    }
    pktline::encode_flush(&mut out);
    send(pkt.get_mut(), &out)?;
    // One have-round: all haves, then a flush that ends the round. The
    // server always answers a have-round (NAK at minimum), so this read
    // cannot deadlock. ACK section bytes are bounded by the one control
    // bound. `done` terminates the request with no trailing flush.
    let multi_ack = caps.has("multi_ack") || caps.has("multi_ack_detailed");
    let mut out = Vec::new();
    for oid in &req.haves {
        pktline::encode_data(&mut out, format!("have {oid}\n").as_bytes())?;
    }
    pktline::encode_flush(&mut out);
    send(pkt.get_mut(), &out)?;
    let mut shallow = Vec::new();
    let mut unshallow = Vec::new();
    let mut ack_bytes = 0usize;
    let mut common = false;
    loop {
        interrupt.check("negotiating the fetch")?;
        let line = pkt.read_line("an acknowledgement")?.to_vec();
        ack_bytes += line.len();
        if ack_bytes > ruk_core::MAX_CONTROL_FRAME_BYTES {
            return Err(GitError::Limit {
                detail: "fetch negotiation exceeds the control bound".to_owned(),
            });
        }
        if let Some(rest) = line.strip_prefix(b"shallow ") {
            shallow.push(super::proto_v2::parse_server_oid(rest, kind)?);
        } else if let Some(rest) = line.strip_prefix(b"unshallow ") {
            unshallow.push(super::proto_v2::parse_server_oid(rest, kind)?);
        } else if is_nak(&line) {
            break;
        } else if line.starts_with(b"ACK ") {
            // Any ACK names common history. A "common" verdict is
            // followed by "ready" (or more verdicts), never by the pack:
            // only NAK, "ready", or a bare ACK ends the round. Breaking
            // on "common" would leave "ready" in the stream and corrupt
            // the post-done exchange.
            common = true;
            if !line.ends_with(b"common") {
                break;
            }
        } else {
            return Err(GitError::Corrupt {
                detail: format!("unexpected acknowledgement {}", line.escape_ascii()),
            });
        }
    }
    let mut done = Vec::new();
    pktline::encode_data(&mut done, b"done\n")?;
    send(pkt.get_mut(), &done)?;
    if multi_ack {
        // Verified against stock git-upload-pack: after done the server
        // sends NAK, then ACK when a common base exists, then the pack.
        // Without multi_ack the pack follows done directly.
        let line = pkt.read_line("the post-done verdict")?;
        if !is_nak(line) {
            return Err(GitError::Corrupt {
                detail: format!("expected NAK after done, got {}", line.escape_ascii()),
            });
        }
        if common {
            let line = pkt.read_line("the post-done acknowledgement")?.to_vec();
            if !line.starts_with(b"ACK ") {
                return Err(GitError::Corrupt {
                    detail: format!("expected ACK after done, got {}", line.escape_ascii()),
                });
            }
        }
    }
    let max_frame = server_sideband(caps);
    let (staged, progress) = read_pack_section(pkt, max_frame, kind, store, limits, interrupt)?;
    Ok(ReceivedPack {
        staged,
        shallow,
        unshallow,
        warnings,
        progress,
        refs: Vec::new(),
    })
}

/// Exact equality with `NAK` without relying on cross-type `==` impls.
fn is_nak(line: &[u8]) -> bool {
    line.len() == 3 && line.starts_with(b"NAK")
}

fn receive_v2<R: Read + Write>(
    pkt: &mut PktReader<R>,
    caps: Capabilities,
    kind: HashKind,
    store: &Store,
    req: &FetchWireRequest,
    limits: IngestLimits,
    interrupt: &Interrupt,
) -> Result<ReceivedPack, GitError> {
    let mut refs = Vec::new();
    if req.list_refs {
        let request = refadv::ls_refs_request(
            &caps,
            kind,
            &req.ref_prefixes
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>(),
        )?;
        send(pkt.get_mut(), &request)?;
        refs = refadv::read_ls_refs(pkt, kind)?;
    }
    let mut warnings = Vec::new();
    let filter = match req.filter {
        Some(filter) if caps.feature("fetch", "filter") => Some(filter),
        Some(filter) => {
            warnings.push(format!(
                "server lacks filter; fetched full objects instead of {}",
                filter.spec()
            ));
            None
        }
        None => None,
    };
    let depth = match req.depth {
        Some(depth) if caps.feature("fetch", "shallow") => Some(depth),
        Some(_) => {
            warnings.push("server lacks shallow; fetched complete history".to_owned());
            None
        }
        None => None,
    };
    let cmd = super::proto_v2::FetchCommand {
        wants: &req.wants,
        haves: &req.haves,
        shallows: &req.shallow,
        depth,
        filter,
        thin_pack: false,
        ofs_delta: false,
        sideband_all: caps.feature("fetch", "sideband-all"),
    };
    let out = super::proto_v2::fetch_request(&caps, kind, &cmd)?;
    send(pkt.get_mut(), &out)?;
    let sections = super::proto_v2::read_fetch_response(pkt, kind, store, limits, interrupt)?;
    Ok(ReceivedPack {
        staged: sections.staged,
        shallow: sections.shallow,
        unshallow: sections.unshallow,
        warnings,
        progress: sections.progress,
        refs,
    })
}

/// Reads one pack after negotiation: side-band demultiplexed when the
/// server negotiated it, raw otherwise (raw packs end at the trailer and
/// the connection is not reused).
///
/// Shared with the smart-http fetch half, whose POST response carries the
/// same post-negotiation bytes as the stateful stream.
pub(crate) fn read_pack_section<R: Read>(
    pkt: &mut PktReader<R>,
    sideband: Option<usize>,
    kind: HashKind,
    store: &Store,
    limits: IngestLimits,
    interrupt: &Interrupt,
) -> Result<(StagedPack, RemoteMessages), GitError> {
    match sideband {
        Some(max_frame) => {
            let mut band = SidebandReader::new(pkt, max_frame);
            let staged = ingest_pack(&mut band, kind, store, limits, interrupt)?;
            Ok((staged, band.drain_to_end()?))
        }
        None => Ok((
            ingest_pack(pkt.get_mut(), kind, store, limits, interrupt)?,
            RemoteMessages::default(),
        )),
    }
}

/// What closure verification found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosureReport {
    /// Wanted tips, all available.
    pub wanted: Vec<Oid>,
    /// Blobs omitted under the filter, to record as promisor rows.
    pub missing_promisor: Vec<Oid>,
}

/// Verifies the closure of `wanted` over staged plus committed objects.
///
/// Committed objects are not descended: their closures were verified at
/// publication time. Every wanted tip must be available. Missing blobs
/// under an active filter are reported for promisor rows; missing parents
/// past a shallow boundary (server-declared or locally recorded) are
/// design; any other missing link is [`GitError::Corrupt`].
///
/// # Errors
/// [`GitError::Corrupt`] for an incomplete pack and store failures.
pub fn verify_closure(
    store: &Store,
    staged: &StagedPack,
    wanted: &[Oid],
    filter: Option<Filter>,
    server_shallow: &[Oid],
    interrupt: &Interrupt,
) -> Result<ClosureReport, GitError> {
    let mut verifier = Verifier {
        store,
        staged,
        filter,
        shallow: server_shallow.iter().copied().collect(),
        present: HashMap::new(),
        missing_promisor: Vec::new(),
        missing_set: HashSet::new(),
        queue: VecDeque::new(),
        interrupt,
    };
    for want in wanted {
        verifier.interrupt.check("verifying the fetch closure")?;
        if !verifier.available(*want)? {
            return Err(GitError::Corrupt {
                detail: format!("fetch did not deliver the wanted object {want}"),
            });
        }
    }
    for oid in staged.oids() {
        let kind = staged
            .payload(*oid)
            .map(|(kind, _)| kind)
            .ok_or_else(|| GitError::Corrupt {
                detail: format!("staged object {oid} vanished"),
            })?;
        verifier.queue.push_back((*oid, kind));
    }
    verifier.drain()?;
    Ok(ClosureReport {
        wanted: wanted.to_vec(),
        missing_promisor: verifier.missing_promisor,
    })
}

/// Closure verification state: staged plus committed availability with one
/// cached probe per OID, promisor collection, and the walk queue.
struct Verifier<'a> {
    store: &'a Store,
    staged: &'a StagedPack,
    filter: Option<Filter>,
    shallow: HashSet<Oid>,
    present: HashMap<Oid, bool>,
    missing_promisor: Vec<Oid>,
    missing_set: HashSet<Oid>,
    queue: VecDeque<(Oid, ObjectKind)>,
    interrupt: &'a Interrupt,
}

impl Verifier<'_> {
    fn available(&mut self, oid: Oid) -> Result<bool, GitError> {
        if self.staged.contains(oid) {
            return Ok(true);
        }
        if let Some(hit) = self.present.get(&oid) {
            return Ok(*hit);
        }
        let present = has_object(self.store, oid)?;
        self.present.insert(oid, present);
        Ok(present)
    }

    fn bytes(&self, oid: Oid) -> Result<Vec<u8>, GitError> {
        if let Some((_, bytes)) = self.staged.payload(oid) {
            return Ok(bytes.to_vec());
        }
        read_object(self.store, oid, WALK_OBJECT_BYTES).map(|(_, bytes)| bytes)
    }

    fn drain(&mut self) -> Result<(), GitError> {
        let mut visited = HashSet::new();
        while let Some((oid, kind)) = self.queue.pop_front() {
            self.interrupt.check("verifying the fetch closure")?;
            if !visited.insert(oid) {
                continue;
            }
            let bytes = self.bytes(oid)?;
            let links = object_links(kind, &bytes, self.store.hash_kind())?;
            self.walk_links(&links, kind, oid)?;
        }
        Ok(())
    }

    fn walk_links(&mut self, links: &Links, kind: ObjectKind, oid: Oid) -> Result<(), GitError> {
        let mut need = Vec::new();
        if let Some(tree) = links.tree {
            need.push((tree, ObjectKind::Tree, false));
        }
        for parent in &links.parents {
            need.push((*parent, ObjectKind::Commit, true));
        }
        for (entry, entry_kind) in &links.entries {
            need.push((*entry, *entry_kind, false));
        }
        if let Some((target, target_kind)) = links.tag_target {
            need.push((target, target_kind, false));
        }
        for (link, link_kind, is_parent) in need {
            self.interrupt.check("verifying the fetch closure")?;
            if self.available(link)? {
                self.queue.push_back((link, link_kind));
                continue;
            }
            if is_parent && (self.shallow.contains(&oid) || super::is_shallow(self.store, oid)?) {
                continue;
            }
            if self.filter.is_some_and(|f| f.omits(link_kind)) && self.missing_set.insert(link) {
                self.missing_promisor.push(link);
                continue;
            }
            return Err(GitError::Corrupt {
                detail: format!("fetch pack omits {link_kind:?} {link} linked from {kind:?} {oid}"),
            });
        }
        Ok(())
    }
}

/// Collects haves while excluding a private closure.
///
/// Excluded roots are never entered, so private history stays private at
/// the cost of offering fewer haves. Every other excluded OID is skipped
/// without descending from it. Promised objects are always excluded.
///
/// # Errors
/// Store failures.
pub fn collect_haves_filtered(
    store: &Store,
    tips: &[Oid],
    max: usize,
    filter: &PrivateFilter,
    interrupt: &Interrupt,
) -> Result<Vec<Oid>, GitError> {
    let mut haves = Vec::new();
    let mut visited = HashSet::new();
    let mut queue: VecDeque<Oid> = filter.filter_haves(tips).into_iter().collect();
    while let Some(oid) = queue.pop_front() {
        interrupt.check("collecting haves")?;
        if !visited.insert(oid) || haves.len() >= max {
            continue;
        }
        if filter.contains(oid) || promisor_row(store, oid)?.is_some() {
            continue;
        }
        let bytes = match read_object(store, oid, WALK_OBJECT_BYTES) {
            Ok((ObjectKind::Commit, bytes)) => bytes,
            Ok(_) => continue,
            Err(GitError::NotFound { .. }) => continue,
            Err(err) => return Err(err),
        };
        haves.push(oid);
        let links = object_links(ObjectKind::Commit, &bytes, store.hash_kind())?;
        queue.extend(filtered_parents(filter, &links.parents));
    }
    Ok(haves)
}

/// Parents minus explicitly private OIDs, preserving discovery order.
fn filtered_parents(filter: &PrivateFilter, parents: &[Oid]) -> Vec<Oid> {
    parents
        .iter()
        .copied()
        .filter(|oid| !filter.contains(*oid))
        .collect()
}

/// Filters `haves` for the wire: private and promised OIDs never reach the
/// server's have-round or `ls-refs` negotiation.
///
/// # Errors
/// Store failures; a malformed promisor row is [`GitError::Corrupt`].
pub fn filter_haves_for_wire(
    store: &Store,
    haves: &[Oid],
    filter: &PrivateFilter,
) -> Result<Vec<Oid>, GitError> {
    filter.filter_haves_store(store, haves)
}

/// Builds promisor-row insertions for blobs the filter omitted.
pub fn promisor_facts(
    remote: &[u8],
    filter: Filter,
    missing: &[Oid],
) -> Result<Vec<FactMutation>, GitError> {
    missing
        .iter()
        .map(|oid| {
            promisor_mutation(
                *oid,
                &PromisorRow {
                    remote: remote.to_vec(),
                    filter: filter.spec().as_bytes().to_vec(),
                },
            )
        })
        .collect()
}

/// Builds promisor-row removals for objects a prefetch delivered.
#[must_use]
pub fn prefetch_clears(delivered: &[Oid]) -> Vec<FactMutation> {
    delivered.iter().map(|oid| promisor_clear(*oid)).collect()
}

/// Builds shallow-row insertions and `unshallow` removals.
#[must_use]
pub fn shallow_facts(shallow: &[Oid], unshallow: &[Oid]) -> Vec<FactMutation> {
    shallow
        .iter()
        .map(|oid| shallow_insert(*oid))
        .chain(unshallow.iter().map(|oid| shallow_remove(*oid)))
        .collect()
}

/// Builds remote-observation mutations for fetched refs.
#[must_use]
pub fn observation_mutations(source: &[u8], pairs: &[(RefName, RefTarget)]) -> Vec<FactMutation> {
    pairs
        .iter()
        .map(|(name, target)| FactMutation {
            table: ruk_core::store::types::FactTable::RemoteObservations,
            key: super::observation_key(source, name),
            expected: ruk_core::store::types::FactExpectation::Any,
            value: Some(super::encode_observation(target)),
        })
        .collect()
}

/// One natively tracked ref after the three-way merge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrackingDecision {
    /// Remote did not move (or matches local): optional observation-only
    /// update, no ref write.
    Unchanged,
    /// Local matches what was last observed: advance to `new_target`.
    Advance {
        /// The ref write for the lane to prepare with CAS.
        update: RefUpdate,
    },
    /// Both sides moved: keep local, the caller records the conflict terms.
    Conflict {
        /// Local OID, when the local target is direct.
        local: Option<Oid>,
        /// Last-observed OID, when that target was direct.
        observed: Option<Oid>,
        /// New remote OID, when the new target is direct.
        new: Option<Oid>,
    },
}

fn direct_oid(target: Option<&RefTarget>) -> Option<Oid> {
    match target {
        Some(RefTarget::Direct(oid)) => Some(*oid),
        _ => None,
    }
}

/// Merges one tracking ref: three-way local/last-observed/new.
///
/// - New equals observed, or local equals new: [`TrackingDecision::Unchanged`].
/// - Local equals observed (or neither exists): [`TrackingDecision::Advance`].
/// - Otherwise [`TrackingDecision::Conflict`]; the caller records the
///   terms and leaves the local ref alone.
#[must_use]
pub fn plan_tracking(
    name: RefName,
    local: Option<&RefTarget>,
    observed: Option<&RefTarget>,
    new_target: &RefTarget,
) -> TrackingDecision {
    if Some(new_target) == observed || Some(new_target) == local {
        return TrackingDecision::Unchanged;
    }
    if local == observed {
        let expected = match observed {
            None => RefExpect::Absent,
            Some(target) => RefExpect::Present(target.clone()),
        };
        return TrackingDecision::Advance {
            update: RefUpdate {
                name,
                expected,
                change: RefChange::Set(new_target.clone()),
            },
        };
    }
    TrackingDecision::Conflict {
        local: direct_oid(local),
        observed: direct_oid(observed),
        new: direct_oid(Some(new_target)),
    }
}

/// Publishes staged objects with `facts` in one atomic transaction: the
/// ref/tracking deltas become visible together with the objects that
/// justify them, never before.
///
/// # Errors
/// Store failures; nothing is published on failure.
pub fn publish_fetch(
    store: &Store,
    staged: StagedPack,
    facts: &[FactMutation],
) -> Result<ruk_core::store::types::Publication, GitError> {
    let mut facts = facts.to_vec();
    facts.extend(commit_record_facts(store, &staged)?);
    Ok(store.publish(staged.into_objects(), &facts)?)
}

/// Compiles commit-record mutations for every commit staged in a pack.
///
/// Fetched commits need their `Commits` table row like an import does, or a
/// later `commit`/`log` in the destination sees the object but no record and
/// refuses the parent. `observe_git_payload` preserves exact bytes; known
/// heads emit no mutations.
///
/// # Errors
/// [`GitError::Corrupt`] when a staged commit payload fails the record
/// boundary; record-boundary failures propagate as [`GitError`] via
/// `CoreError`.
pub fn commit_record_facts(
    store: &Store,
    staged: &StagedPack,
) -> Result<Vec<FactMutation>, GitError> {
    let mut batch = ruk_core::records::ImportBatch::new(store);
    for oid in staged.oids() {
        if let Some((ObjectKind::Commit, payload)) = staged.payload(*oid) {
            batch
                .observe_git_payload(payload.to_vec(), None)
                .map_err(GitError::from)?;
        }
    }
    batch.into_mutations().map_err(GitError::from)
}

#[cfg(test)]
mod tests {
    use super::super::pktline as pkt;
    use super::*;
    use crate::transport::session::test_support::{
        ScriptedPeer, receive_from_script, store_with_pack, test_store,
    };

    const FOUR: &str = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";
    const THREE: &str = "7a4943e466a7ce4f4c56d9eeb89c8909b1c43d22";

    fn oid(hex: &str) -> Oid {
        Oid::from_hex(hex).expect("hex")
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        pkt::encode_data(&mut out, payload).expect("frame");
        out
    }

    fn v0_script(tip: &str, pack: &[u8]) -> Vec<u8> {
        let mut script = Vec::new();
        script.extend(frame(
            format!(
                "{tip} HEAD\0multi_ack thin-pack ofs-delta filter object-format=sha1 agent=git/2\n"
            )
            .as_bytes(),
        ));
        script.extend(frame(format!("{tip} refs/heads/main\n").as_bytes()));
        script.extend(b"0000");
        script.extend(frame(b"NAK\n"));
        // No common base in these scripts: post-done NAK, then the pack.
        script.extend(frame(b"NAK\n"));
        script.extend_from_slice(pack);
        script
    }

    #[test]
    fn v0_fetch_negotiates_and_verifies() {
        let store = test_store(HashKind::Sha1);
        let pack = include_bytes!("fixtures/basic.pack");
        let req = FetchWireRequest::native(vec![oid(FOUR)], Vec::new());
        let (received, written) =
            receive_from_script(v0_script(FOUR, pack), HashKind::Sha1, &store, &req);
        let text = String::from_utf8_lossy(&written);
        assert!(text.contains(FOUR), "sends the want");
        assert!(text.contains("filter blob:none"), "sends the filter");
        assert!(text.contains("done\n"), "terminates negotiation with done");
        assert!(received.warnings.is_empty());
        assert_eq!(received.staged.oids().len(), 16);
        let report = verify_closure(
            &store,
            &received.staged,
            &req.wants,
            req.filter,
            &[],
            &Interrupt::none(),
        )
        .expect("complete pack verifies");
        assert!(report.missing_promisor.is_empty());
        let mut facts =
            promisor_facts(b"origin", Filter::BlobNone, &report.missing_promisor).expect("facts");
        facts.extend(observation_mutations(b"origin", &[]));
        let publication = publish_fetch(&store, received.staged, &facts).expect("publish");
        assert_eq!(publication.objects.len(), 16);
        assert!(
            store.read(oid(FOUR)).is_ok(),
            "tip is readable after publish"
        );
    }

    #[test]
    fn v0_common_round_survives_ready() {
        // Oracle trace: "ACK common", "ACK ready" pre-done, then done,
        // post-done NAK + ACK, then the pack. Breaking on "common" would
        // misread "ready" as the post-done NAK.
        let store = test_store(HashKind::Sha1);
        let pack = include_bytes!("fixtures/basic.pack");
        let two = THREE;
        let mut script = Vec::new();
        script.extend(frame(
            format!(
                "{FOUR} HEAD\0multi_ack_detailed thin-pack ofs-delta filter object-format=sha1\n"
            )
            .as_bytes(),
        ));
        script.extend(b"0000");
        script.extend(frame(format!("ACK {two} common\n").as_bytes()));
        script.extend(frame(format!("ACK {two} ready\n").as_bytes()));
        script.extend(frame(b"NAK\n"));
        script.extend(frame(format!("ACK {two}\n").as_bytes()));
        script.extend_from_slice(pack);
        let req = FetchWireRequest {
            wants: vec![oid(FOUR)],
            haves: vec![oid(two)],
            filter: None,
            depth: None,
            shallow: Vec::new(),
            list_refs: false,
            ref_prefixes: Vec::new(),
        };
        let (received, written) = receive_from_script(script, HashKind::Sha1, &store, &req);
        let text = String::from_utf8_lossy(&written);
        assert!(text.contains(two), "offers the have");
        assert!(text.contains("done\n"), "sends done once the round ends");
        assert_eq!(received.staged.oids().len(), 16);
        verify_closure(
            &store,
            &received.staged,
            &req.wants,
            None,
            &[],
            &Interrupt::none(),
        )
        .expect("complete pack verifies");
    }

    #[test]
    fn v2_packfile_section_demultiplexes_sideband() {
        // Live v2 servers multiplex the packfile section (band-1 pack,
        // band-2 progress) without any `sideband-all` negotiation; a raw
        // pack here must fail, never silently ingest.
        let store = test_store(HashKind::Sha1);
        let pack = include_bytes!("fixtures/basic.pack");
        let mut script = Vec::new();
        script.extend(frame(b"version 2\n"));
        script.extend(frame(b"fetch=shallow wait-for-done\n"));
        script.extend(b"0000");
        script.extend(frame(b"packfile\n"));
        let mut banded = vec![0x01];
        banded.extend_from_slice(&pack[..pack.len() / 2]);
        script.extend(frame(&banded));
        script.extend(frame(b"\x02progress\n"));
        let mut banded = vec![0x01];
        banded.extend_from_slice(&pack[pack.len() / 2..]);
        script.extend(frame(&banded));
        script.extend(b"0000");
        let req = FetchWireRequest {
            wants: vec![oid(FOUR)],
            haves: Vec::new(),
            filter: None,
            depth: None,
            shallow: Vec::new(),
            list_refs: false,
            ref_prefixes: Vec::new(),
        };
        let (received, written) = receive_from_script(script, HashKind::Sha1, &store, &req);
        let text = String::from_utf8_lossy(&written);
        assert!(text.contains("command=fetch"), "speaks v2");
        assert_eq!(received.staged.oids().len(), 16);
        assert!(received.progress.progress.starts_with(b"progress\n"));
        verify_closure(
            &store,
            &received.staged,
            &req.wants,
            None,
            &[],
            &Interrupt::none(),
        )
        .expect("complete pack verifies");
    }

    #[test]
    fn v0_malformed_ack_is_corrupt() {
        let store = test_store(HashKind::Sha1);
        let mut script = Vec::new();
        script.extend(frame(format!("{FOUR} HEAD\0multi_ack\n").as_bytes()));
        script.extend(b"0000");
        script.extend(frame(b"GARBAGE\n"));
        let req = FetchWireRequest::native(vec![oid(FOUR)], Vec::new());
        let mut peer = ScriptedPeer::new(script);
        let err = receive(
            &mut peer,
            HashKind::Sha1,
            &store,
            &req,
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect_err("garbage ack");
        assert!(matches!(err, GitError::Corrupt { .. }), "got {err:?}");
    }

    #[test]
    fn tracking_merge_decides_three_ways() {
        use ruk_core::refdata::{RefChange, RefExpect};
        let name = RefName::new(b"refs/remotes/origin/main".to_vec()).expect("name");
        let oid_a = oid(FOUR);
        let oid_b = oid(THREE);
        let direct = |o| RefTarget::Direct(o);
        // Remote unmoved: observation only.
        assert_eq!(
            plan_tracking(
                name.clone(),
                Some(&direct(oid_a)),
                Some(&direct(oid_a)),
                &direct(oid_a)
            ),
            TrackingDecision::Unchanged
        );
        // Clean advance: local matches observed.
        match plan_tracking(
            name.clone(),
            Some(&direct(oid_a)),
            Some(&direct(oid_a)),
            &direct(oid_b),
        ) {
            TrackingDecision::Advance { update } => {
                assert_eq!(update.expected, RefExpect::Present(direct(oid_a)));
                assert_eq!(update.change, RefChange::Set(direct(oid_b)));
            }
            other => panic!("expected advance, got {other:?}"),
        }
        // First fetch: nothing local, nothing observed.
        assert!(matches!(
            plan_tracking(name.clone(), None, None, &direct(oid_b)),
            TrackingDecision::Advance { .. }
        ));
        // Both moved: conflict with terms, no invented merge. The new value
        // must differ from both local and observed for a true conflict.
        let oid_c = Oid::from_bytes(&[7u8; 20]).expect("oid c");
        match plan_tracking(
            name.clone(),
            Some(&direct(oid_b)),
            Some(&direct(oid_a)),
            &direct(oid_c),
        ) {
            TrackingDecision::Conflict {
                local,
                observed,
                new,
            } => {
                assert_eq!(
                    (local, observed, new),
                    (Some(oid_b), Some(oid_a), Some(oid_c))
                );
            }
            other => panic!("expected conflict, got {other:?}"),
        }
        // Local already at new: unchanged even when observed lags.
        assert_eq!(
            plan_tracking(
                name,
                Some(&direct(oid_b)),
                Some(&direct(oid_a)),
                &direct(oid_b)
            ),
            TrackingDecision::Unchanged
        );
    }

    struct ScriptConnector {
        batches: std::collections::VecDeque<ScriptedPeer>,
    }

    impl Reconnectable for ScriptConnector {
        fn reconnect(&mut self) -> Result<Box<dyn Duplex>, GitError> {
            self.batches
                .pop_front()
                .map(|p| Box::new(p) as Box<dyn Duplex>)
                .ok_or_else(|| GitError::Io {
                    detail: "no more scripted batches".to_owned(),
                })
        }
    }

    #[test]
    fn prefetch_delivers_batches_and_clears_rows() {
        let kind = HashKind::Sha1;
        let src = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let dest = test_store(kind);
        // The big blob of commit four, promised from "origin".
        let missing = oid("51e57698a4ba83f75f80aadb52854e18e00cba6e");
        dest.publish(
            Vec::new(),
            &promisor_facts(b"origin", Filter::BlobNone, &[missing]).expect("row"),
        )
        .expect("promise the blob");
        assert!(
            super::super::promisor_row(&dest, missing)
                .expect("read")
                .is_some()
        );
        // One batch: advertisement, NAK, and a pack holding just the blob.
        let (obj_kind, bytes) = read_object(&src, missing, 1 << 20).expect("blob");
        let entry = super::super::pack::PackEntry {
            oid: missing,
            kind: obj_kind,
            bytes: &bytes,
            base: None,
        };
        let mut pack = Vec::new();
        super::super::pack::write_pack(&mut pack, kind, &[entry], &Interrupt::none())
            .expect("pack");
        let script = v0_script(&missing.to_hex(), &pack);
        let mut connector = ScriptConnector {
            batches: [ScriptedPeer::new(script)].into_iter().collect(),
        };
        let report = prefetch(
            &mut connector,
            kind,
            &dest,
            &[missing],
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect("prefetch");
        assert_eq!(report.delivered, vec![missing]);
        assert_eq!(report.batches, 1);
        assert!(dest.read(missing).is_ok());
        assert!(
            super::super::promisor_row(&dest, missing)
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn prefetch_missing_delivery_is_corrupt() {
        let kind = HashKind::Sha1;
        let dest = test_store(kind);
        let missing = oid("51e57698a4ba83f75f80aadb52854e18e00cba6e");
        let mut pack = Vec::new();
        super::super::pack::write_pack(&mut pack, kind, &[], &Interrupt::none())
            .expect("empty pack");
        let script = v0_script(&missing.to_hex(), &pack);
        let mut connector = ScriptConnector {
            batches: [ScriptedPeer::new(script)].into_iter().collect(),
        };
        let err = prefetch(
            &mut connector,
            kind,
            &dest,
            &[missing],
            IngestLimits::default(),
            &Interrupt::none(),
        )
        .expect_err("empty delivery");
        assert!(matches!(err, GitError::Corrupt { .. }), "got {err:?}");
    }
}

/// A stream factory for prefetch batches: one fresh connection per batch.
pub trait Reconnectable {
    /// Opens a fresh stream to the same upload-pack endpoint.
    ///
    /// # Errors
    /// [`GitError::Offline`] when the network is absent, [`GitError::Io`]
    /// when the peer cannot be reached.
    fn reconnect(&mut self) -> Result<Box<dyn Duplex>, GitError>;
}

/// What a prefetch completed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefetchReport {
    /// Every missing OID now present.
    pub delivered: Vec<Oid>,
    /// Connections opened (one per batch).
    pub batches: usize,
}

/// Completes promisor-missing closures in batches of [`PREFETCH_BATCH`]
/// OIDs, continuing under deadline/cancellation with no cap on the batch
/// count. Each batch publishes its objects and clears their promisor rows
/// in one transaction.
///
/// # Errors
/// [`GitError::Corrupt`] when a batch does not deliver a requested OID,
/// plus connection, ingest and store failures.
pub fn prefetch(
    connector: &mut dyn Reconnectable,
    kind: HashKind,
    store: &Store,
    missing: &[Oid],
    limits: IngestLimits,
    interrupt: &Interrupt,
) -> Result<PrefetchReport, GitError> {
    let mut delivered = Vec::with_capacity(missing.len());
    let mut batches = 0;
    for batch in missing.chunks(PREFETCH_BATCH) {
        interrupt.check("prefetching missing objects")?;
        let stream = connector.reconnect()?;
        let req = FetchWireRequest {
            wants: batch.to_vec(),
            haves: Vec::new(),
            filter: None,
            depth: None,
            shallow: Vec::new(),
            list_refs: false,
            ref_prefixes: Vec::new(),
        };
        let received = receive(stream, kind, store, &req, limits, interrupt)?;
        for want in batch {
            interrupt.check("prefetching missing objects")?;
            if !(received.staged.contains(*want) || has_object(store, *want)?) {
                return Err(GitError::Corrupt {
                    detail: format!("prefetch batch did not deliver {want}"),
                });
            }
        }
        verify_closure(store, &received.staged, batch, None, &[], interrupt)?;
        let facts = prefetch_clears(batch);
        store.publish(received.staged.into_objects(), &facts)?;
        delivered.extend(batch.iter().copied());
        batches += 1;
    }
    Ok(PrefetchReport { delivered, batches })
}
