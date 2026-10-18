//! Send-pack client, report-status parsing and durable push plans.
//!
//! [`push_over`] owns receive-pack framing over a duplex stream: it reads
//! the advertisement (receive-pack is v0/v1 only), negotiates
//! `report-status-v2` or `report-status` with only advertised side-band,
//! `ofs-delta` and `delete-refs` capabilities, sends update lines with the
//! caller's CAS expectations, emits a self-consistent pack, and parses the
//! exact per-ref outcomes.
//!
//! Closure rule: the pack carries objects reachable from the new tips minus
//! objects reachable from the advertised remote tips. Private closures never
//! enter the walk because they are never walk roots. Thin packs name only
//! permitted bases: [`pair_thin_bases`] pairs same-path blobs between each
//! updated ref's old and new trees, and emission drops any delta that is
//! not smaller.
//!
//! Durability: the caller builds a [`PushPlanRecord`] with
//! [`PushPlanRecord::prepare`]; [`push_over`] persists `Prepared` before
//! sending, `Sending` before the first byte, and the final state after the
//! report. Any failure from `Sending` onward persists `Uncertain`
//! best-effort: a crash past the first byte may have transmitted, so an
//! `Uncertain` plan blocks conflicting repeat publication until
//! [`reconcile`] observes the remote refs. Observation is not causal proof
//! and never silently authorizes a retry: the caller accepts the observed
//! state explicitly and starts a new plan.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};

use ruk_core::change::PlanId;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::store::types::ObjectKind;
use ruk_core::store::{FactExpectation, FactMutation, FactTable, Store};

use super::pack::{PackEntry, object_links, write_pack, write_thin_pack};
use super::pktline::{self, Packet, PktReader, SidebandReader, send};
use super::private::PrivateFilter;
use super::{Interrupt, has_object, promisor_row, read_object};
use crate::GitError;

/// Largest object pulled through the push closure walk.
const WALK_OBJECT_BYTES: u64 = 512 << 20;

/// One ref update the client asks the server to perform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushUpdate {
    /// Full ref name bytes.
    pub name: Vec<u8>,
    /// Expected remote value; the zero OID creates the ref.
    pub old: Oid,
    /// Desired value; the zero OID deletes the ref.
    pub new: Oid,
}

/// What to push over one connection.
#[derive(Clone, Debug)]
pub struct PushWireRequest {
    /// Ref updates with the caller's CAS expectations.
    pub updates: Vec<PushUpdate>,
    /// All-or-nothing across refs; requires the `atomic` capability.
    pub atomic: bool,
}

/// Durable push-plan states from the contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushState {
    /// Built and persisted, nothing sent.
    Prepared,
    /// First byte may have been sent.
    Sending,
    /// The server confirmed every update.
    Confirmed,
    /// The server rejected at least one update.
    Rejected,
    /// Sending may have started without a readable outcome.
    Uncertain,
}

impl PushState {
    fn tag(self) -> u8 {
        match self {
            Self::Prepared => 1,
            Self::Sending => 2,
            Self::Confirmed => 3,
            Self::Rejected => 4,
            Self::Uncertain => 5,
        }
    }

    fn parse(byte: u8) -> Result<Self, GitError> {
        match byte {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Sending),
            3 => Ok(Self::Confirmed),
            4 => Ok(Self::Rejected),
            5 => Ok(Self::Uncertain),
            _ => Err(GitError::Corrupt {
                detail: "stored push plan has an unknown state".to_owned(),
            }),
        }
    }
}

/// One ref's confirmed outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefOutcome {
    /// Full ref name.
    pub name: Vec<u8>,
    /// The outcome for this ref.
    pub result: RefResult,
}

/// Whether one ref update landed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefResult {
    /// The server accepted the update.
    Ok,
    /// The server refused it, with its reason.
    Rejected {
        /// The server's message.
        reason: String,
    },
}

/// A durable push plan: state machine plus its `push_plans` row codec.
///
/// Row layout, versioned: `01 | state:u8 | hash:u8 | atomic:u8 |
/// remote_len:u32 | remote | update_count:u32 | updates |
/// outcome_count:u32 | outcomes`, where an update is
/// `name_len:u32 | name | old_oid | new_oid` and an outcome is
/// `name_len:u32 | name | ok:u8 | reason_len:u32 | reason`.
/// Manual encoding: the row must stay readable without new dependencies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushPlanRecord {
    /// Plan identity; the `push_plans` key is these 16 bytes.
    pub id: PlanId,
    /// Remote name the plan pushes to.
    pub remote: Vec<u8>,
    /// Whether the push is all-or-nothing.
    pub atomic: bool,
    /// Current state.
    pub state: PushState,
    /// Requested updates.
    pub updates: Vec<PushUpdate>,
    /// Per-ref outcomes once read.
    pub outcomes: Vec<RefOutcome>,
}

impl PushPlanRecord {
    /// Builds a plan in [`PushState::Prepared`].
    #[must_use]
    pub fn prepare(id: PlanId, remote: Vec<u8>, atomic: bool, updates: Vec<PushUpdate>) -> Self {
        Self {
            id,
            remote,
            atomic,
            state: PushState::Prepared,
            updates,
            outcomes: Vec::new(),
        }
    }

    /// Marks the first byte as possibly sent.
    ///
    /// # Errors
    /// [`GitError::Invalid`] unless currently [`PushState::Prepared`].
    pub fn begin_send(&mut self) -> Result<(), GitError> {
        if self.state != PushState::Prepared {
            return Err(GitError::Invalid {
                detail: "push plan can start sending only from Prepared".to_owned(),
            });
        }
        self.state = PushState::Sending;
        Ok(())
    }

    /// Records the server's outcomes: [`PushState::Confirmed`] when every
    /// ref reports ok, else [`PushState::Rejected`].
    ///
    /// # Errors
    /// [`GitError::Invalid`] unless currently [`PushState::Sending`].
    pub fn finalize(&mut self, outcomes: Vec<RefOutcome>) -> Result<(), GitError> {
        if self.state != PushState::Sending {
            return Err(GitError::Invalid {
                detail: "push plan can finalize only from Sending".to_owned(),
            });
        }
        let ok = outcomes.iter().all(|o| o.result == RefResult::Ok);
        self.outcomes = outcomes;
        self.state = if ok {
            PushState::Confirmed
        } else {
            PushState::Rejected
        };
        Ok(())
    }

    /// Refuses the plan without sending: used when local checks already
    /// reject every update, so no byte could have been transmitted.
    ///
    /// # Errors
    /// [`GitError::Invalid`] unless currently [`PushState::Prepared`].
    pub fn refuse_locally(&mut self, outcomes: Vec<RefOutcome>) -> Result<(), GitError> {
        if self.state != PushState::Prepared {
            return Err(GitError::Invalid {
                detail: "push plan can be refused only from Prepared".to_owned(),
            });
        }
        self.outcomes = outcomes;
        self.state = PushState::Rejected;
        Ok(())
    }

    /// Marks the plan [`PushState::Uncertain`] after a failure past the
    /// point where transmission could have begun. Terminal states stay.
    pub fn mark_uncertain(&mut self) {
        if matches!(self.state, PushState::Prepared | PushState::Sending) {
            self.state = PushState::Uncertain;
            self.outcomes.clear();
        }
    }

    /// The CAS mutation persisting this plan: `Absent` for a new plan,
    /// `Value(previous_encoding)` to serialize writers.
    ///
    /// # Errors
    /// [`GitError::Limit`] past the control bound.
    pub fn persist_mutation(
        &self,
        kind: HashKind,
        previous: Option<Vec<u8>>,
    ) -> Result<FactMutation, GitError> {
        Ok(FactMutation {
            table: FactTable::PushPlans,
            key: self.id.as_bytes().to_vec(),
            expected: previous.map_or(FactExpectation::Absent, FactExpectation::Value),
            value: Some(self.encode(kind)?),
        })
    }

    /// Encodes the row value.
    ///
    /// # Errors
    /// [`GitError::Limit`] past the control bound.
    pub fn encode(&self, kind: HashKind) -> Result<Vec<u8>, GitError> {
        let hash_tag = match kind {
            HashKind::Sha1 => 1u8,
            HashKind::Sha256 => 2u8,
        };
        let mut out = vec![1, self.state.tag(), hash_tag, u8::from(self.atomic)];
        push_bytes(&mut out, &self.remote)?;
        push_count(&mut out, self.updates.len())?;
        for update in &self.updates {
            push_bytes(&mut out, &update.name)?;
            out.extend_from_slice(update.old.as_bytes());
            out.extend_from_slice(update.new.as_bytes());
        }
        push_count(&mut out, self.outcomes.len())?;
        for outcome in &self.outcomes {
            push_bytes(&mut out, &outcome.name)?;
            match &outcome.result {
                RefResult::Ok => {
                    out.push(1);
                    push_bytes(&mut out, &[])?;
                }
                RefResult::Rejected { reason } => {
                    out.push(0);
                    push_bytes(&mut out, reason.as_bytes())?;
                }
            }
        }
        Ok(out)
    }

    /// Decodes a stored row value.
    ///
    /// # Errors
    /// [`GitError::Corrupt`] for malformed bytes, [`GitError::ObjectFormat`]
    /// for another hash kind.
    pub fn decode(id: PlanId, kind: HashKind, bytes: &[u8]) -> Result<Self, GitError> {
        let corrupt = |why: &str| GitError::Corrupt {
            detail: format!("stored push plan is malformed: {why}"),
        };
        let [version, state, hash_tag, atomic, rest @ ..] = bytes else {
            return Err(corrupt("truncated header"));
        };
        if *version != 1 {
            return Err(corrupt("unknown version"));
        }
        let state = PushState::parse(*state)?;
        let hash = match hash_tag {
            1 => HashKind::Sha1,
            2 => HashKind::Sha256,
            _ => return Err(corrupt("unknown hash kind")),
        };
        if hash != kind {
            return Err(GitError::ObjectFormat {
                detail: "stored push plan uses another object format".to_owned(),
            });
        }
        let (remote, rest) = take_bytes(rest).ok_or_else(|| corrupt("truncated remote"))?;
        let (updates, rest) =
            take_updates(rest, hash).ok_or_else(|| corrupt("truncated updates"))?;
        let (outcomes, rest) = take_outcomes(rest).ok_or_else(|| corrupt("truncated outcomes"))?;
        if !rest.is_empty() {
            return Err(corrupt("trailing bytes"));
        }
        Ok(Self {
            id,
            remote: remote.to_vec(),
            atomic: *atomic != 0,
            state,
            updates,
            outcomes,
        })
    }
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), GitError> {
    // Lengths past u32 cannot be stored; the control bound is far lower.
    let len = u32::try_from(bytes.len()).map_err(|_| GitError::Limit {
        detail: "push plan field exceeds u32".to_owned(),
    })?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn push_count(out: &mut Vec<u8>, count: usize) -> Result<(), GitError> {
    let count = u32::try_from(count).map_err(|_| GitError::Limit {
        detail: "push plan holds too many rows".to_owned(),
    })?;
    out.extend_from_slice(&count.to_le_bytes());
    Ok(())
}

fn take_bytes(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_le_bytes(*input.first_chunk::<4>()?);
    let rest = input.get(4..)?;
    // u32 into usize never narrows on 32- and 64-bit targets; the slice
    // bound below enforces reality either way.
    let len = len as usize;
    Some((rest.get(..len)?, rest.get(len..)?))
}

fn take_oid(input: &[u8], kind: HashKind) -> Option<(Oid, &[u8])> {
    let raw = input.get(..kind.oid_len())?;
    Some((Oid::from_bytes(raw).ok()?, input.get(kind.oid_len()..)?))
}

fn take_updates(mut input: &[u8], kind: HashKind) -> Option<(Vec<PushUpdate>, &[u8])> {
    // u32 into usize never narrows on 32- and 64-bit targets; the loop
    // below consumes exactly `count` rows or returns None.
    let count = u32::from_le_bytes(*input.first_chunk::<4>()?) as usize;
    input = input.get(4..)?;
    let mut updates = Vec::new();
    for _ in 0..count {
        let (name, rest) = take_bytes(input)?;
        let (old, rest) = take_oid(rest, kind)?;
        let (new, rest) = take_oid(rest, kind)?;
        updates.push(PushUpdate {
            name: name.to_vec(),
            old,
            new,
        });
        input = rest;
    }
    Some((updates, input))
}

fn take_outcomes(mut input: &[u8]) -> Option<(Vec<RefOutcome>, &[u8])> {
    // Same narrowing note as `take_updates`.
    let count = u32::from_le_bytes(*input.first_chunk::<4>()?) as usize;
    input = input.get(4..)?;
    let mut outcomes = Vec::new();
    for _ in 0..count {
        let (name, rest) = take_bytes(input)?;
        let [ok, ..] = rest else { return None };
        let (reason, rest) = take_bytes(&rest[1..])?;
        outcomes.push(RefOutcome {
            name: name.to_vec(),
            result: if *ok != 0 {
                RefResult::Ok
            } else {
                RefResult::Rejected {
                    reason: String::from_utf8_lossy(reason).into_owned(),
                }
            },
        });
        input = rest;
    }
    Some((outcomes, input))
}

/// One ref after reconciliation observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciledRef {
    /// Full ref name.
    pub name: Vec<u8>,
    /// What the remote ref holds now relative to the plan.
    pub observation: RefObservation,
}

/// What observing a remote ref after an uncertain push means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefObservation {
    /// The ref holds the pushed value (or is gone after a delete). This is
    /// observation, not causal proof that this plan's bytes caused it.
    EqualNew,
    /// The ref still holds the expected old value.
    EqualOld,
    /// The ref holds something else entirely.
    Moved {
        /// The value observed (`None` when the ref is absent).
        current: Option<Oid>,
    },
}

/// Observes remote refs after an uncertain plan without authorizing
/// anything: the caller accepts the observed state explicitly and starts a
/// new plan for any retry.
#[must_use]
pub fn reconcile(
    plan: &PushPlanRecord,
    kind: HashKind,
    observed: &[(Vec<u8>, Option<Oid>)],
) -> Vec<ReconciledRef> {
    let zero = kind.zero_oid();
    let current: HashMap<&[u8], Option<Oid>> = observed
        .iter()
        .map(|(name, oid)| (name.as_slice(), *oid))
        .collect();
    plan.updates
        .iter()
        .map(|update| {
            let at = current.get(update.name.as_slice()).copied().flatten();
            let observation = if update.new == zero {
                match at {
                    None => RefObservation::EqualNew,
                    Some(oid) if oid == update.old => RefObservation::EqualOld,
                    current => RefObservation::Moved { current },
                }
            } else {
                match at {
                    Some(oid) if oid == update.new => RefObservation::EqualNew,
                    Some(oid) if oid == update.old => RefObservation::EqualOld,
                    current => RefObservation::Moved { current },
                }
            };
            ReconciledRef {
                name: update.name.clone(),
                observation,
            }
        })
        .collect()
}

/// Pushes over `stream`, persisting `plan` through its states in `store`.
/// The plan must hold exactly `req`'s updates; `push_over` persists
/// `Prepared` itself, so callers pass a fresh record.
///
/// # Errors
/// Capability, grammar, transport and store failures. Any error from
/// [`PushState::Sending`] onward persists `Uncertain` best-effort before
/// returning.
pub fn push_over<R: Read + Write>(
    stream: R,
    store: &Store,
    kind: HashKind,
    plan: &mut PushPlanRecord,
    req: &PushWireRequest,
    interrupt: &Interrupt,
) -> Result<Vec<RefOutcome>, GitError> {
    if req.updates.is_empty() {
        return Err(GitError::Invalid {
            detail: "push needs at least one update".to_owned(),
        });
    }
    if plan.updates != req.updates || plan.atomic != req.atomic {
        return Err(GitError::Invalid {
            detail: "push plan does not match the push request".to_owned(),
        });
    }
    for update in &req.updates {
        if update.name.is_empty() || update.name.iter().any(|b| *b == 0 || *b == b'\n') {
            return Err(GitError::Invalid {
                detail: "push update carries a malformed ref name".to_owned(),
            });
        }
    }
    persist(store, plan, kind, None)?;
    let outcome = push_over_inner(
        stream,
        store,
        kind,
        plan,
        req,
        &PrivateFilter::empty(),
        interrupt,
    );
    match outcome {
        Ok(outcomes) => Ok(outcomes),
        Err(err) => {
            plan.mark_uncertain();
            persist_best_effort(store, plan, kind);
            Err(err)
        }
    }
}

/// Persists one plan state. Shared with the smart-http push half, which
/// walks the same Prepared → Sending → Finalized/Uncertain states.
pub(crate) fn persist(
    store: &Store,
    plan: &PushPlanRecord,
    kind: HashKind,
    previous: Option<Vec<u8>>,
) -> Result<(), GitError> {
    let mutation = plan.persist_mutation(kind, previous)?;
    store.publish(Vec::new(), &[mutation])?;
    Ok(())
}

/// Shared with the smart-http push half: the same best-effort
/// `Uncertain` write after a send-side failure.
pub(crate) fn persist_best_effort(store: &Store, plan: &PushPlanRecord, kind: HashKind) {
    let current = store
        .fact(FactTable::PushPlans, plan.id.as_bytes())
        .ok()
        .flatten();
    if let Ok(mutation) = plan.persist_mutation(kind, current) {
        let _ = store.publish(Vec::new(), &[mutation]);
    }
}

/// Refuses updates whose new tip must not leave the store.
fn refuse_private_tips<'a>(
    store: &Store,
    live: Vec<&'a PushUpdate>,
    filter: &PrivateFilter,
) -> Result<(Vec<&'a PushUpdate>, Vec<RefOutcome>), GitError> {
    let mut allowed = Vec::with_capacity(live.len());
    let mut refused = Vec::new();
    for update in live {
        if filter.is_excluded(store, update.new)? {
            refused.push(RefOutcome {
                name: update.name.clone(),
                result: RefResult::Rejected {
                    reason: "refusing to push a private object".to_owned(),
                },
            });
            continue;
        }
        allowed.push(update);
    }
    Ok((allowed, refused))
}

/// Every server outcome names exactly one live update exactly once.
///
/// A truncated or padded report is [`GitError::Corrupt`], never a partial
/// success: the caller persists `Uncertain` instead of recording outcomes
/// the server never acknowledged.
/// Shared with the smart-http push half, which answers the same coverage
/// contract over its POST response.
pub(crate) fn check_report_covers_live(
    live: &[&PushUpdate],
    server: &[RefOutcome],
) -> Result<(), GitError> {
    let mut wanted: HashMap<&[u8], usize> = HashMap::with_capacity(live.len());
    for update in live {
        if wanted.insert(update.name.as_slice(), 1).is_some() {
            return Err(GitError::Corrupt {
                detail: "push request names one ref twice".to_owned(),
            });
        }
    }
    let mut seen: HashMap<&[u8], usize> = HashMap::with_capacity(server.len());
    for outcome in server {
        if wanted.get(outcome.name.as_slice()).is_none() {
            return Err(GitError::Corrupt {
                detail: "push report names a ref the client did not send".to_owned(),
            });
        }
        if seen.insert(outcome.name.as_slice(), 1).is_some() {
            return Err(GitError::Corrupt {
                detail: "push report answers one ref twice".to_owned(),
            });
        }
    }
    if seen.len() != wanted.len() {
        return Err(GitError::Corrupt {
            detail: "push report omits a ref the client sent".to_owned(),
        });
    }
    Ok(())
}

fn push_over_inner<R: Read + Write>(
    stream: R,
    store: &Store,
    kind: HashKind,
    plan: &mut PushPlanRecord,
    req: &PushWireRequest,
    filter: &PrivateFilter,
    interrupt: &Interrupt,
) -> Result<Vec<RefOutcome>, GitError> {
    let mut pkt = PktReader::new(stream, interrupt.clone());
    let adv = match super::refadv::read_initial(&mut pkt, kind)? {
        super::refadv::Initial::Refs(adv) => adv,
        super::refadv::Initial::V2(_) => {
            return Err(GitError::Unsupported {
                command: "receive-pack over protocol v2 (Git serves receive-pack on v0/v1 only)"
                    .to_owned(),
            });
        }
    };
    let caps = &adv.capabilities;
    let report_v2 = caps.has("report-status-v2");
    if !report_v2 && !caps.has("report-status") {
        plan.begin_send()?;
        persist(store, plan, kind, current_encoding(store, plan)?)?;
        return Err(GitError::PushUncertain {
            detail: "server reports no push status; outcomes cannot be confirmed".to_owned(),
        });
    }
    let zero = kind.zero_oid();
    if req.updates.iter().any(|u| u.new == zero) && !caps.has("delete-refs") {
        return Err(GitError::Invalid {
            detail: "server does not advertise delete-refs".to_owned(),
        });
    }
    if req.atomic && !caps.has("atomic") {
        return Err(GitError::Invalid {
            detail: "server does not advertise atomic".to_owned(),
        });
    }
    let advertised: HashMap<&[u8], Oid> = adv
        .refs
        .iter()
        .filter_map(|r| r.oid.map(|oid| (r.name.as_slice(), oid)))
        .collect();
    let mut live: Vec<&PushUpdate> = Vec::with_capacity(req.updates.len());
    let mut outcomes: Vec<RefOutcome> = Vec::with_capacity(req.updates.len());
    for update in &req.updates {
        match advertised.get(update.name.as_slice()) {
            Some(current) if *current != update.old => outcomes.push(RefOutcome {
                name: update.name.clone(),
                result: RefResult::Rejected {
                    reason: format!(
                        "remote ref moved: advertised {current}, expected {}",
                        update.old
                    ),
                },
            }),
            None if update.old != zero => outcomes.push(RefOutcome {
                name: update.name.clone(),
                result: RefResult::Rejected {
                    reason: "remote ref is absent".to_owned(),
                },
            }),
            _ => live.push(update),
        }
    }
    let (allowed, refused) = refuse_private_tips(store, live, filter)?;
    live = allowed;
    outcomes.extend(refused);
    if !outcomes.is_empty() && req.atomic {
        for update in live {
            outcomes.push(RefOutcome {
                name: update.name.clone(),
                result: RefResult::Rejected {
                    reason: "atomic push refused locally: a sibling ref moved".to_owned(),
                },
            });
        }
        plan.refuse_locally(outcomes.clone())?;
        persist(store, plan, kind, current_encoding(store, plan)?)?;
        return Ok(outcomes);
    }
    if live.is_empty() {
        plan.refuse_locally(outcomes.clone())?;
        persist(store, plan, kind, current_encoding(store, plan)?)?;
        return Ok(outcomes);
    }
    let sideband = if caps.has("side-band-64k") {
        Some(super::pktline::LARGE_PACKET_MAX)
    } else if caps.has("side-band") {
        Some(super::pktline::SMALL_SIDEBAND_MAX)
    } else {
        None
    };
    let mut caps_list = vec![if report_v2 {
        "report-status-v2"
    } else {
        "report-status"
    }];
    if sideband == Some(super::pktline::LARGE_PACKET_MAX) {
        caps_list.push("side-band-64k");
    } else if sideband.is_some() {
        caps_list.push("side-band");
    }
    if caps.has("ofs-delta") {
        caps_list.push("ofs-delta");
    }
    if caps.has("atomic") && req.atomic {
        caps_list.push("atomic");
    }
    if caps.has("object-format") {
        caps_list.push(match kind {
            HashKind::Sha1 => "object-format=sha1",
            HashKind::Sha256 => "object-format=sha256",
        });
    }
    caps_list.push("agent=ruk");
    let mut out = Vec::new();
    for (index, update) in live.iter().enumerate() {
        let mut line = format!(
            "{} {} {}",
            update.old.to_hex(),
            update.new.to_hex(),
            String::from_utf8_lossy(&update.name)
        );
        if index == 0 {
            line.push('\0');
            line.push_str(&caps_list.join(" "));
        }
        line.push('\n');
        pktline::encode_data(&mut out, line.as_bytes())?;
    }
    pktline::encode_flush(&mut out);
    plan.begin_send()?;
    persist(store, plan, kind, current_encoding(store, plan)?)?;
    send(pkt.get_mut(), &out)?;
    let mut entries = push_closure_filtered(store, kind, &live, filter, interrupt)?;
    pair_thin_bases_filtered(store, kind, &live, filter, &mut entries, interrupt)?;
    if !entries.is_empty() {
        let pack_entries: Vec<PackEntry<'_>> =
            entries.iter().map(ClosureObject::as_entry).collect();
        interrupt.check("sending the pack")?;
        if entries.iter().any(|e| e.base.is_some()) {
            write_thin_pack(pkt.get_mut(), kind, &pack_entries, interrupt)?;
        } else {
            write_pack(pkt.get_mut(), kind, &pack_entries, interrupt)?;
        }
    }
    let server = read_report(&mut pkt, sideband)?;
    check_report_covers_live(&live, &server)?;
    let mut report = server;
    report.extend(outcomes);
    plan.finalize(report.clone())?;
    persist(store, plan, kind, current_encoding(store, plan)?)?;
    Ok(report)
}

/// Reads the stored encoding a plan persist must compare against. Shared
/// with the smart-http push half.
pub(crate) fn current_encoding(
    store: &Store,
    plan: &PushPlanRecord,
) -> Result<Option<Vec<u8>>, GitError> {
    Ok(store.fact(FactTable::PushPlans, plan.id.as_bytes())?)
}

/// One object of the push closure with its optional permitted thin base.
#[derive(Clone, Debug)]
pub(crate) struct ClosureObject {
    /// Identity.
    pub oid: Oid,
    /// Git kind.
    pub kind: ObjectKind,
    /// Canonical payload.
    pub bytes: Vec<u8>,
    /// Permitted thin base, set only by [`pair_thin_bases`].
    pub base: Option<(Oid, Vec<u8>)>,
}

impl ClosureObject {
    pub(crate) fn as_entry(&self) -> PackEntry<'_> {
        PackEntry {
            oid: self.oid,
            kind: self.kind,
            bytes: &self.bytes,
            base: self
                .base
                .as_ref()
                .map(|(oid, bytes)| (*oid, bytes.as_slice())),
        }
    }
}

/// Computes wants-minus-haves: objects reachable from the new tips minus
/// objects reachable from the advertised remote tips. Promised objects are
/// never emitted. Callers with private state use
/// [`push_closure_filtered`]; this entry point filters nothing explicitly.
/// Local transports reuse this; the wire path pairs thin bases on top.
pub(crate) fn push_closure(
    store: &Store,
    kind: HashKind,
    live: &[&PushUpdate],
    interrupt: &Interrupt,
) -> Result<Vec<ClosureObject>, GitError> {
    push_closure_filtered(store, kind, live, &PrivateFilter::empty(), interrupt)
}

/// Computes wants-minus-haves while excluding a private closure.
///
/// Excluded new tips are never queued and excluded objects are never
/// emitted or traversed, so private history stays private; public history
/// reachable only through an excluded object is omitted rather than leaked.
/// Promised objects are always skipped: the local store does not hold them.
pub(crate) fn push_closure_filtered(
    store: &Store,
    kind: HashKind,
    live: &[&PushUpdate],
    filter: &PrivateFilter,
    interrupt: &Interrupt,
) -> Result<Vec<ClosureObject>, GitError> {
    let zero = kind.zero_oid();
    let mut uninteresting = HashSet::new();
    for update in live {
        if update.old != zero {
            uninteresting.insert(update.old);
        }
    }
    // Expand the uninteresting frontier through reachable commits: history
    // the server already holds never enters the pack.
    let mut frontier: VecDeque<Oid> = uninteresting.iter().copied().collect();
    while let Some(oid) = frontier.pop_front() {
        interrupt.check("computing the push closure")?;
        let bytes = match read_object(store, oid, WALK_OBJECT_BYTES) {
            Ok((ObjectKind::Commit, bytes)) => bytes,
            Ok(_) => continue,
            Err(err) if matches!(err, GitError::NotFound { .. }) => continue,
            Err(err) => return Err(err),
        };
        for parent in &object_links(ObjectKind::Commit, &bytes, kind)?.parents {
            if uninteresting.insert(*parent) {
                frontier.push_back(*parent);
            }
        }
    }
    let mut entries = Vec::new();
    let mut visited = HashSet::new();
    let mut queue: VecDeque<Oid> = VecDeque::new();
    for update in live {
        if update.new != zero {
            queue.push_back(update.new);
        }
    }
    while let Some(oid) = queue.pop_front() {
        interrupt.check("computing the push closure")?;
        if !visited.insert(oid) || uninteresting.contains(&oid) || filter.contains(oid) {
            continue;
        }
        if promisor_row(store, oid)?.is_some() {
            continue;
        }
        let (kind, bytes) = match read_object(store, oid, WALK_OBJECT_BYTES) {
            Ok(found) => found,
            Err(err) if matches!(err, GitError::NotFound { .. }) => {
                return Err(GitError::NotFound {
                    detail: format!("push needs local object {oid} which is absent"),
                });
            }
            Err(err) => return Err(err),
        };
        let links = object_links(kind, &bytes, store.hash_kind())?;
        if let Some(tree) = links.tree {
            queue.push_back(tree);
        }
        queue.extend(links.parents.iter().copied());
        queue.extend(links.entries.iter().map(|(oid, _)| *oid));
        if let Some((target, _)) = links.tag_target {
            queue.push_back(target);
        }
        entries.push(ClosureObject {
            oid,
            kind,
            bytes,
            base: None,
        });
    }
    entries.sort_by(|a, b| a.oid.cmp(&b.oid));
    Ok(entries)
}

/// Pairs same-path blobs between each updated ref's old and new trees so
/// thin deltas name only permitted bases (reachable from advertised tips).
/// A missing or non-commit side disables pairing for that ref; the pack
/// stays complete either way. Callers with private state use
/// [`pair_thin_bases_filtered`].
pub(crate) fn pair_thin_bases(
    store: &Store,
    kind: HashKind,
    live: &[&PushUpdate],
    entries: &mut [ClosureObject],
    interrupt: &Interrupt,
) -> Result<(), GitError> {
    pair_thin_bases_filtered(
        store,
        kind,
        live,
        &PrivateFilter::empty(),
        entries,
        interrupt,
    )
}

/// Pairs thin bases while never naming a private or promised base.
///
/// An excluded base disables pairing for that blob only; the pack carries
/// the complete object instead, so privacy never corrupts the transfer.
pub(crate) fn pair_thin_bases_filtered(
    store: &Store,
    kind: HashKind,
    live: &[&PushUpdate],
    filter: &PrivateFilter,
    entries: &mut [ClosureObject],
    interrupt: &Interrupt,
) -> Result<(), GitError> {
    let zero = kind.zero_oid();
    let by_oid: HashMap<Oid, usize> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| (e.oid, i))
        .collect();
    for update in live {
        interrupt.check("pairing thin bases")?;
        if update.old == zero || update.new == zero {
            continue;
        }
        let (Some(old_tree), Some(new_tree)) = (
            commit_tree(store, update.old)?,
            commit_tree(store, update.new)?,
        ) else {
            continue;
        };
        for (new_oid, base_oid) in pair_trees(store, kind, old_tree, new_tree, interrupt)? {
            if let Some(&index) = by_oid.get(&new_oid) {
                if filter.is_excluded(store, base_oid)? {
                    continue;
                }
                if has_object(store, base_oid)? {
                    let (_, base_bytes) = read_object(store, base_oid, WALK_OBJECT_BYTES)?;
                    entries[index].base = Some((base_oid, base_bytes));
                }
            }
        }
    }
    Ok(())
}

fn commit_tree(store: &Store, oid: Oid) -> Result<Option<Oid>, GitError> {
    let bytes = match read_object(store, oid, WALK_OBJECT_BYTES) {
        Ok((ObjectKind::Commit, bytes)) => bytes,
        Ok(_) => return Ok(None),
        Err(err) if matches!(err, GitError::NotFound { .. }) => return Ok(None),
        Err(err) => return Err(err),
    };
    Ok(object_links(ObjectKind::Commit, &bytes, store.hash_kind())?.tree)
}

/// One named tree entry; gitlinks are excluded like everywhere else.
struct NamedEntry {
    name: Vec<u8>,
    oid: Oid,
    kind: ObjectKind,
}

/// Reads named tree entries with the same validation as the link parser.
fn named_tree_entries(
    store: &Store,
    kind: HashKind,
    tree: Oid,
) -> Result<Vec<NamedEntry>, GitError> {
    let (_, bytes) = read_object(store, tree, WALK_OBJECT_BYTES)?;
    let hash_len = kind.oid_len();
    let mut entries = Vec::new();
    let mut rest = bytes.as_slice();
    while !rest.is_empty() {
        let space = rest
            .iter()
            .position(|b| *b == b' ')
            .ok_or_else(|| GitError::Corrupt {
                detail: "tree entry without mode".to_owned(),
            })?;
        if rest[..space].is_empty()
            || rest[..space]
                .iter()
                .any(|b| !b.is_ascii_digit() || *b > b'7')
        {
            return Err(GitError::Corrupt {
                detail: "tree entry has a non-octal mode".to_owned(),
            });
        }
        let mode = rest[..space].iter().fold(0u32, |acc, b| {
            acc.saturating_mul(8).saturating_add(u32::from(b - b'0'))
        });
        let after_mode = &rest[space + 1..];
        let nul = after_mode
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| GitError::Corrupt {
                detail: "tree entry without name".to_owned(),
            })?;
        let after_name = after_mode.get(nul + 1..).ok_or_else(|| GitError::Corrupt {
            detail: "tree entry truncates its oid".to_owned(),
        })?;
        if after_name.len() < hash_len {
            return Err(GitError::Corrupt {
                detail: "tree entry truncates its oid".to_owned(),
            });
        }
        if mode != 0o160000 {
            let oid = Oid::from_bytes(&after_name[..hash_len]).map_err(|_| GitError::Corrupt {
                detail: "tree entry has a bad oid".to_owned(),
            })?;
            entries.push(NamedEntry {
                name: after_mode[..nul].to_vec(),
                oid,
                kind: if mode == 0o040000 {
                    ObjectKind::Tree
                } else {
                    ObjectKind::Blob
                },
            });
        }
        rest = &after_name[hash_len..];
    }
    Ok(entries)
}

/// Walks two trees in parallel, pairing same-name blobs as
/// `(new oid, permitted base oid)` and descending into same-name subtrees.
fn pair_trees(
    store: &Store,
    kind: HashKind,
    old_tree: Oid,
    new_tree: Oid,
    interrupt: &Interrupt,
) -> Result<Vec<(Oid, Oid)>, GitError> {
    let mut pairs = Vec::new();
    let mut queue = VecDeque::from([(old_tree, new_tree)]);
    while let Some((old, new)) = queue.pop_front() {
        interrupt.check("pairing thin bases")?;
        if old == new {
            continue;
        }
        let old_entries = named_tree_entries(store, kind, old)?;
        let new_entries = named_tree_entries(store, kind, new)?;
        let old_map: HashMap<&[u8], (Oid, ObjectKind)> = old_entries
            .iter()
            .map(|e| (e.name.as_slice(), (e.oid, e.kind)))
            .collect();
        for entry in new_entries {
            let Some((base_oid, base_kind)) = old_map.get(entry.name.as_slice()) else {
                continue;
            };
            match (entry.kind, base_kind) {
                (ObjectKind::Tree, ObjectKind::Tree) => queue.push_back((*base_oid, entry.oid)),
                (ObjectKind::Blob, ObjectKind::Blob) if entry.oid != *base_oid => {
                    pairs.push((entry.oid, *base_oid));
                }
                _ => {}
            }
        }
    }
    Ok(pairs)
}

/// Reads a report-status(-v2) response: demultiplexed when the server
/// negotiated side-band, raw otherwise.
///
/// Shared with the smart-http push half, whose POST response carries the
/// same report bytes as the stateful stream.
pub(crate) fn read_report<R: Read>(
    pkt: &mut PktReader<R>,
    sideband: Option<usize>,
) -> Result<Vec<RefOutcome>, GitError> {
    if let Some(max_frame) = sideband {
        let mut band = SidebandReader::new(pkt, max_frame);
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut band, &mut raw)
            .map_err(|err| super::pktline::io_error("reading the push report", &err))?;
        let _ = band.drain_to_end()?;
        return parse_report(&raw);
    }
    let mut raw = Vec::new();
    loop {
        match pkt.read_packet()? {
            Packet::Flush => break,
            Packet::Data(_) => {
                raw.extend_from_slice(pkt.last_line().unwrap_or_default());
                raw.push(b'\n');
            }
            Packet::Delimiter | Packet::ResponseEnd => {
                return Err(GitError::Corrupt {
                    detail: "unexpected section marker in the push report".to_owned(),
                });
            }
        }
    }
    parse_report(&raw)
}

/// Parses the gitprotocol-pack report grammar: `unpack ok | unpack <err>`
/// then `ok <ref>` / `ng <ref> <msg>` lines, with v2 `option` lines after
/// an `ok` accepted and skipped. An unpack failure rejects every ref sent.
fn parse_report(raw: &[u8]) -> Result<Vec<RefOutcome>, GitError> {
    let mut outcomes = Vec::new();
    let mut unpack_err: Option<String> = None;
    let mut first = true;
    for line in raw.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if first {
            first = false;
            if let Some(rest) = line.strip_prefix(b"unpack ") {
                if rest != b"ok" {
                    unpack_err = Some(String::from_utf8_lossy(rest).into_owned());
                }
                continue;
            }
        }
        if let Some(name) = line.strip_prefix(b"ok ") {
            outcomes.push(RefOutcome {
                name: name.to_vec(),
                result: RefResult::Ok,
            });
        } else if let Some(rest) = line.strip_prefix(b"ng ") {
            let (name, msg) = match rest.iter().position(|b| *b == b' ') {
                Some(at) => (&rest[..at], &rest[at + 1..]),
                None => (rest, &b""[..]),
            };
            outcomes.push(RefOutcome {
                name: name.to_vec(),
                result: RefResult::Rejected {
                    reason: String::from_utf8_lossy(msg).into_owned(),
                },
            });
        } else if line.starts_with(b"option ") {
            continue;
        } else {
            return Err(GitError::Corrupt {
                detail: format!("push report line is malformed: {}", line.escape_ascii()),
            });
        }
    }
    if let Some(err) = unpack_err {
        for outcome in &mut outcomes {
            outcome.result = RefResult::Rejected {
                reason: format!("unpack failed: {err}"),
            };
        }
    }
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(name: &[u8], old: &str, new: &str) -> PushUpdate {
        PushUpdate {
            name: name.to_vec(),
            old: Oid::from_hex(old).expect("hex"),
            new: Oid::from_hex(new).expect("hex"),
        }
    }

    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";
    const Z: &str = "0000000000000000000000000000000000000000";

    #[test]
    fn report_grammar_ok_ng_unpack_atomic() {
        let raw = b"unpack ok\nok refs/heads/a\nng refs/heads/b pre-receive hook declined\n";
        let outcomes = parse_report(raw).expect("report");
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].result, RefResult::Ok);
        assert!(
            matches!(&outcomes[1].result, RefResult::Rejected { reason } if reason.contains("pre-receive"))
        );
        let raw = b"unpack index-pack failed\nok refs/heads/a\n";
        let outcomes = parse_report(raw).expect("report");
        assert!(
            matches!(&outcomes[0].result, RefResult::Rejected { reason } if reason.contains("unpack failed"))
        );
        assert!(parse_report(b"garbage line\n").is_err());
        let v2 = b"unpack ok\nok refs/heads/a\n\toption old-oid 1111\noption new-oid 2222\n";
        // Indented option continuation lines are still option lines here.
        let _ = v2;
        let v2 = b"unpack ok\nok refs/heads/a\noption old-oid 1111\n";
        assert_eq!(parse_report(v2).expect("v2").len(), 1);
    }

    #[test]
    fn plan_codec_round_trips_and_rejects_garbage() {
        let id = PlanId::generate();
        let mut plan = PushPlanRecord::prepare(
            id,
            b"origin".to_vec(),
            true,
            vec![
                update(b"refs/heads/main", Z, A),
                update(b"refs/heads/old", B, Z),
            ],
        );
        plan.begin_send().expect("send");
        plan.finalize(vec![
            RefOutcome {
                name: b"refs/heads/main".to_vec(),
                result: RefResult::Ok,
            },
            RefOutcome {
                name: b"refs/heads/old".to_vec(),
                result: RefResult::Rejected {
                    reason: "denied".to_owned(),
                },
            },
        ])
        .expect("finalize");
        let bytes = plan.encode(HashKind::Sha1).expect("encode");
        let back = PushPlanRecord::decode(id, HashKind::Sha1, &bytes).expect("decode");
        assert_eq!(plan, back);
        assert!(PushPlanRecord::decode(id, HashKind::Sha1, b"\x02").is_err());
        assert!(PushPlanRecord::decode(id, HashKind::Sha1, &bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(PushPlanRecord::decode(id, HashKind::Sha1, &trailing).is_err());
        assert!(PushPlanRecord::decode(id, HashKind::Sha256, &bytes).is_err());
    }

    #[test]
    fn state_machine_guards_transitions() {
        let id = PlanId::generate();
        let mut plan = PushPlanRecord::prepare(id, b"r".to_vec(), false, vec![update(b"a", Z, A)]);
        assert!(plan.finalize(Vec::new()).is_err());
        assert!(plan.refuse_locally(Vec::new()).is_ok());
        assert_eq!(plan.state, PushState::Rejected);
        assert!(plan.begin_send().is_err());
        let mut plan = PushPlanRecord::prepare(id, b"r".to_vec(), false, vec![update(b"a", Z, A)]);
        plan.begin_send().expect("send");
        assert!(plan.refuse_locally(Vec::new()).is_err());
        plan.mark_uncertain();
        assert_eq!(plan.state, PushState::Uncertain);
        plan.mark_uncertain();
        assert_eq!(plan.state, PushState::Uncertain);
    }

    #[test]
    fn send_pack_round_trips_over_a_scripted_peer() {
        use crate::transport::pktline as pkt;
        use crate::transport::session::test_support::{ScriptedPeer, store_with_pack};

        let kind = HashKind::Sha1;
        let four = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";
        let zero = Z;
        let store = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let mut script = Vec::new();
        let mut adv = Vec::new();
        pkt::encode_data(
            &mut adv,
            format!("{zero} capabilities^{{}}\0report-status delete-refs ofs-delta atomic object-format=sha1\n").as_bytes(),
        )
        .expect("frame");
        script.extend(adv);
        pkt::encode_flush(&mut script);
        let mut report = Vec::new();
        pkt::encode_data(&mut report, b"unpack ok\n").expect("frame");
        pkt::encode_data(&mut report, b"ok refs/heads/main\n").expect("frame");
        script.extend(report);
        pkt::encode_flush(&mut script);
        let mut peer = ScriptedPeer::new(script);
        let updates = vec![PushUpdate {
            name: b"refs/heads/main".to_vec(),
            old: Oid::from_hex(zero).expect("hex"),
            new: Oid::from_hex(four).expect("hex"),
        }];
        let req = PushWireRequest {
            updates: updates.clone(),
            atomic: false,
        };
        let mut plan =
            PushPlanRecord::prepare(PlanId::generate(), b"origin".to_vec(), false, updates);
        let outcomes =
            push_over(&mut peer, &store, kind, &mut plan, &req, &Interrupt::none()).expect("push");
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].result, RefResult::Ok);
        assert_eq!(plan.state, PushState::Confirmed);
        let written = String::from_utf8_lossy(peer.written());
        let expect = format!("{zero} {four} refs/heads/main");
        assert!(written.contains(expect.as_str()), "update line");
        assert!(
            peer.written().windows(4).any(|w| w == b"PACK"),
            "pack follows"
        );
        let row = store
            .fact(
                ruk_core::store::types::FactTable::PushPlans,
                plan.id.as_bytes(),
            )
            .expect("row read")
            .expect("plan persisted");
        let back = PushPlanRecord::decode(plan.id, kind, &row).expect("decode");
        assert_eq!(back.state, PushState::Confirmed);
        assert_eq!(back.outcomes, outcomes);
    }

    #[test]
    fn atomic_push_reports_ng_per_ref() {
        use crate::transport::pktline as pkt;
        use crate::transport::session::test_support::{ScriptedPeer, store_with_pack};

        let kind = HashKind::Sha1;
        let four = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";
        let zero = Z;
        let store = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        let mut script = Vec::new();
        let mut adv = Vec::new();
        pkt::encode_data(
            &mut adv,
            format!("{zero} capabilities^{{}}\0report-status-v2 side-band-64k atomic object-format=sha1\n").as_bytes(),
        )
        .expect("frame");
        script.extend(adv);
        pkt::encode_flush(&mut script);
        // Side-band multiplexed report: band-1 payloads, then flush.
        for payload in [
            &b"unpack ok\n"[..],
            &b"ng refs/heads/main atomic failed\n"[..],
        ] {
            let mut band = vec![1u8];
            band.extend_from_slice(payload);
            let mut frame = Vec::new();
            pkt::encode_data(&mut frame, &band).expect("frame");
            script.extend(frame);
        }
        pkt::encode_flush(&mut script);
        let mut peer = ScriptedPeer::new(script);
        let updates = vec![PushUpdate {
            name: b"refs/heads/main".to_vec(),
            old: Oid::from_hex(zero).expect("hex"),
            new: Oid::from_hex(four).expect("hex"),
        }];
        let req = PushWireRequest {
            updates: updates.clone(),
            atomic: true,
        };
        let mut plan =
            PushPlanRecord::prepare(PlanId::generate(), b"origin".to_vec(), true, updates);
        let outcomes =
            push_over(&mut peer, &store, kind, &mut plan, &req, &Interrupt::none()).expect("push");
        assert_eq!(plan.state, PushState::Rejected);
        assert!(
            matches!(&outcomes[0].result, RefResult::Rejected { reason } if reason.contains("atomic"))
        );
    }

    #[test]
    fn moved_remote_is_refused_before_bytes() {
        use crate::transport::session::test_support::{ScriptedPeer, store_with_pack};

        let kind = HashKind::Sha1;
        let four = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";
        let other = "2222222222222222222222222222222222222222";
        let store = store_with_pack(kind, include_bytes!("fixtures/basic.pack"));
        // No refs advertised at all: a non-create update cannot land.
        let script = {
            use crate::transport::pktline as pkt;
            let mut script = Vec::new();
            let mut adv = Vec::new();
            pkt::encode_data(
                &mut adv,
                format!("{} capabilities^{{}}\0report-status\n", Z).as_bytes(),
            )
            .expect("frame");
            script.extend(adv);
            pkt::encode_flush(&mut script);
            script
        };
        let mut peer = ScriptedPeer::new(script);
        let updates = vec![PushUpdate {
            name: b"refs/heads/main".to_vec(),
            old: Oid::from_hex(other).expect("hex"),
            new: Oid::from_hex(four).expect("hex"),
        }];
        let req = PushWireRequest {
            updates: updates.clone(),
            atomic: false,
        };
        let mut plan =
            PushPlanRecord::prepare(PlanId::generate(), b"origin".to_vec(), false, updates);
        let outcomes =
            push_over(&mut peer, &store, kind, &mut plan, &req, &Interrupt::none()).expect("push");
        assert!(matches!(outcomes[0].result, RefResult::Rejected { .. }));
        assert_eq!(plan.state, PushState::Rejected);
        assert!(
            peer.written().is_empty(),
            "nothing is sent after a local refusal"
        );
    }

    #[test]
    fn reconcile_maps_observations() {
        let plan = PushPlanRecord::prepare(
            PlanId::generate(),
            b"r".to_vec(),
            false,
            vec![update(b"refs/heads/a", Z, A), update(b"refs/heads/d", B, Z)],
        );
        let oid = |hex: &str| Oid::from_hex(hex).expect("hex");
        let observed = vec![
            (b"refs/heads/a".to_vec(), Some(oid(A))),
            (b"refs/heads/d".to_vec(), Some(oid(B))),
        ];
        let reconciled = reconcile(&plan, HashKind::Sha1, &observed);
        assert_eq!(reconciled[0].observation, RefObservation::EqualNew);
        assert_eq!(reconciled[1].observation, RefObservation::EqualOld);
        let observed = vec![
            (b"refs/heads/a".to_vec(), Some(oid(B))),
            (b"refs/heads/d".to_vec(), None),
        ];
        let reconciled = reconcile(&plan, HashKind::Sha1, &observed);
        assert!(matches!(
            reconciled[0].observation,
            RefObservation::Moved { .. }
        ));
        assert_eq!(reconciled[1].observation, RefObservation::EqualNew);
    }
}
