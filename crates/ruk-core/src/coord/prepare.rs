//! Per-method preparation of bare mutation requests into lane parts.
//!
//! [`HostedCoordinator`](super::hosted::HostedCoordinator) admits and publishes
//! only fully prepared candidates. This module translates the mechanically
//! preparable subset of mutations — ref updates whose semantics the lane
//! re-checks authoritatively at commit time — into [`PreparedMutation`].
//!
//! Covered today: `bookmark.set` (commit and change targets),
//! `bookmark.delete`, `bookmark.resolve`, `tag.set` (plain and annotated),
//! `tag.delete`, `pin`, `unpin`, `attest.add`, `new`, `claim.acquire`,
//! `claim.release`, `ws.new`, `describe`, `split`, `rebase`, `squash`,
//! `abandon`, `edit`, `ws.scope`, `ws.take`, `ws.drop`, `resolve`, `revert`,
//! `undo`, and `land.prepare`.
//! The annotated tag arm needs the coordinator clock and a tagger identity,
//! `new` and `ws.new` need the session identity row and the clock for
//! signature synthesis, and `attest.add` needs the attestation progress gate,
//! so those arms stay refused on the legacy [`prepare_mutation`] path and
//! serve only through [`prepare_mutation_with`]. The history-rewrite arms
//! preserve existing signatures and need no clock or identity row, so they
//! serve on both paths. Everything else is honestly refused with
//! [`ErrorCode::EHosted`]:
//!
//! * `claim.acquire` / `claim.release` validate here (path canonicalization
//!   plus the session's `claim_paths` capability) and seal in the lane under
//!   sole publication ownership: the fence and overlap checks need a
//!   commit-time snapshot, so preparation stages no claim facts and mints
//!   only the acquire id the sealed record must carry. The lane seals with
//!   that id and writes the authoritative record back into the reply.
//! * Workspace dirty state (`snapshot`, `write`, `ws.recover`), transport
//!   (`fetch`, `push`, `push.reconcile`), `land.execute`, and prune mutations
//!   need worktree file I/O, object preparation, network round-trips, or plan
//!   evaluation that no caller on this path supplies. The pure row transitions
//!   (`edit`, `ws.scope`, `ws.take`, `ws.drop`) serve on both paths: they stage
//!   the fenced row fact and leave worktree materialization to the post-commit
//!   daemon job, exactly like the `new` workspace switch. `land.prepare` serves
//!   too: it freezes the resolved head as the exact candidate and moves no ref,
//!   so the plan row stages with no transport involved.
//!
//! The `crate::ops`-adjacent methods were evaluated one by one against
//! their protocol args, each refused arm naming its missing piece:
//! `new` mints the empty tree and synthesizes its signature from the session
//! identity row plus the coordinator clock (multi-parent trees need merge
//! evaluation with no producer here, so they stay refused); `ws.new` builds
//! on the same mint for native workspaces and writes only the row — no
//! worktree materialization happens in this call;
//! protocol `describe` rewrites a change's description through
//! `ops::prepare_edit` with the tree preserved, re-parenting descendants with
//! unchanged trees in the same batch (a message rewrite moves no content, so
//! no tree derivation is needed); protocol `edit` checks a change out into a
//! workspace while `ops::edit` rewrites a commit's message/tree/identities;
//! `rebase` serves content-less (empty-delta) sources only — a non-empty
//! source needs per-commit tree re-derivation over the moved base, which is
//! content-merge work with no producer here (`ops::prepare_rebase` needs one
//! caller-resolved tree per root and keeps stale descendant trees, so the
//! translator stages the whole moved set through one record batch preparer
//! instead); `squash` moves selected paths (or all) from a single-child source
//! into its destination, keeping the source's tree and re-deriving its
//! descendants; `split` partitions one change by path; and `abandon` re-parents
//! descendants onto the abandoned commits' parents in the same batch as the
//! change-state transitions (merge-commit targets need fan-in parent
//! replacement with no producer here, so they stay refused). `land.prepare`
//! freezes the resolved head as the single exact candidate with empty
//! requirements (the policy carries no land-requirement fields yet) and stages
//! the plan row; `fetch`, `push`, `push.reconcile`, and `land.execute` refuse,
//! each naming its missing transport job or plan codec.
//!
//! Path-level tree derivation (split, squash, revert, resolve) goes through
//! [`crate::ops::tree_edit`]: `apply_delta` is a three-tree apply restricted to
//! a selection that refuses `E_CONFLICTED` where both sides diverged, and
//! `set_entry`/`lookup`/`conflicted_paths` address conflicted terms one path at
//! a time. `resolve` rewrites every term tree at the path, keeping other
//! conflicts as term lists. `revert` reverses the target's delta onto its single
//! `onto` parent in a fresh change. `undo` ([`super::undo`]) inverts a
//! retained operation's tracked deltas as exact facts. `op.prune` refuses,
//! naming the missing operation-retention policy.
//!
//! Ref safety: each helper checks its transaction against the store before
//! returning, and the lane keeps ref mutations safe after that. The batch
//! accumulator never admits two items touching refs into one batch, so a
//! prepared ref mutation commits sequentially with respect to every other
//! ref write, where the lane re-checks the carried transaction against
//! fresh store state under sole publication ownership. A store that moved
//! between preparation and publication is refused there rather than
//! committed, and the exact fact expectations add point compare-and-swap
//! as a second layer.

use super::claims::{ClaimClock, canonical_paths, read_record};
use super::land::{LandPrepareRequest, prepare_land_plan};
use std::collections::{BTreeMap, BTreeSet};

use super::clock::Clock;
use super::hosted::PreparedMutation;
use super::policy::Policy;
use super::rows::{self, SessionRow, WorkspaceRow};
use super::undo::prepare_undo;
use super::workspace::{self, ObservedWorkspace};
use crate::attestation::{Checkpoint, prepare_add};
use crate::bytes::ByteString;
use crate::change::{ChangeId, ClaimId, RequestId, SessionId, WorkspaceId};
use crate::commit::{CommitRecord, NativeCommitInput};
use crate::conflict::{ExtraHeader, Signature, TzOffset};
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::ids::Oid;
use crate::index::{FileMode, RepoPath};
use crate::merge::Merge;
use crate::merge::composed::{MergeMetadata, MergeMode, MergeNotices, MergeReport};
use crate::merge::syntax::LANGUAGE_SET_VERSION;
use crate::ops::revert::default_revert_message;
use crate::ops::tree_edit::{
    Node, Selection, apply_delta, conflicted_paths, covered_by, empty_tree, lookup, set_entry,
};
use crate::ops::{
    AbandonRequest, EditRequest, NewRequest, NewResult, PreparedOp, prepare_abandon, prepare_edit,
    prepare_new,
};
use crate::ops::{children, descendants};
use crate::protocol::{
    AbandonArgs, AttestAddArgs, AttestAddReply, BookmarkDeleteArgs, BookmarkDeleteReply,
    BookmarkResolution, BookmarkResolveArgs, BookmarkResolveReply, BookmarkSetArgs,
    BookmarkSetReply, BookmarkTarget, BoundedList, ChangeHead, ChangeRef, ClaimAcquireArgs,
    ClaimAcquireReply, ClaimRecord, ClaimReleaseArgs, ClaimReleaseReply, DescribeArgs, EditArgs,
    EditReply, EffectiveIdentity, GitCommitArgs, HeadRewrite, IdentityClaim, IdentitySource,
    LandExecuteArgs, LandExecuteReply, LandLocalState, LandPrepareArgs, LandPrepareReply,
    MutationOutcome, NewArgs, NewReply, PinArgs, PinReply, PolicySetArgs, PolicySetReply,
    PushRefOutcome, PushRefStatus, RebaseArgs, RebaseScope, ReceiptRef, Reply, Request,
    RequestDigest, RewriteReply, SnapshotArgs, SquashArgs, TagDeleteArgs, TagDeleteReply,
    TagSetArgs, TagSetReply, Timestamp, UnpinArgs, UnpinReply, Validate, WorkspaceBinding,
    WorkspaceInit, WriteArgs, WsDropArgs, WsDropReply, WsNewArgs, WsNewReply, WsRecoverArgs,
    WsScopeArgs, WsScopeReply, WsTakeArgs, WsTakeReply,
};
use crate::protocol::{
    Content, PathSelection, RemainingConflict, Resolution, ResolveArgs, ResolveReply, RevertArgs,
    RevertReply, SplitArgs, SplitPlacement, UndoArgs, UndoReply,
};
use crate::records::Records;
use crate::records::codec::{decode_change_entry, encode_change_entry};
use crate::records::keys::head_key;
use crate::records::types::{ChangeEntry, ChangeState};
use crate::refdata::{
    RefChange, RefExpect, RefName, RefRead, RefTarget, RefTransaction, RefUpdate,
};
use crate::refs::{StoreRefs, prepare_checked_transaction, prepare_clear_ref_conflict_checked};
use crate::store::ObjectKind;
use crate::store::Store;
use crate::store::types::{FactExpectation, FactMutation, FactTable, PreparedObject};
use crate::workcopy::journal_state::{NoJournal, ensure_idle};
use crate::workcopy::tree::TreeMode;
use crate::workspace::{
    GitCompatWorkspace, HeadRef, NativeWorkspace, Scope, WorkspaceStamp, WorkspaceState,
};
use std::num::NonZeroU32;

/// Inputs beyond the store that identity synthesis, timestamped signatures,
/// claim sealing, and land plans need.
///
/// Every field but `store`/`session` is optional so the legacy
/// [`prepare_mutation`] wrapper (which has no session row, clocks, policy,
/// or gate) keeps serving the ref-only arms. An arm whose required input is
/// absent refuses with the same named [`ErrorCode::EHosted`] reason it gave
/// before the context existed, never with an invented value. The socket
/// dispatch path always supplies the full context through
/// [`HostedCoordinator::prepare_for_dispatch`](super::hosted::HostedCoordinator::prepare_for_dispatch).
pub(crate) struct PrepareContext<'a> {
    pub(crate) store: &'a Store,
    pub(crate) session: SessionId,
    /// Identity row for signature synthesis; absent on the legacy path.
    pub(crate) session_row: Option<&'a SessionRow>,
    /// Wall clock for signature timestamps; absent on the legacy path.
    pub(crate) clock: Option<&'a Clock>,
    /// Monotonic claim clock for claim sealing; absent on the legacy path.
    #[expect(dead_code, reason = "wired in CS-R42 (claim sealing)")]
    pub(crate) claim_clock: Option<&'a ClaimClock>,
    /// Admission policy for land preparation; absent on the legacy path.
    #[expect(dead_code, reason = "wired in CS-R38/40/44 (land preparation)")]
    pub(crate) policy: Option<&'a Policy>,
    /// Progress gate for attestation verification; absent on the legacy path.
    pub(crate) checkpoint: Option<&'a Checkpoint<'a>>,
    /// Provenance the invoking call declared; recorded, never authorized on.
    pub(crate) on_behalf_of: Option<String>,
}

/// One method's lane parts: the precomputed reply, staged objects, exact
/// facts, the checked transaction when the method moves a ref, and the ref
/// names the transaction was validated against.
struct Parts {
    reply: Reply,
    objects: Vec<PreparedObject>,
    facts: Vec<FactMutation>,
    transaction: Option<RefTransaction>,
    dependencies: Vec<RefName>,
    fence: Option<(WorkspaceId, WorkspaceStamp)>,
}

/// Translates one bare mutation [`Request`] into lane-ready parts.
///
/// The caller decoded and validated the request already; the returned
/// [`PreparedMutation`] carries no prepared objects and no workspace fence,
/// only exact-expectation ref facts plus (for `bookmark.resolve`) its
/// conflict-clearing fact.
///
/// # Errors
/// - [`ErrorCode::EInvalid`] when the request is not a mutation (the caller
///   routes reads elsewhere).
/// - [`ErrorCode::EHosted`] when the method has no preparation on this path.
/// - [`ErrorCode::EStale`] when a conditional expectation or the resolve
///   conflict terms no longer match the store.
/// - [`ErrorCode::EForbidden`], [`ErrorCode::ECorrupt`], [`ErrorCode::EIo`],
///   or [`ErrorCode::ELimit`] from ref validation and store reads.
pub fn prepare_mutation(
    store: &Store,
    session: SessionId,
    request: Request,
) -> Result<PreparedMutation, CoreError> {
    // No checkpoint: the legacy path refuses every arm that needs the
    // attestation gate, so no caller reaches verification with a no-op gate.
    let ctx = PrepareContext {
        store,
        session,
        session_row: None,
        clock: None,
        claim_clock: None,
        policy: None,
        checkpoint: None,
        on_behalf_of: None,
    };
    prepare_mutation_with(&ctx, request)
}

/// Translates one bare mutation [`Request`] into lane-ready parts with the
/// full coordinator context.
///
/// This is the entry the socket dispatch path uses; arms that need identity,
/// time, policy, or the attestation gate serve only here, while the
/// ref-only arms behave identically under both entries.
///
/// # Errors
/// Same as [`prepare_mutation`], plus the named `E_HOSTED` refusal of any
/// arm whose required context input is absent.
pub(crate) fn prepare_mutation_with(
    ctx: &PrepareContext<'_>,
    request: Request,
) -> Result<PreparedMutation, CoreError> {
    let method = request.method();
    let looks_mutation = request.request_id().is_some();
    if !looks_mutation {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "method `{}` is not a mutation and has no preparation",
                method.as_str()
            ),
        ));
    }
    let parts = match &request {
        Request::BookmarkSet(m) => bookmark_set_parts(ctx, m.request_id, &m.args)?,
        Request::BookmarkDelete(m) => bookmark_delete_parts(ctx, m.request_id, &m.args)?,
        Request::BookmarkResolve(m) => bookmark_resolve_parts(ctx, m.request_id, &m.args)?,
        Request::TagSet(m) => tag_set_parts(ctx, m.request_id, &m.args)?,
        Request::TagDelete(m) => tag_delete_parts(ctx, m.request_id, &m.args)?,
        Request::Pin(m) => pin_parts(ctx, m.request_id, &m.args)?,
        Request::Unpin(m) => unpin_parts(ctx, m.request_id, &m.args)?,
        Request::AttestAdd(m) => attest_add_parts(ctx, m.request_id, &m.args)?,
        Request::New(m) => new_parts(ctx, m.request_id, &m.args)?,
        Request::GitCommit(m) => git_commit_parts(ctx, m.request_id, &m.args)?,
        Request::ClaimAcquire(m) => claim_acquire_parts(ctx, m.request_id, &m.args)?,
        Request::ClaimRelease(m) => claim_release_parts(ctx, m.request_id, &m.args)?,
        Request::WsNew(m) => ws_new_parts(ctx, m.request_id, &m.args)?,
        Request::WsScope(m) => ws_scope_parts(ctx, m.request_id, &m.args)?,
        Request::WsTake(m) => ws_take_parts(ctx, m.request_id, &m.args)?,
        Request::WsDrop(m) => ws_drop_parts(ctx, m.request_id, &m.args)?,
        Request::Snapshot(m) => snapshot_parts(ctx, m.request_id, &m.args)?,
        Request::Write(m) => write_parts(ctx, m.request_id, &m.args)?,
        Request::WsRecover(m) => ws_recover_parts(ctx, m.request_id, &m.args)?,
        Request::Describe(m) => describe_parts(ctx, m.request_id, &m.args)?,
        Request::Edit(m) => edit_parts(ctx, m.request_id, &m.args)?,
        Request::Split(m) => split_parts(ctx, m.request_id, &m.args)?,
        Request::Squash(m) => squash_parts(ctx, m.request_id, &m.args)?,
        Request::Rebase(m) => rebase_parts(ctx, m.request_id, &m.args)?,
        Request::Abandon(m) => abandon_parts(ctx, m.request_id, &m.args)?,
        Request::Resolve(m) => resolve_parts(ctx, m.request_id, &m.args)?,
        Request::Revert(m) => revert_parts(ctx, m.request_id, &m.args)?,
        Request::Undo(m) => undo_parts(ctx, m.request_id, &m.args)?,
        Request::Fetch(_) => {
            return Err(uncovered(
                "fetch",
                "fetch stages remote objects before any ref can move, and the transfer plus object ingest run in a transport job: the lane can only publish ref deltas with staged objects plus a ref transaction, and no fetch job producer exists on this path — transport/mirror.rs plus net.rs own the transfer and RemoteObservations rows are written by transport outside the lane",
            ));
        }
        Request::Push(_) => {
            return Err(uncovered(
                "push",
                "push persists a PushPlans row whose codec lives in ruk-git transport (PushPlanRecord manual encoding): staging a second core-side encoding would corrupt the table for transport readers, and the send leg runs as a transport job after the plan commits, with no producer for either on this path",
            ));
        }
        Request::PushReconcile(_) => {
            return Err(uncovered(
                "push.reconcile",
                "push.reconcile observes the remote's live refs for an uncertain plan: observation is a network round-trip, not lane work, and RemoteObservations rows are written by transport outside the lane, so no preparation exists on this path",
            ));
        }
        Request::LandPrepare(m) => land_prepare_parts(ctx, m.request_id, &m.args)?,
        Request::PolicySet(m) => policy_set_parts(ctx, m.request_id, &m.args)?,
        Request::LandExecute(m) => land_execute_parts(ctx, m.request_id, &m.args)?,
        Request::OpPrune(_) => {
            return Err(uncovered(
                "op.prune",
                "pruning needs an operation-retention policy, and none exists: the retention sweep covers receipts and sessions only, so no operation is ever expired; its sweep cursor lives in the lane-owned OpHead row, which only the internal Sweep candidate may advance, and that candidate writes no receipt for this reply",
            ));
        }
        _ => {
            return Err(CoreError::new(
                ErrorCode::EHosted,
                format!(
                    "method `{}` does not cover preparation: no per-method preparation exists on this path",
                    method.as_str(),
                ),
            ));
        }
    };
    let Some(request_id) = request.request_id() else {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "internal: prepared request lost its idempotency key",
        ));
    };
    Ok(PreparedMutation {
        session: ctx.session,
        request_id,
        request,
        reply: parts.reply,
        objects: parts.objects,
        facts: parts.facts,
        workspace_fence: parts.fence,
        ref_transaction: parts.transaction,
        ref_dependencies: parts.dependencies,
        on_behalf_of: ctx.on_behalf_of.clone(),
    })
}

/// Builds the `E_HOSTED` refusal for a method outside the covered subset.
fn uncovered(method: &str, reason: &str) -> CoreError {
    CoreError::new(
        ErrorCode::EHosted,
        format!("method `{method}` does not cover preparation: {reason}"),
    )
}

/// Placeholder outcome header; the lane overwrites `receipt` and `operation`
/// at commit time, so the digest and retention here never escape.
fn pending_outcome(session: SessionId, request_id: RequestId) -> MutationOutcome {
    MutationOutcome {
        receipt: ReceiptRef {
            session,
            request_id,
            digest: RequestDigest::from_bytes([0; 32]),
            replayed: false,
            retained_until: Timestamp::new(jiff::Timestamp::now()),
        },
        operation: None,
        heads: BoundedList::complete(Vec::new()).expect("empty heads fit"),
        stamps: BoundedList::complete(Vec::new()).expect("empty stamps fit"),
        warnings: BoundedList::complete(Vec::new()).expect("empty warnings fit"),
        merge: None,
        provenance: BoundedList::complete(Vec::new()).expect("empty provenance fits"),
        identity: None,
    }
}

/// Checks one ref update against the store and lowers it to exact facts.
fn check_ref_update(
    store: &Store,
    update: RefUpdate,
) -> Result<(Vec<FactMutation>, RefTransaction), CoreError> {
    let transaction =
        RefTransaction::new(store.hash_kind(), vec![update]).map_err(CoreError::from)?;
    transaction.check(&StoreRefs::new(store))?;
    let prepared = prepare_checked_transaction(store, &transaction)?;
    Ok((prepared.into_mutations(), transaction))
}

fn bookmark_set_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &BookmarkSetArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    // A commit target points at its object directly; a change target
    // resolves through the stored change entry to the Git commit a
    // bookmark may name.
    let oid = match &args.target {
        BookmarkTarget::Commit { oid } => *oid,
        BookmarkTarget::Change { change } => resolve_change_target(store, change)?,
    };
    let name = args.name.clone();
    let (facts, transaction) = check_ref_update(
        store,
        RefUpdate {
            name: name.clone(),
            expected: args.expected.clone(),
            change: RefChange::Set(RefTarget::Direct(oid)),
        },
    )?;
    Ok(Parts {
        reply: Reply::BookmarkSet(Box::new(BookmarkSetReply {
            outcome: pending_outcome(session, request_id),
            name: name.clone(),
            target: oid,
        })),
        objects: Vec::new(),
        facts,
        transaction: Some(transaction),
        dependencies: vec![name],
        fence: None,
    })
}

/// Resolves a [`ChangeRef`] to the Git commit a bookmark can point at.
///
/// # Errors
/// - [`ErrorCode::ENotFound`] when the change is not stored.
/// - [`ErrorCode::EStale`] when the pinned head is not a current head of
///   the change.
/// - [`ErrorCode::EDivergent`] when the change has several current heads
///   and the reference pins none.
/// - [`ErrorCode::EInvalid`] when the resolved head is conflicted: a native
///   conflicted commit cannot become a Git ref.
fn resolve_change_target(store: &Store, target: &ChangeRef) -> Result<Oid, CoreError> {
    let entry = Records::new(store)
        .get_change(&target.change)?
        .ok_or_else(|| {
            CoreError::new(
                ErrorCode::ENotFound,
                format!("change {} is not stored", target.change),
            )
        })?;
    let head = match target.head {
        Some(head) => {
            if !entry.contains_head(&head) {
                return Err(CoreError::new(
                    ErrorCode::EStale,
                    format!(
                        "pinned head is not a current head of change {}",
                        target.change
                    ),
                ));
            }
            head
        }
        None => match entry.heads.as_slice() {
            [head] => *head,
            _ => {
                return Err(CoreError::new(
                    ErrorCode::EDivergent,
                    format!(
                        "change {} has {} current heads; pin one with head",
                        target.change,
                        entry.heads.len()
                    ),
                ));
            }
        },
    };
    head.as_git().copied().ok_or_else(|| {
        CoreError::new(
            ErrorCode::EInvalid,
            "a conflicted head cannot become a Git ref".to_string(),
        )
    })
}

fn bookmark_delete_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &BookmarkDeleteArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    let name = args.name.clone();
    let (facts, transaction) = check_ref_update(
        store,
        RefUpdate {
            name: name.clone(),
            expected: args.expected.clone(),
            change: RefChange::Delete,
        },
    )?;
    Ok(Parts {
        reply: Reply::BookmarkDelete(Box::new(BookmarkDeleteReply {
            outcome: pending_outcome(session, request_id),
        })),
        objects: Vec::new(),
        facts,
        transaction: Some(transaction),
        dependencies: vec![name],
        fence: None,
    })
}

fn bookmark_resolve_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &BookmarkResolveArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    // No caller-supplied ref expectation exists for a resolve; the conflict
    // terms are the compare-and-swap, checked and lowered in a single read
    // so the terms and the clear expectation cannot disagree.
    let change = match &args.resolution {
        BookmarkResolution::Set { oid } => RefChange::Set(RefTarget::Direct(*oid)),
        BookmarkResolution::Delete => RefChange::Delete,
    };
    let name = args.name.clone();
    let clear = prepare_clear_ref_conflict_checked(store, &name, &args.expected_terms)?;
    let (mut facts, transaction) = check_ref_update(
        store,
        RefUpdate {
            name: name.clone(),
            expected: RefExpect::Any,
            change,
        },
    )?;
    facts.push(clear);
    Ok(Parts {
        reply: Reply::BookmarkResolve(Box::new(BookmarkResolveReply {
            outcome: pending_outcome(session, request_id),
        })),
        objects: Vec::new(),
        facts,
        transaction: Some(transaction),
        dependencies: vec![name],
        fence: None,
    })
}

fn tag_set_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &TagSetArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    // An annotated tag points the ref at a rendered tag object, not at the
    // target commit: the tagger comes from the annotation or the session
    // identity, and the tagger timestamp comes from the coordinator clock.
    let Some(annotation) = &args.annotation else {
        let name = args.name.clone();
        let (facts, transaction) = check_ref_update(
            store,
            RefUpdate {
                name: name.clone(),
                expected: args.expected.clone(),
                change: RefChange::Set(RefTarget::Direct(args.target)),
            },
        )?;
        return Ok(Parts {
            reply: Reply::TagSet(Box::new(TagSetReply {
                outcome: pending_outcome(session, request_id),
                name: name.clone(),
                target: RefTarget::Direct(args.target),
            })),
            objects: Vec::new(),
            facts,
            transaction: Some(transaction),
            dependencies: vec![name],
            fence: None,
        });
    };
    let clock = ctx.clock.ok_or_else(|| {
        uncovered(
            "tag.set",
            "`tag.set` with an annotation needs the coordinator clock for the tagger timestamp, which this path does not supply",
        )
    })?;
    let tagger = annotation
        .tagger
        .clone()
        .or_else(|| ctx.session_row.and_then(|row| row.identity.clone()))
        .ok_or_else(|| {
            CoreError::new(
                ErrorCode::EInvalid,
                "annotated `tag.set` needs a tagger: neither the annotation nor the session carries an identity",
            )
        })?;
    tagger.validate()?;
    let short = args
        .name
        .as_bytes()
        .strip_prefix(b"refs/tags/")
        .ok_or_else(|| {
            CoreError::new(ErrorCode::EInvalid, "a tag name must live under refs/tags/")
        })?;
    // An annotated tag object declares `type commit`: the target must be a
    // stored commit, the way `pin` refuses unstored heads, so a tag never
    // renders a commit header for bytes the store cannot serve.
    if Records::new(store)
        .get_commit(&Head::Git { oid: args.target })?
        .is_none()
    {
        return Err(CoreError::new(
            ErrorCode::ENotFound,
            format!("tag target {} is not a stored commit", args.target),
        ));
    }
    let secs = clock.sample()?.timestamp().instant().as_second();
    let payload = tag_payload(
        args.target,
        short,
        &tagger,
        annotation.message.as_bytes(),
        secs,
    );
    let oid = store
        .hash_kind()
        .hash_git_object("tag", &payload)
        .map_err(CoreError::from)?;
    let len = u64::try_from(payload.len())
        .map_err(|_| CoreError::new(ErrorCode::ELimit, "tag object exceeds the length bound"))?;
    // The identity is deterministic, so re-staging a stored object would be
    // harmless; skipping it keeps duplicate bytes out of the spool.
    let staged = match store.object_len(oid).map_err(CoreError::from)? {
        Some(_) => None,
        None => Some(
            store
                .prepare(ObjectKind::Tag, len, &payload[..], None)
                .map_err(CoreError::from)?,
        ),
    };
    let name = args.name.clone();
    let (facts, transaction) = check_ref_update(
        store,
        RefUpdate {
            name: name.clone(),
            expected: args.expected.clone(),
            change: RefChange::Set(RefTarget::Direct(oid)),
        },
    )?;
    Ok(Parts {
        reply: Reply::TagSet(Box::new(TagSetReply {
            outcome: pending_outcome(session, request_id),
            name: name.clone(),
            target: RefTarget::Direct(oid),
        })),
        objects: staged.into_iter().collect(),
        facts,
        transaction: Some(transaction),
        dependencies: vec![name],
        fence: None,
    })
}

/// Renders the canonical Git tag object for an annotated `tag.set`.
///
/// Layout mirrors `git mktag`: `object <oid>\ntype commit\ntag <short>\n`
/// plus a UTC tagger line and the raw message. The short name and the
/// message splice in as bytes (ref names need not be UTF-8); the tagger
/// name and email are validated strings, so the tagger line formats.
fn tag_payload(
    target: Oid,
    short: &[u8],
    tagger: &IdentityClaim,
    message: &[u8],
    secs: i64,
) -> Vec<u8> {
    let mut payload = format!("object {target}\ntype commit\ntag ").into_bytes();
    payload.extend_from_slice(short);
    payload.extend_from_slice(
        format!(
            "\ntagger {} <{}> {secs} {}\n\n",
            tagger.name,
            tagger.email,
            TzOffset::UTC
        )
        .as_bytes(),
    );
    payload.extend_from_slice(message);
    payload
}

fn pin_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &PinArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    // A pin is a GC root over a stored head: the key joins the head grammar
    // and presence is the fact, so an unstored head is `E_NOT_FOUND` while
    // re-pinning fails stale at publish on the `Absent` expectation.
    if Records::new(store).get_commit(&args.head)?.is_none() {
        return Err(CoreError::new(
            ErrorCode::ENotFound,
            format!("pin target {:?} is not stored", args.head),
        ));
    }
    Ok(Parts {
        reply: Reply::Pin(Box::new(PinReply {
            outcome: pending_outcome(session, request_id),
        })),
        objects: Vec::new(),
        facts: vec![FactMutation {
            table: FactTable::Pins,
            key: head_key(&args.head),
            expected: FactExpectation::Absent,
            value: Some(Vec::new()),
        }],
        transaction: None,
        dependencies: Vec::new(),
        fence: None,
    })
}

fn unpin_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &UnpinArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    // Unpinning removes the presence fact, so the current bytes are the
    // compare-and-swap expectation and a missing pin is `E_NOT_FOUND`.
    let key = head_key(&args.head);
    let existing = store.fact(FactTable::Pins, &key).map_err(CoreError::from)?;
    let Some(value) = existing else {
        return Err(CoreError::new(
            ErrorCode::ENotFound,
            format!("no pin holds {:?}", args.head),
        ));
    };
    Ok(Parts {
        reply: Reply::Unpin(Box::new(UnpinReply {
            outcome: pending_outcome(session, request_id),
        })),
        objects: Vec::new(),
        facts: vec![FactMutation {
            table: FactTable::Pins,
            key,
            expected: FactExpectation::Value(value),
            value: None,
        }],
        transaction: None,
        dependencies: Vec::new(),
        fence: None,
    })
}

/// Prepares `attest.add` through [`prepare_add`], returning its mutations
/// with exact fact expectations so row publication stays compare-and-swap
/// safe.
///
/// Subject-lease invariant: this arm stages no lease over the attested
/// subject, so a collection mark running in the prepare-to-submit window
/// could condemn an otherwise unrooted subject before the batch commits in
/// lane order. That window is inert today — the only `begin_mark` callers
/// are the `leases`/`barrier` unit tests; no collector runs against a live
/// lane — which is why staging nothing is sound. Once a collector exists,
/// prepare must acquire a subject lease from the lane registry and the
/// prepared mutation must carry it to submit; the `PreparedMutation` shape
/// has no field for that guard yet, so the collector wiring must add the
/// carriage, not just the mark.
fn attest_add_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &AttestAddArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    let Some(checkpoint) = ctx.checkpoint else {
        return Err(uncovered(
            "attest.add",
            "`attest.add` needs the attestation progress gate, which this path does not supply",
        ));
    };
    // `prepare_add` asks for sole publication-lane ownership with a live
    // object lease covering the subject. This path stages no lease: no
    // prepare-to-publish lease carriage exists, and the emitted facts
    // carry exact expectations, so the row publication itself stays
    // compare-and-swap safe. The residual race is a collection mark
    // condemning an unrooted subject in the prepare-to-submit window; once
    // submitted the batch commits atomically in lane order. Staging a
    // subject lease (registry acquire in prepare, release after settle) is
    // follow-up work.
    let prepared = prepare_add(store, args, checkpoint)?;
    let mut records = prepared.records;
    if records.len() != 1 {
        return Err(CoreError::new(
            ErrorCode::ECorrupt,
            "attestation preparation answered a single statement with another record count",
        ));
    }
    let record = records
        .pop()
        .ok_or_else(|| {
            CoreError::new(
                ErrorCode::ECorrupt,
                "attestation preparation returned no record",
            )
        })?
        .record;
    Ok(Parts {
        reply: Reply::AttestAdd(Box::new(AttestAddReply {
            outcome: pending_outcome(session, request_id),
            record,
        })),
        objects: Vec::new(),
        facts: prepared.mutations,
        transaction: None,
        dependencies: Vec::new(),
        fence: None,
    })
}

fn tag_delete_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &TagDeleteArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    let name = args.name.clone();
    let (facts, transaction) = check_ref_update(
        store,
        RefUpdate {
            name: name.clone(),
            expected: args.expected.clone(),
            change: RefChange::Delete,
        },
    )?;
    Ok(Parts {
        reply: Reply::TagDelete(Box::new(TagDeleteReply {
            outcome: pending_outcome(session, request_id),
        })),
        objects: Vec::new(),
        facts,
        transaction: Some(transaction),
        dependencies: vec![name],
        fence: None,
    })
}
/// Mints the empty tree when absent and stages one empty-tree commit through
/// `ops::prepare_new`, synthesizing author and committer from `over` (the
/// operation override) or the session identity.
///
/// The empty tree OID is content-addressed and deterministic. When absent it
/// is published standalone with no facts — an object-only publication whose
/// duplicates the store accepts idempotently — because `ops::prepare_new`
/// only resolves stored trees and a staged-but-unpublished spool object is
/// invisible to its check. No facts, oplog entries, or receipts are touched,
/// so the lane's linearizable state is unaffected; the parent-storage and
/// message-shape pre-checks below run read-only first, so every refusal path
/// exits before any write and only a post-publish store failure could strand
/// the universally reusable empty tree.
///
/// The change id is always freshly generated: `ops::prepare_new` with
/// `change_id: None` would resolve the tree's stable by-OID mapping and pile
/// every empty-tree commit onto one divergent change instead of minting a
/// fresh one.
///
/// # Errors
/// - [`ErrorCode::EHosted`] without the session row (no identity source) or
///   the coordinator clock (no signature timestamp), or over several parents
///   (no tree-merge producer exists on this path).
/// - [`ErrorCode::EInvalid`] with neither an override nor a session identity,
///   or with a malformed identity.
/// - [`ErrorCode::ENotFound`] for an unstored parent.
fn mint_empty_commit(
    ctx: &PrepareContext<'_>,
    method: &str,
    parents: &[Head],
    message: &ByteString,
    over: Option<&IdentityClaim>,
) -> Result<(PreparedOp<NewResult>, EffectiveIdentity), CoreError> {
    let store = ctx.store;
    let row = ctx.session_row.ok_or_else(|| {
        uncovered(
            method,
            "minting an empty-tree commit needs the session identity row for its signature, which this path does not supply",
        )
    })?;
    let clock = ctx.clock.ok_or_else(|| {
        uncovered(
            method,
            "minting an empty-tree commit needs the coordinator clock for its signature timestamp, which this path does not supply",
        )
    })?;
    if parents.len() > 1 {
        return Err(uncovered(
            method,
            "a commit over several parents needs tree-merge evaluation with no producer on this path; supply one parent or none",
        ));
    }
    let (author, identity) = commit_signature(row, clock, method, over)?;
    // Read-only pre-checks before the tree staging below: a refused mint
    // must leave no state, so the checks `prepare_new` would run first run
    // here against committed state. They stay advisory — `prepare_new` and
    // the lane re-check authoritatively at commit time.
    let kind = store.hash_kind();
    for parent in parents {
        parent.validate(kind)?;
        if Records::new(store).get_commit(parent)?.is_none() {
            let describe = match parent {
                Head::Git { oid } => oid.to_string(),
                Head::Conflicted { key } => format!("{key:?}"),
            };
            return Err(CoreError::new(
                ErrorCode::ENotFound,
                format!("parent {describe} is not a stored commit"),
            ));
        }
    }
    if message.as_bytes().contains(&0) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "commit message carries NUL",
        ));
    }
    let empty = store
        .hash_kind()
        .hash_git_object("tree", b"")
        .map_err(CoreError::from)?;
    // The deterministic empty tree rides the lane with the minted commit:
    // staging (never publishing) keeps preparation side-effect free, so a
    // later refusal leaves no state and receipt replay never observes a
    // half-minted commit. `prepare_new` only resolves committed trees, so
    // the tail below replicates its staging against the staged tree instead
    // of calling it.
    let mut staged_prefix = Vec::new();
    if store.object_len(empty).map_err(CoreError::from)?.is_none() {
        let empty_bytes: &[u8] = b"";
        staged_prefix.push(
            store
                .prepare(ObjectKind::Tree, 0, empty_bytes, None)
                .map_err(CoreError::from)?,
        );
    }
    let records = Records::new(store);
    let input = NativeCommitInput {
        change_id: ChangeId::generate(),
        tree: Merge::from_vec(vec![empty]),
        parents: parents.to_vec(),
        predecessor: None,
        author: author.clone(),
        committer: author,
        extra_headers: Vec::new(),
        message: message.clone(),
        provenance: None,
    };
    let staged = records.prepare_native_commit(input)?;
    let head = staged.head;
    let output = NewResult {
        head,
        change_id: staged.record.change_id(),
        oid: head.as_git().copied(),
    };
    if let Some(existing) = records.get_commit(&head)?
        && existing == staged.record
    {
        return Ok((
            PreparedOp {
                objects: staged_prefix,
                facts: Vec::new(),
                output,
            },
            identity,
        ));
    }
    let mut objects = staged_prefix;
    objects.push(staged.prepared_object);
    Ok((
        PreparedOp {
            objects,
            facts: staged.mutations,
            output,
        },
        identity,
    ))
}

/// Prepares `git.commit`: one concrete commit over a caller-staged tree with
/// caller-supplied identities, plus the caller's branch move applied
/// atomically on the lane.
///
/// Preparation is side-effect free: the tree arrives already stored (the
/// caller stages content through its own brief object-only opens, which are
/// content-addressed and idempotent), and every staged object below rides
/// `Parts` to the lane's single linearizable publication. Unlike the
/// empty-tree mint, any parent count is accepted: no tree merge is evaluated
/// because the merged tree arrives precomputed.
///
/// A retried submission whose commit already landed and whose ref already
/// holds it skips the ref transaction, so the lane replays the stored reply
/// (same session, same request id) or succeeds idempotently instead of
/// failing its own compare-and-swap.
///
/// # Errors
/// - [`ErrorCode::EInvalid`] for a message carrying NUL.
/// - [`ErrorCode::EHosted`] when the created head has no Git identity to
///   move a ref to.
/// - [`ErrorCode::ENotFound`] for an unstored tree or parent.
/// - [`ErrorCode::EStale`] from the ref transaction when another writer won.
fn git_commit_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &GitCommitArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    let kind = store.hash_kind();
    if args.message.as_bytes().contains(&0) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "commit message carries NUL",
        ));
    }
    args.tree.expect_kind(kind, "tree")?;
    let records = Records::new(store);
    for parent in &args.parents {
        parent.validate(kind)?;
        if records.get_commit(parent)?.is_none() {
            let describe = match parent {
                Head::Git { oid } => oid.to_string(),
                Head::Conflicted { key } => format!("{key:?}"),
            };
            return Err(CoreError::new(
                ErrorCode::ENotFound,
                format!("parent {describe} is not a stored commit"),
            ));
        }
    }
    let Some(len) = store.object_len(args.tree).map_err(CoreError::from)? else {
        return Err(CoreError::new(
            ErrorCode::ENotFound,
            format!("tree {} is not stored", args.tree),
        ));
    };
    let read = store.read(args.tree).map_err(CoreError::from)?;
    if read.kind != ObjectKind::Tree {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "{} is a {:?} object of {len} bytes, not a tree",
                args.tree, read.kind
            ),
        ));
    }
    let prepared = prepare_new(
        store,
        NewRequest {
            tree: args.tree,
            parents: args.parents.clone(),
            author: args.author.clone(),
            committer: args.committer.clone(),
            message: args.message.clone(),
            change_id: args.change_id,
            predecessor: args.predecessor,
            provenance: None,
        },
    )?;
    let output = prepared.output;
    let new_oid = output
        .oid
        .or_else(|| output.head.as_git().copied())
        .ok_or_else(|| {
            CoreError::new(
                ErrorCode::EHosted,
                "git.commit with `ref_update` needs a head with a Git identity",
            )
        })?;
    let created = ChangeHead {
        change: output.change_id,
        head: output.head,
    };
    let mut facts = prepared.facts;
    let mut transaction = None;
    let mut dependencies = Vec::new();
    if let Some(ref_update) = &args.ref_update {
        let target = RefTarget::Direct(new_oid);
        let landed = prepared.objects.is_empty()
            && StoreRefs::new(store).get(&ref_update.name)?.as_ref() == Some(&target);
        if !landed {
            let (mut ref_facts, ref_transaction) = check_ref_update(
                store,
                RefUpdate {
                    name: ref_update.name.clone(),
                    expected: ref_update.expected.clone(),
                    change: RefChange::Set(target),
                },
            )?;
            facts.append(&mut ref_facts);
            dependencies.push(ref_update.name.clone());
            transaction = Some(ref_transaction);
        }
    }
    Ok(Parts {
        reply: Reply::GitCommit(Box::new(NewReply {
            outcome: pending_outcome(session, request_id),
            created,
            state: None,
        })),
        objects: prepared.objects,
        facts,
        transaction,
        dependencies,
        fence: None,
    })
}

/// Prepares `new`: one empty-tree native change on `parents`, with an
/// optional workspace switch onto the minted head.
///
/// The workspace switch fences the binding and moves a native workspace;
/// switching a GitCompat workspace needs HEAD/index application with no
/// producer on this path, so it stays refused.
///
/// # Errors
/// Same as [`mint_empty_commit`], plus `E_NOT_FOUND` for an unknown
/// workspace and `E_LEASE_LOST`/`E_STALE` from the switch fence.
fn new_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &NewArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    let (prepared, identity) = mint_empty_commit(
        ctx,
        "new",
        &args.parents,
        &args.description,
        args.identity.as_ref(),
    )?;
    let mut outcome = pending_outcome(session, request_id);
    outcome.identity = Some(identity);
    let created = ChangeHead {
        change: prepared.output.change_id,
        head: prepared.output.head,
    };
    let objects = prepared.objects;
    let mut facts = prepared.facts;
    let mut state = None;
    let mut fence = None;
    if let Some(binding) = &args.workspace {
        let observed = workspace::observe(store, binding.workspace)?;
        observed.fence(session, binding.expected)?;
        let WorkspaceState::Native(current) = &observed.row.state else {
            return Err(uncovered(
                "new",
                "switching a GitCompat workspace needs HEAD/index application with no producer on this path",
            ));
        };
        let next = WorkspaceState::Native(current.move_to(
            binding.expected,
            created.change,
            created.head,
        )?);
        let root = observed.row.root.clone();
        facts.push(observed.replace(WorkspaceRow {
            state: next.clone(),
            holder: session,
            root,
        })?);
        state = Some(next);
        fence = Some((binding.workspace, binding.expected));
    }
    Ok(Parts {
        reply: Reply::New(Box::new(NewReply {
            outcome,
            created,
            state,
        })),
        objects,
        facts,
        transaction: None,
        dependencies: Vec::new(),
        fence,
    })
}

/// Prepares `claim.acquire` without sealing: canonicalizes the paths (pure)
/// and checks them against the session's `claim_paths` capability, then
/// mints the id the lane must seal with so the sealed record matches the
/// precomputed reply.
///
/// The expiry below predicts `now + ttl`; the lane overwrites the whole
/// record with the authoritative sealed one after settle, and failures never
/// return a reply, so the prediction never escapes.
///
/// Consistency: the overlap check needs a linearizable commit-time snapshot
/// (sole lane ownership), which preparation does not hold — hence no fence
/// and no claim facts here. The lane re-checks capability-free validity
/// (overlap, ttl) and the candidate's session admission at commit time.
///
/// # Errors
/// - [`ErrorCode::EHosted`] without the session row (no capability source).
/// - [`ErrorCode::EInvalid`] for an empty path set.
/// - [`ErrorCode::EForbidden`] for a path outside the session's claim grant.
fn claim_acquire_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &ClaimAcquireArgs,
) -> Result<Parts, CoreError> {
    let session = ctx.session;
    let row = ctx.session_row.ok_or_else(|| {
        uncovered(
            "claim.acquire",
            "checking the session's `claim_paths` capability needs the session identity row, which this path does not supply",
        )
    })?;
    let paths = canonical_paths(args.paths.clone())?;
    for path in &paths {
        row.capabilities.require_claim(path)?;
    }
    let now = jiff::Timestamp::now();
    let expires_at = Timestamp::new(
        now.checked_add(jiff::SignedDuration::from_secs(i64::from(
            args.ttl.seconds(),
        )))
        .unwrap_or(now),
    );
    Ok(Parts {
        reply: Reply::ClaimAcquire(Box::new(ClaimAcquireReply {
            outcome: pending_outcome(session, request_id),
            claim: ClaimRecord {
                claim: ClaimId::generate(),
                holder: session,
                paths,
                mode: args.mode,
                expires_at,
                on_behalf_of: ctx.on_behalf_of.clone(),
            },
        })),
        objects: Vec::new(),
        facts: Vec::new(),
        transaction: None,
        dependencies: Vec::new(),
        fence: None,
    })
}

/// Prepares `claim.release` without sealing: reads the stored record for an
/// early holder check and predicts the reply. The lane re-reads and seals
/// authoritatively at commit time and overwrites the record.
///
/// # Errors
/// - [`ErrorCode::ENotFound`] for an unknown claim.
/// - [`ErrorCode::EForbidden`] for another session's claim.
fn claim_release_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &ClaimReleaseArgs,
) -> Result<Parts, CoreError> {
    let session = ctx.session;
    let Some(record) = read_record(ctx.store, args.claim)? else {
        return Err(CoreError::new(ErrorCode::ENotFound, "claim does not exist"));
    };
    if record.holder != session {
        return Err(CoreError::new(
            ErrorCode::EForbidden,
            "claim belongs to another session",
        ));
    }
    Ok(Parts {
        reply: Reply::ClaimRelease(Box::new(ClaimReleaseReply {
            outcome: pending_outcome(session, request_id),
            released: record,
        })),
        objects: Vec::new(),
        facts: Vec::new(),
        transaction: None,
        dependencies: Vec::new(),
        fence: None,
    })
}

/// Prepares `ws.new`: one workspace row, natively on a freshly minted
/// empty-tree change over `parents`, or GitCompat at the given HEAD.
///
/// Only the row is written: worktree materialization is a post-commit daemon
/// job, and the host root is stored on the row for the later snapshot, write,
/// and recover job split to resolve. Native creation needs the session
/// identity row and the coordinator clock for the inner commit's signature;
/// GitCompat creation is context-free.
///
/// # Errors
/// Same as [`mint_empty_commit`] for native workspaces, plus `E_LIMIT` for
/// an oversized row, the target validation of a GitCompat HEAD, and
/// `E_NOT_FOUND` for a detached HEAD naming no stored commit.
fn ws_new_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &WsNewArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    let scope = args.scope.clone().unwrap_or(Scope::Full);
    let id = WorkspaceId::generate();
    let mut outcome = pending_outcome(session, request_id);
    let (state, objects, mut facts) = match &args.init {
        WorkspaceInit::Native { parents } => {
            // `ws.new` carries no description: the inner change starts empty.
            let empty_message = ByteString::from("");
            let (prepared, identity) =
                mint_empty_commit(ctx, "ws.new", parents, &empty_message, None)?;
            outcome.identity = Some(identity);
            let state = WorkspaceState::Native(NativeWorkspace::new(
                prepared.output.change_id,
                prepared.output.head,
                scope,
            ));
            (state, prepared.objects, prepared.facts)
        }
        WorkspaceInit::GitCompat { head } => {
            head.validate(store.hash_kind()).map_err(CoreError::from)?;
            if let HeadRef::Detached(oid) = head {
                let stored = Records::new(store)
                    .get_commit(&Head::Git { oid: *oid })?
                    .is_some();
                if !stored {
                    return Err(CoreError::new(
                        ErrorCode::ENotFound,
                        format!("workspace HEAD {oid} is not a stored commit"),
                    ));
                }
            }
            (
                WorkspaceState::GitCompat(GitCompatWorkspace::new(head.clone(), scope)),
                Vec::new(),
                Vec::new(),
            )
        }
    };
    let encoded = rows::encode(
        "workspace",
        &WorkspaceRow {
            state: state.clone(),
            holder: session,
            root: args.root.clone(),
        },
    )?;
    let key = rows::workspace_key(id).to_vec();
    if key
        .len()
        .checked_add(encoded.len())
        .is_none_or(|pair_bytes| {
            u64::try_from(pair_bytes).is_ok_and(|bytes| bytes > rows::ROW_MAX_BYTES)
        })
    {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "workspace row exceeds the publication row limit",
        ));
    }
    facts.push(FactMutation {
        table: FactTable::Workspaces,
        key,
        expected: FactExpectation::Absent,
        value: Some(encoded),
    });
    Ok(Parts {
        reply: Reply::WsNew(Box::new(WsNewReply {
            outcome,
            workspace: id,
            state,
        })),
        objects,
        facts,
        transaction: None,
        dependencies: Vec::new(),
        fence: None,
    })
}

/// Prepares `edit`: checks a resolved change out into a workspace through
/// `NativeWorkspace::move_to`, fencing at the binding's stamp. This is a
/// workspace transition, not a commit rewrite: `ops::edit` is unrelated and
/// stays uncalled.
///
/// File materialization is not part of the lane commit: the daemon opens a
/// `WsApply` journal after publication. The wire reply carries only the
/// resulting state, which matches `EditReply`.
///
/// # Errors
/// - [`ErrorCode::ENotFound`] for an unknown workspace or an unstored change.
/// - [`ErrorCode::ELeaseLost`] when another session holds the workspace.
/// - [`ErrorCode::EStale`] for a moved stamp or a pinned head that is no
///   longer current.
/// - [`ErrorCode::EDivergent`] for an unpinned divergent change.
/// - [`ErrorCode::EHosted`] for a GitCompat workspace: moving it needs
///   HEAD/index application with no producer on this path.
fn edit_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &EditArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    let observed = workspace::observe(store, args.binding.workspace)?;
    observed.fence(session, args.binding.expected)?;
    let (change, head) = resolve_rewrite_head(store, &args.target)?;
    let WorkspaceState::Native(current) = &observed.row.state else {
        return Err(uncovered(
            "edit",
            "moving a GitCompat workspace needs HEAD/index application with no producer on this path",
        ));
    };
    let next = WorkspaceState::Native(current.move_to(args.binding.expected, change, head)?);
    let root = observed.row.root.clone();
    let fact = observed.replace(WorkspaceRow {
        state: next.clone(),
        holder: session,
        root,
    })?;
    Ok(Parts {
        reply: Reply::Edit(Box::new(EditReply {
            outcome: pending_outcome(session, request_id),
            state: next,
        })),
        objects: Vec::new(),
        facts: vec![fact],
        transaction: None,
        dependencies: Vec::new(),
        fence: Some((args.binding.workspace, args.binding.expected)),
    })
}

/// Prepares `ws.scope`: replaces the workspace scope through
/// `WorkspaceState::rescope`, advancing the stamp once. Serves both workspace
/// kinds: scope is kind-independent.
///
/// # Errors
/// - [`ErrorCode::ENotFound`] for an unknown workspace.
/// - [`ErrorCode::ELeaseLost`] when another session holds the workspace.
/// - [`ErrorCode::EStale`] for a moved stamp.
fn ws_scope_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &WsScopeArgs,
) -> Result<Parts, CoreError> {
    let session = ctx.session;
    let observed = workspace::observe(ctx.store, args.binding.workspace)?;
    observed.fence(session, args.binding.expected)?;
    let next = observed
        .row
        .state
        .rescope(args.binding.expected, args.scope.clone())?;
    let root = observed.row.root.clone();
    let fact = observed.replace(WorkspaceRow {
        state: next.clone(),
        holder: session,
        root,
    })?;
    Ok(Parts {
        reply: Reply::WsScope(Box::new(WsScopeReply {
            outcome: pending_outcome(session, request_id),
            state: next,
        })),
        objects: Vec::new(),
        facts: vec![fact],
        transaction: None,
        dependencies: Vec::new(),
        fence: Some((args.binding.workspace, args.binding.expected)),
    })
}

/// Prepares `ws.take`: advances the lease epoch through `WorkspaceState::take`
/// so the taker fences the previous holder. A pinned take fences at the given
/// stamp; an unpinned take seizes the workspace from whoever holds it and
/// carries no lane fence (the lane would re-check holder against the still-old
/// row). The exact row fact stays compare-and-swap either way.
///
/// # Errors
/// - [`ErrorCode::ENotFound`] for an unknown workspace.
/// - [`ErrorCode::ELeaseLost`] when a pinned take names another holder's
///   stamp.
/// - [`ErrorCode::EStale`] for a moved stamp on a pinned take.
fn ws_take_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &WsTakeArgs,
) -> Result<Parts, CoreError> {
    let session = ctx.session;
    let observed = workspace::observe(ctx.store, args.workspace)?;
    let fence = match args.expected {
        Some(expected) => {
            observed.fence(session, expected)?;
            Some((args.workspace, expected))
        }
        None => None,
    };
    let next = observed.row.state.take()?;
    let root = observed.row.root.clone();
    let fact = observed.replace(WorkspaceRow {
        state: next.clone(),
        holder: session,
        root,
    })?;
    Ok(Parts {
        reply: Reply::WsTake(Box::new(WsTakeReply {
            outcome: pending_outcome(session, request_id),
            state: next,
        })),
        objects: Vec::new(),
        facts: vec![fact],
        transaction: None,
        dependencies: Vec::new(),
        fence,
    })
}

/// Prepares `ws.drop`: removes the workspace row; user files are never
/// touched. The fence still guards the stamp so a drop never lands over a
/// concurrent workspace move.
///
/// # Errors
/// - [`ErrorCode::ENotFound`] for an unknown workspace.
/// - [`ErrorCode::ELeaseLost`] when another session holds the workspace.
/// - [`ErrorCode::EStale`] for a moved stamp.
fn ws_drop_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &WsDropArgs,
) -> Result<Parts, CoreError> {
    let session = ctx.session;
    let observed = workspace::observe(ctx.store, args.binding.workspace)?;
    observed.fence(session, args.binding.expected)?;
    let fact = observed.remove();
    Ok(Parts {
        reply: Reply::WsDrop(Box::new(WsDropReply {
            outcome: pending_outcome(session, request_id),
        })),
        objects: Vec::new(),
        facts: vec![fact],
        transaction: None,
        dependencies: Vec::new(),
        fence: Some((args.binding.workspace, args.binding.expected)),
    })
}

/// Validates the binding and journal state shared by the dirty-state methods,
/// returning the observed workspace. The worktree crawl itself runs outside
/// preparation (see [`snapshot_parts`]), so this covers only what the store
/// can answer purely.
fn gate_dirty_workspace(
    ctx: &PrepareContext<'_>,
    method: &str,
    binding: &WorkspaceBinding,
) -> Result<ObservedWorkspace, CoreError> {
    let observed = workspace::observe(ctx.store, binding.workspace)?;
    observed.fence(ctx.session, binding.expected)?;
    ensure_idle(&NoJournal, ctx.store, binding.workspace).map(|_| ())?;
    if observed.row.root.is_empty() {
        return Err(uncovered(
            method,
            "resolving the worktree needs the row root (WorkspaceRow.root), which rows written before the root field do not carry; re-create the workspace through `ws.new`",
        ));
    }
    Ok(observed)
}

/// Refuses `snapshot` after its pure checks. Capturing the worktree needs a
/// crawl, blob hashing, and a tree rebuild through `workcopy::snapshot`,
/// which does file I/O and cannot run inside preparation without holding the
/// lane. The honest shape is a prepare/job split — prepare stages the fence
/// plus the expectation, a post-commit job applies the bytes — with no job
/// producer on this path, so preparation stops at the refusal.
///
/// # Errors
/// - [`ErrorCode::ENotFound`] for an unknown workspace.
/// - [`ErrorCode::ELeaseLost`] when another session holds the workspace.
/// - [`ErrorCode::EStale`] for a moved stamp.
/// - [`ErrorCode::EWorkspaceApplying`] while a materialization is open.
/// - [`ErrorCode::EHosted`] naming the missing job split (or the missing row
///   root on pre-root rows).
fn snapshot_parts(
    ctx: &PrepareContext<'_>,
    _request_id: RequestId,
    args: &SnapshotArgs,
) -> Result<Parts, CoreError> {
    gate_dirty_workspace(ctx, "snapshot", &args.binding)?;
    Err(uncovered(
        "snapshot",
        "capturing the worktree needs a crawl, blob hashing, and a tree rebuild through workcopy::snapshot, which does file I/O and cannot run inside preparation without holding the lane; the prepare/job split (fence plus expectation in prepare, bytes in a post-commit job) has no producer on this path",
    ))
}

/// Refuses `write` after its pure checks. Hashing the named paths and
/// rebuilding the tree through `workcopy::write` is file I/O with the same
/// lane-holding problem as [`snapshot_parts`]; the prepare/job split has no
/// producer on this path.
///
/// # Errors
/// Same as [`snapshot_parts`].
fn write_parts(
    ctx: &PrepareContext<'_>,
    _request_id: RequestId,
    args: &WriteArgs,
) -> Result<Parts, CoreError> {
    gate_dirty_workspace(ctx, "write", &args.binding)?;
    Err(uncovered(
        "write",
        "hashing the named paths and rebuilding the tree through workcopy::write does file I/O and cannot run inside preparation without holding the lane; the prepare/job split (fence plus expectation in prepare, bytes in a post-commit job) has no producer on this path",
    ))
}

/// Refuses `ws.recover` after its pure checks. Resolving the open journal
/// through `workcopy_journal::recover` reads and writes the worktree, which
/// cannot run inside preparation without holding the lane; the prepare/job
/// split has no producer on this path. Unlike `snapshot` and `write`, an open
/// journal is the normal case here, so no idle check applies.
///
/// # Errors
/// - [`ErrorCode::ENotFound`] for an unknown workspace.
/// - [`ErrorCode::ELeaseLost`] when another session holds the workspace.
/// - [`ErrorCode::EStale`] for a moved stamp.
/// - [`ErrorCode::EHosted`] naming the missing job split (or the missing row
///   root on pre-root rows).
fn ws_recover_parts(
    ctx: &PrepareContext<'_>,
    _request_id: RequestId,
    args: &WsRecoverArgs,
) -> Result<Parts, CoreError> {
    let observed = workspace::observe(ctx.store, args.binding.workspace)?;
    observed.fence(ctx.session, args.binding.expected)?;
    if observed.row.root.is_empty() {
        return Err(uncovered(
            "ws.recover",
            "resolving the worktree needs the row root (WorkspaceRow.root), which rows written before the root field do not carry; re-create the workspace through `ws.new`",
        ));
    }
    Err(uncovered(
        "ws.recover",
        "resolving the open journal through workcopy_journal::recover reads and writes the worktree and cannot run inside preparation without holding the lane; the prepare/job split (fence plus expectation in prepare, bytes in a post-commit job) has no producer on this path",
    ))
}

/// Header carrying the native change ID; rewrites preserve every other header.
const CHANGE_ID_HEADER: &[u8] = b"change-id";

/// One resolved rewrite target: its change, its current head, and its record.
struct RewriteTarget {
    change: ChangeId,
    head: Head,
    record: CommitRecord,
}

/// One staged rewrite for the reply: the change, its old and new heads, and
/// whether the new tree is conflicted.
struct StagedRewrite {
    change: ChangeId,
    old: Head,
    new: Head,
    conflicted: bool,
}

fn describe_head(head: &Head) -> String {
    match head {
        Head::Git { oid } => oid.to_string(),
        Head::Conflicted { .. } => "conflicted head".to_string(),
    }
}

fn not_stored(head: &Head) -> CoreError {
    CoreError::new(
        ErrorCode::ENotFound,
        format!("commit {} is not stored", describe_head(head)),
    )
}

/// Resolves a [`ChangeRef`] to its change and current head for a rewrite.
/// Conflicted heads are allowed: rewrites preserve trees, only Git export
/// forbids them.
fn resolve_rewrite_head(store: &Store, target: &ChangeRef) -> Result<(ChangeId, Head), CoreError> {
    let entry = Records::new(store)
        .get_change(&target.change)?
        .ok_or_else(|| {
            CoreError::new(
                ErrorCode::ENotFound,
                format!("change {} is not stored", target.change),
            )
        })?;
    let head = match target.head {
        Some(head) => {
            if !entry.contains_head(&head) {
                return Err(CoreError::new(
                    ErrorCode::EStale,
                    format!(
                        "pinned head is not a current head of change {}",
                        target.change
                    ),
                ));
            }
            head
        }
        None => match entry.heads.as_slice() {
            [head] => *head,
            _ => {
                return Err(CoreError::new(
                    ErrorCode::EDivergent,
                    format!(
                        "change {} has {} current heads; pin one with head",
                        target.change,
                        entry.heads.len()
                    ),
                ));
            }
        },
    };
    Ok((target.change, head))
}

fn load_rewrite_target(store: &Store, target: &ChangeRef) -> Result<RewriteTarget, CoreError> {
    let (change, head) = resolve_rewrite_head(store, target)?;
    let record = Records::new(store)
        .get_commit(&head)?
        .ok_or_else(|| not_stored(&head))?;
    Ok(RewriteTarget {
        change,
        head,
        record,
    })
}

/// Reports the identity a rewrite committed: the committer preserved from the
/// rewritten commit. Rewrites keep the original signatures — new-style
/// synthesis from the session or override identity is a documented deviation —
/// so the reply reports who the new commits actually name. Arms with no
/// single primary commit (`rebase` stages every source with its own
/// committer, `abandon` only re-parents descendants) report `None` instead of
/// a session identity no new commit records.
fn preserved_identity(record: &CommitRecord) -> Result<EffectiveIdentity, CoreError> {
    let committer = record.committer()?;
    Ok(EffectiveIdentity {
        name: String::from_utf8_lossy(committer.name.as_bytes()).into_owned(),
        email: String::from_utf8_lossy(committer.email.as_bytes()).into_owned(),
        source: IdentitySource::Preserved,
    })
}

/// Echoes an explicit merge-mode request in the reply. No content is merged
/// on this path, so an absent selection stays absent.
fn merge_report_of(mode: Option<MergeMode>) -> Result<Option<MergeReport>, CoreError> {
    let Some(effective_mode) = mode else {
        return Ok(None);
    };
    let metadata = MergeMetadata::new(effective_mode, LANGUAGE_SET_VERSION)?;
    Ok(Some(MergeReport::new(metadata, MergeNotices::default())?))
}

/// Observes and fences every listed workspace. The lane carries a single
/// workspace fence, so more than one binding is refused rather than silently
/// fencing the first.
fn gate_workspaces(
    ctx: &PrepareContext<'_>,
    method: &str,
    bindings: &[WorkspaceBinding],
) -> Result<Vec<(WorkspaceBinding, ObservedWorkspace)>, CoreError> {
    if bindings.len() > 1 {
        return Err(uncovered(
            method,
            "listing several workspaces needs one lane fence per binding and the lane carries a single workspace fence; list one workspace",
        ));
    }
    let mut gated = Vec::with_capacity(bindings.len());
    for binding in bindings {
        let observed = workspace::observe(ctx.store, binding.workspace)?;
        observed.fence(ctx.session, binding.expected)?;
        gated.push((*binding, observed));
    }
    Ok(gated)
}

/// The workspace half of a prepared rewrite: row facts plus the lane fence.
type WorkspaceAdvance = (Vec<FactMutation>, Option<(WorkspaceId, WorkspaceStamp)>);

/// Advances a gated workspace onto its rewritten head. A workspace on an
/// unaffected change keeps its state; the fence still guards its stamp. A
/// GitCompat workspace on a rewritten head needs HEAD/index application with
/// no producer here, so that case is refused.
fn advance_workspaces(
    gated: Vec<(WorkspaceBinding, ObservedWorkspace)>,
    session: SessionId,
    method: &str,
    rewrites: &BTreeMap<Head, (ChangeId, Head)>,
) -> Result<WorkspaceAdvance, CoreError> {
    let Some((binding, observed)) = gated.into_iter().next() else {
        return Ok((Vec::new(), None));
    };
    let fence = Some((binding.workspace, binding.expected));
    match &observed.row.state {
        WorkspaceState::Native(current) => {
            let Some((change, new_head)) = rewrites.get(&current.head) else {
                return Ok((Vec::new(), fence));
            };
            let next =
                WorkspaceState::Native(current.move_to(binding.expected, *change, *new_head)?);
            let root = observed.row.root.clone();
            let fact = observed.replace(WorkspaceRow {
                state: next,
                holder: session,
                root,
            })?;
            Ok((vec![fact], fence))
        }
        WorkspaceState::GitCompat(current) => {
            if let HeadRef::Detached(oid) = &current.head
                && rewrites.keys().any(|old| old.as_git() == Some(oid))
            {
                return Err(uncovered(
                    method,
                    "moving a GitCompat workspace needs HEAD/index application with no producer on this path",
                ));
            }
            Ok((Vec::new(), fence))
        }
    }
}

/// Copies extra headers except the change-id header, which the new record
/// re-derives from its change.
fn copy_extra_headers(record: &CommitRecord) -> Vec<ExtraHeader> {
    record
        .extra_headers()
        .iter()
        .filter(|header| header.name.as_bytes() != CHANGE_ID_HEADER)
        .cloned()
        .collect()
}

/// Builds one rewrite commit input preserving everything but the tree and
/// parents.
fn preserved_input(
    record: &CommitRecord,
    tree: Merge<Oid>,
    parents: Vec<Head>,
    predecessor: Option<Head>,
) -> Result<NativeCommitInput, CoreError> {
    Ok(NativeCommitInput {
        change_id: record.change_id(),
        tree,
        parents,
        predecessor,
        author: record.author()?,
        committer: record.committer()?,
        extra_headers: copy_extra_headers(record),
        message: ByteString::from(record.message()),
        provenance: record.provenance().cloned(),
    })
}

/// Remaps rewrite parents through staged rewrites, failing closed when a
/// parent was scheduled for rewrite but is not staged yet: keeping its old
/// head would fork history onto a superseded commit. Parents outside the
/// rewritten set are unmoved and kept as they are.
fn map_strict(
    parents: &[Head],
    rewritten: &BTreeSet<Head>,
    staged: &BTreeMap<Head, Head>,
) -> Result<Vec<Head>, CoreError> {
    parents
        .iter()
        .map(|parent| {
            if rewritten.contains(parent) {
                staged.get(parent).copied().ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::ECorrupt,
                        "internal: rewrite parent staged out of order",
                    )
                })
            } else {
                Ok(*parent)
            }
        })
        .collect()
}

/// Refuses a commit with several parents or none where exactly one base is
/// needed; moving a root grafts a snapshot and moving a merge needs merge
/// evaluation, neither of which exists on this path.
fn require_single_parent(
    record: &CommitRecord,
    method: &str,
    noun: &str,
) -> Result<Head, CoreError> {
    match record.parents() {
        [parent] => Ok(*parent),
        [] => Err(uncovered(
            method,
            &format!("{noun} a root commit grafts a full snapshot with no producer on this path"),
        )),
        _ => Err(uncovered(
            method,
            &format!("{noun} a merge commit needs merge evaluation with no producer on this path"),
        )),
    }
}

/// Refuses a commit carrying content: its resolved tree must equal its single
/// parent's resolved tree, so the move carries no content across bases.
fn require_empty_delta(
    store: &Store,
    method: &str,
    record: &CommitRecord,
    parent: &Head,
) -> Result<(), CoreError> {
    let tree = record.tree().as_resolved().ok_or_else(|| {
        uncovered(
            method,
            "moving a conflicted commit needs merge evaluation with no producer on this path",
        )
    })?;
    let parent_record = Records::new(store)
        .get_commit(parent)?
        .ok_or_else(|| not_stored(parent))?;
    let parent_tree = parent_record.tree().as_resolved().ok_or_else(|| {
        uncovered(
            method,
            "moving onto a conflicted base needs merge evaluation with no producer on this path",
        )
    })?;
    if tree != parent_tree {
        return Err(uncovered(
            method,
            "moving a commit with content changes needs per-commit tree re-derivation over the moved base (ops/tree_edit.rs) with no producer on this path; only content-less commits move here",
        ));
    }
    Ok(())
}

/// Refuses a kept tree over changed content: the kept tree must equal the new
/// single base's tree, else re-parenting would silently carry stale content.
fn require_kept_tree(method: &str, kept: &Oid, base: &Oid) -> Result<(), CoreError> {
    if kept != base {
        return Err(uncovered(
            method,
            "re-parenting a commit with content changes needs per-commit tree re-derivation over the new base (ops/tree_edit.rs) with no producer on this path; only content-less descendants move here",
        ));
    }
    Ok(())
}

/// Reads the tree a new base carries: a staged rewrite's tree, else the
/// stored commit's resolved tree.
fn new_base_tree(
    store: &Store,
    method: &str,
    new_trees: &BTreeMap<Head, Oid>,
    base: &Head,
) -> Result<Oid, CoreError> {
    if let Some(tree) = new_trees.get(base) {
        return Ok(*tree);
    }
    let record = Records::new(store)
        .get_commit(base)?
        .ok_or_else(|| not_stored(base))?;
    record.tree().as_resolved().copied().ok_or_else(|| {
        uncovered(
            method,
            "re-parenting onto a conflicted base needs merge evaluation with no producer on this path",
        )
    })
}

/// Merges staged Changes-table facts colliding on one change key, returning
/// the merged facts plus the final entry per touched change.
///
/// Two staged batches (an ops root rewrite plus descendant re-parenting, or
/// rewrites plus abandon transitions) collide when a rewritten descendant
/// shares the root's change. Both facts carry the same `Value(old)`
/// expectation from the same committed snapshot; the merged fact keeps it and
/// unions the head transitions. Anything else colliding is an internal error.
fn merge_changes_facts(
    store: &Store,
    staged: Vec<FactMutation>,
    extra: Vec<FactMutation>,
) -> Result<(Vec<FactMutation>, BTreeMap<ChangeId, ChangeEntry>), CoreError> {
    let mut others = Vec::new();
    let mut seen_keys = BTreeSet::new();
    let mut grouped: BTreeMap<Vec<u8>, Vec<FactMutation>> = BTreeMap::new();
    for fact in staged.into_iter().chain(extra) {
        if fact.table == FactTable::Changes {
            grouped.entry(fact.key.clone()).or_default().push(fact);
        } else {
            if !seen_keys.insert((fact.table, fact.key.clone())) {
                return Err(CoreError::new(
                    ErrorCode::ECorrupt,
                    "internal: staged batches collide outside the Changes table",
                ));
            }
            others.push(fact);
        }
    }
    let mut facts = others;
    let mut finals = BTreeMap::new();
    for (key, group) in grouped {
        let bytes: [u8; ChangeId::LEN] = key
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::new(ErrorCode::ECorrupt, "internal: malformed change key"))?;
        let change = ChangeId::from_bytes(bytes);
        let [first, rest @ ..] = group.as_slice() else {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "internal: empty change group",
            ));
        };
        let FactExpectation::Value(expected) = &first.expected else {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "internal: Changes fact without an exact expectation",
            ));
        };
        let old_entry = decode_change_entry(store, &change, expected)?;
        let final_entry = match rest {
            [] => decode_value_entry(store, &change, first)?,
            [second] => {
                let FactExpectation::Value(second_old) = &second.expected else {
                    return Err(CoreError::new(
                        ErrorCode::ECorrupt,
                        "internal: Changes fact without an exact expectation",
                    ));
                };
                if second_old != expected {
                    return Err(CoreError::new(
                        ErrorCode::ECorrupt,
                        "internal: staged batches disagree on a change entry",
                    ));
                }
                let first_new = decode_value_entry(store, &change, first)?;
                let second_new = decode_value_entry(store, &change, second)?;
                union_entries(&old_entry, &first_new, &second_new).ok_or_else(|| {
                    CoreError::new(
                        ErrorCode::ECorrupt,
                        "internal: staged batches drain a change without abandoning it",
                    )
                })?
            }
            _ => {
                return Err(CoreError::new(
                    ErrorCode::ECorrupt,
                    "internal: more than two staged batches touch one change",
                ));
            }
        };
        facts.push(FactMutation {
            table: FactTable::Changes,
            key,
            expected: FactExpectation::Value(expected.clone()),
            value: Some(encode_change_entry(&final_entry)?),
        });
        finals.insert(change, final_entry);
    }
    Ok((facts, finals))
}

fn decode_value_entry(
    store: &Store,
    _change: &ChangeId,
    fact: &FactMutation,
) -> Result<ChangeEntry, CoreError> {
    let Some(value) = &fact.value else {
        return Err(CoreError::new(
            ErrorCode::ECorrupt,
            "internal: Changes fact without a value",
        ));
    };
    decode_staged_entry(store, value)
}

/// Decodes a staged change value produced in this call. Unlike
/// [`decode_change_entry`], a drained (abandoned, headless) entry is valid:
/// staged abandon transitions write exactly that. Staged bytes never come
/// from the store, so quarantine latching does not apply; non-empty values
/// still validate exactly like stored ones.
fn decode_staged_entry(store: &Store, value: &[u8]) -> Result<ChangeEntry, CoreError> {
    let entry: ChangeEntry = postcard::from_bytes(value).map_err(|err| {
        CoreError::new(
            ErrorCode::ECorrupt,
            format!("internal: staged change entry does not decode: {err}"),
        )
    })?;
    if entry.heads.is_empty() {
        if entry.state != ChangeState::Abandoned {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "internal: staged change entry drains without abandoning",
            ));
        }
        return Ok(entry);
    }
    entry.validate(store.hash_kind()).map_err(CoreError::from)?;
    Ok(entry)
}

/// Unions two head transitions over the same committed entry: a surviving
/// head must be untouched by both batches (present in each new list — either
/// batch may have replaced it), heads added by either batch are added in
/// staged order, and the change drains only when a batch marked it abandoned.
///
/// The merged entry is `None` when it would drain without abandoning: an
/// empty headless active entry must never reach the store, so the caller
/// fails closed instead of publishing it.
fn union_entries(
    old: &ChangeEntry,
    first: &ChangeEntry,
    second: &ChangeEntry,
) -> Option<ChangeEntry> {
    let mut heads: Vec<Head> = old
        .heads
        .iter()
        .filter(|head| first.contains_head(head) && second.contains_head(head))
        .copied()
        .collect();
    for entry in [first, second] {
        for head in &entry.heads {
            if !old.contains_head(head) && !heads.contains(head) {
                heads.push(*head);
            }
        }
    }
    heads.sort_unstable();
    if heads.is_empty() {
        if first.state == ChangeState::Abandoned || second.state == ChangeState::Abandoned {
            return Some(ChangeEntry {
                state: ChangeState::Abandoned,
                heads,
            });
        }
        return None;
    }
    Some(ChangeEntry {
        state: old.state,
        heads,
    })
}

/// Builds the shared rewrite reply: staged rewrites in order, drained changes
/// abandoned, rewritten conflicted heads flagged, and every new head listed
/// for discovery.
fn rewrite_reply(
    session: SessionId,
    request_id: RequestId,
    identity: Option<EffectiveIdentity>,
    merge: Option<MergeReport>,
    staged: &[StagedRewrite],
    abandoned: Vec<ChangeId>,
) -> Result<RewriteReply, CoreError> {
    let mut outcome = pending_outcome(session, request_id);
    outcome.identity = identity;
    outcome.merge = merge;
    outcome.heads = BoundedList::complete(
        staged
            .iter()
            .map(|rewrite| ChangeHead {
                change: rewrite.change,
                head: rewrite.new,
            })
            .collect(),
    )?;
    Ok(RewriteReply {
        outcome,
        rewrites: BoundedList::complete(
            staged
                .iter()
                .map(|rewrite| HeadRewrite {
                    change: rewrite.change,
                    old: rewrite.old,
                    new: rewrite.new,
                })
                .collect(),
        )?,
        abandoned: BoundedList::complete(abandoned)?,
        conflicted: BoundedList::complete(
            staged
                .iter()
                .filter(|rewrite| rewrite.conflicted)
                .map(|rewrite| ChangeHead {
                    change: rewrite.change,
                    head: rewrite.new,
                })
                .collect(),
        )?,
    })
}

/// Prepares `describe`: rewrites the target's message through
/// `ops::prepare_edit` with the tree preserved, re-parenting descendants with
/// unchanged trees in the same batch. A message rewrite moves no content, so
/// descendants of any shape keep their trees soundly.
///
/// # Errors
/// - [`ErrorCode::EInvalid`] when the description matches the current message.
/// - [`ErrorCode::ENotFound`], [`ErrorCode::EStale`], or
///   [`ErrorCode::EDivergent`] from target resolution.
/// - [`ErrorCode::EHosted`] for several workspace bindings or a GitCompat
///   workspace on a rewritten head.
fn describe_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &DescribeArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    let target = load_rewrite_target(store, &args.target)?;
    if args.description.as_bytes() == target.record.message() {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "method `describe` needs a new description: it is identical to the current message",
        ));
    }
    let prepared = prepare_edit(
        store,
        EditRequest {
            head: target.head,
            tree: None,
            message: Some(args.description.clone()),
            author: None,
            committer: None,
        },
    )?;
    let mut staged = vec![StagedRewrite {
        change: target.change,
        old: target.head,
        new: prepared.output.head,
        conflicted: target.record.tree().as_resolved().is_none(),
    }];
    let mut head_map = BTreeMap::from([(target.head, prepared.output.head)]);
    let mut objects = prepared.objects;
    let root_facts = prepared.facts;
    let records = Records::new(store);
    let mut preparer = records.batch_preparer();
    let closure = descendants(store, &[target.head])?;
    let rewritten: BTreeSet<Head> = closure
        .iter()
        .copied()
        .chain(std::iter::once(target.head))
        .collect();
    for old in closure {
        let record = records.get_commit(&old)?.ok_or_else(|| not_stored(&old))?;
        let input = preserved_input(
            &record,
            record.tree().clone(),
            map_strict(record.parents(), &rewritten, &head_map)?,
            Some(old),
        )?;
        let new = preparer.add_native_commit(input)?;
        head_map.insert(old, new);
        staged.push(StagedRewrite {
            change: record.change_id(),
            old,
            new,
            conflicted: record.tree().as_resolved().is_none(),
        });
    }
    let batch = preparer.finish()?;
    objects.extend(batch.prepared_objects);
    let (mut facts, _) = merge_changes_facts(store, root_facts, batch.mutations)?;
    let gated = gate_workspaces(ctx, "describe", &args.workspaces)?;
    let rewrite_map: BTreeMap<Head, (ChangeId, Head)> = staged
        .iter()
        .map(|rewrite| (rewrite.old, (rewrite.change, rewrite.new)))
        .collect();
    let (mut workspace_facts, fence) =
        advance_workspaces(gated, session, "describe", &rewrite_map)?;
    facts.append(&mut workspace_facts);
    let reply = rewrite_reply(
        session,
        request_id,
        Some(preserved_identity(&target.record)?),
        None,
        &staged,
        Vec::new(),
    )?;
    Ok(Parts {
        reply: Reply::Describe(Box::new(reply)),
        objects,
        facts,
        transaction: None,
        dependencies: Vec::new(),
        fence,
    })
}

/// One rebase source with its single original parent.
struct RebaseSource {
    change: ChangeId,
    head: Head,
    record: CommitRecord,
    parent: Head,
}

/// Shared lookup tables for planning one rebase descendant's new parents
/// and tree.
struct RebasePlan<'a> {
    store: &'a Store,
    scope: RebaseScope,
    moved: &'a BTreeSet<Head>,
    head_map: &'a BTreeMap<Head, Head>,
    parent_map: &'a BTreeMap<Head, Head>,
    new_trees: &'a BTreeMap<Head, Oid>,
}

/// Plans one rebase descendant's new parents and tree: under
/// `SourceAndDescendants` the descendant must be content-less with its single
/// parent inside the moved set and takes its rewritten parent's tree; under
/// `RevisionsOnly` it re-parents onto the sources' old parents and keeps its
/// tree only when the tree still matches the new base.
fn rebase_descendant_plan(
    plan: &RebasePlan<'_>,
    record: &CommitRecord,
) -> Result<(Vec<Head>, Oid), CoreError> {
    match plan.scope {
        RebaseScope::SourceAndDescendants => {
            let [parent] = record.parents() else {
                return Err(uncovered(
                    "rebase",
                    "rebasing a merge commit needs merge evaluation with no producer on this path",
                ));
            };
            if !plan.moved.contains(parent) {
                return Err(uncovered(
                    "rebase",
                    "rebase moves a commit with a parent outside the moved set and needs merge evaluation with no producer on this path",
                ));
            }
            require_empty_delta(plan.store, "rebase", record, parent)?;
            let new_parent = plan.head_map.get(parent).copied().ok_or_else(|| {
                CoreError::new(
                    ErrorCode::ECorrupt,
                    "internal: rebase parent staged out of order",
                )
            })?;
            let tree = plan.new_trees.get(&new_parent).copied().ok_or_else(|| {
                CoreError::new(ErrorCode::ECorrupt, "internal: rebase parent tree missing")
            })?;
            Ok((vec![new_parent], tree))
        }
        RebaseScope::RevisionsOnly => {
            let new_parents = map_strict(record.parents(), plan.moved, plan.parent_map)?;
            let [base] = new_parents.as_slice() else {
                return Err(uncovered(
                    "rebase",
                    "re-parenting a merge commit needs merge evaluation with no producer on this path",
                ));
            };
            let base_tree = new_base_tree(plan.store, "rebase", plan.new_trees, base)?;
            let kept = record.tree().as_resolved().copied().ok_or_else(|| {
                uncovered(
                    "rebase",
                    "re-parenting a conflicted commit needs merge evaluation with no producer on this path",
                )
            })?;
            require_kept_tree("rebase", &kept, &base_tree)?;
            Ok((new_parents, kept))
        }
    }
}

/// Prepares `rebase`: moves content-less sources onto one new parent,
/// deriving the descendant closure by scope and staging the whole moved set
/// through one batch preparer. Sources and `SourceAndDescendants` members
/// must carry no content (tree equal to their single parent's tree); a
/// non-empty commit needs per-commit tree re-derivation over the moved base
/// with no producer here. `RevisionsOnly` descendants keep their trees over
/// their unchanged old bases only when the kept tree still matches.
///
/// # Errors
/// - [`ErrorCode::EInvalid`] when a source is `onto` or onto a descendant,
///   or when nothing moves.
/// - [`ErrorCode::EHosted`] for several onto parents, `keep_empty = false`,
///   overlapping sources, merge or lateral members of the moved set, and
///   content-carrying commits.
fn rebase_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &RebaseArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    let [onto] = args.onto.as_slice() else {
        return Err(uncovered(
            "rebase",
            "rebase onto several parents mints a merge commit and needs merge evaluation with no producer on this path; supply exactly one",
        ));
    };
    if !args.keep_empty {
        return Err(uncovered(
            "rebase",
            "rebase with keep_empty=false drops newly-empty commits and needs empty-chain collapsing with no producer on this path",
        ));
    }
    let onto_record = Records::new(store).get_commit(onto)?.ok_or_else(|| {
        CoreError::new(
            ErrorCode::ENotFound,
            format!("rebase destination {} is not stored", describe_head(onto)),
        )
    })?;
    let onto_tree = onto_record.tree().as_resolved().copied().ok_or_else(|| {
        uncovered(
            "rebase",
            "rebase onto a conflicted commit needs merge evaluation with no producer on this path",
        )
    })?;
    let mut sources = Vec::with_capacity(args.sources.len());
    for source in &args.sources {
        let target = load_rewrite_target(store, source)?;
        if target.head == *onto {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "cannot rebase a commit onto itself",
            ));
        }
        let parent = require_single_parent(&target.record, "rebase", "rebasing")?;
        require_empty_delta(store, "rebase", &target.record, &parent)?;
        sources.push(RebaseSource {
            change: target.change,
            head: target.head,
            record: target.record,
            parent,
        });
    }
    if sources.iter().all(|source| source.parent == *onto) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "method `rebase` moves nothing: every source is already based on onto",
        ));
    }
    let mut moved: BTreeSet<Head> = sources.iter().map(|source| source.head).collect();
    let mut closures = Vec::with_capacity(sources.len());
    for source in &sources {
        let closure = descendants(store, &[source.head])?;
        if closure.contains(onto) {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("cannot rebase onto descendant {}", describe_head(onto)),
            ));
        }
        for member in &closure {
            if !moved.insert(*member) {
                return Err(uncovered(
                    "rebase",
                    "rebase sources overlap (one source descends from another, or they share descendants); rebase one source at a time",
                ));
            }
        }
        closures.push(closure);
    }
    let records = Records::new(store);
    let mut preparer = records.batch_preparer();
    let mut head_map = BTreeMap::new();
    // RevisionsOnly descendants re-parent onto the sources' old parents, not
    // the moved sources, so they map through a separate table seeded here.
    let mut parent_map: BTreeMap<Head, Head> = BTreeMap::new();
    let mut new_trees = BTreeMap::from([(*onto, onto_tree)]);
    let mut staged = Vec::new();
    let mut objects = Vec::new();
    for source in &sources {
        let input = preserved_input(
            &source.record,
            Merge::from_vec(vec![onto_tree]),
            vec![*onto],
            Some(source.head),
        )?;
        let new = preparer.add_native_commit(input)?;
        head_map.insert(source.head, new);
        parent_map.insert(source.head, source.parent);
        new_trees.insert(new, onto_tree);
        staged.push(StagedRewrite {
            change: source.change,
            old: source.head,
            new,
            conflicted: false,
        });
    }
    for (_source, closure) in sources.iter().zip(closures) {
        for old in closure {
            let record = records.get_commit(&old)?.ok_or_else(|| not_stored(&old))?;
            let plan = RebasePlan {
                store,
                scope: args.scope,
                moved: &moved,
                head_map: &head_map,
                parent_map: &parent_map,
                new_trees: &new_trees,
            };
            let (new_parents, new_tree) = rebase_descendant_plan(&plan, &record)?;
            let input = preserved_input(
                &record,
                Merge::from_vec(vec![new_tree]),
                new_parents,
                Some(old),
            )?;
            let new = preparer.add_native_commit(input)?;
            head_map.insert(old, new);
            parent_map.insert(old, new);
            new_trees.insert(new, new_tree);
            staged.push(StagedRewrite {
                change: record.change_id(),
                old,
                new,
                conflicted: false,
            });
        }
    }
    let batch = preparer.finish()?;
    objects.extend(batch.prepared_objects);
    let (mut facts, _) = merge_changes_facts(store, Vec::new(), batch.mutations)?;
    let gated = gate_workspaces(ctx, "rebase", &args.workspaces)?;
    let rewrite_map: BTreeMap<Head, (ChangeId, Head)> = staged
        .iter()
        .map(|rewrite| (rewrite.old, (rewrite.change, rewrite.new)))
        .collect();
    let (mut workspace_facts, fence) = advance_workspaces(gated, session, "rebase", &rewrite_map)?;
    facts.append(&mut workspace_facts);
    // Every source keeps its own committer, so no single recorded identity
    // exists to report.
    let reply = rewrite_reply(
        session,
        request_id,
        None,
        merge_report_of(args.merge.mode)?,
        &staged,
        Vec::new(),
    )?;
    Ok(Parts {
        reply: Reply::Rebase(Box::new(reply)),
        objects,
        facts,
        transaction: None,
        dependencies: Vec::new(),
        fence,
    })
}

/// Prepares `split`: partitions one change's delta by path. The selected
/// paths' changes form a new change; the source identity keeps the remainder.
///
/// The stack always ends in a commit carrying the source's full tree, so the
/// source's descendants keep their trees and only re-parent onto it:
/// - `SelectedFirst`: the new change (parent tree plus the selection) sits
///   below the source identity, whose commit holds the full tree.
/// - `SelectedSecond`: the source identity keeps the remainder (parent tree plus
///   the unselected paths) below the new change, which holds the full tree.
///
/// # Errors
/// - [`ErrorCode::EInvalid`] for `all` paths, an empty selection, a selection
///   that changes nothing, or one that leaves nothing in the source.
/// - [`ErrorCode::EHosted`] for merge sources or parents, conflicted trees, and
///   several workspace bindings or a GitCompat workspace on the rewritten head.
fn split_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &SplitArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    let PathSelection::Paths(paths) = &args.paths else {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "method `split` needs paths: `all` would leave nothing to split",
        ));
    };
    if paths.is_empty() {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "method `split` needs at least one path",
        ));
    }
    let source = load_rewrite_target(store, &args.source)?;
    let source_tree = resolved_tree_of(
        &source.record,
        "split",
        "splitting a conflicted change needs merge evaluation with no producer on this path",
    )?;
    let parent_tree = single_parent_tree(store, &source.record, "split")?;
    let selection = Selection::Paths(paths);
    let selected = apply_delta(store, parent_tree, parent_tree, source_tree, selection)?;
    let remainder = apply_delta(store, source_tree, source_tree, parent_tree, selection)?;
    if selected.root == parent_tree {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "method `split` selects nothing: the selected paths do not change this change",
        ));
    }
    if remainder.root == parent_tree {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "method `split` leaves nothing in the source: the selection covers the whole change",
        ));
    }
    let mut objects = selected.objects;
    push_unique(&mut objects, remainder.objects);
    let selection_change = ChangeId::generate();
    let records = Records::new(store);
    let mut preparer = records.batch_preparer();
    let (source_head, top_head, top_change, selection_head) = match args.placement {
        SplitPlacement::SelectedFirst => {
            let selection_head = preparer.add_native_commit(NativeCommitInput {
                change_id: selection_change,
                tree: Merge::resolved(selected.root),
                parents: source.record.parents().to_vec(),
                predecessor: None,
                author: source.record.author()?,
                committer: source.record.committer()?,
                extra_headers: copy_extra_headers(&source.record),
                message: args.description.clone(),
                provenance: None,
            })?;
            let source_head = preparer.add_native_commit(preserved_input(
                &source.record,
                Merge::resolved(source_tree),
                vec![selection_head],
                Some(source.head),
            )?)?;
            (source_head, source_head, source.change, selection_head)
        }
        SplitPlacement::SelectedSecond => {
            let source_head = preparer.add_native_commit(preserved_input(
                &source.record,
                Merge::resolved(remainder.root),
                source.record.parents().to_vec(),
                Some(source.head),
            )?)?;
            let selection_head = preparer.add_native_commit(NativeCommitInput {
                change_id: selection_change,
                tree: Merge::resolved(source_tree),
                parents: vec![source_head],
                predecessor: None,
                author: source.record.author()?,
                committer: source.record.committer()?,
                extra_headers: copy_extra_headers(&source.record),
                message: args.description.clone(),
                provenance: None,
            })?;
            (
                source_head,
                selection_head,
                selection_change,
                selection_head,
            )
        }
    };
    let mut staged = vec![StagedRewrite {
        change: source.change,
        old: source.head,
        new: source_head,
        conflicted: false,
    }];
    let mut head_map = BTreeMap::from([(source.head, top_head)]);
    let closure = descendants(store, &[source.head])?;
    let rewritten: BTreeSet<Head> = closure
        .iter()
        .copied()
        .chain(std::iter::once(source.head))
        .collect();
    for old in closure {
        let record = records.get_commit(&old)?.ok_or_else(|| not_stored(&old))?;
        let new_parents = map_strict(record.parents(), &rewritten, &head_map)?;
        let input = preserved_input(&record, record.tree().clone(), new_parents, Some(old))?;
        let new = preparer.add_native_commit(input)?;
        head_map.insert(old, new);
        staged.push(StagedRewrite {
            change: record.change_id(),
            old,
            new,
            conflicted: record.tree().as_resolved().is_none(),
        });
    }
    let batch = preparer.finish()?;
    objects.extend(batch.prepared_objects);
    let mut rewrite_map: BTreeMap<Head, (ChangeId, Head)> = staged
        .iter()
        .map(|rewrite| (rewrite.old, (rewrite.change, rewrite.new)))
        .collect();
    rewrite_map.insert(source.head, (top_change, top_head));
    let gated = gate_workspaces(ctx, "split", &args.workspaces)?;
    let (mut workspace_facts, fence) = advance_workspaces(gated, session, "split", &rewrite_map)?;
    let mut facts = batch.mutations;
    facts.append(&mut workspace_facts);
    let mut reply = rewrite_reply(
        session,
        request_id,
        Some(preserved_identity(&source.record)?),
        merge_report_of(args.merge.mode)?,
        &staged,
        Vec::new(),
    )?;
    let mut heads: Vec<ChangeHead> = staged
        .iter()
        .map(|rewrite| ChangeHead {
            change: rewrite.change,
            head: rewrite.new,
        })
        .collect();
    heads.push(ChangeHead {
        change: selection_change,
        head: selection_head,
    });
    reply.outcome.heads = BoundedList::complete(heads)?;
    Ok(Parts {
        reply: Reply::Split(Box::new(reply)),
        objects,
        facts,
        transaction: None,
        dependencies: Vec::new(),
        fence,
    })
}

/// The tree a change's only parent carries, or the empty tree for a root.
/// Merge parents refuse: their trees need merge evaluation.
fn single_parent_tree(
    store: &Store,
    record: &CommitRecord,
    method: &str,
) -> Result<Oid, CoreError> {
    match record.parents() {
        [] => empty_tree(store.hash_kind()),
        [parent] => {
            let commit = Records::new(store)
                .get_commit(parent)?
                .ok_or_else(|| not_stored(parent))?;
            resolved_tree_of(
                &commit,
                method,
                "a change against a conflicted parent needs merge evaluation with no producer on this path",
            )
        }
        _ => Err(uncovered(
            method,
            "a merge commit needs merge evaluation with no producer on this path",
        )),
    }
}

/// Prepares `squash`: moves the selected paths of a source's delta into its
/// destination parent. The source keeps its tree; it is dropped only when
/// emptied (its tree already equals the moved tree) and `keep_empty` is false.
///
/// The source must be a direct only child of the destination, so the
/// destination's tree is the source's parent tree and the move is one
/// three-tree apply per side. Source descendants are re-derived over their new
/// base with [`apply_delta`], so a descendant whose delta collides with the
/// moved paths refuses `E_CONFLICTED` naming them. `ops::prepare_squash`
/// absorbs intra-change chains only, so the cross-change composition stages
/// here through one batch preparer.
///
/// # Errors
/// - [`ErrorCode::EInvalid`] for an empty path list or a move that changes nothing.
/// - [`ErrorCode::EConflicted`] for descendant collisions.
/// - [`ErrorCode::EHosted`] for non-linear placement, siblings of the source,
///   merge commits, and conflicted trees.
fn squash_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &SquashArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    let source = load_rewrite_target(store, &args.source)?;
    let destination = load_rewrite_target(store, &args.destination)?;
    match source.record.parents() {
        [parent] if *parent == destination.head => {}
        [_] => {
            return Err(uncovered(
                "squash",
                "squash needs the source to be a direct child of the destination with no producer for general placement on this path",
            ));
        }
        [] => {
            return Err(uncovered(
                "squash",
                "squash of a root source needs merge evaluation with no producer on this path",
            ));
        }
        _ => {
            return Err(uncovered(
                "squash",
                "squash of a merge source needs merge evaluation with no producer on this path",
            ));
        }
    }
    if children(store, &destination.head)? != vec![source.head] {
        return Err(uncovered(
            "squash",
            "squash with siblings of the source needs sibling tree re-derivation with no producer on this path",
        ));
    }
    let source_tree = resolved_tree_of(
        &source.record,
        "squash",
        "squash of a conflicted source needs merge evaluation with no producer on this path",
    )?;
    let destination_tree = resolved_tree_of(
        &destination.record,
        "squash",
        "squash into a conflicted destination needs merge evaluation with no producer on this path",
    )?;
    let selection = match &args.paths {
        PathSelection::All => Selection::All,
        PathSelection::Paths(paths) if paths.is_empty() => {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "method `squash` needs at least one path or all",
            ));
        }
        PathSelection::Paths(paths) => Selection::Paths(paths),
    };
    // The source's parent is the destination, so its delta is the source tree
    // against the destination tree. The selection moves from one side to the other.
    let moved = apply_delta(
        store,
        destination_tree,
        destination_tree,
        source_tree,
        selection,
    )?;
    if moved.root == destination_tree {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "method `squash` moves nothing: the destination already carries the source content",
        ));
    }
    // The kept source keeps its own tree: the moved selection already lives on
    // the new destination below it, so the source is emptied exactly when its
    // tree equals the moved tree. Reverting the selected paths to the old
    // destination (a "remainder") would revert the moved paths in the source
    // and in every descendant re-derived onto it.
    let keep_source = args.keep_empty || moved.root != source_tree;
    let mut objects = moved.objects;
    let message = match &args.description {
        Some(description) => description.clone(),
        None => ByteString::from(destination.record.message()),
    };
    let records = Records::new(store);
    let mut preparer = records.batch_preparer();
    let destination_input = NativeCommitInput {
        change_id: destination.change,
        tree: Merge::resolved(moved.root),
        parents: destination.record.parents().to_vec(),
        predecessor: Some(destination.head),
        author: destination.record.author()?,
        committer: source.record.committer()?,
        extra_headers: copy_extra_headers(&destination.record),
        message,
        provenance: destination.record.provenance().cloned(),
    };
    let new_destination = preparer.add_native_commit(destination_input)?;
    let mut head_map = BTreeMap::from([(destination.head, new_destination)]);
    let mut new_trees = BTreeMap::from([(new_destination, moved.root)]);
    let mut staged = vec![StagedRewrite {
        change: destination.change,
        old: destination.head,
        new: new_destination,
        conflicted: false,
    }];
    // The old tree of every commit the moved set re-parents, by its old head.
    let mut old_trees = BTreeMap::from([(source.head, source_tree)]);
    // Descendants of the source re-parent onto the kept source, else the destination.
    if keep_source {
        let source_input = preserved_input(
            &source.record,
            Merge::resolved(source_tree),
            vec![new_destination],
            Some(source.head),
        )?;
        let kept = preparer.add_native_commit(source_input)?;
        head_map.insert(source.head, kept);
        new_trees.insert(kept, source_tree);
        staged.push(StagedRewrite {
            change: source.change,
            old: source.head,
            new: kept,
            conflicted: false,
        });
    } else {
        head_map.insert(source.head, new_destination);
    }
    let closure = descendants(store, &[source.head])?;
    let rewritten: BTreeSet<Head> = closure
        .iter()
        .copied()
        .chain([destination.head, source.head])
        .collect();
    for old in closure {
        let record = records.get_commit(&old)?.ok_or_else(|| not_stored(&old))?;
        let new_parents = map_strict(record.parents(), &rewritten, &head_map)?;
        let [base] = new_parents.as_slice() else {
            return Err(uncovered(
                "squash",
                "re-parenting a merge commit needs merge evaluation with no producer on this path",
            ));
        };
        let [old_parent] = record.parents() else {
            return Err(uncovered(
                "squash",
                "re-parenting a merge commit needs merge evaluation with no producer on this path",
            ));
        };
        let base_tree = new_base_tree(store, "squash", &new_trees, base)?;
        let old_parent_tree = *old_trees
            .get(old_parent)
            .ok_or_else(|| not_stored(old_parent))?;
        let child_tree = resolved_tree_of(
            &record,
            "squash",
            "re-parenting a conflicted commit needs merge evaluation with no producer on this path",
        )?;
        let derived = apply_delta(
            store,
            base_tree,
            old_parent_tree,
            child_tree,
            Selection::All,
        )?;
        push_unique(&mut objects, derived.objects);
        let input = preserved_input(
            &record,
            Merge::resolved(derived.root),
            new_parents,
            Some(old),
        )?;
        let new = preparer.add_native_commit(input)?;
        head_map.insert(old, new);
        new_trees.insert(new, derived.root);
        old_trees.insert(old, child_tree);
        staged.push(StagedRewrite {
            change: record.change_id(),
            old,
            new,
            conflicted: false,
        });
    }
    let batch = preparer.finish()?;
    push_unique(&mut objects, batch.prepared_objects);
    let mut rewrite_map: BTreeMap<Head, (ChangeId, Head)> = staged
        .iter()
        .map(|rewrite| (rewrite.old, (rewrite.change, rewrite.new)))
        .collect();
    let mut facts = batch.mutations;
    let mut abandoned = Vec::new();
    if !keep_source {
        let drop_source = prepare_abandon(
            store,
            AbandonRequest {
                heads: vec![source.head],
            },
        )?;
        let (merged, finals) = merge_changes_facts(store, facts, drop_source.facts)?;
        facts = merged;
        if finals
            .get(&source.change)
            .is_none_or(|entry| entry.heads.is_empty())
        {
            abandoned.push(source.change);
        }
        // The emptied source's workspace content now lives on the destination.
        rewrite_map.insert(source.head, (destination.change, new_destination));
    }
    let gated = gate_workspaces(ctx, "squash", &args.workspaces)?;
    let (mut workspace_facts, fence) = advance_workspaces(gated, session, "squash", &rewrite_map)?;
    facts.append(&mut workspace_facts);
    let reply = rewrite_reply(
        session,
        request_id,
        Some(preserved_identity(&source.record)?),
        merge_report_of(args.merge.mode)?,
        &staged,
        abandoned,
    )?;
    Ok(Parts {
        reply: Reply::Squash(Box::new(reply)),
        objects,
        facts,
        transaction: None,
        dependencies: Vec::new(),
        fence,
    })
}

/// Prepares `resolve`: replaces one conflicted path of a conflicted commit with
/// a resolution and rewrites the commit.
///
/// Every tree term takes the resolved entry at the path, so the path agrees
/// across the terms while every other conflict keeps its term list. A commit
/// whose conflicts are all resolved becomes a singleton tree; `remaining` lists
/// the paths still conflicted with their term counts.
///
/// # Errors
/// - [`ErrorCode::EInvalid`] when the target is resolved, the path is not
///   conflicted, a side index is out of range, `AcceptSame` finds sides that
///   still differ, or the resolution leaves the tree unchanged.
/// - [`ErrorCode::EConflicted`] when an ancestor of the path is a file in a term.
/// - [`ErrorCode::EHosted`] for a target with descendants (re-deriving them over
///   a resolved base needs merge evaluation), supplied staged content that is
///   not in the store (uploads resolve through the lease registry), and a
///   GitCompat workspace on the rewritten head.
/// - Target resolution errors as for `describe`.
fn resolve_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &ResolveArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    let target = load_rewrite_target(store, &args.target)?;
    if target.record.tree().is_resolved() {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "method `resolve` needs a conflicted target: its tree is already resolved",
        ));
    }
    if !children(store, &target.head)?.is_empty() {
        return Err(uncovered(
            "resolve",
            "the target has descendants, which must be re-derived over the resolved tree with merge evaluation and no producer on this path",
        ));
    }
    let path = &args.path;
    let terms: Vec<Oid> = target.record.tree().iter().copied().collect();
    let entries = terms
        .iter()
        .map(|term| lookup(store, *term, path))
        .collect::<Result<Vec<Node>, CoreError>>()?;
    if entries
        .iter()
        .any(|entry| matches!(entry, Some((TreeMode::Tree, _))))
    {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "path {} names a directory in the target: resolve addresses files, since resolving a directory would drop the nested conflicts beneath it",
                String::from_utf8_lossy(path.as_bytes())
            ),
        ));
    }
    let merged = Merge::try_from_vec(entries).map_err(CoreError::from)?;
    if merged.simplify().is_resolved() {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "path {} is not conflicted in the target",
                String::from_utf8_lossy(path.as_bytes())
            ),
        ));
    }
    let mut objects = Vec::new();
    let resolved = resolution_entry(store, &merged, &args.resolution, &mut objects)?;
    let mut rewritten = Vec::with_capacity(terms.len());
    for term in &terms {
        let edit = set_entry(store, *term, path, resolved)?;
        rewritten.push(edit.root);
        push_unique(&mut objects, edit.objects);
    }
    let tree = Merge::try_from_vec(rewritten)
        .map_err(CoreError::from)?
        .simplify();
    if tree == *target.record.tree() {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "method `resolve` leaves the target's tree unchanged",
        ));
    }
    let remaining = remaining_after(store, &terms, path)?;
    let input = preserved_input(
        &target.record,
        tree,
        target.record.parents().to_vec(),
        Some(target.head),
    )?;
    let prepared = Records::new(store).prepare_native_commit(input)?;
    let head = prepared.head;
    push_unique(&mut objects, vec![prepared.prepared_object]);
    let mut facts = prepared.mutations;
    let gated = gate_workspaces(ctx, "resolve", &args.workspaces)?;
    let rewrites = BTreeMap::from([(target.head, (target.change, head))]);
    let (mut workspace_facts, fence) = advance_workspaces(gated, session, "resolve", &rewrites)?;
    facts.append(&mut workspace_facts);
    let change = ChangeHead {
        change: target.change,
        head,
    };
    let mut outcome = pending_outcome(session, request_id);
    outcome.heads = BoundedList::complete(vec![change])?;
    let reply = ResolveReply {
        outcome,
        change,
        remaining: BoundedList::complete(remaining)?,
    };
    Ok(Parts {
        reply: Reply::Resolve(Box::new(reply)),
        objects,
        facts,
        transaction: None,
        dependencies: Vec::new(),
        fence,
    })
}

/// The entry a resolution writes at the conflicted path, staging any supplied
/// blob into `objects`.
///
/// A side index addresses the simplified merge's adds: the same sides the
/// conflict check and `remaining` report. A raw add can name a cancelled
/// value (such as the base) that no side holds, so indexing it would resolve
/// to content the client never saw as a side.
fn resolution_entry(
    store: &Store,
    merged: &Merge<Node>,
    resolution: &Resolution,
    objects: &mut Vec<PreparedObject>,
) -> Result<Node, CoreError> {
    match resolution {
        Resolution::Side { index } => {
            let simplified = merged.simplify();
            let position =
                usize::try_from(*index).map_err(|_| side_missing(*index, &simplified))?;
            simplified
                .get_add(position)
                .copied()
                .ok_or_else(|| side_missing(*index, &simplified))
        }
        Resolution::AcceptSame => accept_same(merged),
        Resolution::Supplied {
            content,
            executable,
        } => {
            let oid = supplied_blob(store, content, objects)?;
            let mode = if *executable {
                FileMode::Executable
            } else {
                FileMode::Regular
            };
            Ok(Some((TreeMode::File(mode), oid)))
        }
    }
}

/// The refusal for a side index the conflict does not have.
fn side_missing(index: u32, merged: &Merge<Node>) -> CoreError {
    CoreError::new(
        ErrorCode::EInvalid,
        format!(
            "side {index} does not exist: the conflict has {} sides",
            merged.num_sides()
        ),
    )
}

/// Collapses a path conflict whose sides agree: a simplification that resolves
/// outright, or add terms that all name one entry (the one lossy collapse).
fn accept_same(merged: &Merge<Node>) -> Result<Node, CoreError> {
    let simplified = merged.simplify();
    if let Some(node) = simplified.as_resolved() {
        return Ok(*node);
    }
    let adds: Vec<&Node> = simplified.adds().collect();
    match adds.split_first() {
        Some((first, rest)) if rest.iter().all(|add| add == first) => Ok(**first),
        _ => Err(CoreError::new(
            ErrorCode::EConflicted,
            "the sides of the conflict still differ at this path: supply content or pick a side",
        )),
    }
}

/// The blob a supplied resolution names. Inline bytes are staged unless the
/// store already holds them; a staged upload must already be stored with its
/// declared size.
fn supplied_blob(
    store: &Store,
    content: &Content,
    objects: &mut Vec<PreparedObject>,
) -> Result<Oid, CoreError> {
    match content {
        Content::Inline { data } => {
            let bytes = data.as_bytes();
            let oid = store.hash_kind().hash_git_object("blob", bytes)?;
            if store.object_len(oid)?.is_none() {
                let len = u64::try_from(bytes.len())
                    .map_err(|_| CoreError::new(ErrorCode::ECapacity, "blob exceeds u64 bytes"))?;
                let staged = store.prepare(ObjectKind::Blob, len, bytes, None)?;
                push_unique(objects, vec![staged]);
            }
            Ok(oid)
        }
        Content::Staged { object } => {
            let Some(size) = store.object_len(object.oid)? else {
                return Err(uncovered(
                    "resolve",
                    "the supplied staged content is not in the store: staged uploads resolve through the lease registry, which this path does not supply",
                ));
            };
            if size != object.size {
                return Err(CoreError::new(
                    ErrorCode::EInvalid,
                    format!(
                        "staged content {} is {size} bytes, not the declared {}",
                        object.oid, object.size
                    ),
                ));
            }
            Ok(object.oid)
        }
    }
}

/// Adds each object whose id is not already in `objects`.
fn push_unique(objects: &mut Vec<PreparedObject>, new: Vec<PreparedObject>) {
    for object in new {
        if !objects.iter().any(|known| known.oid() == object.oid()) {
            objects.push(object);
        }
    }
}

/// The conflicts a resolution of `path` leaves: every conflicted path of the
/// old terms outside the resolved path and beneath it.
fn remaining_after(
    store: &Store,
    terms: &[Oid],
    path: &RepoPath,
) -> Result<Vec<RemainingConflict>, CoreError> {
    conflicted_paths(store, terms)?
        .into_iter()
        .filter(|(conflict, _)| !covered_by(conflict.as_bytes(), path))
        .map(|(conflict, count)| {
            let terms = u32::try_from(count).map_err(|_| {
                CoreError::new(ErrorCode::ECapacity, "conflict term count exceeds u32")
            })?;
            Ok(RemainingConflict {
                path: conflict,
                terms,
            })
        })
        .collect()
}

/// The single tree of a commit, refusing a conflicted one with `reason`.
fn resolved_tree_of(record: &CommitRecord, method: &str, reason: &str) -> Result<Oid, CoreError> {
    record
        .tree()
        .as_resolved()
        .copied()
        .ok_or_else(|| uncovered(method, reason))
}

/// Prepares `revert`: a new change on `onto` whose tree is the target's delta
/// reversed.
///
/// The delta is the target's tree against the mainline parent's tree (the
/// empty tree for a root). Applying its reverse onto the new parent's tree
/// refuses with `E_CONFLICTED` where the parent diverged on the same paths.
/// The commit is minted in a fresh change under the session identity and the
/// coordinator clock, as `new` does.
///
/// # Errors
/// - [`ErrorCode::EInvalid`] for `mainline` on a non-merge or missing on a
///   merge, a mainline out of range, no `onto`, or a message carrying NUL.
/// - [`ErrorCode::EHosted`] for a conflicted target or parent tree, several
///   `onto` parents (tree merge), and the legacy path without identity or clock.
/// - [`ErrorCode::EConflicted`] naming every path where the reversal collides.
fn revert_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &RevertArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    let row = ctx.session_row.ok_or_else(|| {
        uncovered(
            "revert",
            "minting the revert's signature needs the session identity row, which this path does not supply",
        )
    })?;
    let clock = ctx.clock.ok_or_else(|| {
        uncovered(
            "revert",
            "minting the revert's signature needs the coordinator clock, which this path does not supply",
        )
    })?;
    let target = load_rewrite_target(store, &args.target)?;
    let target_tree = resolved_tree_of(
        &target.record,
        "revert",
        "reverting a conflicted commit needs merge evaluation with no producer on this path",
    )?;
    let mainline_tree = match revert_base(target.record.parents(), args.mainline)? {
        None => empty_tree(store.hash_kind())?,
        Some(parent) => {
            let commit = Records::new(store)
                .get_commit(&parent)?
                .ok_or_else(|| not_stored(&parent))?;
            resolved_tree_of(
                &commit,
                "revert",
                "reverting a change against a conflicted parent needs merge evaluation with no producer on this path",
            )?
        }
    };
    let onto = match args.onto.as_slice() {
        [] => {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "method `revert` needs at least one parent in onto",
            ));
        }
        [onto] => *onto,
        _ => {
            return Err(uncovered(
                "revert",
                "a revert over several parents needs tree-merge evaluation with no producer on this path; supply one parent",
            ));
        }
    };
    let onto_record = Records::new(store)
        .get_commit(&onto)?
        .ok_or_else(|| not_stored(&onto))?;
    let onto_tree = resolved_tree_of(
        &onto_record,
        "revert",
        "reverting onto a conflicted parent needs merge evaluation with no producer on this path",
    )?;
    let message = args
        .description
        .clone()
        .unwrap_or_else(|| default_revert_message(target.record.message()));
    if message.as_bytes().contains(&0) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "commit message carries NUL",
        ));
    }
    let reversed = apply_delta(store, onto_tree, target_tree, mainline_tree, Selection::All)?;
    let (author, identity) = commit_signature(row, clock, "revert", args.identity.as_ref())?;
    let input = NativeCommitInput {
        change_id: ChangeId::generate(),
        tree: Merge::resolved(reversed.root),
        parents: vec![onto],
        predecessor: None,
        author: author.clone(),
        committer: author,
        extra_headers: Vec::new(),
        message,
        provenance: None,
    };
    let prepared = Records::new(store).prepare_native_commit(input)?;
    let created = ChangeHead {
        change: prepared.record.change_id(),
        head: prepared.head,
    };
    let mut objects = reversed.objects;
    push_unique(&mut objects, vec![prepared.prepared_object]);
    let mut outcome = pending_outcome(session, request_id);
    outcome.identity = Some(identity);
    outcome.merge = merge_report_of(args.merge.mode)?;
    outcome.heads = BoundedList::complete(vec![created])?;
    Ok(Parts {
        reply: Reply::Revert(Box::new(RevertReply { outcome, created })),
        objects,
        facts: prepared.mutations,
        transaction: None,
        dependencies: Vec::new(),
        fence: None,
    })
}

/// The parent whose tree a revert measures the target's delta against: none
/// for a root, the only parent for a plain commit, and the one-based mainline
/// for a merge. `mainline` is refused wherever it does not select a parent.
fn revert_base(parents: &[Head], mainline: Option<NonZeroU32>) -> Result<Option<Head>, CoreError> {
    match (parents, mainline) {
        ([], None) => Ok(None),
        ([parent], None) => Ok(Some(*parent)),
        ([] | [_], Some(_)) => Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "method `revert`: `mainline` selects a parent of a merge commit, and this commit has {} parents",
                parents.len()
            ),
        )),
        (_, None) => Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "method `revert` needs `mainline` to revert a merge commit, which has {} parents",
                parents.len()
            ),
        )),
        (_, Some(mainline)) => usize::try_from(mainline.get() - 1)
            .ok()
            .and_then(|index| parents.get(index).copied())
            .map(Some)
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::EInvalid,
                    format!(
                        "`mainline` {mainline} names no parent of this {}-parent merge",
                        parents.len()
                    ),
                )
            }),
    }
}

/// Prepares `undo`: the exact inverse of a retained operation.
///
/// # Errors
/// As [`prepare_undo`]: `E_NOT_FOUND` for a pruned or unknown operation,
/// `E_UNDO_CONFLICT` for methods whose effects lie outside the tracked tables.
fn undo_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &UndoArgs,
) -> Result<Parts, CoreError> {
    let plan = prepare_undo(ctx.store, args.operation)?;
    let reply = UndoReply {
        outcome: pending_outcome(ctx.session, request_id),
        undone: args.operation,
        restored: plan.summary,
    };
    Ok(Parts {
        reply: Reply::Undo(Box::new(reply)),
        objects: Vec::new(),
        facts: plan.facts,
        transaction: plan.ref_transaction,
        dependencies: plan.ref_dependencies,
        fence: None,
    })
}

/// Prepares `policy.set`: replaces the repo-wide landing policy and bumps
/// the policy generation by one. The write is conditional on the row read,
/// so a concurrent `policy.set` fails loudly as stale instead of silently
/// winning. Landing plans prepared under an older generation refuse at
/// execution with `E_STALE`, so a policy bump invalidates prepared plans.
///
/// # Errors
/// - [`ErrorCode::EHosted`] without the session row (no identity source).
/// - [`ErrorCode::ELimit`] for a policy larger than the land bounds.
/// - [`ErrorCode::ENotFound`] when no metadata row exists yet.
/// - [`ErrorCode::EStale`] when the policy row moved under the call.
/// - Store failures.
fn policy_set_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &PolicySetArgs,
) -> Result<Parts, CoreError> {
    let _row = ctx.session_row.ok_or_else(|| {
        uncovered(
            "policy.set",
            "policy.set checks the session identity row this path does not supply",
        )
    })?;
    crate::attestation::check_land_policy(args.requirements.len(), &args.trusted_signers)?;
    let key = crate::store::types::REPO_META_KEY.to_vec();
    let Some((row, raw)) = ctx.store.repo_meta_raw().map_err(CoreError::from)? else {
        return Err(CoreError::new(
            ErrorCode::ENotFound,
            "repo metadata is missing; run repo.init first",
        ));
    };
    let generation = row
        .policy_generation
        .checked_add(1)
        .ok_or_else(|| CoreError::new(ErrorCode::ECapacity, "land policy generation overflow"))?;
    let next = crate::store::types::RepoMetaRow {
        default_branch: row.default_branch,
        land_requirements: args.requirements.clone(),
        trusted_signers: args.trusted_signers.clone(),
        policy_generation: generation,
    };
    let bytes = crate::store::encode("repo meta", &next).map_err(CoreError::from)?;
    let reply = Reply::PolicySet(Box::new(PolicySetReply {
        outcome: pending_outcome(ctx.session, request_id),
        generation,
    }));
    Ok(Parts {
        reply,
        objects: Vec::new(),
        facts: vec![crate::store::types::FactMutation {
            table: crate::store::types::FactTable::RepoMeta,
            key,
            expected: crate::store::types::FactExpectation::Value(raw),
            value: Some(bytes),
        }],
        transaction: None,
        dependencies: Vec::new(),
        fence: None,
    })
}

/// Prepares `land.prepare`: freezes the resolved change head as the exact
/// single-candidate plan over the target's live tip, moving no ref.
///
/// The candidate set derives from the resolved head: one exact commit.
/// Requirements, trusted signers, and the policy generation come from the
/// repo-wide landing policy (`policy.set`); stores predating the policy
/// prepare unconstrained at generation zero. The target still needs the
/// session's `land` capability, checked here while the lane re-checks
/// authority at commit time.
///
/// # Errors
/// - [`ErrorCode::EHosted`] without the session row (no capability source),
///   the coordinator clock (no creation timestamp), or the attestation gate.
/// - [`ErrorCode::EForbidden`] when the target leaves the session's `land`
///   grant.
/// - [`ErrorCode::EInvalid`] for a conflicted head: only an exact commit
///   can land.
/// - Target resolution errors as for `describe`.
fn land_prepare_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &LandPrepareArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let row = ctx.session_row.ok_or_else(|| {
        uncovered(
            "land.prepare",
            "land.prepare checks the session's `land` capability, which needs the session identity row this path does not supply",
        )
    })?;
    let clock = ctx.clock.ok_or_else(|| {
        uncovered(
            "land.prepare",
            "land.prepare stamps the plan creation time, which needs the coordinator clock this path does not supply",
        )
    })?;
    let Some(checkpoint) = ctx.checkpoint else {
        return Err(uncovered(
            "land.prepare",
            "land.prepare snapshots attestation requirements, which needs the attestation progress gate this path does not supply",
        ));
    };
    let (_change, head) = resolve_rewrite_head(store, &args.change)?;
    let Some(candidate) = head.as_git() else {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "land.prepare needs an exact commit: conflicted heads cannot land",
        ));
    };
    row.capabilities.require_land(&args.target)?;
    if args.remote.is_some() {
        return Err(CoreError::new(
            ErrorCode::EHosted,
            "land.prepare with a remote refuses: the transport push leg is not served yet",
        ));
    }
    let (requirements, trusted, policy_generation) =
        match store.repo_meta().map_err(CoreError::from)? {
            Some(meta) => (
                meta.land_requirements,
                meta.trusted_signers,
                meta.policy_generation,
            ),
            None => (Vec::new(), Vec::new(), 0),
        };
    let (plan, mutation) = prepare_land_plan(
        store,
        LandPrepareRequest {
            change: args.change,
            target: args.target.clone(),
            candidates: vec![*candidate],
            requirements,
            trusted,
            merge: args.merge,
            policy_generation,
            now: clock.sample()?.timestamp(),
        },
        checkpoint,
    )?;
    let Some(primary) = plan.candidate() else {
        return Err(CoreError::new(
            ErrorCode::ECorrupt,
            "land preparation staged an empty candidate set",
        ));
    };
    let reply = LandPrepareReply {
        outcome: pending_outcome(ctx.session, request_id),
        plan: plan.plan,
        candidate: primary,
        base: plan.base.unwrap_or_else(|| store.hash_kind().zero_oid()),
        expires_at: plan.expires_at,
        policy_generation: plan.policy_generation,
        requirements: plan.requirements,
    };
    Ok(Parts {
        reply: Reply::LandPrepare(Box::new(reply)),
        objects: Vec::new(),
        facts: vec![mutation],
        transaction: None,
        dependencies: Vec::new(),
        fence: None,
    })
}

/// Prepares `land.execute`: validates the stored plan against live state and
/// stages the target move plus plan-row deletion for the lane to publish.
///
/// The presented candidate must be the plan's primary candidate, and the
/// policy generation must still match: a `policy.set` after prepare fails
/// the execution as stale. The executing session must hold the `land`
/// capability on the stored target, re-checked here because the executor
/// may differ from the session that prepared the plan. Only the local leg
/// is served: `remote` must be absent (this store); a present remote names
/// a transport push the coordinator does not run.
///
/// The staged target move travels in `Parts.transaction` so the lane
/// re-runs its collision check against live state at publication.
///
/// # Errors
/// `E_HOSTED` for a present remote; `E_NOT_FOUND` for an unknown plan;
/// `E_STALE` for a non-primary candidate, an expired plan, a moved target
/// tip, a changed land policy, or a lost commit race; `E_POLICY` for a
/// candidate that misses a requirement; `E_FORBIDDEN` when the executing
/// session lacks the `land` grant on the target; `E_CORRUPT` or `E_IO`
/// from the store.
fn land_execute_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &LandExecuteArgs,
) -> Result<Parts, CoreError> {
    let row = ctx.session_row.ok_or_else(|| {
        uncovered(
            "land.execute",
            "land.execute checks the executing session's `land` capability, which needs the session identity row this path does not supply",
        )
    })?;
    let clock = ctx.clock.ok_or_else(|| {
        uncovered(
            "land.execute",
            "land.execute checks the plan deadline, which needs the coordinator clock this path does not supply",
        )
    })?;
    let Some(checkpoint) = ctx.checkpoint else {
        return Err(uncovered(
            "land.execute",
            "land.execute re-evaluates attestations, which needs the attestation progress gate this path does not supply",
        ));
    };
    let now = clock.sample()?.timestamp();
    let (outcome, facts) =
        super::land::prepare_land_execute(ctx.store, args.plan, args.candidate, now, checkpoint)?;
    row.capabilities.require_land(&outcome.target)?;
    let transaction = RefTransaction::new(
        ctx.store.hash_kind(),
        vec![RefUpdate {
            name: outcome.target.clone(),
            expected: match outcome.base {
                Some(base) => RefExpect::Present(RefTarget::Direct(base)),
                None => RefExpect::Absent,
            },
            change: RefChange::Set(RefTarget::Direct(outcome.candidate)),
        }],
    )
    .map_err(CoreError::from)?;
    let reply = Reply::LandExecute(Box::new(LandExecuteReply {
        outcome: pending_outcome(ctx.session, request_id),
        plan: outcome.plan,
        remote: PushRefOutcome {
            remote_ref: outcome.target.clone(),
            status: PushRefStatus::Confirmed {
                new: Some(outcome.candidate),
            },
        },
        local: LandLocalState::Published,
    }));
    Ok(Parts {
        reply,
        objects: Vec::new(),
        facts,
        transaction: Some(transaction),
        dependencies: vec![outcome.target.clone()],
        fence: None,
    })
}

/// The signature a new commit carries: the call's identity override, else the
/// session identity, stamped with the coordinator clock in UTC.
///
/// # Errors
/// - [`ErrorCode::EInvalid`] with neither an override nor a session identity,
///   or with a malformed identity.
fn commit_signature(
    row: &SessionRow,
    clock: &Clock,
    method: &str,
    over: Option<&IdentityClaim>,
) -> Result<(Signature, EffectiveIdentity), CoreError> {
    let claim = over.or(row.identity.as_ref()).ok_or_else(|| {
        CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "method `{method}` needs an identity: neither the call nor the session carries one"
            ),
        )
    })?;
    claim.validate()?;
    let secs = clock.sample()?.timestamp().instant().as_second();
    let author = Signature {
        name: ByteString::from(claim.name.as_str()),
        email: ByteString::from(claim.email.as_str()),
        timestamp: secs,
        offset: TzOffset::UTC,
    };
    let identity = EffectiveIdentity {
        name: claim.name.clone(),
        email: claim.email.clone(),
        source: if over.is_some() {
            IdentitySource::OperationOverride
        } else {
            IdentitySource::SessionClaim
        },
    };
    Ok((author, identity))
}

/// Prepares `abandon`: drops target heads and re-parents descendants onto the
/// abandoned commits' parents, staging rewrites and change-state transitions
/// through one batch so publication stays atomic. Merge-commit targets need
/// fan-in parent replacement with no producer here, so they stay refused.
///
/// # Errors
/// - [`ErrorCode::EHosted`] for merge-commit targets, merge descendants, and
///   content-carrying descendants.
fn abandon_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &AbandonArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    let mut abandoned_parents: BTreeMap<Head, Vec<Head>> = BTreeMap::new();
    let mut target_heads = Vec::with_capacity(args.targets.len());
    for target in &args.targets {
        let resolved = load_rewrite_target(store, target)?;
        let parents = match resolved.record.parents() {
            [] => Vec::new(),
            [parent] => vec![*parent],
            _ => {
                return Err(uncovered(
                    "abandon",
                    "abandon of a merge commit needs fan-in parent replacement with no producer on this path",
                ));
            }
        };
        abandoned_parents.insert(resolved.head, parents);
        target_heads.push(resolved.head);
    }
    // One closure over every target: roots are excluded even when nested, and
    // emission is topological across targets, so a descendant shared by two
    // targets stages once after every rewritten parent.
    let closure = descendants(store, &target_heads)?;
    let records = Records::new(store);
    let mut preparer = records.batch_preparer();
    let mut head_map = BTreeMap::new();
    let mut new_trees = BTreeMap::new();
    let mut staged = Vec::new();
    let rewritten: BTreeSet<Head> = closure.iter().copied().collect();
    for old in closure {
        let record = records.get_commit(&old)?.ok_or_else(|| not_stored(&old))?;
        let mut expanded = Vec::with_capacity(record.parents().len());
        for parent in record.parents() {
            expand_abandoned(parent, &abandoned_parents, &mut expanded);
        }
        if expanded
            .iter()
            .any(|parent| abandoned_parents.contains_key(parent))
        {
            return Err(CoreError::new(
                ErrorCode::ECorrupt,
                "internal: abandoned parent survived expansion",
            ));
        }
        let new_parents = map_strict(&expanded, &rewritten, &head_map)?;
        if let [base] = new_parents.as_slice() {
            let base_tree = new_base_tree(store, "abandon", &new_trees, base)?;
            let kept = record.tree().as_resolved().copied().ok_or_else(|| {
                uncovered(
                    "abandon",
                    "re-parenting a conflicted commit needs merge evaluation with no producer on this path",
                )
            })?;
            require_kept_tree("abandon", &kept, &base_tree)?;
        } else if !new_parents.is_empty() {
            return Err(uncovered(
                "abandon",
                "re-parenting a merge commit needs merge evaluation with no producer on this path",
            ));
        }
        let input = preserved_input(&record, record.tree().clone(), new_parents, Some(old))?;
        let new = preparer.add_native_commit(input)?;
        head_map.insert(old, new);
        if let Some(tree) = record.tree().as_resolved() {
            new_trees.insert(new, *tree);
        }
        staged.push(StagedRewrite {
            change: record.change_id(),
            old,
            new,
            conflicted: record.tree().as_resolved().is_none(),
        });
    }
    let batch = preparer.finish()?;
    let abandoned = prepare_abandon(
        store,
        AbandonRequest {
            heads: target_heads,
        },
    )?;
    let (mut facts, finals) = merge_changes_facts(store, batch.mutations, abandoned.facts)?;
    let mut drained = Vec::new();
    for target in &args.targets {
        if finals
            .get(&target.change)
            .is_none_or(|entry| entry.heads.is_empty())
        {
            drained.push(target.change);
        }
    }
    let gated = gate_workspaces(ctx, "abandon", &args.workspaces)?;
    let rewrite_map: BTreeMap<Head, (ChangeId, Head)> = staged
        .iter()
        .map(|rewrite| (rewrite.old, (rewrite.change, rewrite.new)))
        .collect();
    let (mut workspace_facts, fence) = advance_workspaces(gated, session, "abandon", &rewrite_map)?;
    facts.append(&mut workspace_facts);
    // Only descendants are re-parented, each keeping its own committer, so no
    // single recorded identity exists to report.
    let reply = rewrite_reply(
        session,
        request_id,
        None,
        merge_report_of(args.merge.mode)?,
        &staged,
        drained,
    )?;
    Ok(Parts {
        reply: Reply::Abandon(Box::new(reply)),
        objects: batch.prepared_objects,
        facts,
        transaction: None,
        dependencies: Vec::new(),
        fence,
    })
}

/// Expands an abandoned parent into its replacement parents, following nested
/// abandonments. Targets carry at most one parent, so expansion never fans out.
fn expand_abandoned(parent: &Head, abandoned: &BTreeMap<Head, Vec<Head>>, out: &mut Vec<Head>) {
    if let Some(replacements) = abandoned.get(parent) {
        for replacement in replacements {
            expand_abandoned(replacement, abandoned, out);
        }
    } else {
        out.push(*parent);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::super::land::load_plan;
    use super::super::policy::Principal;
    use super::*;
    use crate::attestation::Progress;
    use crate::bytes::ByteString;
    use crate::capability::{AttestKind, AttestResult, Capabilities, PathPattern, RefPattern};
    use crate::change::{ChangeId, ClaimId, PlanId, SessionId, WorkspaceId};
    use crate::commit::ProvenanceClaims;
    use crate::conflict::Signature;
    use crate::heads::Head;
    use crate::ids::{CommitKey, HashKind, Oid};
    use crate::index::RepoPath;
    use crate::ops::{NewRequest, prepare_new};
    use crate::protocol::{
        AbandonArgs, AttestAddArgs, AttestRequirement, AttestSignature, AttestStatement,
        BookmarkDeleteArgs, ChangeRef, ClaimAcquireArgs, ClaimMode, ClaimReleaseArgs, ClaimTtl,
        DescribeArgs, EditArgs, FetchArgs, FetchFilter, FetchRefs, GitCommitArgs,
        GitCommitRefUpdate, IdentityClaim, LandExecuteArgs, LandPrepareArgs, MergeSelection,
        Mutation as WireMutation, NewArgs, PathSelection, PinArgs, PolicySetArgs, PushArgs,
        PushAtomicity, PushReconcileArgs, PushSource, PushUpdate, RebaseArgs, RebaseScope,
        RemoteName, RemoteSpec, Resolution, ResolveArgs, RevertArgs, SessionAuthority,
        SignerFingerprint, SplitArgs, SplitPlacement, SquashArgs, TagAnnotation, UnpinArgs,
        WorkspaceBinding, WorkspaceInit, WsNewArgs,
    };
    use crate::records::codec::encode_change_entry;
    use crate::records::keys::change_key;
    use crate::records::types::{ChangeEntry, ChangeState};
    use crate::refdata::RefName;
    use crate::store::{EventContext, EventSource, PreparationBudget};
    use crate::workcopy::journal_state::ws_apply_key;
    use crate::workspace::WorkspaceStamp;

    static SEQ: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(std::path::PathBuf);

    impl TempRoot {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |e| e.as_nanos());
            let dir = std::env::temp_dir().join(format!(
                "ruk-prepare-test-{tag}-{}-{}-{nanos}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).expect("temp dir");
            Self(dir)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> (TempRoot, Store, SessionId) {
        let temp = TempRoot::new("matrix");
        let store = Store::create(
            &temp.0.join("store"),
            HashKind::Sha1,
            Arc::new(PreparationBudget::reference_defaults()),
        )
        .expect("create store");
        (temp, store, SessionId::generate())
    }

    fn oid(byte: u8) -> Oid {
        Oid::from_bytes(&[byte; 20]).expect("test oid")
    }

    fn name(text: &str) -> RefName {
        RefName::new(text).expect("test ref name")
    }

    fn request_id() -> RequestId {
        RequestId::generate()
    }

    fn signature() -> Signature {
        Signature {
            name: ByteString::from("Ada"),
            email: ByteString::from("ada@example.invalid"),
            timestamp: 1_700_000_000,
            offset: TzOffset::UTC,
        }
    }

    /// Mints a real commit through `ops::prepare_new` and publishes it, so
    /// change-target, pin, and divergence tests resolve stored facts. Each
    /// seed carries a distinct message, so heads never collide; an absent
    /// change mints a fresh one (`prepare_new` with `None` would resolve the
    /// tree's stable by-OID mapping and pile every empty-tree seed onto one
    /// divergent change).
    fn seed_commit(store: &Store, change_id: Option<ChangeId>) -> (Head, ChangeId, Oid) {
        let number = SEQ.fetch_add(1, Ordering::SeqCst);
        let tree = store
            .prepare(ObjectKind::Tree, 0, std::io::Cursor::new(Vec::new()), None)
            .expect("prepare empty tree");
        let tree_oid = tree.oid();
        store
            .publish(
                vec![tree],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish empty tree");
        let prepared = prepare_new(
            store,
            NewRequest {
                tree: tree_oid,
                parents: Vec::new(),
                author: signature(),
                committer: signature(),
                message: ByteString::from(format!("seed-{number}")),
                change_id: Some(change_id.unwrap_or_else(ChangeId::generate)),
                predecessor: None,
                provenance: None,
            },
        )
        .expect("prepare seed commit");
        let head = prepared.output.head;
        let change = prepared.output.change_id;
        let oid = prepared.output.oid.expect("seed commit is a Git commit");
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish seed commit");
        (head, change, oid)
    }

    fn session_row(identity: Option<IdentityClaim>) -> SessionRow {
        SessionRow {
            principal: Principal::from_peer_uid(1000),
            identity,
            claims: ProvenanceClaims::default(),
            capabilities: Capabilities::default(),
            secret_hash: [0; 32],
            authority: SessionAuthority::Active {
                idle_expires_at: Timestamp::new(jiff::Timestamp::now()),
            },
        }
    }

    fn fixed_clock() -> Clock {
        Clock::injected(
            jiff::Timestamp::from_second(1_700_000_000).expect("fixed test time"),
            std::time::Instant::now(),
        )
    }

    fn open_checkpoint(_: Progress) -> Result<(), CoreError> {
        Ok(())
    }

    fn full_ctx<'a>(
        store: &'a Store,
        session: SessionId,
        row: Option<&'a SessionRow>,
        clock: Option<&'a Clock>,
        checkpoint: Option<&'a Checkpoint<'a>>,
    ) -> PrepareContext<'a> {
        PrepareContext {
            store,
            session,
            session_row: row,
            clock,
            claim_clock: None,
            policy: None,
            checkpoint,
            on_behalf_of: None,
        }
    }

    #[test]
    fn covered_ref_mutations_prepare_exact_facts() {
        let (_temp, store, session) = fixture();
        let prepared = prepare_mutation(
            &store,
            session,
            Request::BookmarkSet(Box::new(WireMutation {
                request_id: request_id(),
                args: BookmarkSetArgs {
                    name: name("refs/heads/main"),
                    target: BookmarkTarget::Commit { oid: oid(0x11) },
                    expected: RefExpect::Absent,
                },
            })),
        )
        .expect("bookmark.set prepares");
        assert_eq!(prepared.session, session);
        assert_eq!(prepared.facts.len(), 1);
        let fact = &prepared.facts[0];
        assert_eq!(fact.table, crate::store::types::FactTable::Refs);
        assert_eq!(fact.key, b"refs/heads/main");
        assert!(prepared.ref_transaction.is_some());
        assert_eq!(prepared.ref_dependencies, vec![name("refs/heads/main")]);
        assert_eq!(
            prepared.request.method(),
            crate::protocol::Method::BookmarkSet
        );
        assert_eq!(
            prepared.reply.method(),
            crate::protocol::Method::BookmarkSet
        );

        // Deleting needs a present ref: the protocol refuses an absent
        // expectation for deletes, so the fixture publishes one first.
        let target = RefTarget::Direct(oid(0x11));
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: crate::store::types::FactTable::Refs,
                    key: b"refs/tags/v1".to_vec(),
                    expected: crate::store::types::FactExpectation::Absent,
                    value: Some(crate::store::encode("ref target", &target).expect("encode ref")),
                }],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish fixture ref");
        let prepared = prepare_mutation(
            &store,
            session,
            Request::TagDelete(Box::new(WireMutation {
                request_id: request_id(),
                args: TagDeleteArgs {
                    name: name("refs/tags/v1"),
                    expected: RefExpect::Present(target.clone()),
                },
            })),
        )
        .expect("tag.delete prepares on a present ref");
        assert_eq!(prepared.facts.len(), 1);
        let fact = &prepared.facts[0];
        assert_eq!(fact.table, crate::store::types::FactTable::Refs);
        assert!(fact.value.is_none());
    }

    #[test]
    fn stale_expectations_surface_before_the_lane() {
        let (_temp, store, session) = fixture();
        let err = prepare_mutation(
            &store,
            session,
            Request::BookmarkDelete(Box::new(WireMutation {
                request_id: request_id(),
                args: BookmarkDeleteArgs {
                    name: name("refs/heads/main"),
                    expected: RefExpect::Present(RefTarget::Direct(oid(0x11))),
                },
            })),
        )
        .expect_err("deleting a missing ref with present expectation is stale");
        assert_eq!(err.code, ErrorCode::EStale);
    }

    #[test]
    fn uncovered_mutations_name_their_missing_preparation() {
        let (_temp, store, session) = fixture();
        // The annotated tag arm needs the coordinator clock, which the
        // legacy path does not supply.
        let annotated = Request::TagSet(Box::new(WireMutation {
            request_id: request_id(),
            args: TagSetArgs {
                name: name("refs/tags/v1"),
                target: oid(0x11),
                annotation: Some(TagAnnotation {
                    tagger: None,
                    message: crate::bytes::ByteString::from("annotated"),
                }),
                expected: RefExpect::Absent,
            },
        }));
        let err =
            prepare_mutation(&store, session, annotated).expect_err("annotated tag stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);

        // `claim.acquire` validates against the session row, which the legacy
        // path does not supply.
        let acquire = Request::ClaimAcquire(Box::new(WireMutation {
            request_id: request_id(),
            args: ClaimAcquireArgs {
                paths: vec![RepoPath::new("src").expect("test path")],
                ttl: ClaimTtl::new(60).expect("ttl"),
                mode: ClaimMode::Enforce,
            },
        }));
        let err =
            prepare_mutation(&store, session, acquire).expect_err("claim.acquire stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
    }

    fn bookmark_set_request(id: RequestId, target: BookmarkTarget) -> Request {
        Request::BookmarkSet(Box::new(WireMutation {
            request_id: id,
            args: BookmarkSetArgs {
                name: name("refs/heads/main"),
                target,
                expected: RefExpect::Absent,
            },
        }))
    }

    #[test]
    fn bookmark_set_change_target_resolves_stored_change() {
        let (_temp, store, session) = fixture();
        let (head, change, commit_oid) = seed_commit(&store, None);

        // An unpinned single-head change resolves to its Git commit.
        let prepared = prepare_mutation(
            &store,
            session,
            bookmark_set_request(
                request_id(),
                BookmarkTarget::Change {
                    change: ChangeRef { change, head: None },
                },
            ),
        )
        .expect("change target resolves");
        let Reply::BookmarkSet(reply) = prepared.reply else {
            panic!("bookmark.set must answer its own reply");
        };
        assert_eq!(reply.target, commit_oid);
        assert_eq!(prepared.facts.len(), 1);
        assert!(prepared.ref_transaction.is_some());
        assert_eq!(prepared.ref_dependencies, vec![name("refs/heads/main")]);

        // A pinned current head resolves the same way.
        let prepared = prepare_mutation(
            &store,
            session,
            bookmark_set_request(
                request_id(),
                BookmarkTarget::Change {
                    change: ChangeRef {
                        change,
                        head: Some(head),
                    },
                },
            ),
        )
        .expect("pinned current head resolves");
        let Reply::BookmarkSet(reply) = prepared.reply else {
            panic!("bookmark.set must answer its own reply");
        };
        assert_eq!(reply.target, commit_oid);

        // A pinned head from another change is stale.
        let err = prepare_mutation(
            &store,
            session,
            bookmark_set_request(
                request_id(),
                BookmarkTarget::Change {
                    change: ChangeRef {
                        change,
                        head: Some(Head::Git { oid: oid(0x99) }),
                    },
                },
            ),
        )
        .expect_err("foreign pinned head is stale");
        assert_eq!(err.code, ErrorCode::EStale);

        // An unknown change is not found.
        let err = prepare_mutation(
            &store,
            session,
            bookmark_set_request(
                request_id(),
                BookmarkTarget::Change {
                    change: ChangeRef {
                        change: ChangeId::from_bytes([0x99; 16]),
                        head: None,
                    },
                },
            ),
        )
        .expect_err("unknown change is not found");
        assert_eq!(err.code, ErrorCode::ENotFound);

        // A second head diverges the change: unpinned resolution refuses
        // while either pinned head still resolves.
        let (head2, _, oid2) = seed_commit(&store, Some(change));
        assert_ne!(head2, head);
        let err = prepare_mutation(
            &store,
            session,
            bookmark_set_request(
                request_id(),
                BookmarkTarget::Change {
                    change: ChangeRef { change, head: None },
                },
            ),
        )
        .expect_err("divergent change needs a pinned head");
        assert_eq!(err.code, ErrorCode::EDivergent);
        for (pinned, expected) in [(head, commit_oid), (head2, oid2)] {
            let prepared = prepare_mutation(
                &store,
                session,
                bookmark_set_request(
                    request_id(),
                    BookmarkTarget::Change {
                        change: ChangeRef {
                            change,
                            head: Some(pinned),
                        },
                    },
                ),
            )
            .expect("pinned divergent head resolves");
            let Reply::BookmarkSet(reply) = prepared.reply else {
                panic!("bookmark.set must answer its own reply");
            };
            assert_eq!(reply.target, expected);
        }

        // A conflicted head cannot become a Git ref.
        let conflicted_change = ChangeId::from_bytes([0x77; 16]);
        // A SHA-1 store holds 20-byte commit keys; the width must match the
        // repository or entry validation reports corruption.
        let conflicted = Head::Conflicted {
            key: CommitKey::from_bytes(&[0x77; 20]).expect("test commit key"),
        };
        let entry = ChangeEntry::new(ChangeState::Active, conflicted);
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: crate::store::types::FactTable::Changes,
                    key: change_key(&conflicted_change).to_vec(),
                    expected: crate::store::types::FactExpectation::Absent,
                    value: Some(encode_change_entry(&entry).expect("encode change entry")),
                }],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish conflicted change");
        let err = prepare_mutation(
            &store,
            session,
            bookmark_set_request(
                request_id(),
                BookmarkTarget::Change {
                    change: ChangeRef {
                        change: conflicted_change,
                        head: Some(conflicted),
                    },
                },
            ),
        )
        .expect_err("conflicted head cannot become a ref");
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn tag_set_annotation_renders_tag_object() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row(Some(IdentityClaim {
            name: "Ses".to_string(),
            email: "ses@example.invalid".to_string(),
        }));
        // The annotated arm renders `type commit`, so the target must be a
        // stored commit; an unstored target is `E_NOT_FOUND` (see below).
        let (_, _, target) = seed_commit(&store, None);

        // An explicit tagger wins over the session identity, and the staged
        // object hashes exactly to the canonical payload.
        let ctx = full_ctx(
            &store,
            session,
            Some(&row),
            Some(&clock),
            Some(&open_checkpoint),
        );
        let prepared = prepare_mutation_with(
            &ctx,
            Request::TagSet(Box::new(WireMutation {
                request_id: request_id(),
                args: TagSetArgs {
                    name: name("refs/tags/v1"),
                    target,
                    annotation: Some(TagAnnotation {
                        tagger: Some(IdentityClaim {
                            name: "Tag".to_string(),
                            email: "tag@example.invalid".to_string(),
                        }),
                        message: ByteString::from("annotated"),
                    }),
                    expected: RefExpect::Absent,
                },
            })),
        )
        .expect("annotated tag prepares");
        let expected_payload = format!(
            "object {target}\ntype commit\ntag v1\ntagger Tag <tag@example.invalid> 1700000000 +0000\n\nannotated"
        )
        .into_bytes();
        let expected_oid = store
            .hash_kind()
            .hash_git_object("tag", &expected_payload)
            .expect("hash tag payload");
        assert_eq!(prepared.objects.len(), 1);
        assert_eq!(prepared.objects[0].kind(), ObjectKind::Tag);
        let decoded = store
            .decode_prepared(&prepared.objects[0])
            .expect("decode staged tag");
        let mut staged = Vec::new();
        std::io::Read::read_to_end(&mut decoded.view(), &mut staged).expect("read staged tag");
        assert_eq!(staged, expected_payload);
        assert_eq!(prepared.objects[0].oid(), expected_oid);
        let Reply::TagSet(reply) = prepared.reply else {
            panic!("tag.set must answer its own reply");
        };
        assert_eq!(reply.target, RefTarget::Direct(expected_oid));
        assert_eq!(prepared.facts.len(), 1);
        assert!(prepared.ref_transaction.is_some());

        // Without an annotation tagger the session identity fills in.
        let prepared = prepare_mutation_with(
            &ctx,
            Request::TagSet(Box::new(WireMutation {
                request_id: request_id(),
                args: TagSetArgs {
                    name: name("refs/tags/v2"),
                    target,
                    annotation: Some(TagAnnotation {
                        tagger: None,
                        message: ByteString::from("session tagger"),
                    }),
                    expected: RefExpect::Absent,
                },
            })),
        )
        .expect("session identity fills the tagger");
        let expected_payload = format!(
            "object {target}\ntype commit\ntag v2\ntagger Ses <ses@example.invalid> 1700000000 +0000\n\nsession tagger"
        )
        .into_bytes();
        let expected_oid = store
            .hash_kind()
            .hash_git_object("tag", &expected_payload)
            .expect("hash tag payload");
        assert_eq!(prepared.objects.len(), 1);
        assert_eq!(prepared.objects[0].oid(), expected_oid);

        // An unstored target never reaches tagger rendering: the commit
        // check reports it first.
        let err = prepare_mutation_with(
            &ctx,
            Request::TagSet(Box::new(WireMutation {
                request_id: request_id(),
                args: TagSetArgs {
                    name: name("refs/tags/v4"),
                    target: oid(0x99),
                    annotation: Some(TagAnnotation {
                        tagger: Some(IdentityClaim {
                            name: "Tag".to_string(),
                            email: "tag@example.invalid".to_string(),
                        }),
                        message: ByteString::from("ghost"),
                    }),
                    expected: RefExpect::Absent,
                },
            })),
        )
        .expect_err("unstored tag target is not found");
        assert_eq!(err.code, ErrorCode::ENotFound);

        // With neither identity the call is invalid, not hosted: there is
        // no configuration ladder for the coordinator to consult.
        let bare_row = session_row(None);
        let bare = full_ctx(
            &store,
            session,
            Some(&bare_row),
            Some(&clock),
            Some(&open_checkpoint),
        );
        let err = prepare_mutation_with(
            &bare,
            Request::TagSet(Box::new(WireMutation {
                request_id: request_id(),
                args: TagSetArgs {
                    name: name("refs/tags/v3"),
                    target,
                    annotation: Some(TagAnnotation {
                        tagger: None,
                        message: ByteString::from("nobody"),
                    }),
                    expected: RefExpect::Absent,
                },
            })),
        )
        .expect_err("taggerless annotation is invalid");
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn pin_and_unpin_round_trip_on_stored_heads() {
        let (_temp, store, session) = fixture();
        let (head, _, _) = seed_commit(&store, None);

        // An unstored head cannot root anything.
        let err = prepare_mutation(
            &store,
            session,
            Request::Pin(Box::new(WireMutation {
                request_id: request_id(),
                args: PinArgs {
                    head: Head::Git { oid: oid(0x99) },
                },
            })),
        )
        .expect_err("unstored pin target is not found");
        assert_eq!(err.code, ErrorCode::ENotFound);

        // Pinning stages the presence fact and moves no ref.
        let prepared = prepare_mutation(
            &store,
            session,
            Request::Pin(Box::new(WireMutation {
                request_id: request_id(),
                args: PinArgs { head },
            })),
        )
        .expect("pin prepares");
        assert_eq!(prepared.facts.len(), 1);
        let fact = &prepared.facts[0];
        assert_eq!(fact.table, crate::store::types::FactTable::Pins);
        assert_eq!(fact.key, head_key(&head));
        assert_eq!(fact.expected, crate::store::types::FactExpectation::Absent);
        assert_eq!(fact.value, Some(Vec::new()));
        assert!(prepared.ref_transaction.is_none());
        assert!(prepared.ref_dependencies.is_empty());
        let Reply::Pin(_) = prepared.reply else {
            panic!("pin must answer its own reply");
        };

        // Once published, unpinning removes the fact against its bytes.
        store
            .publish(
                Vec::new(),
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish pin");
        let prepared = prepare_mutation(
            &store,
            session,
            Request::Unpin(Box::new(WireMutation {
                request_id: request_id(),
                args: UnpinArgs { head },
            })),
        )
        .expect("unpin prepares");
        assert_eq!(prepared.facts.len(), 1);
        let fact = &prepared.facts[0];
        assert_eq!(fact.table, crate::store::types::FactTable::Pins);
        assert_eq!(
            fact.expected,
            crate::store::types::FactExpectation::Value(Vec::new())
        );
        assert_eq!(fact.value, None);
        let Reply::Unpin(_) = prepared.reply else {
            panic!("unpin must answer its own reply");
        };

        // A pin that was never published is not found.
        let (other, _, _) = seed_commit(&store, None);
        let err = prepare_mutation(
            &store,
            session,
            Request::Unpin(Box::new(WireMutation {
                request_id: request_id(),
                args: UnpinArgs { head: other },
            })),
        )
        .expect_err("missing pin is not found");
        assert_eq!(err.code, ErrorCode::ENotFound);
    }

    #[test]
    fn attest_add_verifies_and_stages_through_context() {
        let (_temp, store, session) = fixture();
        let body = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\nattest subject\n";
        let subject_object = store
            .prepare(
                ObjectKind::Commit,
                u64::try_from(body.len()).expect("subject fits u64"),
                &body[..],
                None,
            )
            .expect("prepare subject");
        let subject = subject_object.oid();
        store
            .publish(
                vec![subject_object],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish subject");

        let key =
            ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[0x11; 32]));
        let statement = AttestStatement {
            subject,
            kind: AttestKind::new("review").expect("kind"),
            result: AttestResult::new("pass").expect("result"),
            signed_at: Timestamp::parse("2026-10-17T12:00:00Z").expect("timestamp"),
            supersedes: None,
            evidence: None,
        };
        let payload = statement
            .canonical_payload_v1(HashKind::Sha1)
            .expect("canonical payload");
        let signature = key
            .sign(
                crate::attestation::ATTEST_NAMESPACE,
                ssh_key::HashAlg::Sha256,
                &payload,
            )
            .expect("sign");
        let armor = signature.to_pem(ssh_key::LineEnding::LF).expect("armor");
        let args = AttestAddArgs {
            statement,
            signature: AttestSignature::new(armor).expect("armored signature"),
        };
        let request = || {
            Request::AttestAdd(Box::new(WireMutation {
                request_id: request_id(),
                args: args.clone(),
            }))
        };

        // The legacy path carries no progress gate and stays refused with
        // the long-standing catch-all text.
        let err =
            prepare_mutation(&store, session, request()).expect_err("attest.add stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(err.message.contains("does not cover preparation"));

        // Through the context the statement verifies and its rows stage.
        let ctx = full_ctx(&store, session, None, None, Some(&open_checkpoint));
        let prepared = prepare_mutation_with(&ctx, request()).expect("attest.add prepares");
        let Reply::AttestAdd(reply) = prepared.reply else {
            panic!("attest.add must answer its own reply");
        };
        assert_eq!(reply.record.subject, subject);
        assert_eq!(
            reply.record.result,
            AttestResult::new("pass").expect("result")
        );
        assert!(!prepared.facts.is_empty());
        assert!(prepared.ref_transaction.is_none());

        // Publishing once makes the repeat a duplicate that stages nothing.
        store
            .publish(
                Vec::new(),
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish attestation");
        let repeat = prepare_mutation_with(&ctx, request()).expect("duplicate prepares");
        assert!(repeat.facts.is_empty());
        let Reply::AttestAdd(repeat_reply) = repeat.reply else {
            panic!("attest.add must answer its own reply");
        };
        assert_eq!(repeat_reply.record, reply.record);
    }

    #[test]
    fn full_context_still_refuses_future_waves() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let ctx = full_ctx(&store, session, None, Some(&clock), Some(&open_checkpoint));
        // `split`, `squash`, `resolve`, `revert`, and `undo` serve through this
        // context; `op.prune` has no retention policy to apply, so it still
        // refuses and names the machinery it lacks.
        let request = Request::OpPrune(Box::new(WireMutation {
            request_id: request_id(),
            args: crate::protocol::OpPruneArgs {},
        }));
        let err = prepare_mutation_with(&ctx, request)
            .expect_err("op.prune stays refused through the context");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("operation-retention policy"),
            "op.prune names its missing policy: {}",
            err.message
        );
    }

    fn land_caps() -> Capabilities {
        Capabilities {
            land: vec![RefPattern::parse("refs/heads/**").expect("land pattern")],
            ..Capabilities::default()
        }
    }

    fn origin_remote() -> RemoteSpec {
        RemoteSpec::Named {
            name: RemoteName::new("origin").expect("remote name"),
        }
    }

    fn land_request(change: ChangeId, head: Option<Head>) -> Request {
        Request::LandPrepare(Box::new(WireMutation {
            request_id: request_id(),
            args: LandPrepareArgs {
                change: ChangeRef { change, head },
                remote: None,
                target: name("refs/heads/main"),
                merge: MergeSelection::default(),
            },
        }))
    }

    fn land_request_remote(change: ChangeId, head: Option<Head>) -> Request {
        Request::LandPrepare(Box::new(WireMutation {
            request_id: request_id(),
            args: LandPrepareArgs {
                change: ChangeRef { change, head },
                remote: Some(origin_remote()),
                target: name("refs/heads/main"),
                merge: MergeSelection::default(),
            },
        }))
    }

    #[test]
    fn land_prepare_freezes_exact_candidate() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(None, land_caps());
        let ctx = full_ctx(
            &store,
            session,
            Some(&row),
            Some(&clock),
            Some(&open_checkpoint),
        );
        let (head, change, oid) = seed_commit(&store, None);
        let prepared = prepare_mutation_with(&ctx, land_request(change, Some(head)))
            .expect("land.prepare serves");
        let Reply::LandPrepare(reply) = prepared.reply else {
            panic!("land.prepare must answer its own reply");
        };
        assert_eq!(reply.candidate, oid);
        assert_eq!(reply.base, HashKind::Sha1.zero_oid());
        assert!(reply.requirements.is_empty());
        assert_eq!(reply.policy_generation, 0);
        assert!(prepared.objects.is_empty());
        assert!(prepared.ref_transaction.is_none());
        assert!(prepared.workspace_fence.is_none());
        assert_eq!(prepared.facts.len(), 1);
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish land plan");
        let stored = load_plan(&store, reply.plan)
            .expect("read plan")
            .expect("plan stored");
        assert_eq!(stored.candidate(), Some(oid));
        assert_eq!(stored.base, None);
    }

    #[test]
    fn policy_set_bumps_generation_and_land_prepare_inherits_it() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(None, land_caps());
        store
            .write_repo_meta(RefName::new("refs/heads/main").expect("branch"))
            .expect("seed repo meta");
        let requirement = || AttestRequirement {
            kind: AttestKind::new("ci/build").expect("kind"),
            result: AttestResult::new("pass").expect("result"),
            valid_until: None,
        };
        let signer =
            || SignerFingerprint::new(format!("SHA256:{}", "A".repeat(43))).expect("signer");
        let set = || {
            Request::PolicySet(Box::new(WireMutation {
                request_id: request_id(),
                args: PolicySetArgs {
                    requirements: vec![requirement()],
                    trusted_signers: vec![signer()],
                },
            }))
        };
        let ctx = full_ctx(
            &store,
            session,
            Some(&row),
            Some(&clock),
            Some(&open_checkpoint),
        );
        let first = prepare_mutation_with(&ctx, set()).expect("policy.set serves");
        let Reply::PolicySet(first_reply) = first.reply else {
            panic!("policy.set must answer its own reply");
        };
        assert_eq!(first_reply.generation, 1);
        store
            .publish(
                first.objects,
                &first.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish first policy");
        let second = prepare_mutation_with(&ctx, set()).expect("policy.set serves again");
        let Reply::PolicySet(second_reply) = second.reply else {
            panic!("policy.set must answer its own reply");
        };
        assert_eq!(second_reply.generation, 2);
        store
            .publish(
                second.objects,
                &second.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish second policy");
        let (head, change, _) = seed_commit(&store, None);
        let prepared = prepare_mutation_with(&ctx, land_request(change, Some(head)))
            .expect("land.prepare serves");
        let Reply::LandPrepare(reply) = prepared.reply else {
            panic!("land.prepare must answer its own reply");
        };
        assert_eq!(reply.policy_generation, 2);
        assert_eq!(reply.requirements, vec![requirement()]);
    }

    #[test]
    fn land_execute_moves_the_tip_and_consumes_the_plan() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(None, land_caps());
        let ctx = full_ctx(
            &store,
            session,
            Some(&row),
            Some(&clock),
            Some(&open_checkpoint),
        );
        let (head, change, oid) = seed_commit(&store, None);
        let prepared = prepare_mutation_with(&ctx, land_request(change, Some(head)))
            .expect("land.prepare serves");
        let Reply::LandPrepare(reply) = prepared.reply else {
            panic!("land.prepare must answer its own reply");
        };
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish land plan");
        let execute = || {
            Request::LandExecute(Box::new(WireMutation {
                request_id: request_id(),
                args: LandExecuteArgs {
                    plan: reply.plan,
                    candidate: oid,
                },
            }))
        };
        let staged = prepare_mutation_with(&ctx, execute()).expect("land.execute serves");
        let Reply::LandExecute(run) = staged.reply else {
            panic!("land.execute must answer its own reply");
        };
        assert_eq!(run.plan, reply.plan);
        assert_eq!(
            run.remote,
            PushRefOutcome {
                remote_ref: RefName::new("refs/heads/main").expect("target"),
                status: crate::protocol::PushRefStatus::Confirmed { new: Some(oid) },
            }
        );
        assert_eq!(run.local, LandLocalState::Published);
        store
            .publish(
                staged.objects,
                &staged.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish land execution");
        let target = store
            .fact(crate::store::types::FactTable::Refs, b"refs/heads/main")
            .expect("read target")
            .expect("target landed");
        let moved: crate::refdata::RefTarget =
            crate::store::decode("ref target", &target).expect("decode target");
        assert_eq!(moved, crate::refdata::RefTarget::Direct(oid));
        assert!(
            load_plan(&store, reply.plan).expect("read plans").is_none(),
            "the executed plan is consumed"
        );
        let err =
            prepare_mutation_with(&ctx, execute()).expect_err("a second execution finds no plan");
        assert_eq!(err.code, ErrorCode::ENotFound);
    }

    #[test]
    fn land_execute_refuses_a_non_primary_candidate() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(None, land_caps());
        let ctx = full_ctx(
            &store,
            session,
            Some(&row),
            Some(&clock),
            Some(&open_checkpoint),
        );
        let (head, change, oid) = seed_commit(&store, None);
        let prepared = prepare_mutation_with(&ctx, land_request(change, Some(head)))
            .expect("land.prepare serves");
        let Reply::LandPrepare(reply) = prepared.reply else {
            panic!("land.prepare must answer its own reply");
        };
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish land plan");
        let wrong = Oid::from_bytes(&[0xabu8; 20]).expect("test oid");
        assert_ne!(wrong, oid);
        let err = prepare_mutation_with(
            &ctx,
            Request::LandExecute(Box::new(WireMutation {
                request_id: request_id(),
                args: LandExecuteArgs {
                    plan: reply.plan,
                    candidate: wrong,
                },
            })),
        )
        .expect_err("a non-primary candidate refuses");
        assert_eq!(err.code, ErrorCode::EStale);
    }

    #[test]
    fn land_execute_refuses_without_land_capability() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(None, land_caps());
        let ctx = full_ctx(
            &store,
            session,
            Some(&row),
            Some(&clock),
            Some(&open_checkpoint),
        );
        let (head, change, oid) = seed_commit(&store, None);
        let prepared = prepare_mutation_with(&ctx, land_request(change, Some(head)))
            .expect("land.prepare serves");
        let Reply::LandPrepare(reply) = prepared.reply else {
            panic!("land.prepare must answer its own reply");
        };
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish land plan");
        // The executing session holds no land grant on the target, even
        // though the preparing session did.
        let bare = session_row_caps(None, Capabilities::default());
        let exec_ctx = full_ctx(
            &store,
            session,
            Some(&bare),
            Some(&clock),
            Some(&open_checkpoint),
        );
        let err = prepare_mutation_with(
            &exec_ctx,
            Request::LandExecute(Box::new(WireMutation {
                request_id: request_id(),
                args: LandExecuteArgs {
                    plan: reply.plan,
                    candidate: oid,
                },
            })),
        )
        .expect_err("land.execute without the land grant is forbidden");
        assert_eq!(err.code, ErrorCode::EForbidden);
    }

    #[test]
    fn land_execute_carries_a_transaction_that_refuses_new_collisions() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(None, land_caps());
        let ctx = full_ctx(
            &store,
            session,
            Some(&row),
            Some(&clock),
            Some(&open_checkpoint),
        );
        let (head, change, oid) = seed_commit(&store, None);
        let prepared = prepare_mutation_with(&ctx, land_request(change, Some(head)))
            .expect("land.prepare serves");
        let Reply::LandPrepare(reply) = prepared.reply else {
            panic!("land.prepare must answer its own reply");
        };
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish land plan");
        // A file ref appears below the target after prepare, so the staged
        // target move now collides with live state.
        let child_target = crate::refdata::RefTarget::Direct(oid);
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: crate::store::types::FactTable::Refs,
                    key: b"refs/heads/main/child".to_vec(),
                    expected: crate::store::types::FactExpectation::Absent,
                    value: Some(
                        crate::store::encode("ref target", &child_target)
                            .expect("encode child target"),
                    ),
                }],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish colliding child ref");
        let staged = prepare_mutation_with(
            &ctx,
            Request::LandExecute(Box::new(WireMutation {
                request_id: request_id(),
                args: LandExecuteArgs {
                    plan: reply.plan,
                    candidate: oid,
                },
            })),
        )
        .expect("land.execute stages against a moved ref namespace");
        let transaction = staged
            .ref_transaction
            .as_ref()
            .expect("land.execute stages its target move");
        let err = transaction
            .check(&StoreRefs::new(&store))
            .expect_err("a new directory/file collision refuses at publication");
        assert!(
            matches!(err, crate::refdata::RefError::Collision { .. }),
            "a collision refuses, got: {err:?}"
        );
    }

    #[test]
    fn land_prepare_refuses_a_remote_push_leg() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(None, land_caps());
        let ctx = full_ctx(
            &store,
            session,
            Some(&row),
            Some(&clock),
            Some(&open_checkpoint),
        );
        let (head, change, _) = seed_commit(&store, None);
        let err = prepare_mutation_with(&ctx, land_request_remote(change, Some(head)))
            .expect_err("remote land.prepare refuses");
        assert_eq!(err.code, ErrorCode::EHosted);
    }

    #[test]
    fn land_prepare_refuses_without_context() {
        let (_temp, store, session) = fixture();
        let (_, change, _) = seed_commit(&store, None);
        let err = prepare_mutation(&store, session, land_request(change, None))
            .expect_err("land.prepare stays refused on the legacy path");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("identity row"),
            "land.prepare names its missing row: {}",
            err.message
        );
    }

    #[test]
    fn land_prepare_needs_land_capability() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(None, Capabilities::default());
        let ctx = full_ctx(
            &store,
            session,
            Some(&row),
            Some(&clock),
            Some(&open_checkpoint),
        );
        let (head, change, _) = seed_commit(&store, None);
        let err = prepare_mutation_with(&ctx, land_request(change, Some(head)))
            .expect_err("land.prepare without the land grant is forbidden");
        assert_eq!(err.code, ErrorCode::EForbidden);
    }

    #[test]
    fn land_prepare_resolves_change_ref() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(None, land_caps());
        let ctx = full_ctx(
            &store,
            session,
            Some(&row),
            Some(&clock),
            Some(&open_checkpoint),
        );
        let missing = ChangeId::generate();
        let err = prepare_mutation_with(&ctx, land_request(missing, None))
            .expect_err("unknown change is not found");
        assert_eq!(err.code, ErrorCode::ENotFound);
        let change = ChangeId::generate();
        seed_commit(&store, Some(change));
        seed_commit(&store, Some(change));
        let err = prepare_mutation_with(&ctx, land_request(change, None))
            .expect_err("divergent change needs a pinned head");
        assert_eq!(err.code, ErrorCode::EDivergent);
    }

    #[test]
    fn transport_arms_name_their_machinery() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(None, land_caps());
        let ctx = full_ctx(
            &store,
            session,
            Some(&row),
            Some(&clock),
            Some(&open_checkpoint),
        );
        let fetch = Request::Fetch(Box::new(WireMutation {
            request_id: request_id(),
            args: FetchArgs {
                remote: origin_remote(),
                refs: FetchRefs::AllBranches,
                depth: None,
                filter: FetchFilter::default(),
            },
        }));
        let err = prepare_mutation_with(&ctx, fetch).expect_err("fetch stays refused with context");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("transport job"),
            "fetch names its missing job: {}",
            err.message
        );
        let push = Request::Push(Box::new(WireMutation {
            request_id: request_id(),
            args: PushArgs {
                remote: origin_remote(),
                updates: vec![PushUpdate {
                    remote_ref: name("refs/heads/agent/x"),
                    source: PushSource::Delete,
                    expected_old: None,
                    force: false,
                }],
                atomicity: PushAtomicity::default(),
            },
        }));
        let err = prepare_mutation_with(&ctx, push).expect_err("push stays refused with context");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("PushPlanRecord"),
            "push names its codec owner: {}",
            err.message
        );
        let reconcile = Request::PushReconcile(Box::new(WireMutation {
            request_id: request_id(),
            args: PushReconcileArgs {
                plan: PlanId::generate(),
            },
        }));
        let err = prepare_mutation_with(&ctx, reconcile)
            .expect_err("push.reconcile stays refused with context");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("not lane work"),
            "push.reconcile names its network leg: {}",
            err.message
        );
        let execute = Request::LandExecute(Box::new(WireMutation {
            request_id: request_id(),
            args: LandExecuteArgs {
                plan: PlanId::generate(),
                candidate: oid(0x31),
            },
        }));
        let err =
            prepare_mutation_with(&ctx, execute).expect_err("unknown land.execute plan refuses");
        assert_eq!(err.code, ErrorCode::ENotFound);
        assert!(
            err.message.contains("unknown land plan"),
            "land.execute names the missing plan: {}",
            err.message
        );
    }

    fn claim_all_caps() -> Capabilities {
        Capabilities {
            claim_paths: vec![PathPattern::parse("**").expect("claim pattern")],
            ..Capabilities::default()
        }
    }

    fn session_row_caps(identity: Option<IdentityClaim>, capabilities: Capabilities) -> SessionRow {
        SessionRow {
            principal: Principal::from_peer_uid(1000),
            identity,
            claims: ProvenanceClaims::default(),
            capabilities,
            secret_hash: [0; 32],
            authority: SessionAuthority::Active {
                idle_expires_at: Timestamp::new(jiff::Timestamp::now()),
            },
        }
    }

    fn ada_claim() -> IdentityClaim {
        IdentityClaim {
            name: "Ada".to_string(),
            email: "ada@example.invalid".to_string(),
        }
    }

    fn empty_tree_oid(store: &Store) -> Oid {
        store
            .hash_kind()
            .hash_git_object("tree", b"")
            .expect("empty tree hashes")
    }

    #[test]
    fn new_mints_empty_tree_with_session_identity() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);
        let prepared = prepare_mutation_with(
            &ctx,
            Request::New(Box::new(WireMutation {
                request_id: request_id(),
                args: NewArgs {
                    parents: Vec::new(),
                    description: ByteString::from("root change"),
                    identity: None,
                    workspace: None,
                },
            })),
        )
        .expect("new prepares");
        let Reply::New(reply) = prepared.reply else {
            panic!("new must answer its own reply");
        };
        // A fresh change every time: never the tree's stable by-OID mapping.
        assert_ne!(
            reply.created.change,
            ChangeId::from_oid(&empty_tree_oid(&store))
        );
        assert_eq!(reply.state, None);
        let Some(identity) = reply.outcome.identity else {
            panic!("new must report its recorded identity");
        };
        assert_eq!(identity.name, "Ada");
        assert_eq!(identity.source, IdentitySource::SessionClaim);
        // The empty tree stages with the candidate (so the lane publishes
        // both atomically) while preparation itself publishes nothing: the
        // tree is unreadable before the publish below.
        assert_eq!(prepared.objects.len(), 2);
        assert_eq!(prepared.objects[0].kind(), ObjectKind::Tree);
        assert_eq!(prepared.objects[1].kind(), ObjectKind::Commit);
        assert!(store.read(empty_tree_oid(&store)).is_err());
        assert!(!prepared.facts.is_empty());
        assert!(prepared.workspace_fence.is_none());
        assert!(prepared.ref_transaction.is_none());

        // The staged parts commit: the head resolves to a stored commit.
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish new");
        let read = store.read(empty_tree_oid(&store)).expect("read empty tree");
        assert_eq!(read.kind, ObjectKind::Tree);
        assert!(
            Records::new(&store)
                .get_commit(&reply.created.head)
                .expect("read commit")
                .is_some()
        );

        // Minting again reuses the stored tree and mints another change.
        let repeat = prepare_mutation_with(
            &ctx,
            Request::New(Box::new(WireMutation {
                request_id: request_id(),
                args: NewArgs {
                    parents: Vec::new(),
                    description: ByteString::from("second root"),
                    identity: None,
                    workspace: None,
                },
            })),
        )
        .expect("second new prepares");
        assert_eq!(repeat.objects.len(), 1, "candidate carries only its commit");
        let Reply::New(repeat_reply) = repeat.reply else {
            panic!("new must answer its own reply");
        };
        assert_ne!(repeat_reply.created.change, reply.created.change);
    }

    fn git_commit_args(
        store: &Store,
        parent: Head,
        branch: RefName,
        expected: RefExpect,
    ) -> GitCommitArgs {
        let tree = store
            .prepare(ObjectKind::Tree, 0, std::io::Cursor::new(Vec::new()), None)
            .expect("stage lane tree");
        let tree_oid = tree.oid();
        store
            .publish(
                vec![tree],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish lane tree");
        GitCommitArgs {
            tree: tree_oid,
            parents: vec![parent],
            author: signature(),
            committer: signature(),
            message: ByteString::from("lane commit"),
            change_id: None,
            predecessor: None,
            ref_update: Some(GitCommitRefUpdate {
                name: branch,
                expected,
            }),
        }
    }

    #[test]
    fn git_commit_records_tree_and_moves_ref_atomically() {
        let (_temp, store, session) = fixture();
        let (parent, _, _) = seed_commit(&store, None);
        let branch = name("refs/heads/main");
        let prepared = prepare_mutation(
            &store,
            session,
            Request::GitCommit(Box::new(WireMutation {
                request_id: request_id(),
                args: git_commit_args(&store, parent, branch.clone(), RefExpect::Absent),
            })),
        )
        .expect("git.commit prepares");
        let Reply::GitCommit(reply) = prepared.reply else {
            panic!("git.commit must answer its own reply");
        };
        let new_oid = reply
            .created
            .head
            .as_git()
            .copied()
            .expect("lane commit has a git identity");
        assert!(prepared.ref_transaction.is_some());
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish lane commit");
        assert!(
            Records::new(&store)
                .get_commit(&reply.created.head)
                .expect("read commit")
                .is_some()
        );
        let stored = StoreRefs::new(&store).get(&branch).expect("read ref");
        assert_eq!(stored, Some(RefTarget::Direct(new_oid)));
    }

    #[test]
    fn git_commit_replays_landed_ref_without_transaction() {
        let (_temp, store, session) = fixture();
        let (parent, _, _) = seed_commit(&store, None);
        let branch = name("refs/heads/main");
        let first = prepare_mutation(
            &store,
            session,
            Request::GitCommit(Box::new(WireMutation {
                request_id: request_id(),
                args: git_commit_args(&store, parent, branch.clone(), RefExpect::Absent),
            })),
        )
        .expect("first git.commit prepares");
        assert!(first.ref_transaction.is_some());
        store
            .publish(
                first.objects,
                &first.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish first lane commit");
        // The retry carries the original (now stale) expectation, but the
        // commit already landed and the ref already holds it, so preparation
        // succeeds with nothing left to publish instead of failing its own
        // compare-and-swap.
        let repeat = prepare_mutation(
            &store,
            session,
            Request::GitCommit(Box::new(WireMutation {
                request_id: request_id(),
                args: git_commit_args(&store, parent, branch, RefExpect::Absent),
            })),
        )
        .expect("landed git.commit re-prepares");
        assert!(repeat.objects.is_empty());
        assert!(repeat.facts.is_empty());
        assert!(repeat.ref_transaction.is_none());
        let Reply::GitCommit(repeat_reply) = repeat.reply else {
            panic!("git.commit must answer its own reply");
        };
        let Reply::GitCommit(first_reply) = first.reply else {
            panic!("git.commit must answer its own reply");
        };
        assert_eq!(repeat_reply.created.head, first_reply.created.head);
    }

    #[test]
    fn new_parents_and_override_identity() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);
        let (parent, parent_change, _) = seed_commit(&store, None);
        let prepared = prepare_mutation_with(
            &ctx,
            Request::New(Box::new(WireMutation {
                request_id: request_id(),
                args: NewArgs {
                    parents: vec![parent],
                    description: ByteString::from("child"),
                    identity: Some(IdentityClaim {
                        name: "Bea".to_string(),
                        email: "bea@example.invalid".to_string(),
                    }),
                    workspace: None,
                },
            })),
        )
        .expect("new on a parent prepares");
        let Reply::New(reply) = prepared.reply else {
            panic!("new must answer its own reply");
        };
        assert_ne!(reply.created.change, parent_change);
        let Some(identity) = reply.outcome.identity else {
            panic!("new must report its recorded identity");
        };
        assert_eq!(identity.name, "Bea");
        assert_eq!(identity.source, IdentitySource::OperationOverride);
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish child");
        let record = Records::new(&store)
            .get_commit(&reply.created.head)
            .expect("read commit")
            .expect("child is stored");
        assert_eq!(record.parents(), &[parent]);
    }

    #[test]
    fn new_refuses_without_context_identity_or_merge() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let (parent, _, _) = seed_commit(&store, None);
        let (other, _, _) = seed_commit(&store, None);

        // Several parents need merge evaluation with no producer here.
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);
        let err = prepare_mutation_with(
            &ctx,
            Request::New(Box::new(WireMutation {
                request_id: request_id(),
                args: NewArgs {
                    parents: vec![parent, other],
                    description: ByteString::from("merge"),
                    identity: None,
                    workspace: None,
                },
            })),
        )
        .expect_err("multi-parent new stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);

        // Neither an override nor a session identity is invalid, not hosted:
        // no configuration ladder exists for the coordinator to consult.
        let bare = session_row_caps(None, claim_all_caps());
        let bare_ctx = full_ctx(&store, session, Some(&bare), Some(&clock), None);
        let err = prepare_mutation_with(
            &bare_ctx,
            Request::New(Box::new(WireMutation {
                request_id: request_id(),
                args: NewArgs {
                    parents: Vec::new(),
                    description: ByteString::from("nobody"),
                    identity: None,
                    workspace: None,
                },
            })),
        )
        .expect_err("identity-less new is invalid");
        assert_eq!(err.code, ErrorCode::EInvalid);

        // An unstored parent is not found.
        let err = prepare_mutation_with(
            &ctx,
            Request::New(Box::new(WireMutation {
                request_id: request_id(),
                args: NewArgs {
                    parents: vec![Head::Git { oid: oid(0x99) }],
                    description: ByteString::from("ghost parent"),
                    identity: None,
                    workspace: None,
                },
            })),
        )
        .expect_err("unstored parent is not found");
        assert_eq!(err.code, ErrorCode::ENotFound);

        // The legacy path carries no row or clock and stays refused.
        let err = prepare_mutation(
            &store,
            session,
            Request::New(Box::new(WireMutation {
                request_id: request_id(),
                args: NewArgs {
                    parents: Vec::new(),
                    description: ByteString::from("legacy"),
                    identity: Some(ada_claim()),
                    workspace: None,
                },
            })),
        )
        .expect_err("legacy new stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
    }

    #[test]
    fn new_workspace_switch_fences_native() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);

        // Create the workspace through `ws.new`, then switch it with `new`.
        let ws = prepare_mutation_with(
            &ctx,
            Request::WsNew(Box::new(WireMutation {
                request_id: request_id(),
                args: WsNewArgs {
                    root: ByteString::from("/tmp/ruk-w2-test"),
                    init: WorkspaceInit::Native {
                        parents: Vec::new(),
                    },
                    scope: None,
                },
            })),
        )
        .expect("ws.new prepares");
        store
            .publish(
                ws.objects,
                &ws.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish workspace");
        let Reply::WsNew(ws_reply) = ws.reply else {
            panic!("ws.new must answer its own reply");
        };
        let before = ws_reply.state.stamp();
        let binding = WorkspaceBinding {
            workspace: ws_reply.workspace,
            expected: before,
        };
        let switched = prepare_mutation_with(
            &ctx,
            Request::New(Box::new(WireMutation {
                request_id: request_id(),
                args: NewArgs {
                    parents: Vec::new(),
                    description: ByteString::from("switched"),
                    identity: None,
                    workspace: Some(binding),
                },
            })),
        )
        .expect("workspace switch prepares");
        assert_eq!(switched.workspace_fence, Some((ws_reply.workspace, before)));
        let Reply::New(switched_reply) = switched.reply else {
            panic!("new must answer its own reply");
        };
        let Some(state) = switched_reply.state else {
            panic!("a switch must answer the resulting state");
        };
        assert_eq!(state.stamp().sequence, before.sequence + 1);
        let facts: Vec<_> = switched
            .facts
            .iter()
            .filter(|fact| fact.table == crate::store::types::FactTable::Workspaces)
            .collect();
        assert_eq!(facts.len(), 1);
        store
            .publish(
                switched.objects,
                &switched.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish switch");

        // A holder that is not the session loses the fence, not the call.
        let holder = SessionId::generate();
        let holder_row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let holder_ctx = full_ctx(&store, holder, Some(&holder_row), Some(&clock), None);
        let err = prepare_mutation_with(
            &holder_ctx,
            Request::New(Box::new(WireMutation {
                request_id: request_id(),
                args: NewArgs {
                    parents: Vec::new(),
                    description: ByteString::from("seized"),
                    identity: None,
                    workspace: Some(WorkspaceBinding {
                        workspace: ws_reply.workspace,
                        expected: state.stamp(),
                    }),
                },
            })),
        )
        .expect_err("foreign holder loses the fence");
        assert_eq!(err.code, ErrorCode::ELeaseLost);

        // An unknown workspace is not found.
        let err = prepare_mutation_with(
            &ctx,
            Request::New(Box::new(WireMutation {
                request_id: request_id(),
                args: NewArgs {
                    parents: Vec::new(),
                    description: ByteString::from("ghost workspace"),
                    identity: None,
                    workspace: Some(workspace_binding()),
                },
            })),
        )
        .expect_err("unknown workspace is not found");
        assert_eq!(err.code, ErrorCode::ENotFound);
    }

    #[test]
    fn claim_acquire_validates_without_sealing() {
        let (_temp, store, session) = fixture();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), None, None);
        let prepared = prepare_mutation_with(
            &ctx,
            Request::ClaimAcquire(Box::new(WireMutation {
                request_id: request_id(),
                args: ClaimAcquireArgs {
                    paths: vec![
                        RepoPath::new("src/lib.rs").expect("test path"),
                        RepoPath::new("src").expect("test path"),
                    ],
                    ttl: ClaimTtl::new(60).expect("ttl"),
                    mode: ClaimMode::Enforce,
                },
            })),
        )
        .expect("claim.acquire prepares");
        let Reply::ClaimAcquire(reply) = prepared.reply else {
            panic!("claim.acquire must answer its own reply");
        };
        // Covered paths canonicalize to their ancestor; the id is minted but
        // nothing seals outside the lane.
        assert_eq!(
            reply.claim.paths,
            vec![RepoPath::new("src").expect("test path")]
        );
        assert_eq!(reply.claim.holder, session);
        assert_ne!(reply.claim.claim, ClaimId::nil());
        assert!(prepared.facts.is_empty());
        assert!(prepared.objects.is_empty());
        let stored = read_record(&store, reply.claim.claim).expect("read claim");
        assert_eq!(stored, None, "prepare stages no claim facts");

        // Outside the session's grant the same call is forbidden.
        let narrow = session_row_caps(Some(ada_claim()), Capabilities::default());
        let narrow_ctx = full_ctx(&store, session, Some(&narrow), None, None);
        let err = prepare_mutation_with(
            &narrow_ctx,
            Request::ClaimAcquire(Box::new(WireMutation {
                request_id: request_id(),
                args: ClaimAcquireArgs {
                    paths: vec![RepoPath::new("src").expect("test path")],
                    ttl: ClaimTtl::new(60).expect("ttl"),
                    mode: ClaimMode::Enforce,
                },
            })),
        )
        .expect_err("uncovered path is forbidden");
        assert_eq!(err.code, ErrorCode::EForbidden);

        // An empty path set is invalid before any capability check.
        let err = prepare_mutation_with(
            &ctx,
            Request::ClaimAcquire(Box::new(WireMutation {
                request_id: request_id(),
                args: ClaimAcquireArgs {
                    paths: Vec::new(),
                    ttl: ClaimTtl::new(60).expect("ttl"),
                    mode: ClaimMode::Enforce,
                },
            })),
        )
        .expect_err("empty claim paths are invalid");
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn claim_release_predicts_the_stored_record() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let claims =
            crate::coord::claims::ClaimClock::open(&store, clock).expect("claim clock opens");
        let sealed = crate::coord::claims::seal_acquire(
            &store,
            &claims,
            session,
            ClaimId::generate(),
            ClaimAcquireArgs {
                paths: vec![RepoPath::new("src").expect("test path")],
                ttl: ClaimTtl::new(60).expect("ttl"),
                mode: ClaimMode::Enforce,
            },
            None,
        )
        .expect("seal fixture claim");
        store
            .publish(
                Vec::new(),
                &sealed.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish fixture claim");

        // The legacy path serves releases: prediction is a read, and the
        // lane re-seals authoritatively at commit time.
        let prepared = prepare_mutation(
            &store,
            session,
            Request::ClaimRelease(Box::new(WireMutation {
                request_id: request_id(),
                args: ClaimReleaseArgs {
                    claim: sealed.record.claim,
                },
            })),
        )
        .expect("claim.release prepares");
        let Reply::ClaimRelease(reply) = prepared.reply else {
            panic!("claim.release must answer its own reply");
        };
        assert_eq!(reply.released, sealed.record);
        assert!(prepared.facts.is_empty());

        // An unknown claim is not found.
        let err = prepare_mutation(
            &store,
            session,
            Request::ClaimRelease(Box::new(WireMutation {
                request_id: request_id(),
                args: ClaimReleaseArgs {
                    claim: ClaimId::generate(),
                },
            })),
        )
        .expect_err("unknown claim is not found");
        assert_eq!(err.code, ErrorCode::ENotFound);

        // Another session's claim is forbidden.
        let holder = SessionId::generate();
        let err = prepare_mutation(
            &store,
            holder,
            Request::ClaimRelease(Box::new(WireMutation {
                request_id: request_id(),
                args: ClaimReleaseArgs {
                    claim: sealed.record.claim,
                },
            })),
        )
        .expect_err("foreign claim is forbidden");
        assert_eq!(err.code, ErrorCode::EForbidden);
    }

    #[test]
    fn ws_new_creates_native_and_gitcompat_rows() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);

        // Native creation mints a fresh change and reports the session claim.
        let prepared = prepare_mutation_with(
            &ctx,
            Request::WsNew(Box::new(WireMutation {
                request_id: request_id(),
                args: WsNewArgs {
                    root: ByteString::from("/tmp/ruk-w2-native"),
                    init: WorkspaceInit::Native {
                        parents: Vec::new(),
                    },
                    scope: None,
                },
            })),
        )
        .expect("native ws.new prepares");
        let Reply::WsNew(reply) = prepared.reply else {
            panic!("ws.new must answer its own reply");
        };
        let Some(identity) = reply.outcome.identity else {
            panic!("native ws.new must report its recorded identity");
        };
        assert_eq!(identity.source, IdentitySource::SessionClaim);
        assert_eq!(
            reply.state.scope(),
            &crate::workspace::Scope::Full,
            "an absent scope means the full tree"
        );
        assert!(prepared.workspace_fence.is_none());
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish native workspace");

        // GitCompat creation is context-free: no identity, no clock.
        let (parent, _, parent_oid) = seed_commit(&store, None);
        let _ = parent;
        let prepared = prepare_mutation(
            &store,
            session,
            Request::WsNew(Box::new(WireMutation {
                request_id: request_id(),
                args: WsNewArgs {
                    root: ByteString::from("/tmp/ruk-w2-git"),
                    init: WorkspaceInit::GitCompat {
                        head: crate::workspace::HeadRef::Detached(parent_oid),
                    },
                    scope: None,
                },
            })),
        )
        .expect("gitcompat ws.new prepares on the legacy path");
        let Reply::WsNew(reply) = prepared.reply else {
            panic!("ws.new must answer its own reply");
        };
        assert!(reply.outcome.identity.is_none());
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish gitcompat workspace");

        // Native creation without an identity is invalid, even with a clock.
        let bare = session_row_caps(None, claim_all_caps());
        let bare_ctx = full_ctx(&store, session, Some(&bare), Some(&clock), None);
        let err = prepare_mutation_with(
            &bare_ctx,
            Request::WsNew(Box::new(WireMutation {
                request_id: request_id(),
                args: WsNewArgs {
                    root: ByteString::from("/tmp/ruk-w2-bare"),
                    init: WorkspaceInit::Native {
                        parents: Vec::new(),
                    },
                    scope: None,
                },
            })),
        )
        .expect_err("identity-less ws.new is invalid");
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn ws_new_refuses_a_detached_head_outside_the_store() {
        let (_temp, store, session) = fixture();
        let err = prepare_mutation(
            &store,
            session,
            Request::WsNew(Box::new(WireMutation {
                request_id: request_id(),
                args: WsNewArgs {
                    root: ByteString::from("/tmp/ruk-w2-ghost"),
                    init: WorkspaceInit::GitCompat {
                        head: HeadRef::Detached(oid(0x44)),
                    },
                    scope: None,
                },
            })),
        )
        .expect_err("an unstored commit is not found");
        assert_eq!(err.code, ErrorCode::ENotFound);
        assert!(
            err.message.contains("not a stored commit"),
            "names the hazard: {}",
            err.message
        );
    }
    fn change_target() -> ChangeRef {
        ChangeRef {
            change: ChangeId::from_bytes([0x22; 16]),
            head: None,
        }
    }

    fn workspace_binding() -> WorkspaceBinding {
        WorkspaceBinding {
            workspace: WorkspaceId::generate(),
            expected: WorkspaceStamp {
                sequence: 0,
                lease_epoch: 0,
            },
        }
    }

    /// Seeds a native workspace through `ws.new` and publishes it, returning
    /// its id and state. Needs a context with a session identity and clock.
    fn seed_workspace(
        store: &Store,
        ctx: &PrepareContext<'_>,
        scope: Option<Scope>,
    ) -> (WorkspaceId, WorkspaceState) {
        let prepared = prepare_mutation_with(
            ctx,
            Request::WsNew(Box::new(WireMutation {
                request_id: request_id(),
                args: WsNewArgs {
                    root: ByteString::from("/tmp/ruk-w4-test"),
                    init: WorkspaceInit::Native {
                        parents: Vec::new(),
                    },
                    scope,
                },
            })),
        )
        .expect("ws.new prepares");
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish workspace");
        let Reply::WsNew(reply) = prepared.reply else {
            panic!("ws.new must answer its own reply");
        };
        (reply.workspace, reply.state)
    }

    fn edit_request(binding: WorkspaceBinding, target: ChangeRef) -> Request {
        Request::Edit(Box::new(WireMutation {
            request_id: request_id(),
            args: EditArgs { binding, target },
        }))
    }

    #[test]
    fn edit_checks_out_resolved_change_on_both_paths() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);
        let (head, change, _) = seed_commit(&store, None);
        let (id, state) = seed_workspace(&store, &ctx, None);
        let before = state.stamp();
        let binding = WorkspaceBinding {
            workspace: id,
            expected: before,
        };
        let target = ChangeRef {
            change,
            head: Some(head),
        };

        let prepared =
            prepare_mutation_with(&ctx, edit_request(binding, target)).expect("edit prepares");
        assert_eq!(prepared.workspace_fence, Some((id, before)));
        let Reply::Edit(reply) = prepared.reply else {
            panic!("edit must answer its own reply");
        };
        let WorkspaceState::Native(next) = &reply.state else {
            panic!("edit of a native workspace stays native");
        };
        assert_eq!(next.change, change);
        assert_eq!(next.head, head);
        assert_eq!(next.stamp.sequence, before.sequence + 1);
        assert_eq!(prepared.facts.len(), 1);
        assert_eq!(
            prepared.facts[0].table,
            crate::store::types::FactTable::Workspaces
        );
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish edit");

        // The row transition is context-free, so the legacy path serves it
        // too once the caller holds the fresh stamp.
        let legacy = prepare_mutation(
            &store,
            session,
            edit_request(
                WorkspaceBinding {
                    workspace: id,
                    expected: reply.state.stamp(),
                },
                target,
            ),
        )
        .expect("edit serves on the legacy path");
        let Reply::Edit(legacy_reply) = legacy.reply else {
            panic!("edit must answer its own reply");
        };
        assert_eq!(legacy_reply.state.stamp().sequence, before.sequence + 2);
    }

    #[test]
    fn edit_refuses_gitcompat_and_bad_bindings() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);
        let (head, change, commit_oid) = seed_commit(&store, None);
        let target = ChangeRef {
            change,
            head: Some(head),
        };

        // A GitCompat workspace has no checkout producer here.
        let git = prepare_mutation_with(
            &ctx,
            Request::WsNew(Box::new(WireMutation {
                request_id: request_id(),
                args: WsNewArgs {
                    root: ByteString::from("/tmp/ruk-w4-git"),
                    init: WorkspaceInit::GitCompat {
                        head: HeadRef::Detached(commit_oid),
                    },
                    scope: None,
                },
            })),
        )
        .expect("gitcompat ws.new prepares");
        store
            .publish(
                git.objects,
                &git.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish gitcompat workspace");
        let Reply::WsNew(git_reply) = git.reply else {
            panic!("ws.new must answer its own reply");
        };
        let err = prepare_mutation_with(
            &ctx,
            edit_request(
                WorkspaceBinding {
                    workspace: git_reply.workspace,
                    expected: git_reply.state.stamp(),
                },
                target,
            ),
        )
        .expect_err("gitcompat edit stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("HEAD/index application"),
            "gitcompat edit names its missing producer: {}",
            err.message
        );

        // An unknown workspace is not found.
        let err = prepare_mutation_with(&ctx, edit_request(workspace_binding(), target))
            .expect_err("unknown workspace is not found");
        assert_eq!(err.code, ErrorCode::ENotFound);

        // A holder that is not the session loses the fence, not the call.
        let (id, state) = seed_workspace(&store, &ctx, None);
        let holder = SessionId::generate();
        let holder_row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let holder_ctx = full_ctx(&store, holder, Some(&holder_row), Some(&clock), None);
        let err = prepare_mutation_with(
            &holder_ctx,
            edit_request(
                WorkspaceBinding {
                    workspace: id,
                    expected: state.stamp(),
                },
                target,
            ),
        )
        .expect_err("foreign holder loses the fence");
        assert_eq!(err.code, ErrorCode::ELeaseLost);

        // A moved stamp is stale.
        let err = prepare_mutation_with(
            &ctx,
            edit_request(
                WorkspaceBinding {
                    workspace: id,
                    expected: WorkspaceStamp {
                        sequence: 7,
                        lease_epoch: 0,
                    },
                },
                target,
            ),
        )
        .expect_err("moved stamp is stale");
        assert_eq!(err.code, ErrorCode::EStale);

        // An unpinned divergent change names every head.
        let (_, divergent, _) = seed_commit(&store, None);
        seed_commit(&store, Some(divergent));
        let err = prepare_mutation_with(
            &ctx,
            edit_request(
                WorkspaceBinding {
                    workspace: id,
                    expected: state.stamp(),
                },
                ChangeRef {
                    change: divergent,
                    head: None,
                },
            ),
        )
        .expect_err("unpinned divergent change");
        assert_eq!(err.code, ErrorCode::EDivergent);
    }

    #[test]
    fn ws_scope_replaces_scope_on_both_paths() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);
        let (id, state) = seed_workspace(&store, &ctx, None);
        let before = state.stamp();
        let scope = Scope::cone([RepoPath::new("src").expect("test path")]);

        let prepared = prepare_mutation_with(
            &ctx,
            Request::WsScope(Box::new(WireMutation {
                request_id: request_id(),
                args: WsScopeArgs {
                    binding: WorkspaceBinding {
                        workspace: id,
                        expected: before,
                    },
                    scope: scope.clone(),
                },
            })),
        )
        .expect("ws.scope prepares");
        assert_eq!(prepared.workspace_fence, Some((id, before)));
        let Reply::WsScope(reply) = prepared.reply else {
            panic!("ws.scope must answer its own reply");
        };
        assert_eq!(reply.state.scope(), &scope);
        assert_eq!(reply.state.stamp().sequence, before.sequence + 1);
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish scope");

        let legacy = prepare_mutation(
            &store,
            session,
            Request::WsScope(Box::new(WireMutation {
                request_id: request_id(),
                args: WsScopeArgs {
                    binding: WorkspaceBinding {
                        workspace: id,
                        expected: reply.state.stamp(),
                    },
                    scope: Scope::Full,
                },
            })),
        )
        .expect("ws.scope serves on the legacy path");
        let Reply::WsScope(legacy_reply) = legacy.reply else {
            panic!("ws.scope must answer its own reply");
        };
        assert_eq!(legacy_reply.state.scope(), &Scope::Full);
    }

    #[test]
    fn ws_take_advances_epoch_pinned_and_seized() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);
        let (id, state) = seed_workspace(&store, &ctx, None);
        let before = state.stamp();

        // A pinned take keeps the sequence and raises the epoch.
        let prepared = prepare_mutation_with(
            &ctx,
            Request::WsTake(Box::new(WireMutation {
                request_id: request_id(),
                args: WsTakeArgs {
                    workspace: id,
                    expected: Some(before),
                },
            })),
        )
        .expect("pinned take prepares");
        assert_eq!(prepared.workspace_fence, Some((id, before)));
        let Reply::WsTake(reply) = prepared.reply else {
            panic!("ws.take must answer its own reply");
        };
        assert_eq!(reply.state.stamp().sequence, before.sequence);
        assert_eq!(reply.state.stamp().lease_epoch, before.lease_epoch + 1);
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish take");

        // An unpinned take seizes from whoever holds the workspace and
        // carries no lane fence: the lane would re-check the holder against
        // the still-old row.
        let intruder = SessionId::generate();
        let intruder_row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let intruder_ctx = full_ctx(&store, intruder, Some(&intruder_row), Some(&clock), None);
        let seized = prepare_mutation_with(
            &intruder_ctx,
            Request::WsTake(Box::new(WireMutation {
                request_id: request_id(),
                args: WsTakeArgs {
                    workspace: id,
                    expected: None,
                },
            })),
        )
        .expect("seize prepares");
        assert_eq!(seized.workspace_fence, None);
        let Reply::WsTake(seized_reply) = seized.reply else {
            panic!("ws.take must answer its own reply");
        };
        assert_eq!(
            seized_reply.state.stamp().lease_epoch,
            before.lease_epoch + 2
        );
        store
            .publish(
                seized.objects,
                &seized.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish seize");

        // The displaced holder's stamp can never match again.
        let err = prepare_mutation_with(
            &ctx,
            Request::WsTake(Box::new(WireMutation {
                request_id: request_id(),
                args: WsTakeArgs {
                    workspace: id,
                    expected: Some(reply.state.stamp()),
                },
            })),
        )
        .expect_err("displaced holder loses the fence");
        assert_eq!(err.code, ErrorCode::ELeaseLost);
    }

    #[test]
    fn ws_drop_removes_row_and_serves_legacy() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);
        let (id, state) = seed_workspace(&store, &ctx, None);
        let before = state.stamp();

        let prepared = prepare_mutation_with(
            &ctx,
            Request::WsDrop(Box::new(WireMutation {
                request_id: request_id(),
                args: WsDropArgs {
                    binding: WorkspaceBinding {
                        workspace: id,
                        expected: before,
                    },
                },
            })),
        )
        .expect("ws.drop prepares");
        assert_eq!(prepared.workspace_fence, Some((id, before)));
        assert_eq!(prepared.facts.len(), 1);
        assert!(prepared.facts[0].value.is_none());
        let Reply::WsDrop(_) = prepared.reply else {
            panic!("ws.drop must answer its own reply");
        };
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish drop");
        assert!(
            workspace::observe(&store, id).is_err(),
            "dropped workspace is gone"
        );

        // Dropping twice names the missing row, on either path.
        let again = Request::WsDrop(Box::new(WireMutation {
            request_id: request_id(),
            args: WsDropArgs {
                binding: WorkspaceBinding {
                    workspace: id,
                    expected: before,
                },
            },
        }));
        let err = prepare_mutation(&store, session, again).expect_err("second drop is not found");
        assert_eq!(err.code, ErrorCode::ENotFound);
    }

    #[test]
    fn snapshot_names_its_missing_job_split() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);
        let snapshot = |binding| {
            Request::Snapshot(Box::new(WireMutation {
                request_id: request_id(),
                args: SnapshotArgs { binding },
            }))
        };

        // An unknown workspace is not found: no machinery invented.
        let err = prepare_mutation_with(&ctx, snapshot(workspace_binding()))
            .expect_err("unknown workspace is not found");
        assert_eq!(err.code, ErrorCode::ENotFound);

        let (id, state) = seed_workspace(&store, &ctx, None);
        let binding = WorkspaceBinding {
            workspace: id,
            expected: state.stamp(),
        };
        let err =
            prepare_mutation_with(&ctx, snapshot(binding)).expect_err("snapshot stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("workcopy::snapshot"),
            "snapshot names its missing producer: {}",
            err.message
        );

        // Dirty state needs no context, so the legacy path refuses alike.
        let err = prepare_mutation(&store, session, snapshot(binding))
            .expect_err("snapshot stays refused on the legacy path");
        assert_eq!(err.code, ErrorCode::EHosted);

        // An open journal refuses with its own code before the job split.
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: crate::store::types::FactTable::WsApply,
                    key: ws_apply_key(id),
                    expected: FactExpectation::Absent,
                    value: Some(vec![0x01]),
                }],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("stage open journal");
        let err =
            prepare_mutation_with(&ctx, snapshot(binding)).expect_err("open journal refuses first");
        assert_eq!(err.code, ErrorCode::EWorkspaceApplying);

        // A pre-root row names the root backfill instead of the job split.
        let (head, change, _) = seed_commit(&store, None);
        let bare_id = WorkspaceId::generate();
        let bare = WorkspaceRow {
            state: WorkspaceState::Native(NativeWorkspace::new(change, head, Scope::Full)),
            holder: session,
            root: ByteString::from(""),
        };
        let value = rows::encode("workspace", &bare).expect("encode bare row");
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: crate::store::types::FactTable::Workspaces,
                    key: rows::workspace_key(bare_id).to_vec(),
                    expected: FactExpectation::Absent,
                    value: Some(value),
                }],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish bare row");
        let err = prepare_mutation_with(
            &ctx,
            snapshot(WorkspaceBinding {
                workspace: bare_id,
                expected: WorkspaceStamp::INITIAL,
            }),
        )
        .expect_err("pre-root snapshot names the root");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("WorkspaceRow.root"),
            "pre-root snapshot names the backfill: {}",
            err.message
        );
    }

    #[test]
    fn write_names_its_missing_job_split() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);
        let (id, state) = seed_workspace(&store, &ctx, None);
        let args = WriteArgs {
            binding: WorkspaceBinding {
                workspace: id,
                expected: state.stamp(),
            },
            edits: vec![crate::protocol::WriteEdit {
                path: RepoPath::new("noted.txt").expect("test path"),
                action: crate::protocol::EditAction::Delete,
            }],
        };
        let request = || {
            Request::Write(Box::new(WireMutation {
                request_id: request_id(),
                args: args.clone(),
            }))
        };
        let err = prepare_mutation_with(&ctx, request()).expect_err("write stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("workcopy::write"),
            "write names its missing producer: {}",
            err.message
        );
        let err =
            prepare_mutation(&store, session, request()).expect_err("write stays refused legacy");
        assert_eq!(err.code, ErrorCode::EHosted);
    }

    #[test]
    fn ws_recover_names_its_missing_job_split() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);
        let (id, state) = seed_workspace(&store, &ctx, None);
        let args = WsRecoverArgs {
            binding: WorkspaceBinding {
                workspace: id,
                expected: state.stamp(),
            },
            action: crate::protocol::RecoverAction::Resume,
        };
        let request = || {
            Request::WsRecover(Box::new(WireMutation {
                request_id: request_id(),
                args: args.clone(),
            }))
        };
        let err = prepare_mutation_with(&ctx, request()).expect_err("ws.recover stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("workcopy_journal::recover"),
            "ws.recover names its missing producer: {}",
            err.message
        );

        // An open journal is the normal case for recovery, so it does not
        // divert to the idle check; the job split is still the refusal.
        store
            .publish(
                Vec::new(),
                &[FactMutation {
                    table: crate::store::types::FactTable::WsApply,
                    key: ws_apply_key(id),
                    expected: FactExpectation::Absent,
                    value: Some(vec![0x01]),
                }],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("stage open journal");
        let err = prepare_mutation(&store, session, request())
            .expect_err("ws.recover stays refused with an open journal");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(err.message.contains("workcopy_journal::recover"));
    }

    #[test]
    fn ops_backed_mutations_name_their_missing_preparation() {
        let (_temp, store, session) = fixture();
        let target = change_target();
        let parent = Head::Git { oid: oid(0x11) };
        // `describe`, `rebase`, `squash`, and `abandon` preserve signatures
        // and serve on the legacy path too, as do the context-free workspace
        // row transitions (`edit`, `ws.scope`, `ws.take`, `ws.drop`); they
        // have dedicated tests below. The rest still name their missing
        // preparation here.
        let requests = [
            Request::New(Box::new(WireMutation {
                request_id: request_id(),
                args: NewArgs {
                    parents: Vec::new(),
                    description: ByteString::from("new change"),
                    identity: None,
                    workspace: None,
                },
            })),
            Request::Revert(Box::new(WireMutation {
                request_id: request_id(),
                args: RevertArgs {
                    target,
                    onto: vec![parent],
                    mainline: None,
                    description: None,
                    identity: None,
                    merge: MergeSelection::default(),
                },
            })),
        ];
        for request in requests {
            let method = request.method();
            request
                .validate()
                .expect("refused requests stay daemon-reachable");
            let err = prepare_mutation(&store, session, request)
                .expect_err("ops-backed mutation stays refused");
            assert_eq!(err.code, ErrorCode::EHosted, "method `{}`", method.as_str());
            assert!(
                err.message.contains("does not cover preparation"),
                "method `{}` names its missing preparation: {}",
                method.as_str(),
                err.message
            );
        }
    }

    /// Seeds one child commit on `parent` in its own fresh change unless
    /// `change` names one, publishing immediately so later prepares resolve it.
    fn seed_child(
        store: &Store,
        parent: Head,
        change: Option<ChangeId>,
        message: &str,
    ) -> (Head, ChangeId) {
        seed_child_on_tree(
            store,
            empty_tree_oid(store),
            vec![parent],
            Some(change.unwrap_or_else(ChangeId::generate)),
            message,
        )
    }

    fn seed_child_on_tree(
        store: &Store,
        tree: Oid,
        parents: Vec<Head>,
        change: Option<ChangeId>,
        message: &str,
    ) -> (Head, ChangeId) {
        let prepared = prepare_new(
            store,
            NewRequest {
                tree,
                parents,
                author: signature(),
                committer: signature(),
                message: ByteString::from(message),
                change_id: Some(change.unwrap_or_else(ChangeId::generate)),
                predecessor: None,
                provenance: None,
            },
        )
        .expect("prepare child commit");
        let head = prepared.output.head;
        let change = prepared.output.change_id;
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish child commit");
        (head, change)
    }

    /// Seeds a stored tree holding one file, distinct per marker byte.
    fn seed_tree(store: &Store, marker: u8) -> Oid {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"100644 f");
        bytes.push(marker);
        bytes.push(0);
        bytes.extend_from_slice(&[0x31; 20]);
        let staged = store
            .prepare(
                ObjectKind::Tree,
                u64::try_from(bytes.len()).expect("tree fits u64"),
                std::io::Cursor::new(bytes),
                None,
            )
            .expect("prepare marker tree");
        let oid = staged.oid();
        store
            .publish(
                vec![staged],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish marker tree");
        oid
    }

    fn commit_message(store: &Store, head: &Head) -> Vec<u8> {
        Records::new(store)
            .get_commit(head)
            .expect("read commit")
            .expect("commit is stored")
            .message()
            .to_vec()
    }

    fn commit_parents(store: &Store, head: &Head) -> Vec<Head> {
        Records::new(store)
            .get_commit(head)
            .expect("read commit")
            .expect("commit is stored")
            .parents()
            .to_vec()
    }

    fn change_heads(store: &Store, change: &ChangeId) -> Vec<Head> {
        Records::new(store)
            .get_change(change)
            .expect("read change")
            .expect("change is stored")
            .heads
            .clone()
    }

    fn describe_request(target: ChangeRef, description: &str) -> Request {
        Request::Describe(Box::new(WireMutation {
            request_id: request_id(),
            args: DescribeArgs {
                target,
                description: ByteString::from(description),
                identity: None,
                workspaces: Vec::new(),
            },
        }))
    }

    #[test]
    fn describe_rewrites_message_and_propagates_to_descendants() {
        let (_temp, store, session) = fixture();
        let (ahead, achange, _) = seed_commit(&store, None);
        let (bhead, bchange) = seed_child(&store, ahead, None, "b");
        let (chead, cchange) = seed_child(&store, bhead, None, "c");
        // History rewrites preserve signatures, so `describe` serves on the
        // legacy path with no session row or clock.
        let prepared = prepare_mutation(
            &store,
            session,
            describe_request(
                ChangeRef {
                    change: achange,
                    head: None,
                },
                "a rewritten",
            ),
        )
        .expect("describe prepares");
        let Reply::Describe(reply) = prepared.reply else {
            panic!("describe must answer its own reply");
        };
        assert_eq!(reply.rewrites.items.len(), 3);
        assert_eq!(reply.rewrites.items[0].old, ahead);
        assert_eq!(reply.abandoned.items.len(), 0);
        assert_eq!(reply.conflicted.items.len(), 0);
        assert_eq!(reply.outcome.heads.items.len(), 3);
        let new_a = reply.rewrites.items[0].new;
        let new_b = reply.rewrites.items[1].new;
        let new_c = reply.rewrites.items[2].new;
        assert_eq!(reply.rewrites.items[1].old, bhead);
        assert_eq!(reply.rewrites.items[2].old, chead);
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish describe");
        assert_eq!(commit_message(&store, &new_a), b"a rewritten");
        assert_eq!(commit_message(&store, &new_b), b"b");
        assert_eq!(commit_message(&store, &new_c), b"c");
        assert_eq!(commit_parents(&store, &new_b), vec![new_a]);
        assert_eq!(commit_parents(&store, &new_c), vec![new_b]);
        assert_eq!(change_heads(&store, &achange), vec![new_a]);
        assert_eq!(change_heads(&store, &bchange), vec![new_b]);
        assert_eq!(change_heads(&store, &cchange), vec![new_c]);
    }

    #[test]
    fn describe_resolves_targets_and_reports_identity() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let (ahead, achange) = seed_child(&store, seed_commit(&store, None).0, None, "a");
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);
        let prepared = prepare_mutation_with(
            &ctx,
            describe_request(
                ChangeRef {
                    change: achange,
                    head: Some(ahead),
                },
                "a reported",
            ),
        )
        .expect("pinned describe prepares");
        let Reply::Describe(reply) = prepared.reply else {
            panic!("describe must answer its own reply");
        };
        let identity = reply
            .outcome
            .identity
            .expect("describe reports the committed identity");
        // The rewrite preserves the seeded committer rather than recording
        // the session identity, so the reply reports who the commit names.
        assert_eq!(identity.source, IdentitySource::Preserved);
        assert_eq!(identity.name, "Ada");
        assert_eq!(identity.email, "ada@example.invalid");

        let missing = ChangeRef {
            change: ChangeId::from_bytes([0x77; 16]),
            head: None,
        };
        let err = prepare_mutation(&store, session, describe_request(missing, "ghost"))
            .expect_err("unknown change is not found");
        assert_eq!(err.code, ErrorCode::ENotFound);

        let foreign = ChangeRef {
            change: achange,
            head: Some(Head::Git { oid: oid(0x99) }),
        };
        let err = prepare_mutation(&store, session, describe_request(foreign, "stale"))
            .expect_err("foreign pinned head is stale");
        assert_eq!(err.code, ErrorCode::EStale);

        let (_, shared) = seed_child(&store, ahead, Some(achange), "divergent");
        let _ = shared;
        let bare = ChangeRef {
            change: achange,
            head: None,
        };
        let err = prepare_mutation(&store, session, describe_request(bare, "split"))
            .expect_err("divergent change needs a pin");
        assert_eq!(err.code, ErrorCode::EDivergent);

        let err = prepare_mutation(
            &store,
            session,
            describe_request(
                ChangeRef {
                    change: achange,
                    head: Some(ahead),
                },
                "a",
            ),
        )
        .expect_err("identical description is invalid");
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn describe_merges_same_change_rewrites_into_one_fact() {
        let (_temp, store, session) = fixture();
        let (ahead, achange, _) = seed_commit(&store, None);
        // A divergent head descending from another head of the same change:
        // the root rewrite and the descendant rewrite collide on the change
        // key and must merge rather than publish twice.
        let (bhead, _) = seed_child(&store, ahead, Some(achange), "same-change child");
        let prepared = prepare_mutation(
            &store,
            session,
            describe_request(
                ChangeRef {
                    change: achange,
                    head: Some(ahead),
                },
                "root rewritten",
            ),
        )
        .expect("same-change describe prepares");
        let Reply::Describe(reply) = prepared.reply else {
            panic!("describe must answer its own reply");
        };
        assert_eq!(reply.rewrites.items.len(), 2);
        let change_facts: Vec<_> = prepared
            .facts
            .iter()
            .filter(|fact| fact.table == crate::store::types::FactTable::Changes)
            .collect();
        assert_eq!(change_facts.len(), 1);
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish merged describe");
        assert_eq!(change_heads(&store, &achange).len(), 2);
        let _ = bhead;
    }

    #[test]
    fn describe_remaps_diamond_descendants() {
        let (_temp, store, session) = fixture();
        let (ahead, _, _) = seed_commit(&store, None);
        let (bhead, _) = seed_child(&store, ahead, None, "b");
        let (chead, _) = seed_child(&store, ahead, None, "c");
        let (dhead, _) = seed_child_on_tree(
            &store,
            empty_tree_oid(&store),
            vec![bhead, chead],
            None,
            "merge child",
        );
        // Describe the root: the merge descendant must follow BOTH rewritten
        // parents, never keep a superseded one.
        let prepared = prepare_mutation(
            &store,
            session,
            Request::Describe(Box::new(WireMutation {
                request_id: request_id(),
                args: DescribeArgs {
                    target: ChangeRef {
                        change: change_of(&store, &ahead),
                        head: Some(ahead),
                    },
                    description: ByteString::from("root rewritten"),
                    identity: None,
                    workspaces: Vec::new(),
                },
            })),
        )
        .expect("diamond describe prepares");
        let Reply::Describe(reply) = prepared.reply else {
            panic!("describe must answer its own reply");
        };
        assert_eq!(reply.rewrites.items.len(), 4);
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish diamond describe");
        let merge_rewrite = reply
            .rewrites
            .items
            .iter()
            .find(|rewrite| rewrite.old == dhead)
            .expect("merge child rewritten");
        let parents = commit_parents(&store, &merge_rewrite.new);
        assert_eq!(parents.len(), 2);
        for parent in &parents {
            assert!(
                reply
                    .rewrites
                    .items
                    .iter()
                    .any(|rewrite| rewrite.new == *parent),
                "merge child follows rewritten parents only"
            );
        }
    }

    fn change_of(store: &Store, head: &Head) -> ChangeId {
        Records::new(store)
            .get_commit(head)
            .expect("read commit")
            .expect("commit is stored")
            .change_id()
    }

    fn rebase_request(
        sources: Vec<ChangeRef>,
        scope: RebaseScope,
        onto: Vec<Head>,
        keep_empty: bool,
    ) -> Request {
        Request::Rebase(Box::new(WireMutation {
            request_id: request_id(),
            args: RebaseArgs {
                sources,
                scope,
                onto,
                merge: crate::protocol::MergeSelection::default(),
                keep_empty,
                workspaces: Vec::new(),
            },
        }))
    }

    #[test]
    fn rebase_moves_an_empty_chain() {
        let (_temp, store, session) = fixture();
        let (ohead, _, _) = seed_commit(&store, None);
        let (phead, _, _) = seed_commit(&store, None);
        let (shead, schange) = seed_child(&store, phead, None, "source");
        let (dhead, dchange) = seed_child(&store, shead, None, "child");
        let prepared = prepare_mutation(
            &store,
            session,
            rebase_request(
                vec![ChangeRef {
                    change: schange,
                    head: None,
                }],
                RebaseScope::SourceAndDescendants,
                vec![ohead],
                true,
            ),
        )
        .expect("empty rebase prepares");
        let Reply::Rebase(reply) = prepared.reply else {
            panic!("rebase must answer its own reply");
        };
        assert_eq!(reply.rewrites.items.len(), 2);
        assert_eq!(reply.rewrites.items[0].old, shead);
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish rebase");
        let new_s = reply.rewrites.items[0].new;
        let new_d = reply.rewrites.items[1].new;
        assert_eq!(new_d, reply.rewrites.items[1].new);
        assert_eq!(commit_parents(&store, &new_s), vec![ohead]);
        assert_eq!(commit_parents(&store, &new_d), vec![new_s]);
        assert_eq!(change_heads(&store, &schange), vec![new_s]);
        assert_eq!(change_heads(&store, &dchange), vec![new_d]);
        let _ = dhead;
    }

    #[test]
    fn rebase_revisions_only_reparents_to_old_parents() {
        let (_temp, store, session) = fixture();
        let (ohead, _, _) = seed_commit(&store, None);
        let (phead, _, _) = seed_commit(&store, None);
        let (shead, _) = seed_child(&store, phead, None, "source");
        let (dhead, dchange) = seed_child(&store, shead, None, "child");
        let prepared = prepare_mutation(
            &store,
            session,
            rebase_request(
                vec![ChangeRef {
                    change: change_of(&store, &shead),
                    head: Some(shead),
                }],
                RebaseScope::RevisionsOnly,
                vec![ohead],
                true,
            ),
        )
        .expect("revisions-only rebase prepares");
        let Reply::Rebase(reply) = prepared.reply else {
            panic!("rebase must answer its own reply");
        };
        assert_eq!(reply.rewrites.items.len(), 2);
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish revisions-only rebase");
        let new_d = reply.rewrites.items[1].new;
        assert_eq!(commit_parents(&store, &new_d), vec![phead]);
        assert_eq!(change_heads(&store, &dchange), vec![new_d]);
        let _ = dhead;
    }

    #[test]
    fn rebase_refusals_name_their_reason() {
        let (_temp, store, session) = fixture();
        let (ohead, _, _) = seed_commit(&store, None);
        let (phead, _, _) = seed_commit(&store, None);
        let (shead, schange) = seed_child(&store, phead, None, "source");
        let pinned = ChangeRef {
            change: schange,
            head: Some(shead),
        };
        // A source carrying content needs per-commit tree re-derivation.
        let full = seed_tree(&store, b'x');
        let (fhead, fchange) = seed_child_on_tree(&store, full, vec![phead], None, "full");
        let err = prepare_mutation(
            &store,
            session,
            rebase_request(
                vec![ChangeRef {
                    change: fchange,
                    head: Some(fhead),
                }],
                RebaseScope::SourceAndDescendants,
                vec![ohead],
                true,
            ),
        )
        .expect_err("content-carrying source stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("tree re-derivation"),
            "names derivation: {}",
            err.message
        );

        // Several onto parents mint a merge commit.
        let err = prepare_mutation(
            &store,
            session,
            rebase_request(
                vec![pinned],
                RebaseScope::SourceAndDescendants,
                vec![ohead, phead],
                true,
            ),
        )
        .expect_err("multi-onto stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("merge"),
            "names merge evaluation: {}",
            err.message
        );

        // Dropping newly-empty commits needs collapsing.
        let err = prepare_mutation(
            &store,
            session,
            rebase_request(
                vec![pinned],
                RebaseScope::SourceAndDescendants,
                vec![ohead],
                false,
            ),
        )
        .expect_err("keep_empty=false stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("collapsing"),
            "names collapsing: {}",
            err.message
        );

        // Onto a descendant is invalid.
        let (dhead, _) = seed_child(&store, shead, None, "child");
        let err = prepare_mutation(
            &store,
            session,
            rebase_request(
                vec![pinned],
                RebaseScope::SourceAndDescendants,
                vec![dhead],
                true,
            ),
        )
        .expect_err("onto-descendant is invalid");
        assert_eq!(err.code, ErrorCode::EInvalid);

        // An already-based source moves nothing.
        let err = prepare_mutation(
            &store,
            session,
            rebase_request(
                vec![pinned],
                RebaseScope::SourceAndDescendants,
                vec![phead],
                true,
            ),
        )
        .expect_err("no-op rebase is invalid");
        assert_eq!(err.code, ErrorCode::EInvalid);

        // A merge source needs merge evaluation.
        let (mhead, mchange) = seed_child_on_tree(
            &store,
            empty_tree_oid(&store),
            vec![ohead, phead],
            None,
            "merge",
        );
        let err = prepare_mutation(
            &store,
            session,
            rebase_request(
                vec![ChangeRef {
                    change: mchange,
                    head: Some(mhead),
                }],
                RebaseScope::SourceAndDescendants,
                vec![shead],
                true,
            ),
        )
        .expect_err("merge source stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("merge"),
            "names merge evaluation: {}",
            err.message
        );

        // Nested sources overlap.
        let (chead, cchange) = seed_child(&store, shead, None, "nested");
        let err = prepare_mutation(
            &store,
            session,
            rebase_request(
                vec![
                    pinned,
                    ChangeRef {
                        change: cchange,
                        head: Some(chead),
                    },
                ],
                RebaseScope::SourceAndDescendants,
                vec![ohead],
                true,
            ),
        )
        .expect_err("nested sources stay refused");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("overlap"),
            "names overlap: {}",
            err.message
        );
    }

    /// Seeds a stored tree holding one regular file per `(path, marker)` pair;
    /// each blob's content is its marker byte.
    fn seed_files(store: &Store, files: &[(&str, u8)]) -> Oid {
        let empty = store
            .prepare(ObjectKind::Tree, 0, std::io::Cursor::new(Vec::new()), None)
            .expect("prepare empty tree");
        let mut root = empty.oid();
        store
            .publish(
                vec![empty],
                &[],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish empty tree");
        for (name, marker) in files {
            let blob_bytes = [*marker];
            let blob = store
                .prepare(ObjectKind::Blob, 1, std::io::Cursor::new(blob_bytes), None)
                .expect("prepare blob");
            let blob_oid = blob.oid();
            store
                .publish(
                    vec![blob],
                    &[],
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("publish blob");
            let path = RepoPath::new(name.as_bytes().to_vec()).expect("test path");
            let entry = Some((TreeMode::File(FileMode::Regular), blob_oid));
            let edit = set_entry(store, root, &path, entry).expect("set entry");
            store
                .publish(
                    edit.objects,
                    &[],
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .expect("publish tree edit");
            root = edit.root;
        }
        root
    }

    #[test]
    fn resolve_side_collapses_a_single_path_conflict() {
        let (_temp, store, session) = fixture();
        let t1 = seed_files(&store, &[("x", 1)]);
        let t2 = seed_files(&store, &[("x", 2)]);
        let t3 = seed_files(&store, &[("x", 3)]);
        let change = ChangeId::generate();
        let input = NativeCommitInput {
            change_id: change,
            tree: Merge::from_vec(vec![t1, t2, t3]),
            parents: Vec::new(),
            predecessor: None,
            author: signature(),
            committer: signature(),
            extra_headers: Vec::new(),
            message: ByteString::from("conflicted"),
            provenance: None,
        };
        let conflicted = Records::new(&store)
            .prepare_native_commit(input)
            .expect("prepare conflicted commit");
        let head = conflicted.head;
        store
            .publish(
                vec![conflicted.prepared_object],
                &conflicted.mutations,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish conflicted commit");
        let request = Request::Resolve(Box::new(WireMutation {
            request_id: request_id(),
            args: ResolveArgs {
                target: ChangeRef {
                    change,
                    head: Some(head),
                },
                path: RepoPath::new("x").expect("test path"),
                resolution: Resolution::Side { index: 0 },
                workspaces: Vec::new(),
            },
        }));
        let prepared = prepare_mutation(&store, session, request).expect("resolve prepares");
        let Reply::Resolve(reply) = prepared.reply else {
            panic!("resolve must answer its own reply");
        };
        assert!(
            reply.remaining.items.is_empty(),
            "the only path is resolved"
        );
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish resolve");
        let resolved = Records::new(&store)
            .get_commit(&reply.change.head)
            .expect("read resolved commit")
            .expect("resolved commit is stored");
        assert_eq!(resolved.tree().as_resolved(), Some(&t1));
        assert_eq!(resolved.predecessor(), Some(head));
    }

    #[test]
    fn resolve_side_indexes_the_simplified_sides() {
        let (_temp, store, session) = fixture();
        let t1 = seed_files(&store, &[("x", 1)]);
        let t2 = seed_files(&store, &[("x", 2)]);
        let t3 = seed_files(&store, &[("x", 3)]);
        let t4 = seed_files(&store, &[("x", 4)]);
        let change = ChangeId::generate();
        // Terms [1, 2, 2, 3, 4] simplify to [1, 3, 4] with sides [1, 4]: the
        // raw second add is the cancelled content 2, while the simplified
        // second side is 4.
        let input = NativeCommitInput {
            change_id: change,
            tree: Merge::from_vec(vec![t1, t2, t2, t3, t4]),
            parents: Vec::new(),
            predecessor: None,
            author: signature(),
            committer: signature(),
            extra_headers: Vec::new(),
            message: ByteString::from("conflicted"),
            provenance: None,
        };
        let conflicted = Records::new(&store)
            .prepare_native_commit(input)
            .expect("prepare conflicted commit");
        let head = conflicted.head;
        store
            .publish(
                vec![conflicted.prepared_object],
                &conflicted.mutations,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish conflicted commit");
        let prepared = prepare_mutation(
            &store,
            session,
            Request::Resolve(Box::new(WireMutation {
                request_id: request_id(),
                args: ResolveArgs {
                    target: ChangeRef {
                        change,
                        head: Some(head),
                    },
                    path: RepoPath::new("x").expect("test path"),
                    resolution: Resolution::Side { index: 1 },
                    workspaces: Vec::new(),
                },
            })),
        )
        .expect("resolve prepares");
        let Reply::Resolve(reply) = prepared.reply else {
            panic!("resolve must answer its own reply");
        };
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish resolve");
        let resolved = Records::new(&store)
            .get_commit(&reply.change.head)
            .expect("read resolved commit")
            .expect("resolved commit is stored");
        assert_eq!(
            resolved.tree().as_resolved(),
            Some(&t4),
            "side 1 is the simplified second side, not the cancelled raw add"
        );
    }

    #[test]
    fn resolve_refuses_a_directory_path_rather_than_dropping_nested_conflicts() {
        let (_temp, store, session) = fixture();
        let t1 = seed_files(&store, &[("d/x", 1)]);
        let t2 = seed_files(&store, &[("d/x", 2)]);
        let t3 = seed_files(&store, &[("d/x", 3)]);
        let change = ChangeId::generate();
        let input = NativeCommitInput {
            change_id: change,
            tree: Merge::from_vec(vec![t1, t2, t3]),
            parents: Vec::new(),
            predecessor: None,
            author: signature(),
            committer: signature(),
            extra_headers: Vec::new(),
            message: ByteString::from("conflicted"),
            provenance: None,
        };
        let conflicted = Records::new(&store)
            .prepare_native_commit(input)
            .expect("prepare conflicted commit");
        let head = conflicted.head;
        store
            .publish(
                vec![conflicted.prepared_object],
                &conflicted.mutations,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish conflicted commit");
        let request = Request::Resolve(Box::new(WireMutation {
            request_id: request_id(),
            args: ResolveArgs {
                target: ChangeRef {
                    change,
                    head: Some(head),
                },
                path: RepoPath::new("d").expect("test path"),
                resolution: Resolution::Side { index: 0 },
                workspaces: Vec::new(),
            },
        }));
        let err =
            prepare_mutation(&store, session, request).expect_err("a directory path is refused");
        assert_eq!(err.code, ErrorCode::EInvalid);
        assert!(err.message.contains("names a directory"), "{}", err.message);
    }

    #[test]
    fn revert_reverses_the_target_delta_in_a_fresh_change() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);
        let base_tree = seed_files(&store, &[("x", 1)]);
        let changed_tree = seed_files(&store, &[("x", 2)]);
        let (parent, _) = seed_child_on_tree(&store, base_tree, Vec::new(), None, "parent");
        let (target, target_change) =
            seed_child_on_tree(&store, changed_tree, vec![parent], None, "target");
        let request = Request::Revert(Box::new(WireMutation {
            request_id: request_id(),
            args: RevertArgs {
                target: ChangeRef {
                    change: target_change,
                    head: Some(target),
                },
                onto: vec![target],
                mainline: None,
                description: None,
                identity: None,
                merge: MergeSelection::default(),
            },
        }));
        let prepared = prepare_mutation_with(&ctx, request).expect("revert prepares");
        let Reply::Revert(reply) = prepared.reply else {
            panic!("revert must answer its own reply");
        };
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish revert");
        assert_ne!(reply.created.change, target_change, "a fresh change");
        let created = Records::new(&store)
            .get_commit(&reply.created.head)
            .expect("read revert commit")
            .expect("revert commit is stored");
        assert_eq!(created.tree().as_resolved(), Some(&base_tree));
        assert_eq!(created.parents(), &[target]);
    }

    #[test]
    fn split_selected_first_stacks_the_selection_under_the_source_identity() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);
        let parent_tree = seed_files(&store, &[("x", 1), ("y", 1)]);
        let source_tree = seed_files(&store, &[("x", 2), ("y", 2)]);
        let selected_tree = seed_files(&store, &[("x", 2), ("y", 1)]);
        let (parent, _) = seed_child_on_tree(&store, parent_tree, Vec::new(), None, "parent");
        let (source, source_change) =
            seed_child_on_tree(&store, source_tree, vec![parent], None, "source");
        let request = Request::Split(Box::new(WireMutation {
            request_id: request_id(),
            args: SplitArgs {
                source: ChangeRef {
                    change: source_change,
                    head: Some(source),
                },
                paths: PathSelection::Paths(vec![RepoPath::new("x").expect("test path")]),
                placement: SplitPlacement::SelectedFirst,
                description: ByteString::from("part"),
                identity: None,
                merge: MergeSelection::default(),
                workspaces: Vec::new(),
            },
        }));
        let prepared = prepare_mutation_with(&ctx, request).expect("split prepares");
        let Reply::Split(reply) = prepared.reply else {
            panic!("split must answer its own reply");
        };
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish split");
        assert_eq!(
            reply.rewrites.items.len(),
            1,
            "only the source identity moves"
        );
        let source_now = reply.rewrites.items[0].new;
        let selection_head = reply
            .outcome
            .heads
            .items
            .iter()
            .map(|head| head.head)
            .find(|head| *head != source_now)
            .expect("the selection commit is listed for discovery");
        let selection = Records::new(&store)
            .get_commit(&selection_head)
            .expect("read selection commit")
            .expect("selection commit is stored");
        assert_eq!(selection.tree().as_resolved(), Some(&selected_tree));
        assert_eq!(selection.parents(), &[parent]);
        assert_eq!(commit_parents(&store, &source_now), vec![selection_head]);
        assert_eq!(
            Records::new(&store)
                .get_commit(&source_now)
                .expect("read source commit")
                .expect("source commit is stored")
                .tree()
                .as_resolved(),
            Some(&source_tree)
        );
    }

    #[test]
    fn squash_selected_path_keeps_the_source_tree() {
        let (_temp, store, session) = fixture();
        let parent_tree = seed_files(&store, &[("x", 1), ("y", 1)]);
        let source_tree = seed_files(&store, &[("x", 2), ("y", 2)]);
        let moved_tree = seed_files(&store, &[("x", 2), ("y", 1)]);
        let (dhead, dchange) =
            seed_child_on_tree(&store, parent_tree, Vec::new(), None, "destination");
        let (shead, schange) = seed_child_on_tree(&store, source_tree, vec![dhead], None, "source");
        let prepared = prepare_mutation(
            &store,
            session,
            squash_request(
                ChangeRef {
                    change: schange,
                    head: Some(shead),
                },
                ChangeRef {
                    change: dchange,
                    head: Some(dhead),
                },
                crate::protocol::PathSelection::Paths(vec![RepoPath::new("x").expect("test path")]),
                false,
            ),
        )
        .expect("selected squash prepares");
        let Reply::Squash(reply) = prepared.reply else {
            panic!("squash must answer its own reply");
        };
        assert!(
            reply.abandoned.items.is_empty(),
            "the remainder keeps the source"
        );
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish squash");
        let new_destination = reply.rewrites.items[0].new;
        let new_source = reply.rewrites.items[1].new;
        assert_eq!(
            Records::new(&store)
                .get_commit(&new_destination)
                .expect("read destination")
                .expect("destination is stored")
                .tree()
                .as_resolved(),
            Some(&moved_tree)
        );
        let source_commit = Records::new(&store)
            .get_commit(&new_source)
            .expect("read source")
            .expect("source is stored");
        // The kept source keeps its own tree: the moved selection lives on the
        // new destination below it, so the tip still carries the moved paths.
        // A remainder (selected paths reverted to the old destination) would
        // revert the moved change in the source and every descendant.
        assert_eq!(source_commit.tree().as_resolved(), Some(&source_tree));
        assert_eq!(source_commit.parents(), &[new_destination]);
    }

    fn squash_request(
        source: ChangeRef,
        destination: ChangeRef,
        paths: crate::protocol::PathSelection,
        keep_empty: bool,
    ) -> Request {
        Request::Squash(Box::new(WireMutation {
            request_id: request_id(),
            args: SquashArgs {
                source,
                destination,
                paths,
                description: None,
                keep_empty,
                identity: None,
                merge: crate::protocol::MergeSelection::default(),
                workspaces: Vec::new(),
            },
        }))
    }

    #[test]
    fn squash_moves_the_whole_delta_and_drops_the_source() {
        let (_temp, store, session) = fixture();
        let (dhead, dchange, _) = seed_commit(&store, None);
        let moved = seed_tree(&store, b's');
        let (shead, schange) = seed_child_on_tree(&store, moved, vec![dhead], None, "source");
        let (ghead, gchange) = seed_child_on_tree(&store, moved, vec![shead], None, "grandchild");
        let prepared = prepare_mutation(
            &store,
            session,
            squash_request(
                ChangeRef {
                    change: schange,
                    head: None,
                },
                ChangeRef {
                    change: dchange,
                    head: None,
                },
                crate::protocol::PathSelection::All,
                false,
            ),
        )
        .expect("whole-delta squash prepares");
        let Reply::Squash(reply) = prepared.reply else {
            panic!("squash must answer its own reply");
        };
        assert_eq!(reply.rewrites.items.len(), 2);
        assert_eq!(reply.rewrites.items[0].old, dhead);
        assert_eq!(reply.abandoned.items, vec![schange]);
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish squash");
        let new_dest = reply.rewrites.items[0].new;
        let new_child = reply.rewrites.items[1].new;
        assert_eq!(commit_parents(&store, &new_child), vec![new_dest]);
        assert_eq!(change_heads(&store, &dchange), vec![new_dest]);
        assert_eq!(change_heads(&store, &gchange), vec![new_child]);
        // The drained source change reads back as a headless abandoned entry,
        // which stored validation rejects; the staged abandon fact carries
        // the transition and the reply reports the drain.
        let _ = (shead, ghead);
    }

    #[test]
    fn squash_refusals_name_their_reason() {
        let (_temp, store, session) = fixture();
        let (dhead, dchange, _) = seed_commit(&store, None);
        let (shead, schange) = seed_child(&store, dhead, None, "source");
        let source = ChangeRef {
            change: schange,
            head: Some(shead),
        };
        let destination = ChangeRef {
            change: dchange,
            head: Some(dhead),
        };
        // An empty path list selects nothing to move.
        let err = prepare_mutation(
            &store,
            session,
            squash_request(
                source,
                destination,
                crate::protocol::PathSelection::Paths(Vec::new()),
                false,
            ),
        )
        .expect_err("an empty selection moves nothing");
        assert_eq!(err.code, ErrorCode::EInvalid);

        // A sibling of the source needs sibling re-derivation.
        let (_sibling, _) = seed_child(&store, dhead, None, "sibling");
        let err = prepare_mutation(
            &store,
            session,
            squash_request(
                source,
                destination,
                crate::protocol::PathSelection::All,
                false,
            ),
        )
        .expect_err("sibling squash stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("sibling"),
            "names siblings: {}",
            err.message
        );
    }

    fn abandon_request(targets: Vec<ChangeRef>) -> Request {
        Request::Abandon(Box::new(WireMutation {
            request_id: request_id(),
            args: AbandonArgs {
                targets,
                merge: crate::protocol::MergeSelection::default(),
                workspaces: Vec::new(),
            },
        }))
    }

    #[test]
    fn abandon_drops_heads_and_reparents_children() {
        let (_temp, store, session) = fixture();
        let (thead, tchange, _) = seed_commit(&store, None);
        let (dhead, dchange) = seed_child(&store, thead, None, "child");
        let prepared = prepare_mutation(
            &store,
            session,
            abandon_request(vec![ChangeRef {
                change: tchange,
                head: None,
            }]),
        )
        .expect("abandon prepares");
        let Reply::Abandon(reply) = prepared.reply else {
            panic!("abandon must answer its own reply");
        };
        assert_eq!(reply.rewrites.items.len(), 1);
        assert_eq!(reply.rewrites.items[0].old, dhead);
        assert_eq!(reply.abandoned.items, vec![tchange]);
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish abandon");
        let new_child = reply.rewrites.items[0].new;
        assert!(commit_parents(&store, &new_child).is_empty());
        assert_eq!(change_heads(&store, &dchange), vec![new_child]);
        let _ = thead;
    }

    #[test]
    fn abandon_expands_nested_targets() {
        let (_temp, store, session) = fixture();
        let (t1head, t1change, _) = seed_commit(&store, None);
        let (t2head, t2change) = seed_child(&store, t1head, None, "middle");
        let (dhead, dchange) = seed_child(&store, t2head, None, "leaf");
        let prepared = prepare_mutation(
            &store,
            session,
            abandon_request(vec![
                ChangeRef {
                    change: t1change,
                    head: None,
                },
                ChangeRef {
                    change: t2change,
                    head: None,
                },
            ]),
        )
        .expect("nested abandon prepares");
        let Reply::Abandon(reply) = prepared.reply else {
            panic!("abandon must answer its own reply");
        };
        assert_eq!(reply.rewrites.items.len(), 1);
        assert_eq!(reply.rewrites.items[0].old, dhead);
        assert_eq!(reply.abandoned.items.len(), 2);
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish nested abandon");
        let new_leaf = reply.rewrites.items[0].new;
        assert!(commit_parents(&store, &new_leaf).is_empty());
        assert_eq!(change_heads(&store, &dchange), vec![new_leaf]);
    }

    #[test]
    fn abandon_refusals_name_their_reason() {
        let (_temp, store, session) = fixture();
        let (ahead, _, _) = seed_commit(&store, None);
        let (bhead, _, _) = seed_commit(&store, None);
        let (mhead, mchange) = seed_child_on_tree(
            &store,
            empty_tree_oid(&store),
            vec![ahead, bhead],
            None,
            "merge",
        );
        let err = prepare_mutation(
            &store,
            session,
            abandon_request(vec![ChangeRef {
                change: mchange,
                head: Some(mhead),
            }]),
        )
        .expect_err("merge target stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("fan-in"),
            "names fan-in: {}",
            err.message
        );

        // A child carrying content over a surviving base needs re-derivation,
        // not silent keeping. (Orphaning onto no parents keeps the snapshot
        // soundly, so the abandoned target here is not a root.)
        let (phead, _, _) = seed_commit(&store, None);
        let (thead, tchange) = seed_child(&store, phead, None, "target");
        let full = seed_tree(&store, b'y');
        let (dhead, dchange) = seed_child_on_tree(&store, full, vec![thead], None, "content child");
        let err = prepare_mutation(
            &store,
            session,
            abandon_request(vec![ChangeRef {
                change: tchange,
                head: None,
            }]),
        )
        .expect_err("content child stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("tree re-derivation"),
            "names derivation: {}",
            err.message
        );
        let _ = (dhead, dchange);
    }

    #[test]
    fn rewrite_workspace_binding_fences_and_advances() {
        let (_temp, store, session) = fixture();
        let clock = fixed_clock();
        let row = session_row_caps(Some(ada_claim()), claim_all_caps());
        let ctx = full_ctx(&store, session, Some(&row), Some(&clock), None);
        let ws = prepare_mutation_with(
            &ctx,
            Request::WsNew(Box::new(WireMutation {
                request_id: request_id(),
                args: WsNewArgs {
                    root: ByteString::from("/tmp/ruk-w3-test"),
                    init: WorkspaceInit::Native {
                        parents: Vec::new(),
                    },
                    scope: None,
                },
            })),
        )
        .expect("ws.new prepares");
        store
            .publish(
                ws.objects,
                &ws.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish workspace");
        let Reply::WsNew(ws_reply) = ws.reply else {
            panic!("ws.new must answer its own reply");
        };
        let binding = WorkspaceBinding {
            workspace: ws_reply.workspace,
            expected: ws_reply.state.stamp(),
        };
        let ws_change = match &ws_reply.state {
            WorkspaceState::Native(native) => native.change,
            WorkspaceState::GitCompat(_) => panic!("native workspace expected"),
        };
        // One binding on the rewritten change fences and advances the row.
        let prepared = prepare_mutation_with(
            &ctx,
            Request::Describe(Box::new(WireMutation {
                request_id: request_id(),
                args: DescribeArgs {
                    target: ChangeRef {
                        change: ws_change,
                        head: None,
                    },
                    description: ByteString::from("workspace change rewritten"),
                    identity: None,
                    workspaces: vec![binding],
                },
            })),
        )
        .expect("fenced describe prepares");
        assert_eq!(
            prepared.workspace_fence,
            Some((ws_reply.workspace, binding.expected))
        );
        let workspace_facts: Vec<_> = prepared
            .facts
            .iter()
            .filter(|fact| fact.table == crate::store::types::FactTable::Workspaces)
            .collect();
        assert_eq!(workspace_facts.len(), 1);
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("publish fenced describe");

        // Two bindings exceed the single lane fence.
        let err = prepare_mutation_with(
            &ctx,
            Request::Describe(Box::new(WireMutation {
                request_id: request_id(),
                args: DescribeArgs {
                    target: ChangeRef {
                        change: ws_change,
                        head: None,
                    },
                    description: ByteString::from("another rewrite"),
                    identity: None,
                    workspaces: vec![binding, workspace_binding()],
                },
            })),
        )
        .expect_err("two bindings stay refused");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(
            err.message.contains("single workspace fence"),
            "names the fence: {}",
            err.message
        );
    }

    #[test]
    fn reads_have_no_preparation() {
        let (_temp, store, session) = fixture();
        for request in [
            Request::ClaimList(Box::default()),
            Request::AttestList(Box::default()),
            Request::OpLog(Box::default()),
        ] {
            let err = prepare_mutation(&store, session, request).expect_err("reads never prepare");
            assert_eq!(err.code, ErrorCode::EInvalid);
        }
    }
}
