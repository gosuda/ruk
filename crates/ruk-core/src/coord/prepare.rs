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
//! `claim.release`, and `ws.new`. The annotated tag arm needs the
//! coordinator clock and a tagger identity, `new` and `ws.new` need the
//! session identity row and the clock for signature synthesis, and
//! `attest.add` needs the attestation progress gate, so those arms stay
//! refused on the legacy [`prepare_mutation`] path and serve only through
//! [`prepare_mutation_with`]. Everything else is honestly refused with
//! [`ErrorCode::EHosted`]:
//!
//! * `claim.acquire` / `claim.release` validate here (path canonicalization
//!   plus the session's `claim_paths` capability) and seal in the lane under
//!   sole publication ownership: the fence and overlap checks need a
//!   commit-time snapshot, so preparation stages no claim facts and mints
//!   only the acquire id the sealed record must carry. The lane seals with
//!   that id and writes the authoritative record back into the reply.
//! * Workspace (beyond `ws.new` and the `new` workspace switch),
//!   change-rewrite, transport, land, undo, and prune mutations need object
//!   preparation, claim sealing, workspace fencing, or plan evaluation that
//!   no caller on this path supplies.
//!
//! The nine `crate::ops`-adjacent methods were evaluated one by one against
//! their protocol args and stay refused, each arm naming its missing piece:
//! `new` mints the empty tree and synthesizes its signature from the session
//! identity row plus the coordinator clock (multi-parent trees need merge
//! evaluation with no producer here, so they stay refused); `ws.new` builds
//! on the same mint for native workspaces and writes only the row — no
//! worktree materialization happens in this call;
//! protocol `describe` rewrites a change's description while `ops::describe`
//! is a pure read of a commit or change with a different request shape, so
//! no description-rewrite producer exists on this path and there are no lane
//! parts for it here; protocol `edit` checks a change out into a workspace while
//! `ops::edit` rewrites a commit's message/tree/identities; and `split`,
//! `squash`, `rebase`, `abandon`, `resolve`, and `revert` all need
//! ChangeRef resolution, merge/content evaluation, descendant handling, or
//! workspace fencing that no caller on this path supplies, while their
//! `ops::*` counterparts need caller-resolved trees or heads.
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
use super::clock::Clock;
use super::hosted::PreparedMutation;
use super::policy::Policy;
use super::rows::{self, SessionRow, WorkspaceRow};
use super::workspace;
use crate::attestation::{Checkpoint, prepare_add};
use crate::bytes::ByteString;
use crate::change::{ChangeId, ClaimId, RequestId, SessionId, WorkspaceId};
use crate::conflict::{Signature, TzOffset};
use crate::error::{CoreError, ErrorCode};
use crate::heads::Head;
use crate::ids::Oid;
use crate::ops::{NewRequest, NewResult, PreparedOp, prepare_new};
use crate::protocol::{
    AttestAddArgs, AttestAddReply, BookmarkDeleteArgs, BookmarkDeleteReply, BookmarkResolution,
    BookmarkResolveArgs, BookmarkResolveReply, BookmarkSetArgs, BookmarkSetReply, BookmarkTarget,
    BoundedList, ChangeHead, ChangeRef, ClaimAcquireArgs, ClaimAcquireReply, ClaimRecord,
    ClaimReleaseArgs, ClaimReleaseReply, EffectiveIdentity, IdentityClaim, IdentitySource,
    MutationOutcome, NewArgs, NewReply, PinArgs, PinReply, ReceiptRef, Reply, Request,
    RequestDigest, TagDeleteArgs, TagDeleteReply, TagSetArgs, TagSetReply, Timestamp, UnpinArgs,
    UnpinReply, Validate, WorkspaceInit, WsNewArgs, WsNewReply,
};
use crate::records::Records;
use crate::records::keys::head_key;
use crate::refdata::{RefChange, RefExpect, RefName, RefTarget, RefTransaction, RefUpdate};
use crate::refs::{StoreRefs, prepare_checked_transaction, prepare_clear_ref_conflict_checked};
use crate::store::ObjectKind;
use crate::store::Store;
use crate::store::types::{FactExpectation, FactMutation, FactTable, PreparedObject};
use crate::workspace::{
    GitCompatWorkspace, NativeWorkspace, Scope, WorkspaceStamp, WorkspaceState,
};

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
    pub(crate) claim_clock: Option<&'a ClaimClock>,
    /// Admission policy for land preparation; absent on the legacy path.
    pub(crate) policy: Option<&'a Policy>,
    /// Progress gate for attestation verification; absent on the legacy path.
    pub(crate) checkpoint: Option<&'a Checkpoint<'a>>,
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
        Request::ClaimAcquire(m) => claim_acquire_parts(ctx, m.request_id, &m.args)?,
        Request::ClaimRelease(m) => claim_release_parts(ctx, m.request_id, &m.args)?,
        Request::WsNew(m) => ws_new_parts(ctx, m.request_id, &m.args)?,
        Request::Describe(_) => {
            return Err(uncovered(
                "describe",
                "protocol `describe` rewrites a change's description while `ops::describe` is a pure read of a commit or change with a different request shape; no description-rewrite producer exists on this path",
            ));
        }
        Request::Edit(_) => {
            return Err(uncovered(
                "edit",
                "protocol `edit` checks a change out into a workspace while `ops::edit` rewrites a commit's message/tree/identities; the names match but the operations do not",
            ));
        }
        Request::Split(_) => {
            return Err(uncovered(
                "split",
                "`split` partitions by path selection with merge evaluation and workspace fences that have no producer on this path; `ops::split` needs a caller-resolved intermediate tree instead",
            ));
        }
        Request::Squash(_) => {
            return Err(uncovered(
                "squash",
                "`squash` moves path selections between changes with merge evaluation and workspace fences that have no producer on this path; `ops::squash` needs caller-resolved heads plus a tree instead",
            ));
        }
        Request::Rebase(_) => {
            return Err(uncovered(
                "rebase",
                "`rebase` resolves ChangeRefs, derives descendants by scope, and computes per-commit trees with no backing on this path; `ops::rebase` needs explicit heads plus a mandatory caller-resolved tree",
            ));
        }
        Request::Abandon(_) => {
            return Err(uncovered(
                "abandon",
                "protocol `abandon` resolves ChangeRefs, re-parents descendants, and fences workspaces; `ops::abandon` drops heads without re-parenting, so mapping heads alone would silently drop those semantics",
            ));
        }
        Request::Resolve(_) => {
            return Err(uncovered(
                "resolve",
                "turning a path Resolution into a resolved tree needs conflict/merge evaluation with no backing on this path; `ops::resolve` needs a caller-resolved tree instead",
            ));
        }
        Request::Revert(_) => {
            return Err(uncovered(
                "revert",
                "computing the reverse-delta tree needs merge evaluation with no backing on this path; `ops::revert` needs a caller-resolved tree instead",
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
    let claim = over.or(row.identity.as_ref()).ok_or_else(|| {
        CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "method `{method}` needs an identity: neither the call nor the session carries one"
            ),
        )
    })?;
    claim.validate()?;
    // Read-only pre-checks before the tree publish below: a refused mint
    // must leave no state, so the checks `prepare_new` would run first run
    // here against committed state. They stay advisory — `prepare_new` and
    // the lane re-check authoritatively at commit time.
    for parent in parents {
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
    let secs = clock.sample()?.timestamp().instant().as_second();
    let author = Signature {
        name: ByteString::from(claim.name.as_str()),
        email: ByteString::from(claim.email.as_str()),
        timestamp: secs,
        offset: TzOffset::UTC,
    };
    let empty = store
        .hash_kind()
        .hash_git_object("tree", b"")
        .map_err(CoreError::from)?;
    if store.object_len(empty).map_err(CoreError::from)?.is_none() {
        let empty_bytes: &[u8] = b"";
        let staged = store
            .prepare(ObjectKind::Tree, 0, empty_bytes, None)
            .map_err(CoreError::from)?;
        store.publish(vec![staged], &[]).map_err(CoreError::from)?;
    }
    let prepared = prepare_new(
        store,
        NewRequest {
            tree: empty,
            parents: parents.to_vec(),
            author: author.clone(),
            committer: author,
            message: message.clone(),
            change_id: Some(ChangeId::generate()),
            predecessor: None,
            provenance: None,
        },
    )?;
    let identity = EffectiveIdentity {
        name: claim.name.clone(),
        email: claim.email.clone(),
        source: if over.is_some() {
            IdentitySource::OperationOverride
        } else {
            IdentitySource::SessionClaim
        },
    };
    Ok((prepared, identity))
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
        facts.push(observed.replace(WorkspaceRow {
            state: next.clone(),
            holder: session,
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
/// job, and the host root is validated but not stored (no row field carries
/// it until W4). Native creation needs the session identity row and the
/// coordinator clock for the inner commit's signature; GitCompat creation is
/// context-free.
///
/// # Errors
/// Same as [`mint_empty_commit`] for native workspaces, plus `E_LIMIT` for
/// an oversized row and the target validation of a GitCompat HEAD.
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::super::policy::Principal;
    use super::*;
    use crate::attestation::Progress;
    use crate::bytes::ByteString;
    use crate::capability::{AttestKind, AttestResult, Capabilities, PathPattern};
    use crate::change::{ChangeId, ClaimId, SessionId, WorkspaceId};
    use crate::commit::ProvenanceClaims;
    use crate::conflict::Signature;
    use crate::heads::Head;
    use crate::ids::{CommitKey, HashKind, Oid};
    use crate::index::RepoPath;
    use crate::ops::{NewRequest, prepare_new};
    use crate::protocol::{
        AbandonArgs, AttestAddArgs, AttestListArgs, AttestSignature, AttestStatement,
        BookmarkDeleteArgs, ChangeRef, ClaimAcquireArgs, ClaimListArgs, ClaimMode,
        ClaimReleaseArgs, ClaimTtl, DescribeArgs, EditArgs, IdentityClaim, MergeSelection,
        Mutation as WireMutation, NewArgs, OpLogArgs, PathSelection, PinArgs, RebaseArgs,
        RebaseScope, Resolution, ResolveArgs, RevertArgs, SessionAuthority, SplitArgs,
        SplitPlacement, SquashArgs, TagAnnotation, UnpinArgs, WorkspaceBinding, WorkspaceInit,
        WsNewArgs,
    };
    use crate::records::codec::encode_change_entry;
    use crate::records::keys::change_key;
    use crate::records::types::{ChangeEntry, ChangeState};
    use crate::refdata::RefName;
    use crate::store::PreparationBudget;
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
    /// seed carries a distinct message, so heads never collide.
    fn seed_commit(store: &Store, change_id: Option<ChangeId>) -> (Head, ChangeId, Oid) {
        let number = SEQ.fetch_add(1, Ordering::SeqCst);
        let tree = store
            .prepare(ObjectKind::Tree, 0, std::io::Cursor::new(Vec::new()), None)
            .expect("prepare empty tree");
        let tree_oid = tree.oid();
        store.publish(vec![tree], &[]).expect("publish empty tree");
        let prepared = prepare_new(
            store,
            NewRequest {
                tree: tree_oid,
                parents: Vec::new(),
                author: signature(),
                committer: signature(),
                message: ByteString::from(format!("seed-{number}")),
                change_id,
                predecessor: None,
                provenance: None,
            },
        )
        .expect("prepare seed commit");
        let head = prepared.output.head;
        let change = prepared.output.change_id;
        let oid = prepared.output.oid.expect("seed commit is a Git commit");
        store
            .publish(prepared.objects, &prepared.facts)
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
            .publish(Vec::new(), &prepared.facts)
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
            .publish(vec![subject_object], &[])
            .expect("publish subject");

        let key =
            ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[0x11; 32]));
        let statement = AttestStatement {
            subject,
            kind: AttestKind::new("review").expect("kind"),
            result: AttestResult::new("pass").expect("result"),
            signed_at: Timestamp::parse("2026-10-17T12:00:00Z").expect("timestamp"),
            supersedes: None,
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
            .publish(Vec::new(), &prepared.facts)
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
        // `new`, `claim.*`, and `ws.new` now serve through this context; the
        // next waves still name their missing preparation.
        for request in [
            Request::Describe(Box::new(WireMutation {
                request_id: request_id(),
                args: DescribeArgs {
                    target: change_target(),
                    description: ByteString::from("rewritten"),
                    identity: None,
                    workspaces: Vec::new(),
                },
            })),
            Request::Split(Box::new(WireMutation {
                request_id: request_id(),
                args: SplitArgs {
                    source: change_target(),
                    paths: PathSelection::Paths(vec![RepoPath::new("x").expect("test path")]),
                    placement: SplitPlacement::SelectedFirst,
                    description: ByteString::from("part"),
                    identity: None,
                    merge: MergeSelection::default(),
                    workspaces: Vec::new(),
                },
            })),
        ] {
            let method = request.method();
            let err = prepare_mutation_with(&ctx, request)
                .expect_err("future wave stays refused through the context");
            assert_eq!(err.code, ErrorCode::EHosted, "method `{}`", method.as_str());
        }
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
        // The empty tree publishes standalone (so `prepare_new` resolves it)
        // while the candidate carries only the commit object.
        assert_eq!(prepared.objects.len(), 1);
        assert_eq!(prepared.objects[0].kind(), ObjectKind::Commit);
        let read = store.read(empty_tree_oid(&store)).expect("read empty tree");
        assert_eq!(read.kind, ObjectKind::Tree);
        assert!(!prepared.facts.is_empty());
        assert!(prepared.workspace_fence.is_none());
        assert!(prepared.ref_transaction.is_none());

        // The staged parts commit: the head resolves to a stored commit.
        store
            .publish(prepared.objects, &prepared.facts)
            .expect("publish new");
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
            .publish(prepared.objects, &prepared.facts)
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
            .publish(ws.objects, &ws.facts)
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
            .publish(switched.objects, &switched.facts)
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
        )
        .expect("seal fixture claim");
        store
            .publish(Vec::new(), &sealed.facts)
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
            .publish(prepared.objects, &prepared.facts)
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
            .publish(prepared.objects, &prepared.facts)
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

    #[test]
    fn ops_backed_mutations_name_their_missing_preparation() {
        let (_temp, store, session) = fixture();
        let target = change_target();
        let other = ChangeRef {
            change: ChangeId::from_bytes([0x33; 16]),
            head: None,
        };
        let parent = Head::Git { oid: oid(0x11) };
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
            Request::Describe(Box::new(WireMutation {
                request_id: request_id(),
                args: DescribeArgs {
                    target,
                    description: ByteString::from("rewritten"),
                    identity: None,
                    workspaces: Vec::new(),
                },
            })),
            Request::Edit(Box::new(WireMutation {
                request_id: request_id(),
                args: EditArgs {
                    binding: workspace_binding(),
                    target,
                },
            })),
            Request::Split(Box::new(WireMutation {
                request_id: request_id(),
                args: SplitArgs {
                    source: target,
                    paths: PathSelection::Paths(vec![RepoPath::new("x").expect("test path")]),
                    placement: SplitPlacement::SelectedFirst,
                    description: ByteString::from("part"),
                    identity: None,
                    merge: MergeSelection::default(),
                    workspaces: Vec::new(),
                },
            })),
            Request::Squash(Box::new(WireMutation {
                request_id: request_id(),
                args: SquashArgs {
                    source: target,
                    destination: other,
                    paths: PathSelection::All,
                    description: None,
                    keep_empty: false,
                    identity: None,
                    merge: MergeSelection::default(),
                    workspaces: Vec::new(),
                },
            })),
            Request::Rebase(Box::new(WireMutation {
                request_id: request_id(),
                args: RebaseArgs {
                    sources: vec![target],
                    scope: RebaseScope::SourceAndDescendants,
                    onto: vec![parent],
                    merge: MergeSelection::default(),
                    keep_empty: false,
                    workspaces: Vec::new(),
                },
            })),
            Request::Abandon(Box::new(WireMutation {
                request_id: request_id(),
                args: AbandonArgs {
                    targets: vec![target],
                    merge: MergeSelection::default(),
                    workspaces: Vec::new(),
                },
            })),
            Request::Resolve(Box::new(WireMutation {
                request_id: request_id(),
                args: ResolveArgs {
                    target,
                    path: RepoPath::new("x").expect("test path"),
                    resolution: Resolution::AcceptSame,
                    workspaces: Vec::new(),
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

    #[test]
    fn reads_have_no_preparation() {
        let (_temp, store, session) = fixture();
        for request in [
            Request::ClaimList(Box::new(ClaimListArgs::default())),
            Request::AttestList(Box::new(AttestListArgs::default())),
            Request::OpLog(Box::new(OpLogArgs::default())),
        ] {
            let err = prepare_mutation(&store, session, request).expect_err("reads never prepare");
            assert_eq!(err.code, ErrorCode::EInvalid);
        }
    }
}
