//! Per-method preparation of bare mutation requests into lane parts.
//!
//! [`HostedCoordinator`](super::hosted::HostedCoordinator) admits and publishes
//! only fully prepared candidates. This module translates the mechanically
//! preparable subset of mutations — ref updates whose semantics the lane
//! re-checks authoritatively at commit time — into [`PreparedMutation`].
//!
//! Covered today: `bookmark.set` (commit targets only), `bookmark.delete`,
//! `bookmark.resolve`, `tag.set` (unannotated only), and `tag.delete`.
//! Everything else is honestly refused with [`ErrorCode::EHosted`]:
//!
//! * `bookmark.set` with a change target needs change-to-head resolution
//!   that has no in-tree backing on this path.
//! * `tag.set` with an annotation needs tag-object creation that has no
//!   in-tree backing on this path.
//! * `claim.acquire` / `claim.release` seal against a claim clock whose
//!   fence and overlap checks require sole lane ownership; preparing them
//!   outside the lane could commit overlapping claims, so they stay refused
//!   until a lane-owned sealer exists.
//! * `pin` / `unpin` have no in-tree producer for their `Pins` fact rows;
//!   the key encoding would be invented here.
//! * Workspace, change-rewrite, transport, land, undo, and prune mutations
//!   need object preparation, claim sealing, workspace fencing, or plan
//!   evaluation that no caller on this path supplies.
//!
//! The nine `crate::ops`-adjacent methods were evaluated one by one against
//! their protocol args and stay refused, each arm naming its missing piece:
//! `new` carries parents, a description, an optional name/email identity, and
//! an optional workspace switch, but no tree object and no timestamped
//! signature, so no `NewRequest` can be built without inventing the commit;
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

use super::claims::ClaimClock;
use super::clock::Clock;
use super::hosted::PreparedMutation;
use super::policy::Policy;
use super::rows::SessionRow;
use crate::attestation::Checkpoint;
use crate::change::{RequestId, SessionId};
use crate::error::{CoreError, ErrorCode};
use crate::protocol::{
    BookmarkDeleteArgs, BookmarkDeleteReply, BookmarkResolution, BookmarkResolveArgs,
    BookmarkResolveReply, BookmarkSetArgs, BookmarkSetReply, BookmarkTarget, BoundedList,
    MutationOutcome, ReceiptRef, Reply, Request, RequestDigest, TagDeleteArgs, TagDeleteReply,
    TagSetArgs, TagSetReply, Timestamp,
};
use crate::refdata::{RefChange, RefExpect, RefName, RefTarget, RefTransaction, RefUpdate};
use crate::refs::{StoreRefs, prepare_checked_transaction, prepare_clear_ref_conflict_checked};
use crate::store::Store;
use crate::store::types::FactMutation;

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

/// One method's lane parts: the precomputed reply, exact facts, the checked
/// transaction, and the ref names it was validated against.
struct Parts {
    reply: Reply,
    facts: Vec<FactMutation>,
    transaction: RefTransaction,
    dependencies: Vec<RefName>,
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
        Request::New(_) => {
            return Err(uncovered(
                "new",
                "`new` carries no tree object and its identity claim is name/email only, so no `ops::NewRequest` can be built without inventing the commit; the workspace switch also needs a fence no caller supplies",
            ));
        }
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
        objects: Vec::new(),
        facts: parts.facts,
        workspace_fence: None,
        ref_transaction: Some(parts.transaction),
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
    let BookmarkTarget::Commit { oid } = &args.target else {
        return Err(uncovered(
            "bookmark.set",
            "`bookmark.set` with a change target needs change-to-head resolution with no backing on this path",
        ));
    };
    let name = args.name.clone();
    let (facts, transaction) = check_ref_update(
        store,
        RefUpdate {
            name: name.clone(),
            expected: args.expected.clone(),
            change: RefChange::Set(RefTarget::Direct(*oid)),
        },
    )?;
    Ok(Parts {
        reply: Reply::BookmarkSet(Box::new(BookmarkSetReply {
            outcome: pending_outcome(session, request_id),
            name: name.clone(),
            target: *oid,
        })),
        facts,
        transaction,
        dependencies: vec![name],
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
        facts,
        transaction,
        dependencies: vec![name],
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
        facts,
        transaction,
        dependencies: vec![name],
    })
}

fn tag_set_parts(
    ctx: &PrepareContext<'_>,
    request_id: RequestId,
    args: &TagSetArgs,
) -> Result<Parts, CoreError> {
    let store = ctx.store;
    let session = ctx.session;
    if args.annotation.is_some() {
        return Err(uncovered(
            "tag.set",
            "`tag.set` with an annotation needs tag-object creation with no backing on this path",
        ));
    }
    let name = args.name.clone();
    let (facts, transaction) = check_ref_update(
        store,
        RefUpdate {
            name: name.clone(),
            expected: args.expected.clone(),
            change: RefChange::Set(RefTarget::Direct(args.target)),
        },
    )?;
    Ok(Parts {
        reply: Reply::TagSet(Box::new(TagSetReply {
            outcome: pending_outcome(session, request_id),
            name: name.clone(),
            target: RefTarget::Direct(args.target),
        })),
        facts,
        transaction,
        dependencies: vec![name],
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
        facts,
        transaction,
        dependencies: vec![name],
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::bytes::ByteString;
    use crate::change::{ChangeId, ClaimId, SessionId, WorkspaceId};
    use crate::heads::Head;
    use crate::ids::{HashKind, Oid};
    use crate::index::RepoPath;
    use crate::protocol::{
        AbandonArgs, AttestListArgs, BookmarkDeleteArgs, ChangeRef, ClaimListArgs,
        ClaimReleaseArgs, DescribeArgs, EditArgs, MergeSelection, Mutation as WireMutation,
        NewArgs, OpLogArgs, PathSelection, PinArgs, RebaseArgs, RebaseScope, Resolution,
        ResolveArgs, RevertArgs, SplitArgs, SplitPlacement, SquashArgs, TagAnnotation, UnpinArgs,
        WorkspaceBinding,
    };
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
        let pin = Request::Pin(Box::new(WireMutation {
            request_id: request_id(),
            args: PinArgs {
                head: Head::Git { oid: oid(0x11) },
            },
        }));
        let err = prepare_mutation(&store, session, pin).expect_err("pin stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
        assert!(err.message.contains("does not cover preparation"));

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

        let change_target = Request::BookmarkSet(Box::new(WireMutation {
            request_id: request_id(),
            args: BookmarkSetArgs {
                name: name("refs/heads/main"),
                target: BookmarkTarget::Change {
                    change: crate::protocol::ChangeRef {
                        change: crate::change::ChangeId::from_bytes([0x22; 16]),
                        head: None,
                    },
                },
                expected: RefExpect::Absent,
            },
        }));
        let err = prepare_mutation(&store, session, change_target)
            .expect_err("change-target bookmark stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);

        let release = Request::ClaimRelease(Box::new(WireMutation {
            request_id: request_id(),
            args: ClaimReleaseArgs {
                claim: ClaimId::nil(),
            },
        }));
        let err =
            prepare_mutation(&store, session, release).expect_err("claim.release stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);

        let unpin = Request::Unpin(Box::new(WireMutation {
            request_id: request_id(),
            args: UnpinArgs {
                head: Head::Git { oid: oid(0x11) },
            },
        }));
        let err = prepare_mutation(&store, session, unpin).expect_err("unpin stays refused");
        assert_eq!(err.code, ErrorCode::EHosted);
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
