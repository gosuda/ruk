//! Per-repository coordinator sidecar: client and server verbs.
//!
//! Commit-writing verbs batch through one coordinator process per
//! repository instead of racing the store lock from every CLI process:
//!
//! * The client builds the exact `git.commit` lane arguments (tree, parents,
//!   identities, message, plus the branch compare-and-swap the caller saw),
//!   drops its own store handle so the server can burst-open the store, and
//!   submits over `<repo>/.ruk/coordinator.sock`. Preparation runs inside
//!   the server from its store view; the lane serializes concurrent
//!   submissions into shared publications.
//! * The coordinator is an accelerator, never a correctness dependency. A
//!   missing, slow, or crashed coordinator falls back to the direct publish
//!   path with identical arguments, and every failure after the submission
//!   may have reached the server replays the same stable request id (the
//!   lane answers from its receipt ledger) before any direct publish of the
//!   same id, so a commit is never duplicated.
//! * `RUK_COORDINATOR=off` bypasses the sidecar (tests, debugging),
//!   `auto` (the default) falls back silently, and `required` hard-fails
//!   when no coordinator answers.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ruk_core::change::RequestId;
#[cfg(all(unix, not(test)))]
use ruk_core::coord::per_repo::socket_path;
use ruk_core::coord::per_repo::{self, CommitAnswer, CommitCall, ServeOutcome};
use ruk_core::heads::Head;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::ops::{
    EditRequest, NewRequest, NewResult, edit as ops_edit, new as ops_new, prepare_new,
};
use ruk_core::protocol::{GitCommitArgs, GitCommitRefUpdate, Mutation, NewReply, Reply, Request};
use ruk_core::refdata::{RefChange, RefExpect, RefName, RefTarget, RefUpdate};
use ruk_core::store::{EventContext, EventSource, PreparationBudget, Store};
use ruk_core::workspace::HeadRef;
use ruk_git::GitError;

use super::Ctx;
use super::state;

/// Coordinator selection for this invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Off,
    Auto,
    Required,
}

impl Mode {
    fn from_ctx(ctx: &Ctx) -> Self {
        match ctx.env.get("RUK_COORDINATOR") {
            Some(value) => match value.trim().to_ascii_lowercase().as_str() {
                "off" => Self::Off,
                "required" => Self::Required,
                _ => Self::Auto,
            },
            None => Self::Auto,
        }
    }
}

/// Bounds one connection attempt.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(50);

/// Bounds spawn plus first contact with a fresh server.
#[cfg(all(unix, not(test)))]
const SPAWN_WAIT: Duration = Duration::from_millis(500);

/// Bounds one submission exchange.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(60);

/// Idle TTL before an unreferenced server exits.
const DEFAULT_IDLE_MS: u64 = 5000;

/// Fresh-tip retries after a lost branch race.
const MAX_STALE_RETRIES: usize = 3;

/// Creates one commit on the current branch, through the coordinator when
/// one answers and directly otherwise. The returned identity is durable
/// before this returns, on either path.
pub(crate) fn commit_new(
    ctx: &mut Ctx,
    request: NewRequest,
    request_id: RequestId,
) -> Result<NewResult, GitError> {
    if Mode::from_ctx(ctx) == Mode::Off {
        return direct_commit(ctx, request, None);
    }
    let store = ctx.store()?;
    let Some((name, expected)) = symbolic_target(store)? else {
        // Detached heads have no ref producer on the lane. `auto` keeps
        // today's direct publish; `required` refuses instead of silently
        // bypassing the sidecar it was told to require.
        if Mode::from_ctx(ctx) == Mode::Required {
            return Err(GitError::Invalid {
                detail: "RUK_COORDINATOR=required cannot serve a detached HEAD".to_owned(),
            });
        }
        return direct_commit(ctx, request, None);
    };
    let args = GitCommitArgs {
        tree: request.tree,
        parents: request.parents.clone(),
        author: request.author.clone(),
        committer: request.committer.clone(),
        message: request.message.clone(),
        change_id: request.change_id,
        predecessor: request.predecessor,
        ref_update: Some(GitCommitRefUpdate {
            name: name.clone(),
            expected: expected.clone(),
        }),
    };
    commit_via_coordinator(
        ctx,
        request,
        args,
        request_id,
        Direct::New {
            expected: Some((name, expected)),
        },
    )
}

/// Creates the amended commit on the current branch: same lane path as a
/// new commit, but carrying the rewritten head as predecessor so the change
/// is preserved instead of remapped.
pub(crate) fn commit_amend(
    ctx: &mut Ctx,
    request: NewRequest,
    request_id: RequestId,
    tip: Oid,
    author: Option<ruk_core::conflict::Signature>,
) -> Result<NewResult, GitError> {
    if Mode::from_ctx(ctx) == Mode::Off {
        return direct_amend(ctx, request, tip, author, None);
    }
    let store = ctx.store()?;
    let Some((name, expected)) = symbolic_target(store)? else {
        if Mode::from_ctx(ctx) == Mode::Required {
            return Err(GitError::Invalid {
                detail: "RUK_COORDINATOR=required cannot serve a detached HEAD".to_owned(),
            });
        }
        return direct_amend(ctx, request, tip, author, None);
    };
    let args = GitCommitArgs {
        tree: request.tree,
        parents: request.parents.clone(),
        author: request.author.clone(),
        committer: request.committer.clone(),
        message: request.message.clone(),
        change_id: request.change_id,
        predecessor: request.predecessor,
        ref_update: Some(GitCommitRefUpdate {
            name: name.clone(),
            expected: expected.clone(),
        }),
    };
    commit_via_coordinator(
        ctx,
        request,
        args,
        request_id,
        Direct::Amend {
            tip,
            author,
            expected: Some((name, expected)),
        },
    )
}

/// Today's amend publish, unchanged: the fallback path and the
/// `RUK_COORDINATOR=off` path share it byte-for-byte.
fn direct_amend(
    ctx: &mut Ctx,
    request: NewRequest,
    tip: Oid,
    author: Option<ruk_core::conflict::Signature>,
    captured: Option<(RefName, RefExpect)>,
) -> Result<NewResult, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let result = ops_edit(
        store,
        EditRequest {
            head: Head::Git { oid: tip },
            tree: Some(request.tree),
            message: Some(request.message),
            author,
            committer: Some(request.committer),
        },
    )
    .map_err(GitError::from)?;
    let new_oid = result
        .head
        .as_git()
        .copied()
        .ok_or_else(|| GitError::Invalid {
            detail: "rewritten commit has no git identity".to_owned(),
        })?;
    advance_head_to(store, kind, new_oid, captured)?;
    Ok(NewResult {
        head: result.head,
        change_id: result.change_id,
        oid: Some(new_oid),
    })
}

/// Which direct publish a lane bypass falls back to.
///
/// The captured branch expectation travels with the fallback: the direct
/// advance compares against the tip the commit was built on, not a fresh
/// read, so a fallback can never strand a commit a racing writer landed
/// while this process was off its store. A moved tip fails stale instead.
/// The retry loop rebuilds this expectation (and the request's parents)
/// against the current tip after every lost race.
#[derive(Clone)]
enum Direct {
    /// Ordinary commit: `ops::new` plus the branch advance.
    New {
        expected: Option<(RefName, RefExpect)>,
    },
    /// Amend rewrite: `ops::edit` of the tip plus the branch advance.
    Amend {
        tip: Oid,
        author: Option<ruk_core::conflict::Signature>,
        expected: Option<(RefName, RefExpect)>,
    },
}

/// Mints one stash commit through the lane when one answers and directly
/// otherwise. Stash commits move no ref, so unlike branch commits this path
/// serves detached heads too; the slot allocation, stash rows, and index
/// rewrite around it stay direct publishes exactly as today.
pub(crate) fn commit_stash(
    ctx: &mut Ctx,
    request: NewRequest,
    request_id: RequestId,
) -> Result<Oid, GitError> {
    if Mode::from_ctx(ctx) == Mode::Off {
        return direct_stash(ctx, request);
    }
    let args = GitCommitArgs {
        tree: request.tree,
        parents: request.parents.clone(),
        author: request.author.clone(),
        committer: request.committer.clone(),
        message: request.message.clone(),
        change_id: request.change_id,
        predecessor: request.predecessor,
        ref_update: None,
    };
    let runtime = client_runtime()?;
    let mut request_id = request_id;
    for _ in 0..MAX_STALE_RETRIES {
        match try_remote(ctx, &runtime, &args, request_id)? {
            Remote::Done(reply) => {
                return reply
                    .created
                    .head
                    .as_git()
                    .copied()
                    .ok_or_else(|| GitError::Invalid {
                        detail: "stash commit has no git identity".to_owned(),
                    });
            }
            Remote::Direct => return direct_stash(ctx, request),
            Remote::Uncertain => {
                if let Some(landed) = landed_output(ctx, &request, &args)? {
                    return landed
                        .oid
                        .or_else(|| landed.head.as_git().copied())
                        .ok_or_else(|| GitError::Invalid {
                            detail: "stash commit has no git identity".to_owned(),
                        });
                }
                return direct_stash(ctx, request);
            }
            Remote::Stale => {
                request_id = RequestId::generate();
            }
        }
    }
    direct_stash(ctx, request)
}

/// Mints one stash commit through the shared exportable path (no
/// `change-id` header, so oids match the oracle byte-for-byte) and returns
/// its object id. A byte-identical commit already lives in the store, so
/// only a missing commit is published.
fn direct_stash(ctx: &mut Ctx, request: NewRequest) -> Result<Oid, GitError> {
    let store = ctx.store()?;
    let prepared = prepare_new(store, request).map_err(GitError::from)?;
    let oid = prepared
        .output
        .oid
        .or_else(|| prepared.output.head.as_git().copied())
        .ok_or_else(|| GitError::Invalid {
            detail: "stash commit has no git identity".to_owned(),
        })?;
    let missing = match state::commit_record(store, oid) {
        Ok(_) => false,
        Err(GitError::NotFound { .. }) => true,
        Err(err) => return Err(err),
    };
    if missing {
        store
            .publish(
                prepared.objects,
                &prepared.facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .map_err(GitError::from)?;
    }
    Ok(oid)
}

/// Retries lane submissions across lost branch races with fresh tips.
///
/// First-contact fallbacks publish the caller's commit with identical
/// arguments. Only proven movement rebuilds: a lane Stale, or a Stale
/// refusal from a fallback publish, rebuilds the lane arguments, the
/// request parents, and the fallback expectation against the current tip,
/// so a lost race retries instead of dying `E_STALE`. The budget bounds
/// the whole loop; exhaustion publishes the freshest triple once more,
/// and a genuinely stale tip still refuses there.
fn commit_via_coordinator(
    ctx: &mut Ctx,
    mut request: NewRequest,
    mut args: GitCommitArgs,
    mut request_id: RequestId,
    mut direct: Direct,
) -> Result<NewResult, GitError> {
    let runtime = client_runtime()?;
    for _ in 0..MAX_STALE_RETRIES {
        match try_remote(ctx, &runtime, &args, request_id)? {
            Remote::Done(reply) => return Ok(finish(*reply)),
            // No coordinator answered: publish the caller's commit
            // directly with identical arguments. A Stale refusal proves a
            // racing writer landed first; only then rebuild against its
            // tip and retry through the lane.
            Remote::Direct => match publish_direct(ctx, request.clone(), direct.clone()) {
                Ok(out) => return Ok(out),
                Err(GitError::Stale { .. }) => {
                    request_id = RequestId::generate();
                    let fresh = refresh_both(ctx, request, direct)?;
                    args = fresh.0;
                    request = fresh.1;
                    direct = fresh.2;
                }
                Err(err) => return Err(err),
            },
            // The submission may have committed: return its identity when
            // it landed, refuse in required mode, else publish the caller's
            // commit directly under the same proven-movement retry rule.
            Remote::Uncertain => {
                if let Some(landed) = landed_output(ctx, &request, &args)? {
                    return Ok(landed);
                }
                if Mode::from_ctx(ctx) == Mode::Required {
                    return Err(GitError::Io {
                        detail: "coordinator answer unreachable and RUK_COORDINATOR=required"
                            .to_owned(),
                    });
                }
                match publish_direct(ctx, request.clone(), direct.clone()) {
                    Ok(out) => return Ok(out),
                    Err(GitError::Stale { .. }) => {
                        request_id = RequestId::generate();
                        let fresh = refresh_both(ctx, request, direct)?;
                        args = fresh.0;
                        request = fresh.1;
                        direct = fresh.2;
                    }
                    Err(err) => return Err(err),
                }
            }
            // Lost branch race: rebuild everything against the current tip
            // and retry through the lane. Refresh refusals (amend, merge,
            // orphan) surface immediately: retrying cannot help them.
            Remote::Stale => {
                request_id = RequestId::generate();
                let fresh = refresh_both(ctx, request, direct)?;
                args = fresh.0;
                request = fresh.1;
                direct = fresh.2;
            }
        }
    }
    publish_direct(ctx, request, direct)
}

/// Publishes without the lane, preserving the caller's operation shape.
fn publish_direct(
    ctx: &mut Ctx,
    request: NewRequest,
    direct: Direct,
) -> Result<NewResult, GitError> {
    match direct {
        Direct::New { expected } => direct_commit(ctx, request, expected),
        Direct::Amend {
            tip,
            author,
            expected,
        } => direct_amend(ctx, request, tip, author, expected),
    }
}

/// Returns the stored identity when the submission already landed (its
/// commit exists and its ref already holds it), without publishing.
fn landed_output(
    ctx: &mut Ctx,
    request: &NewRequest,
    args: &GitCommitArgs,
) -> Result<Option<NewResult>, GitError> {
    let store = ctx.store()?;
    let prepared = prepare_new(store, request.clone()).map_err(GitError::from)?;
    if !prepared.objects.is_empty() || !prepared.facts.is_empty() {
        return Ok(None);
    }
    let oid = prepared
        .output
        .oid
        .or_else(|| prepared.output.head.as_git().copied())
        .ok_or_else(|| GitError::Invalid {
            detail: "new commit has no git identity".to_owned(),
        })?;
    match &args.ref_update {
        None => Ok(Some(prepared.output)),
        Some(ref_update) => {
            let current = state::read_ref(store, &ref_update.name)?;
            if current.as_ref() == Some(&RefTarget::Direct(oid)) {
                Ok(Some(prepared.output))
            } else {
                Ok(None)
            }
        }
    }
}

/// Converts a lane reply into the operation output.
fn finish(reply: NewReply) -> NewResult {
    let oid = reply.created.head.as_git().copied();
    NewResult {
        head: reply.created.head,
        change_id: reply.created.change,
        oid,
    }
}

/// Rebuilds the lane arguments, the commit request, and the fallback
/// expectation against the current tip after a lost race.
///
/// A retry that rebuilt only the lane arguments would leave the eventual
/// `publish_direct` fallback CASing against the stale captured tip with
/// the stale parent, so the second racer died `E_STALE` on exhaustion.
/// The refreshed request carries the fresh tip as its single parent (so a
/// fallback commit stays parented on the tip its CAS expects, never a
/// stranded orphan) and the refreshed fallback carries the fresh
/// expectation. A genuinely stale commit built on a moved tip still
/// refuses on the direct path; only a coordinator-lost-race retry moves
/// onto the fresh tip here.
///
/// Only intent-preserving rebuilds retry; anything that would strand or
/// rewrite a racing writer refuses `E_STALE` so the caller rebuilds
/// explicitly:
/// * amend: the rewritten head is fixed; advancing the branch from the
///   winner's tip to a rewrite of the old tip would strand the winner.
/// * root on a born branch, or merge / non-tip parent on a moved tip: the
///   recorded parents do not descend from the fresh tip, so publishing
///   under its CAS would strand the winner (or silently revert its tree).
/// * root on a branch born mid-flight (unborn `Absent` to `Present`): the
///   branch-tip parent is adopted, exactly what a re-run commit would do.
fn refresh_both(
    ctx: &mut Ctx,
    request: NewRequest,
    direct: Direct,
) -> Result<(GitCommitArgs, NewRequest, Direct), GitError> {
    let Direct::New { expected: captured } = direct else {
        return Err(GitError::Stale {
            detail: "branch moved under this amend".to_owned(),
        });
    };
    let Some((_, stale_expected)) = captured else {
        return Err(GitError::Stale {
            detail: "commit carries no captured tip to rebuild from".to_owned(),
        });
    };
    let store = ctx.store()?;
    let Some((name, expected)) = symbolic_target(store)? else {
        return Err(GitError::Stale {
            detail: "branch moved under a detached HEAD".to_owned(),
        });
    };
    let stale_tip = expected_tip(&stale_expected).ok();
    let fresh_tip = expected_tip(&expected).ok();
    let mut parents = request.parents.clone();
    match (stale_tip, fresh_tip) {
        // Still unborn (or otherwise tip-less): retry as-is; the
        // compare-and-swap arbitrates creation.
        (None, None) => {}
        // Born mid-flight: adopt the tip as the root's parent, exactly
        // what a re-run commit would record. Anything deliberately
        // parented elsewhere cannot adopt; refuse instead of stranding.
        (None, Some(tip)) => {
            if parents.is_empty() {
                parents.push(Head::Git { oid: tip });
            } else {
                return Err(GitError::Stale {
                    detail: "branch was created under this commit; rebuild it on the new tip"
                        .to_owned(),
                });
            }
        }
        // Moved tip: only an exact single-parent fast-forward reparents.
        // Merges, orphans, and off-tip parents refuse: publishing them
        // under the fresh CAS would strand the winner.
        (Some(stale), Some(tip)) if stale != tip => {
            let stale_head = Head::Git { oid: stale };
            if parents.len() == 1 && parents[0] == stale_head {
                parents[0] = Head::Git { oid: tip };
            } else {
                return Err(GitError::Stale {
                    detail: "branch moved under this commit; rebuild it on the new tip".to_owned(),
                });
            }
        }
        // Tip unchanged, or branch deleted: retry as-is; the
        // compare-and-swap arbitrates or refuses.
        _ => {}
    }
    let refreshed_request = NewRequest {
        tree: request.tree,
        parents: parents.clone(),
        author: request.author,
        committer: request.committer,
        message: request.message,
        change_id: request.change_id,
        predecessor: request.predecessor,
        provenance: request.provenance,
    };
    let args = GitCommitArgs {
        tree: refreshed_request.tree,
        parents,
        author: refreshed_request.author.clone(),
        committer: refreshed_request.committer.clone(),
        message: refreshed_request.message.clone(),
        change_id: refreshed_request.change_id,
        predecessor: refreshed_request.predecessor,
        ref_update: Some(GitCommitRefUpdate {
            name: name.clone(),
            expected: expected.clone(),
        }),
    };
    let refreshed_direct = Direct::New {
        expected: Some((name, expected)),
    };
    Ok((args, refreshed_request, refreshed_direct))
}

/// Extracts the tip a fresh compare-and-swap must expect.
fn expected_tip(expected: &RefExpect) -> Result<Oid, GitError> {
    match expected {
        RefExpect::Present(RefTarget::Direct(oid)) => Ok(*oid),
        _ => Err(GitError::Stale {
            detail: "branch moved under this commit".to_owned(),
        }),
    }
}

/// Reads the current branch compare-and-swap. Detached heads have no ref
/// producer on the lane and always take the direct path.
fn symbolic_target(store: &Store) -> Result<Option<(RefName, RefExpect)>, GitError> {
    let (workspace, _) = state::load_or_default(store)?;
    match &workspace.head {
        HeadRef::Symbolic(name) => {
            let before = state::read_ref(store, name)?;
            let expected = before.map(RefExpect::Present).unwrap_or(RefExpect::Absent);
            Ok(Some((name.clone(), expected)))
        }
        HeadRef::Detached(_) => Ok(None),
    }
}

/// Today's two-step publish, unchanged: the fallback path and the
/// `RUK_COORDINATOR=off` path share it byte-for-byte, except a fallback
/// carries the captured tip so its advance cannot strand a racing writer.
fn direct_commit(
    ctx: &mut Ctx,
    request: NewRequest,
    captured: Option<(RefName, RefExpect)>,
) -> Result<NewResult, GitError> {
    let store = ctx.store()?;
    let kind = ctx.kind()?;
    let result = ops_new(store, request).map_err(GitError::from)?;
    let new_oid = result
        .oid
        .or_else(|| result.head.as_git().copied())
        .ok_or_else(|| GitError::Invalid {
            detail: "new commit has no git identity".to_owned(),
        })?;
    advance_head_to(store, kind, new_oid, captured)?;
    Ok(result)
}

/// Moves the current branch tip, or a detached `HEAD`, to a new commit.
/// A captured expectation pins the advance to the tip the commit was built
/// on; without one the advance reads the current tip as before.
fn advance_head_to(
    store: &Store,
    kind: HashKind,
    new_oid: Oid,
    captured: Option<(RefName, RefExpect)>,
) -> Result<(), GitError> {
    let (workspace, raw) = state::load_or_default(store)?;
    match &workspace.head {
        HeadRef::Symbolic(name) => {
            let expected = match captured {
                Some((ref_name, expected)) if ref_name == *name => expected,
                _ => {
                    let before = state::read_ref(store, name)?;
                    before.map(RefExpect::Present).unwrap_or(RefExpect::Absent)
                }
            };
            state::apply_refs(
                store,
                kind,
                vec![RefUpdate {
                    name: name.clone(),
                    expected,
                    change: RefChange::Set(RefTarget::Direct(new_oid)),
                }],
            )?;
            Ok(())
        }
        HeadRef::Detached(_) => {
            let next = workspace.move_head(workspace.stamp, HeadRef::Detached(new_oid))?;
            let mutation = state::workspace_mutation(raw.as_deref(), &next)?;
            store
                .publish(
                    Vec::new(),
                    &[mutation],
                    EventSource::LocalPush,
                    &EventContext::default(),
                )
                .map_err(GitError::from)?;
            Ok(())
        }
    }
}

/// What one remote round settled as.
enum Remote {
    /// The lane answered; the commit is durable.
    Done(Box<NewReply>),
    /// No coordinator answered before any byte could commit; publish direct.
    Direct,
    /// The lane refused a lost branch race; retry with a fresh tip.
    Stale,
    /// A submission may have committed but its answer is unreachable: check
    /// whether it landed before publishing anything directly.
    Uncertain,
}

/// Builds the shared client runtime once per commit verb: every lane round
/// would otherwise pay a fresh runtime build, stretching the loser's retry
/// gap past the group-commit sharing window for no reason.
fn client_runtime() -> Result<tokio::runtime::Runtime, GitError> {
    tokio::runtime::Builder::new_current_thread()
        .thread_name("ruk-coordinator-client")
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| GitError::Io {
            detail: format!("coordinator runtime: {err}"),
        })
}

/// Submits through the sidecar, restoring the caller's store first on every
/// path. The store is dropped across the round trip so the server can
/// burst-open it without waiting on this process's lock.
fn try_remote(
    ctx: &mut Ctx,
    runtime: &tokio::runtime::Runtime,
    args: &GitCommitArgs,
    request_id: RequestId,
) -> Result<Remote, GitError> {
    let root = ctx.root.clone();
    let store_dir = root.join(".ruk");
    ctx.store.take();
    let outcome = remote_round(runtime, &store_dir, Mode::from_ctx(ctx), args, request_id);
    let budget = Arc::new(PreparationBudget::reference_defaults());
    ctx.store = Some(Store::open(&store_dir, budget).map_err(GitError::from)?);
    outcome
}

/// One remote round: connect, submit, and classify the failure phase.
fn remote_round(
    runtime: &tokio::runtime::Runtime,
    store_dir: &Path,
    mode: Mode,
    args: &GitCommitArgs,
    request_id: RequestId,
) -> Result<Remote, GitError> {
    runtime.block_on(async move {
        match round(store_dir, args, request_id).await {
            Ok(answer) => settle(answer),
            Err(Phase::Pre) => {
                spawn_server(store_dir);
                match round(store_dir, args, request_id).await {
                    Ok(answer) => settle(answer),
                    // A post-submit failure here still may have committed
                    // on the fresh server: resolve, never publish blind.
                    Err(Phase::Post) => Ok(Remote::Uncertain),
                    Err(Phase::Pre) => direct_or_required(mode),
                }
            }
            Err(Phase::Post) => match round(store_dir, args, request_id).await {
                Ok(answer) => settle(answer),
                Err(_) => Ok(Remote::Uncertain),
            },
        }
    })
}

/// Maps a lane answer onto the caller's next step.
///
/// Only success and the lost-race retry settle here. Every other refusal
/// resolves as uncertain: a failed burst open or an ambiguous store failure
/// may still have committed, so the landed check runs before any direct
/// publish (or any required-mode failure).
fn settle(answer: CommitAnswer) -> Result<Remote, GitError> {
    if answer.ok {
        return match answer.body {
            Some(Reply::GitCommit(boxed)) => Ok(Remote::Done(boxed)),
            Some(_) => Ok(Remote::Uncertain),
            None => Ok(Remote::Uncertain),
        };
    }
    match answer.code.as_deref() {
        Some("EStale") => Ok(Remote::Stale),
        _ => Ok(Remote::Uncertain),
    }
}

/// Falls back unless the caller required the sidecar.
fn direct_or_required(mode: Mode) -> Result<Remote, GitError> {
    if mode == Mode::Required {
        return Err(GitError::Io {
            detail: "RUK_COORDINATOR=required but no coordinator answered".to_owned(),
        });
    }
    Ok(Remote::Direct)
}

/// Transport failure phase: before any byte could commit (safe to publish
/// directly) or after (replay the same id first; the lane answers from its
/// receipt ledger when the submission already landed).
enum Phase {
    Pre,
    Post,
}

/// Connects, shakes hands, submits, and reads the answer.
async fn round(
    store_dir: &Path,
    args: &GitCommitArgs,
    request_id: RequestId,
) -> Result<CommitAnswer, Phase> {
    let (store_id, body) = per_repo::read_cli_endpoint(store_dir).map_err(|_| Phase::Pre)?;
    let now = tokio::time::Instant::now();
    let mut stream = per_repo::cli_connect(&body, now + CONNECT_TIMEOUT)
        .await
        .map_err(|_| Phase::Pre)?;
    let far = tokio::time::Instant::now() + EXCHANGE_TIMEOUT;
    per_repo::cli_handshake(&mut stream, store_id, &body, far)
        .await
        .map_err(|_| Phase::Pre)?;
    let request = Request::GitCommit(Box::new(Mutation {
        request_id,
        args: args.clone(),
    }));
    let bytes = per_repo::encode_frame(&CommitCall {
        v: 1,
        body: request,
    })
    .map_err(|_| Phase::Pre)?;
    // A send error may still have reached the server, so a retry replays
    // the same id instead of publishing directly.
    per_repo::send_frame(&mut stream, &bytes, far)
        .await
        .map_err(|_| Phase::Post)?;
    let raw = per_repo::recv_frame(&mut stream, far)
        .await
        .map_err(|_| Phase::Post)?;
    // The server always answers a received submission; an undecodable frame
    // is a post-submit failure with the same replay rule.
    per_repo::decode_frame::<CommitAnswer>(&raw).map_err(|_| Phase::Post)
}

/// Starts a detached server for the repository; the socket file is the
/// rendezvous, so callers poll it instead of supervising the child.
///
/// Unit tests never spawn: the test binary is not a coordinator, so an
/// in-process commit would wait out the full rendezvous before falling
/// back. Integration tests drive the real binary and spawn normally.
#[cfg(not(test))]
fn spawn_server(store_dir: &Path) {
    let root = store_dir.parent().map(Path::to_path_buf);
    let exe = std::env::var("RUK_COORDINATOR_BIN")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::current_exe().ok());
    let (Some(exe), Some(root)) = (exe, root) else {
        return;
    };
    let _ = std::process::Command::new(exe)
        .arg("git")
        .arg("coordinator")
        .arg(root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    wait_socket(store_dir);
}

#[cfg(test)]
fn spawn_server(_store_dir: &Path) {}

/// Polls for a serving coordinator after a spawn. Unix only: elsewhere the
/// coordinator cannot serve, so spawns simply fall back to direct publish.
/// Never compiled into unit tests, where spawning is stubbed out.
///
/// The rendezvous is the published lock body, not the socket file: the
/// server binds the socket before publishing, so a connectable socket
/// alone can still precede a readable endpoint, and the next round would
/// give up to a direct publish while the server is starting. Requiring
/// both keeps racing commits on the lane. A dead owner still times out:
/// its socket never connects, so the fallback path is unchanged.
#[cfg(all(unix, not(test)))]
fn wait_socket(store_dir: &Path) {
    let sock = socket_path(store_dir);
    let end = std::time::Instant::now() + SPAWN_WAIT;
    while std::time::Instant::now() < end {
        if per_repo::read_cli_endpoint(store_dir).is_ok()
            && sock.exists()
            && std::os::unix::net::UnixStream::connect(&sock).is_ok()
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(not(unix))]
fn wait_socket(_store_dir: &Path) {}

/// Serves this repository's coordinator sidecar until its idle TTL lapses.
/// Hidden: `ruk coordinator <repo>`.
pub(crate) fn serve(_ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let repo = args
        .iter()
        .find(|arg| !arg.starts_with('-'))
        .ok_or_else(|| GitError::Invalid {
            detail: "usage: ruk coordinator <repo>".to_owned(),
        })?;
    let repo = PathBuf::from(repo);
    let store_dir = if repo.join(".ruk").is_dir() {
        repo.join(".ruk")
    } else {
        repo
    };
    let idle_ms = std::env::var("RUK_COORDINATOR_IDLE_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_IDLE_MS);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_name("ruk-coordinator")
        .enable_io()
        .enable_time()
        .build()
        .map_err(|err| GitError::Io {
            detail: format!("coordinator runtime: {err}"),
        })?;
    match runtime.block_on(per_repo::cli_serve(
        store_dir,
        Duration::from_millis(idle_ms),
    )) {
        Ok((ServeOutcome::Idle, _)) | Ok((ServeOutcome::AlreadyRunning, _)) => Ok(Vec::new()),
        Err(err) => Err(GitError::from(err)),
    }
}
