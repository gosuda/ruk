//! Hosted `push` / `push.reconcile` transport jobs.
//!
//! R28 routes both methods around the coordinator: the lane owns no network
//! path, so the daemon intercepts them before `prepare_for_dispatch` and
//! serves each as a transport job:
//!
//! 1. The invocation's session is checked and a committed receipt replays,
//!    so a retried push returns the stored reply instead of re-sending.
//! 2. Discovery plus update translation runs off the lane on the transport
//!    bulkhead, and a `Prepared` plan commits on the lane under a fresh
//!    idempotency key, before the first byte moves.
//! 3. The send runs on the same bulkhead under the invocation's
//!    [`Interrupt`]: lease or connection loss trips the shared flag, so
//!    in-flight transfers observe cancellation at their next check.
//! 4. The terminal plan state plus the reply commits on the lane under the
//!    caller's original idempotency key, filling the receipt the retry
//!    path in step 1 reads back. Exactly-once delivery does not exist, so
//!    the idempotency key plus the replay check make retries safe, and the
//!    terminal fact chains on the row bytes the send left behind, whatever
//!    the transport's best-effort `Uncertain` write did first.
//!
//! A new push to a ref whose prior plan is `Uncertain` refuses with
//! `E_PUSH_UNCERTAIN` until that plan confirms, rejects, or a reconcile
//! observes the remote: the observation is the operator looking before
//! retrying, so it clears the block and a fresh plan may proceed. The block
//! lives in the [`Registry`], covering every connection of the daemon
//! process but not a restart.
//!
//! No wall-clock deadline rides the job interrupt: mirror syncs may run
//! long, and a fixed horizon would kill legitimate transfers. Lease and
//! invocation cancellation trip the flag instead, and the transport's own
//! I/O timeouts still bound silent stalls. Each invocation makes exactly
//! one send attempt: no retries inside the job, the client retries under
//! its idempotency key.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ruk_core::change::{PlanId, RequestId, SessionId};
use ruk_core::coord::{Cancel, HostedCoordinator, PreparedMutation, Principal, receipt};
use ruk_core::error::{CoreError, ErrorCode};
use ruk_core::heads::Head;
use ruk_core::protocol::{
    BoundedList, ChangeRef, Method, MutationOutcome, PushAtomicity, PushReconcileReply,
    PushRefOutcome, PushRefStatus, PushReply, PushSource, PushState, ReceiptRef,
    ReconcileObservation, ReconcileVerdict, RemoteExpect, RemoteSpec, Reply, ReplyEnvelope,
    Request, RequestDigest, Timestamp,
};
use ruk_core::records::Records;
use ruk_core::refdata::{RefName, RefTarget};
use ruk_core::store::{FactTable, Store};
use ruk_core::{HashKind, Oid};
use ruk_git::GitError;
use ruk_git::transport::Interrupt;
use ruk_git::transport::credentials::{
    AuthPolicy, TransportAuthKind, hermetic_vars, refuse_url_userinfo,
};
use ruk_git::transport::net::{self, EgressPolicy, Endpoint};
use ruk_git::transport::push::{
    self, PushPlanRecord, PushState as PlanState, PushUpdate, PushWireRequest, RefObservation,
    RefOutcome, RefResult,
};
use ruk_git::transport::refadv::Advertisement;
use ruk_git::transport::session::{AdvertisedLocalRef, Service};
use ruk_git::transport::smart_http::{self, RpcCall};

use super::{ConnectionRefs, InvocationOpen, decode_request_args};
use crate::cli::state::is_ancestor;
use crate::daemon::ipc;

/// The shared handles of one hosted push invocation.
pub(crate) struct PushJob<'a> {
    coordinator: &'a Arc<HostedCoordinator>,
    principal: &'a Principal,
    session: SessionId,
    repo_path: &'a Path,
    refs: &'a ConnectionRefs,
    cancel: &'a Cancel,
}

impl<'a> PushJob<'a> {
    /// Binds one session-checked invocation; the caller refuses sessionless
    /// calls with the method's own error first.
    pub(crate) fn bind(
        coordinator: &'a Arc<HostedCoordinator>,
        principal: &'a Principal,
        session: SessionId,
        repo_path: &'a Path,
        refs: &'a ConnectionRefs,
        cancel: &'a Cancel,
    ) -> Self {
        Self {
            coordinator,
            principal,
            session,
            repo_path,
            refs,
            cancel,
        }
    }

    /// Serves one hosted `push` invocation as a transport job.
    ///
    /// # Errors
    /// Session, replay, translation, transport, and lane failures.
    pub(crate) async fn push(self, open: &InvocationOpen) -> Result<Vec<u8>, CoreError> {
        self.coordinator
            .check_session(self.principal, self.session, self.cancel)
            .await?;
        let request = decode_request_args(
            Method::Push,
            open.args_json.as_deref(),
            open.request_id.as_deref(),
        )?;
        request.validate()?;
        let Request::Push(args) = &request else {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "internal: push decoded to another method",
            ));
        };
        let request_id = request.request_id().ok_or_else(|| {
            CoreError::new(
                ErrorCode::EInvalid,
                "push needs a request id for its receipt",
            )
        })?;
        if let Some(reply) = self.replay_committed(&request)? {
            return encode_reply(Some(request_id), reply);
        }

        let url = push_url(&args.args.remote)?;
        let bridge = CancelBridge::arm(self.cancel, open, self.refs.registry.egress_policy());
        refuse_url_userinfo(url, &bridge.auth).map_err(to_core)?;
        let ref_names: Vec<Vec<u8>> = args
            .args
            .updates
            .iter()
            .map(|update| update.remote_ref.as_bytes().to_vec())
            .collect();
        self.refs
            .registry
            .push_guard_check(self.repo_path, &ref_names)?;

        // Discovery plus translation runs on the bulkhead: store reads and
        // network I/O never block the lane. Each phase arms its own
        // watcher, so cancellation trips the flag exactly while that
        // phase can still observe it.
        let job = self.snapshot();
        let updates = args.args.updates.clone();
        let atomicity = args.args.atomicity;
        let url_owned = url.to_owned();
        let prepared = self
            .refs
            .transport
            .run(move || job.discover_and_translate(&url_owned, &updates, atomicity, &bridge))
            .await??;
        let plan_id = prepared.plan.id;
        self.commit_prepare(open, &request, &prepared.plan).await?;

        let job = self.snapshot();
        let bridge = CancelBridge::arm(self.cancel, open, self.refs.registry.egress_policy());
        let sent = self
            .refs
            .transport
            .run(move || job.send_updates(prepared, &bridge))
            .await??;
        let reply = Reply::Push(Box::new(sent.reply));
        let stored = self
            .coordinator
            .submit_prepared(
                self.principal,
                PreparedMutation {
                    session: self.session,
                    request_id,
                    request,
                    reply: reply.clone(),
                    objects: Vec::new(),
                    facts: vec![sent.terminal_fact],
                    workspace_fence: None,
                    ref_transaction: None,
                    ref_dependencies: Vec::new(),
                    on_behalf_of: open.on_behalf_of.clone(),
                },
                self.cancel,
            )
            .await?;
        self.refs.registry.note_push_terminal(
            self.repo_path,
            plan_id,
            &ref_names,
            sent.state == PushState::Uncertain,
        )?;
        encode_reply(Some(request_id), stored)
    }

    /// Serves one hosted `push.reconcile` invocation: observes the
    /// remote's current refs for a stored plan and maps them through the
    /// pure reconciler, committing only the reply plus its receipt.
    ///
    /// # Errors
    /// Session, replay, plan-load, transport, and lane failures.
    pub(crate) async fn reconcile(self, open: &InvocationOpen) -> Result<Vec<u8>, CoreError> {
        self.coordinator
            .check_session(self.principal, self.session, self.cancel)
            .await?;
        let request = decode_request_args(
            Method::PushReconcile,
            open.args_json.as_deref(),
            open.request_id.as_deref(),
        )?;
        request.validate()?;
        let Request::PushReconcile(args) = &request else {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "internal: push.reconcile decoded to another method",
            ));
        };
        let request_id = request.request_id().ok_or_else(|| {
            CoreError::new(
                ErrorCode::EInvalid,
                "push.reconcile needs a request id for its receipt",
            )
        })?;
        if let Some(reply) = self.replay_committed(&request)? {
            return encode_reply(Some(request_id), reply);
        }

        let plan_id = args.args.plan;
        let store = self.coordinator.store();
        let kind = store.hash_kind();
        let encoded = store
            .fact(FactTable::PushPlans, plan_id.as_bytes())?
            .ok_or_else(|| {
                CoreError::new(ErrorCode::ENotFound, format!("unknown push plan {plan_id}"))
            })?;
        let plan = PushPlanRecord::decode(plan_id, kind, &encoded).map_err(to_core)?;
        let remote = String::from_utf8(plan.remote.clone()).map_err(|_| {
            CoreError::new(
                ErrorCode::ECorrupt,
                "stored push plan carries a non-UTF-8 remote",
            )
        })?;

        let bridge = CancelBridge::arm(self.cancel, open, self.refs.registry.egress_policy());
        refuse_url_userinfo(&remote, &bridge.auth).map_err(to_core)?;
        let kind = self.coordinator.store().hash_kind();
        // The closure below moves the plan record in; pin the wire state
        // first (`PushState` is `Copy`, so this reads nothing twice).
        let plan_state = wire_state(plan.state);
        let job = self.snapshot();
        let observations = self
            .refs
            .transport
            .run(move || {
                let advertised = job.discover(&remote, &bridge)?;
                map_observations(kind, &plan, &advertised)
            })
            .await??;

        let observed_refs: Vec<Vec<u8>> = observations
            .iter()
            .map(|observation| observation.remote_ref.as_bytes().to_vec())
            .collect();
        let reply = Reply::PushReconcile(Box::new(PushReconcileReply {
            outcome: pending_outcome(self.session, request_id),
            plan: plan_id,
            state: plan_state,
            observations: BoundedList::complete(observations)?,
        }));
        let stored = self
            .coordinator
            .submit_prepared(
                self.principal,
                PreparedMutation {
                    session: self.session,
                    request_id,
                    request,
                    reply: reply.clone(),
                    objects: Vec::new(),
                    facts: Vec::new(),
                    workspace_fence: None,
                    ref_transaction: None,
                    ref_dependencies: Vec::new(),
                    on_behalf_of: open.on_behalf_of.clone(),
                },
                self.cancel,
            )
            .await?;
        self.refs
            .registry
            .note_push_reconciled(self.repo_path, &observed_refs)?;
        encode_reply(Some(request_id), stored)
    }

    /// Returns the stored reply when this request already committed, so a
    /// retry never re-sends.
    fn replay_committed(&self, request: &Request) -> Result<Option<Reply>, CoreError> {
        let wall = jiff::Timestamp::now();
        receipt::replay_if_committed(self.coordinator.store(), self.session, request, wall)
    }

    /// Snapshots the blocking-safe half of the job for the bulkhead
    /// closures: the store reads behind the coordinator stay valid across
    /// the pool hop.
    fn snapshot(&self) -> BlockingJob {
        BlockingJob {
            coordinator: Arc::clone(self.coordinator),
            session: self.session,
        }
    }

    /// Commits the `Prepared` plan on the lane under a fresh idempotency
    /// key, before the first byte moves.
    async fn commit_prepare(
        &self,
        open: &InvocationOpen,
        request: &Request,
        plan: &PushPlanRecord,
    ) -> Result<(), CoreError> {
        let store = self.coordinator.store();
        let prepare_fact = plan
            .persist_mutation(store.hash_kind(), None)
            .map_err(to_core)?;
        let reply = Reply::Push(Box::new(PushReply {
            outcome: pending_outcome(self.session, RequestId::generate()),
            plan: plan.id,
            state: PushState::Prepared,
            refs: BoundedList::complete(Vec::new())?,
        }));
        self.coordinator
            .submit_prepared(
                self.principal,
                PreparedMutation {
                    session: self.session,
                    request_id: RequestId::generate(),
                    request: request.clone(),
                    reply,
                    objects: Vec::new(),
                    facts: vec![prepare_fact],
                    workspace_fence: None,
                    ref_transaction: None,
                    ref_dependencies: Vec::new(),
                    on_behalf_of: open.on_behalf_of.clone(),
                },
                self.cancel,
            )
            .await?;
        Ok(())
    }
}

/// The blocking-safe half of a push job: everything a bulkhead closure
/// may touch.
#[derive(Clone)]
struct BlockingJob {
    coordinator: Arc<HostedCoordinator>,
    session: SessionId,
}

impl BlockingJob {
    /// Discovery plus update translation for the prepare phase: resolves
    /// every protocol update against the advertised refs, withholding
    /// refspecs the fast-forward gate refuses, and builds the `Prepared`
    /// plan record the lane commits before the send.
    fn discover_and_translate(
        &self,
        url: &str,
        updates: &[ruk_core::protocol::PushUpdate],
        atomicity: PushAtomicity,
        bridge: &CancelBridge,
    ) -> Result<TranslatedPush, CoreError> {
        let advertised = self.discover(url, bridge)?;
        let atomic = matches!(atomicity, PushAtomicity::Atomic);
        let mut translated = Vec::with_capacity(updates.len());
        let mut early = Vec::new();
        for update in updates {
            match self.translate_update(&advertised, update)? {
                Some(wire) => translated.push(wire),
                None => {
                    let noun = update.remote_ref.to_string();
                    early.push(RefOutcome {
                        name: update.remote_ref.as_bytes().to_vec(),
                        result: RefResult::Rejected {
                            reason: format!("rejected {noun} (non-fast-forward)"),
                        },
                    });
                }
            }
        }
        let mut plan = PushPlanRecord::prepare(
            PlanId::generate(),
            url.as_bytes().to_vec(),
            atomic,
            translated.clone(),
        );
        if atomic && !early.is_empty() {
            // Withhold the whole batch without sending: the plan records
            // the sibling refusals locally and reaches `Rejected`.
            for wire in &translated {
                early.push(RefOutcome {
                    name: wire.name.clone(),
                    result: RefResult::Rejected {
                        reason: "atomic push withheld: a sibling ref diverged".to_owned(),
                    },
                });
            }
            plan.refuse_locally(early.clone()).map_err(to_core)?;
            return Ok(TranslatedPush {
                wire: PushWireRequest {
                    updates: translated,
                    atomic,
                },
                early,
                plan,
                withheld: true,
                http: None,
            });
        }
        let http = match net::parse_endpoint(url).map_err(to_core)? {
            Endpoint::Http { .. } => Some(self.http_adv(url, bridge)?),
            _ => None,
        };
        Ok(TranslatedPush {
            wire: PushWireRequest {
                updates: translated,
                atomic,
            },
            early,
            plan,
            withheld: false,
            http,
        })
    }

    /// Advertised refs of one remote, in the local rows the verbs map.
    fn discover(
        &self,
        url: &str,
        bridge: &CancelBridge,
    ) -> Result<Vec<AdvertisedLocalRef>, CoreError> {
        discover_advertised(
            self.coordinator.store(),
            url,
            &bridge.auth,
            &bridge.egress,
            &bridge.interrupt,
        )
    }

    /// The HTTP advertisement for the POST half, discovered with the same
    /// policy the send runs under.
    fn http_adv(&self, url: &str, bridge: &CancelBridge) -> Result<HttpAdv, CoreError> {
        let store = self.coordinator.store();
        let Endpoint::Http { url: http_url, .. } = net::parse_endpoint(url).map_err(to_core)?
        else {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "internal: non-HTTP remote asked for an HTTP advertisement",
            ));
        };
        let base = smart_http::normalize_base(&http_url).map_err(to_core)?;
        let adv = smart_http::discover(
            &base,
            smart_http::SmartService::ReceivePack,
            store.hash_kind(),
            RpcCall {
                extra: &[],
                auth: &bridge.auth,
                egress: &bridge.egress,
                tls_roots: None,
                interrupt: &bridge.interrupt,
            },
        )
        .map_err(to_core)?;
        Ok(HttpAdv { base, adv })
    }

    /// Sends the translated updates and returns the terminal reply plus
    /// the chained fact. A withheld batch skips the network: its plan is
    /// already `Rejected` with the sibling refusals recorded. A send
    /// failure before the first persist propagates as the job error; once
    /// the plan leaves `Prepared`, the terminal `Uncertain` reply commits
    /// and the cause goes to the daemon log, since the reply model carries
    /// no error slot.
    fn send_updates(
        &self,
        prepared: TranslatedPush,
        bridge: &CancelBridge,
    ) -> Result<SentPush, CoreError> {
        let store = self.coordinator.store();
        let kind = store.hash_kind();
        let TranslatedPush {
            wire,
            mut early,
            mut plan,
            withheld,
            http,
        } = prepared;
        if withheld {
            let (state, refs) = map_outcomes(plan.state, &early)?;
            return self.finish_send(plan, state, refs);
        }
        if wire.updates.is_empty() {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "push needs at least one update",
            ));
        }
        let outcome = match http {
            Some(HttpAdv { base, adv }) => smart_http::push_pack(
                &base,
                &adv,
                store,
                &mut plan,
                &wire,
                RpcCall {
                    extra: &[],
                    auth: &bridge.auth,
                    egress: &bridge.egress,
                    tls_roots: None,
                    interrupt: &bridge.interrupt,
                },
            )
            .map_err(to_core),
            None => {
                let endpoint = net::parse_endpoint(&plan_remote(&plan)?).map_err(to_core)?;
                let stream = net::open_stream(&endpoint, Service::ReceivePack, &bridge.egress)
                    .map_err(to_core)?;
                push::push_over(stream, store, kind, &mut plan, &wire, &bridge.interrupt)
                    .map_err(to_core)
            }
        };
        match outcome {
            Ok(mut outcomes) => {
                outcomes.append(&mut early);
                let (state, refs) = map_outcomes(plan.state, &outcomes)?;
                self.finish_send(plan, state, refs)
            }
            Err(err) => {
                if plan.state == PlanState::Prepared {
                    return Err(err);
                }
                tracing::warn!(error = %err, "ruk push: send failed after first persist");
                let outcomes = send_failure_outcomes(early, &wire);
                let (state, refs) = map_outcomes(plan.state, &outcomes)?;
                self.finish_send(plan, state, refs)
            }
        }
    }

    /// Chains the terminal fact on the row bytes the send left behind and
    /// builds the terminal reply.
    fn finish_send(
        &self,
        plan: PushPlanRecord,
        state: PushState,
        refs: Vec<PushRefOutcome>,
    ) -> Result<SentPush, CoreError> {
        let store = self.coordinator.store();
        let kind = store.hash_kind();
        let current = store.fact(FactTable::PushPlans, plan.id.as_bytes())?;
        let terminal_fact = plan.persist_mutation(kind, current).map_err(to_core)?;
        Ok(SentPush {
            reply: PushReply {
                outcome: pending_outcome(self.session, RequestId::generate()),
                plan: plan.id,
                state,
                refs: BoundedList::complete(refs)?,
            },
            terminal_fact,
            state,
        })
    }

    /// Translates one protocol update against the advertised refs:
    /// resolves the new tip, pins the CAS expectation, and applies the
    /// fast-forward gate. Returns `None` for a non-fast-forward update,
    /// which the caller reports as a local refusal without sending.
    fn translate_update(
        &self,
        advertised: &[AdvertisedLocalRef],
        update: &ruk_core::protocol::PushUpdate,
    ) -> Result<Option<PushUpdate>, CoreError> {
        let store = self.coordinator.store();
        let zero = store.hash_kind().zero_oid();
        let name = update.remote_ref.as_bytes().to_vec();
        let entry = advertised.iter().find(|entry| entry.name == name);
        let advertised_tip = match entry {
            None => None,
            Some(entry) => match &entry.target {
                RefTarget::Direct(oid) => Some(*oid),
                RefTarget::Symbolic(_) => {
                    return Err(CoreError::new(
                        ErrorCode::EInvalid,
                        "destination ref is symbolic",
                    ));
                }
            },
        };
        let new = match &update.source {
            PushSource::Commit { oid } => *oid,
            PushSource::Delete => zero,
            PushSource::Change { change } => self.resolve_change_tip(store, change)?,
        };
        let old = match update.expected_old {
            Some(RemoteExpect::Absent) => zero,
            Some(RemoteExpect::Present { oid }) => oid,
            None => advertised_tip.unwrap_or(zero),
        };
        if !update.force
            && old != zero
            && new != zero
            && !is_ancestor(store, old, new).map_err(to_core)?
        {
            return Ok(None);
        }
        Ok(Some(PushUpdate { name, old, new }))
    }

    /// Resolves a change source to its commit tip, mirroring the land
    /// preparation's pinning rules: a pinned head must stay current, an
    /// unpinned change must have exactly one.
    fn resolve_change_tip(&self, store: &Store, target: &ChangeRef) -> Result<Oid, CoreError> {
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
                        "pinned head is not a current head of the change",
                    ));
                }
                head
            }
            None => match entry.heads.as_slice() {
                [head] => *head,
                _ => {
                    return Err(CoreError::new(
                        ErrorCode::EDivergent,
                        "change has several current heads; pin one with head",
                    ));
                }
            },
        };
        match head {
            Head::Git { oid } => Ok(oid),
            Head::Conflicted { .. } => Err(CoreError::new(
                ErrorCode::EConflicted,
                "change head is conflicted",
            )),
        }
    }
}

/// The credential policy of one transport job: the injected record when
/// the invocation carries one, else the hermetic ambient map, which
/// resolves no config files and reads no process environment behind the
/// caller's back. Shared with the `remote.refs` read, which authenticates
/// the same way and never stores what it learns.
pub(crate) fn job_auth(open: &InvocationOpen) -> AuthPolicy {
    if open.transport_auth.kind != TransportAuthKind::None {
        AuthPolicy::explicit(open.transport_auth.clone())
    } else {
        AuthPolicy::ambient_in(hermetic_vars())
    }
}

/// The explicit remote URL of a push: named remotes need the R31
/// resolution map, which does not exist yet.
fn push_url(remote: &RemoteSpec) -> Result<&str, CoreError> {
    match remote {
        RemoteSpec::Url { url } => Ok(url.as_str()),
        RemoteSpec::Named { name } => Err(CoreError::new(
            ErrorCode::EInvalid,
            format!("push to named remote `{name}` needs remote resolution (R31)"),
        )),
    }
}

/// Advertised refs of one remote: HTTP goes through the smart-http
/// discovery the POST half reuses, other transports through the endpoint
/// discovery. Local paths refuse: daemon jobs serve network remotes, and
/// a local path would resolve against the server's filesystem, not the
/// caller's. Shared with the `remote.refs` read.
pub(crate) fn discover_advertised(
    store: &Store,
    url: &str,
    auth: &AuthPolicy,
    egress: &EgressPolicy,
    interrupt: &Interrupt,
) -> Result<Vec<AdvertisedLocalRef>, CoreError> {
    let kind = store.hash_kind();
    let endpoint = net::parse_endpoint(url).map_err(to_core)?;
    if matches!(endpoint, Endpoint::Local { .. }) {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "daemon jobs serve network remotes; local paths stay out",
        ));
    }
    match &endpoint {
        Endpoint::Http { url: http_url, .. } => {
            let base = smart_http::normalize_base(http_url).map_err(to_core)?;
            let adv = smart_http::discover(
                &base,
                smart_http::SmartService::ReceivePack,
                kind,
                RpcCall {
                    extra: &[],
                    auth,
                    egress,
                    tls_roots: None,
                    interrupt,
                },
            )
            .map_err(to_core)?;
            net::to_local_refs(adv.refs.clone()).map_err(to_core)
        }
        _ => {
            let refs =
                net::discover_endpoint(&endpoint, Service::ReceivePack, kind, auth, egress, None)
                    .map_err(to_core)?;
            net::to_local_refs(refs).map_err(to_core)
        }
    }
}

/// The invocation's interrupt plus the policy one send runs under. The
/// watcher trips the shared flag when the lease or the connection goes,
/// so in-flight transfers observe cancellation at their next check; the
/// guard aborts the watcher once the send no longer needs it.
pub(crate) struct CancelBridge {
    pub(crate) interrupt: Interrupt,
    pub(crate) auth: AuthPolicy,
    pub(crate) egress: EgressPolicy,
    watcher: tokio::task::JoinHandle<()>,
}

impl CancelBridge {
    /// Arms one phase: the policy comes from the invocation, the flag
    /// trips on lease or connection loss, and dropping the bridge aborts
    /// a watcher whose phase already ended. `egress` is the daemon's
    /// configured dial allowlist.
    pub(crate) fn arm(cancel: &Cancel, open: &InvocationOpen, egress: EgressPolicy) -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        let tripped = Arc::clone(&flag);
        let mut cancelled = cancel.clone();
        let watcher = tokio::spawn(async move {
            cancelled.cancelled().await;
            tripped.store(true, Ordering::SeqCst);
        });
        Self {
            interrupt: Interrupt::none().with_cancel(flag),
            auth: job_auth(open),
            egress,
            watcher,
        }
    }
}

impl Drop for CancelBridge {
    fn drop(&mut self) {
        self.watcher.abort();
    }
}

/// Reads the scrubbed remote back off the plan record for the send phase;
/// the record stores no userinfo by construction.
fn plan_remote(plan: &PushPlanRecord) -> Result<String, CoreError> {
    String::from_utf8(plan.remote.clone()).map_err(|_| {
        CoreError::new(
            ErrorCode::ECorrupt,
            "stored push plan carries a non-UTF-8 remote",
        )
    })
}

/// Outcome rows for a send that failed after the first persist: every
/// ref whose update may have moved a byte gets a verdict-less row, which
/// `map_outcomes` reports `Uncertain` under the plan's state, while the
/// local refusals in `early` keep their verdicts — the transport clears
/// server outcomes when it marks the plan, so nothing here lies about a
/// remote answer.
fn send_failure_outcomes(mut early: Vec<RefOutcome>, wire: &PushWireRequest) -> Vec<RefOutcome> {
    early.extend(wire.updates.iter().map(|update| RefOutcome {
        name: update.name.clone(),
        result: RefResult::Ok,
    }));
    early
}

/// Maps transport outcomes plus the terminal plan state to reply rows: an
/// `Uncertain` plan marks every ref without a verdict uncertain, while a
/// rejection keeps its verdict — under `Uncertain` the only rejections
/// are local refusals that moved no bytes, since the transport clears
/// server outcomes when it marks the plan.
fn map_outcomes(
    state: PlanState,
    outcomes: &[RefOutcome],
) -> Result<(PushState, Vec<PushRefOutcome>), CoreError> {
    let wire = wire_state(state);
    let mut refs = Vec::with_capacity(outcomes.len());
    for outcome in outcomes {
        let remote_ref = RefName::new(outcome.name.clone()).map_err(|err| {
            CoreError::new(
                ErrorCode::ECorrupt,
                format!("push outcome carries a malformed ref name: {err}"),
            )
        })?;
        let status = match &outcome.result {
            RefResult::Rejected { reason } => PushRefStatus::Rejected {
                reason: reason.clone(),
            },
            RefResult::Ok if state == PlanState::Uncertain => PushRefStatus::Uncertain,
            RefResult::Ok => PushRefStatus::Confirmed { new: None },
        };
        refs.push(PushRefOutcome { remote_ref, status });
    }
    Ok((wire, refs))
}

/// The wire twin of a terminal plan state: the transport and protocol
/// models spell the same five states, and the reply carries the protocol
/// one.
fn wire_state(state: PlanState) -> PushState {
    match state {
        PlanState::Prepared => PushState::Prepared,
        PlanState::Sending => PushState::Sending,
        PlanState::Confirmed => PushState::Confirmed,
        PlanState::Rejected => PushState::Rejected,
        PlanState::Uncertain => PushState::Uncertain,
    }
}

/// Maps the pure reconciler over the advertised tips to reply rows.
fn map_observations(
    kind: HashKind,
    plan: &PushPlanRecord,
    advertised: &[AdvertisedLocalRef],
) -> Result<Vec<ReconcileObservation>, CoreError> {
    let zero = kind.zero_oid();
    let observed: Vec<(Vec<u8>, Option<Oid>)> = advertised
        .iter()
        .map(|entry| {
            let tip = match &entry.target {
                RefTarget::Direct(oid) => Some(*oid),
                RefTarget::Symbolic(_) => None,
            };
            (entry.name.clone(), tip)
        })
        .collect();
    let mut out = Vec::new();
    for reconciled in push::reconcile(plan, kind, &observed) {
        let remote_ref = RefName::new(reconciled.name.clone()).map_err(|_| {
            CoreError::new(
                ErrorCode::ECorrupt,
                "stored push plan carries a malformed ref name",
            )
        })?;
        // EqualNew/EqualOld reaffirm the plan's own pins; only a move
        // reports the remote's divergent value.
        let wire = plan
            .updates
            .iter()
            .find(|update| update.name == reconciled.name);
        let (observed, verdict) = match reconciled.observation {
            RefObservation::EqualNew => (
                wire.map(|update| update.new).filter(|oid| *oid != zero),
                ReconcileVerdict::EqualNew,
            ),
            RefObservation::EqualOld => (
                wire.map(|update| update.old).filter(|oid| *oid != zero),
                ReconcileVerdict::EqualOld,
            ),
            RefObservation::Moved { current } => (current, ReconcileVerdict::Moved),
        };
        out.push(ReconcileObservation {
            remote_ref,
            observed,
            verdict,
        });
    }
    Ok(out)
}

/// A placeholder outcome header: the lane overwrites the receipt plus the
/// operation at commit, the way `prepare_for_dispatch` callers leave it.
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

fn encode_reply(id: Option<RequestId>, reply: Reply) -> Result<Vec<u8>, CoreError> {
    ipc::encode_control(&ReplyEnvelope::success(id, reply))
}

pub(crate) fn to_core(err: GitError) -> CoreError {
    CoreError::new(err.code(), err.to_string())
}

struct TranslatedPush {
    wire: PushWireRequest,
    early: Vec<RefOutcome>,
    plan: PushPlanRecord,
    withheld: bool,
    http: Option<HttpAdv>,
}

struct HttpAdv {
    base: String,
    adv: Advertisement,
}

struct SentPush {
    reply: PushReply,
    terminal_fact: ruk_core::store::FactMutation,
    state: PushState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::registry::Registry;
    use ruk_core::protocol::{RemoteName, RemoteUrl};
    use ruk_git::transport::credentials::TransportAuth;

    fn test_open(auth: TransportAuth) -> InvocationOpen {
        InvocationOpen {
            repo: String::new(),
            method: String::new(),
            request_id: None,
            args_json: None,
            session_id: None,
            on_behalf_of: None,
            transport_auth: auth,
        }
    }

    fn oid_fill(byte: u8) -> Oid {
        Oid::from_bytes(&[byte; 32]).expect("filled oid parses")
    }

    #[test]
    fn job_auth_defaults_to_hermetic_ambient() {
        let policy = job_auth(&test_open(TransportAuth::none()));
        let AuthPolicy::Ambient { vars } = policy else {
            panic!("expected the ambient policy without an injected record");
        };
        assert_eq!(
            vars.get("GIT_CONFIG_NOSYSTEM").map(String::as_str),
            Some("1")
        );
        assert_eq!(vars.get("HOME").map(String::as_str), Some(""));
    }

    #[test]
    fn job_auth_uses_the_injected_record() {
        let policy = job_auth(&test_open(TransportAuth {
            kind: TransportAuthKind::Bearer,
            credential: "token".to_owned(),
            origin: "https://mirror.example".to_owned(),
        }));
        assert!(matches!(policy, AuthPolicy::Explicit { .. }));
    }

    #[test]
    fn push_url_accepts_explicit_rejects_named() {
        let url = RemoteUrl::new("https://mirror.example/repo.git").expect("url parses");
        assert_eq!(
            push_url(&RemoteSpec::Url { url }).expect("explicit url serves"),
            "https://mirror.example/repo.git"
        );
        let name = RemoteName::new("origin").expect("name parses");
        let err = push_url(&RemoteSpec::Named { name }).expect_err("named needs R31");
        assert_eq!(err.code, ErrorCode::EInvalid);
    }

    #[test]
    fn map_outcomes_reports_each_server_verdict() {
        let outcomes = vec![
            RefOutcome {
                name: b"refs/heads/a".to_vec(),
                result: RefResult::Ok,
            },
            RefOutcome {
                name: b"refs/heads/b".to_vec(),
                result: RefResult::Rejected {
                    reason: "stale".to_owned(),
                },
            },
        ];
        let (state, refs) = map_outcomes(PlanState::Confirmed, &outcomes).expect("maps");
        assert_eq!(state, PushState::Confirmed);
        assert!(matches!(refs[0].status, PushRefStatus::Confirmed { .. }));
        assert!(matches!(refs[1].status, PushRefStatus::Rejected { .. }));
    }

    #[test]
    fn map_outcomes_uncertain_forces_every_ref_uncertain() {
        let outcomes = vec![RefOutcome {
            name: b"refs/heads/a".to_vec(),
            result: RefResult::Ok,
        }];
        let (_, refs) = map_outcomes(PlanState::Uncertain, &outcomes).expect("maps");
        assert!(matches!(refs[0].status, PushRefStatus::Uncertain));
    }

    #[test]
    fn map_outcomes_uncertain_preserves_local_rejections() {
        let outcomes = vec![
            RefOutcome {
                name: b"refs/heads/sent".to_vec(),
                result: RefResult::Ok,
            },
            RefOutcome {
                name: b"refs/heads/refused".to_vec(),
                result: RefResult::Rejected {
                    reason: "non-fast-forward".to_owned(),
                },
            },
        ];
        let (state, refs) = map_outcomes(PlanState::Uncertain, &outcomes).expect("maps");
        assert_eq!(state, PushState::Uncertain);
        assert!(matches!(refs[0].status, PushRefStatus::Uncertain));
        assert!(matches!(refs[1].status, PushRefStatus::Rejected { .. }));
    }

    #[test]
    fn send_failure_outcomes_names_every_sent_ref() {
        let early = vec![RefOutcome {
            name: b"refs/heads/refused".to_vec(),
            result: RefResult::Rejected {
                reason: "non-fast-forward".to_owned(),
            },
        }];
        let wire = PushWireRequest {
            atomic: true,
            updates: vec![
                PushUpdate {
                    name: b"refs/heads/a".to_vec(),
                    old: oid_fill(1),
                    new: oid_fill(2),
                },
                PushUpdate {
                    name: b"refs/heads/b".to_vec(),
                    old: oid_fill(1),
                    new: oid_fill(2),
                },
            ],
        };
        let outcomes = send_failure_outcomes(early, &wire);
        let (state, refs) = map_outcomes(PlanState::Uncertain, &outcomes).expect("maps");
        assert_eq!(state, PushState::Uncertain);
        assert_eq!(refs.len(), 3);
        assert!(matches!(refs[0].status, PushRefStatus::Rejected { .. }));
        assert!(
            refs[1..]
                .iter()
                .all(|row| { matches!(row.status, PushRefStatus::Uncertain) })
        );
    }

    #[test]
    fn map_outcomes_malformed_ref_fails_corrupt() {
        let outcomes = vec![
            RefOutcome {
                name: b"refs/heads/fine".to_vec(),
                result: RefResult::Ok,
            },
            RefOutcome {
                name: b"refs/../escaped".to_vec(),
                result: RefResult::Ok,
            },
        ];
        let err = map_outcomes(PlanState::Confirmed, &outcomes)
            .expect_err("a malformed outcome name refuses the whole row");
        assert_eq!(err.code, ErrorCode::ECorrupt);
    }

    #[test]
    fn plan_remote_rejects_non_utf8_remote() {
        let plan = PushPlanRecord::prepare(
            PlanId::generate(),
            b"https://mirror.example/\xff".to_vec(),
            false,
            Vec::new(),
        );
        let err = plan_remote(&plan).expect_err("non-UTF-8 remote refuses");
        assert_eq!(err.code, ErrorCode::ECorrupt);
    }

    #[test]
    fn discover_advertised_refuses_local_paths() {
        let root = std::env::temp_dir().join(format!("ruk-push-local-{}", std::process::id()));
        let budget = Arc::new(ruk_core::store::PreparationBudget::reference_defaults());
        let store =
            Store::create(&root.join(".ruk"), HashKind::Sha256, budget).expect("store creates");
        let auth = AuthPolicy::ambient_in(hermetic_vars());
        let egress = EgressPolicy::deny_private();
        let interrupt = Interrupt::none();
        for url in ["/tmp/elsewhere/repo", &root.display().to_string()] {
            let err = discover_advertised(&store, url, &auth, &egress, &interrupt)
                .expect_err("a local path refuses before any dial");
            assert_eq!(err.code, ErrorCode::EInvalid);
        }
    }

    #[tokio::test]
    async fn cancel_bridge_trips_interrupt_on_cancel() {
        let (handle, cancel) = ruk_core::coord::cancellation();
        let open = test_open(TransportAuth::none());
        let bridge = CancelBridge::arm(&cancel, &open, EgressPolicy::deny_private());
        bridge.interrupt.check("probe").expect("untripped");
        handle.cancel();
        for _ in 0..100 {
            if bridge.interrupt.check("probe").is_err() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("interrupt never observed the cancellation");
    }

    #[test]
    fn map_observations_moved_when_remote_loses_the_ref() {
        let kind = HashKind::Sha256;
        let old = oid_fill(1);
        let new = oid_fill(2);
        let plan = PushPlanRecord::prepare(
            PlanId::generate(),
            b"https://mirror.example/r.git".to_vec(),
            false,
            vec![PushUpdate {
                name: b"refs/heads/gone".to_vec(),
                old,
                new,
            }],
        );
        let observations = map_observations(kind, &plan, &[]).expect("maps");
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].verdict, ReconcileVerdict::Moved);
        assert_eq!(observations[0].observed, None);
    }

    #[test]
    fn map_observations_malformed_plan_ref_fails_corrupt() {
        let kind = HashKind::Sha256;
        let plan = PushPlanRecord::prepare(
            PlanId::generate(),
            b"origin".to_vec(),
            false,
            vec![PushUpdate {
                name: b"refs/../escaped".to_vec(),
                old: oid_fill(1),
                new: oid_fill(2),
            }],
        );
        let err = map_observations(kind, &plan, &[])
            .expect_err("a malformed plan ref refuses the whole row");
        assert_eq!(err.code, ErrorCode::ECorrupt);
    }

    #[test]
    fn map_observations_reports_verdicts_with_tips() {
        let kind = HashKind::Sha256;
        let old = oid_fill(1);
        let new = oid_fill(2);
        let other = oid_fill(3);
        let plan = PushPlanRecord::prepare(
            PlanId::generate(),
            b"https://mirror.example/r.git".to_vec(),
            true,
            vec![
                PushUpdate {
                    name: b"refs/heads/landed".to_vec(),
                    old,
                    new,
                },
                PushUpdate {
                    name: b"refs/heads/stayed".to_vec(),
                    old,
                    new,
                },
                PushUpdate {
                    name: b"refs/heads/moved".to_vec(),
                    old,
                    new,
                },
            ],
        );
        let advertised = vec![
            AdvertisedLocalRef {
                name: b"refs/heads/landed".to_vec(),
                target: RefTarget::Direct(new),
            },
            AdvertisedLocalRef {
                name: b"refs/heads/stayed".to_vec(),
                target: RefTarget::Direct(old),
            },
            AdvertisedLocalRef {
                name: b"refs/heads/moved".to_vec(),
                target: RefTarget::Direct(other),
            },
        ];
        let observations = map_observations(kind, &plan, &advertised).expect("maps");
        assert_eq!(observations.len(), 3);
        assert_eq!(observations[0].verdict, ReconcileVerdict::EqualNew);
        assert_eq!(observations[0].observed, Some(new));
        assert_eq!(observations[1].verdict, ReconcileVerdict::EqualOld);
        assert_eq!(observations[1].observed, Some(old));
        assert_eq!(observations[2].verdict, ReconcileVerdict::Moved);
        assert_eq!(observations[2].observed, Some(other));
    }

    #[test]
    fn uncertain_guard_blocks_until_terminal_or_reconcile() {
        let root = std::env::temp_dir().join(format!("ruk-push-guard-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("scratch fits");
        let registry = Registry::new(vec![root.clone()]).expect("registry builds");
        let name = b"refs/heads/main".to_vec();
        registry
            .push_guard_check(&root, std::slice::from_ref(&name))
            .expect("clean ref passes");
        let blocking = PlanId::generate();
        registry
            .note_push_terminal(&root, blocking, std::slice::from_ref(&name), true)
            .expect("uncertain records");
        let err = registry
            .push_guard_check(&root, std::slice::from_ref(&name))
            .expect_err("uncertain blocks");
        assert_eq!(err.code, ErrorCode::EPushUncertain);
        assert!(err.to_string().contains(&blocking.to_string()));
        registry
            .note_push_terminal(&root, blocking, std::slice::from_ref(&name), false)
            .expect("confirmed clears");
        registry
            .push_guard_check(&root, std::slice::from_ref(&name))
            .expect("confirmed passes");
        registry
            .note_push_terminal(&root, blocking, std::slice::from_ref(&name), true)
            .expect("uncertain records again");
        registry
            .note_push_reconciled(&root, std::slice::from_ref(&name))
            .expect("reconcile clears");
        registry
            .push_guard_check(&root, std::slice::from_ref(&name))
            .expect("reconciled passes");
    }
}
