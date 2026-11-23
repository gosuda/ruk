use super::*;
use crate::daemon::BoundedExecutor;
use ruk_core::coord::CancelHandle;
use ruk_core::protocol::{Mutation, PushReconcileArgs, ReplyBody, SessionOpenArgs};
use ruk_core::store::{EventContext, EventSource, PreparationBudget};
use ruk_git::transport::credentials::TransportAuth;
use ruk_git::transport::pktline;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpListener;
use std::os::unix::fs::MetadataExt as _;
use std::time::Duration;

struct RecoveryFixture {
    root: PathBuf,
    path: PathBuf,
    coordinator: Arc<HostedCoordinator>,
    principal: Principal,
    session: SessionId,
    refs: ConnectionRefs,
    cancel: Cancel,
    _hold: CancelHandle,
}

impl RecoveryFixture {
    async fn new(plan: &PushPlanRecord) -> Self {
        Self::with_refs(plan, &[]).await
    }

    async fn with_refs(plan: &PushPlanRecord, advertised: &[AdvertisedLocalRef]) -> Self {
        let root = std::env::temp_dir().join(format!("ruk-push-recovery-{}", plan.id));
        std::fs::create_dir_all(&root).expect("scratch directory");
        let store = Store::create(
            &root.join(".ruk"),
            HashKind::Sha256,
            Arc::new(PreparationBudget::reference_defaults()),
        )
        .expect("store creates");
        let transaction = ruk_core::refdata::RefTransaction::new(
            HashKind::Sha256,
            advertised
                .iter()
                .map(|entry| ruk_core::refdata::RefUpdate {
                    name: RefName::new(entry.name.clone()).expect("advertised ref"),
                    expected: ruk_core::refdata::RefExpect::Absent,
                    change: ruk_core::refdata::RefChange::Set(entry.target.clone()),
                })
                .collect(),
        )
        .expect("fixture refs validate");
        let mut facts = ruk_core::refs::prepare_checked_transaction(&store, &transaction)
            .expect("fixture refs prepare before hosting")
            .into_mutations();
        facts.push(
            plan.persist_mutation(HashKind::Sha256, None)
                .expect("plan mutation"),
        );
        store
            .publish(
                Vec::new(),
                &facts,
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("uncertain plan persists");
        drop(store);
        Self::open_existing(root).await
    }

    async fn open_existing(root: PathBuf) -> Self {
        let uid = std::fs::metadata(&root).expect("scratch owner").uid();
        let principal = Principal::from_peer_uid(uid);
        let registry = Arc::new(Registry::new(vec![root.clone()]).expect("registry opens"));
        registry.set_runtime(tokio::runtime::Handle::current());
        registry.set_egress_policy(EgressPolicy::deny_private().allow_loopback());
        let (_, path, coordinator) = registry
            .open(root.to_str().expect("scratch path is UTF-8"))
            .expect("repository restores uncertain guards");
        let (hold, cancel) = cancellation();
        let (session, _) = coordinator
            .open_session(&principal, &SessionOpenArgs::default(), &cancel)
            .await
            .expect("session opens");
        let refs = ConnectionRefs {
            registry,
            executor: BoundedExecutor::new(2).expect("executor"),
            transport: BoundedExecutor::new(2).expect("transport executor"),
            window_bytes: 65536,
            handshake_timeout: Duration::from_secs(10),
            frame_timeout: Duration::from_secs(10),
            allowed_uids: vec![uid],
            admin_uids: Vec::new(),
        };
        Self {
            root,
            path,
            coordinator,
            principal,
            session,
            refs,
            cancel,
            _hold: hold,
        }
    }

    async fn restart(self) -> Self {
        let root = self.root.clone();
        self.refs.registry.shutdown_and_drain().await;
        drop(self);
        Self::open_existing(root).await
    }

    fn page_invocation(
        &self,
        plan: PlanId,
        request: RequestId,
        cursor: ruk_core::protocol::PushReconcileCursor,
    ) -> InvocationOpen {
        let mut open = self.invocation(plan, request, None);
        open.args_json = Some(
            sonic_rs::to_string(&PushReconcileArgs {
                plan,
                original_remote: None,
                original_ssh: None,
                cursor: Some(cursor),
            })
            .expect("page arguments"),
        );
        open
    }

    fn job(&self) -> PushJob<'_> {
        PushJob::bind(
            &self.coordinator,
            &self.principal,
            self.session,
            &self.path,
            &self.refs,
            &self.cancel,
        )
    }

    fn invocation(
        &self,
        plan: PlanId,
        request_id: RequestId,
        original_remote: Option<&str>,
    ) -> InvocationOpen {
        InvocationOpen {
            repo: self
                .path
                .to_str()
                .expect("scratch path is UTF-8")
                .to_owned(),
            method: "push.reconcile".to_owned(),
            request_id: Some(request_id.to_string()),
            args_json: Some(
                sonic_rs::to_string(&PushReconcileArgs {
                    plan,
                    original_remote: original_remote.map(str::to_owned),
                    original_ssh: None,
                    cursor: None,
                })
                .expect("arguments encode"),
            ),
            session_id: Some(self.session.to_string()),
            on_behalf_of: None,
            transport_auth: TransportAuth::none(),
        }
    }

    fn plan_bytes(&self, id: PlanId) -> Vec<u8> {
        self.coordinator
            .store()
            .fact(FactTable::PushPlans, id.as_bytes())
            .expect("plan row loads")
            .expect("plan row exists")
    }

    fn marker(&self, id: PlanId) -> Option<Vec<u8>> {
        self.coordinator
            .store()
            .fact(
                FactTable::RemoteObservations,
                &reconciliation_marker_key(id),
            )
            .expect("marker loads")
    }

    async fn finish(self) {
        self.refs.registry.shutdown_and_drain().await;
        let root = self.root.clone();
        drop(self);
        std::fs::remove_dir_all(root).expect("scratch directory removes");
    }
}

fn uncertain_plan(remote: &[u8], reported: bool) -> PushPlanRecord {
    let mut plan = PushPlanRecord::prepare(
        PlanId::generate(),
        remote.to_vec(),
        false,
        vec![PushUpdate {
            name: b"refs/heads/main".to_vec(),
            old: Oid::from_bytes(&[1; 32]).expect("old OID"),
            new: Oid::from_bytes(&[2; 32]).expect("new OID"),
        }],
    );
    plan.remote_is_resolved = false;
    if reported {
        plan.reported_updates.push(PushUpdate {
            name: b"refs/changes/7/head".to_vec(),
            old: HashKind::Sha256.zero_oid(),
            new: plan.updates[0].new,
        });
    }
    plan.begin_send().expect("send begins");
    plan.mark_uncertain();
    plan
}

fn advertisement(plan: &PushPlanRecord) -> Vec<u8> {
    let mut body = Vec::new();
    pktline::encode_data(&mut body, b"# service=git-receive-pack\n").expect("service packet");
    pktline::encode_flush(&mut body);
    for (index, update) in plan.updates.iter().enumerate() {
        let capabilities = if index == 0 {
            "\0report-status object-format=sha256"
        } else {
            ""
        };
        pktline::encode_data(
            &mut body,
            format!(
                "{} {}{capabilities}\n",
                update.old.to_hex(),
                String::from_utf8_lossy(&update.name),
            )
            .as_bytes(),
        )
        .expect("requested ref packet");
    }
    for update in &plan.reported_updates {
        pktline::encode_data(
            &mut body,
            format!(
                "{} {}\n",
                update.new.to_hex(),
                String::from_utf8_lossy(&update.name)
            )
            .as_bytes(),
        )
        .expect("reported ref packet");
    }
    pktline::encode_flush(&mut body);
    body
}

fn discovery_peer(
    body: Vec<u8>,
    before_reply: impl FnOnce() + Send + 'static,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
    let remote = format!(
        "http://{}/repo.git",
        listener.local_addr().expect("address")
    );
    let task = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("discovery connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("read deadline");
        let mut reader = BufReader::new(stream.try_clone().expect("split socket"));
        let mut head = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).expect("request header"), 0);
            head.push_str(&line);
            if line == "\r\n" {
                break;
            }
        }
        assert!(head.starts_with("GET /repo.git/info/refs?service=git-receive-pack HTTP/1.1\r\n"));
        before_reply();
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/x-git-receive-pack-advertisement\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).expect("response head");
        stream.write_all(&body).expect("response body");
    });
    (remote, task)
}

fn reconcile_reply(bytes: &[u8]) -> PushReconcileReply {
    let envelope: ReplyEnvelope = ipc::decode_control(bytes).expect("reply envelope");
    let ReplyBody::Success(Reply::PushReconcile(reply)) = envelope.body else {
        panic!("expected reconciliation reply");
    };
    *reply
}

#[tokio::test]
async fn legacy_reconcile_requires_an_original_destination() {
    let plan = uncertain_plan(b"origin", false);
    let fixture = RecoveryFixture::new(&plan).await;
    let before = fixture.plan_bytes(plan.id);
    let open = fixture.invocation(plan.id, RequestId::generate(), None);
    let err = fixture
        .job()
        .reconcile(&open)
        .await
        .expect_err("legacy identity needs explicit recovery");
    assert_eq!(err.code, ErrorCode::EInvalid);
    assert!(err.to_string().contains(&plan.id.to_string()));
    assert!(err.to_string().contains("original_remote"));
    assert_eq!(fixture.plan_bytes(plan.id), before);
    assert!(fixture.marker(plan.id).is_none());
    assert_eq!(
        fixture
            .refs
            .registry
            .push_guard_check(
                &fixture.path,
                b"https://original.example/repo.git",
                None,
                std::slice::from_ref(&plan.updates[0].name),
            )
            .expect_err("wildcard remains")
            .code,
        ErrorCode::EPushUncertain
    );
    fixture.finish().await;
}

#[tokio::test]
async fn legacy_reconcile_refuses_url_credentials_before_binding() {
    let plan = uncertain_plan(b"origin", false);
    let fixture = RecoveryFixture::new(&plan).await;
    let before = fixture.plan_bytes(plan.id);
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("unused destination");
    listener.set_nonblocking(true).expect("nonblocking probe");
    let origin = format!("http://{}", listener.local_addr().expect("address"));
    let remote = format!(
        "http://alice:CANARY-secret@{}/repo.git",
        listener.local_addr().expect("address")
    );
    let mut open = fixture.invocation(plan.id, RequestId::generate(), Some(&remote));
    open.transport_auth = TransportAuth {
        kind: TransportAuthKind::Bearer,
        credential: "injected-token".to_owned(),
        origin,
    };
    let err = fixture
        .job()
        .reconcile(&open)
        .await
        .expect_err("explicit authentication refuses URL credentials");
    assert_eq!(err.code, ErrorCode::EInvalid);
    assert!(!err.to_string().contains("CANARY-secret"));
    assert_eq!(
        listener
            .accept()
            .expect_err("no connection before policy validation")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(fixture.plan_bytes(plan.id), before);
    assert!(fixture.marker(plan.id).is_none());
    fixture.finish().await;
}

#[tokio::test]
async fn known_reconcile_destination_cannot_be_rebound() {
    let plan = uncertain_plan(b"https://known.example/repo.git", false);
    let fixture = RecoveryFixture::new(&plan).await;
    let before = fixture.plan_bytes(plan.id);
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("unused destination");
    listener.set_nonblocking(true).expect("nonblocking probe");
    let replacement = format!(
        "http://{}/repo.git",
        listener.local_addr().expect("address")
    );
    let open = fixture.invocation(plan.id, RequestId::generate(), Some(&replacement));
    let err = fixture
        .job()
        .reconcile(&open)
        .await
        .expect_err("known destination cannot be rebound");
    assert_eq!(err.code, ErrorCode::EInvalid);
    assert!(err.to_string().contains("known destination"));
    assert_eq!(
        listener
            .accept()
            .expect_err("no replacement connection")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(fixture.plan_bytes(plan.id), before);
    assert!(fixture.marker(plan.id).is_none());
    fixture.finish().await;
}

#[tokio::test]
async fn legacy_local_reconcile_observes_only_the_authenticated_store() {
    for direct_store_path in [false, true] {
        let plan = uncertain_plan(b"origin", true);
        let advertised = [
            AdvertisedLocalRef {
                name: plan.updates[0].name.clone(),
                target: RefTarget::Direct(plan.updates[0].old),
            },
            AdvertisedLocalRef {
                name: plan.reported_updates[0].name.clone(),
                target: RefTarget::Direct(plan.reported_updates[0].new),
            },
        ];
        let fixture = RecoveryFixture::with_refs(&plan, &advertised).await;
        let remote = if direct_store_path {
            fixture.path.to_str().expect("store path is UTF-8")
        } else {
            fixture.root.to_str().expect("repository path is UTF-8")
        };
        let open = fixture.invocation(plan.id, RequestId::generate(), Some(remote));
        let reply = reconcile_reply(
            &fixture
                .job()
                .reconcile(&open)
                .await
                .expect("local recovery observes the authenticated destination"),
        );
        assert!(reply.rewritten);
        assert_eq!(reply.observations.items.len(), 2);
        assert_eq!(
            reply.observations.items[0].verdict,
            ReconcileVerdict::EqualOld
        );
        assert_eq!(
            reply.observations.items[0].observed,
            Some(plan.updates[0].old)
        );
        assert_eq!(
            reply.observations.items[1].verdict,
            ReconcileVerdict::EqualNew
        );
        assert_eq!(
            reply.observations.items[1].observed,
            Some(plan.reported_updates[0].new)
        );
        let stored =
            PushPlanRecord::decode(plan.id, HashKind::Sha256, &fixture.plan_bytes(plan.id))
                .expect("bound local plan decodes");
        assert_eq!(stored.remote, remote.as_bytes());
        assert!(stored.destination_is_known());
        assert_eq!(fixture.marker(plan.id), Some(vec![0x01]));
        for update in plan.updates.iter().chain(&plan.reported_updates) {
            fixture
                .refs
                .registry
                .push_guard_check(
                    &fixture.path,
                    b"https://unrelated.example/repo.git",
                    None,
                    std::slice::from_ref(&update.name),
                )
                .expect("completed local recovery releases its wildcard owner");
        }
        let fresh = fixture.invocation(plan.id, RequestId::generate(), None);
        let known = reconcile_reply(
            &fixture
                .job()
                .reconcile(&fresh)
                .await
                .expect("known local destination remains recoverable"),
        );
        assert_eq!(known.observations, reply.observations);
        fixture.finish().await;
    }
}

#[tokio::test]
async fn legacy_local_reconcile_refuses_other_stores_and_path_escapes() {
    let plan = uncertain_plan(b"origin", false);
    let fixture = RecoveryFixture::new(&plan).await;
    let before = fixture.plan_bytes(plan.id);
    let other = fixture.root.join("other");
    std::fs::create_dir(&other).expect("other repository directory");
    let other_store = Store::create(
        &other.join(".ruk"),
        HashKind::Sha256,
        Arc::new(PreparationBudget::reference_defaults()),
    )
    .expect("other repository store");
    drop(other_store);
    let link = fixture.root.join("alias");
    std::os::unix::fs::symlink(&fixture.root, &link).expect("symlink fixture");
    for remote in [other.as_path(), link.as_path(), Path::new("/")] {
        let open = fixture.invocation(
            plan.id,
            RequestId::generate(),
            Some(remote.to_str().expect("fixture path is UTF-8")),
        );
        let err = fixture
            .job()
            .reconcile(&open)
            .await
            .expect_err("local recovery cannot read a different store or escape containment");
        assert_eq!(err.code, ErrorCode::EForbidden);
        assert_eq!(fixture.plan_bytes(plan.id), before);
        assert!(fixture.marker(plan.id).is_none());
        assert_eq!(
            fixture
                .refs
                .registry
                .push_guard_check(
                    &fixture.path,
                    b"https://unrelated.example/repo.git",
                    None,
                    std::slice::from_ref(&plan.updates[0].name),
                )
                .expect_err("failed local recovery retains the wildcard")
                .code,
            ErrorCode::EPushUncertain
        );
    }
    fixture.finish().await;
}

#[tokio::test]
async fn legacy_local_reconcile_refuses_replaced_store_identity() {
    let plan = uncertain_plan(b"origin", false);
    let fixture = RecoveryFixture::new(&plan).await;
    let before = fixture.plan_bytes(plan.id);
    let format_path = fixture.path.join(Store::format_file());
    let original = std::fs::read(&format_path).expect("original store identity");
    let replacement = ruk_core::store::types::StoreFormat {
        kind: HashKind::Sha256,
        id: ruk_core::change::StoreId::generate(),
    };
    std::fs::write(&format_path, replacement.to_bytes()).expect("replacement store identity");
    let open = fixture.invocation(
        plan.id,
        RequestId::generate(),
        Some(fixture.root.to_str().expect("repository path is UTF-8")),
    );
    let result = fixture.job().reconcile(&open).await;
    std::fs::write(&format_path, original).expect("restore fixture store identity");
    let err = result.expect_err("a replaced store is not the authenticated destination");
    assert_eq!(err.code, ErrorCode::EForbidden);
    assert_eq!(fixture.plan_bytes(plan.id), before);
    assert!(fixture.marker(plan.id).is_none());
    assert_eq!(
        fixture
            .refs
            .registry
            .push_guard_check(
                &fixture.path,
                b"https://unrelated.example/repo.git",
                None,
                std::slice::from_ref(&plan.updates[0].name),
            )
            .expect_err("replaced store identity retains the wildcard")
            .code,
        ErrorCode::EPushUncertain
    );
    fixture.finish().await;
}

#[tokio::test]
async fn legacy_reconcile_receipt_replays_without_releasing_unknown_guard() {
    let plan = uncertain_plan(b"ssh://mirror.example/repo.git", false);
    let fixture = RecoveryFixture::new(&plan).await;
    let before = fixture.plan_bytes(plan.id);
    let request_id = RequestId::generate();
    let observed = [AdvertisedLocalRef {
        name: plan.updates[0].name.clone(),
        target: RefTarget::Direct(plan.updates[0].new),
    }];
    let stored = fixture
        .coordinator
        .submit_prepared(
            &fixture.principal,
            PreparedMutation {
                session: fixture.session,
                request_id,
                request: Request::PushReconcile(Box::new(Mutation {
                    request_id,
                    args: PushReconcileArgs {
                        plan: plan.id,
                        original_remote: None,
                        original_ssh: None,
                        cursor: None,
                    },
                })),
                reply: Reply::PushReconcile(Box::new(PushReconcileReply {
                    reported_observations: BoundedList::default(),
                    next: None,
                    outcome: pending_outcome(fixture.session, request_id),
                    plan: plan.id,
                    state: PushState::Uncertain,
                    rewritten: false,
                    observations: BoundedList::complete(
                        map_observations(HashKind::Sha256, &plan, &observed)
                            .expect("legacy observations"),
                    )
                    .expect("observations fit"),
                })),
                objects: Vec::new(),
                facts: vec![
                    reconciliation_marker_fact(fixture.coordinator.store(), plan.id)
                        .expect("legacy marker mutation"),
                ],
                workspace_fence: None,
                ref_transaction: None,
                ref_dependencies: Vec::new(),
                on_behalf_of: None,
            },
            &fixture.cancel,
        )
        .await
        .expect("legacy observation and receipt commit without destination binding");
    let Reply::PushReconcile(stored) = stored else {
        panic!("reconciliation reply");
    };
    let open = fixture.invocation(plan.id, request_id, None);
    let replay = reconcile_reply(
        &fixture
            .job()
            .reconcile(&open)
            .await
            .expect("a matching retained observation replays"),
    );
    assert!(replay.outcome.receipt.replayed);
    assert_eq!(replay.observations, stored.observations);
    assert_eq!(replay.state, stored.state);
    assert_eq!(fixture.plan_bytes(plan.id), before);
    assert_eq!(fixture.marker(plan.id), Some(vec![0x01]));
    assert_eq!(
        fixture
            .refs
            .registry
            .push_guard_check(
                &fixture.path,
                b"https://unrelated.example/repo.git",
                None,
                std::slice::from_ref(&plan.updates[0].name),
            )
            .expect_err("receipt replay cannot prove the missing destination")
            .code,
        ErrorCode::EPushUncertain
    );
    fixture.finish().await;
}

#[tokio::test]
async fn legacy_reconcile_binds_and_observes_reported_refs() {
    let plan = uncertain_plan(b"origin", true);
    let fixture = RecoveryFixture::new(&plan).await;
    let (remote, peer) = discovery_peer(advertisement(&plan), || {});
    let open = fixture.invocation(plan.id, RequestId::generate(), Some(&remote));
    let reply = reconcile_reply(
        &fixture
            .job()
            .reconcile(&open)
            .await
            .expect("explicit recovery succeeds"),
    );
    peer.join().expect("discovery peer completes");
    assert!(reply.rewritten);
    assert_eq!(reply.state, PushState::Uncertain);
    assert_eq!(reply.observations.items.len(), 2);
    assert_eq!(
        reply.observations.items[0].verdict,
        ReconcileVerdict::EqualOld
    );
    assert_eq!(
        reply.observations.items[1].remote_ref.as_bytes(),
        plan.reported_updates[0].name
    );
    assert_eq!(
        reply.observations.items[1].observed,
        Some(plan.reported_updates[0].new)
    );
    assert_eq!(
        reply.observations.items[1].verdict,
        ReconcileVerdict::EqualNew
    );
    let stored = PushPlanRecord::decode(plan.id, HashKind::Sha256, &fixture.plan_bytes(plan.id))
        .expect("bound plan decodes");
    assert_eq!(stored.remote, remote.as_bytes());
    assert!(stored.remote_is_resolved);
    assert!(stored.destination_is_known());
    assert_eq!(stored.updates, plan.updates);
    assert_eq!(stored.reported_updates, plan.reported_updates);
    assert_eq!(fixture.marker(plan.id), Some(vec![0x01]));
    for update in plan.updates.iter().chain(&plan.reported_updates) {
        fixture
            .refs
            .registry
            .push_guard_check(
                &fixture.path,
                remote.as_bytes(),
                None,
                std::slice::from_ref(&update.name),
            )
            .expect("observed requested and reported refs release their owner");
    }
    fixture.finish().await;
}

#[tokio::test]
async fn legacy_reconcile_writer_race_preserves_guard_and_marker() {
    let plan = uncertain_plan(b"origin", true);
    let fixture = RecoveryFixture::new(&plan).await;
    let before = fixture.plan_bytes(plan.id);
    let coordinator = Arc::clone(&fixture.coordinator);
    let mut changed = plan.clone();
    changed.atomic = true;
    let changed_bytes = changed
        .encode(HashKind::Sha256)
        .expect("concurrent plan encodes");
    let (remote, peer) = discovery_peer(advertisement(&plan), move || {
        coordinator
            .store()
            .publish(
                Vec::new(),
                &[changed
                    .persist_mutation(HashKind::Sha256, Some(before))
                    .expect("concurrent mutation")],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("concurrent plan update wins before reconciliation publication");
    });
    let open = fixture.invocation(plan.id, RequestId::generate(), Some(&remote));
    let err = fixture
        .job()
        .reconcile(&open)
        .await
        .expect_err("writer rejects a stale bound plan");
    peer.join().expect("discovery peer completes");
    assert_eq!(err.code, ErrorCode::EStale);
    assert_eq!(fixture.plan_bytes(plan.id), changed_bytes);
    assert!(fixture.marker(plan.id).is_none());
    for update in plan.updates.iter().chain(&plan.reported_updates) {
        assert_eq!(
            fixture
                .refs
                .registry
                .push_guard_check(
                    &fixture.path,
                    remote.as_bytes(),
                    None,
                    std::slice::from_ref(&update.name)
                )
                .expect_err("failed publication retains every wildcard guard")
                .code,
            ErrorCode::EPushUncertain
        );
    }
    fixture.finish().await;
}

#[tokio::test]
async fn legacy_reconcile_after_lost_completion_releases_committed_binding() {
    for replay in [true, false] {
        let plan = uncertain_plan(b"origin", true);
        let fixture = RecoveryFixture::new(&plan).await;
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("unused destination");
        listener.set_nonblocking(true).expect("nonblocking probe");
        let remote = format!(
            "http://{}/repo.git",
            listener.local_addr().expect("address")
        );
        let (remote, peer) = if replay {
            (remote, None)
        } else {
            let (remote, peer) = discovery_peer(advertisement(&plan), || {});
            (remote, Some(peer))
        };
        let request_id = RequestId::generate();
        let mut bound = plan.clone();
        bound
            .bind_original_remote(remote.as_bytes().to_vec(), None)
            .expect("explicit legacy binding");
        let observed = vec![
            AdvertisedLocalRef {
                name: plan.updates[0].name.clone(),
                target: RefTarget::Direct(plan.updates[0].old),
            },
            AdvertisedLocalRef {
                name: plan.reported_updates[0].name.clone(),
                target: RefTarget::Direct(plan.reported_updates[0].new),
            },
        ];
        fixture
            .coordinator
            .submit_prepared(
                &fixture.principal,
                PreparedMutation {
                    session: fixture.session,
                    request_id,
                    request: Request::PushReconcile(Box::new(Mutation {
                        request_id,
                        args: PushReconcileArgs {
                            plan: plan.id,
                            original_remote: Some(remote.clone()),
                            original_ssh: None,
                            cursor: None,
                        },
                    })),
                    reply: Reply::PushReconcile(Box::new(PushReconcileReply {
                        reported_observations: BoundedList::default(),
                        next: None,
                        outcome: pending_outcome(fixture.session, request_id),
                        plan: plan.id,
                        state: PushState::Uncertain,
                        rewritten: true,
                        observations: BoundedList::complete(
                            map_observations(HashKind::Sha256, &bound, &observed)
                                .expect("observations"),
                        )
                        .expect("observations fit"),
                    })),
                    objects: Vec::new(),
                    facts: vec![
                        bound
                            .persist_mutation(HashKind::Sha256, Some(fixture.plan_bytes(plan.id)))
                            .expect("bound plan mutation"),
                        reconciliation_marker_fact(fixture.coordinator.store(), plan.id)
                            .expect("marker mutation"),
                    ],
                    workspace_fence: None,
                    ref_transaction: None,
                    ref_dependencies: Vec::new(),
                    on_behalf_of: None,
                },
                &fixture.cancel,
            )
            .await
            .expect("binding and receipt commit before completion is lost");
        assert_eq!(
            fixture
                .refs
                .registry
                .push_guard_check(
                    &fixture.path,
                    remote.as_bytes(),
                    None,
                    std::slice::from_ref(&plan.updates[0].name)
                )
                .expect_err("in-memory wildcard still awaits completion")
                .code,
            ErrorCode::EPushUncertain
        );
        let open = fixture.invocation(
            plan.id,
            if replay {
                request_id
            } else {
                RequestId::generate()
            },
            if replay { Some(&remote) } else { None },
        );
        let reply = reconcile_reply(
            &fixture
                .job()
                .reconcile(&open)
                .await
                .expect("committed receipt replays"),
        );
        assert_eq!(reply.outcome.receipt.replayed, replay);
        assert!(reply.rewritten);
        if let Some(peer) = peer {
            peer.join()
                .expect("fresh recovery observes bound destination");
        }
        assert_eq!(
            listener
                .accept()
                .expect_err("receipt replay does not rediscover")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        for update in plan.updates.iter().chain(&plan.reported_updates) {
            fixture
                .refs
                .registry
                .push_guard_check(
                    &fixture.path,
                    remote.as_bytes(),
                    None,
                    std::slice::from_ref(&update.name),
                )
                .expect("receipt replay releases each committed wildcard owner");
        }
        fixture.finish().await;
    }
}

fn large_recovery_plan() -> PushPlanRecord {
    let mut plan = uncertain_plan(b"origin", false);
    let old = plan.updates[0].old;
    let new = plan.updates[0].new;
    plan.updates = (0..501)
        .map(|index| PushUpdate {
            name: format!("refs/heads/topic-{index:04}").into_bytes(),
            old,
            new,
        })
        .collect();
    plan.reported_updates = (0..501)
        .map(|index| PushUpdate {
            name: format!("refs/changes/{index:04}/head").into_bytes(),
            old: HashKind::Sha256.zero_oid(),
            new,
        })
        .collect();
    plan
}

#[tokio::test]
async fn large_reconciliation_pages_survive_restart_and_release_only_at_completion() {
    let plan = large_recovery_plan();
    let fixture = RecoveryFixture::new(&plan).await;
    fixture
        .coordinator
        .store()
        .publish(
            Vec::new(),
            &[
                reconciliation_marker_fact(fixture.coordinator.store(), plan.id)
                    .expect("legacy marker"),
            ],
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("legacy completion predates known destination");
    assert!(fixture.marker(plan.id).is_some());
    let (remote, peer) = discovery_peer(advertisement(&plan), || {});
    let first_request = RequestId::generate();
    let open = fixture.invocation(plan.id, first_request, Some(&remote));
    let first = reconcile_reply(&fixture.job().reconcile(&open).await.expect("first page"));
    peer.join().expect("the only network observation completes");
    assert!(first.rewritten);
    assert_eq!(first.observations.total, 1002);
    assert_eq!(first.reported_observations.total, 501);
    assert_eq!(first.observations.items.len(), 1000);
    assert!(first.reported_observations.items.is_empty());
    let cursor = first.next.expect("second page is required");
    assert_eq!(cursor.page, 1);
    assert!(fixture.marker(plan.id).is_none());
    let replay = reconcile_reply(
        &fixture
            .job()
            .reconcile(&open)
            .await
            .expect("first-page receipt replay"),
    );
    assert!(replay.outcome.receipt.replayed);
    assert_eq!(replay.next, first.next);
    for target in [remote.as_bytes(), b"https://unrelated.example/repo.git"] {
        fixture
            .refs
            .registry
            .push_guard_check(
                &fixture.path,
                target,
                None,
                std::slice::from_ref(&plan.updates[0].name),
            )
            .expect_err("partial replay must retain the wildcard guard");
    }

    let fixture = fixture.restart().await;
    assert_ne!(fixture.session, cursor.session);
    let bound = PushPlanRecord::decode(plan.id, HashKind::Sha256, &fixture.plan_bytes(plan.id))
        .expect("bound plan survives restart");
    let Principal::Unix(uid) = &fixture.principal else {
        panic!("Unix fixture has a Unix principal");
    };
    let other_principal = Principal::from_peer_uid(uid.wrapping_add(1));
    let other_job = PushJob::bind(
        &fixture.coordinator,
        &other_principal,
        fixture.session,
        &fixture.path,
        &fixture.refs,
        &fixture.cancel,
    );
    let err = reconcile_pages::next(&other_job, &bound, cursor, RequestId::generate())
        .err()
        .expect("another principal cannot consume this snapshot");
    assert_eq!(err.code, ErrorCode::EForbidden);
    let mut skipped = cursor;
    skipped.page += 1;
    let invalid = fixture.page_invocation(plan.id, RequestId::generate(), skipped);
    assert_eq!(
        fixture
            .job()
            .reconcile(&invalid)
            .await
            .expect_err("skipped page")
            .code,
        ErrorCode::EStale
    );
    assert!(fixture.marker(plan.id).is_none());
    for target in [remote.as_bytes(), b"https://unrelated.example/repo.git"] {
        fixture
            .refs
            .registry
            .push_guard_check(
                &fixture.path,
                target,
                None,
                std::slice::from_ref(&plan.reported_updates[500].name),
            )
            .expect_err("restart retains wildcard guards for every reported target");
    }

    let last_request = RequestId::generate();
    let last_open = fixture.page_invocation(plan.id, last_request, cursor);
    let last = reconcile_reply(
        &fixture
            .job()
            .reconcile(&last_open)
            .await
            .expect("durable second page"),
    );
    assert!(last.next.is_none());
    assert_eq!(last.observations.total, 1002);
    assert_eq!(last.reported_observations.total, 501);
    assert_eq!(last.observations.items.len(), 2);
    assert_eq!(last.reported_observations.items.len(), 501);
    let observations: Vec<_> = first
        .observations
        .items
        .into_iter()
        .chain(last.observations.items)
        .collect();
    assert_eq!(observations.len(), 1002);
    assert!(
        observations[..501]
            .iter()
            .all(|row| row.verdict == ReconcileVerdict::EqualOld)
    );
    assert!(
        observations[501..]
            .iter()
            .all(|row| row.verdict == ReconcileVerdict::EqualNew)
    );
    for (row, update) in last
        .reported_observations
        .items
        .iter()
        .zip(&plan.reported_updates)
    {
        assert_eq!(row.remote_ref.as_bytes(), update.name);
        assert_eq!(row.old, None);
        assert_eq!(row.new, Some(update.new));
        assert_eq!(row.observed, Some(update.new));
        assert_eq!(row.verdict, ReconcileVerdict::EqualNew);
    }
    assert_eq!(fixture.marker(plan.id), Some(vec![0x01]));
    for update in plan.updates.iter().chain(&plan.reported_updates) {
        for target in [remote.as_bytes(), b"https://unrelated.example/repo.git"] {
            fixture
                .refs
                .registry
                .push_guard_check(
                    &fixture.path,
                    target,
                    None,
                    std::slice::from_ref(&update.name),
                )
                .expect("only completed snapshot releases every observed target");
        }
    }
    let replay = reconcile_reply(
        &fixture
            .job()
            .reconcile(&last_open)
            .await
            .expect("last-page receipt replay"),
    );
    assert!(replay.outcome.receipt.replayed);
    assert!(replay.next.is_none());
    let fixture = fixture.restart().await;
    for target in [remote.as_bytes(), b"https://unrelated.example/repo.git"] {
        fixture
            .refs
            .registry
            .push_guard_check(
                &fixture.path,
                target,
                None,
                std::slice::from_ref(&plan.updates[0].name),
            )
            .expect("completed legacy recovery remains released after restart");
    }
    fixture.finish().await;
}

#[tokio::test]
async fn legacy_progress_replacement_preserves_wildcard_guards() {
    let plan = large_recovery_plan();
    let fixture = RecoveryFixture::new(&plan).await;
    let (remote, peer) = discovery_peer(advertisement(&plan), || {});
    let open = fixture.invocation(plan.id, RequestId::generate(), Some(&remote));
    let first = reconcile_reply(&fixture.job().reconcile(&open).await.expect("first page"));
    peer.join().expect("discovery completes");
    assert!(first.next.is_some());

    let mut key = b"push-reconcile-progress\0".to_vec();
    key.extend_from_slice(plan.id.as_bytes());
    let store = fixture.coordinator.store();
    let previous = store
        .fact(FactTable::RemoteObservations, &key)
        .expect("progress loads")
        .expect("first page persists progress");
    let mut progress: std::collections::BTreeMap<String, sonic_rs::Value> =
        sonic_rs::from_slice(&previous).expect("progress is an object");
    assert!(progress.remove("legacy_guard").is_some());
    store
        .publish(
            Vec::new(),
            &[FactMutation {
                table: FactTable::RemoteObservations,
                key,
                expected: FactExpectation::Value(previous),
                value: Some(sonic_rs::to_vec(&progress).expect("old progress encodes")),
            }],
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("fixture uses progress from before the guard field");

    let fixture = fixture.restart().await;
    fixture
        .refs
        .registry
        .push_guard_check(
            &fixture.path,
            b"https://unrelated.example/repo.git",
            None,
            std::slice::from_ref(&plan.updates[0].name),
        )
        .expect_err("old progress conservatively restores the wildcard");
    let previous = fixture.plan_bytes(plan.id);
    let bound = PushPlanRecord::decode(plan.id, HashKind::Sha256, &previous)
        .expect("first page bound the destination");
    assert!(bound.destination_is_known());
    let advertised: Vec<_> = bound
        .updates
        .iter()
        .chain(&bound.reported_updates)
        .map(|update| AdvertisedLocalRef {
            name: update.name.clone(),
            target: RefTarget::Direct(update.new),
        })
        .collect();
    let request_id = RequestId::generate();
    let replacement = reconcile_pages::first(
        &fixture.job(),
        &bound,
        map_observations(HashKind::Sha256, &bound, &advertised).expect("new observations"),
        map_reported_observations(HashKind::Sha256, &bound, &advertised)
            .expect("new reported observations"),
        request_id,
        false,
    )
    .expect("a new snapshot does not rebind the destination");
    let mut facts = replacement.facts;
    facts.push(
        bound
            .persist_mutation(HashKind::Sha256, Some(previous))
            .expect("bound plan CAS"),
    );
    let reply = fixture
        .coordinator
        .submit_prepared(
            &fixture.principal,
            PreparedMutation {
                session: fixture.session,
                request_id,
                request: Request::PushReconcile(Box::new(Mutation {
                    request_id,
                    args: PushReconcileArgs {
                        plan: plan.id,
                        original_remote: None,
                        original_ssh: None,
                        cursor: None,
                    },
                })),
                reply: replacement.reply,
                objects: Vec::new(),
                facts,
                workspace_fence: None,
                ref_transaction: None,
                ref_dependencies: Vec::new(),
                on_behalf_of: None,
            },
            &fixture.cancel,
        )
        .await
        .expect("replacement snapshot commits");
    let Reply::PushReconcile(reply) = reply else {
        panic!("reconciliation reply");
    };
    let cursor = reply
        .next
        .expect("replacement still requires its last page");
    let fixture = fixture.restart().await;
    assert!(fixture.marker(plan.id).is_none());
    fixture
        .refs
        .registry
        .push_guard_check(
            &fixture.path,
            b"https://unrelated.example/repo.git",
            None,
            std::slice::from_ref(&plan.updates[0].name),
        )
        .expect_err("replacement retains the original wildcard after restart");
    let open = fixture.page_invocation(plan.id, RequestId::generate(), cursor);
    let last = reconcile_reply(&fixture.job().reconcile(&open).await.expect("last page"));
    assert!(last.next.is_none());
    assert_eq!(fixture.marker(plan.id), Some(vec![0x01]));
    fixture
        .refs
        .registry
        .push_guard_check(
            &fixture.path,
            b"https://unrelated.example/repo.git",
            None,
            std::slice::from_ref(&plan.updates[0].name),
        )
        .expect("replacement completion releases the wildcard");
    fixture.finish().await;
}

#[tokio::test]
async fn paged_reconciliation_rejects_a_changed_plan_without_releasing_guards() {
    let plan = large_recovery_plan();
    let fixture = RecoveryFixture::new(&plan).await;
    let (remote, peer) = discovery_peer(advertisement(&plan), || {});
    let open = fixture.invocation(plan.id, RequestId::generate(), Some(&remote));
    let first = reconcile_reply(&fixture.job().reconcile(&open).await.expect("first page"));
    peer.join().expect("discovery completes");
    let before = fixture.plan_bytes(plan.id);
    let mut changed =
        PushPlanRecord::decode(plan.id, HashKind::Sha256, &before).expect("bound plan");
    changed.atomic = !changed.atomic;
    fixture
        .coordinator
        .store()
        .publish(
            Vec::new(),
            &[changed
                .persist_mutation(HashKind::Sha256, Some(before))
                .expect("plan change")],
            EventSource::LocalPush,
            &EventContext::default(),
        )
        .expect("concurrent plan mutation");
    let open = fixture.page_invocation(
        plan.id,
        RequestId::generate(),
        first.next.expect("continuation"),
    );
    assert_eq!(
        fixture
            .job()
            .reconcile(&open)
            .await
            .expect_err("stale snapshot")
            .code,
        ErrorCode::EStale
    );
    assert!(fixture.marker(plan.id).is_none());
    fixture
        .refs
        .registry
        .push_guard_check(
            &fixture.path,
            remote.as_bytes(),
            None,
            std::slice::from_ref(&plan.updates[0].name),
        )
        .expect_err("changed plan must remain guarded");
    fixture.finish().await;
}

#[test]
fn same_ref_rewrites_keep_both_requested_and_reported_comparisons() {
    let mut plan = uncertain_plan(b"https://remote.example/repo.git", false);
    let replacement = Oid::from_bytes(&[3; 32]).expect("reported OID");
    plan.reported_updates.push(PushUpdate {
        name: plan.updates[0].name.clone(),
        old: plan.updates[0].old,
        new: replacement,
    });
    let advertised = vec![AdvertisedLocalRef {
        name: plan.updates[0].name.clone(),
        target: RefTarget::Direct(replacement),
    }];
    let requested =
        map_observations(HashKind::Sha256, &plan, &advertised).expect("requested comparisons");
    let reported = map_reported_observations(HashKind::Sha256, &plan, &advertised)
        .expect("reported comparisons");
    assert_eq!(requested.len(), 1);
    assert_eq!(requested[0].observed, Some(replacement));
    assert_eq!(requested[0].verdict, ReconcileVerdict::Moved);
    assert_eq!(reported.len(), 1);
    assert_eq!(reported[0].old, Some(plan.updates[0].old));
    assert_eq!(reported[0].new, Some(replacement));
    assert_eq!(reported[0].observed, Some(replacement));
    assert_eq!(reported[0].verdict, ReconcileVerdict::EqualNew);
}
