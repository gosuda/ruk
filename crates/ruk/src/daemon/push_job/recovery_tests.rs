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
        let root = std::env::temp_dir().join(format!("ruk-push-recovery-{}", plan.id));
        std::fs::create_dir_all(&root).expect("scratch directory");
        let store = Store::create(
            &root.join(".ruk"),
            HashKind::Sha256,
            Arc::new(PreparationBudget::reference_defaults()),
        )
        .expect("store creates");
        store
            .publish(
                Vec::new(),
                &[plan
                    .persist_mutation(HashKind::Sha256, None)
                    .expect("plan mutation")],
                EventSource::LocalPush,
                &EventContext::default(),
            )
            .expect("uncertain plan persists");
        drop(store);
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
    pktline::send(&mut body, b"# service=git-receive-pack\n").expect("service packet");
    body.extend_from_slice(b"0000");
    pktline::send(
        &mut body,
        format!(
            "{} refs/heads/main\0report-status object-format=sha256\n",
            plan.updates[0].old.to_hex()
        )
        .as_bytes(),
    )
    .expect("requested ref packet");
    for update in &plan.reported_updates {
        pktline::send(
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
    body.extend_from_slice(b"0000");
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
                &[plan.updates[0].name.clone()],
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
            .push_guard_check(&fixture.path, remote.as_bytes(), &[update.name.clone()])
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
                .push_guard_check(&fixture.path, remote.as_bytes(), &[update.name.clone()])
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
            .bind_original_remote(remote.as_bytes().to_vec())
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
                        },
                    })),
                    reply: Reply::PushReconcile(Box::new(PushReconcileReply {
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
                    &[plan.updates[0].name.clone()]
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
                .push_guard_check(&fixture.path, remote.as_bytes(), &[update.name.clone()])
                .expect("receipt replay releases each committed wildcard owner");
        }
        fixture.finish().await;
    }
}
