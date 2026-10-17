use ruk_core::change::PlanId;
use ruk_core::ids::{HashKind, Oid};
use ruk_core::store::types::FactTable;

use crate::transport::Interrupt;
use crate::transport::pktline as pkt;
use crate::transport::push::{
    PushPlanRecord, PushState, PushUpdate, PushWireRequest, RefResult, push_over,
};
use crate::transport::session::test_support::{ScriptedPeer, store_with_pack};

const FOUR: &str = "b7ee0f83149b8f52744bf4de0bc706afcd5302c8";

fn oid(hex: &str) -> Oid {
    Oid::from_hex(hex).expect("hex")
}

fn advertisement() -> Vec<u8> {
    let kind = HashKind::Sha1;
    let zero = kind.zero_oid();
    let mut adv = Vec::new();
    pkt::encode_data(
        &mut adv,
        format!("{zero} capabilities^{{}}\0report-status delete-refs ofs-delta atomic object-format=sha1\n").as_bytes(),
    )
    .expect("frame");
    let mut script = adv;
    pkt::encode_flush(&mut script);
    script
}

fn report_script(lines: &[&[u8]]) -> Vec<u8> {
    let mut script = advertisement();
    for line in lines {
        let mut frame = Vec::new();
        pkt::encode_data(&mut frame, line).expect("frame");
        script.extend(frame);
    }
    pkt::encode_flush(&mut script);
    script
}

fn updates() -> Vec<PushUpdate> {
    let kind = HashKind::Sha1;
    vec![
        PushUpdate {
            name: b"refs/heads/a".to_vec(),
            old: kind.zero_oid(),
            new: oid(FOUR),
        },
        PushUpdate {
            name: b"refs/heads/b".to_vec(),
            old: kind.zero_oid(),
            new: oid(FOUR),
        },
    ]
}

fn decoded_plan(store: &ruk_core::store::Store, id: PlanId, kind: HashKind) -> PushPlanRecord {
    let row = store
        .fact(FactTable::PushPlans, id.as_bytes())
        .expect("row read")
        .expect("plan persisted");
    PushPlanRecord::decode(id, kind, &row).expect("decode")
}

#[test]
fn acknowledged_updates_are_durable_before_ok() {
    let kind = HashKind::Sha1;
    let store = store_with_pack(kind, include_bytes!("../fixtures/basic.pack"));
    let script = report_script(&[b"unpack ok\n", b"ok refs/heads/a\n", b"ok refs/heads/b\n"]);
    let mut peer = ScriptedPeer::new(script);
    let current = updates();
    let req = PushWireRequest {
        updates: current.clone(),
        atomic: false,
    };
    let mut plan = PushPlanRecord::prepare(PlanId::generate(), b"origin".to_vec(), false, current);
    let outcomes =
        push_over(&mut peer, &store, kind, &mut plan, &req, &Interrupt::none()).expect("push");
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes.iter().all(|o| o.result == RefResult::Ok));
    assert_eq!(plan.state, PushState::Confirmed);
    let stored = decoded_plan(&store, plan.id, kind);
    assert_eq!(stored.state, PushState::Confirmed);
    assert_eq!(stored.outcomes, outcomes);
}

#[test]
fn rejected_refs_leave_local_refs_untouched() {
    let kind = HashKind::Sha1;
    let store = store_with_pack(kind, include_bytes!("../fixtures/basic.pack"));
    let script = report_script(&[
        b"unpack ok\n",
        b"ok refs/heads/a\n",
        b"ng refs/heads/b pre-receive hook declined\n",
    ]);
    let mut peer = ScriptedPeer::new(script);
    let current = updates();
    let req = PushWireRequest {
        updates: current.clone(),
        atomic: false,
    };
    let mut plan = PushPlanRecord::prepare(PlanId::generate(), b"origin".to_vec(), false, current);
    let outcomes =
        push_over(&mut peer, &store, kind, &mut plan, &req, &Interrupt::none()).expect("push");
    assert_eq!(outcomes.len(), 2);
    assert_eq!(plan.state, PushState::Rejected);
    let stored = decoded_plan(&store, plan.id, kind);
    assert_eq!(stored.state, PushState::Rejected);
    assert_eq!(stored.outcomes, outcomes);
    for name in [b"refs/heads/a".as_slice(), b"refs/heads/b".as_slice()] {
        assert!(
            store
                .fact(FactTable::Refs, name)
                .expect("ref read")
                .is_none()
        );
    }
}

#[test]
fn truncated_report_is_uncertain_never_confirmed() {
    let kind = HashKind::Sha1;
    let store = store_with_pack(kind, include_bytes!("../fixtures/basic.pack"));
    let script = report_script(&[b"unpack ok\n", b"ok refs/heads/a\n"]);
    let mut peer = ScriptedPeer::new(script);
    let current = updates();
    let req = PushWireRequest {
        updates: current.clone(),
        atomic: false,
    };
    let mut plan = PushPlanRecord::prepare(PlanId::generate(), b"origin".to_vec(), false, current);
    let err = push_over(&mut peer, &store, kind, &mut plan, &req, &Interrupt::none())
        .expect_err("truncated report");
    assert!(matches!(err, crate::GitError::Corrupt { .. }));
    assert_eq!(plan.state, PushState::Uncertain);
    let stored = decoded_plan(&store, plan.id, kind);
    assert_eq!(stored.state, PushState::Uncertain);
}
