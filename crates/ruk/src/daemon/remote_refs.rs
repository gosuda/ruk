//! Hosted `remote.refs` read: the advertised refs of one explicit remote
//! URL, observed live and never stored.
//!
//! R22 adopts the mirror gap for exact-mode prune: rukie computes refspecs
//! from `refs.list` (local) plus this read (remote), so the daemon answers
//! with a discovery round-trip instead of a lane query. Authentication
//! reuses the push transport job's policy (the injected record or the
//! hermetic ambient map), and the credential never touches the store: the
//! reply carries refs only, no receipt, no facts.
//!
//! The argument carries a bare URL, so named remotes refuse by
//! construction; local paths refuse in discovery, which would otherwise
//! resolve against the server's filesystem.

use std::sync::Arc;

use ruk_core::change::SessionId;
use ruk_core::coord::{Cancel, HostedCoordinator, Principal};
use ruk_core::error::{CoreError, ErrorCode};
use ruk_core::protocol::{Method, RemoteRefsReply, Reply, ReplyEnvelope, Request};
use ruk_core::refdata::RefName;
use ruk_core::refs::RefEntry;
use ruk_git::transport::credentials::refuse_url_userinfo;
use ruk_git::transport::session::Service;

use super::push_job::{CancelBridge, discover_advertised, to_core};
use super::{ConnectionRefs, InvocationOpen, decode_request_args};
use crate::daemon::ipc;

/// Serves one hosted `remote.refs` invocation: checks the session, runs
/// one discovery round-trip on the transport bulkhead, and answers with
/// the advertised refs plus the store's current view.
///
/// # Errors
/// Session, argument, transport, and view failures.
pub(crate) async fn run_remote_refs(
    coordinator: &Arc<HostedCoordinator>,
    principal: &Principal,
    session: SessionId,
    open: &InvocationOpen,
    refs: &ConnectionRefs,
    cancel: &Cancel,
) -> Result<Vec<u8>, CoreError> {
    coordinator
        .check_session(principal, session, cancel)
        .await?;
    let request = decode_request_args(
        Method::RemoteRefs,
        open.args_json.as_deref(),
        open.request_id.as_deref(),
    )?;
    request.validate()?;
    let Request::RemoteRefs(args) = &request else {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "internal: remote.refs decoded to another method",
        ));
    };
    let url = args.url.as_str();
    let bridge = CancelBridge::arm(cancel, open, refs.registry.egress_policy());
    refuse_url_userinfo(url, &bridge.auth).map_err(to_core)?;
    let coordinator_job = Arc::clone(coordinator);
    let url_owned = url.to_owned();
    let (view, entries) = refs
        .transport
        .run(move || {
            let advertised = discover_advertised(
                coordinator_job.store(),
                &url_owned,
                &bridge.auth,
                &bridge.egress,
                &bridge.interrupt,
                Service::UploadPack,
            )?;
            let view = coordinator_job.view()?;
            let entries = map_entries(&advertised)?;
            Ok::<_, CoreError>((view, entries))
        })
        .await??;
    let reply = Reply::RemoteRefs(Box::new(RemoteRefsReply {
        view,
        refs: entries,
    }));
    ipc::encode_control(&ReplyEnvelope::success(None, reply))
}

/// Maps advertised refs to reply rows, validating the names the remote
/// sent: a malformed advertised name fails the read rather than entering
/// a typed row.
fn map_entries(
    advertised: &[ruk_git::transport::session::AdvertisedLocalRef],
) -> Result<Vec<RefEntry>, CoreError> {
    advertised
        .iter()
        .map(|entry| {
            let name = RefName::new(entry.name.clone()).map_err(|_| {
                CoreError::new(
                    ErrorCode::ECorrupt,
                    "remote advertised a malformed ref name",
                )
            })?;
            Ok(RefEntry {
                name,
                target: entry.target.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::map_entries;
    use ruk_core::ids::{HashKind, Oid};
    use ruk_core::refdata::RefTarget;
    use ruk_git::transport::session::AdvertisedLocalRef;

    fn advertised(name: &[u8], oid: Option<Oid>) -> AdvertisedLocalRef {
        AdvertisedLocalRef {
            name: name.to_vec(),
            target: match oid {
                Some(oid) => RefTarget::Direct(oid),
                None => RefTarget::Direct(HashKind::Sha256.zero_oid()),
            },
        }
    }

    #[test]
    fn entries_carry_direct_tips() {
        let oid = Oid::from_bytes(&[7u8; 32]).expect("oid parses");
        let rows = map_entries(&[advertised(b"refs/heads/main", Some(oid))]).expect("maps");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name.as_bytes(), b"refs/heads/main");
        assert!(matches!(rows[0].target, RefTarget::Direct(tip) if tip == oid));
    }

    #[test]
    fn entries_carry_symbolic_targets() {
        let target =
            ruk_core::refdata::RefName::new(b"refs/heads/main".to_vec()).expect("ref name parses");
        let entry = AdvertisedLocalRef {
            name: b"refs/heads/alias".to_vec(),
            target: RefTarget::Symbolic(target),
        };
        let rows = map_entries(&[entry]).expect("symbolic rows map");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name.as_bytes(), b"refs/heads/alias");
        assert!(matches!(rows[0].target, RefTarget::Symbolic(_)));
    }

    #[test]
    fn malformed_advertised_name_fails_corrupt() {
        let oid = Oid::from_bytes(&[7u8; 32]).expect("oid parses");
        let err = map_entries(&[advertised(b"refs/heads/../escape", Some(oid))])
            .expect_err("bad name refuses");
        assert_eq!(err.code, ruk_core::error::ErrorCode::ECorrupt);
    }
}
