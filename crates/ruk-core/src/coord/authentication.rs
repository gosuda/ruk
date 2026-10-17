use std::sync::Arc;

use tokio::time::{Instant, timeout_at};

use super::admission::{Admitted, run_blocking};
use super::cancel::Cancel;
use super::endpoint::{self, Incoming};
use super::handshake;
use super::lock::EndpointNonce;
use super::policy::{PolicySource, Principal};
use crate::{CoreError, ErrorCode, StoreId};

pub(crate) struct Authentication {
    pub(crate) store: StoreId,
    pub(crate) nonce: EndpointNonce,
    pub(crate) policy: Arc<PolicySource>,
}

pub(crate) struct Authenticated {
    pub(crate) stream: Incoming,
    pub(crate) principal: Principal,
}

impl Authentication {
    /// Proves the endpoint and checks the OS principal against current policy.
    ///
    /// The caller reserves a connection slot before this call. It supplies a
    /// control admission permit and a deadline set at accept, at most one
    /// second later. No session payload may be read before this call succeeds.
    pub(crate) async fn accept(
        &self,
        mut stream: Incoming,
        admitted: Admitted,
        cancel: Cancel,
        deadline: Instant,
    ) -> Result<(Admitted, Authenticated), CoreError> {
        cancel.check()?;
        handshake::prove_server(&mut stream, self.store, &self.nonce, deadline).await?;
        cancel.check()?;
        let policy = Arc::clone(&self.policy);
        let work = run_blocking(admitted, cancel.clone(), move |cancel| {
            let principal = authorize_peer(&stream, &policy, cancel);
            (stream, principal)
        });
        let (admitted, (mut stream, principal)) = timeout_at(deadline, work)
            .await
            .map_err(|_| {
                CoreError::new(
                    ErrorCode::ECoordinatorUnresponsive,
                    "coordinator authentication deadline expired",
                )
            })??;
        cancel.check()?;
        let principal = match principal {
            Ok(principal) => principal,
            Err(error) if error.code == ErrorCode::EForbidden => {
                handshake::reject_client(&mut stream, deadline).await?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        handshake::accept_client(&mut stream, deadline).await?;
        Ok((admitted, Authenticated { stream, principal }))
    }
}

fn authorize_peer(
    stream: &Incoming,
    policy: &PolicySource,
    cancel: &Cancel,
) -> Result<Principal, CoreError> {
    cancel.check()?;
    let principal = endpoint::principal(stream)?;
    policy.load()?.lookup(&principal)?;
    cancel.check()?;
    Ok(principal)
}
