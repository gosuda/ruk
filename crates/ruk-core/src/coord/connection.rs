use super::cancel::{Cancel, CancelHandle, cancellation};
use super::policy::Principal;
use super::session::BoundSession;
use crate::{CoreError, ErrorCode, SessionId};

#[expect(
    dead_code,
    reason = "no caller at this commit; retained for later changeset rows"
)]
pub(crate) struct Connection {
    pub(crate) principal: Principal,
    pub(crate) session: Option<BoundSession>,
    pub(crate) cancel: Cancel,
    _lifetime: CancelHandle,
}

impl Connection {
    #[expect(
        dead_code,
        reason = "no caller at this commit; retained for later changeset rows"
    )]
    pub(crate) fn new(principal: Principal) -> Self {
        let (lifetime, cancel) = cancellation();
        Self {
            principal,
            session: None,
            cancel,
            _lifetime: lifetime,
        }
    }

    #[expect(
        dead_code,
        reason = "no caller at this commit; retained for later changeset rows"
    )]
    pub(crate) fn bound_session(&self, requested: SessionId) -> Result<&BoundSession, CoreError> {
        self.cancel.check()?;
        self.session
            .as_ref()
            .filter(|bound| bound.id() == requested)
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::EForbidden,
                    "request does not name this connection's authenticated session",
                )
            })
    }
}
