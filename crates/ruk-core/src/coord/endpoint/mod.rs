use super::policy::Principal;
use crate::CoreError;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub(crate) use super::windows::ensure_local_storage;
#[cfg(unix)]
pub(crate) use unix::{UnixEndpoint as Endpoint, connect, ensure_local_storage};
#[cfg(windows)]
pub(crate) use windows::{WindowsEndpoint as Endpoint, connect};

#[cfg(unix)]
pub(crate) type Incoming = tokio::net::UnixStream;
#[cfg(unix)]
pub(crate) type Outgoing = tokio::net::UnixStream;
#[cfg(windows)]
pub(crate) type Incoming = tokio::net::windows::named_pipe::NamedPipeServer;
#[cfg(windows)]
pub(crate) type Outgoing = tokio::net::windows::named_pipe::NamedPipeClient;

pub(crate) fn owner() -> Result<Principal, CoreError> {
    #[cfg(unix)]
    {
        Ok(Principal::from_peer_uid(
            rustix::process::geteuid().as_raw(),
        ))
    }
    #[cfg(windows)]
    {
        Principal::from_verified_sid(&super::windows::current_sid()?)
    }
}

pub(crate) fn principal(stream: &Incoming) -> Result<Principal, CoreError> {
    #[cfg(unix)]
    {
        Ok(Principal::from_peer_uid(unix::peer_uid(stream)?))
    }
    #[cfg(windows)]
    {
        Principal::from_verified_sid(&super::windows::pipe_peer_sid(stream)?)
    }
}
