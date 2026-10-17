//! Windows coordinator endpoint platform implementation: local named pipes,
//! owner-only DACL enforcement, remote client rejection, and cancellation-safe
//! connection acceptance.
//!
//! # Cancellation Safety
//! The pending server instance is kept alive in `self.pending` while waiting
//! for connection. If the caller's `accept().await` future is dropped
//! (cancelled) before a client connects, the pipe remains open and in-flight;
//! it is never closed mid-handshake. When a client connects, a replacement
//! server instance is created and installed before the connected server is
//! returned to the caller.
//!
//! All unsafe Win32 FFI operations are delegated to [`crate::coord::windows`].
//! This module contains zero unsafe code.

use std::io;

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer};

use crate::StoreId;
use crate::coord::lock::EndpointAddress;
use crate::coord::windows::{
    create_first_pipe_server, create_subsequent_pipe_server, generate_pipe_name,
    validate_pipe_address,
};
use crate::error::{CoreError, ErrorCode};

/// The Windows named pipe coordinator endpoint listener.
pub(crate) struct WindowsEndpoint {
    address: EndpointAddress,
    pending: Option<NamedPipeServer>,
}

impl core::fmt::Debug for WindowsEndpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WindowsEndpoint")
            .field("address", &self.address)
            .finish()
    }
}

impl WindowsEndpoint {
    /// Binds a fresh coordinator endpoint for `store_id`.
    ///
    /// Generates an unpredictable local named pipe address combining the store
    /// UUID and independent cryptographic randomness. The first instance is
    /// created with `FILE_FLAG_FIRST_PIPE_INSTANCE` and an owner-only protected
    /// DACL, rejecting remote clients.
    pub(crate) fn bind(store_id: StoreId) -> Result<Self, CoreError> {
        let pipe_name = generate_pipe_name(store_id)?;
        let first_server = create_first_pipe_server(&pipe_name).map_err(|err| {
            CoreError::new(
                ErrorCode::EIo,
                format!("bind initial named pipe instance {pipe_name}: {err}"),
            )
        })?;

        Ok(Self {
            address: EndpointAddress::Pipe(pipe_name),
            pending: Some(first_server),
        })
    }

    /// The published endpoint address for contenders and attachers.
    pub(crate) fn address(&self) -> &EndpointAddress {
        &self.address
    }

    /// Asynchronously waits for a client connection.
    ///
    /// # Cancellation Safety
    /// If dropped while waiting on `connect().await`, the pending instance is
    /// retained in `self.pending` so the operating system does not close the
    /// in-flight listener. When a client connects, a replacement server instance
    /// is created and stored before returning the connected instance.
    pub(crate) async fn accept(&mut self) -> io::Result<NamedPipeServer> {
        let EndpointAddress::Pipe(pipe_name) = &self.address else {
            unreachable!("WindowsEndpoint always holds a Pipe address");
        };

        loop {
            // Ensure a pending server instance is armed.
            if self.pending.is_none() {
                self.pending = Some(create_subsequent_pipe_server(pipe_name)?);
            }

            let pending_ref = self.pending.as_ref().expect("pending server armed");
            pending_ref.connect().await?;

            // Create replacement instance before releasing the connected one.
            let replacement = create_subsequent_pipe_server(pipe_name)?;
            let connected = self.pending.replace(replacement).expect("pending server");
            return Ok(connected);
        }
    }
}

/// Connects an outgoing named pipe client to the given endpoint address.
///
/// Unix domain socket addresses are rejected with [`ErrorCode::EInvalid`].
/// Enforces local `\\.\pipe\` prefix, rejects remote names, and sets
/// `SECURITY_IDENTIFICATION` QOS flags.
pub(crate) async fn connect(address: &EndpointAddress) -> Result<NamedPipeClient, CoreError> {
    let pipe_name = match address {
        EndpointAddress::Pipe(name) => name,
        EndpointAddress::Unix(_) => {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "Unix domain socket address is not supported on Windows",
            ));
        }
    };

    validate_pipe_address(pipe_name)?;

    let mut opts = ClientOptions::new();
    opts.security_qos_flags(
        windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION
            | windows_sys::Win32::Storage::FileSystem::SECURITY_SQOS_PRESENT,
    );

    match opts.open(pipe_name) {
        Ok(client) => Ok(client),
        Err(err) => {
            let raw = err.raw_os_error();
            if raw == Some(windows_sys::Win32::Foundation::ERROR_PIPE_BUSY as i32) {
                Err(CoreError::new(
                    ErrorCode::ECoordinatorUnresponsive,
                    format!("named pipe server is busy: {pipe_name}"),
                ))
            } else if raw == Some(windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND as i32)
                || err.kind() == io::ErrorKind::NotFound
            {
                Err(CoreError::new(
                    ErrorCode::ENotFound,
                    format!("named pipe not found: {pipe_name}"),
                ))
            } else if raw == Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32)
                || err.kind() == io::ErrorKind::PermissionDenied
            {
                Err(CoreError::new(
                    ErrorCode::EForbidden,
                    format!("access denied connecting to named pipe: {pipe_name}"),
                ))
            } else {
                Err(CoreError::new(
                    ErrorCode::EIo,
                    format!("connect named pipe {pipe_name}: {err}"),
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_independent_pipe_generations() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        rt.block_on(async {
            let store_id = StoreId::generate();
            let ep1 = WindowsEndpoint::bind(store_id).expect("bind ep1");
            let ep2 = WindowsEndpoint::bind(store_id).expect("bind ep2");

            assert_ne!(
                ep1.address(),
                ep2.address(),
                "independent pipe bindings must produce distinct addresses",
            );

            let name1 = match ep1.address() {
                EndpointAddress::Pipe(n) => n,
                _ => panic!("expected pipe address"),
            };
            let name2 = match ep2.address() {
                EndpointAddress::Pipe(n) => n,
                _ => panic!("expected pipe address"),
            };

            assert!(name1.contains(&store_id.to_string()));
            assert!(name2.contains(&store_id.to_string()));
        });
    }

    #[test]
    fn test_connect_rejects_unix_address() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        rt.block_on(async {
            let unix_addr = EndpointAddress::Unix(PathBuf::from("/tmp/ruk.sock"));
            let err = connect(&unix_addr).await.unwrap_err();
            assert_eq!(err.code, ErrorCode::EInvalid);
        });
    }

    #[test]
    fn test_connect_missing_pipe_reports_not_found() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        rt.block_on(async {
            let missing_addr =
                EndpointAddress::Pipe(r"\\.\pipe\ruk-nonexistent-test-pipe".to_string());
            let err = connect(&missing_addr).await.unwrap_err();
            assert_eq!(err.code, ErrorCode::ENotFound);
        });
    }

    #[test]
    fn test_accept_and_connect_roundtrip() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        rt.block_on(async {
            let store_id = StoreId::generate();
            let mut endpoint = WindowsEndpoint::bind(store_id).expect("bind endpoint");
            let address = endpoint.address().clone();

            let client_task = tokio::spawn(async move {
                let mut client = connect(&address).await.expect("connect client");
                client.write_all(b"ping").await.expect("client write ping");

                let mut reply = [0u8; 4];
                client
                    .read_exact(&mut reply)
                    .await
                    .expect("client read pong");
                assert_eq!(&reply, b"pong");
            });

            let mut server = endpoint.accept().await.expect("accept server");
            let mut request = [0u8; 4];
            server
                .read_exact(&mut request)
                .await
                .expect("server read ping");
            assert_eq!(&request, b"ping");

            server.write_all(b"pong").await.expect("server write pong");

            client_task.await.expect("client task");

            // Verify a second client can connect immediately because accept created replacement.
            let second_address = endpoint.address().clone();
            let second_client_task = tokio::spawn(async move {
                let mut client = connect(&second_address).await.expect("second connect");
                client.write_all(b"ok").await.expect("second client write");
            });

            let mut second_server = endpoint.accept().await.expect("second accept");
            let mut buf = [0u8; 2];
            second_server
                .read_exact(&mut buf)
                .await
                .expect("second server read");
            assert_eq!(&buf, b"ok");

            second_client_task.await.expect("second client task");
        });
    }

    #[test]
    fn test_cancellation_safety_retains_pending_server() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        rt.block_on(async {
            let store_id = StoreId::generate();
            let mut endpoint = WindowsEndpoint::bind(store_id).expect("bind endpoint");
            let address = endpoint.address().clone();

            // Cancel accept while waiting (timeout of 10 ms).
            let timeout_result =
                tokio::time::timeout(std::time::Duration::from_millis(10), endpoint.accept()).await;
            assert!(
                timeout_result.is_err(),
                "accept must timeout without client"
            );

            // Verify endpoint is still intact and can accept subsequent client connection.
            let client_task = tokio::spawn(async move {
                let mut client = connect(&address)
                    .await
                    .expect("connect client after cancel");
                client.write_all(b"data").await.expect("write after cancel");
            });

            let mut server = endpoint.accept().await.expect("accept after cancel");
            let mut buf = [0u8; 4];
            server
                .read_exact(&mut buf)
                .await
                .expect("read after cancel");
            assert_eq!(&buf, b"data");

            client_task.await.expect("client task");
        });
    }
}
