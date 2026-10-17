//! Coordinator IPC client.
//!
//! A [`Client`] represents an authenticated, single-flight connection to an
//! active coordinator endpoint for a specific store. It performs the initial
//! handshake to authenticate the session, and executes individual request/reply
//! exchanges over length-prefixed JSON control frames.
//!
//! # Protocol and Framing Discipline
//!
//! * Frame boundaries and size limits are strictly validated using
//!   [`transport::read_length`], [`transport::read_body`], and
//!   [`transport::write_body`]. Announced reply sizes are bounded before
//!   payload allocation.
//! * The client takes ownership of its underlying stream before any await point
//!   during a request exchange, and restores it only after a complete, valid
//!   response is received and verified. If a future is canceled or an error
//!   occurs mid-frame, the connection is irreversibly closed so a desynchronized
//!   stream is never reused.
//! * Reply correlation is validated: the reply's `request_id` must match the
//!   request's expected `request_id`.
//! * Successful replies must match the request's method variant.
//! * Legitimate typed failure replies ([`ReplyBody::Failure`]) are preserved
//!   and returned as valid responses, without retrying mutations or replacing
//!   structured server errors.
//! * All operations enforce an absolute deadline ([`tokio::time::Instant`]);
//!   expired deadlines report [`ErrorCode::ECoordinatorUnresponsive`].

use std::fmt;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{Instant, timeout_at};

use super::endpoint::{self, Outgoing};
use super::handshake;
use super::lock::LockBody;
use super::transport;
use crate::protocol::{ReplyBody, ReplyEnvelope, RequestEnvelope, decode_reply, encode_request};
use crate::{CoreError, ErrorCode, StoreId};

/// A connected, authenticated coordinator client.
pub(crate) struct Client {
    stream: Option<Outgoing>,
    store: StoreId,
}

impl Client {
    /// Connects to a published coordinator endpoint for ONE attempt.
    ///
    /// The connection and handshake are bounded by a single absolute deadline:
    /// the earlier of the caller's `deadline` and `now + 1s`. No request,
    /// session, or reconnect data is sent before handshake acceptance.
    ///
    /// Retry, ownership checks, and coordinator process startup belong to the
    /// caller (e.g. `attach`), not this client.
    ///
    /// # Errors
    /// * [`ErrorCode::ECoordinatorUnresponsive`] if the deadline expires.
    /// * [`ErrorCode::EIo`] if transport connection fails.
    /// * Handshake errors ([`ErrorCode::EForbidden`], [`ErrorCode::EVersion`], etc.)
    ///   if authentication fails.
    pub(crate) async fn connect(
        store: StoreId,
        body: &LockBody,
        deadline: Instant,
    ) -> Result<Self, CoreError> {
        let attempt_deadline = deadline.min(Instant::now() + Duration::from_secs(1));
        if Instant::now() >= attempt_deadline {
            return Err(CoreError::new(
                ErrorCode::ECoordinatorUnresponsive,
                "coordinator connect deadline expired",
            ));
        }

        let mut stream = match timeout_at(attempt_deadline, endpoint::connect(&body.address)).await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(CoreError::new(
                    ErrorCode::ECoordinatorUnresponsive,
                    "coordinator connect deadline expired",
                ));
            }
        };

        if Instant::now() >= attempt_deadline {
            return Err(CoreError::new(
                ErrorCode::ECoordinatorUnresponsive,
                "coordinator connect deadline expired",
            ));
        }

        handshake::prove_client(&mut stream, store, &body.nonce, attempt_deadline).await?;

        Ok(Self {
            stream: Some(stream),
            store,
        })
    }

    /// Sends a request and receives its correlated reply under an absolute deadline.
    ///
    /// The deadline covers both send and receive. If the request future is
    /// canceled or an I/O or framing error occurs, the stream is taken and
    /// closed irreversibly; subsequent calls on this client will fail with
    /// [`ErrorCode::ECoordinatorUnresponsive`].
    pub(crate) async fn request(
        &mut self,
        request: &RequestEnvelope,
        deadline: Instant,
    ) -> Result<ReplyEnvelope, CoreError> {
        exchange(&mut self.stream, request, deadline).await
    }

    /// Returns the store ID this client is connected to.
    #[must_use]
    pub(crate) fn store(&self) -> StoreId {
        self.store
    }

    /// Returns true if the client connection is open and ready.
    #[must_use]
    pub(crate) fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    /// Explicitly closes the connection.
    pub(crate) fn close(&mut self) {
        self.stream = None;
    }

    #[cfg(test)]
    pub(crate) fn from_stream(store: StoreId, stream: Outgoing) -> Self {
        Self {
            stream: Some(stream),
            store,
        }
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("store", &self.store)
            .field("connected", &self.stream.is_some())
            .finish()
    }
}

/// Executes a single request/reply exchange over a generic stream slot.
///
/// The stream is taken out of `stream_slot` before any await points. It is
/// restored *only* after a complete, successfully validated reply has been
/// received. Any cancellation or error leaves `stream_slot` as `None`,
/// closing the connection irreversibly so that a desynchronized stream is
/// never reused.
pub(crate) async fn exchange<S>(
    stream_slot: &mut Option<S>,
    request: &RequestEnvelope,
    deadline: Instant,
) -> Result<ReplyEnvelope, CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut stream = stream_slot.take().ok_or_else(|| {
        CoreError::new(
            ErrorCode::ECoordinatorUnresponsive,
            "coordinator connection is closed or uninitialized",
        )
    })?;

    if Instant::now() >= deadline {
        return Err(CoreError::new(
            ErrorCode::ECoordinatorUnresponsive,
            "coordinator request deadline expired",
        ));
    }

    let payload = encode_request(request)?;

    transport::write_body(&mut stream, &payload, deadline).await?;

    let length = transport::read_length(&mut stream, deadline).await?;
    let body = transport::read_body(&mut stream, length, deadline).await?;

    if Instant::now() >= deadline {
        return Err(CoreError::new(
            ErrorCode::ECoordinatorUnresponsive,
            "coordinator request deadline expired",
        ));
    }

    let reply = decode_reply(&body)?;

    // Validate request ID correlation.
    let expected_request_id = request.request.request_id();
    if reply.request_id != expected_request_id {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            format!(
                "coordinator reply request_id mismatch: expected {expected_request_id:?}, got {:?}",
                reply.request_id
            ),
        ));
    }

    // Validate method match on success replies.
    // Legitimate typed failure replies (ReplyBody::Failure) are preserved.
    if let ReplyBody::Success(success_reply) = &reply.body {
        let expected_method = request.request.method();
        let actual_method = success_reply.method();
        if actual_method != expected_method {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                format!(
                    "coordinator reply method mismatch: expected `{}`, got `{}`",
                    expected_method.as_str(),
                    actual_method.as_str()
                ),
            ));
        }
    }

    *stream_slot = Some(stream);
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncWriteExt, duplex};
    use tokio::runtime::Builder;
    use tokio::time::Instant;

    use super::*;
    use crate::MAX_CONTROL_FRAME_BYTES;
    use crate::change::RequestId;
    use crate::protocol::{
        ErrorReply, Method, MethodDescriptor, MethodKind, Mutation, OpPruneArgs, Reply, Request,
        SchemaArgs, SchemaReply, SchemaVersion, SessionOpenArgs,
    };

    fn runtime() -> tokio::runtime::Runtime {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime")
    }

    fn fixture_store() -> StoreId {
        StoreId::from_bytes([0x42; 16])
    }

    fn generous_deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn schema_request() -> RequestEnvelope {
        RequestEnvelope {
            schema_version: SchemaVersion::current(),
            session: None,
            request: Request::Schema(Box::new(SchemaArgs { method: None })),
        }
    }

    fn schema_reply() -> ReplyEnvelope {
        ReplyEnvelope::success(
            None,
            Reply::Schema(Box::new(SchemaReply {
                schema_version: SchemaVersion::current(),
                methods: vec![MethodDescriptor {
                    method: Method::Schema,
                    kind: MethodKind::Read,
                }],
                document: schemars::json_schema!(true),
            })),
        )
    }

    fn prune_request(req_id: RequestId) -> RequestEnvelope {
        RequestEnvelope {
            schema_version: SchemaVersion::current(),
            session: None,
            request: Request::OpPrune(Box::new(Mutation {
                request_id: req_id,
                args: OpPruneArgs {},
            })),
        }
    }

    fn session_open_request() -> RequestEnvelope {
        RequestEnvelope {
            schema_version: SchemaVersion::current(),
            session: None,
            request: Request::SessionOpen(Box::new(SessionOpenArgs::default())),
        }
    }

    #[test]
    fn fragmented_frames_exchange_success() {
        runtime().block_on(async {
            let (client_stream, mut server_stream) = duplex(1024);
            let mut client_slot = Some(client_stream);

            let server_task = tokio::spawn(async move {
                // Read request prefix and body.
                let req_len = transport::read_length(&mut server_stream, generous_deadline())
                    .await
                    .expect("server read req len");
                let _req_body =
                    transport::read_body(&mut server_stream, req_len, generous_deadline())
                        .await
                        .expect("server read req body");

                // Encode response.
                let reply_env = schema_reply();
                let reply_bytes = crate::protocol::encode_reply(&reply_env).expect("encode reply");

                // Write 4-byte prefix in 2 separate writes.
                let len_u32 = u32::try_from(reply_bytes.len()).expect("fits u32");
                let len_bytes = len_u32.to_be_bytes();
                server_stream
                    .write_all(&len_bytes[..1])
                    .await
                    .expect("write len 1");
                tokio::task::yield_now().await;
                server_stream
                    .write_all(&len_bytes[1..])
                    .await
                    .expect("write len 2");
                tokio::task::yield_now().await;

                // Write body in small fragments (e.g. 15 bytes each).
                for chunk in reply_bytes.chunks(15) {
                    server_stream.write_all(chunk).await.expect("write chunk");
                    tokio::task::yield_now().await;
                }
            });

            let req = schema_request();
            let result = exchange(&mut client_slot, &req, generous_deadline())
                .await
                .expect("client exchange succeeds");

            server_task.await.expect("server task finishes");

            assert_eq!(result.schema_version, SchemaVersion::current());
            assert_eq!(result.request_id, None);
            match result.body {
                ReplyBody::Success(Reply::Schema(_)) => {}
                other => panic!("expected Schema reply, got {other:?}"),
            }
            assert!(client_slot.is_some(), "stream must be restored on success");
        });
    }

    #[test]
    fn oversized_advertised_reply_rejected_before_reading_body() {
        runtime().block_on(async {
            let (client_stream, mut server_stream) = duplex(1024);
            let mut client_slot = Some(client_stream);

            let server_task = tokio::spawn(async move {
                // Read request.
                let req_len = transport::read_length(&mut server_stream, generous_deadline())
                    .await
                    .expect("server read req len");
                let _req_body =
                    transport::read_body(&mut server_stream, req_len, generous_deadline())
                        .await
                        .expect("server read req body");

                // Send advertised length > MAX_CONTROL_FRAME_BYTES.
                let max_u32 = u32::try_from(MAX_CONTROL_FRAME_BYTES).expect("fits u32");
                let oversized_len = max_u32 + 1;
                server_stream
                    .write_all(&oversized_len.to_be_bytes())
                    .await
                    .expect("write prefix");
                // Intentionally do NOT send body bytes.
            });

            let req = schema_request();
            let err = exchange(&mut client_slot, &req, generous_deadline())
                .await
                .expect_err("oversized frame must be rejected");

            server_task.await.expect("server task finishes");

            assert_eq!(err.code, ErrorCode::ELimit);
            assert!(
                client_slot.is_none(),
                "stream must be taken and dropped on error"
            );
        });
    }

    #[test]
    fn wrong_response_request_id_rejected() {
        runtime().block_on(async {
            let (client_stream, mut server_stream) = duplex(1024);
            let mut client_slot = Some(client_stream);

            let client_req_id = RequestId::from_bytes([0x11; 16]);
            let server_wrong_id = RequestId::from_bytes([0x22; 16]);

            let server_task = tokio::spawn(async move {
                let req_len = transport::read_length(&mut server_stream, generous_deadline())
                    .await
                    .expect("server read req len");
                let _req_body =
                    transport::read_body(&mut server_stream, req_len, generous_deadline())
                        .await
                        .expect("server read req body");

                // Return a failure reply with the WRONG request_id.
                let err_reply = ErrorReply {
                    code: ErrorCode::EInvalid,
                    message: "bad request".to_string(),
                    hints: Vec::new(),
                    fixes: Vec::new(),
                    detail: None,
                };
                let reply_env = ReplyEnvelope::failure(Some(server_wrong_id), err_reply);
                let reply_bytes = crate::protocol::encode_reply(&reply_env).expect("encode reply");
                transport::write_body(&mut server_stream, &reply_bytes, generous_deadline())
                    .await
                    .expect("server write reply");
            });

            let req = prune_request(client_req_id);
            let err = exchange(&mut client_slot, &req, generous_deadline())
                .await
                .expect_err("wrong request_id must be rejected");

            server_task.await.expect("server task finishes");

            assert_eq!(err.code, ErrorCode::EInvalid);
            assert!(err.message.contains("request_id mismatch"));
            assert!(
                client_slot.is_none(),
                "connection must be closed on correlation failure"
            );
        });
    }

    #[test]
    fn wrong_response_method_rejected() {
        runtime().block_on(async {
            let (client_stream, mut server_stream) = duplex(1024);
            let mut client_slot = Some(client_stream);

            let server_task = tokio::spawn(async move {
                let req_len = transport::read_length(&mut server_stream, generous_deadline())
                    .await
                    .expect("server read req len");
                let _req_body =
                    transport::read_body(&mut server_stream, req_len, generous_deadline())
                        .await
                        .expect("server read req body");

                // Client asked for session.open; server answers with Schema success reply!
                let reply_env = schema_reply();
                let reply_bytes = crate::protocol::encode_reply(&reply_env).expect("encode reply");
                transport::write_body(&mut server_stream, &reply_bytes, generous_deadline())
                    .await
                    .expect("server write reply");
            });

            let req = session_open_request();
            let err = exchange(&mut client_slot, &req, generous_deadline())
                .await
                .expect_err("mismatched method must be rejected");

            server_task.await.expect("server task finishes");

            assert_eq!(err.code, ErrorCode::EInvalid);
            assert!(err.message.contains("method mismatch"));
            assert!(
                client_slot.is_none(),
                "connection must be closed on method mismatch"
            );
        });
    }

    #[test]
    fn preserve_typed_failure_reply() {
        runtime().block_on(async {
            let (client_stream, mut server_stream) = duplex(1024);
            let mut client_slot = Some(client_stream);

            let req_id = RequestId::from_bytes([0x33; 16]);

            let server_task = tokio::spawn(async move {
                let req_len = transport::read_length(&mut server_stream, generous_deadline())
                    .await
                    .expect("server read req len");
                let _req_body =
                    transport::read_body(&mut server_stream, req_len, generous_deadline())
                        .await
                        .expect("server read req body");

                // Legitimate typed failure reply with MATCHING request_id.
                let err_reply = ErrorReply {
                    code: ErrorCode::EForbidden,
                    message: "permission denied for operation".to_string(),
                    hints: Vec::new(),
                    fixes: Vec::new(),
                    detail: None,
                };
                let reply_env = ReplyEnvelope::failure(Some(req_id), err_reply);
                let reply_bytes = crate::protocol::encode_reply(&reply_env).expect("encode reply");
                transport::write_body(&mut server_stream, &reply_bytes, generous_deadline())
                    .await
                    .expect("server write reply");
            });

            let req = prune_request(req_id);
            let result = exchange(&mut client_slot, &req, generous_deadline())
                .await
                .expect("typed failure reply is preserved as Ok(ReplyEnvelope)");

            server_task.await.expect("server task finishes");

            assert_eq!(result.request_id, Some(req_id));
            match result.body {
                ReplyBody::Failure(error) => {
                    assert_eq!(error.code, ErrorCode::EForbidden);
                    assert_eq!(error.message, "permission denied for operation");
                }
                ReplyBody::Success(_) => panic!("expected Failure reply"),
            }
            assert!(
                client_slot.is_some(),
                "stream must be restored on valid failure response"
            );
        });
    }

    #[test]
    fn absolute_deadline_covers_stalled_peer() {
        runtime().block_on(async {
            let (client_stream, mut server_stream) = duplex(1024);
            let mut client_slot = Some(client_stream);

            let server_task = tokio::spawn(async move {
                // Read request but never reply.
                let req_len = transport::read_length(&mut server_stream, generous_deadline())
                    .await
                    .expect("server read req len");
                let _req_body =
                    transport::read_body(&mut server_stream, req_len, generous_deadline())
                        .await
                        .expect("server read req body");

                // Stall until cancelled.
                tokio::time::sleep(Duration::from_secs(10)).await;
            });

            let short_deadline = Instant::now() + Duration::from_millis(50);
            let req = schema_request();
            let err = exchange(&mut client_slot, &req, short_deadline)
                .await
                .expect_err("stalled peer must hit absolute deadline");

            assert_eq!(err.code, ErrorCode::ECoordinatorUnresponsive);
            assert!(
                client_slot.is_none(),
                "stream must be dropped on deadline expiry"
            );

            server_task.abort();
        });
    }

    #[test]
    fn expired_deadline_exchange_case() {
        runtime().block_on(async {
            let (client_stream, _server_stream) = duplex(1024);
            let mut client_slot = Some(client_stream);

            let already_expired = Instant::now() - Duration::from_millis(50);
            let req = schema_request();
            let err = exchange(&mut client_slot, &req, already_expired)
                .await
                .expect_err("already expired deadline must fail immediately");

            assert_eq!(err.code, ErrorCode::ECoordinatorUnresponsive);
            assert!(
                client_slot.is_none(),
                "stream must be taken and dropped, leaving stream unusable"
            );

            // Subsequent exchange fails immediately because connection is closed.
            let err2 = exchange(&mut client_slot, &req, generous_deadline())
                .await
                .expect_err("subsequent exchange must fail on closed connection");
            assert_eq!(err2.code, ErrorCode::ECoordinatorUnresponsive);
        });
    }

    #[test]
    fn canceled_exchange_cannot_reuse_stream() {
        runtime().block_on(async {
            let (client_stream, mut server_stream) = duplex(1024);
            let mut client_slot = Some(client_stream);

            let server_task = tokio::spawn(async move {
                let req_len = transport::read_length(&mut server_stream, generous_deadline())
                    .await
                    .expect("server read req len");
                let _req_body =
                    transport::read_body(&mut server_stream, req_len, generous_deadline())
                        .await
                        .expect("server read req body");

                // Sleep to ensure client cancels while waiting for response.
                tokio::time::sleep(Duration::from_millis(200)).await;
            });

            let req = schema_request();
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(20),
                    exchange(&mut client_slot, &req, generous_deadline()),
                )
                .await
                .is_err()
            );

            // Stream must NOT be restored after mid-frame cancellation.
            assert!(
                client_slot.is_none(),
                "canceled exchange must not leave a reusable stream"
            );

            // Attempting to reuse the stream fails immediately.
            let err = exchange(&mut client_slot, &req, generous_deadline())
                .await
                .expect_err("attempting to reuse canceled client must fail");
            assert_eq!(err.code, ErrorCode::ECoordinatorUnresponsive);

            server_task.abort();
        });
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_pair_real_stream_exchange() {
        runtime().block_on(async {
            let (client_sock, mut server_sock) =
                tokio::net::UnixStream::pair().expect("unix socket pair");
            let mut client = Client::from_stream(fixture_store(), client_sock);
            assert!(client.is_connected());

            let server_task = tokio::spawn(async move {
                let req_len = transport::read_length(&mut server_sock, generous_deadline())
                    .await
                    .expect("server read req len");
                let _req_body =
                    transport::read_body(&mut server_sock, req_len, generous_deadline())
                        .await
                        .expect("server read req body");

                let reply_env = schema_reply();
                let reply_bytes = crate::protocol::encode_reply(&reply_env).expect("encode reply");
                transport::write_body(&mut server_sock, &reply_bytes, generous_deadline())
                    .await
                    .expect("server write reply");
                server_sock
            });

            let req = schema_request();
            let result = client
                .request(&req, generous_deadline())
                .await
                .expect("unix socket pair request succeeds");

            let _held_server = server_task.await.expect("server task completes");

            assert_eq!(result.schema_version, SchemaVersion::current());
            assert!(
                client.is_connected(),
                "client must remain connected after success"
            );

            assert!(
                tokio::time::timeout(
                    Duration::from_millis(20),
                    client.request(&req, generous_deadline()),
                )
                .await
                .is_err()
            );

            assert!(
                !client.is_connected(),
                "client must be disconnected after cancellation"
            );
            let err = client
                .request(&req, generous_deadline())
                .await
                .expect_err("client must refuse new requests after cancellation");
            assert_eq!(err.code, ErrorCode::ECoordinatorUnresponsive);
        });
    }

    #[test]
    fn connect_expired_deadline_fails() {
        runtime().block_on(async {
            let lock_body = LockBody {
                pid: 1234,
                address: crate::coord::lock::EndpointAddress::Unix(std::path::PathBuf::from(
                    "/tmp/nonexistent",
                )),
                nonce: crate::coord::lock::EndpointNonce::generate().expect("nonce"),
            };
            let expired = Instant::now() - Duration::from_millis(100);
            let err = Client::connect(fixture_store(), &lock_body, expired)
                .await
                .expect_err("connect with expired deadline must fail");
            assert_eq!(err.code, ErrorCode::ECoordinatorUnresponsive);
        });
    }
}
