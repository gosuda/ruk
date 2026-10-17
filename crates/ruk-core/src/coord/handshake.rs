//! Coordinator endpoint handshake: server-proves-first HMAC-SHA-256
//! authentication of the store nonce over an already-connected stream.
//!
//! Four fixed frames are exchanged on one connection: the client hello
//! (C1), the server proof (S1), the client proof (C2), and the verdict
//! (S2). Every framed message opens with a magic, a protocol version, and
//! reserved zero bytes; any deviation is a typed error:
//!
//! ```text
//! C1: RUKC | version | 3 reserved | 32-byte client challenge
//! S1: RUKS | version | status    | 2 reserved | server challenge | server tag
//! C2: the 32-byte client tag
//! S2: RUKA | version | status    | 2 reserved
//! ```
//!
//! Tags are HMAC-SHA-256 under the endpoint nonce, domain-separated per
//! side and bound to the 16 raw store-id bytes plus both challenges.
//! Verification goes through the constant-time [`hmac::Mac::verify_slice`]
//! API. The client never sends its tag, or any later session secret,
//! before the server proof verifies and the verdict accepts. One absolute
//! [`tokio::time::Instant`] deadline covers every read and write of an
//! attempt; this module never retries and never sleeps. Principal identity
//! comes from OS credentials outside this module: the handshake proves
//! knowledge of the nonce from the current lock body only, and is not a
//! sandbox against same-user processes with that filesystem authority.
//!
//! Cancelling a proof future mid-frame leaves the stream in an unknown
//! state; callers discard the connection instead of reusing it.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

use super::lock::EndpointNonce;
use crate::{CoreError, ErrorCode, StoreId};

/// HMAC-SHA-256 instance used for both endpoint proof directions.
type EndpointMac = Hmac<Sha256>;

/// Width of every frame magic, in bytes.
const MAGIC_LEN: usize = 4;
/// Exact magic of the client hello (C1).
const CLIENT_HELLO_MAGIC: [u8; MAGIC_LEN] = *b"RUKC";
/// Exact magic of the server proof (S1).
const SERVER_PROOF_MAGIC: [u8; MAGIC_LEN] = *b"RUKS";
/// Exact magic of the final verdict (S2).
const VERDICT_MAGIC: [u8; MAGIC_LEN] = *b"RUKA";

/// Wire position of the one-byte protocol version.
const VERSION_POS: usize = MAGIC_LEN;
/// Wire position of the one-byte status in S1 and S2. C1 holds a reserved
/// byte here instead.
const STATUS_POS: usize = MAGIC_LEN + 1;
/// First of the two reserved bytes that close the S1 and S2 headers.
const RESERVED_START: usize = STATUS_POS + 1;
/// Fixed header width: magic, version, and three bytes that are reserved in
/// C1 or hold the status and two reserved bytes in S1 and S2.
const HEADER_LEN: usize = 8;

/// The only protocol version this build speaks.
const PROTOCOL_VERSION: u8 = 1;
/// Status of an S1 or S2 that continues or accepts the peer.
const STATUS_OK: u8 = 0;
/// Status of an S2 that refuses the authenticated peer.
const STATUS_FORBIDDEN: u8 = 1;

/// Challenge width, in bytes.
const CHALLENGE_LEN: usize = 32;
/// HMAC-SHA-256 tag width, in bytes.
const TAG_LEN: usize = 32;
/// C1: header, then the client challenge.
const C1_LEN: usize = HEADER_LEN + CHALLENGE_LEN;
/// Start of the S1 tag: header, then the server challenge.
const SERVER_TAG_START: usize = HEADER_LEN + CHALLENGE_LEN;
/// S1: header, then the server challenge and the server tag.
const S1_LEN: usize = SERVER_TAG_START + TAG_LEN;
/// C2: the bare client tag.
const C2_LEN: usize = TAG_LEN;
/// S2: header only.
const S2_LEN: usize = HEADER_LEN;

/// Domain-separation prefix of the server proof tag.
const SERVER_DOMAIN: &[u8] = b"ruk-endpoint-v1\0server\0";
/// Domain-separation prefix of the client proof tag.
const CLIENT_DOMAIN: &[u8] = b"ruk-endpoint-v1\0client\0";

/// Client side of the endpoint handshake.
///
/// Sends C1, verifies the server proof in S1, only then sends the client tag
/// as C2, and finally validates the S2 verdict. `deadline` is the single
/// absolute deadline for every read and write. The caller must not send any
/// session or reconnect secret before this returns `Ok`.
///
/// # Errors
///
/// Framing and version violations are [`ErrorCode::EInvalid`] and
/// [`ErrorCode::EVersion`]; a rejected server proof or a forbidden verdict is
/// [`ErrorCode::EForbidden`]; deadline expiry is
/// [`ErrorCode::ECoordinatorUnresponsive`]; I/O and entropy failures are
/// [`ErrorCode::EIo`].
pub(crate) async fn prove_client<S>(
    stream: &mut S,
    store_id: StoreId,
    nonce: &EndpointNonce,
    deadline: Instant,
) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_challenge = [0u8; CHALLENGE_LEN];
    fill_challenge(&mut client_challenge)?;
    write_frame(stream, &client_hello(&client_challenge), deadline).await?;

    let mut s1 = [0u8; S1_LEN];
    read_frame(stream, &mut s1, deadline).await?;
    let (server_challenge, server_tag) = check_server_proof(&s1)?;

    // The server must prove nonce knowledge before the client reveals its
    // own tag; a rejected proof ends the attempt with no further bytes.
    transcript_mac(
        SERVER_DOMAIN,
        nonce,
        &store_id,
        &client_challenge,
        &server_challenge,
    )?
    .verify_slice(&server_tag)
    .map_err(|_| forbidden_error("server proof rejected"))?;

    let client_tag = tag_of(transcript_mac(
        CLIENT_DOMAIN,
        nonce,
        &store_id,
        &client_challenge,
        &server_challenge,
    )?);
    write_frame(stream, &client_tag, deadline).await?;

    let mut s2 = [0u8; S2_LEN];
    read_frame(stream, &mut s2, deadline).await?;
    check_verdict(&s2)
}

/// Server side of the endpoint handshake.
///
/// Reads C1, proves nonce knowledge with S1, and verifies the client tag in
/// C2. Returns only after the client proof succeeds. The caller then derives
/// the OS principal, checks policy, and sends the verdict with
/// [`accept_client`] or [`reject_client`] under the same deadline.
///
/// # Errors
///
/// Same mapping as [`prove_client`]. A rejected client proof is
/// [`ErrorCode::EForbidden`], and no verdict is sent.
pub(crate) async fn prove_server<S>(
    stream: &mut S,
    store_id: StoreId,
    nonce: &EndpointNonce,
    deadline: Instant,
) -> Result<(), CoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut c1 = [0u8; C1_LEN];
    read_frame(stream, &mut c1, deadline).await?;
    let client_challenge = check_client_hello(&c1)?;

    let mut server_challenge = [0u8; CHALLENGE_LEN];
    fill_challenge(&mut server_challenge)?;
    let s1 = server_proof_frame(nonce, &store_id, &client_challenge, &server_challenge)?;
    write_frame(stream, &s1, deadline).await?;

    let mut client_tag = [0u8; C2_LEN];
    read_frame(stream, &mut client_tag, deadline).await?;
    transcript_mac(
        CLIENT_DOMAIN,
        nonce,
        &store_id,
        &client_challenge,
        &server_challenge,
    )?
    .verify_slice(&client_tag)
    .map_err(|_| forbidden_error("client proof rejected"))
}

/// Sends the accepting verdict (S2 with status 0) within `deadline`.
///
/// # Errors
///
/// Deadline expiry is [`ErrorCode::ECoordinatorUnresponsive`]; I/O failures
/// are [`ErrorCode::EIo`].
pub(crate) async fn accept_client<S>(stream: &mut S, deadline: Instant) -> Result<(), CoreError>
where
    S: AsyncWrite + Unpin,
{
    write_frame(stream, &verdict_frame(STATUS_OK), deadline).await
}

/// Sends the refusing verdict (S2 with status 1) within `deadline`.
///
/// # Errors
///
/// Same mapping as [`accept_client`].
pub(crate) async fn reject_client<S>(stream: &mut S, deadline: Instant) -> Result<(), CoreError>
where
    S: AsyncWrite + Unpin,
{
    write_frame(stream, &verdict_frame(STATUS_FORBIDDEN), deadline).await
}

/// Builds the client hello (C1) around a fresh challenge.
fn client_hello(client_challenge: &[u8; CHALLENGE_LEN]) -> [u8; C1_LEN] {
    let mut frame = [0u8; C1_LEN];
    frame[..MAGIC_LEN].copy_from_slice(&CLIENT_HELLO_MAGIC);
    frame[VERSION_POS] = PROTOCOL_VERSION;
    // Bytes VERSION_POS + 1..HEADER_LEN stay zero: reserved.
    frame[HEADER_LEN..].copy_from_slice(client_challenge);
    frame
}

/// Builds the server proof (S1) with its domain-bound HMAC tag.
fn server_proof_frame(
    nonce: &EndpointNonce,
    store_id: &StoreId,
    client_challenge: &[u8; CHALLENGE_LEN],
    server_challenge: &[u8; CHALLENGE_LEN],
) -> Result<[u8; S1_LEN], CoreError> {
    let mut frame = [0u8; S1_LEN];
    frame[..MAGIC_LEN].copy_from_slice(&SERVER_PROOF_MAGIC);
    frame[VERSION_POS] = PROTOCOL_VERSION;
    frame[STATUS_POS] = STATUS_OK;
    // Reserved bytes stay zero.
    frame[HEADER_LEN..SERVER_TAG_START].copy_from_slice(server_challenge);
    let tag = tag_of(transcript_mac(
        SERVER_DOMAIN,
        nonce,
        store_id,
        client_challenge,
        server_challenge,
    )?);
    frame[SERVER_TAG_START..].copy_from_slice(&tag);
    Ok(frame)
}

/// Builds the final verdict (S2) for one status value.
fn verdict_frame(status: u8) -> [u8; S2_LEN] {
    let mut frame = [0u8; S2_LEN];
    frame[..MAGIC_LEN].copy_from_slice(&VERDICT_MAGIC);
    frame[VERSION_POS] = PROTOCOL_VERSION;
    frame[STATUS_POS] = status;
    frame
}

/// Validates the C1 header and returns the client challenge.
fn check_client_hello(frame: &[u8; C1_LEN]) -> Result<[u8; CHALLENGE_LEN], CoreError> {
    check_magic(&frame[..MAGIC_LEN], &CLIENT_HELLO_MAGIC)?;
    check_version(frame[VERSION_POS])?;
    check_reserved(&frame[VERSION_POS + 1..HEADER_LEN])?;
    let mut client_challenge = [0u8; CHALLENGE_LEN];
    client_challenge.copy_from_slice(&frame[HEADER_LEN..]);
    Ok(client_challenge)
}

/// Validates the S1 header and returns the server challenge and tag.
fn check_server_proof(
    frame: &[u8; S1_LEN],
) -> Result<([u8; CHALLENGE_LEN], [u8; TAG_LEN]), CoreError> {
    check_magic(&frame[..MAGIC_LEN], &SERVER_PROOF_MAGIC)?;
    check_version(frame[VERSION_POS])?;
    if frame[STATUS_POS] != STATUS_OK {
        return Err(invalid_frame("server proof status"));
    }
    check_reserved(&frame[RESERVED_START..HEADER_LEN])?;
    let mut server_challenge = [0u8; CHALLENGE_LEN];
    server_challenge.copy_from_slice(&frame[HEADER_LEN..SERVER_TAG_START]);
    let mut server_tag = [0u8; TAG_LEN];
    server_tag.copy_from_slice(&frame[SERVER_TAG_START..]);
    Ok((server_challenge, server_tag))
}

/// Validates the S2 verdict, mapping the forbidden status to its error.
fn check_verdict(frame: &[u8; S2_LEN]) -> Result<(), CoreError> {
    check_magic(&frame[..MAGIC_LEN], &VERDICT_MAGIC)?;
    check_version(frame[VERSION_POS])?;
    match frame[STATUS_POS] {
        STATUS_OK => {}
        STATUS_FORBIDDEN => return Err(forbidden_error("endpoint access denied")),
        _ => return Err(invalid_frame("verdict status")),
    }
    check_reserved(&frame[RESERVED_START..HEADER_LEN])
}

/// Keys a fresh HMAC under the endpoint nonce.
fn endpoint_mac(nonce: &EndpointNonce) -> Result<EndpointMac, CoreError> {
    EndpointMac::new_from_slice(nonce.as_bytes())
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("endpoint handshake key: {err}")))
}

/// Builds the domain-bound MAC over one proof transcript. The caller either
/// finalizes it into a tag or verifies a received tag with
/// [`Mac::verify_slice`].
fn transcript_mac(
    domain: &[u8],
    nonce: &EndpointNonce,
    store_id: &StoreId,
    client_challenge: &[u8; CHALLENGE_LEN],
    server_challenge: &[u8; CHALLENGE_LEN],
) -> Result<EndpointMac, CoreError> {
    let mut mac = endpoint_mac(nonce)?;
    mac.update(domain);
    mac.update(store_id.as_bytes());
    mac.update(client_challenge);
    mac.update(server_challenge);
    Ok(mac)
}

/// The 32-byte tag of a fully updated MAC.
fn tag_of(mac: EndpointMac) -> [u8; TAG_LEN] {
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(mac.finalize().into_bytes().as_slice());
    tag
}

/// Draws one challenge from the OS generator.
fn fill_challenge(challenge: &mut [u8; CHALLENGE_LEN]) -> Result<(), CoreError> {
    getrandom::fill(challenge)
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("endpoint handshake entropy: {err}")))
}

/// One framed write plus flush under the single absolute deadline.
async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), CoreError> {
    timeout_at(deadline, stream.write_all(frame))
        .await
        .map_err(|_| deadline_error())?
        .map_err(|err| io_error("write", err))?;
    timeout_at(deadline, stream.flush())
        .await
        .map_err(|_| deadline_error())?
        .map_err(|err| io_error("flush", err))
}

/// One exact-length framed read under the single absolute deadline.
async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    frame: &mut [u8],
    deadline: Instant,
) -> Result<(), CoreError> {
    timeout_at(deadline, stream.read_exact(frame))
        .await
        .map_err(|_| deadline_error())?
        .map_err(|err| io_error("read", err))?;
    Ok(())
}

fn check_magic(found: &[u8], expected: &[u8; MAGIC_LEN]) -> Result<(), CoreError> {
    if found != expected.as_slice() {
        return Err(invalid_frame("magic"));
    }
    Ok(())
}

fn check_version(found: u8) -> Result<(), CoreError> {
    if found != PROTOCOL_VERSION {
        return Err(CoreError::new(
            ErrorCode::EVersion,
            "endpoint handshake: unsupported protocol version",
        ));
    }
    Ok(())
}

fn check_reserved(reserved: &[u8]) -> Result<(), CoreError> {
    if reserved.iter().any(|&byte| byte != 0) {
        return Err(invalid_frame("reserved bytes"));
    }
    Ok(())
}

fn invalid_frame(what: &'static str) -> CoreError {
    CoreError::new(
        ErrorCode::EInvalid,
        format!("endpoint handshake: invalid {what}"),
    )
}

fn forbidden_error(what: &'static str) -> CoreError {
    CoreError::new(ErrorCode::EForbidden, format!("endpoint handshake: {what}"))
}

fn deadline_error() -> CoreError {
    CoreError::new(
        ErrorCode::ECoordinatorUnresponsive,
        "endpoint handshake deadline expired",
    )
}

/// I/O failures carry the error kind only: no nonce, challenge, or payload
/// bytes ever enter an error message.
fn io_error(op: &'static str, err: std::io::Error) -> CoreError {
    let kind = err.kind();
    CoreError::new(ErrorCode::EIo, format!("endpoint handshake {op}: {kind}"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
    use tokio::runtime::Builder;
    use tokio::time::Instant;

    use super::*;

    /// Drives one scenario on a fresh current-thread runtime. Manual builders
    /// keep the crate free of the Tokio macros feature.
    fn run(scenario: impl Future<Output = ()>) {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime")
            .block_on(scenario);
    }

    fn fixture_store() -> StoreId {
        StoreId::from_bytes([0x5A; 16])
    }

    fn other_store() -> StoreId {
        StoreId::from_bytes([0xA5; 16])
    }

    fn fresh_nonce() -> EndpointNonce {
        EndpointNonce::generate().expect("nonce entropy")
    }

    fn random_challenge() -> [u8; CHALLENGE_LEN] {
        let mut challenge = [0u8; CHALLENGE_LEN];
        getrandom::fill(&mut challenge).expect("challenge entropy");
        challenge
    }

    fn generous_deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn short_deadline() -> Instant {
        Instant::now() + Duration::from_millis(50)
    }

    /// Reads C1 from a peer and returns the client challenge it carries.
    async fn read_hello(
        stream: &mut DuplexStream,
        deadline: Instant,
    ) -> Result<[u8; CHALLENGE_LEN], CoreError> {
        let mut c1 = [0u8; C1_LEN];
        read_frame(stream, &mut c1, deadline).await?;
        check_client_hello(&c1)
    }

    /// Scripted server: completes the proof, then accepts the peer.
    async fn serve_accept(
        mut stream: DuplexStream,
        store: StoreId,
        nonce: EndpointNonce,
        deadline: Instant,
    ) -> Result<(), CoreError> {
        prove_server(&mut stream, store, &nonce, deadline).await?;
        accept_client(&mut stream, deadline).await
    }

    /// Scripted server: completes the proof, then refuses the peer.
    async fn serve_reject(
        mut stream: DuplexStream,
        store: StoreId,
        nonce: EndpointNonce,
        deadline: Instant,
    ) -> Result<(), CoreError> {
        prove_server(&mut stream, store, &nonce, deadline).await?;
        reject_client(&mut stream, deadline).await
    }

    /// Scripted server: answers C1 with an S1 whose bytes `mutate` altered.
    async fn send_mutated_s1(
        mut stream: DuplexStream,
        nonce: EndpointNonce,
        store: StoreId,
        mutate: fn(&mut [u8; S1_LEN]),
        deadline: Instant,
    ) -> Result<(), CoreError> {
        let client_challenge = read_hello(&mut stream, deadline).await?;
        let mut frame = server_proof_frame(&nonce, &store, &client_challenge, &random_challenge())?;
        mutate(&mut frame);
        write_frame(&mut stream, &frame, deadline).await
    }

    /// Scripted server: answers C1 with an S1 bound to a challenge the client
    /// never sent, which is what a replayed proof looks like on the wire.
    async fn send_stale_s1(
        mut stream: DuplexStream,
        nonce: EndpointNonce,
        store: StoreId,
        deadline: Instant,
    ) -> Result<(), CoreError> {
        read_hello(&mut stream, deadline).await?;
        let stale_challenge = random_challenge();
        let frame = server_proof_frame(&nonce, &store, &stale_challenge, &random_challenge())?;
        write_frame(&mut stream, &frame, deadline).await
    }

    /// Scripted server: sends an S1 with a corrupted tag, then checks that the
    /// client wrote nothing after its hello.
    async fn send_bad_tag_then_probe(
        mut stream: DuplexStream,
        nonce: EndpointNonce,
        store: StoreId,
        deadline: Instant,
    ) -> Result<(), CoreError> {
        let client_challenge = read_hello(&mut stream, deadline).await?;
        let mut frame = server_proof_frame(&nonce, &store, &client_challenge, &random_challenge())?;
        frame[S1_LEN - 1] ^= 0x01;
        write_frame(&mut stream, &frame, deadline).await?;
        let mut probe = [0u8; 1];
        let received = timeout_at(deadline, stream.read(&mut probe))
            .await
            .map_err(|_| deadline_error())?
            .map_err(|err| io_error("probe", err))?;
        if received != 0 {
            return Err(CoreError::new(
                ErrorCode::EInvalid,
                "client sent bytes after a failed server proof",
            ));
        }
        Ok(())
    }

    /// Scripted server: sends S1 missing its final byte, then closes.
    async fn send_truncated_s1(
        mut stream: DuplexStream,
        nonce: EndpointNonce,
        store: StoreId,
        deadline: Instant,
    ) -> Result<(), CoreError> {
        let client_challenge = read_hello(&mut stream, deadline).await?;
        let frame = server_proof_frame(&nonce, &store, &client_challenge, &random_challenge())?;
        write_frame(&mut stream, &frame[..S1_LEN - 1], deadline).await
    }

    /// Scripted server: completes S1 and reads C2, then sends `verdict`, or
    /// closes the stream when `verdict` is `None`.
    async fn send_s1_then_verdict(
        mut stream: DuplexStream,
        nonce: EndpointNonce,
        store: StoreId,
        verdict: Option<[u8; S2_LEN]>,
        deadline: Instant,
    ) -> Result<(), CoreError> {
        let client_challenge = read_hello(&mut stream, deadline).await?;
        let frame = server_proof_frame(&nonce, &store, &client_challenge, &random_challenge())?;
        write_frame(&mut stream, &frame, deadline).await?;
        let mut client_tag = [0u8; C2_LEN];
        read_frame(&mut stream, &mut client_tag, deadline).await?;
        match verdict {
            Some(bytes) => write_frame(&mut stream, &bytes, deadline).await,
            None => Ok(()),
        }
    }

    /// Scripted client: answers S1 with a C2 tag computed under `key`
    /// instead of the store nonce.
    async fn send_client_tag_under(
        mut stream: DuplexStream,
        store: StoreId,
        key: EndpointNonce,
        deadline: Instant,
    ) -> Result<(), CoreError> {
        let client_challenge = random_challenge();
        write_frame(&mut stream, &client_hello(&client_challenge), deadline).await?;
        let mut s1 = [0u8; S1_LEN];
        read_frame(&mut stream, &mut s1, deadline).await?;
        let (server_challenge, _) = check_server_proof(&s1)?;
        let tag = tag_of(transcript_mac(
            CLIENT_DOMAIN,
            &key,
            &store,
            &client_challenge,
            &server_challenge,
        )?);
        write_frame(&mut stream, &tag, deadline).await
    }

    /// Scripted client: answers S1 with a C2 tag recorded from another
    /// transcript.
    async fn send_replayed_tag(
        mut stream: DuplexStream,
        recorded: [u8; TAG_LEN],
        deadline: Instant,
    ) -> Result<(), CoreError> {
        write_frame(&mut stream, &client_hello(&random_challenge()), deadline).await?;
        let mut s1 = [0u8; S1_LEN];
        read_frame(&mut stream, &mut s1, deadline).await?;
        write_frame(&mut stream, &recorded, deadline).await
    }

    /// One S1 mutation case: the client must refuse it with `expected`.
    async fn refuse_mutated_s1(
        name: &'static str,
        mutate: fn(&mut [u8; S1_LEN]),
        expected: ErrorCode,
    ) {
        let (mut client, server) = duplex(256);
        let store = fixture_store();
        let key = fresh_nonce();
        let deadline = generous_deadline();
        let peer = tokio::spawn(send_mutated_s1(
            server,
            key.clone(),
            store,
            mutate,
            deadline,
        ));
        let result = prove_client(&mut client, store, &key, deadline).await;
        assert_eq!(result.expect_err(name).code, expected, "case {name}");
        drop(client);
        peer.await.expect("peer task").expect("scripted peer");
    }

    /// One S2 mutation case: the client must refuse it with `expected`.
    async fn refuse_mutated_s2(
        name: &'static str,
        mutate: fn(&mut [u8; S2_LEN]),
        expected: ErrorCode,
    ) {
        let (mut client, server) = duplex(256);
        let store = fixture_store();
        let key = fresh_nonce();
        let deadline = generous_deadline();
        let mut verdict = verdict_frame(STATUS_OK);
        mutate(&mut verdict);
        let peer = tokio::spawn(send_s1_then_verdict(
            server,
            key.clone(),
            store,
            Some(verdict),
            deadline,
        ));
        let result = prove_client(&mut client, store, &key, deadline).await;
        assert_eq!(result.expect_err(name).code, expected, "case {name}");
        drop(client);
        peer.await.expect("peer task").expect("scripted peer");
    }

    /// One C1 mutation case: the server must refuse it with `expected`.
    async fn refuse_mutated_c1(
        name: &'static str,
        mutate: fn(&mut [u8; C1_LEN]),
        expected: ErrorCode,
    ) {
        let (mut client, mut server) = duplex(256);
        let mut hello = client_hello(&random_challenge());
        mutate(&mut hello);
        client.write_all(&hello).await.expect("write hello");
        let result = prove_server(
            &mut server,
            fixture_store(),
            &fresh_nonce(),
            generous_deadline(),
        )
        .await;
        assert_eq!(result.expect_err(name).code, expected, "case {name}");
    }

    #[test]
    fn accepted_exchange_completes_on_both_sides() {
        run(async {
            let (mut client, server) = duplex(256);
            let store = fixture_store();
            let key = fresh_nonce();
            let deadline = generous_deadline();
            let peer = tokio::spawn(serve_accept(server, store, key.clone(), deadline));
            let client_result = prove_client(&mut client, store, &key, deadline).await;
            assert!(client_result.is_ok(), "client refused: {client_result:?}");
            let server_result = peer.await.expect("server task");
            assert!(server_result.is_ok(), "server failed: {server_result:?}");
        });
    }

    #[test]
    fn rejected_peer_is_refused_by_client() {
        run(async {
            let (mut client, server) = duplex(256);
            let store = fixture_store();
            let key = fresh_nonce();
            let deadline = generous_deadline();
            let peer = tokio::spawn(serve_reject(server, store, key.clone(), deadline));
            let result = prove_client(&mut client, store, &key, deadline).await;
            assert_eq!(
                result.expect_err("refused peer").code,
                ErrorCode::EForbidden
            );
            peer.await.expect("server task").expect("refusal sent");
        });
    }

    #[test]
    fn wrong_nonce_is_refused_and_no_client_proof_arrives() {
        run(async {
            let (mut client, server) = duplex(256);
            let store = fixture_store();
            let client_key = fresh_nonce();
            let deadline = generous_deadline();
            let peer = tokio::spawn(serve_accept(server, store, fresh_nonce(), deadline));
            let result = prove_client(&mut client, store, &client_key, deadline).await;
            assert_eq!(result.expect_err("wrong nonce").code, ErrorCode::EForbidden);
            drop(client);
            let peer_result = peer.await.expect("server task");
            assert_eq!(
                peer_result.expect_err("no client proof").code,
                ErrorCode::EIo
            );
        });
    }

    #[test]
    fn wrong_store_id_is_refused_and_no_client_proof_arrives() {
        run(async {
            let (mut client, server) = duplex(256);
            let key = fresh_nonce();
            let deadline = generous_deadline();
            let peer = tokio::spawn(serve_accept(server, fixture_store(), key.clone(), deadline));
            let result = prove_client(&mut client, other_store(), &key, deadline).await;
            assert_eq!(result.expect_err("wrong store").code, ErrorCode::EForbidden);
            drop(client);
            let peer_result = peer.await.expect("server task");
            assert_eq!(
                peer_result.expect_err("no client proof").code,
                ErrorCode::EIo
            );
        });
    }

    #[test]
    fn client_tag_under_foreign_key_is_refused_by_server() {
        run(async {
            let (client, mut server) = duplex(256);
            let store = fixture_store();
            let key = fresh_nonce();
            let deadline = generous_deadline();
            let forger = tokio::spawn(send_client_tag_under(
                client,
                store,
                fresh_nonce(),
                deadline,
            ));
            let result = prove_server(&mut server, store, &key, deadline).await;
            assert_eq!(result.expect_err("foreign tag").code, ErrorCode::EForbidden);
            forger.await.expect("forger task").expect("forger frames");
        });
    }

    #[test]
    fn replayed_client_tag_from_another_transcript_is_refused() {
        run(async {
            let (client, mut server) = duplex(256);
            let store = fixture_store();
            let key = fresh_nonce();
            let deadline = generous_deadline();
            let recorded = transcript_mac(
                CLIENT_DOMAIN,
                &key,
                &store,
                &random_challenge(),
                &random_challenge(),
            )
            .map(tag_of)
            .expect("recorded transcript");
            let replayer = tokio::spawn(send_replayed_tag(client, recorded, deadline));
            let result = prove_server(&mut server, store, &key, deadline).await;
            assert_eq!(
                result.expect_err("replayed tag").code,
                ErrorCode::EForbidden
            );
            replayer
                .await
                .expect("replayer task")
                .expect("replayer frames");
        });
    }

    #[test]
    fn stale_server_proof_is_refused_by_client() {
        run(async {
            let (mut client, server) = duplex(256);
            let store = fixture_store();
            let key = fresh_nonce();
            let deadline = generous_deadline();
            let peer = tokio::spawn(send_stale_s1(server, key.clone(), store, deadline));
            let result = prove_client(&mut client, store, &key, deadline).await;
            assert_eq!(result.expect_err("stale proof").code, ErrorCode::EForbidden);
            drop(client);
            peer.await.expect("peer task").expect("scripted peer");
        });
    }

    #[test]
    fn failed_server_proof_keeps_client_silent() {
        run(async {
            let (mut client, server) = duplex(256);
            let store = fixture_store();
            let key = fresh_nonce();
            let deadline = generous_deadline();
            let peer = tokio::spawn(send_bad_tag_then_probe(
                server,
                key.clone(),
                store,
                deadline,
            ));
            let result = prove_client(&mut client, store, &key, deadline).await;
            assert_eq!(
                result.expect_err("bad server tag").code,
                ErrorCode::EForbidden
            );
            drop(client);
            peer.await
                .expect("peer task")
                .expect("client wrote nothing after the failed proof");
        });
    }

    #[test]
    fn malformed_server_proof_is_refused_by_client() {
        let cases: [(&'static str, fn(&mut [u8; S1_LEN]), ErrorCode); 5] = [
            (
                "magic",
                |frame: &mut [u8; S1_LEN]| frame[0] ^= 0xff,
                ErrorCode::EInvalid,
            ),
            (
                "version",
                |frame: &mut [u8; S1_LEN]| frame[VERSION_POS] = PROTOCOL_VERSION.wrapping_add(1),
                ErrorCode::EVersion,
            ),
            (
                "status",
                |frame: &mut [u8; S1_LEN]| frame[STATUS_POS] = STATUS_FORBIDDEN,
                ErrorCode::EInvalid,
            ),
            (
                "reserved",
                |frame: &mut [u8; S1_LEN]| frame[RESERVED_START] = 0x01,
                ErrorCode::EInvalid,
            ),
            (
                "tag",
                |frame: &mut [u8; S1_LEN]| frame[S1_LEN - 1] ^= 0x01,
                ErrorCode::EForbidden,
            ),
        ];
        for (name, mutate, expected) in cases {
            run(refuse_mutated_s1(name, mutate, expected));
        }
    }

    #[test]
    fn truncated_server_proof_is_an_io_failure() {
        run(async {
            let (mut client, server) = duplex(256);
            let store = fixture_store();
            let key = fresh_nonce();
            let deadline = generous_deadline();
            let peer = tokio::spawn(send_truncated_s1(server, key.clone(), store, deadline));
            let result = prove_client(&mut client, store, &key, deadline).await;
            assert_eq!(result.expect_err("truncated proof").code, ErrorCode::EIo);
            peer.await.expect("peer task").expect("scripted peer");
        });
    }

    #[test]
    fn malformed_verdict_is_refused_by_client() {
        let cases: [(&'static str, fn(&mut [u8; S2_LEN]), ErrorCode); 5] = [
            (
                "magic",
                |frame: &mut [u8; S2_LEN]| frame[0] ^= 0xff,
                ErrorCode::EInvalid,
            ),
            (
                "version",
                |frame: &mut [u8; S2_LEN]| frame[VERSION_POS] = PROTOCOL_VERSION.wrapping_add(1),
                ErrorCode::EVersion,
            ),
            (
                "forbidden",
                |frame: &mut [u8; S2_LEN]| frame[STATUS_POS] = STATUS_FORBIDDEN,
                ErrorCode::EForbidden,
            ),
            (
                "unknown status",
                |frame: &mut [u8; S2_LEN]| frame[STATUS_POS] = 0x02,
                ErrorCode::EInvalid,
            ),
            (
                "reserved",
                |frame: &mut [u8; S2_LEN]| frame[RESERVED_START] = 0x01,
                ErrorCode::EInvalid,
            ),
        ];
        for (name, mutate, expected) in cases {
            run(refuse_mutated_s2(name, mutate, expected));
        }
    }

    #[test]
    fn server_closing_before_verdict_is_an_io_failure() {
        run(async {
            let (mut client, server) = duplex(256);
            let store = fixture_store();
            let key = fresh_nonce();
            let deadline = generous_deadline();
            let peer = tokio::spawn(send_s1_then_verdict(
                server,
                key.clone(),
                store,
                None,
                deadline,
            ));
            let result = prove_client(&mut client, store, &key, deadline).await;
            assert_eq!(result.expect_err("no verdict").code, ErrorCode::EIo);
            peer.await.expect("peer task").expect("scripted peer");
        });
    }

    #[test]
    fn malformed_client_hello_is_refused_by_server() {
        let cases: [(&'static str, fn(&mut [u8; C1_LEN]), ErrorCode); 4] = [
            (
                "magic",
                |frame: &mut [u8; C1_LEN]| frame[0] ^= 0xff,
                ErrorCode::EInvalid,
            ),
            (
                "version",
                |frame: &mut [u8; C1_LEN]| frame[VERSION_POS] = PROTOCOL_VERSION.wrapping_add(1),
                ErrorCode::EVersion,
            ),
            (
                "reserved",
                |frame: &mut [u8; C1_LEN]| frame[VERSION_POS + 1] = 0x01,
                ErrorCode::EInvalid,
            ),
            (
                "last reserved",
                |frame: &mut [u8; C1_LEN]| frame[HEADER_LEN - 1] = 0x01,
                ErrorCode::EInvalid,
            ),
        ];
        for (name, mutate, expected) in cases {
            run(refuse_mutated_c1(name, mutate, expected));
        }
    }

    #[test]
    fn truncated_client_hello_is_an_io_failure() {
        run(async {
            let (mut client, mut server) = duplex(256);
            let hello = client_hello(&random_challenge());
            client
                .write_all(&hello[..C1_LEN - 1])
                .await
                .expect("write partial hello");
            drop(client);
            let result = prove_server(
                &mut server,
                fixture_store(),
                &fresh_nonce(),
                generous_deadline(),
            )
            .await;
            assert_eq!(result.expect_err("truncated hello").code, ErrorCode::EIo);
        });
    }

    #[test]
    fn silent_server_hits_client_deadline() {
        run(async {
            let (mut client, _silent_server) = duplex(256);
            let key = fresh_nonce();
            let result = prove_client(&mut client, fixture_store(), &key, short_deadline()).await;
            assert_eq!(
                result.expect_err("silent server").code,
                ErrorCode::ECoordinatorUnresponsive
            );
        });
    }

    #[test]
    fn silent_client_hits_server_deadline() {
        run(async {
            let (mut client, mut server) = duplex(256);
            let key = fresh_nonce();
            client
                .write_all(&client_hello(&random_challenge()))
                .await
                .expect("write hello");
            let result = prove_server(&mut server, fixture_store(), &key, short_deadline()).await;
            assert_eq!(
                result.expect_err("silent client").code,
                ErrorCode::ECoordinatorUnresponsive
            );
            drop(client);
        });
    }
}
