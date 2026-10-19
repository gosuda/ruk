//! IPC framing, directional credit windows, and the stream-zero handshake.
//!
//! One frame is a big-endian `u32` length followed by `kind: u8`,
//! `stream_id: u64`, and the payload. Length counts every byte after the
//! prefix. Data payloads hold raw bytes; control payloads hold JSON
//! documents bounded by [`MAX_IPC_CONTROL_BYTES`]. Stream zero is the
//! connection control channel: it carries the handshake and global
//! cancellation, never invocation data.

use std::collections::HashMap;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

use ruk_core::error::{CoreError, ErrorCode};
use ruk_core::protocol::{SCHEMA_MAJOR, SCHEMA_MINOR};

/// Maximum payload bytes of one data frame.
pub(crate) const MAX_DATA_CHUNK_BYTES: usize = 64 * 1024;

/// Maximum payload bytes of one control frame.
pub(crate) const MAX_IPC_CONTROL_BYTES: usize = 1024 * 1024;

/// Stream identifier of the connection control channel.
pub(crate) const CONTROL_STREAM_ID: u64 = 0;

/// Credit bytes granted to each direction of a new stream.
pub(crate) const INITIAL_STREAM_WINDOW_BYTES: u64 = 256 * 1024;

/// Credit bytes one direction of one stream may hold at most.
pub(crate) const MAX_STREAM_WINDOW_BYTES: u64 = 16 * 1024 * 1024;

/// Wire width of the frame length prefix in bytes.
pub(crate) const FRAME_PREFIX_BYTES: usize = 4;

/// Wire width of the kind plus stream identifier header in bytes.
pub(crate) const FRAME_HEADER_BYTES: usize = 9;

/// Feature strings this daemon build negotiates: directional credit flow,
/// structured merge notices, and outcome lookup for reconnects.
pub(crate) const SUPPORTED_FEATURES: &[&str] = &["credits", "merge-notices", "outcome-lookup"];

/// The kind byte of one IPC frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(crate) enum FrameKind {
    /// Opens one invocation stream with a JSON [`super::InvocationOpen`].
    Open = 1,
    /// Accepts one invocation stream with a JSON accepted document.
    Accepted = 2,
    /// Carries raw invocation input bytes toward the daemon.
    Stdin = 3,
    /// Ends invocation input; the daemon may dispatch after it.
    StdinEof = 4,
    /// Carries raw invocation output bytes toward the client.
    Stdout = 5,
    /// Carries raw invocation diagnostic bytes toward the client.
    Stderr = 6,
    /// Grants outbound credit bytes to its stream.
    WindowUpdate = 7,
    /// Cancels its stream, or every stream on the control channel.
    Cancel = 8,
    /// Carries bounded structured merge notices toward the client.
    MergeNotices = 9,
    /// Ends one invocation with a JSON [`super::ExitReport`].
    Exit = 10,
    /// Reports one invocation failure with a JSON [`super::ErrorReport`].
    Error = 11,
}

impl FrameKind {
    /// Decodes one kind byte.
    ///
    /// # Errors
    /// `E_INVALID` for an unknown discriminant.
    pub(crate) fn from_u8(byte: u8) -> Result<Self, CoreError> {
        match byte {
            1 => Ok(Self::Open),
            2 => Ok(Self::Accepted),
            3 => Ok(Self::Stdin),
            4 => Ok(Self::StdinEof),
            5 => Ok(Self::Stdout),
            6 => Ok(Self::Stderr),
            7 => Ok(Self::WindowUpdate),
            8 => Ok(Self::Cancel),
            9 => Ok(Self::MergeNotices),
            10 => Ok(Self::Exit),
            11 => Ok(Self::Error),
            _ => Err(CoreError::new(
                ErrorCode::EInvalid,
                format!("unknown IPC frame kind {byte}"),
            )),
        }
    }

    /// Encodes this kind as one wire byte.
    #[must_use]
    pub(crate) const fn as_u8(self) -> u8 {
        match self {
            Self::Open => 1,
            Self::Accepted => 2,
            Self::Stdin => 3,
            Self::StdinEof => 4,
            Self::Stdout => 5,
            Self::Stderr => 6,
            Self::WindowUpdate => 7,
            Self::Cancel => 8,
            Self::MergeNotices => 9,
            Self::Exit => 10,
            Self::Error => 11,
        }
    }

    /// True for raw-byte data frames, false for JSON control frames.
    #[must_use]
    pub(crate) const fn is_data(self) -> bool {
        match self {
            Self::Stdin | Self::Stdout | Self::Stderr => true,
            Self::Open
            | Self::Accepted
            | Self::StdinEof
            | Self::WindowUpdate
            | Self::Cancel
            | Self::MergeNotices
            | Self::Exit
            | Self::Error => false,
        }
    }
}

/// One decoded IPC frame: its kind, its stream, and its payload bytes.
#[derive(Debug)]
pub(crate) struct Frame {
    /// The frame kind.
    pub kind: FrameKind,
    /// The stream the frame belongs to; zero is connection control.
    pub stream_id: u64,
    /// The frame payload: raw bytes for data kinds, JSON for control kinds.
    pub payload: Vec<u8>,
}

/// Encodes one frame: length prefix, kind, stream identifier, payload.
///
/// # Errors
/// `E_LIMIT` when the payload exceeds its kind's bound.
pub(crate) fn encode_frame(
    kind: FrameKind,
    stream_id: u64,
    payload: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let bound = if kind.is_data() {
        MAX_DATA_CHUNK_BYTES
    } else {
        MAX_IPC_CONTROL_BYTES
    };
    if payload.len() > bound {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "IPC frame payload exceeds its bound".to_string(),
        ));
    }
    let length = u32::try_from(FRAME_HEADER_BYTES + payload.len())
        .map_err(|_| CoreError::new(ErrorCode::ELimit, "IPC frame length exceeds its prefix"))?;
    let mut out = Vec::with_capacity(FRAME_PREFIX_BYTES + FRAME_HEADER_BYTES + payload.len());
    out.extend_from_slice(&length.to_be_bytes());
    out.push(kind.as_u8());
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Reads one frame before `deadline`.
///
/// # Errors
/// `E_LIMIT` for an over-bound announced length or payload,
/// `E_INVALID` for a short or unknown frame, `E_IO` for transport
/// failures, `E_COORDINATOR_UNRESPONSIVE` on deadline expiry.
pub(crate) async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    deadline: Instant,
) -> Result<Frame, CoreError> {
    let mut prefix = [0u8; FRAME_PREFIX_BYTES];
    read_exact_before(stream, &mut prefix, deadline).await?;
    let total = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| CoreError::new(ErrorCode::ELimit, "IPC frame length exceeds its prefix"))?;
    if total < FRAME_HEADER_BYTES {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "IPC frame is shorter than its header",
        ));
    }
    if total > FRAME_HEADER_BYTES + MAX_IPC_CONTROL_BYTES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "IPC frame announces more than the control bound",
        ));
    }
    let mut header = [0u8; FRAME_HEADER_BYTES];
    read_exact_before(stream, &mut header, deadline).await?;
    let kind = FrameKind::from_u8(header[0])?;
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&header[1..FRAME_HEADER_BYTES]);
    let stream_id = u64::from_be_bytes(id_bytes);
    let payload_len = total - FRAME_HEADER_BYTES;
    let bound = if kind.is_data() {
        MAX_DATA_CHUNK_BYTES
    } else {
        MAX_IPC_CONTROL_BYTES
    };
    if payload_len > bound {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "IPC frame payload exceeds its kind bound",
        ));
    }
    let mut payload = vec![0u8; payload_len];
    read_exact_before(stream, &mut payload, deadline).await?;
    Ok(Frame {
        kind,
        stream_id,
        payload,
    })
}

/// Writes one frame before `deadline`.
///
/// # Errors
/// As for [`encode_frame`], plus `E_IO` and deadline expiry as for
/// [`read_frame`].
pub(crate) async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    kind: FrameKind,
    stream_id: u64,
    payload: &[u8],
    deadline: Instant,
) -> Result<(), CoreError> {
    let bytes = encode_frame(kind, stream_id, payload)?;
    match timeout_at(deadline, stream.write_all(&bytes)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(CoreError::new(
            ErrorCode::EIo,
            format!("IPC frame write failed: {err}"),
        )),
        Err(_) => Err(CoreError::new(
            ErrorCode::ECoordinatorUnresponsive,
            "IPC frame write deadline expired",
        )),
    }
}

/// One direction of one stream's credit window.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CreditWindow {
    /// The most credit bytes this direction may hold.
    capacity: u64,
    /// The credit bytes currently available for writes.
    available: u64,
}

impl CreditWindow {
    /// Builds one window capped at `capacity_bytes`, starting at the lesser
    /// of `initial_bytes` and the capacity.
    #[must_use]
    pub(crate) const fn new(capacity_bytes: u64, initial_bytes: u64) -> Self {
        Self {
            capacity: capacity_bytes,
            available: if initial_bytes < capacity_bytes {
                initial_bytes
            } else {
                capacity_bytes
            },
        }
    }

    /// Adds `bytes` of credit, saturating at the capacity.
    pub(crate) fn grant(&mut self, bytes: u64) {
        self.available = self.available.saturating_add(bytes).min(self.capacity);
    }

    /// Spends `bytes` of credit on one write.
    ///
    /// # Errors
    /// `E_LIMIT` when the window holds fewer than `bytes`.
    pub(crate) fn consume(&mut self, bytes: u64) -> Result<(), CoreError> {
        if self.available < bytes {
            return Err(CoreError::new(
                ErrorCode::ELimit,
                "stream credit window is exhausted",
            ));
        }
        self.available -= bytes;
        Ok(())
    }

    /// Returns the credit bytes currently available.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only the test target calls this at this commit; retained for later changeset rows"
        )
    )]
    #[must_use]
    pub(crate) const fn available(self) -> u64 {
        self.available
    }

    /// Returns the most credit bytes this direction may hold.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only the test target calls this at this commit; retained for later changeset rows"
        )
    )]
    #[must_use]
    pub(crate) const fn capacity(self) -> u64 {
        self.capacity
    }
}

/// Per-stream directional credit windows of one connection.
#[derive(Debug)]
pub(crate) struct StreamCredits {
    /// Bytes the client may still send per stream.
    inbound: HashMap<u64, CreditWindow>,
    /// Bytes the daemon may still send per stream.
    outbound: HashMap<u64, CreditWindow>,
    /// The starting window of each new direction.
    default_window: u64,
}

impl StreamCredits {
    /// Builds empty credit state granting `default_window_bytes` per new
    /// direction, capped by [`MAX_STREAM_WINDOW_BYTES`].
    #[must_use]
    pub(crate) fn new(default_window_bytes: u64) -> Self {
        Self {
            inbound: HashMap::new(),
            outbound: HashMap::new(),
            default_window: default_window_bytes.min(MAX_STREAM_WINDOW_BYTES),
        }
    }

    /// Registers both directions of `stream_id` with the default window.
    pub(crate) fn open_stream(&mut self, stream_id: u64) {
        let window = CreditWindow::new(MAX_STREAM_WINDOW_BYTES, self.default_window);
        self.inbound.insert(stream_id, window);
        self.outbound.insert(stream_id, window);
    }

    /// Forgets both directions of `stream_id`.
    pub(crate) fn close_stream(&mut self, stream_id: u64) {
        self.inbound.remove(&stream_id);
        self.outbound.remove(&stream_id);
    }

    /// Adds `bytes` of outbound credit to `stream_id`.
    ///
    /// # Errors
    /// `E_INVALID` for an unknown stream.
    pub(crate) fn grant_outbound(&mut self, stream_id: u64, bytes: u64) -> Result<(), CoreError> {
        match self.outbound.get_mut(&stream_id) {
            Some(window) => {
                window.grant(bytes);
                Ok(())
            }
            None => Err(CoreError::new(
                ErrorCode::EInvalid,
                "credit update names an unknown stream",
            )),
        }
    }

    /// Adds `bytes` of client-to-daemon credit to `stream_id`.
    ///
    /// # Errors
    /// `E_INVALID` for an unknown stream.
    pub(crate) fn grant_inbound(&mut self, stream_id: u64, bytes: u64) -> Result<(), CoreError> {
        match self.inbound.get_mut(&stream_id) {
            Some(window) => {
                window.grant(bytes);
                Ok(())
            }
            None => Err(CoreError::new(
                ErrorCode::EInvalid,
                "credit update names an unknown stream",
            )),
        }
    }

    /// Spends `bytes` of daemon-to-client credit on `stream_id`.
    ///
    /// # Errors
    /// `E_INVALID` for an unknown stream, `E_LIMIT` on exhaustion.
    pub(crate) fn consume_outbound(&mut self, stream_id: u64, bytes: u64) -> Result<(), CoreError> {
        match self.outbound.get_mut(&stream_id) {
            Some(window) => window.consume(bytes),
            None => Err(CoreError::new(
                ErrorCode::EInvalid,
                "data write names an unknown stream",
            )),
        }
    }

    /// Spends `bytes` of client-to-daemon credit on `stream_id`.
    ///
    /// # Errors
    /// `E_INVALID` for an unknown stream, `E_LIMIT` on exhaustion.
    pub(crate) fn consume_inbound(&mut self, stream_id: u64, bytes: u64) -> Result<(), CoreError> {
        match self.inbound.get_mut(&stream_id) {
            Some(window) => window.consume(bytes),
            None => Err(CoreError::new(
                ErrorCode::EInvalid,
                "data read names an unknown stream",
            )),
        }
    }
}

/// The client's stream-zero handshake proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HandshakeHello {
    /// The client's protocol major version.
    pub protocol_major: u32,
    /// The client's protocol minor version. Older clients omit
    /// this field, so it defaults to zero (unknown) instead of rejecting
    /// the handshake.
    #[serde(default)]
    pub protocol_minor: u32,
    /// The requested service profile, such as `host`.
    pub profile: String,
    /// The object formats the client speaks, such as `sha1`.
    pub object_formats: Vec<String>,
    /// The feature strings the client supports.
    pub features: Vec<String>,
}

/// The daemon's stream-zero handshake acceptance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HandshakeAccept {
    /// The negotiated protocol major version.
    pub protocol_major: u32,
    /// The negotiated protocol minor version.
    pub protocol_minor: u32,
    /// The accepted service profile.
    pub profile: String,
    /// The object formats both peers speak.
    pub object_formats: Vec<String>,
    /// The features both peers support.
    pub features: Vec<String>,
}

/// Negotiates one handshake proposal against this build.
///
/// # Errors
/// `E_VERSION` on a protocol major mismatch, `E_INVALID` on an empty
/// profile or empty object-format list.
pub(crate) fn negotiate(hello: &HandshakeHello) -> Result<HandshakeAccept, CoreError> {
    if hello.protocol_major != SCHEMA_MAJOR {
        return Err(CoreError::new(
            ErrorCode::EVersion,
            format!(
                "protocol major {} is unsupported by major {SCHEMA_MAJOR}",
                hello.protocol_major
            ),
        ));
    }
    if hello.profile.is_empty() {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "handshake profile must not be empty",
        ));
    }
    if hello.object_formats.is_empty() {
        return Err(CoreError::new(
            ErrorCode::EInvalid,
            "handshake must name at least one object format",
        ));
    }
    let features: Vec<String> = SUPPORTED_FEATURES
        .iter()
        .map(|name| (*name).to_string())
        .filter(|name| hello.features.contains(name))
        .collect();
    Ok(HandshakeAccept {
        protocol_major: SCHEMA_MAJOR,
        protocol_minor: SCHEMA_MINOR.min(hello.protocol_minor),
        profile: hello.profile.clone(),
        object_formats: hello.object_formats.clone(),
        features,
    })
}

/// Encodes one control payload as JSON.
///
/// # Errors
/// `E_LIMIT` above [`MAX_IPC_CONTROL_BYTES`], `E_INVALID` when the value
/// has no JSON form.
pub(crate) fn encode_control<T: Serialize>(value: &T) -> Result<Vec<u8>, CoreError> {
    let text = sonic_rs::to_string(value).map_err(|err| {
        CoreError::new(
            ErrorCode::EInvalid,
            format!("control payload is not encodable: {err}"),
        )
    })?;
    if text.len() > MAX_IPC_CONTROL_BYTES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "control payload exceeds its bound",
        ));
    }
    Ok(text.into_bytes())
}

/// Decodes one JSON control payload.
///
/// # Errors
/// `E_LIMIT` above [`MAX_IPC_CONTROL_BYTES`], `E_INVALID` on malformed
/// JSON or a shape mismatch.
pub(crate) fn decode_control<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CoreError> {
    if bytes.len() > MAX_IPC_CONTROL_BYTES {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            "control payload exceeds its bound",
        ));
    }
    sonic_rs::from_slice(bytes).map_err(|err| {
        CoreError::new(
            ErrorCode::EInvalid,
            format!("control payload is malformed: {err}"),
        )
    })
}
/// The authenticated local peer of one Unix-socket connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PeerIdentity {
    /// The peer's user identifier.
    pub uid: u32,
    /// The peer's group identifier.
    pub gid: u32,
    /// The peer's process identifier, when the platform reports one.
    pub pid: Option<u32>,
}

/// Authenticates one Unix-socket peer through `SO_PEERCRED`.
///
/// # Errors
/// `E_IO` when peer credentials are unavailable, `E_FORBIDDEN` when the
/// peer's user is outside `allowed_uids` (empty allows every local peer).
#[cfg(unix)]
pub(crate) fn authenticate_peer(
    stream: &tokio::net::UnixStream,
    allowed_uids: &[u32],
) -> Result<PeerIdentity, CoreError> {
    let cred = stream.peer_cred().map_err(|err| {
        CoreError::new(
            ErrorCode::EIo,
            format!("peer credentials are unavailable: {err}"),
        )
    })?;
    let uid = cred.uid();
    if !allowed_uids.is_empty() && !allowed_uids.contains(&uid) {
        return Err(CoreError::new(
            ErrorCode::EForbidden,
            "Unix-socket peer user is not an authorized service identity",
        ));
    }
    let gid = cred.gid();
    let pid =
        cred.pid().map(u32::try_from).transpose().map_err(|_| {
            CoreError::new(ErrorCode::EIo, "peer process identifier is out of range")
        })?;
    Ok(PeerIdentity { uid, gid, pid })
}

async fn read_exact_before<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<(), CoreError> {
    match timeout_at(deadline, stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(CoreError::new(
            ErrorCode::EIo,
            format!("IPC frame read failed: {err}"),
        )),
        Err(_) => Err(CoreError::new(
            ErrorCode::ECoordinatorUnresponsive,
            "IPC frame read deadline expired",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CreditWindow, FrameKind, HandshakeHello, MAX_DATA_CHUNK_BYTES, MAX_IPC_CONTROL_BYTES,
        StreamCredits, encode_frame, negotiate,
    };

    #[test]
    fn frame_kind_round_trip() {
        for byte in 1u8..=11u8 {
            let kind = FrameKind::from_u8(byte).expect("known kind decodes");
            assert_eq!(kind.as_u8(), byte);
        }
        assert!(FrameKind::from_u8(0).is_err());
        assert!(FrameKind::from_u8(12).is_err());
    }

    #[test]
    fn data_and_control_bounds_differ() {
        assert!(FrameKind::Stdout.is_data());
        assert!(!FrameKind::Open.is_data());
        assert!(!FrameKind::Exit.is_data());
        let oversized = vec![0u8; MAX_DATA_CHUNK_BYTES + 1];
        assert!(encode_frame(FrameKind::Stdout, 1, &oversized).is_err());
        let oversized_control = vec![0u8; MAX_IPC_CONTROL_BYTES + 1];
        assert!(encode_frame(FrameKind::Open, 1, &oversized_control).is_err());
        assert!(
            encode_frame(
                FrameKind::Stdout,
                1,
                &oversized_control[..MAX_DATA_CHUNK_BYTES]
            )
            .is_ok()
        );
    }

    #[test]
    fn credit_window_exhaustion_fails() {
        let mut window = CreditWindow::new(100, 100);
        assert!(window.consume(64).is_ok());
        assert_eq!(window.available(), 36);
        assert!(window.consume(37).is_err());
        window.grant(1000);
        assert_eq!(window.available(), 100);
        assert_eq!(window.capacity(), 100);
    }

    #[test]
    fn unknown_stream_credit_fails() {
        let mut credits = StreamCredits::new(1024);
        assert!(credits.consume_outbound(7, 1).is_err());
        credits.open_stream(7);
        assert!(credits.consume_outbound(7, 2048).is_err());
        assert!(credits.grant_outbound(7, 4096).is_ok());
        assert!(credits.consume_outbound(7, 2048).is_ok());
        credits.close_stream(7);
        assert!(credits.grant_outbound(7, 1).is_err());
    }

    #[test]
    fn handshake_rejects_major_mismatch() {
        let hello = HandshakeHello {
            protocol_major: 999,
            protocol_minor: 0,
            profile: String::from("host"),
            object_formats: vec![String::from("sha1")],
            features: Vec::new(),
        };
        assert!(negotiate(&hello).is_err());
        let empty_profile = HandshakeHello {
            protocol_major: super::SCHEMA_MAJOR,
            protocol_minor: 0,
            profile: String::new(),
            object_formats: vec![String::from("sha1")],
            features: Vec::new(),
        };
        assert!(negotiate(&empty_profile).is_err());
    }
}
