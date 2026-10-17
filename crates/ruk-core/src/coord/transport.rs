use std::ops::Deref;
use std::sync::{Arc, LazyLock};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

use crate::budget::{ByteBudget, ByteReservation};
use crate::protocol::{FRAME_PREFIX_BYTES, control_frame_len};
use crate::{CoreError, ErrorCode};

pub(crate) static STREAM_BUFFERS: LazyLock<Arc<ByteBudget>> =
    LazyLock::new(|| ByteBudget::new(1024 * 1024 * 1024));

#[derive(Debug)]
pub(crate) struct Frame {
    body: Vec<u8>,
    _reservation: ByteReservation,
}

impl Deref for Frame {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.body
    }
}

#[derive(Clone, Copy)]
pub(crate) struct FrameLength(usize);

impl FrameLength {
    pub(crate) const fn bytes(self) -> usize {
        self.0
    }
}

pub(crate) async fn read_length<S: AsyncRead + Unpin>(
    stream: &mut S,
    deadline: Instant,
) -> Result<FrameLength, CoreError> {
    let mut prefix = [0; FRAME_PREFIX_BYTES];
    within_deadline(deadline, stream.read_exact(&mut prefix)).await?;
    control_frame_len(prefix).map(FrameLength)
}

pub(crate) async fn read_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    length: FrameLength,
    deadline: Instant,
) -> Result<Frame, CoreError> {
    if Instant::now() >= deadline {
        return Err(deadline_expired());
    }
    let reservation = STREAM_BUFFERS.reserve(length.bytes() as u64)?;
    let body = within_deadline(deadline, async {
        let mut body = vec![0; length.bytes()];
        stream.read_exact(&mut body).await?;
        Ok(body)
    })
    .await?;
    Ok(Frame {
        body,
        _reservation: reservation,
    })
}

pub(crate) async fn write_body<S: AsyncWrite + Unpin>(
    stream: &mut S,
    body: &[u8],
    deadline: Instant,
) -> Result<(), CoreError> {
    let length = u32::try_from(body.len()).map_err(|_| {
        CoreError::new(ErrorCode::ELimit, "control frame length exceeds its prefix")
    })?;
    let prefix = length.to_be_bytes();
    control_frame_len(prefix)?;
    within_deadline(deadline, async {
        stream.write_all(&prefix).await?;
        stream.write_all(body).await
    })
    .await
}

async fn within_deadline<T>(
    deadline: Instant,
    work: impl Future<Output = std::io::Result<T>>,
) -> Result<T, CoreError> {
    if Instant::now() >= deadline {
        return Err(deadline_expired());
    }
    let result = timeout_at(deadline, work)
        .await
        .map_err(|_| deadline_expired())?
        .map_err(io_error)?;
    if Instant::now() >= deadline {
        return Err(deadline_expired());
    }
    Ok(result)
}

fn deadline_expired() -> CoreError {
    CoreError::new(
        ErrorCode::ECoordinatorUnresponsive,
        "coordinator control frame deadline expired",
    )
}

fn io_error(error: std::io::Error) -> CoreError {
    CoreError::new(
        ErrorCode::EIo,
        format!("coordinator control frame: {error}"),
    )
}
