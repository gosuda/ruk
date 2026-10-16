use std::io::{Read as _, Write as _};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use ruk_core::MAX_CONTROL_FRAME_BYTES;
use ruk_core::conflict::{ConflictRecord, ConflictRecordInput};
use ruk_core::error::{CoreError, ErrorCode};
use ruk_core::ids::HashKind;

/// Ruk: an agent-native version control system with exact Git interoperability.
#[derive(Parser, Debug)]
#[command(
    name = "ruk",
    version,
    about = "Ruk agent-native version control",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Render the implemented model schema and encoding contracts.
    ///
    /// Only model-level schema/encoding is implemented in this slice; no
    /// repository operations are advertised or accepted.
    Model {
        /// Output form of the schema.
        #[arg(long, value_enum, default_value_t = ModelFormat::Json)]
        format: ModelFormat,
    },
    /// Encode a native conflict-v1 record from JSON input bytes.
    ///
    /// Reads the [`ConflictRecordInput`] document from `--input` (`-` for
    /// stdin) as raw bytes, validates it against the repository hash kind,
    /// and writes the exact `conflict-v1` byte form to stdout.
    EncodeConflict {
        /// Object format of the enclosing repository.
        #[arg(long, value_enum, default_value_t = ObjectFormatArg::Sha1)]
        object_format: ObjectFormatArg,
        /// Input path, or `-` for stdin.
        #[arg(long, default_value = "-")]
        input: String,
    },
    /// Decode a native conflict-v1 record to its canonical JSON form.
    ///
    /// Reads the exact `conflict-v1` byte form from `--input` (`-` for
    /// stdin), validates it against the repository hash kind, and writes
    /// the [`ConflictRecordInput`]-shaped JSON document to stdout. Byte
    /// fields (message, signature names, header values) render as a JSON
    /// string when valid UTF-8, else as `{"hex": "<lowercase hex>"}`,
    /// matching the core byte-string contract.
    DecodeConflict {
        /// Object format of the enclosing repository.
        #[arg(long, value_enum, default_value_t = ObjectFormatArg::Sha1)]
        object_format: ObjectFormatArg,
        /// Input path, or `-` for stdin.
        #[arg(long, default_value = "-")]
        input: String,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum ModelFormat {
    Json,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum ObjectFormatArg {
    Sha1,
    Sha256,
}

impl From<ObjectFormatArg> for HashKind {
    fn from(arg: ObjectFormatArg) -> Self {
        match arg {
            ObjectFormatArg::Sha1 => Self::Sha1,
            ObjectFormatArg::Sha256 => Self::Sha256,
        }
    }
}

fn run(cli: Cli) -> Result<Vec<u8>, CoreError> {
    match cli.command {
        Command::Model { .. } => model_schema_document(),
        Command::EncodeConflict {
            object_format,
            input,
        } => {
            let bytes = read_input(&input)?;
            encode_conflict(&bytes, HashKind::from(object_format))
        }
        Command::DecodeConflict {
            object_format,
            input,
        } => {
            let bytes = read_input(&input)?;
            decode_conflict(&bytes, HashKind::from(object_format))
        }
    }
}

/// Reads one input document from a file path or stdin (`-`), bounded by
/// [`MAX_CONTROL_FRAME_BYTES`]. Larger inputs fail with `E_LIMIT` instead
/// of growing memory without limit.
fn read_input(path: &str) -> Result<Vec<u8>, CoreError> {
    let limit = u64::try_from(MAX_CONTROL_FRAME_BYTES).map_err(|_| {
        CoreError::new(
            ErrorCode::ELimit,
            "control frame bound exceeds the CLI input range",
        )
    })?;
    if path == "-" {
        read_bounded(std::io::stdin(), limit)
    } else {
        let file = std::fs::File::open(path).map_err(io_error)?;
        read_bounded(file, limit)
    }
}

/// Consumes at most `limit + 1` bytes, rejecting the input when it is longer
/// than `limit`. The `take` bound applies to the open stream itself, so a
/// growing file or a FIFO can never force an unbounded read: overflow is
/// detected after bounded consumption instead of via a racy size pre-check.
fn read_bounded(source: impl std::io::Read, limit: u64) -> Result<Vec<u8>, CoreError> {
    let mut limited = source.take(limit + 1);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf).map_err(io_error)?;
    if buf.len() as u64 > limit {
        return Err(CoreError::new(
            ErrorCode::ELimit,
            format!("input exceeds {limit} bytes"),
        ));
    }
    Ok(buf)
}

fn io_error(err: std::io::Error) -> CoreError {
    CoreError::new(ErrorCode::EIo, format!("input/output: {err}"))
}

fn encode_conflict(bytes: &[u8], kind: HashKind) -> Result<Vec<u8>, CoreError> {
    let input: ConflictRecordInput = serde_json::from_slice(bytes).map_err(|err| {
        CoreError::new(
            ErrorCode::EInvalid,
            format!("malformed conflict input: {err}"),
        )
    })?;
    let record = ConflictRecord::from_input(&input, kind).map_err(CoreError::from)?;
    Ok(record.encode())
}

fn decode_conflict(bytes: &[u8], kind: HashKind) -> Result<Vec<u8>, CoreError> {
    let record = ConflictRecord::decode(bytes, kind).map_err(CoreError::from)?;
    // Canonical JSON is the validated input projection itself: byte fields
    // serialize through the core ByteString contract with no CLI-side copy
    // of the encoding logic.
    serde_json::to_vec(&record.to_input())
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("schema render: {err}")))
}

fn model_schema_document() -> Result<Vec<u8>, CoreError> {
    let doc = ruk_core::protocol::model_schema_json();
    serde_json::to_vec(&doc)
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("schema render: {err}")))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(out) => {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            if lock.write_all(&out).is_err() || lock.flush().is_err() {
                return ExitCode::from(ErrorCode::EIo.exit_code());
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            let stderr = std::io::stderr();
            let mut lock = stderr.lock();
            let _ = writeln!(lock, "ruk: {err}");
            for hint in &err.hints {
                let _ = writeln!(lock, "hint: {hint}");
            }
            ExitCode::from(err.code.exit_code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Endless zero bytes that count every byte pulled from the source.
    struct CountingInfinite {
        pulled: u64,
    }

    impl std::io::Read for CountingInfinite {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let n = buf.len().min(8192);
            buf[..n].fill(0);
            // Capped at 8192 above, so this usize -> u64 cast is lossless.
            self.pulled += n as u64;
            Ok(n)
        }
    }

    #[test]
    fn bounded_input_stops_past_limit() {
        let limit = 1024;
        let mut source = CountingInfinite { pulled: 0 };
        let err = read_bounded(&mut source, limit).expect_err("limit + 1 bytes must overflow");
        assert_eq!(err.code, ErrorCode::ELimit);
        assert_eq!(
            source.pulled,
            limit + 1,
            "must not consume past limit + 1 even when the source never ends"
        );
    }
}
