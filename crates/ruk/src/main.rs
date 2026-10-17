use std::io::{Read as _, Write as _};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

mod cli;
mod daemon;

use ruk_core::MAX_CONTROL_FRAME_BYTES;
use ruk_core::conflict::{ConflictRecord, ConflictRecordInput};
use ruk_core::error::{CoreError, ErrorCode};
use ruk_core::ids::HashKind;
use ruk_core::ops::{DescribeRequest, NewRequest};
use ruk_core::store::{PreparationBudget, Store};

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
enum ForgejoCommand {
    /// Serve the daemon until interrupted.
    Serve {
        /// Daemon configuration document path (TOML).
        #[arg(long)]
        config: std::path::PathBuf,
    },
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
    /// Serve Forgejo as a hosted multi-repository daemon.
    ///
    /// Loads a TOML config naming the socket path, repository roots, and
    /// the runtime bounds, then serves the pooled IPC surface until
    /// interrupted.
    Forgejo {
        #[command(subcommand)]
        command: ForgejoCommand,
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
    /// Create one native commit from a JSON request and print its identity.
    ///
    /// Reads a [`NewRequest`] document from `--input` (`-` for stdin) and
    /// publishes the commit atomically. Nothing is published when any
    /// precondition fails.
    New {
        /// Repository root holding a Ruk store.
        #[arg(long)]
        repo: std::path::PathBuf,
        /// Input path, or `-` for stdin.
        #[arg(long, default_value = "-")]
        input: String,
    },
    /// Describe one commit or one change from a JSON request.
    ///
    /// Reads a [`DescribeRequest`] document from `--input` (`-` for stdin)
    /// and writes the typed description as JSON.
    Describe {
        /// Repository root holding a Ruk store.
        #[arg(long)]
        repo: std::path::PathBuf,
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
        Command::New { repo, input } => {
            let request: NewRequest = decode_document(&read_input(&input)?)?;
            let store = open_store(&repo)?;
            let result = ruk_core::ops::new(&store, request)?;
            render(&result)
        }
        Command::Describe { repo, input } => {
            let request: DescribeRequest = decode_document(&read_input(&input)?)?;
            let store = open_store(&repo)?;
            let description = ruk_core::ops::describe(&store, request)?;
            render(&description)
        }
        Command::Forgejo {
            command: ForgejoCommand::Serve { config },
        } => {
            let doc = std::fs::read(&config).map_err(|err| {
                CoreError::new(
                    ErrorCode::EIo,
                    format!("daemon config {}: {err}", config.display()),
                )
            })?;
            let cfg = daemon::DaemonConfig::from_toml(&doc).map_err(|err| match err {
                daemon::Error::Core(err) => err,
                other => CoreError::new(ErrorCode::EHosted, other.to_string()),
            })?;
            daemon::serve(cfg).map_err(|err| match err {
                daemon::Error::Core(err) => err,
                other => CoreError::new(ErrorCode::EHosted, other.to_string()),
            })?;
            Ok(Vec::new())
        }
    }
}

/// Opens the store rooted at `path` under the reference preparation budget.
fn open_store(path: &std::path::Path) -> Result<Store, CoreError> {
    Store::open(
        path,
        std::sync::Arc::new(PreparationBudget::reference_defaults()),
    )
    .map_err(|err| CoreError::new(err.code(), err.to_string()))
}

fn decode_document<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CoreError> {
    ruk_core::protocol::decode_json(bytes)
}

fn render<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, CoreError> {
    sonic_rs::to_vec(value)
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("schema render: {err}")))
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
    let input: ConflictRecordInput = ruk_core::protocol::decode_json(bytes).map_err(|err| {
        CoreError::new(
            err.code,
            format!("malformed conflict input: {}", err.message),
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
    sonic_rs::to_vec(&record.to_input())
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("schema render: {err}")))
}

fn model_schema_document() -> Result<Vec<u8>, CoreError> {
    let doc = ruk_core::protocol::model_schema_json();
    sonic_rs::to_vec(&doc)
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("schema render: {err}")))
}

fn main() -> ExitCode {
    // A re-executed syntax worker is not a user command: it owns stdin and
    // stdout as a framed stream, so it is dispatched before any CLI parsing.
    if std::env::args().nth(1).as_deref() == Some(ruk_core::merge::syntax::pool::WORKER_ARG) {
        return match ruk_core::merge::syntax::pool::run_worker_stdio() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                let _ = writeln!(std::io::stderr(), "ruk syntax worker: {err}");
                ExitCode::from(err.code().exit_code())
            }
        };
    }
    // Git-compatibility dispatch: invoked as `git`, or `ruk git <verb>`.
    let argv: Vec<String> = std::env::args().collect();
    let invoked_as_git = argv
        .first()
        .and_then(|arg0| std::path::Path::new(arg0).file_name())
        .is_some_and(|name| name == "git");
    let git_verb = argv.get(1).is_some_and(|arg| arg == "git");
    if invoked_as_git || git_verb {
        let rest = if invoked_as_git {
            argv.clone()
        } else {
            argv[1..].to_vec()
        };
        return cli::run(rest, cli::CliEnv::capture());
    }
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
    fn new_and_describe_round_trip_through_the_cli() {
        use std::io::Cursor;
        use std::sync::Arc;

        use ruk_core::bytes::ByteString;
        use ruk_core::change::ChangeId;
        use ruk_core::conflict::{Signature, TzOffset};
        use ruk_core::store::types::ObjectKind;

        let root = std::env::temp_dir().join(format!("ruk-cli-ops-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = Store::create(
            &root,
            HashKind::Sha1,
            Arc::new(PreparationBudget::reference_defaults()),
        )
        .expect("create store");
        let mut tree_bytes = Vec::from(b"100644 xa".as_slice());
        tree_bytes.push(0);
        tree_bytes.extend_from_slice(&[0x11; 20]);
        let prepared = store
            .prepare(
                ObjectKind::Tree,
                u64::try_from(tree_bytes.len()).expect("test tree fits u64"),
                Cursor::new(&tree_bytes),
                None,
            )
            .expect("prepare tree");
        let tree = prepared.oid();
        store.publish(vec![prepared], &[]).expect("publish tree");
        drop(store);

        let signature = Signature {
            name: ByteString::from("Ada"),
            email: ByteString::from("ada@example.invalid"),
            timestamp: 1_700_000_000,
            offset: TzOffset::UTC,
        };
        let change_id = ChangeId::generate();
        let request = NewRequest {
            tree,
            parents: Vec::new(),
            author: signature.clone(),
            committer: signature,
            message: ByteString::from("root\n"),
            change_id: Some(change_id),
            predecessor: None,
            provenance: None,
        };
        let new_path = root.join("new.json");
        std::fs::write(
            &new_path,
            sonic_rs::to_vec(&request).expect("encode request"),
        )
        .expect("write request");
        let out = run(Cli {
            command: Command::New {
                repo: root.clone(),
                input: new_path.display().to_string(),
            },
        })
        .expect("run new");
        let created: ruk_core::ops::NewResult =
            ruk_core::protocol::decode_json(&out).expect("decode new result");
        assert_eq!(created.change_id, change_id);

        let describe_path = root.join("describe.json");
        std::fs::write(
            &describe_path,
            sonic_rs::to_vec(&DescribeRequest::commit(created.head)).expect("encode request"),
        )
        .expect("write request");
        let out = run(Cli {
            command: Command::Describe {
                repo: root.clone(),
                input: describe_path.display().to_string(),
            },
        })
        .expect("run describe");
        let described: ruk_core::ops::Description =
            ruk_core::protocol::decode_json(&out).expect("decode description");
        let ruk_core::ops::Description::Commit(described) = described else {
            panic!("a commit request must answer with a commit");
        };
        assert_eq!(described.head, created.head);
        assert_eq!(described.change_id, change_id);
        assert_eq!(described.message, "root\n");
        let _ = std::fs::remove_dir_all(&root);
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
