//! JSON-RPC 2.0 stdio transport for the MCP tool surface.
//!
//! The transport reads newline-delimited JSON-RPC documents from a buffered
//! reader and writes one response per request to a writer. Supported methods
//! are `initialize`, `tools/list`, `tools/call`, and `ping`; the
//! `notifications/initialized` notification is accepted and never answered.
//! Every other method fails `METHOD_NOT_FOUND`, and every malformed document
//! fails `PARSE_ERROR` or `INVALID_REQUEST`.
//!
//! Error mapping keeps CoreError codes visible on both paths: bad params
//! (unknown tools, mistyped arguments, oversized lines, and any tool
//! failure coded `E_INVALID`, which covers every argument decode failure)
//! fail with `INVALID_PARAMS` carrying the CoreError code in
//! `data.core_code`, while store opens and operation failures with any
//! other code come back as `tools/call` results with `isError: true` whose
//! text starts with the CoreError code. Input paths never panic: every
//! decode, cast, and index is guarded.
//!
//! Framing is bounded by [`ruk_core::MAX_CONTROL_FRAME_BYTES`]: one line
//! past the bound is answered with an `E_LIMIT` error and drained, so a
//! hostile peer cannot force unbounded buffering.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use ruk_core::MAX_CONTROL_FRAME_BYTES;
use ruk_core::error::{CoreError, ErrorCode};
use ruk_core::store::{PreparationBudget, Store};

use super::tools::{TOOL_TABLE, Tool, call_on_store};

/// The JSON-RPC version this server speaks.
pub(crate) const JSONRPC_VERSION: &str = "2.0";

/// The MCP protocol version reported by `initialize`.
pub(crate) const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

/// The server name reported by `initialize`.
pub(crate) const SERVER_NAME: &str = "ruk";

/// The server version reported by `initialize`.
pub(crate) const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// JSON-RPC parse error: the document is not JSON.
pub(crate) const PARSE_ERROR: i32 = -32700;

/// JSON-RPC invalid request: the document is JSON but not one request.
pub(crate) const INVALID_REQUEST: i32 = -32600;

/// JSON-RPC method not found.
pub(crate) const METHOD_NOT_FOUND: i32 = -32601;

/// JSON-RPC invalid params, including unknown tools and mistyped arguments.
pub(crate) const INVALID_PARAMS: i32 = -32602;

/// JSON-RPC internal error: the store or the transport failed.
pub(crate) const INTERNAL_ERROR: i32 = -32603;

/// The `initialize` method name.
pub(crate) const METHOD_INITIALIZE: &str = "initialize";

/// The `notifications/initialized` notification name.
pub(crate) const METHOD_INITIALIZED: &str = "notifications/initialized";

/// The `tools/list` method name.
pub(crate) const METHOD_TOOLS_LIST: &str = "tools/list";

/// The `tools/call` method name.
pub(crate) const METHOD_TOOLS_CALL: &str = "tools/call";

/// The `ping` method name.
pub(crate) const METHOD_PING: &str = "ping";

/// One JSON-RPC 2.0 request or notification as received.
#[derive(Debug, serde::Deserialize)]
struct WireRequest {
    #[serde(default)]
    jsonrpc: Option<String>,
    #[serde(default)]
    id: Option<sonic_rs::Value>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<sonic_rs::Value>,
}

/// The `tools/call` params: a tool name with its arguments.
#[derive(Debug, serde::Deserialize)]
struct ToolsCallParams {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<sonic_rs::Value>,
}

/// One JSON-RPC 2.0 response as written.
#[derive(Debug, serde::Serialize)]
struct WireResponse {
    jsonrpc: &'static str,
    id: Option<sonic_rs::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<HandlerResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

/// The successful result of one handled method.
#[derive(Debug, serde::Serialize)]
#[serde(untagged)]
enum HandlerResult {
    Initialize(InitializeResult),
    ToolsList(ToolsListResult),
    ToolCall(ToolCallResult),
    Empty(EmptyResult),
}

/// The `initialize` result.
#[derive(Debug, serde::Serialize)]
struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    protocol_version: &'static str,
    capabilities: InitializeCapabilities,
    #[serde(rename = "serverInfo")]
    server_info: ServerInfo,
}

/// The capabilities the server advertises.
#[derive(Debug, serde::Serialize)]
struct InitializeCapabilities {
    tools: ToolsCapability,
}

/// The tools capability: tools exist, the list never changes mid-session.
#[derive(Debug, serde::Serialize)]
struct ToolsCapability {}

/// The server identity.
#[derive(Debug, serde::Serialize)]
struct ServerInfo {
    name: &'static str,
    version: &'static str,
}

/// The `tools/list` result.
#[derive(Debug, serde::Serialize)]
struct ToolsListResult {
    tools: Vec<ToolListEntry>,
}

/// One listed tool with the schema its arguments decode as.
#[derive(Debug, serde::Serialize)]
struct ToolListEntry {
    name: &'static str,
    description: &'static str,
    #[serde(rename = "inputSchema")]
    input_schema: InputSchema,
}

/// The advertised input schema of one tool: a JSON object whose exact shape
/// is the existing Rust request type named in `params_type`.
#[derive(Debug, serde::Serialize)]
struct InputSchema {
    #[serde(rename = "type")]
    kind: &'static str,
    description: String,
    #[serde(rename = "x-ruk-params-type")]
    params_type: &'static str,
}

/// The `tools/call` result: text content plus the MCP error flag.
#[derive(Debug, serde::Serialize)]
struct ToolCallResult {
    content: Vec<ContentPart>,
    #[serde(rename = "isError")]
    is_error: bool,
}

/// One text content part.
#[derive(Debug, serde::Serialize)]
struct ContentPart {
    #[serde(rename = "type")]
    kind: &'static str,
    text: String,
}

/// The `ping` and other empty results.
#[derive(Debug, serde::Serialize)]
struct EmptyResult {}

/// One JSON-RPC error with the CoreError code attached.
#[derive(Debug, serde::Serialize)]
struct RpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<ErrorData>,
}

/// The CoreError behind a JSON-RPC error.
#[derive(Debug, serde::Serialize)]
struct ErrorData {
    core_code: String,
    detail: String,
}

/// The MCP stdio server bound to one repository root.
#[derive(Clone, Debug)]
pub(crate) struct Server {
    repo: PathBuf,
}

impl Server {
    /// Binds the server to a repository root. The store opens lazily, once
    /// per `tools/call`, exactly as the CLI commands open it.
    #[must_use]
    pub(crate) fn new(repo: PathBuf) -> Self {
        Self { repo }
    }

    /// The repository root this server opens.
    #[expect(
        dead_code,
        reason = "no caller at this commit; retained for later changeset rows"
    )]
    #[must_use]
    pub(crate) fn repo(&self) -> &Path {
        &self.repo
    }

    /// Handles one framed JSON-RPC document and renders its response.
    ///
    /// Notifications (requests without an id, and `notifications/initialized`
    /// with or without one) execute without answering and yield `None`.
    /// Oversized documents fail `E_LIMIT`; anything undecodable fails
    /// `PARSE_ERROR` or `INVALID_REQUEST`.
    pub(crate) fn handle(&self, raw: &[u8]) -> Option<Vec<u8>> {
        if raw.len() > MAX_CONTROL_FRAME_BYTES {
            let oversized = CoreError::new(
                ErrorCode::ELimit,
                format!("input exceeds {MAX_CONTROL_FRAME_BYTES} bytes"),
            );
            return Some(render_response(&error_response(
                None,
                INVALID_PARAMS,
                &oversized,
            )));
        }
        if sonic_rs::from_slice::<sonic_rs::Value>(raw).is_err() {
            let malformed = CoreError::new(ErrorCode::EInvalid, "request is not a JSON document");
            return Some(render_response(&error_response(
                None,
                PARSE_ERROR,
                &malformed,
            )));
        }
        let request = match ruk_core::protocol::decode_json::<WireRequest>(raw) {
            Ok(request) => request,
            Err(err) => {
                return Some(render_response(&error_response(
                    None,
                    INVALID_REQUEST,
                    &err,
                )));
            }
        };
        if request.jsonrpc.as_deref() != Some(JSONRPC_VERSION) {
            let version = CoreError::new(
                ErrorCode::EInvalid,
                "request must carry \"jsonrpc\": \"2.0\"",
            );
            return Some(render_response(&error_response(
                request.id,
                INVALID_REQUEST,
                &version,
            )));
        }
        let method = match request.method {
            Some(method) => method,
            None => {
                let missing = CoreError::new(ErrorCode::EInvalid, "request has no method");
                return Some(render_response(&error_response(
                    request.id,
                    INVALID_REQUEST,
                    &missing,
                )));
            }
        };
        if method == METHOD_INITIALIZED {
            return None;
        }
        let response = self.answer(request.id, &method, request.params);
        response.id.as_ref()?;
        Some(render_response(&response))
    }

    /// Serves newline-delimited JSON-RPC documents until the reader ends.
    ///
    /// Blank lines are skipped. A line past [`MAX_CONTROL_FRAME_BYTES`] is
    /// answered with an `E_LIMIT` error and drained instead of buffering
    /// without bound.
    ///
    /// # Errors
    /// `E_IO` when the reader or the writer fails.
    pub(crate) fn serve_stdio(
        &self,
        reader: impl BufRead,
        writer: impl Write,
    ) -> Result<(), CoreError> {
        let mut reader = reader;
        let mut writer = writer;
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match read_line_bounded(&mut reader, &mut buf)? {
                LineRead::Eof => return Ok(()),
                LineRead::TooLong => {
                    drain_line(&mut reader)?;
                    let oversized = CoreError::new(
                        ErrorCode::ELimit,
                        format!("input exceeds {MAX_CONTROL_FRAME_BYTES} bytes"),
                    );
                    let response =
                        render_response(&error_response(None, INVALID_PARAMS, &oversized));
                    write_response(&mut writer, &response)?;
                }
                LineRead::Line => {
                    let document = trimmed(&buf);
                    if document.is_empty() {
                        continue;
                    }
                    if let Some(response) = self.handle(document) {
                        write_response(&mut writer, &response)?;
                    }
                }
            }
        }
    }

    /// Answers one well-formed request.
    fn answer(
        &self,
        id: Option<sonic_rs::Value>,
        method: &str,
        params: Option<sonic_rs::Value>,
    ) -> WireResponse {
        match method {
            METHOD_INITIALIZE => {
                success_response(id, HandlerResult::Initialize(InitializeResult::current()))
            }
            METHOD_PING => success_response(id, HandlerResult::Empty(EmptyResult {})),
            METHOD_TOOLS_LIST => {
                success_response(id, HandlerResult::ToolsList(ToolsListResult::current()))
            }
            METHOD_TOOLS_CALL => self.answer_call(id, params),
            _ => {
                let unknown =
                    CoreError::new(ErrorCode::ENotFound, format!("unknown method `{method}`"));
                error_response(id, METHOD_NOT_FOUND, &unknown)
            }
        }
    }

    /// Answers one `tools/call`: resolves the tool, opens the store, and
    /// runs the typed dispatch.
    fn answer_call(
        &self,
        id: Option<sonic_rs::Value>,
        params: Option<sonic_rs::Value>,
    ) -> WireResponse {
        let Some(params) = params else {
            let missing = CoreError::new(
                ErrorCode::EInvalid,
                "tools/call requires params with `name` and `arguments`",
            );
            return error_response(id, INVALID_PARAMS, &missing);
        };
        let params_bytes = match sonic_rs::to_vec(&params) {
            Ok(bytes) => bytes,
            Err(err) => {
                let failure = CoreError::new(ErrorCode::EIo, format!("params render: {err}"));
                return error_response(id, INTERNAL_ERROR, &failure);
            }
        };
        let call = match ruk_core::protocol::decode_json::<ToolsCallParams>(&params_bytes) {
            Ok(call) => call,
            Err(err) => return error_response(id, INVALID_PARAMS, &err),
        };
        let Some(name) = call.name else {
            let missing = CoreError::new(ErrorCode::EInvalid, "tools/call params require a `name`");
            return error_response(id, INVALID_PARAMS, &missing);
        };
        let tool = match Tool::from_name(&name) {
            Ok(tool) => tool,
            Err(err) => return error_response(id, INVALID_PARAMS, &err),
        };
        let args_bytes = match call.arguments {
            Some(arguments) => match sonic_rs::to_vec(&arguments) {
                Ok(bytes) => bytes,
                Err(err) => {
                    let failure =
                        CoreError::new(ErrorCode::EIo, format!("arguments render: {err}"));
                    return error_response(id, INTERNAL_ERROR, &failure);
                }
            },
            None => b"null".to_vec(),
        };
        let store = match open_store(&self.repo) {
            Ok(store) => store,
            Err(err) => return error_response(id, INTERNAL_ERROR, &err),
        };
        match call_on_store(&store, tool, &args_bytes) {
            Ok(result_json) => match String::from_utf8(result_json) {
                Ok(text) => success_response(id, HandlerResult::ToolCall(ToolCallResult::ok(text))),
                Err(err) => {
                    let failure = CoreError::new(ErrorCode::EIo, format!("result text: {err}"));
                    error_response(id, INTERNAL_ERROR, &failure)
                }
            },
            Err(err) => {
                if err.code == ErrorCode::EInvalid {
                    error_response(id, INVALID_PARAMS, &err)
                } else {
                    success_response(
                        id,
                        HandlerResult::ToolCall(ToolCallResult::tool_error(&err)),
                    )
                }
            }
        }
    }
}

/// Serves the MCP stdio transport for one repository root.
///
/// This is the dispatch key the binary root calls: route one subcommand
/// here with the locked stdio handles.
///
/// # Errors
/// `E_IO` when the reader or the writer fails.
pub(crate) fn serve(
    repo: &Path,
    reader: impl BufRead,
    writer: impl Write,
) -> Result<(), CoreError> {
    Server::new(repo.to_path_buf()).serve_stdio(reader, writer)
}

impl InitializeResult {
    /// The current server identity and capabilities.
    fn current() -> Self {
        Self {
            protocol_version: MCP_PROTOCOL_VERSION,
            capabilities: InitializeCapabilities {
                tools: ToolsCapability {},
            },
            server_info: ServerInfo {
                name: SERVER_NAME,
                version: SERVER_VERSION,
            },
        }
    }
}

impl ToolsListResult {
    /// The full tool table with each tool's advertised input schema.
    fn current() -> Self {
        Self {
            tools: TOOL_TABLE
                .iter()
                .map(|info| ToolListEntry {
                    name: info.name,
                    description: info.description,
                    input_schema: InputSchema {
                        kind: "object",
                        description: format!(
                            "Decodes as {}; unknown fields are rejected.",
                            info.params_type
                        ),
                        params_type: info.params_type,
                    },
                })
                .collect(),
        }
    }
}

impl ToolCallResult {
    /// A successful tool answer carrying a JSON document as text.
    fn ok(text: String) -> Self {
        Self {
            content: vec![ContentPart { kind: "text", text }],
            is_error: false,
        }
    }

    /// A failed tool answer whose text starts with the CoreError code.
    fn tool_error(error: &CoreError) -> Self {
        Self {
            content: vec![ContentPart {
                kind: "text",
                text: format!("{}: {}", error.code.as_str(), error.message),
            }],
            is_error: true,
        }
    }
}

/// Builds a successful response.
fn success_response(id: Option<sonic_rs::Value>, result: HandlerResult) -> WireResponse {
    WireResponse {
        jsonrpc: JSONRPC_VERSION,
        id,
        result: Some(result),
        error: None,
    }
}

/// Builds an error response carrying the CoreError code.
fn error_response(id: Option<sonic_rs::Value>, code: i32, error: &CoreError) -> WireResponse {
    WireResponse {
        jsonrpc: JSONRPC_VERSION,
        id,
        result: None,
        error: Some(RpcError {
            code,
            message: error.message.clone(),
            data: Some(ErrorData {
                core_code: error.code.as_str().to_owned(),
                detail: error.message.clone(),
            }),
        }),
    }
}

/// Renders a response, falling back to a static internal error when the
/// response itself cannot render.
fn render_response(response: &WireResponse) -> Vec<u8> {
    sonic_rs::to_vec(response).unwrap_or_else(|_| {
        br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"response render failed"}}"#.to_vec()
    })
}

/// Opens the store exactly as the CLI commands do.
fn open_store(path: &Path) -> Result<Store, CoreError> {
    Store::open(
        path,
        std::sync::Arc::new(PreparationBudget::reference_defaults()),
    )
    .map_err(|err| CoreError::new(err.code(), err.to_string()))
}

/// Maps a transport failure to `E_IO`.
fn io_error(err: std::io::Error) -> CoreError {
    CoreError::new(ErrorCode::EIo, format!("input/output: {err}"))
}

/// Writes one framed response.
fn write_response(writer: &mut impl Write, response: &[u8]) -> Result<(), CoreError> {
    writer.write_all(response).map_err(io_error)?;
    writer.write_all(b"\n").map_err(io_error)?;
    writer.flush().map_err(io_error)?;
    Ok(())
}

/// How one bounded line read ended.
enum LineRead {
    /// The reader ended.
    Eof,
    /// One full line, newline-terminated or trailing at end of input.
    Line,
    /// The line runs past the bound without a newline.
    TooLong,
}

/// Reads one line without buffering past the control-frame bound.
fn read_line_bounded(reader: &mut impl BufRead, buf: &mut Vec<u8>) -> Result<LineRead, CoreError> {
    let bound = u64::try_from(MAX_CONTROL_FRAME_BYTES).map_err(|_| {
        CoreError::new(
            ErrorCode::ELimit,
            "control frame bound exceeds the input range",
        )
    })?;
    let mut limited = std::io::Read::take(reader.by_ref(), bound + 1);
    limited.read_until(b'\n', buf).map_err(io_error)?;
    if buf.is_empty() {
        return Ok(LineRead::Eof);
    }
    if buf.len() > MAX_CONTROL_FRAME_BYTES && !buf.ends_with(b"\n") {
        return Ok(LineRead::TooLong);
    }
    Ok(LineRead::Line)
}

/// Discards the remainder of an over-long line through end of line or input.
fn drain_line(reader: &mut impl BufRead) -> Result<(), CoreError> {
    let mut chunk = [0u8; 8192];
    loop {
        let read = reader.read(&mut chunk).map_err(io_error)?;
        if read == 0 || chunk[..read].contains(&b'\n') {
            return Ok(());
        }
    }
}

/// Strips leading blanks and trailing carriage returns and newlines.
fn trimmed(buf: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < buf.len() && (buf[start] == b' ' || buf[start] == b'\t') {
        start += 1;
    }
    let mut end = buf.len();
    while end > start && (buf[end - 1] == b'\n' || buf[end - 1] == b'\r') {
        end -= 1;
    }
    match buf.get(start..end) {
        Some(document) => document,
        None => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use ruk_core::bytes::ByteString;
    use ruk_core::change::ChangeId;
    use ruk_core::conflict::{Signature, TzOffset};
    use ruk_core::ids::HashKind;
    use ruk_core::ops::{DescribeRequest, NewRequest, NewResult};
    use ruk_core::protocol::{AttestListArgs, PageRequest, QueryArgs, RevsetText};

    #[derive(Debug, serde::Serialize)]
    struct Envelope<P: serde::Serialize> {
        jsonrpc: &'static str,
        id: u64,
        method: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        params: Option<P>,
    }

    #[derive(Debug, serde::Serialize)]
    struct NamedCall<A: serde::Serialize> {
        name: &'static str,
        arguments: A,
    }

    #[derive(Debug, serde::Deserialize)]
    struct TestResponse {
        #[serde(default)]
        result: Option<sonic_rs::Value>,
        #[serde(default)]
        error: Option<TestError>,
    }

    #[derive(Debug, serde::Deserialize)]
    struct TestError {
        code: i32,
        message: String,
        #[serde(default)]
        data: Option<TestErrorData>,
    }

    #[derive(Debug, serde::Deserialize)]
    struct TestErrorData {
        core_code: String,
    }

    #[derive(Debug, serde::Deserialize)]
    struct InitResult {
        #[serde(rename = "protocolVersion")]
        protocol_version: String,
        #[serde(rename = "serverInfo")]
        server_info: ServerName,
    }

    #[derive(Debug, serde::Deserialize)]
    struct ServerName {
        name: String,
    }

    #[derive(Debug, serde::Deserialize)]
    struct ListResult {
        tools: Vec<ListedTool>,
    }

    #[derive(Debug, serde::Deserialize)]
    struct ListedTool {
        name: String,
        #[serde(rename = "inputSchema")]
        input_schema: ListedSchema,
    }

    #[derive(Debug, serde::Deserialize)]
    struct ListedSchema {
        #[serde(rename = "type")]
        kind: String,
    }

    #[derive(Debug, serde::Deserialize)]
    struct CallResult {
        content: Vec<CallPart>,
        #[serde(rename = "isError")]
        is_error: bool,
    }

    #[derive(Debug, serde::Deserialize)]
    struct CallPart {
        #[serde(rename = "type")]
        kind: String,
        text: String,
    }

    #[derive(Debug, serde::Deserialize)]
    struct AttestationAnswer {
        records: Vec<ruk_core::protocol::AttestationRecord>,
        next: Option<String>,
    }

    fn test_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("ruk-mcp-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create test root");
        root
    }

    fn fixture_tree(root: &Path) -> ruk_core::ids::Oid {
        let store = Store::create(
            root,
            HashKind::Sha1,
            std::sync::Arc::new(PreparationBudget::reference_defaults()),
        )
        .expect("create store");
        let mut tree_bytes = Vec::from(b"100644 xa".as_slice());
        tree_bytes.push(0);
        tree_bytes.extend_from_slice(&[0x11; 20]);
        let prepared = store
            .prepare(
                ruk_core::store::types::ObjectKind::Tree,
                u64::try_from(tree_bytes.len()).expect("test tree fits u64"),
                Cursor::new(&tree_bytes),
                None,
            )
            .expect("prepare tree");
        let tree = prepared.oid();
        store.publish(vec![prepared], &[]).expect("publish tree");
        tree
    }

    fn fixture_signature() -> Signature {
        Signature {
            name: ByteString::from("Ada"),
            email: ByteString::from("ada@example.invalid"),
            timestamp: 1_700_000_000,
            offset: TzOffset::UTC,
        }
    }

    fn request_line<P: serde::Serialize>(
        id: u64,
        method: &'static str,
        params: Option<P>,
    ) -> Vec<u8> {
        let envelope = Envelope {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };
        sonic_rs::to_vec(&envelope).expect("encode request")
    }

    fn run_lines(server: &Server, lines: &[Vec<u8>]) -> Vec<TestResponse> {
        let mut input = Vec::new();
        for line in lines {
            input.extend_from_slice(line);
            input.push(b'\n');
        }
        let mut reader = Cursor::new(input);
        let mut writer = Cursor::new(Vec::new());
        server
            .serve_stdio(&mut reader, &mut writer)
            .expect("serve stdio");
        writer
            .into_inner()
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| sonic_rs::from_slice(line).expect("decode response"))
            .collect()
    }

    fn result_of(response: &TestResponse) -> &sonic_rs::Value {
        response.result.as_ref().expect("success carries a result")
    }

    fn call_result_of(response: &TestResponse) -> CallResult {
        let result = result_of(response);
        sonic_rs::from_slice(&sonic_rs::to_vec(result).expect("render result"))
            .expect("decode call result")
    }

    #[test]
    fn initialize_and_list_round_trip_over_stdio() {
        let root = test_root("init-list");
        let server = Server::new(root.clone());
        let lines = vec![
            request_line::<()>(1, METHOD_INITIALIZE, None),
            request_line::<()>(2, METHOD_TOOLS_LIST, None),
        ];
        let responses = run_lines(&server, &lines);
        assert_eq!(responses.len(), 2);

        let init: InitResult =
            sonic_rs::from_slice(&sonic_rs::to_vec(result_of(&responses[0])).expect("render"))
                .expect("decode init");
        assert_eq!(init.protocol_version, MCP_PROTOCOL_VERSION);
        assert_eq!(init.server_info.name, SERVER_NAME);

        let list: ListResult =
            sonic_rs::from_slice(&sonic_rs::to_vec(result_of(&responses[1])).expect("render"))
                .expect("decode list");
        assert_eq!(list.tools.len(), TOOL_TABLE.len());
        for (listed, info) in list.tools.iter().zip(TOOL_TABLE.iter()) {
            assert_eq!(listed.name, info.name);
            assert_eq!(listed.input_schema.kind, "object");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn new_and_describe_round_trip_over_stdio() {
        let root = test_root("new-describe");
        let tree = fixture_tree(&root);
        let server = Server::new(root.clone());
        let signature = fixture_signature();
        let change_id = ChangeId::generate();
        let new_request = NewRequest {
            tree,
            parents: Vec::new(),
            author: signature.clone(),
            committer: signature,
            message: ByteString::from("root\n"),
            change_id: Some(change_id),
            predecessor: None,
            provenance: None,
        };
        let new_call = NamedCall {
            name: Tool::NewCommit.name(),
            arguments: new_request,
        };
        let responses = run_lines(
            &server,
            &[request_line(1, METHOD_TOOLS_CALL, Some(new_call))],
        );
        assert_eq!(responses.len(), 1);
        let call = call_result_of(&responses[0]);
        assert!(!call.is_error);
        assert_eq!(call.content.len(), 1);
        assert_eq!(call.content[0].kind, "text");
        let created: NewResult =
            sonic_rs::from_str(&call.content[0].text).expect("decode new result");
        assert_eq!(created.change_id, change_id);

        let describe_call = NamedCall {
            name: Tool::DescribeChange.name(),
            arguments: DescribeRequest::commit(created.head),
        };
        let responses = run_lines(
            &server,
            &[request_line(2, METHOD_TOOLS_CALL, Some(describe_call))],
        );
        let call = call_result_of(&responses[0]);
        assert!(!call.is_error);
        assert!(call.content[0].text.contains("root"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn bad_params_unknown_tool_and_unknown_method_fail_typed() {
        let root = test_root("errors");
        // A real store must exist: tools/call decodes arguments against it.
        let _ = fixture_tree(&root);
        let server = Server::new(root.clone());
        let mistyped = NamedCall {
            name: Tool::DescribeChange.name(),
            arguments: "not an object",
        };
        let unknown = NamedCall {
            name: "no_such_tool",
            arguments: DescribeRequest::change(ChangeId::generate()),
        };
        let lines = vec![
            request_line(1, METHOD_TOOLS_CALL, Some(mistyped)),
            request_line(2, METHOD_TOOLS_CALL, Some(unknown)),
            request_line::<()>(3, "bogus/method", None),
        ];
        let responses = run_lines(&server, &lines);
        assert_eq!(responses.len(), 3);

        let mistyped_error = responses[0].error.as_ref().expect("mistyped fails");
        assert_eq!(mistyped_error.code, INVALID_PARAMS);
        assert_eq!(
            mistyped_error
                .data
                .as_ref()
                .expect("code attached")
                .core_code,
            "E_INVALID"
        );

        let unknown_error = responses[1].error.as_ref().expect("unknown tool fails");
        assert_eq!(unknown_error.code, INVALID_PARAMS);
        assert_eq!(
            unknown_error
                .data
                .as_ref()
                .expect("code attached")
                .core_code,
            "E_NOT_FOUND"
        );

        let method_error = responses[2].error.as_ref().expect("unknown method fails");
        assert_eq!(method_error.code, METHOD_NOT_FOUND);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn degraded_reads_answer_with_local_semantics() {
        let root = test_root("degraded");
        let _ = fixture_tree(&root);
        let server = Server::new(root.clone());
        let revset = NamedCall {
            name: Tool::RevsetEval.name(),
            arguments: QueryArgs {
                revset: RevsetText::new("all()").expect("literal revset"),
                page: PageRequest::default(),
            },
        };
        let refs = NamedCall {
            name: Tool::RefsList.name(),
            arguments: PageRequest::default(),
        };
        let attestations = NamedCall {
            name: Tool::AttestationQuery.name(),
            arguments: AttestListArgs::default(),
        };
        let lines = vec![
            request_line(1, METHOD_TOOLS_CALL, Some(revset)),
            request_line(2, METHOD_TOOLS_CALL, Some(refs)),
            request_line(3, METHOD_TOOLS_CALL, Some(attestations)),
        ];
        let responses = run_lines(&server, &lines);
        assert_eq!(responses.len(), 3);

        let revset_error = responses[0]
            .error
            .as_ref()
            .expect("unsupported revset fails");
        assert_eq!(revset_error.code, INVALID_PARAMS);
        assert_eq!(
            revset_error.data.as_ref().expect("code attached").core_code,
            "E_INVALID"
        );
        assert!(revset_error.message.contains("E_UNSUPPORTED_OPERATION"));

        let refs_call = call_result_of(&responses[1]);
        assert!(!refs_call.is_error);
        let page: ruk_core::refs::RefPage =
            sonic_rs::from_str(&refs_call.content[0].text).expect("decode ref page");
        assert!(page.entries.is_empty());
        assert!(!page.more);

        let attestation_call = call_result_of(&responses[2]);
        assert!(!attestation_call.is_error);
        let answer: AttestationAnswer =
            sonic_rs::from_str(&attestation_call.content[0].text).expect("decode answer");
        assert!(answer.records.is_empty());
        assert_eq!(answer.next, None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn notifications_are_accepted_without_an_answer() {
        let root = test_root("notifications");
        let server = Server::new(root.clone());
        let response = server.handle(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        assert!(response.is_none());
        let _ = std::fs::remove_dir_all(&root);
    }
}
