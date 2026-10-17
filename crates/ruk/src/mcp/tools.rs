//! Typed MCP tool table over the ruk-core operation API.
//!
//! Each tool names the existing request type its arguments decode as, and
//! [`call_on_store`] decodes with [`ruk_core::protocol::decode_json`] so the
//! nesting bound, JSON syntax, and unknown-field checks that guard every
//! other boundary apply here too. A decode failure is a [`CoreError`] the
//! server reports; no tool coerces a mismatched document into a nearby
//! shape.
//!
//! The nine change operations run against the store exactly as the CLI's
//! `New` and `Describe` commands do. The three read tools that need
//! coordinator state degrade to the local semantics documented on
//! [`crate::mcp`]: `revset_eval` reports `E_UNSUPPORTED_OPERATION`,
//! `refs_list` pages without enforcing cursor binding, and
//! `attestation_query` reads with an allow-all checkpoint.

use ruk_core::attestation::{Progress, StatementFilter};
use ruk_core::error::{CoreError, ErrorCode};
use ruk_core::protocol::{AttestListArgs, AttestationRecord, PageLimit, PageRequest, QueryArgs};
use ruk_core::store::Store;

use ruk_core::ops::{
    AbandonRequest, DescribeRequest, EditRequest, NewRequest, RebaseRequest, ResolveRequest,
    RevertRequest, SplitRequest, SquashRequest,
};

/// The wire name of the `describe_change` tool.
pub const TOOL_DESCRIBE_CHANGE: &str = "describe_change";

/// The wire name of the `new_commit` tool.
pub const TOOL_NEW_COMMIT: &str = "new_commit";

/// The wire name of the `edit` tool.
pub const TOOL_EDIT: &str = "edit";

/// The wire name of the `split` tool.
pub const TOOL_SPLIT: &str = "split";

/// The wire name of the `squash` tool.
pub const TOOL_SQUASH: &str = "squash";

/// The wire name of the `rebase` tool.
pub const TOOL_REBASE: &str = "rebase";

/// The wire name of the `abandon` tool.
pub const TOOL_ABANDON: &str = "abandon";

/// The wire name of the `resolve` tool.
pub const TOOL_RESOLVE: &str = "resolve";

/// The wire name of the `revert` tool.
pub const TOOL_REVERT: &str = "revert";

/// The wire name of the `revset_eval` tool.
pub const TOOL_REVSET_EVAL: &str = "revset_eval";

/// The wire name of the `refs_list` tool.
pub const TOOL_REFS_LIST: &str = "refs_list";

/// The wire name of the `attestation_query` tool.
pub const TOOL_ATTESTATION_QUERY: &str = "attestation_query";

/// One exposed tool: its wire name, what it does, and the existing Rust
/// request type its arguments decode as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ToolInfo {
    /// The wire name accepted by `tools/call`.
    pub name: &'static str,
    /// What the tool does, including any degraded local semantics.
    pub description: &'static str,
    /// The existing request type the arguments decode as.
    pub params_type: &'static str,
}

/// The full tool table in wire order: nine change operations, then the three
/// degraded reads.
pub const TOOL_TABLE: &[ToolInfo] = &[
    ToolInfo {
        name: TOOL_DESCRIBE_CHANGE,
        description: "Describe one commit or one change in typed form; never publishes.",
        params_type: "ruk_core::ops::DescribeRequest",
    },
    ToolInfo {
        name: TOOL_NEW_COMMIT,
        description: "Create one native commit and publish it atomically.",
        params_type: "ruk_core::ops::NewRequest",
    },
    ToolInfo {
        name: TOOL_EDIT,
        description: "Rewrite one commit's message, identities, or tree under its change identity.",
        params_type: "ruk_core::ops::EditRequest",
    },
    ToolInfo {
        name: TOOL_SPLIT,
        description: "Split one commit into two consecutive commits within its change.",
        params_type: "ruk_core::ops::SplitRequest",
    },
    ToolInfo {
        name: TOOL_SQUASH,
        description: "Squash an ordered linear chain of commits into one commit.",
        params_type: "ruk_core::ops::SquashRequest",
    },
    ToolInfo {
        name: TOOL_REBASE,
        description: "Rebase one commit onto a new base with a caller-resolved tree.",
        params_type: "ruk_core::ops::RebaseRequest",
    },
    ToolInfo {
        name: TOOL_ABANDON,
        description: "Remove commits from their changes, abandoning emptied changes.",
        params_type: "ruk_core::ops::AbandonRequest",
    },
    ToolInfo {
        name: TOOL_RESOLVE,
        description: "Record a resolution of a conflicted commit with a resolved tree.",
        params_type: "ruk_core::ops::ResolveRequest",
    },
    ToolInfo {
        name: TOOL_REVERT,
        description: "Publish a fresh change undoing one commit's tree change.",
        params_type: "ruk_core::ops::RevertRequest",
    },
    ToolInfo {
        name: TOOL_REVSET_EVAL,
        description: "Validate a revset query; evaluation reports E_UNSUPPORTED_OPERATION without coordinator sessions.",
        params_type: "ruk_core::protocol::QueryArgs",
    },
    ToolInfo {
        name: TOOL_REFS_LIST,
        description: "Page stored refs; cursor position resumes, cursor binding is not enforced locally.",
        params_type: "ruk_core::protocol::PageRequest",
    },
    ToolInfo {
        name: TOOL_ATTESTATION_QUERY,
        description: "List verified attestations with an allow-all checkpoint; continuation is lowercase hex.",
        params_type: "ruk_core::protocol::AttestListArgs",
    },
];

/// Typed identity of one tool in [`TOOL_TABLE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tool {
    /// Reads one commit or change via `ops::describe`.
    DescribeChange,
    /// Publishes one commit via `ops::new`.
    NewCommit,
    /// Rewrites one commit via `ops::edit`.
    Edit,
    /// Splits one commit via `ops::split`.
    Split,
    /// Squashes a commit chain via `ops::squash`.
    Squash,
    /// Rebases one commit via `ops::rebase`.
    Rebase,
    /// Abandons commits via `ops::abandon`.
    Abandon,
    /// Resolves a conflicted commit via `ops::resolve`.
    Resolve,
    /// Reverts a commit via `ops::revert`.
    Revert,
    /// Validates a revset query; evaluation is unsupported locally.
    RevsetEval,
    /// Pages stored refs via `refs::page_refs`.
    RefsList,
    /// Lists verified attestations via `attestation::list`.
    AttestationQuery,
}

impl Tool {
    /// Resolves a wire name to its tool.
    ///
    /// # Errors
    /// `E_NOT_FOUND` naming the unknown tool.
    pub fn from_name(name: &str) -> Result<Self, CoreError> {
        match name {
            TOOL_DESCRIBE_CHANGE => Ok(Self::DescribeChange),
            TOOL_NEW_COMMIT => Ok(Self::NewCommit),
            TOOL_EDIT => Ok(Self::Edit),
            TOOL_SPLIT => Ok(Self::Split),
            TOOL_SQUASH => Ok(Self::Squash),
            TOOL_REBASE => Ok(Self::Rebase),
            TOOL_ABANDON => Ok(Self::Abandon),
            TOOL_RESOLVE => Ok(Self::Resolve),
            TOOL_REVERT => Ok(Self::Revert),
            TOOL_REVSET_EVAL => Ok(Self::RevsetEval),
            TOOL_REFS_LIST => Ok(Self::RefsList),
            TOOL_ATTESTATION_QUERY => Ok(Self::AttestationQuery),
            _ => Err(CoreError::new(
                ErrorCode::ENotFound,
                format!("unknown MCP tool `{name}`"),
            )),
        }
    }

    /// The wire name accepted by `tools/call`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DescribeChange => TOOL_DESCRIBE_CHANGE,
            Self::NewCommit => TOOL_NEW_COMMIT,
            Self::Edit => TOOL_EDIT,
            Self::Split => TOOL_SPLIT,
            Self::Squash => TOOL_SQUASH,
            Self::Rebase => TOOL_REBASE,
            Self::Abandon => TOOL_ABANDON,
            Self::Resolve => TOOL_RESOLVE,
            Self::Revert => TOOL_REVERT,
            Self::RevsetEval => TOOL_REVSET_EVAL,
            Self::RefsList => TOOL_REFS_LIST,
            Self::AttestationQuery => TOOL_ATTESTATION_QUERY,
        }
    }
}

/// Calls one tool against an open store and renders the result as a JSON document.
///
/// Arguments decode directly into the existing request type named by the
/// tool's table entry: `ruk_core::ops` requests for the nine change
/// operations, `protocol::QueryArgs` for `revset_eval`,
/// `protocol::PageRequest` for `refs_list`, and `protocol::AttestListArgs`
/// for `attestation_query`.
///
/// # Errors
/// The [`CoreError`] from argument decoding, the operation itself, or result
/// rendering. `revset_eval` always fails `E_INVALID` carrying
/// `E_UNSUPPORTED_OPERATION`.
pub fn call_on_store(store: &Store, tool: Tool, args_json: &[u8]) -> Result<Vec<u8>, CoreError> {
    match tool {
        Tool::DescribeChange => {
            let request: DescribeRequest = decode_args(args_json)?;
            render(&ruk_core::ops::describe(store, request)?)
        }
        Tool::NewCommit => {
            let request: NewRequest = decode_args(args_json)?;
            render(&ruk_core::ops::new(store, request)?)
        }
        Tool::Edit => {
            let request: EditRequest = decode_args(args_json)?;
            render(&ruk_core::ops::edit(store, request)?)
        }
        Tool::Split => {
            let request: SplitRequest = decode_args(args_json)?;
            render(&ruk_core::ops::split(store, request)?)
        }
        Tool::Squash => {
            let request: SquashRequest = decode_args(args_json)?;
            render(&ruk_core::ops::squash(store, request)?)
        }
        Tool::Rebase => {
            let request: RebaseRequest = decode_args(args_json)?;
            render(&ruk_core::ops::rebase(store, request)?)
        }
        Tool::Abandon => {
            let request: AbandonRequest = decode_args(args_json)?;
            render(&ruk_core::ops::abandon(store, request)?)
        }
        Tool::Resolve => {
            let request: ResolveRequest = decode_args(args_json)?;
            render(&ruk_core::ops::resolve(store, request)?)
        }
        Tool::Revert => {
            let request: RevertRequest = decode_args(args_json)?;
            render(&ruk_core::ops::revert(store, request)?)
        }
        Tool::RevsetEval => {
            let request: QueryArgs = decode_args(args_json)?;
            eval_revset(request)
        }
        Tool::RefsList => {
            let request: PageRequest = decode_args(args_json)?;
            list_refs(store, &request)
        }
        Tool::AttestationQuery => {
            let request: AttestListArgs = decode_args(args_json)?;
            query_attestations(store, request)
        }
    }
}

/// Decodes tool arguments into the tool's existing request type.
fn decode_args<T: serde::de::DeserializeOwned>(args_json: &[u8]) -> Result<T, CoreError> {
    ruk_core::protocol::decode_json(args_json)
}

/// Renders a tool result as a JSON document.
fn render<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, CoreError> {
    sonic_rs::to_vec(value)
        .map_err(|err| CoreError::new(ErrorCode::EIo, format!("schema render: {err}")))
}

/// Validates a revset query and reports that evaluation is unsupported
/// without coordinator sessions.
fn eval_revset(request: QueryArgs) -> Result<Vec<u8>, CoreError> {
    let _ = request;
    Err(CoreError::new(
        ErrorCode::EInvalid,
        "E_UNSUPPORTED_OPERATION: revset evaluation needs coordinator session authority and the private revset engine; open a session and call query instead",
    ))
}

/// Pages stored refs, reusing a cursor's position bytes as the resume key.
fn list_refs(store: &Store, request: &PageRequest) -> Result<Vec<u8>, CoreError> {
    let after: Option<&[u8]> = request
        .cursor
        .as_ref()
        .map(|cursor| cursor.position.as_bytes());
    let page = ruk_core::refs::page_refs(store, after, request.effective_limit())?;
    render(&page)
}

/// The local answer of the `attestation_query` tool.
#[derive(Debug, serde::Serialize)]
struct AttestationQueryResult {
    records: Vec<AttestationRecord>,
    next: Option<String>,
}

/// Lists verified attestations with an allow-all checkpoint.
fn query_attestations(store: &Store, request: AttestListArgs) -> Result<Vec<u8>, CoreError> {
    let after: Option<&[u8]> = request
        .page
        .cursor
        .as_ref()
        .map(|cursor| cursor.position.as_bytes());
    let filter = StatementFilter {
        subject: request.subject,
        kind: request.kind,
        signer: request.signer,
        include_superseded: request.include_superseded,
    };
    let limit = request.page.limit.unwrap_or(PageLimit::DEFAULT);
    let checkpoint = |_: Progress| Ok::<(), CoreError>(());
    let page = ruk_core::attestation::list(store, &filter, limit, after, &checkpoint)?;
    render(&AttestationQueryResult {
        records: page.records,
        next: page.next.as_deref().map(encode_hex),
    })
}

/// Renders bytes as lowercase hex.
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_names_round_trip_through_the_table() {
        assert_eq!(TOOL_TABLE.len(), 12);
        for info in TOOL_TABLE {
            let tool = Tool::from_name(info.name).expect("table names resolve");
            assert_eq!(tool.name(), info.name);
        }
        let unknown = Tool::from_name("no_such_tool").expect_err("unknown tools fail");
        assert_eq!(unknown.code, ErrorCode::ENotFound);
    }

    #[test]
    fn revset_eval_validates_then_reports_unsupported() {
        let args = QueryArgs {
            revset: ruk_core::protocol::RevsetText::new("all()").expect("literal revset"),
            page: PageRequest::default(),
        };
        let failure = eval_revset(args).expect_err("evaluation is unsupported");
        assert_eq!(failure.code, ErrorCode::EInvalid);
        assert!(failure.message.contains("E_UNSUPPORTED_OPERATION"));
    }

    #[test]
    fn hex_renders_lowercase_pairs() {
        assert_eq!(encode_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }
}
