//! MCP (Model Context Protocol) adapter surface over the ruk-core operation API.
//!
//! The adapter has two layers: [`tools`] holds the typed tool table and the
//! dispatch that decodes each tool's arguments directly into the existing
//! request type, and [`server`] speaks newline-delimited JSON-RPC 2.0 over
//! stdio (`initialize`, `tools/list`, `tools/call`, plus `ping`).
//!
//! Every tool schema reuses an existing serde type instead of defining a new
//! input shape: the nine change operations decode the `ruk_core::ops`
//! request types, `revset_eval` decodes `protocol::QueryArgs`,
//! `refs_list` decodes `protocol::PageRequest`, and `attestation_query`
//! decodes `protocol::AttestListArgs`. A mismatch is reported as an error,
//! never shimmed into a nearby shape.
//!
//! # Local semantics
//!
//! Coordinator sessions live behind `pub(crate)` boundaries, so there is no
//! session plumbing to call into. Every tool opens the store with
//! `Store::open` exactly as the `New` and `Describe` CLI commands do and
//! calls the `ruk_core::ops` API directly. Three tools degrade to documented
//! local semantics:
//!
//! * `revset_eval` validates its `QueryArgs` and then reports
//!   `E_UNSUPPORTED_OPERATION`: the revset engine is a private module and
//!   evaluation needs coordinator session authority.
//! * `refs_list` pages through `refs::page_refs`. A page cursor's position
//!   bytes are reused as the resume key, but cursor binding
//!   (store/view/query/lease) and lease expiry are not enforced locally.
//! * `attestation_query` reads through `attestation::list` with an
//!   allow-all checkpoint and returns the continuation as lowercase hex.
//!   There is no session-bound paging and no `ViewInfo`, both of which need
//!   the coordinator.
//!
//! # Parent wiring
//!
//! The binary root must declare `mod mcp;` and route one subcommand to
//! [`serve`], for example `Mcp { repo }` calling
//! `mcp::serve(&repo, std::io::stdin().lock(), std::io::stdout().lock())`.
//! No manifest change is needed: the adapter uses only the `ruk` crate's
//! existing dependencies (`ruk-core`, `serde`, `sonic-rs`).

pub(crate) mod server;
pub(crate) mod tools;

pub(crate) use server::serve;
