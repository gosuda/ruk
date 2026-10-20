//! Hosted receive policy: judging pushes through daemon hook callbacks.
//!
//! [`HostPolicy`] implements [`ReceivePolicy`] by sending [`HookCall`]
//! frames to the hosting daemon's callback consumer and applying its
//! [`HookReply`] verdicts. The blocking serve thread and the async frame
//! pump meet at a bounded channel: the policy sends one exchange and
//! blocks for its reply, while the pump relays frames both ways. Every
//! exchange failure fails closed to a whole-push refusal, and verdicts
//! that do not cover the batch exactly reject the whole push.

use std::sync::Mutex;
use std::time::Duration;

use ruk_core::capability::Capabilities;
use tokio::sync::{mpsc, oneshot};

use super::policy::{LandedRefs, ReceiveBatch, ReceivePolicy, RefVerdict};
use super::proc_receive::AlternateRef;

/// Hook callback phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookPhase {
    /// Judge the push before anything publishes.
    PreReceive,
    /// Observe the landing after the CAS path; advisory only.
    PostReceive,
}

/// One command inside a [`HookCall`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HookCommand {
    /// Full ref name.
    pub name: String,
    /// Expected value as hex (`0{40}` creates the ref).
    pub old: String,
    /// Desired value as hex (`0{40}` deletes the ref).
    pub new: String,
    /// Whether the session's `push_refs` capability covers this ref.
    /// An accept for an unauthorized command is ignored.
    pub authorized: bool,
}

/// A daemon hook callback request, sent as a kind-12 frame.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HookCall {
    /// Which callback this is.
    pub phase: HookPhase,
    /// The judged commands.
    pub commands: Vec<HookCommand>,
    /// Push option lines in wire order.
    pub push_options: Vec<String>,
    /// New commit tips introduced by the push, as hex.
    pub new_commits: Vec<String>,
    /// Staged object payload bytes.
    pub pack_bytes: u64,
    /// Milliseconds the pump waits for the reply before failing closed.
    pub deadline_ms: u64,
}

/// One ref verdict inside a [`HookReply`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HookRefVerdict {
    /// Full ref name.
    pub name: String,
    /// The verdict for this ref.
    pub verdict: HookVerdict,
}

/// One ref's verdict.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookVerdict {
    /// Apply through the CAS path.
    Accept,
    /// Report `ng` with this reason (at most 512 bytes).
    Reject {
        /// In-band reason for the client's `ng` line.
        reason: String,
    },
    /// Report `ok` for the original ref and write this review ref
    /// through the CAS path. Must sit under `refs/changes/`.
    Divert {
        /// The review ref to write.
        review_ref: String,
    },
}

/// A daemon hook callback reply, sent as a kind-13 frame.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HookReply {
    /// Refuse every undecided command when true, ignoring `verdicts`.
    pub reject_all: bool,
    /// Why the whole push was refused, if it was.
    pub reason: Option<String>,
    /// One verdict per judged command.
    pub verdicts: Vec<HookRefVerdict>,
}

impl HookReply {
    /// Fails a whole push closed with one reason.
    #[must_use]
    pub fn reject_all(reason: impl Into<String>) -> Self {
        Self {
            reject_all: true,
            reason: Some(reason.into()),
            verdicts: Vec::new(),
        }
    }
}

/// One hook exchange: the callback request plus the reply slot.
#[derive(Debug)]
pub struct HookExchange {
    /// The callback to relay.
    pub call: HookCall,
    /// Where the pump delivers the reply.
    pub reply: oneshot::Sender<HookReply>,
}

/// The policy end of the hook bridge.
#[derive(Debug)]
pub struct HookClient {
    sender: mpsc::Sender<HookExchange>,
}

impl HookClient {
    /// Sends one callback and blocks for its reply. Any exchange
    /// failure (closed channel, dropped pump) fails closed to a
    /// whole-push refusal; the pump enforces the deadline and answers
    /// with its own refusal on expiry.
    fn exchange(&self, call: HookCall) -> HookReply {
        let (tx, rx) = oneshot::channel();
        if self
            .sender
            .blocking_send(HookExchange { call, reply: tx })
            .is_err()
        {
            return HookReply::reject_all("hook channel closed");
        }
        rx.blocking_recv()
            .unwrap_or_else(|_| HookReply::reject_all("hook pump went away"))
    }
}

/// The pump end of the hook bridge, driven by the async frame task.
#[derive(Debug)]
pub struct HookServer {
    receiver: mpsc::Receiver<HookExchange>,
}

impl HookServer {
    /// Receives the next hook exchange, if the policy asked for one.
    pub async fn recv(&mut self) -> Option<HookExchange> {
        self.receiver.recv().await
    }
}

/// Builds one bridge: the policy sends exchanges, the pump relays them.
#[must_use]
pub fn hook_bridge() -> (HookClient, HookServer) {
    let (sender, receiver) = mpsc::channel(4);
    (HookClient { sender }, HookServer { receiver })
}

/// The review-ref namespace diverted refs land under.
pub const REVIEW_REF_PREFIX: &str = "refs/changes";

/// Maximum bytes of a hook refusal reason; longer reasons truncate on a
/// character boundary.
pub const MAX_REASON_BYTES: usize = 512;

/// Truncates a hook refusal reason to the wire bound.
#[must_use]
pub fn truncate_reason(reason: &str) -> String {
    if reason.len() <= MAX_REASON_BYTES {
        return reason.to_owned();
    }
    let mut end = MAX_REASON_BYTES;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason[..end].to_owned()
}

/// Whether a review ref sits under the review namespace.
#[must_use]
pub fn is_review_ref(name: &str) -> bool {
    name == REVIEW_REF_PREFIX
        || name
            .strip_prefix(REVIEW_REF_PREFIX)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The hosted callback policy: every verdict arrives over hook frames.
///
/// The policy holds the session capabilities for the `authorized` flags
/// and the callback deadline. It remembers the judged batch plus its
/// verdicts so the advisory `post-receive` reports exactly what landed
/// without re-parsing.
#[derive(Debug)]
pub struct HostPolicy {
    capabilities: Capabilities,
    deadline_ms: u64,
    client: HookClient,
    state: Mutex<Option<PreState>>,
    pending: Mutex<Option<PendingPost>>,
}

#[derive(Debug)]
struct PreState {
    commands: Vec<StoredCommand>,
    verdicts: Vec<RefVerdict>,
    new_commits: Vec<String>,
    pack_bytes: u64,
    push_options: Vec<String>,
}

/// An advisory post-receive callback stashed by the serve and pumped
/// by the daemon after the receipt write and the report delivery.
#[derive(Debug)]
struct PendingPost {
    commands: Vec<HookCommand>,
    push_options: Vec<String>,
    new_commits: Vec<String>,
    pack_bytes: u64,
}

#[derive(Debug)]
struct StoredCommand {
    name: String,
    old: String,
    new: String,
    authorized: bool,
    live: bool,
}

impl HostPolicy {
    /// Builds one hosted policy for a push: session capabilities for
    /// authorization, the callback deadline, and the bridge client.
    /// The pump enforces the deadline; the policy blocks without its
    /// own timer and fails closed on any exchange failure.
    #[must_use]
    pub fn new(capabilities: Capabilities, deadline: Duration, client: HookClient) -> Self {
        Self {
            capabilities,
            deadline_ms: u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
            client,
            state: Mutex::new(None),
            pending: Mutex::new(None),
        }
    }

    /// Whether the session may push this ref.
    fn authorized(&self, name: &[u8]) -> bool {
        self.capabilities
            .push_refs
            .iter()
            .any(|pattern| pattern.matches(name))
    }

    /// Takes the deferred advisory post-receive callback the serve
    /// stashed, if any. The daemon pumps it after the receipt write
    /// and the report delivery; its reply never touches the landed
    /// push. On a replayed push nothing is taken, so the advisory
    /// never fires twice for one landing.
    #[must_use]
    pub fn take_post_receive(&self) -> Option<HookCall> {
        let pending = self.pending.lock().expect("hook pending lock").take()?;
        Some(HookCall {
            phase: HookPhase::PostReceive,
            commands: pending.commands,
            push_options: pending.push_options,
            new_commits: pending.new_commits,
            pack_bytes: pending.pack_bytes,
            deadline_ms: self.deadline_ms,
        })
    }

    /// Maps one callback reply onto per-command verdicts. Anything that
    /// is not exactly one verdict per live command naming a known ref
    /// rejects the whole push: missing, duplicate, and unknown refs are
    /// all fail-closed. Verdicts for already-decided commands are
    /// ignored, like the serve path ignores them.
    fn map_reply(commands: &[StoredCommand], reply: HookReply) -> Vec<RefVerdict> {
        let fill = |verdict: RefVerdict| commands.iter().map(|_| verdict.clone()).collect();
        // Protocol-level failures refuse the whole push AND drop the
        // staging unpublished, mirroring a `pre-receive` decline:
        // untrusted objects from a refused callback never enter the
        // store, not even unreachable.
        let refuse_push = |reason: String| {
            fill(RefVerdict::RejectPush {
                reason: truncate_reason(&reason),
            })
        };
        if reply.reject_all {
            let reason = reply
                .reason
                .unwrap_or_else(|| "hook rejected the push".to_owned());
            return refuse_push(reason);
        }
        let mut by_name: std::collections::HashMap<&str, &HookVerdict> =
            std::collections::HashMap::new();
        for verdict in &reply.verdicts {
            if by_name
                .insert(verdict.name.as_str(), &verdict.verdict)
                .is_some()
            {
                let reason = format!("hook answered ref `{}` twice", verdict.name);
                return refuse_push(reason);
            }
        }
        for verdict in &reply.verdicts {
            if !commands.iter().any(|c| c.name == verdict.name) {
                let reason = format!("hook answered unknown ref `{}`", verdict.name);
                return refuse_push(reason);
            }
        }
        let mut out = Vec::with_capacity(commands.len());
        for command in commands {
            if !command.live {
                out.push(RefVerdict::Accept);
                continue;
            }
            let Some(decision) = by_name.get(command.name.as_str()) else {
                let reason = format!("hook left ref `{}` undecided", command.name);
                return refuse_push(reason);
            };
            match decision {
                HookVerdict::Accept => {
                    if command.authorized {
                        out.push(RefVerdict::Accept);
                    } else {
                        out.push(RefVerdict::Reject {
                            reason: format!("hook accepted unauthorized ref `{}`", command.name),
                        });
                    }
                }
                HookVerdict::Reject { reason } => out.push(RefVerdict::Reject {
                    reason: truncate_reason(reason),
                }),
                HookVerdict::Divert { review_ref } => {
                    if !command.authorized {
                        out.push(RefVerdict::Reject {
                            reason: format!("hook diverted unauthorized ref `{}`", command.name),
                        });
                    } else if !is_review_ref(review_ref) {
                        out.push(RefVerdict::Reject {
                            reason: format!(
                                "review ref `{review_ref}` escapes {REVIEW_REF_PREFIX}/"
                            ),
                        });
                    } else {
                        out.push(RefVerdict::Divert {
                            alternate: AlternateRef {
                                refname: review_ref.as_bytes().to_vec(),
                                old_oid: None,
                                new_oid: None,
                                forced: false,
                            },
                            write_through_cas: true,
                        });
                    }
                }
            }
        }
        out
    }
}

impl ReceivePolicy for HostPolicy {
    fn needs_quarantine(&self) -> bool {
        false
    }

    fn quarantine_parent(&self) -> Option<std::path::PathBuf> {
        None
    }

    fn pre_receive(&self, batch: &ReceiveBatch<'_>) -> Vec<RefVerdict> {
        let stored: Vec<StoredCommand> = batch
            .commands
            .iter()
            .map(|command| {
                let name = String::from_utf8_lossy(&command.name).into_owned();
                let authorized = command.live && self.authorized(&command.name);
                StoredCommand {
                    old: command.old.to_hex(),
                    new: command.new.to_hex(),
                    name,
                    authorized,
                    live: command.live,
                }
            })
            .collect();
        if !stored.iter().any(|command| command.authorized) {
            // Refused before any callback: no command carries push
            // authority, so no HookCall frame is emitted, and the
            // untrusted staging drops unpublished.
            return stored
                .iter()
                .map(|_| RefVerdict::RejectPush {
                    reason: "no push_refs capability covers this push".to_owned(),
                })
                .collect();
        }
        let call = HookCall {
            phase: HookPhase::PreReceive,
            commands: stored
                .iter()
                .map(|command| HookCommand {
                    name: command.name.clone(),
                    old: command.old.clone(),
                    new: command.new.clone(),
                    authorized: command.authorized,
                })
                .collect(),
            push_options: batch.push_options.to_vec(),
            new_commits: batch.new_commits.iter().map(|oid| oid.to_hex()).collect(),
            pack_bytes: batch.pack_bytes,
            deadline_ms: self.deadline_ms,
        };
        let reply = self.client.exchange(call);
        let verdicts = Self::map_reply(&stored, reply);
        *self.state.lock().expect("hook state lock") = Some(PreState {
            commands: stored,
            verdicts: verdicts.clone(),
            new_commits: batch.new_commits.iter().map(|oid| oid.to_hex()).collect(),
            pack_bytes: batch.pack_bytes,
            push_options: batch.push_options.to_vec(),
        });
        verdicts
    }

    fn post_receive(&self, landed: &LandedRefs<'_>) {
        let state = self.state.lock().expect("hook state lock").take();
        let Some(state) = state else {
            return;
        };
        if landed.lines.is_empty() {
            return;
        }
        let landed_commands: Vec<HookCommand> = state
            .commands
            .into_iter()
            .zip(state.verdicts)
            .filter_map(|(command, verdict)| {
                matches!(verdict, RefVerdict::Accept | RefVerdict::Divert { .. }).then(|| {
                    HookCommand {
                        name: command.name,
                        old: command.old,
                        new: command.new,
                        authorized: command.authorized,
                    }
                })
            })
            .collect();
        if landed_commands.is_empty() {
            return;
        }
        // Stashed, not exchanged: the daemon pumps the advisory
        // callback after the receipt write and the report delivery,
        // so a slow or absent answer never delays the push itself.
        *self.pending.lock().expect("hook pending lock") = Some(PendingPost {
            commands: landed_commands,
            push_options: state.push_options,
            new_commits: state.new_commits,
            pack_bytes: state.pack_bytes,
        });
    }
}
