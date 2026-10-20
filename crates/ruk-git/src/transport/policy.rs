//! Receive-pack policy: who decides per-ref verdicts.
//!
//! The serve path parses commands, stages the pack, then asks one
//! [`ReceivePolicy`] for verdicts before the CAS path. [`ScriptPolicy`]
//! runs the repository's hook scripts with byte-identical behavior to the
//! historical inline phases; [`NoPolicy`] accepts everything without
//! touching the filesystem. The hosted daemon's callback policy (a later
//! row) implements the same trait over its hook frames.

use std::path::PathBuf;

use ruk_core::ids::{HashKind, Oid};

use super::Interrupt;
use super::hooks::{Quarantine, ReceiveHooks, run_hook};
use super::proc_receive::{
    AlternateRef, ProcReceiveCommand, ProcVerdict, PushOptions, is_proc_receive_ref,
    run_proc_receive,
};

/// One wire command awaiting a verdict, in command order. The
/// `pre-receive` hook observes every command exactly as the client
/// sent it; only live commands reach the later phases.
#[derive(Clone, Debug)]
pub struct ReceiveCommand {
    /// Full ref name bytes.
    pub name: Vec<u8>,
    /// Expected value; the zero OID creates the ref.
    pub old: Oid,
    /// Desired value; the zero OID deletes the ref.
    pub new: Oid,
    /// False for duplicates and malformed names, which already carry
    /// their verdict before judging starts.
    pub live: bool,
}

/// One command's verdict, in batch order.
#[derive(Clone, Debug)]
pub enum RefVerdict {
    /// Apply through the CAS path.
    Accept,
    /// Report `ng` with this reason.
    Reject {
        /// In-band reason for the client's `ng` line.
        reason: String,
    },
    /// Refuse the whole push: every live ref reports `ng` and the
    /// staged pack drops unpublished, mirroring a `pre-receive` hook
    /// decline. The serve path checks for this before applying any
    /// per-ref verdict.
    RejectPush {
        /// In-band reason for every `ng` line.
        reason: String,
    },
    /// Report `ok` for the original ref while `post-receive` observes
    /// the hook-supplied review ref.
    Divert {
        /// The review ref the hook reported creating.
        alternate: AlternateRef,
    },
}

/// Everything a policy needs to judge one batch.
#[derive(Debug)]
pub struct ReceiveBatch<'a> {
    /// Live updates in command order.
    pub commands: &'a [ReceiveCommand],
    /// Push option lines in wire order.
    pub push_options: &'a [String],
    /// Whether the client negotiated `push-options`.
    pub push_options_negotiated: bool,
    /// Staged pack for hook inspection, when quarantine is enabled.
    pub quarantine: Option<&'a Quarantine>,
    /// Object format of the OIDs above.
    pub kind: HashKind,
    /// True when the client set the `atomic` capability: no review
    /// backend can span it, so every undecided ref is refused.
    pub atomic: bool,
    /// Cancellation source, forwarded to the hook conversation only;
    /// the serve path owns the coarse checks around the policy call.
    pub interrupt: &'a Interrupt,
}

/// Everything a policy needs to observe one landing.
#[derive(Debug)]
pub struct LandedRefs<'a> {
    /// `<old> <new> <ref>` lines of the landed refs, plus the
    /// hook-supplied review lines for diverted commands.
    pub lines: &'a str,
    /// Push option lines in wire order.
    pub push_options: &'a [String],
    /// Whether the client negotiated `push-options`.
    pub push_options_negotiated: bool,
    /// Staged pack for hook inspection, when quarantine is enabled.
    pub quarantine: Option<&'a Quarantine>,
}

/// Decides per-ref receive-pack verdicts.
pub trait ReceivePolicy {
    /// Whether the serve path stages a quarantine directory for hook
    /// inspection before judging.
    fn needs_quarantine(&self) -> bool;
    /// Where quarantine staging materializes. `None` stages nothing;
    /// script hooks resolve their configured parent (or the system
    /// temp directory) here when enabled.
    fn quarantine_parent(&self) -> Option<PathBuf>;
    /// Judges one batch, returning one verdict per command in order.
    fn pre_receive(&self, batch: &ReceiveBatch<'_>) -> Vec<RefVerdict>;
    /// Observes the landed refs after the CAS path. A refusal has no
    /// channel: the report already sent, so the reason is dropped and
    /// the push stays landed.
    fn post_receive(&self, landed: &LandedRefs<'_>);
}

/// Runs the repository's hook scripts. Every phase matches the
/// historical inline order byte for byte: `pre-receive` over all
/// commands, `update` per non-diverted ref, `proc-receive` for diverted
/// refs that survived, then `update` for fall-through refs.
#[derive(Debug)]
pub struct ScriptPolicy {
    hooks: ReceiveHooks,
}

impl ScriptPolicy {
    /// Wraps repository hooks for policy-driven serving.
    #[must_use]
    pub fn new(hooks: ReceiveHooks) -> Self {
        Self { hooks }
    }
}

fn hook_line(name: &[u8], old: Oid, new: Oid) -> String {
    format!(
        "{} {} {}\n",
        old.to_hex(),
        new.to_hex(),
        String::from_utf8_lossy(name),
    )
}

fn update_args(command: &ReceiveCommand) -> [String; 3] {
    [
        String::from_utf8_lossy(&command.name).into_owned(),
        command.old.to_hex(),
        command.new.to_hex(),
    ]
}

impl ReceivePolicy for ScriptPolicy {
    fn needs_quarantine(&self) -> bool {
        self.hooks.enabled()
    }

    fn quarantine_parent(&self) -> Option<PathBuf> {
        self.hooks.enabled().then(|| {
            self.hooks
                .quarantine_parent()
                .unwrap_or_else(std::env::temp_dir)
        })
    }

    fn pre_receive(&self, batch: &ReceiveBatch<'_>) -> Vec<RefVerdict> {
        let mut verdicts: Vec<Option<RefVerdict>> = batch.commands.iter().map(|_| None).collect();
        let options = PushOptions {
            values: batch.push_options,
            negotiated: batch.push_options_negotiated,
        };
        let all_lines: String = batch
            .commands
            .iter()
            .map(|command| hook_line(&command.name, command.old, command.new))
            .collect();
        if let Some(reason) = run_hook(
            &self.hooks,
            batch.quarantine,
            "pre-receive",
            &[],
            Some(all_lines.as_bytes()),
            batch.push_options,
            batch.push_options_negotiated,
        ) {
            return batch
                .commands
                .iter()
                .map(|_| RefVerdict::RejectPush {
                    reason: reason.clone(),
                })
                .collect();
        }
        for (command, verdict) in batch.commands.iter().zip(verdicts.iter_mut()) {
            if !command.live
                || is_proc_receive_ref(self.hooks.proc_receive_prefixes(), &command.name)
            {
                continue;
            }
            let args = update_args(command);
            if let Some(reason) = run_hook(
                &self.hooks,
                batch.quarantine,
                "update",
                &args,
                None,
                batch.push_options,
                batch.push_options_negotiated,
            ) {
                *verdict = Some(RefVerdict::Reject { reason });
            }
        }
        if batch.atomic {
            return verdicts
                .into_iter()
                .map(|verdict| {
                    verdict.unwrap_or(RefVerdict::Reject {
                        reason: "atomic pushes are not supported".to_owned(),
                    })
                })
                .collect();
        }
        let mut diverted: Vec<(usize, ProcReceiveCommand)> = Vec::new();
        for (index, command) in batch.commands.iter().enumerate() {
            if !command.live
                || verdicts[index].is_some()
                || !is_proc_receive_ref(self.hooks.proc_receive_prefixes(), &command.name)
            {
                continue;
            }
            diverted.push((
                index,
                ProcReceiveCommand {
                    old: command.old,
                    new: command.new,
                    name: command.name.clone(),
                },
            ));
        }
        if !diverted.is_empty() {
            let hook_commands: Vec<ProcReceiveCommand> = diverted
                .iter()
                .map(|(_, command)| command.clone())
                .collect();
            let outcomes = run_proc_receive(
                &self.hooks,
                batch.quarantine,
                &hook_commands,
                &options,
                batch.kind,
                batch.interrupt,
            );
            for ((index, _), outcome) in diverted.iter().zip(outcomes) {
                match outcome {
                    ProcVerdict::Accepted { alternate } => {
                        verdicts[*index] = Some(match alternate {
                            Some(alternate) => RefVerdict::Divert { alternate },
                            None => RefVerdict::Accept,
                        });
                    }
                    ProcVerdict::Rejected { reason } => {
                        verdicts[*index] = Some(RefVerdict::Reject { reason });
                    }
                    ProcVerdict::FallThrough => {
                        let command = &batch.commands[*index];
                        let args = update_args(command);
                        if let Some(reason) = run_hook(
                            &self.hooks,
                            batch.quarantine,
                            "update",
                            &args,
                            None,
                            batch.push_options,
                            batch.push_options_negotiated,
                        ) {
                            verdicts[*index] = Some(RefVerdict::Reject { reason });
                        }
                    }
                }
            }
        }
        verdicts
            .into_iter()
            .map(|verdict| verdict.unwrap_or(RefVerdict::Accept))
            .collect()
    }

    fn post_receive(&self, landed: &LandedRefs<'_>) {
        let _ = run_hook(
            &self.hooks,
            landed.quarantine,
            "post-receive",
            &[],
            Some(landed.lines.as_bytes()),
            landed.push_options,
            landed.push_options_negotiated,
        );
    }
}

/// Accepts every command without touching the filesystem: the policy for
/// callers without a repository directory.
#[derive(Debug)]
pub struct NoPolicy;

impl ReceivePolicy for NoPolicy {
    fn needs_quarantine(&self) -> bool {
        false
    }

    fn quarantine_parent(&self) -> Option<PathBuf> {
        None
    }

    fn pre_receive(&self, batch: &ReceiveBatch<'_>) -> Vec<RefVerdict> {
        // Atomicity spans no review backend either: match the script
        // path and refuse every undecided ref (with no hooks, all of them).
        if batch.atomic {
            return batch
                .commands
                .iter()
                .map(|_| RefVerdict::Reject {
                    reason: "atomic pushes are not supported".to_owned(),
                })
                .collect();
        }
        batch.commands.iter().map(|_| RefVerdict::Accept).collect()
    }

    fn post_receive(&self, _landed: &LandedRefs<'_>) {}
}
