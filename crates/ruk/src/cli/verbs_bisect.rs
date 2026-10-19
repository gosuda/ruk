//! Bisect verb: `bisect start/bad/good/skip/reset/log/terms/run`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `bisect` | ancestor paint-down + detached checkout | implemented (`start`/`bad`/`good`/`skip`/`reset`/`log`/`terms`/`run`, `--first-parent`, `--no-checkout`, `--term-*`; `replay`/`visualize` are `Unsupported`) |
//!
//! Session state is ten pseudo-heads under `cli/pseudo/` (never refs, so
//! no ref-namespace or gc-root side effects): `BISECT_START` (the pre-run
//! `HEAD` as `branch:<short>` or `oid:<hex>`), `BISECT_BAD` (one hex),
//! `BISECT_GOODS` (newline-joined hexes), `BISECT_SKIPPED`
//! (newline-joined hexes), `BISECT_EXPECTED_REV` (the checkout the next
//! bare mark must sit on), `BISECT_HEAD` (last checked-out candidate),
//! `BISECT_TERMS` (bad term line, good term line), `BISECT_LOG`
//! (replayable action lines), and the `BISECT_FIRST_PARENT` /
//! `BISECT_NO_CHECKOUT` presence markers.
//!
//! The midpoint is git's `find_bisection` choice: with `total` interesting
//! commits (`bad` minus `goods`, first-parent-restricted when asked), each
//! candidate's weight is the interesting commits at or below it, and the
//! checkout is the candidate minimizing `|total - 2*weight|`, ties to the
//! newest. Linear history therefore halves every step (`~log2` marks).
//!
//! Oracle anchors: `git/builtin/bisect.c` (`cmd_bisect`, `find_bisection`).

use std::collections::HashSet;

use ruk_core::commit::CommitRecord;
use ruk_core::ids::Oid;
use ruk_core::store::Store;
use ruk_core::workspace::HeadRef;
use ruk_git::GitError;

use super::state::{
    commit_record, head_oid, is_ancestor, load_or_default, pseudo_delete, pseudo_read,
    pseudo_read_oid, pseudo_write,
};
use super::verbs_branch::checkout;
use super::verbs_history::resolve_local;
use super::{Ctx, FlagSpec, collect, line};

/// Default term for a broken revision.
const DEFAULT_BAD_TERM: &str = "bad";
/// Default term for a working revision.
const DEFAULT_GOOD_TERM: &str = "good";

/// Entry point for `bisect <subcommand>`.
///
/// Oracle: `git/builtin/bisect.c:cmd_bisect`. The first token is a
/// subcommand or a current good/bad term alias; `run` takes its command
/// verbatim while every other subcommand parses flags.
pub(crate) fn bisect(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let (bad_term, good_term) = read_terms(store)?;
    let [sub, rest @ ..] = args else {
        return bisect_status(ctx);
    };
    if *sub == "bad" || *sub == bad_term {
        return mark(ctx, Mark::Bad, rest);
    }
    if *sub == "good" || *sub == good_term {
        return mark(ctx, Mark::Good, rest);
    }
    match sub.as_str() {
        "start" => start(ctx, rest),
        "skip" => skip(ctx, rest),
        "reset" => reset(ctx, rest),
        "log" => log(ctx, rest),
        "terms" => terms(ctx, rest),
        "run" => run_cmd(ctx, rest),
        "replay" | "visualize" => Err(GitError::Unsupported {
            command: format!("bisect {sub} is not supported"),
        }),
        _ => Err(GitError::Invalid {
            detail: format!("usage: bisect start|bad|good|skip|reset|log|terms|run (got {sub:?})"),
        }),
    }
}

/// Which side a mark lands on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mark {
    /// A broken revision.
    Bad,
    /// A working revision.
    Good,
}

/// Starts a session: `bisect start [bad [good...]] [--no-checkout]
/// [--first-parent] [--term-*] [--] [paths]`.
///
/// Path limits are refused honestly instead of silently bisecting the full
/// graph. With both marks present the first midpoint checks out at once.
fn start(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    ctx.require_worktree()?;
    let (head_args, paths) = split_paths(args);
    if !paths.is_empty() {
        return Err(GitError::Unsupported {
            command: "bisect start with path limits is not supported".to_owned(),
        });
    }
    let specs = [
        FlagSpec {
            long: "no-checkout",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "first-parent",
            short: None,
            takes_value: false,
        },
        FlagSpec {
            long: "term-bad",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "term-old",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "term-good",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "term-new",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(&head_args, &specs)?;
    let store = ctx.store()?;
    if is_active(store)? {
        return Err(GitError::Invalid {
            detail: "already bisecting; 'bisect reset' first".to_owned(),
        });
    }
    let bad_term = opts
        .single("term-bad")?
        .or(opts.single("term-old")?)
        .unwrap_or_else(|| DEFAULT_BAD_TERM.to_owned());
    let good_term = opts
        .single("term-good")?
        .or(opts.single("term-new")?)
        .unwrap_or_else(|| DEFAULT_GOOD_TERM.to_owned());
    check_term(&bad_term)?;
    check_term(&good_term)?;
    if bad_term == good_term {
        return Err(GitError::Invalid {
            detail: "good and bad terms must differ".to_owned(),
        });
    }
    write_terms(store, &bad_term, &good_term)?;
    if opts.is_set("first-parent") {
        pseudo_write(store, "BISECT_FIRST_PARENT", b"1".to_vec())?;
    }
    let no_checkout = opts.is_set("no-checkout");
    if no_checkout {
        pseudo_write(store, "BISECT_NO_CHECKOUT", b"1".to_vec())?;
    }
    pseudo_write(store, "BISECT_START", start_record(store)?)?;
    append_log(store, "git bisect start\n")?;
    match opts.positionals.as_slice() {
        [] => Ok(line(b"waiting for good and bad commits".to_vec())),
        [bad, goods @ ..] => {
            let kind = ctx.kind()?;
            let bad_oid = resolve_local(store, kind, bad)?;
            commit_record(store, bad_oid)?;
            let mut good_oids = Vec::new();
            for rev in goods {
                let oid = resolve_local(store, kind, rev)?;
                commit_record(store, oid)?;
                good_oids.push(oid);
            }
            check_compatible(store, Some(bad_oid), &good_oids)?;
            pseudo_write(store, "BISECT_BAD", bad_oid.to_hex().into_bytes())?;
            append_log(store, &mark_line(store, "bad", bad_oid)?)?;
            if !good_oids.is_empty() {
                write_goods(store, &good_oids)?;
                for oid in &good_oids {
                    append_log(store, &mark_line(store, "good", *oid)?)?;
                }
            }
            advance(ctx)
        }
    }
}

/// Marks revisions: `bisect bad [<rev>]`, `bisect good [<rev>...]` (or the
/// current custom-term aliases).
fn mark(ctx: &mut Ctx, side: Mark, args: &[String]) -> Result<Vec<u8>, GitError> {
    ctx.require_worktree()?;
    let specs = [FlagSpec {
        long: "first-parent",
        short: None,
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    if opts.is_set("first-parent") {
        return Err(GitError::Invalid {
            detail: "bisect --first-parent belongs on 'bisect start'".to_owned(),
        });
    }
    let store = ctx.store()?;
    require_active(store)?;
    let kind = ctx.kind()?;
    let head = head_oid(store)?;
    let revs: Vec<Oid> = if opts.positionals.is_empty() {
        check_expected(store, head)?;
        vec![head]
    } else {
        let mut out = Vec::new();
        for rev in &opts.positionals {
            let oid = resolve_local(store, kind, rev)?;
            commit_record(store, oid)?;
            out.push(oid);
        }
        out
    };
    match side {
        Mark::Bad => {
            if revs.len() > 1 {
                return Err(GitError::Invalid {
                    detail: "usage: bisect bad [<rev>]".to_owned(),
                });
            }
            mark_bad(ctx, revs[0])
        }
        Mark::Good => mark_goods(ctx, &revs),
    }
}

/// Records one bad revision, refusing marks that contradict the goods.
fn mark_bad(ctx: &mut Ctx, bad: Oid) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let goods = read_goods(store)?;
    check_compatible(store, Some(bad), &goods)?;
    if interesting(store, bad, &goods)?.is_empty() {
        return Err(GitError::Invalid {
            detail: "contradictory marks leave no revisions to test".to_owned(),
        });
    }
    pseudo_write(store, "BISECT_BAD", bad.to_hex().into_bytes())?;
    append_log(store, &mark_line(store, "bad", bad)?)?;
    advance(ctx)
}

/// Records working revisions, refusing marks that would empty the range.
fn mark_goods(ctx: &mut Ctx, goods: &[Oid]) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    let bad = pseudo_read_oid(store, "BISECT_BAD")?;
    let mut merged = read_goods(store)?;
    for oid in goods {
        if !merged.contains(oid) {
            merged.push(*oid);
        }
    }
    check_compatible(store, bad, &merged)?;
    if let Some(bad_oid) = bad {
        if interesting(store, bad_oid, &merged)?.is_empty() {
            return Err(GitError::Invalid {
                detail: "contradictory marks leave no revisions to test".to_owned(),
            });
        }
    }
    write_goods(store, &merged)?;
    for oid in goods {
        append_log(store, &mark_line(store, "good", *oid)?)?;
    }
    advance(ctx)
}

/// Skips revisions: `bisect skip [<rev>...]` (default `HEAD`).
///
/// Skipped commits stay in the graph weights but are never checked out;
/// when every interesting commit is skipped the next pick reports it.
fn skip(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    ctx.require_worktree()?;
    let specs = [FlagSpec {
        long: "first-parent",
        short: None,
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    if opts.is_set("first-parent") {
        return Err(GitError::Invalid {
            detail: "bisect --first-parent belongs on 'bisect start'".to_owned(),
        });
    }
    let store = ctx.store()?;
    require_active(store)?;
    let kind = ctx.kind()?;
    let head = head_oid(store)?;
    let revs: Vec<Oid> = if opts.positionals.is_empty() {
        check_expected(store, head)?;
        vec![head]
    } else {
        let mut out = Vec::new();
        for rev in &opts.positionals {
            let oid = resolve_local(store, kind, rev)?;
            commit_record(store, oid)?;
            out.push(oid);
        }
        out
    };
    let mut skipped = read_skipped(store)?;
    for oid in &revs {
        if !skipped.contains(oid) {
            skipped.push(*oid);
        }
    }
    write_skipped(store, &skipped)?;
    for oid in &revs {
        append_log(store, &mark_line(store, "skip", *oid)?)?;
    }
    advance(ctx)
}

/// Ends the session: `bisect reset [<commit>]`.
///
/// Checks out the pre-run branch (or detached oid, or the explicit target)
/// before wiping state, so a failed checkout keeps the session intact.
fn reset(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    ctx.require_worktree()?;
    let specs = [FlagSpec {
        long: "first-parent",
        short: None,
        takes_value: false,
    }];
    let opts = collect(args, &specs)?;
    if opts.is_set("first-parent") {
        return Err(GitError::Invalid {
            detail: "bisect --first-parent belongs on 'bisect start'".to_owned(),
        });
    }
    let store = ctx.store()?;
    require_active(store)?;
    if opts.positionals.len() > 1 {
        return Err(GitError::Invalid {
            detail: "usage: bisect reset [<commit>]".to_owned(),
        });
    }
    let target: String = {
        let store = ctx.store()?;
        match opts.positionals.first() {
            Some(rev) => {
                let oid = resolve_local(store, ctx.kind()?, rev)?;
                commit_record(store, oid)?;
                oid.to_hex()
            }
            None => start_target(store)?,
        }
    };
    checkout(ctx, &[target])?;
    wipe(ctx.store()?)?;
    Ok(Vec::new())
}

/// Prints the session log: `bisect log`.
fn log(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    if !args.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: bisect log".to_owned(),
        });
    }
    let store = ctx.store()?;
    require_active(store)?;
    Ok(pseudo_read(store, "BISECT_LOG")?.unwrap_or_default())
}

/// Shows or sets the session terms: `bisect terms [--term-good|--term-bad
/// ...]`.
///
/// Reading works outside a session (defaults); setting needs one, since
/// the terms live in session state.
fn terms(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    let specs = [
        FlagSpec {
            long: "term-bad",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "term-old",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "term-good",
            short: None,
            takes_value: true,
        },
        FlagSpec {
            long: "term-new",
            short: None,
            takes_value: true,
        },
    ];
    let opts = collect(args, &specs)?;
    if !opts.positionals.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: bisect terms [--term-good <term> --term-bad <term>]".to_owned(),
        });
    }
    let store = ctx.store()?;
    let bad = opts.single("term-bad")?.or(opts.single("term-old")?);
    let good = opts.single("term-good")?.or(opts.single("term-new")?);
    if bad.is_none() && good.is_none() {
        let (bad_term, good_term) = read_terms(store)?;
        return Ok(line(
            format!("Your current terms are {good_term} and {bad_term}.").into_bytes(),
        ));
    }
    require_active(store)?;
    let (mut bad_term, mut good_term) = read_terms(store)?;
    if let Some(term) = bad {
        check_term(&term)?;
        bad_term = term;
    }
    if let Some(term) = good {
        check_term(&term)?;
        good_term = term;
    }
    if bad_term == good_term {
        return Err(GitError::Invalid {
            detail: "good and bad terms must differ".to_owned(),
        });
    }
    write_terms(store, &bad_term, &good_term)?;
    Ok(line(
        format!("Your new terms are {good_term} and {bad_term}.").into_bytes(),
    ))
}

/// Automates the session: `bisect run <cmd> [args...]`.
///
/// Exit `0` marks the checkout good, `125` skips it, anything else
/// (including death by signal) marks it bad. Stops at the first bad
/// commit, when a verdict stops narrowing the range, or when everything
/// interesting is skipped.
fn run_cmd(ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    ctx.require_worktree()?;
    if args.is_empty() {
        return Err(GitError::Invalid {
            detail: "usage: bisect run <cmd> [args...]".to_owned(),
        });
    }
    let store = ctx.store()?;
    require_active(store)?;
    let mut out = Vec::new();
    let initial = interesting_count(ctx)?;
    let cap = initial + 64;
    for _ in 0..cap {
        let head = head_oid(ctx.store()?)?;
        let code = run_test(ctx, args)?;
        let before = interesting_count(ctx)?;
        let step = match code {
            Some(0) => mark_goods(ctx, &[head])?,
            Some(125) => {
                let skipped_out = skip(ctx, &[head.to_hex()])?;
                out.extend_from_slice(&skipped_out);
                continue;
            }
            _ => mark_bad(ctx, head)?,
        };
        let text = String::from_utf8_lossy(&step);
        out.extend_from_slice(&step);
        if text.contains("first bad commit") {
            return Ok(out);
        }
        if interesting_count(ctx)? >= before {
            out.extend_from_slice(b"test verdict did not narrow the range; stopping\n");
            return Ok(out);
        }
    }
    out.extend_from_slice(b"bisect run stopped: step budget exhausted\n");
    Ok(out)
}

/// Runs one test command at the current checkout.
///
/// The child inherits the environment with the repository root as its
/// working directory and a null stdin; only the exit code is read.
fn run_test(ctx: &Ctx, args: &[String]) -> Result<Option<i32>, GitError> {
    let status = std::process::Command::new(&args[0])
        .args(&args[1..])
        .current_dir(&ctx.root)
        .stdin(std::process::Stdio::null())
        .status()
        .map_err(|err| GitError::Io {
            detail: format!("bisect run {:?} failed to start: {err}", args[0]),
        })?;
    Ok(status.code())
}

/// Reports session state without moving: bare `bisect`.
fn bisect_status(ctx: &mut Ctx) -> Result<Vec<u8>, GitError> {
    let store = ctx.store()?;
    if !is_active(store)? {
        return Err(GitError::Invalid {
            detail: "not currently bisecting; 'bisect start' first".to_owned(),
        });
    }
    let Some(bad) = pseudo_read_oid(store, "BISECT_BAD")? else {
        return Ok(line(b"waiting for bad commit".to_vec()));
    };
    let goods = read_goods(store)?;
    if goods.is_empty() {
        return Ok(line(b"waiting for good commits".to_vec()));
    }
    let range = interesting(store, bad, &goods)?;
    if range.len() == 1 {
        return Ok(line(first_bad_line(range[0])));
    }
    Ok(line(
        format!(
            "Bisecting: {} revisions left to test\n",
            range.len().saturating_sub(1),
        )
        .into_bytes(),
    ))
}

/// Recomputes the range, checks out the midpoint (or names the first bad
/// commit), and renders the step line.
///
/// Store borrows stay scoped: the checkout takes `ctx` mutably, so every
/// pseudo-head write re-opens the store after it.
fn advance(ctx: &mut Ctx) -> Result<Vec<u8>, GitError> {
    let range: Vec<Oid> = {
        let store = ctx.store()?;
        let Some(bad) = pseudo_read_oid(store, "BISECT_BAD")? else {
            return Ok(line(b"waiting for bad commit".to_vec()));
        };
        let goods = read_goods(store)?;
        if goods.is_empty() {
            return Ok(line(b"waiting for good commits".to_vec()));
        }
        interesting(store, bad, &goods)?
    };
    if range.len() == 1 {
        let first = range[0];
        checkout_candidate(ctx, first)?;
        let store = ctx.store()?;
        pseudo_write(store, "BISECT_EXPECTED_REV", first.to_hex().into_bytes())?;
        pseudo_write(store, "BISECT_HEAD", first.to_hex().into_bytes())?;
        append_log(
            store,
            &format!("# first bad commit: {}\n", log_ref(store, first)?),
        )?;
        return Ok(line(first_bad_line(first)));
    }
    let candidate = pick_midpoint(ctx.store()?, &range)?;
    checkout_candidate(ctx, candidate)?;
    let store = ctx.store()?;
    pseudo_write(
        store,
        "BISECT_EXPECTED_REV",
        candidate.to_hex().into_bytes(),
    )?;
    pseudo_write(store, "BISECT_HEAD", candidate.to_hex().into_bytes())?;
    let left = range.len().saturating_sub(1);
    let steps = bisect_steps(range.len());
    Ok(line(
        format!(
            "Bisecting: {left} revision{} left to test after this (roughly {steps} step{})\n",
            if left == 1 { "" } else { "s" },
            if steps == 1 { "" } else { "s" },
        )
        .into_bytes(),
    ))
}

/// Checks out one candidate unless `--no-checkout` or already there.
fn checkout_candidate(ctx: &mut Ctx, candidate: Oid) -> Result<(), GitError> {
    {
        let store = ctx.store()?;
        if no_checkout_mode(store)? {
            return Ok(());
        }
        if head_oid(store)? == candidate {
            return Ok(());
        }
    }
    checkout(ctx, &[candidate.to_hex()])?;
    Ok(())
}

/// Picks the `|total - 2*weight|` minimizer over testable candidates,
/// ties to the newest walk position.
fn pick_midpoint(store: &Store, range: &[Oid]) -> Result<Oid, GitError> {
    let skipped = read_skipped(store)?;
    let total = range.len();
    let mut best: Option<(Oid, usize)> = None;
    for candidate in range {
        if skipped.contains(candidate) {
            continue;
        }
        let distance = total.abs_diff(2 * weight(store, *candidate, range)?);
        match best {
            Some((_, known)) if distance >= known => {}
            _ => best = Some((*candidate, distance)),
        }
    }
    best.map(|(oid, _)| oid).ok_or_else(|| GitError::Invalid {
        detail: "no testable revisions left (all skipped)".to_owned(),
    })
}

/// Counts interesting commits at or below one candidate.
fn weight(store: &Store, candidate: Oid, range: &[Oid]) -> Result<usize, GitError> {
    let set: HashSet<Oid> = range.iter().copied().collect();
    let first_parent = first_parent_mode(store)?;
    let mut seen = HashSet::new();
    let mut stack = vec![candidate];
    let mut count = 0;
    while let Some(oid) = stack.pop() {
        if !seen.insert(oid) {
            continue;
        }
        if !set.contains(&oid) {
            continue;
        }
        count += 1;
        let record = commit_record(store, oid)?;
        if first_parent {
            stack.extend(first_parent_chain(&record));
        } else {
            stack.extend(all_parents(&record));
        }
    }
    Ok(count)
}

/// Lists `bad` minus `goods` newest-first: the commits under test.
///
/// Mirrors the merge-base paint-down over the same parent links, pruned at
/// anything reachable from a good revision.
fn interesting(store: &Store, bad: Oid, goods: &[Oid]) -> Result<Vec<Oid>, GitError> {
    let first_parent = first_parent_mode(store)?;
    let mut excluded = HashSet::new();
    let mut stack: Vec<Oid> = goods.to_vec();
    while let Some(oid) = stack.pop() {
        if !excluded.insert(oid) {
            continue;
        }
        let record = commit_record(store, oid)?;
        if first_parent {
            stack.extend(first_parent_chain(&record));
        } else {
            stack.extend(all_parents(&record));
        }
    }
    let mut seen = HashSet::new();
    let mut order = Vec::new();
    let mut stack = vec![bad];
    while let Some(oid) = stack.pop() {
        if !seen.insert(oid) {
            continue;
        }
        if excluded.contains(&oid) {
            continue;
        }
        let record = commit_record(store, oid)?;
        order.push(oid);
        let mut parents = if first_parent {
            first_parent_chain(&record)
        } else {
            all_parents(&record)
        };
        parents.reverse();
        stack.extend(parents);
    }
    Ok(order)
}

/// Counts the current range for `run` progress guards.
fn interesting_count(ctx: &Ctx) -> Result<usize, GitError> {
    let store = ctx.store()?;
    let Some(bad) = pseudo_read_oid(store, "BISECT_BAD")? else {
        return Err(GitError::Invalid {
            detail: "bisect run needs bad and good commits first".to_owned(),
        });
    };
    let goods = read_goods(store)?;
    if goods.is_empty() {
        return Err(GitError::Invalid {
            detail: "bisect run needs bad and good commits first".to_owned(),
        });
    }
    Ok(interesting(store, bad, &goods)?.len())
}

/// Reads one commit's parent oids in payload order.
fn all_parents(record: &CommitRecord) -> Vec<Oid> {
    parent_oids(record, false)
}

/// Reads one commit's first-parent oid.
fn first_parent_chain(record: &CommitRecord) -> Vec<Oid> {
    parent_oids(record, true)
}

/// Shared parent reader behind [`all_parents`] and [`first_parent_chain`].
fn parent_oids(record: &CommitRecord, first_only: bool) -> Vec<Oid> {
    let mut parents: Vec<Oid> = record
        .parents()
        .iter()
        .filter_map(|head| head.as_git().copied())
        .collect();
    if first_only {
        parents.truncate(1);
    }
    parents
}

/// Steps to halve `n` revisions by bisection.
fn bisect_steps(n: usize) -> usize {
    let mut steps = 0;
    let mut remaining = n;
    while remaining > 1 {
        remaining = remaining.div_ceil(2);
        steps += 1;
    }
    steps
}

/// Refuses a bad revision that a good revision already clears.
fn check_compatible(store: &Store, bad: Option<Oid>, goods: &[Oid]) -> Result<(), GitError> {
    let Some(bad_oid) = bad else {
        return Ok(());
    };
    for good in goods {
        if *good == bad_oid || is_ancestor(store, bad_oid, *good)? {
            return Err(GitError::Invalid {
                detail: format!(
                    "bad revision {} is an ancestor of good revision {}",
                    bad_oid.to_hex(),
                    good.to_hex(),
                ),
            });
        }
    }
    Ok(())
}

/// Refuses a bare mark when `HEAD` drifted off the expected checkout.
fn check_expected(store: &Store, head: Oid) -> Result<(), GitError> {
    if no_checkout_mode(store)? {
        return Ok(());
    }
    if let Some(expected) = pseudo_read_oid(store, "BISECT_EXPECTED_REV")? {
        if expected != head {
            return Err(GitError::Invalid {
                detail: format!(
                    "not on the expected revision {}; check it out or pass an explicit revision",
                    expected.to_hex(),
                ),
            });
        }
    }
    Ok(())
}

/// Refuses empty or multi-word terms.
fn check_term(term: &str) -> Result<(), GitError> {
    if term.is_empty() || term.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(GitError::Invalid {
            detail: format!("bad bisect term {term:?}: want one word"),
        });
    }
    Ok(())
}

/// Reports whether a session is active.
fn is_active(store: &Store) -> Result<bool, GitError> {
    Ok(pseudo_read(store, "BISECT_START")?.is_some())
}

/// Demands an active session.
fn require_active(store: &Store) -> Result<(), GitError> {
    if !is_active(store)? {
        return Err(GitError::Invalid {
            detail: "not currently bisecting; 'bisect start' first".to_owned(),
        });
    }
    Ok(())
}

/// Reports whether the session follows first parents only.
fn first_parent_mode(store: &Store) -> Result<bool, GitError> {
    Ok(pseudo_read(store, "BISECT_FIRST_PARENT")?.is_some())
}

/// Reports whether the session skips worktree checkouts.
fn no_checkout_mode(store: &Store) -> Result<bool, GitError> {
    Ok(pseudo_read(store, "BISECT_NO_CHECKOUT")?.is_some())
}

/// Captures the pre-run `HEAD` for `reset`.
fn start_record(store: &Store) -> Result<Vec<u8>, GitError> {
    let (workspace, _) = load_or_default(store)?;
    match &workspace.head {
        HeadRef::Symbolic(name) => {
            let text = String::from_utf8_lossy(name.as_bytes());
            let short = text.strip_prefix("refs/heads/").map_or(&*text, |rest| rest);
            Ok(format!("branch:{short}").into_bytes())
        }
        HeadRef::Detached(oid) => Ok(format!("oid:{}", oid.to_hex()).into_bytes()),
    }
}

/// Resolves the `reset` checkout target from the start record.
fn start_target(store: &Store) -> Result<String, GitError> {
    let raw = pseudo_read(store, "BISECT_START")?.ok_or_else(|| GitError::Corrupt {
        detail: "BISECT_START vanished mid-session".to_owned(),
    })?;
    let text = std::str::from_utf8(&raw).map_err(|_| GitError::Corrupt {
        detail: "BISECT_START is not valid UTF-8".to_owned(),
    })?;
    if let Some(branch) = text.strip_prefix("branch:") {
        return Ok(branch.to_owned());
    }
    if let Some(hex) = text.strip_prefix("oid:") {
        return Ok(hex.to_owned());
    }
    Err(GitError::Corrupt {
        detail: "BISECT_START does not decode".to_owned(),
    })
}

/// Deletes every `BISECT_*` pseudo-head, ending the session.
fn wipe(store: &Store) -> Result<(), GitError> {
    for name in [
        "BISECT_START",
        "BISECT_BAD",
        "BISECT_GOODS",
        "BISECT_SKIPPED",
        "BISECT_EXPECTED_REV",
        "BISECT_HEAD",
        "BISECT_TERMS",
        "BISECT_LOG",
        "BISECT_FIRST_PARENT",
        "BISECT_NO_CHECKOUT",
    ] {
        pseudo_delete(store, name)?;
    }
    Ok(())
}

/// Reads the session terms, defaulting outside a fresh session.
fn read_terms(store: &Store) -> Result<(String, String), GitError> {
    let Some(raw) = pseudo_read(store, "BISECT_TERMS")? else {
        return Ok((DEFAULT_BAD_TERM.to_owned(), DEFAULT_GOOD_TERM.to_owned()));
    };
    let text = std::str::from_utf8(&raw).map_err(|_| GitError::Corrupt {
        detail: "BISECT_TERMS is not valid UTF-8".to_owned(),
    })?;
    let mut lines = text.lines();
    let bad = lines.next().unwrap_or(DEFAULT_BAD_TERM).to_owned();
    let good = lines.next().unwrap_or(DEFAULT_GOOD_TERM).to_owned();
    Ok((bad, good))
}

/// Writes the session terms: bad term first, good term second.
fn write_terms(store: &Store, bad: &str, good: &str) -> Result<(), GitError> {
    pseudo_write(
        store,
        "BISECT_TERMS",
        format!("{bad}\n{good}\n").into_bytes(),
    )
}

/// Reads marked-good revisions in mark order.
fn read_goods(store: &Store) -> Result<Vec<Oid>, GitError> {
    read_oid_list(store, "BISECT_GOODS")
}

/// Writes marked-good revisions in mark order.
fn write_goods(store: &Store, goods: &[Oid]) -> Result<(), GitError> {
    write_oid_list(store, "BISECT_GOODS", goods)
}

/// Reads skipped revisions in mark order.
fn read_skipped(store: &Store) -> Result<Vec<Oid>, GitError> {
    read_oid_list(store, "BISECT_SKIPPED")
}

/// Writes skipped revisions in mark order.
fn write_skipped(store: &Store, skipped: &[Oid]) -> Result<(), GitError> {
    write_oid_list(store, "BISECT_SKIPPED", skipped)
}

/// Reads one newline-joined oid list pseudo-head.
fn read_oid_list(store: &Store, name: &str) -> Result<Vec<Oid>, GitError> {
    let Some(raw) = pseudo_read(store, name)? else {
        return Ok(Vec::new());
    };
    let text = std::str::from_utf8(&raw).map_err(|_| GitError::Corrupt {
        detail: format!("{name} is not valid UTF-8"),
    })?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            Oid::from_hex(line.trim()).map_err(|_| GitError::Corrupt {
                detail: format!("{name} does not hold object ids"),
            })
        })
        .collect()
}

/// Writes one newline-joined oid list pseudo-head.
fn write_oid_list(store: &Store, name: &str, oids: &[Oid]) -> Result<(), GitError> {
    if oids.is_empty() {
        pseudo_delete(store, name)?;
        return Ok(());
    }
    let mut body = String::new();
    for oid in oids {
        body.push_str(&oid.to_hex());
        body.push('\n');
    }
    pseudo_write(store, name, body.into_bytes())
}

/// Appends one line to the session log.
fn append_log(store: &Store, text: &str) -> Result<(), GitError> {
    let mut body = pseudo_read(store, "BISECT_LOG")?.unwrap_or_default();
    body.extend_from_slice(text.as_bytes());
    pseudo_write(store, "BISECT_LOG", body)
}

/// Renders one `# <kind>: <hex> <subject>` log line.
fn mark_line(store: &Store, kind: &str, oid: Oid) -> Result<String, GitError> {
    Ok(format!("# {kind}: {}\n", log_ref(store, oid)?))
}

/// Renders one `<hex> <subject>` log reference.
fn log_ref(store: &Store, oid: Oid) -> Result<String, GitError> {
    Ok(format!("{} {}", oid.to_hex(), subject(store, oid)?))
}

/// Renders the first-bad verdict line.
fn first_bad_line(oid: Oid) -> Vec<u8> {
    format!("{} is the first bad commit\n", oid.to_hex()).into_bytes()
}

/// Reads one commit's subject (first message line).
fn subject(store: &Store, oid: Oid) -> Result<String, GitError> {
    let message = commit_record(store, oid)?.message().to_vec();
    let text = String::from_utf8_lossy(&message);
    Ok(text.lines().next().unwrap_or("").trim().to_owned())
}

/// Splits raw `start` args at `--`: the tail names refused path limits.
fn split_paths(args: &[String]) -> (Vec<String>, Vec<String>) {
    match args.iter().position(|arg| arg == "--") {
        None => (args.to_vec(), Vec::new()),
        Some(index) => (args[..index].to_vec(), args[index + 1..].to_vec()),
    }
}
