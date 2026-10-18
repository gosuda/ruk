//! Git-compatible command interpreter for the `ruk` executable.
//!
//! This module owns argv parsing in the `git.c` tradition (verb first, global
//! options before the verb, `ruk <verb> --help` rewriting) and the shared
//! per-command context over the native store. Every verb is a separate
//! function in one `verbs_*` module; [`dispatch`] maps the 59 advertised
//! names to those functions the way `git.c`'s `commands[]` table maps names
//! to `cmd_*` entry points.
//!
//! State layout in the native store (see [`state`] for the exact key
//! discipline):
//!
//! * `HEAD` is a workspace field ([`ruk_core::workspace::HeadRef`]) held in
//!   the CLI workspace row, resolved through the ref namespace on demand.
//!   `HEAD` is never a `Refs` entry (`refdata` documents it out of that
//!   namespace).
//! * The index is stage rows in `WsIndex` plus the workspace row's own
//!   `index_generation`, bumped in the one transaction that writes the rows.
//! * Config, remotes-as-config, sequencer records, and stash slots are fact
//!   records (`Pins`), never parsed text.
//!
//! Oracle anchors: `git/git.c` (`handle_options`, `handle_builtin`,
//! `commands[]`) and `git/builtin/<verb>.c` per verb, named in each
//! `verbs_*` header and in `STATUS.md`.

pub(crate) mod dispatch;
pub(crate) mod state;
pub(crate) mod tree;
pub(crate) mod verbs_branch;
pub(crate) mod verbs_grep;
pub(crate) mod verbs_history;
pub(crate) mod verbs_meta;
pub(crate) mod verbs_objects;
pub(crate) mod verbs_repo;
pub(crate) mod verbs_stage;
pub(crate) mod verbs_transport;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::io::Read as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use ruk_core::ids::HashKind;
use ruk_core::store::{PreparationBudget, Store};
use ruk_git::GitError;

/// Snapshot of the process environment one command runs against.
///
/// Carrying the environment as a value keeps every verb testable without
/// touching the real process, the same reason `git.c` threads explicit
/// option state instead of reading globals at each call site.
#[derive(Clone, Debug)]
pub struct CliEnv {
    /// Process variables (`GIT_DIR`, `GIT_AUTHOR_*`, ...).
    pub(crate) vars: HashMap<String, String>,
    /// Working directory the command starts in.
    pub(crate) cwd: PathBuf,
    /// Captured standard input for verbs reading stdin. `None` reads the
    /// live process stdin; the IPC daemon sets `Some` so verbs run without
    /// touching the daemon's own descriptors.
    pub(crate) stdin: Option<Vec<u8>>,
}

impl CliEnv {
    /// Captures the live process environment.
    #[must_use]
    pub fn capture() -> Self {
        Self {
            vars: std::env::vars().collect(),
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            stdin: None,
        }
    }

    /// Reads one variable, exactly like `getenv`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }
}

/// Shared per-command context: the open store and its roots.
///
/// `root` holds `.ruk/`; `file_base` is where worktree files are read and
/// written (`--work-tree` moves it, like `git --work-tree`). A bare
/// repository refuses worktree verbs the way Git does. Repository-optional
/// verbs (`init`, `clone`, `hash-object`) run without an open store and open
/// the stores they need themselves.
pub(crate) struct Ctx {
    /// The open native store, when the verb needs a repository.
    pub(crate) store: Option<Store>,
    /// Repository root holding `.ruk/`, or the working directory.
    pub(crate) root: PathBuf,
    /// Base directory for worktree file access.
    pub(crate) file_base: PathBuf,
    /// Object format of the open repository.
    pub(crate) kind: Option<HashKind>,
    /// Process environment snapshot.
    pub(crate) env: CliEnv,
    /// Bare repository: no worktree verbs.
    pub(crate) bare: bool,
    /// `-c` / `--config-env` overrides, in order given.
    pub(crate) cli_config: Vec<(String, String)>,
    /// Advisory bytes for standard error (e.g. `Switched to branch ...`),
    /// kept off the stdout return the way git splits its descriptors.
    pub(crate) stderr: Vec<u8>,
}

impl Ctx {
    /// Borrows the open store, refusing when no repository was discovered.
    pub(crate) fn store(&self) -> Result<&Store, GitError> {
        self.store.as_ref().ok_or_else(|| GitError::Invalid {
            detail: "not a ruk repository".to_owned(),
        })
    }

    /// Reads the repository object format.
    pub(crate) fn kind(&self) -> Result<HashKind, GitError> {
        self.kind.ok_or_else(|| GitError::Invalid {
            detail: "not a ruk repository".to_owned(),
        })
    }
    /// Reads config with `-c` overrides winning over stored records.
    #[must_use]
    pub(crate) fn config_get(&self, name: &str) -> Option<String> {
        for (key, value) in self.cli_config.iter().rev() {
            if key == name {
                return Some(value.clone());
            }
        }
        self.store
            .as_ref()
            .and_then(|store| state::config_read(store, name).ok().flatten())
    }

    /// Queues advisory bytes for standard error, the way `checkout` and
    /// `switch` report branch moves off the stdout channel.
    pub(crate) fn emit_stderr(&mut self, text: &[u8]) {
        self.stderr.extend_from_slice(text);
    }

    /// Refuses worktree verbs on bare repositories.
    pub(crate) fn require_worktree(&self) -> Result<(), GitError> {
        if self.bare {
            return Err(GitError::Invalid {
                detail: "this operation cannot run in a bare repository".to_owned(),
            });
        }
        Ok(())
    }
}

/// One parsed global option before the verb, mirroring the subset of
/// `git.c:handle_options` this interpreter honors.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Global {
    ChangeDir(PathBuf),
    Define(String, String),
    GitDir(PathBuf),
    WorkTree(PathBuf),
    Bare,
}

/// Entry point for git-compatible argv handling.
///
/// `argv[0]` is the program name and is skipped, as in `git.c:main`.
/// `--help` and `--version` short-circuit before repository discovery, also
/// as in `git.c`. Every failure maps to its native exit status through
/// [`GitError::exit_code`].
/// The captured output of one interpreter run, for callers that cannot use
/// the process descriptors (the IPC daemon serves command streams on its
/// socket and must return bytes, not write the daemon's stdout).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CliOutcome {
    /// Bytes for standard output; empty when the verb prints nothing.
    pub(crate) stdout: Vec<u8>,
    /// Bytes for standard error; empty on success.
    pub(crate) stderr: Vec<u8>,
    /// Native process exit status: zero on success.
    pub(crate) code: u8,
}

/// Runs one argv against `env` without touching process descriptors.
///
/// Success carries the verb's stdout bytes with code zero; failure renders
/// the same `ruk: {err}` line [`run`] would print, with the error's native
/// exit status.
pub(crate) fn run_captured(argv: Vec<String>, env: CliEnv) -> CliOutcome {
    match run_inner(&argv, env) {
        Ok((stdout, stderr)) => CliOutcome {
            stdout,
            stderr,
            code: 0,
        },
        Err(err) => CliOutcome {
            stdout: Vec::new(),
            stderr: format!("ruk: {err}\n").into_bytes(),
            code: err.exit_code(),
        },
    }
}

/// Reads standard input bytes for `env`: the captured buffer when the
/// caller supplied one, else the live process stdin.
pub(crate) fn read_stdin_bytes(env: &CliEnv) -> Result<Vec<u8>, GitError> {
    if let Some(bytes) = env.stdin.as_deref() {
        return Ok(bytes.to_vec());
    }
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .map_err(|err| GitError::Io {
            detail: format!("reading stdin: {err}"),
        })?;
    Ok(buf)
}

/// Reads standard input as text, tolerating non-UTF-8 bytes the way a
/// byte-oriented daemon transport must.
pub(crate) fn read_stdin_text(env: &CliEnv) -> Result<String, GitError> {
    Ok(String::from_utf8_lossy(&read_stdin_bytes(env)?).into_owned())
}

#[must_use]
pub fn run(argv: Vec<String>, env: CliEnv) -> ExitCode {
    let outcome = run_captured(argv, env);
    if !outcome.stdout.is_empty() {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        if lock.write_all(&outcome.stdout).is_err() || lock.flush().is_err() {
            return ExitCode::from(1);
        }
    }
    if !outcome.stderr.is_empty() {
        let stderr = std::io::stderr();
        let mut lock = stderr.lock();
        let _ = lock.write_all(&outcome.stderr);
    }
    ExitCode::from(outcome.code)
}

/// Parses globals, discovers the repository, and dispatches the verb.
pub(crate) fn run_inner(argv: &[String], env: CliEnv) -> Result<(Vec<u8>, Vec<u8>), GitError> {
    let rest = argv.first().map_or(&[][..], |_| &argv[1.min(argv.len())..]);
    let (globals, verb, verb_args) = split_globals(rest)?;
    let mut env = env;
    let mut cli_config: Vec<(String, String)> = Vec::new();
    let mut git_dir: Option<PathBuf> = None;
    let mut work_tree: Option<PathBuf> = None;
    let mut bare = false;
    for global in globals {
        match global {
            Global::ChangeDir(dir) => {
                if !dir.is_dir() {
                    return Err(GitError::Io {
                        detail: format!("cannot change to {}", dir.display()),
                    });
                }
                env.cwd = dir;
            }
            Global::Define(key, value) => cli_config.push((key, value)),
            Global::GitDir(dir) => git_dir = Some(dir),
            Global::WorkTree(dir) => work_tree = Some(dir),
            Global::Bare => bare = true,
        }
    }
    if let Some(value) = env.get("GIT_DIR").map(str::to_owned) {
        if git_dir.is_none() {
            git_dir = Some(PathBuf::from(value));
        }
    }
    let Some(verb) = verb else {
        return Err(GitError::Invalid {
            detail: "no command given; see 'ruk help'".to_owned(),
        });
    };
    if verb == "--help" || verb == "-h" {
        return Ok((dispatch::help_text(None), Vec::new()));
    }
    if verb == "--version" || verb == "-v" {
        return Ok((dispatch::version_text(), Vec::new()));
    }
    let entry = dispatch::lookup(&verb).ok_or_else(|| GitError::Unsupported {
        command: verb.clone(),
    })?;
    if verb_args.iter().any(|arg| arg == "--help") {
        return Ok((dispatch::help_text(Some(entry)), Vec::new()));
    }
    let mut ctx = open_ctx(env, git_dir, work_tree, bare, cli_config, entry.needs_repo)?;
    let stdout = (entry.run)(&mut ctx, &verb_args)?;
    Ok((stdout, std::mem::take(&mut ctx.stderr)))
}

/// Splits leading global options from the verb and its arguments.
fn split_globals(rest: &[String]) -> Result<(Vec<Global>, Option<String>, Vec<String>), GitError> {
    let mut globals = Vec::new();
    let mut index = 0;
    while index < rest.len() {
        let arg = &rest[index];
        if arg == "-v" || arg == "--version" {
            return Ok((globals, Some("--version".to_owned()), Vec::new()));
        }
        if arg == "-h" || arg == "--help" {
            return Ok((globals, Some("--help".to_owned()), Vec::new()));
        }
        if arg == "-C" {
            index += 1;
            let dir = rest.get(index).ok_or_else(|| GitError::Invalid {
                detail: "option -C requires a path".to_owned(),
            })?;
            globals.push(Global::ChangeDir(PathBuf::from(dir)));
        } else if arg == "-c" {
            index += 1;
            let pair = rest.get(index).ok_or_else(|| GitError::Invalid {
                detail: "option -c requires name=value".to_owned(),
            })?;
            let (key, value) = parse_config_pair(pair)?;
            globals.push(Global::Define(key, value));
        } else if arg == "--bare" {
            globals.push(Global::Bare);
        } else if arg == "-p" || arg == "--paginate" || arg == "-P" || arg == "--no-pager" {
            let _ = arg;
        } else if arg == "--no-replace-objects"
            || arg == "--no-lazy-fetch"
            || arg == "--no-optional-locks"
            || arg == "--no-advice"
        {
            let _ = arg;
        } else if arg == "--git-dir" || arg == "--work-tree" {
            index += 1;
            let path = rest.get(index).ok_or_else(|| GitError::Invalid {
                detail: format!("option {arg} requires a path"),
            })?;
            if arg == "--git-dir" {
                globals.push(Global::GitDir(PathBuf::from(path)));
            } else {
                globals.push(Global::WorkTree(PathBuf::from(path)));
            }
        } else if let Some(path) = prefixed_value(arg, "--git-dir=") {
            globals.push(Global::GitDir(PathBuf::from(path)));
        } else if let Some(path) = prefixed_value(arg, "--work-tree=") {
            globals.push(Global::WorkTree(PathBuf::from(path)));
        } else if arg == "--config-env" {
            index += 1;
            let pair = rest.get(index).ok_or_else(|| GitError::Invalid {
                detail: "option --config-env requires name=ENVVAR".to_owned(),
            })?;
            let (key, value) = parse_config_env(pair)?;
            globals.push(Global::Define(key, value));
        } else if arg == "--exec-path"
            || arg == "--html-path"
            || arg == "--man-path"
            || arg == "--info-path"
        {
            return Err(GitError::Unsupported {
                command: arg.clone(),
            });
        } else if arg.starts_with('-') && arg.len() > 1 {
            return Err(GitError::Unsupported {
                command: arg.clone(),
            });
        } else {
            let verb_args = rest[index + 1..].to_vec();
            return Ok((globals, Some(arg.clone()), verb_args));
        }
        index += 1;
    }
    Ok((globals, None, Vec::new()))
}

/// Splits the value off a `--name=value` token.
fn prefixed_value<'a>(arg: &'a str, prefix: &str) -> Option<&'a str> {
    arg.strip_prefix(prefix)
}

/// Parses `-c name=value` exactly: the first `=` separates the pair.
fn parse_config_pair(pair: &str) -> Result<(String, String), GitError> {
    pair.split_once('=')
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .ok_or_else(|| GitError::Invalid {
            detail: format!("bad config -c {pair:?}: want name=value"),
        })
}

/// Parses `--config-env name=ENVVAR` by reading the named variable now.
fn parse_config_env(pair: &str) -> Result<(String, String), GitError> {
    let (key, var) = pair.split_once('=').ok_or_else(|| GitError::Invalid {
        detail: format!("bad --config-env {pair:?}: want name=ENVVAR"),
    })?;
    std::env::var(var)
        .map(|value| (key.to_owned(), value))
        .map_err(|_| GitError::Invalid {
            detail: format!("config-env {var:?} is not set"),
        })
}

/// Discovers the repository root and opens its store.
///
/// `--git-dir` names the `.ruk` directory itself (or the root holding it);
/// otherwise the search walks up from the working directory for `.ruk`,
/// the way `setup_git_directory` walks for `.git`.
fn open_ctx(
    env: CliEnv,
    git_dir: Option<PathBuf>,
    work_tree: Option<PathBuf>,
    bare: bool,
    cli_config: Vec<(String, String)>,
    needs_repo: bool,
) -> Result<Ctx, GitError> {
    let budget = || Arc::new(PreparationBudget::reference_defaults());
    if !needs_repo {
        let root = work_tree.clone().unwrap_or_else(|| env.cwd.clone());
        let file_base = work_tree.unwrap_or_else(|| root.clone());
        let store = git_dir
            .as_deref()
            .and_then(|dir| Store::open(&git_dir_root(dir).join(".ruk"), budget()).ok());
        let kind = store.as_ref().map(Store::hash_kind);
        return Ok(Ctx {
            store,
            root,
            file_base,
            kind,
            env,
            bare,
            cli_config,
            stderr: Vec::new(),
        });
    }
    let root = find_root(&env.cwd, git_dir.as_deref(), bare)?;
    if let Some(work_tree) = &work_tree {
        if !work_tree.is_dir() {
            return Err(GitError::Io {
                detail: format!("work tree {} is not a directory", work_tree.display()),
            });
        }
    }
    let store = Store::open(&root.join(".ruk"), budget()).map_err(GitError::from)?;
    let kind = store.hash_kind();
    let file_base = work_tree.unwrap_or_else(|| root.clone());
    Ok(Ctx {
        store: Some(store),
        root,
        file_base,
        kind: Some(kind),
        env,
        bare,
        cli_config,
        stderr: Vec::new(),
    })
}

/// Runs `ruk lfs-payload-sync`: a native subcommand that shares the
/// verb's store plumbing without entering the `git` compatibility table.
pub(crate) fn lfs_payload_sync_native(
    repo: PathBuf,
    from: Option<String>,
    upload: bool,
) -> Result<Vec<u8>, GitError> {
    let mut env = CliEnv::capture();
    env.cwd = repo;
    let mut ctx = open_ctx(env, None, None, false, Vec::new(), true)?;
    let mut args = from.map_or_else(Vec::new, |dir| vec!["--from".to_owned(), dir]);
    if upload {
        args.push("--upload".to_owned());
    }
    verbs_transport::lfs_payload_sync(&mut ctx, &args)
}

/// Opens a store for repo-optional verbs when one is already there.
fn open_existing(root: &Path, git_dir: &Option<PathBuf>) -> Result<Store, GitError> {
    let budget = Arc::new(PreparationBudget::reference_defaults());
    if let Some(dir) = git_dir {
        let root = git_dir_root(dir);
        return Store::open(&root.join(".ruk"), budget).map_err(GitError::from);
    }
    find_root(root, None, false)
        .and_then(|found| Store::open(&found.join(".ruk"), budget).map_err(GitError::from))
}

/// Maps a `--git-dir` path to the repository root it belongs to.
fn git_dir_root(dir: &Path) -> PathBuf {
    if dir.file_name().is_some_and(|name| name == ".ruk") {
        dir.parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    } else {
        dir.to_path_buf()
    }
}

/// Walks up from `start` for a directory holding `.ruk`.
fn find_root(start: &Path, git_dir: Option<&Path>, bare: bool) -> Result<PathBuf, GitError> {
    if let Some(dir) = git_dir {
        let root = git_dir_root(dir);
        if root.join(".ruk").is_dir() || dir.is_dir() {
            return Ok(root);
        }
        return Err(GitError::Invalid {
            detail: format!("not a ruk repository: {}", dir.display()),
        });
    }
    if bare {
        if start.join(".ruk").is_dir() {
            return Ok(start.to_path_buf());
        }
        return Err(GitError::Invalid {
            detail: "not a ruk repository".to_owned(),
        });
    }
    let mut current = Some(start);
    while let Some(dir) = current {
        if dir.join(".ruk").is_dir() {
            return Ok(dir.to_path_buf());
        }
        current = dir.parent();
    }
    Err(GitError::Invalid {
        detail: "not a ruk repository (no .ruk found upward)".to_owned(),
    })
}

/// One flag declaration for [`collect`]: its long name, short alias, and
/// whether it consumes the following token, as `parse-options` knows per
/// builtin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FlagSpec {
    /// Long name without leading dashes.
    pub(crate) long: &'static str,
    /// Short alias, when the builtin offers one.
    pub(crate) short: Option<char>,
    /// The flag takes a value (`--flag=value` or `--flag value`).
    pub(crate) takes_value: bool,
}

/// Verbatim arguments collected against a spec: bare switches, valued
/// options, and positionals after `--`.
#[derive(Clone, Debug, Default)]
pub(crate) struct Collected {
    /// Flag name to its occurrences (`None` is a bare switch hit).
    pub(crate) present: HashMap<String, Vec<Option<String>>>,
    /// Non-flag arguments in order.
    pub(crate) positionals: Vec<String>,
}

impl Collected {
    /// Counts bare and valued hits of `name` together.
    #[must_use]
    pub(crate) fn count(&self, name: &str) -> usize {
        self.present.get(name).map_or(0, Vec::len)
    }

    /// Reports whether `name` was given at all.
    #[must_use]
    pub(crate) fn is_set(&self, name: &str) -> bool {
        self.count(name) > 0
    }

    /// Takes the single value of `name`, refusing repeats and bare hits.
    pub(crate) fn single(&self, name: &str) -> Result<Option<String>, GitError> {
        match self.present.get(name) {
            None => Ok(None),
            Some(values) => {
                if values.len() > 1 {
                    return Err(GitError::Invalid {
                        detail: format!("option --{name} given more than once"),
                    });
                }
                values[0].clone().map_or_else(
                    || {
                        Err(GitError::Invalid {
                            detail: format!("option --{name} requires a value"),
                        })
                    },
                    |value| Ok(Some(value)),
                )
            }
        }
    }

    /// Takes every value of a repeatable option, refusing bare hits.
    pub(crate) fn all(&self, name: &str) -> Result<Vec<String>, GitError> {
        match self.present.get(name) {
            None => Ok(Vec::new()),
            Some(values) => values
                .iter()
                .map(|value| {
                    value.clone().ok_or_else(|| GitError::Invalid {
                        detail: format!("option --{name} requires a value"),
                    })
                })
                .collect(),
        }
    }
}

/// Collects `args` against `specs`, stopping positionals at `--`.
pub(crate) fn collect(args: &[String], specs: &[FlagSpec]) -> Result<Collected, GitError> {
    let mut out = Collected::default();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            out.positionals.extend_from_slice(&args[index + 1..]);
            return Ok(out);
        }
        if arg.starts_with("--") {
            index = collect_long(&args, index, specs, &mut out)?;
        } else if arg.starts_with('-') && arg.len() > 1 {
            index = collect_short(&args, index, specs, &mut out)?;
        } else {
            out.positionals.push(arg.clone());
        }
        index += 1;
    }
    Ok(out)
}

/// Collects one `--long[=value]` token at `index`, returning `index`.
fn collect_long(
    args: &[String],
    index: usize,
    specs: &[FlagSpec],
    out: &mut Collected,
) -> Result<usize, GitError> {
    let token = &args[index][2..];
    let (name, inline) = token
        .split_once('=')
        .map_or((token, None), |(key, value)| (key, Some(value.to_owned())));
    let spec = specs
        .iter()
        .find(|spec| spec.long == name)
        .ok_or_else(|| GitError::Invalid {
            detail: format!("unknown option --{name}"),
        })?;
    if spec.takes_value {
        let had_inline = inline.is_some();
        let value = match inline {
            Some(inline) => inline,
            None => args
                .get(index + 1)
                .cloned()
                .ok_or_else(|| GitError::Invalid {
                    detail: format!("option --{name} requires a value"),
                })?,
        };
        out.present
            .entry(name.to_owned())
            .or_default()
            .push(Some(value));
        return Ok(if had_inline { index } else { index + 1 });
    }
    if inline.is_some() {
        return Err(GitError::Invalid {
            detail: format!("option --{name} takes no value"),
        });
    }
    out.present.entry(name.to_owned()).or_default().push(None);
    Ok(index)
}

/// Collects one `-x[value]` token at `index`, returning `index`.
fn collect_short(
    args: &[String],
    index: usize,
    specs: &[FlagSpec],
    out: &mut Collected,
) -> Result<usize, GitError> {
    let token = &args[index][1..];
    let mut chars = token.chars();
    let first = chars.next().ok_or_else(|| GitError::Invalid {
        detail: "bad option".to_owned(),
    })?;
    let spec = specs
        .iter()
        .find(|spec| spec.short == Some(first))
        .ok_or_else(|| GitError::Invalid {
            detail: format!("unknown option -{first}"),
        })?;
    if spec.takes_value {
        let rest: String = chars.collect();
        let (value, consumed) = if rest.is_empty() {
            (
                args.get(index + 1)
                    .cloned()
                    .ok_or_else(|| GitError::Invalid {
                        detail: format!("option -{first} requires a value"),
                    })?,
                true,
            )
        } else {
            (rest, false)
        };
        out.present
            .entry(spec.long.to_owned())
            .or_default()
            .push(Some(value));
        return Ok(if consumed { index + 1 } else { index });
    }
    if chars.next().is_some() {
        return Err(GitError::Invalid {
            detail: format!("unknown option group {}", args[index]),
        });
    }
    out.present
        .entry(spec.long.to_owned())
        .or_default()
        .push(None);
    Ok(index)
}

/// Renders bytes to stdout with a trailing newline when absent.
#[must_use]
pub(crate) fn line(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.last() != Some(&b'\n') {
        bytes.push(b'\n');
    }
    bytes
}
