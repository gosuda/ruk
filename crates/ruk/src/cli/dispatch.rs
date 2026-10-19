//! Verb table: the 90 advertised names and their handlers.
//!
//! The shape mirrors `git.c:commands[]`: one row per verb with its oracle
//! anchor, whether it needs a repository, a one-line summary, and the entry
//! function. `ruk <verb> --help` rewrites to `ruk help <verb>` the way
//! `git.c:handle_builtin` rewrites `git <cmd> --help` to `git help`.

use ruk_git::GitError;

use super::verbs_bisect;
use super::verbs_blame;
use super::verbs_branch;
use super::verbs_bundle;
use super::verbs_grep;
use super::verbs_history;
use super::verbs_merge_plumbing;
use super::verbs_meta;
use super::verbs_misc;
use super::verbs_notes;
use super::verbs_objects;
use super::verbs_patch;
use super::verbs_repo;
use super::verbs_sparse;
use super::verbs_stage;
use super::verbs_submodule;
use super::verbs_transport;
use super::verbs_worktree;
use super::{Ctx, line};

/// One advertised verb, after `struct cmd_struct` in `git.c`.
pub(crate) struct Verb {
    /// Command name as typed.
    pub(crate) name: &'static str,
    /// The builtin file that defines its oracle semantics.
    pub(crate) oracle: &'static str,
    /// Needs repository discovery before running.
    pub(crate) needs_repo: bool,
    /// One-line summary for `help`.
    pub(crate) summary: &'static str,
    /// Entry function; returns bytes for stdout.
    pub(crate) run: fn(&mut Ctx, &[String]) -> Result<Vec<u8>, GitError>,
}

/// The 90 advertised verbs in alphabetical order.
pub(crate) static VERBS: &[Verb] = &[
    Verb {
        name: "add",
        oracle: "git/builtin/add.c",
        needs_repo: true,
        summary: "Add file contents to the index",
        run: verbs_stage::add,
    },
    Verb {
        name: "am",
        oracle: "git/builtin/am.c",
        needs_repo: true,
        summary: "Apply a series of patches from a mailbox",
        run: verbs_patch::am,
    },
    Verb {
        name: "annotate",
        oracle: "git/builtin/blame.c",
        needs_repo: true,
        summary: "Annotate each line with its introducing commit",
        run: verbs_blame::blame,
    },
    Verb {
        name: "apply",
        oracle: "git/builtin/apply.c",
        needs_repo: true,
        summary: "Apply a patch to files and/or to the index",
        run: verbs_patch::apply,
    },
    Verb {
        name: "archive",
        oracle: "git/builtin/archive.c",
        needs_repo: true,
        summary: "Create an archive of files from a named tree",
        run: verbs_transport::archive,
    },
    Verb {
        name: "bisect",
        oracle: "git/builtin/bisect.c",
        needs_repo: true,
        summary: "Find the commit that introduced a bug",
        run: verbs_bisect::bisect,
    },
    Verb {
        name: "blame",
        oracle: "git/builtin/blame.c",
        needs_repo: true,
        summary: "Show what revision and author last modified each line",
        run: verbs_blame::blame,
    },
    Verb {
        name: "branch",
        oracle: "git/builtin/branch.c",
        needs_repo: true,
        summary: "List, create, or delete branches",
        run: verbs_branch::branch,
    },
    Verb {
        name: "bundle",
        oracle: "git/builtin/bundle.c",
        needs_repo: true,
        summary: "Move objects and refs by archive",
        run: verbs_bundle::bundle,
    },
    Verb {
        name: "cat-file",
        oracle: "git/builtin/cat-file.c",
        needs_repo: true,
        summary: "Provide contents or details for repository objects",
        run: verbs_objects::cat_file,
    },
    Verb {
        name: "check-attr",
        oracle: "git/builtin/check-attr.c",
        needs_repo: false,
        summary: "Display gitattributes information",
        run: verbs_misc::check_attr,
    },
    Verb {
        name: "check-ignore",
        oracle: "git/builtin/check-ignore.c",
        needs_repo: false,
        summary: "Test whether paths are ignored",
        run: verbs_misc::check_ignore,
    },
    Verb {
        name: "check-ref-format",
        oracle: "git/builtin/check-ref-format.c",
        needs_repo: false,
        summary: "Ensure that a reference name is well formed",
        run: verbs_objects::check_ref_format,
    },
    Verb {
        name: "checkout",
        oracle: "git/builtin/checkout.c",
        needs_repo: true,
        summary: "Switch branches or restore working tree files",
        run: verbs_branch::checkout,
    },
    Verb {
        name: "checkout-index",
        oracle: "git/builtin/checkout-index.c",
        needs_repo: true,
        summary: "Copy files from the index to the working directory",
        run: verbs_merge_plumbing::checkout_index,
    },
    Verb {
        name: "cherry",
        oracle: "git/builtin/cherry.c",
        needs_repo: true,
        summary: "Find commits not yet applied upstream",
        run: verbs_misc::cherry,
    },
    Verb {
        name: "cherry-pick",
        oracle: "git/builtin/revert.c (cmd_cherry_pick)",
        needs_repo: true,
        summary: "Apply the changes introduced by existing commits",
        run: verbs_history::cherry_pick,
    },
    Verb {
        name: "clean",
        oracle: "git/builtin/clean.c",
        needs_repo: true,
        summary: "Remove untracked files from the working tree",
        run: verbs_misc::clean,
    },
    Verb {
        name: "clone",
        oracle: "git/builtin/clone.c",
        needs_repo: false,
        summary: "Clone a repository into a new directory",
        run: verbs_repo::clone,
    },
    Verb {
        name: "commit",
        oracle: "git/builtin/commit.c",
        needs_repo: true,
        summary: "Record changes to the repository",
        run: verbs_history::commit,
    },
    Verb {
        name: "commit-tree",
        oracle: "git/builtin/commit-tree.c",
        needs_repo: true,
        summary: "Create a new commit object",
        run: verbs_objects::commit_tree,
    },
    Verb {
        name: "config",
        oracle: "git/builtin/config.c",
        needs_repo: true,
        summary: "Get and set repository options",
        run: verbs_repo::config,
    },
    Verb {
        name: "count-objects",
        oracle: "git/builtin/count-objects.c",
        needs_repo: true,
        summary: "Count unpacked objects and display their disk consumption",
        run: verbs_objects::count_objects,
    },
    Verb {
        name: "credential",
        oracle: "git/builtin/credential.c",
        needs_repo: false,
        summary: "Fill and approve credentials",
        run: verbs_transport::credential,
    },
    Verb {
        name: "describe",
        oracle: "git/builtin/describe.c",
        needs_repo: true,
        summary: "Name a commit by its nearest tag",
        run: verbs_misc::describe,
    },
    Verb {
        name: "diff",
        oracle: "git/builtin/diff.c",
        needs_repo: true,
        summary: "Show changes between commits, commit and working tree, etc",
        run: verbs_history::diff,
    },
    Verb {
        name: "fetch",
        oracle: "git/builtin/fetch.c",
        needs_repo: true,
        summary: "Download objects and refs from another repository",
        run: verbs_transport::fetch,
    },
    Verb {
        name: "fmt-merge-msg",
        oracle: "git/builtin/fmt-merge-msg.c",
        needs_repo: true,
        summary: "Format a merge message from FETCH_HEAD",
        run: verbs_misc::fmt_merge_msg,
    },
    Verb {
        name: "for-each-ref",
        oracle: "git/builtin/for-each-ref.c",
        needs_repo: true,
        summary: "Output information on each ref",
        run: verbs_branch::for_each_ref,
    },
    Verb {
        name: "format-patch",
        oracle: "git/builtin/log.c",
        needs_repo: true,
        summary: "Prepare patches for e-mail submission",
        run: verbs_patch::format_patch,
    },
    Verb {
        name: "fsck",
        oracle: "git/builtin/fsck.c",
        needs_repo: true,
        summary: "Verify the connectivity and validity of objects",
        run: verbs_transport::fsck,
    },
    Verb {
        name: "gc",
        oracle: "git/builtin/gc.c",
        needs_repo: true,
        summary: "Cleanup unnecessary files and optimize the local repository",
        run: verbs_transport::gc,
    },
    Verb {
        name: "get-tar-commit-id",
        oracle: "git/builtin/get-tar-commit-id.c",
        needs_repo: false,
        summary: "Print the commit id stored in a tar archive",
        run: verbs_misc::get_tar_commit_id,
    },
    Verb {
        name: "grep",
        oracle: "git/builtin/grep.c",
        needs_repo: true,
        summary: "Print lines matching a pattern",
        run: verbs_grep::grep,
    },
    Verb {
        name: "hash-object",
        oracle: "git/builtin/hash-object.c",
        needs_repo: false,
        summary: "Compute object ID and optionally create an object",
        run: verbs_objects::hash_object,
    },
    Verb {
        name: "help",
        oracle: "git/builtin/help.c",
        needs_repo: false,
        summary: "Display help information about ruk",
        run: verbs_meta::help,
    },
    Verb {
        name: "index-pack",
        oracle: "git/builtin/index-pack.c",
        needs_repo: true,
        summary: "Build pack index file for an existing packed archive",
        run: verbs_objects::index_pack,
    },
    Verb {
        name: "init",
        oracle: "git/builtin/init-db.c",
        needs_repo: false,
        summary: "Create an empty Ruk repository",
        run: verbs_repo::init,
    },
    Verb {
        name: "interpret-trailers",
        oracle: "git/builtin/interpret-trailers.c",
        needs_repo: false,
        summary: "Parse commit-message trailers",
        run: verbs_misc::interpret_trailers,
    },
    Verb {
        name: "log",
        oracle: "git/builtin/log.c",
        needs_repo: true,
        summary: "Show commit logs",
        run: verbs_history::log,
    },
    Verb {
        name: "ls-files",
        oracle: "git/builtin/ls-files.c",
        needs_repo: true,
        summary: "Show information about files in the index",
        run: verbs_stage::ls_files,
    },
    Verb {
        name: "ls-remote",
        oracle: "git/builtin/ls-remote.c",
        needs_repo: false,
        summary: "List references in a remote repository",
        run: verbs_transport::ls_remote,
    },
    Verb {
        name: "ls-tree",
        oracle: "git/builtin/ls-tree.c",
        needs_repo: true,
        summary: "List the contents of a tree object",
        run: verbs_objects::ls_tree,
    },
    Verb {
        name: "merge",
        oracle: "git/builtin/merge.c",
        needs_repo: true,
        summary: "Join two or more development histories together",
        run: verbs_history::merge,
    },
    Verb {
        name: "merge-base",
        oracle: "git/builtin/merge-base.c",
        needs_repo: true,
        summary: "Find as good common ancestors as possible for a merge",
        run: verbs_history::merge_base,
    },
    Verb {
        name: "merge-file",
        oracle: "git/builtin/merge-file.c",
        needs_repo: false,
        summary: "Run a three-way file merge",
        run: verbs_merge_plumbing::merge_file_cmd,
    },
    Verb {
        name: "merge-tree",
        oracle: "git/builtin/merge-tree.c",
        needs_repo: true,
        summary: "Show three-way merge without touching the index",
        run: verbs_merge_plumbing::merge_tree,
    },
    Verb {
        name: "migrate",
        oracle: "git/builtin/init-db.c",
        needs_repo: false,
        summary: "Import an existing Git repository into a .ruk store",
        run: verbs_repo::migrate,
    },
    Verb {
        name: "mktree",
        oracle: "git/builtin/mktree.c",
        needs_repo: true,
        summary: "Build a tree-object from ls-tree formatted text",
        run: verbs_objects::mktree,
    },
    Verb {
        name: "mv",
        oracle: "git/builtin/mv.c",
        needs_repo: true,
        summary: "Move or rename a file, a directory, or a symlink",
        run: verbs_stage::mv,
    },
    Verb {
        name: "name-rev",
        oracle: "git/builtin/name-rev.c",
        needs_repo: true,
        summary: "Name an object by a nearby ref",
        run: verbs_misc::name_rev,
    },
    Verb {
        name: "notes",
        oracle: "git/builtin/notes.c",
        needs_repo: true,
        summary: "Add or inspect object notes",
        run: verbs_notes::notes,
    },
    Verb {
        name: "pack-objects",
        oracle: "git/builtin/pack-objects.c",
        needs_repo: true,
        summary: "Create a packed archive of objects",
        run: verbs_objects::pack_objects,
    },
    Verb {
        name: "pull",
        oracle: "git/builtin/pull.c",
        needs_repo: true,
        summary: "Fetch from and integrate with another repository",
        run: verbs_transport::pull,
    },
    Verb {
        name: "push",
        oracle: "git/builtin/push.c",
        needs_repo: true,
        summary: "Update remote refs along with associated objects",
        run: verbs_transport::push,
    },
    Verb {
        name: "read-tree",
        oracle: "git/builtin/read-tree.c",
        needs_repo: true,
        summary: "Read tree information into the index",
        run: verbs_merge_plumbing::read_tree,
    },
    Verb {
        name: "rebase",
        oracle: "git/builtin/rebase.c",
        needs_repo: true,
        summary: "Reapply commits on top of another base tip",
        run: verbs_history::rebase,
    },
    Verb {
        name: "receive-pack",
        oracle: "git/builtin/receive-pack.c",
        needs_repo: false,
        summary: "Receive what is pushed into the repository",
        run: verbs_transport::receive_pack,
    },
    Verb {
        name: "reflog",
        oracle: "git/builtin/reflog.c",
        needs_repo: true,
        summary: "Show and expire reflog records",
        run: verbs_misc::reflog,
    },
    Verb {
        name: "remote",
        oracle: "git/builtin/remote.c",
        needs_repo: true,
        summary: "Manage the set of tracked repositories",
        run: verbs_repo::remote,
    },
    Verb {
        name: "replace",
        oracle: "git/builtin/replace.c",
        needs_repo: true,
        summary: "Create, list, and delete object replacements",
        run: verbs_notes::replace,
    },
    Verb {
        name: "rerere",
        oracle: "git/builtin/rerere.c",
        needs_repo: true,
        summary: "Reuse recorded resolution of conflicted merges",
        run: verbs_merge_plumbing::rerere,
    },
    Verb {
        name: "reset",
        oracle: "git/builtin/reset.c",
        needs_repo: true,
        summary: "Reset current HEAD to the specified state",
        run: verbs_branch::reset,
    },
    Verb {
        name: "restore",
        oracle: "git/builtin/restore.c",
        needs_repo: true,
        summary: "Restore working tree files",
        run: verbs_branch::restore,
    },
    Verb {
        name: "rev-list",
        oracle: "git/builtin/rev-list.c",
        needs_repo: true,
        summary: "List commit objects in reverse chronological order",
        run: verbs_history::rev_list,
    },
    Verb {
        name: "rev-parse",
        oracle: "git/builtin/rev-parse.c",
        needs_repo: true,
        summary: "Pick out and massage parameters",
        run: verbs_history::rev_parse,
    },
    Verb {
        name: "revert",
        oracle: "git/builtin/revert.c (cmd_revert)",
        needs_repo: true,
        summary: "Revert existing commits",
        run: verbs_history::revert,
    },
    Verb {
        name: "rm",
        oracle: "git/builtin/rm.c",
        needs_repo: true,
        summary: "Remove files from the working tree and from the index",
        run: verbs_stage::rm,
    },
    Verb {
        name: "show",
        oracle: "git/builtin/log.c (cmd_show)",
        needs_repo: true,
        summary: "Show various types of objects",
        run: verbs_history::show,
    },
    Verb {
        name: "shortlog",
        oracle: "git/builtin/shortlog.c",
        needs_repo: true,
        summary: "Summarize history by author",
        run: verbs_misc::shortlog,
    },
    Verb {
        name: "show-ref",
        oracle: "git/builtin/show-ref.c",
        needs_repo: true,
        summary: "List references in a local repository",
        run: verbs_branch::show_ref,
    },
    Verb {
        name: "sparse-checkout",
        oracle: "git/builtin/sparse-checkout.c",
        needs_repo: true,
        summary: "Initialize and modify the sparse-checkout",
        run: verbs_sparse::sparse_checkout,
    },
    Verb {
        name: "stash",
        oracle: "git/builtin/stash.c",
        needs_repo: true,
        summary: "Stash the changes in a dirty working directory away",
        run: verbs_branch::stash,
    },
    Verb {
        name: "status",
        oracle: "git/builtin/commit.c (cmd_status)",
        needs_repo: true,
        summary: "Show the working tree status",
        run: verbs_stage::status,
    },
    Verb {
        name: "stripspace",
        oracle: "git/builtin/stripspace.c",
        needs_repo: false,
        summary: "Clean whitespace from standard input",
        run: verbs_misc::stripspace,
    },
    Verb {
        name: "submodule",
        oracle: "git/builtin/submodule--helper.c",
        needs_repo: true,
        summary: "Initialize, update or inspect submodules",
        run: verbs_submodule::submodule,
    },
    Verb {
        name: "switch",
        oracle: "git/builtin/switch.c",
        needs_repo: true,
        summary: "Switch branches",
        run: verbs_branch::switch,
    },
    Verb {
        name: "symbolic-ref",
        oracle: "git/builtin/symbolic-ref.c",
        needs_repo: true,
        summary: "Read, modify and delete symbolic refs",
        run: verbs_branch::symbolic_ref,
    },
    Verb {
        name: "tag",
        oracle: "git/builtin/tag.c",
        needs_repo: true,
        summary: "Create, list, delete or verify a tag object",
        run: verbs_branch::tag,
    },
    Verb {
        name: "update-index",
        oracle: "git/builtin/update-index.c",
        needs_repo: true,
        summary: "Register file contents in the working tree to the index",
        run: verbs_stage::update_index,
    },
    Verb {
        name: "update-ref",
        oracle: "git/builtin/update-ref.c",
        needs_repo: true,
        summary: "Update the object name stored in a ref safely",
        run: verbs_branch::update_ref,
    },
    Verb {
        name: "upload-archive",
        oracle: "git/builtin/upload-archive.c",
        needs_repo: false,
        summary: "Serve archives to git-archive --remote",
        run: verbs_transport::upload_archive,
    },
    Verb {
        name: "upload-pack",
        oracle: "git/builtin/upload-pack.c",
        needs_repo: false,
        summary: "Send objects packed back to git-fetch-pack",
        run: verbs_transport::upload_pack,
    },
    Verb {
        name: "var",
        oracle: "git/builtin/var.c",
        needs_repo: false,
        summary: "Show a Git logical variable",
        run: verbs_misc::var,
    },
    Verb {
        name: "verify-commit",
        oracle: "git/builtin/verify-commit.c",
        needs_repo: true,
        summary: "Check commit signatures (refuses: none exist)",
        run: verbs_misc::verify_commit,
    },
    Verb {
        name: "verify-pack",
        oracle: "git/builtin/verify-pack.c",
        needs_repo: true,
        summary: "Validate packed Git archive files",
        run: verbs_objects::verify_pack,
    },
    Verb {
        name: "verify-tag",
        oracle: "git/builtin/verify-tag.c",
        needs_repo: true,
        summary: "Check tag signatures (refuses: none exist)",
        run: verbs_misc::verify_tag,
    },
    Verb {
        name: "version",
        oracle: "git/builtin/version.c",
        needs_repo: false,
        summary: "Display version information",
        run: verbs_meta::version,
    },
    Verb {
        name: "worktree",
        oracle: "git/builtin/worktree.c",
        needs_repo: true,
        summary: "Manage multiple working trees",
        run: verbs_worktree::worktree,
    },
    Verb {
        name: "write-tree",
        oracle: "git/builtin/write-tree.c",
        needs_repo: true,
        summary: "Create a tree object from the current index",
        run: verbs_objects::write_tree,
    },
];

/// Looks up one verb by name.
///
/// A leading `git-` falls back to the bare verb (`git-upload-pack` resolves
/// to `upload-pack`), mirroring how `git.c` strips the prefix before its
/// builtin lookup. No advertised name starts with `git-`, so the direct
/// match always wins and the fallback can never shadow one.
#[must_use]
pub(crate) fn lookup(name: &str) -> Option<&'static Verb> {
    VERBS.iter().find(|verb| verb.name == name).or_else(|| {
        name.strip_prefix("git-")
            .and_then(|rest| VERBS.iter().find(|verb| verb.name == rest))
    })
}

/// Renders `ruk version`.
#[must_use]
pub(crate) fn version_text() -> Vec<u8> {
    line(format!("ruk version {}", env!("CARGO_PKG_VERSION")).into_bytes())
}

/// Renders the top-level help or one verb's help.
#[must_use]
pub(crate) fn help_text(entry: Option<&Verb>) -> Vec<u8> {
    match entry {
        Some(verb) => line(
            format!(
                "ruk {} - {}\noracle: {}\nsee 'ruk help' for the verb list",
                verb.name, verb.summary, verb.oracle
            )
            .into_bytes(),
        ),
        None => {
            let mut out = b"usage: ruk [-C <path>] [-c <name>=<value>] [--git-dir=<path>] [--bare] <command> [<args>]\n\ncommands:\n".to_vec();
            for verb in VERBS {
                out.extend_from_slice(format!("  {:<16} {}\n", verb.name, verb.summary).as_bytes());
            }
            out
        }
    }
}
