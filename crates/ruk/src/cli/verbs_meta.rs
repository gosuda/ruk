//! Session verbs: `help` and `version`.
//!
//! | verb | backing | status |
//! | --- | --- | --- |
//! | `help` | static verb table | implemented |
//! | `version` | `CARGO_PKG_VERSION` | implemented |
//!
//! Oracle anchors: `git/builtin/help.c`, `git/builtin/version.c`.

use ruk_git::GitError;

use super::dispatch::{help_text, lookup, version_text};
use super::{Ctx, line};

/// Shows the verb list or one verb's summary.
///
/// Oracle: `git/builtin/help.c`.
pub(crate) fn help(_ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    if args.iter().any(|arg| arg.starts_with('-')) {
        return Err(GitError::Invalid {
            detail: "help takes only a command name".to_owned(),
        });
    }
    match args.first() {
        None => Ok(help_text(None)),
        Some(name) => lookup(name).map_or_else(
            || {
                Err(GitError::NotFound {
                    detail: format!("no help for {name:?}"),
                })
            },
            |entry| Ok(help_text(Some(entry))),
        ),
    }
}

/// Prints the executable version.
///
/// Oracle: `git/builtin/version.c`.
pub(crate) fn version(_ctx: &mut Ctx, args: &[String]) -> Result<Vec<u8>, GitError> {
    if !args.is_empty() {
        return Err(GitError::Invalid {
            detail: "version takes no arguments".to_owned(),
        });
    }
    Ok(line(version_text()))
}
