//! Vendored from swc_common 12.0.1 by Ruk.
//!
//! The only change: `pub use serde::__private as serde;` is removed. serde
//! 1.0.225 moved its internals to `serde_core` and stopped re-exporting
//! `__private` from the facade, so that line no longer resolves. Nothing in
//! swc_common reads this module; it is deleted rather than repointed.
//! This module is private module and can be changed without notice.

