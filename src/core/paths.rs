//! The one place that knows where this server keeps state.
//!
//! Everything durable and scratch lives under a single per-user root,
//! `~/.filesystem-mcp-rs/`, identically on Windows, macOS and Linux. State used to be
//! spread over four roots (`data_local_dir`, `data_dir`, two different temp subdirs), two
//! of which differ per OS and per Windows account, which made "where is it?" unanswerable.
//!
//! No other module may call `dirs::*` or `std::env::temp_dir()`; `paths_are_centralized`
//! in `src/core/paths_guard.rs` enforces that mechanically.

// The resolver lands before its callers: the call sites move onto it in the later tasks of
// this wave, so parts of the surface are legitimately unreferenced until then.
#![allow(dead_code)]

use std::io;
use std::path::PathBuf;

use crate::env_spec;

/// A subdirectory of the state root. One variant per kind of state the server keeps,
/// so the names exist once instead of being spelled at each call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubDir {
    /// Per-process log files (wave 2).
    Logs,
    /// Downloaded OCR models.
    Ocrs,
    /// Saved window layouts.
    Layouts,
    /// Computer-control safety state.
    Safety,
    /// Scratch: captures, `run_command` output, temporary scripts. Swept by age.
    Tmp,
}

impl SubDir {
    /// Directory name on disk.
    pub fn as_str(&self) -> &'static str {
        match self {
            SubDir::Logs => "logs",
            SubDir::Ocrs => "ocrs",
            SubDir::Layouts => "layouts",
            SubDir::Safety => "safety",
            SubDir::Tmp => "tmp",
        }
    }
}

/// The state root, created if missing.
pub fn state_dir() -> io::Result<PathBuf> {
    resolve_root(env_spec::get("FS_MCP_STATE_DIR").map(PathBuf::from))
}

/// Path of a file directly in the state root (`stats.db`, `memory2.db`, `panic.log`).
/// The root is created; the file is not.
pub fn db_path(name: &str) -> io::Result<PathBuf> {
    Ok(state_dir()?.join(name))
}

/// A subdirectory of the state root, created if missing.
pub fn sub_dir(kind: SubDir) -> io::Result<PathBuf> {
    resolve_sub(env_spec::get("FS_MCP_STATE_DIR").map(PathBuf::from), kind)
}

/// Resolve and create the root. Split from [`state_dir`] so tests can inject an override
/// without mutating the process environment.
fn resolve_root(override_dir: Option<PathBuf>) -> io::Result<PathBuf> {
    let root = resolve_root_from(override_dir, dirs::home_dir())?;
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

/// Resolve a subdirectory and create it. Split for the same reason as [`resolve_root`].
fn resolve_sub(override_dir: Option<PathBuf>, kind: SubDir) -> io::Result<PathBuf> {
    let dir = resolve_root(override_dir)?.join(kind.as_str());
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Pure path arithmetic: the override wins, otherwise `<home>/.filesystem-mcp-rs`.
///
/// Returns an error rather than falling back to the current directory: a silent fallback
/// would put a database wherever the agent happened to start, and the resulting
/// "my memory disappeared" bug costs far more than a loud failure at startup.
fn resolve_root_from(override_dir: Option<PathBuf>, home: Option<PathBuf>) -> io::Result<PathBuf> {
    if let Some(dir) = override_dir {
        return Ok(dir);
    }
    match home {
        Some(h) => Ok(h.join(".filesystem-mcp-rs")),
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Cannot resolve the home directory; set FS_MCP_STATE_DIR to choose the state directory explicitly",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The override wins over the home directory, and the root is created on demand.
    /// This is also the seam every other test uses to avoid touching the real home dir.
    #[test]
    fn override_redirects_root_and_creates_it() {
        let tmp = std::env::temp_dir().join(format!("fsmcp-paths-{}", uuid::Uuid::new_v4()));
        let root = resolve_root(Some(tmp.clone())).expect("root resolves");
        assert_eq!(root, tmp);
        assert!(tmp.is_dir(), "root must be created on demand");
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Every subdirectory hangs off the root under its documented name.
    #[test]
    fn subdirs_hang_off_root() {
        let tmp = std::env::temp_dir().join(format!("fsmcp-paths-{}", uuid::Uuid::new_v4()));
        let logs = resolve_sub(Some(tmp.clone()), SubDir::Logs).expect("logs dir");
        assert_eq!(logs, tmp.join("logs"));
        assert!(logs.is_dir());
        assert_eq!(SubDir::Tmp.as_str(), "tmp");
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// An unresolvable home is an error, never a silent fallback to the current directory:
    /// falling back would scatter databases into whatever directory an agent started in.
    #[test]
    fn unresolvable_home_is_an_error() {
        let err = resolve_root_from(None, None).expect_err("must not fall back");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(err.to_string().contains("FS_MCP_STATE_DIR"));
    }
}
