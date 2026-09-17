//! The one place that knows where this server keeps state.
//!
//! Everything durable and scratch lives under a single per-user root,
//! `~/.filesystem-mcp-rs/`, identically on Windows, macOS and Linux. State used to be
//! spread over four roots (`data_local_dir`, `data_dir`, two different temp subdirs), two
//! of which differ per OS and per Windows account, which made "where is it?" unanswerable.
//!
//! No other module may call `dirs::*` or `std::env::temp_dir()`; `paths_are_centralized`
//! in `src/core/paths_guard.rs` enforces that mechanically.

use std::io;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::env_spec;

/// A subdirectory of the state root. One variant per kind of state the server keeps,
/// so the names exist once instead of being spelled at each call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubDir {
    /// Per-process log files (wave 2).
    #[allow(dead_code)] // wired when logging lands in wave 2; delete this attribute there
    Logs,
    /// Downloaded OCR models.
    Ocrs,
    /// Saved window layouts.
    Layouts,
    /// Computer-control safety state.
    Safety,
    /// Scratch: captures, `run_command` output, temporary scripts. Swept by age.
    #[allow(dead_code)] // wired by Task 4; delete this attribute there
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
///
/// A relative override is rejected for the same reason: `FS_MCP_STATE_DIR=state` resolves
/// against the process working directory, which is whatever launched the server, and would
/// reintroduce exactly the scattering this module exists to remove.
fn resolve_root_from(override_dir: Option<PathBuf>, home: Option<PathBuf>) -> io::Result<PathBuf> {
    if let Some(dir) = override_dir {
        if !dir.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "FS_MCP_STATE_DIR must be an absolute path, got {}",
                    dir.display()
                ),
            ));
        }
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

/// Outcome of migrating one location from its pre-2026-09 home to the state root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Migrated {
    /// The old location existed and was moved to the new one.
    Moved,
    /// Nothing to migrate: either neither path exists, or only the new one does. The latter is
    /// the steady state of every run after a successful migration, so this variant means "no
    /// action required", not "the server has no data".
    FreshStart,
    /// Both existed, or the move failed. Nothing was touched: the data is still at `old`.
    Ambiguous { old: PathBuf, new: PathBuf },
}

/// Move `old` to `new` when that is unambiguous.
///
/// **Single files only.** Every location this wave migrates is one file; the directories under
/// the state root (`ocrs`, `layouts`, `safety`) are regenerable and are never migrated. A
/// directory `old` is therefore a programming error, and is refused rather than half-moved:
/// `fs::copy` cannot copy a directory and `fs::remove_file` cannot remove one, so the
/// cross-volume path would corrupt the outcome while the same-volume path silently worked.
///
/// `rename` is instantaneous within a volume; across volumes it fails with a platform-specific
/// error, so we fall back to copy + remove. On any failure the original at `old` is left intact
/// and a partial or duplicate `new` is removed, so `Ambiguous` means literally what it says:
/// after a failed migration the only file that exists is the original.
///
/// Coverage note, precisely: the cross-volume `copy` fallback is never entered on a single-volume
/// test machine, so the copy step itself is verified by inspection only. The cleanup that removes
/// a leftover `new` is reached on Windows by `migrate_removes_the_leftover_when_the_original_cannot_be_unlinked`;
/// on Unix that arm is verified by reading. The parent-creation failure returns before any of
/// this and is covered separately.
pub fn migrate(old: &Path, new: &Path) -> Migrated {
    let ambiguous = || Migrated::Ambiguous {
        old: old.to_path_buf(),
        new: new.to_path_buf(),
    };
    if old.is_dir() {
        warn!(
            "Refusing to migrate {}: migrate() moves single files, not directories",
            old.display()
        );
        return ambiguous();
    }
    match (old.exists(), new.exists()) {
        (true, false) => {
            if let Some(parent) = new.parent()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                warn!("Cannot create {}: {e}", parent.display());
                return ambiguous();
            }
            if std::fs::rename(old, new).is_ok() {
                info!("Migrated {} -> {}", old.display(), new.display());
                return Migrated::Moved;
            }
            match std::fs::copy(old, new).and_then(|_| std::fs::remove_file(old)) {
                Ok(()) => {
                    info!("Migrated (copied) {} -> {}", old.display(), new.display());
                    Migrated::Moved
                }
                Err(e) => {
                    warn!(
                        "Failed to migrate {} -> {}: {e}",
                        old.display(),
                        new.display()
                    );
                    // The copy may have half-written `new`, or have succeeded with only the
                    // removal of `old` failing. Either way `new` must go: a truncated database
                    // would be opened as real data, and a complete duplicate would make every
                    // later startup see two candidates and report a conflict forever.
                    if new.exists()
                        && let Err(e) = std::fs::remove_file(new)
                    {
                        // Deliberately not "copy": this file may be a truncated partial, and an
                        // operator told it is a copy would assume the data there is complete.
                        warn!(
                            "Left a leftover file at {} that could not be removed: {e}",
                            new.display()
                        );
                    }
                    ambiguous()
                }
            }
        }
        (true, true) => ambiguous(),
        (false, _) => Migrated::FreshStart,
    }
}

/// The pre-2026-09 root for files that lived in `data_local_dir`, used only to find data left
/// by older builds. Never used for new writes.
pub fn legacy_local_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("filesystem-mcp-rs"))
}

/// The pre-2026-09 path of the computer-control audit log, the one file under the old
/// `computer-mcp-rs` directory that cannot be regenerated. Used only to migrate it; the
/// sibling directories there (ocrs models, layouts, safety state) are re-created on demand
/// and are deliberately not moved.
///
/// Returns the file, not the directory it sits in, so no caller can hand a directory to
/// [`migrate`], which refuses those.
pub fn legacy_ctl_audit() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("computer-mcp-rs").join("audit.jsonl"))
}

/// What the caller should do with the memory database after migration.
///
/// Produced by [`memory_db_decision`] and consumed at startup in `main.rs`, which either opens
/// the database at the new path or leaves the memory tools out of the server entirely.
#[derive(Debug)]
pub enum MemoryDbDecision {
    /// Open the database at the new path.
    Use,
    /// Do not open anything; report this message to the operator.
    Disabled(String),
}

/// Two memory databases mean two different sets of the user's notes. Choosing one silently is
/// how "where did my memories go" bugs are born, so the store stays off until a human decides
/// which file to keep.
pub fn memory_db_decision(m: Migrated) -> MemoryDbDecision {
    match m {
        Migrated::Moved | Migrated::FreshStart => MemoryDbDecision::Use,
        Migrated::Ambiguous { old, new } => MemoryDbDecision::Disabled(format!(
            "Memory tools disabled: a memory database exists both at {} and at {}. \
             Keep the one you want, delete or rename the other, then restart.",
            old.display(),
            new.display()
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

    /// A relative override is refused: it would resolve against whatever directory launched the
    /// server, which is the scattering this module exists to remove.
    #[test]
    fn relative_override_is_rejected() {
        let err = resolve_root_from(Some(PathBuf::from("state")), dirs::home_dir())
            .expect_err("a relative override must not be accepted");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let msg = err.to_string();
        assert!(msg.contains("FS_MCP_STATE_DIR"), "{msg}");
        assert!(msg.contains("state"), "{msg}");
    }

    /// An ambiguous memory database must disable the memory store rather than pick a file.
    #[test]
    fn ambiguous_memory_db_disables_the_store() {
        let decision = memory_db_decision(Migrated::Ambiguous {
            old: PathBuf::from("/old/memory2.db"),
            new: PathBuf::from("/new/memory2.db"),
        });
        match decision {
            MemoryDbDecision::Disabled(msg) => {
                assert!(msg.contains("/old/memory2.db") && msg.contains("/new/memory2.db"));
            }
            other => panic!("expected Disabled, got {other:?}"),
        }
        assert!(matches!(memory_db_decision(Migrated::Moved), MemoryDbDecision::Use));
        assert!(matches!(
            memory_db_decision(Migrated::FreshStart),
            MemoryDbDecision::Use
        ));
    }

    /// Old file present, new absent: the data moves and the old path is gone.
    #[test]
    fn migrate_moves_when_unambiguous() {
        let base = std::env::temp_dir().join(format!("fsmcp-mig-{}", uuid::Uuid::new_v4()));
        let old = base.join("old/memory2.db");
        let new = base.join("new/memory2.db");
        std::fs::create_dir_all(old.parent().expect("parent")).expect("mkdir");
        std::fs::write(&old, b"payload").expect("write");

        assert_eq!(migrate(&old, &new), Migrated::Moved);
        assert!(!old.exists(), "old path must be gone after a move");
        assert_eq!(std::fs::read(&new).expect("read"), b"payload");
        std::fs::remove_dir_all(&base).ok();
    }

    /// Both present: refuse to guess, touch nothing.
    #[test]
    fn migrate_refuses_when_both_exist() {
        let base = std::env::temp_dir().join(format!("fsmcp-mig-{}", uuid::Uuid::new_v4()));
        let old = base.join("old/memory2.db");
        let new = base.join("new/memory2.db");
        for p in [&old, &new] {
            std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
            std::fs::write(p, b"payload").expect("write");
        }

        match migrate(&old, &new) {
            Migrated::Ambiguous { old: o, new: n } => {
                assert_eq!(o, old);
                assert_eq!(n, new);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
        assert!(old.exists() && new.exists(), "neither file may be touched");
        std::fs::remove_dir_all(&base).ok();
    }

    /// Nothing to migrate, and nothing conjured into existence while finding that out.
    #[test]
    fn migrate_reports_fresh_start() {
        let base = std::env::temp_dir().join(format!("fsmcp-mig-{}", uuid::Uuid::new_v4()));
        let old = base.join("old.db");
        let new = base.join("new.db");
        assert_eq!(migrate(&old, &new), Migrated::FreshStart);
        assert!(!old.exists() && !new.exists(), "nothing may be created");
        assert!(!base.exists(), "the parent may not be created either");
    }

    /// A directory is refused outright: `fs::copy` cannot copy one and `fs::remove_file` cannot
    /// remove one, so the cross-volume path would corrupt what the same-volume path moved fine.
    #[test]
    fn migrate_refuses_a_directory() {
        let base = std::env::temp_dir().join(format!("fsmcp-mig-{}", uuid::Uuid::new_v4()));
        let old = base.join("old_dir");
        let new = base.join("new_dir");
        std::fs::create_dir_all(old.join("inner")).expect("mkdir");

        assert_eq!(
            migrate(&old, &new),
            Migrated::Ambiguous {
                old: old.clone(),
                new: new.clone()
            }
        );
        assert!(old.join("inner").is_dir(), "the directory must be intact");
        assert!(!new.exists(), "nothing may be created at the new path");
        std::fs::remove_dir_all(&base).ok();
    }

    /// When the new parent cannot be created the original must survive untouched. This is the
    /// portable stand-in for the failure handling around the cross-volume copy: a plain file sits
    /// where `new`'s parent directory would go, so `create_dir_all` cannot succeed.
    #[test]
    fn migrate_keeps_the_original_when_the_new_parent_cannot_be_created() {
        let base = std::env::temp_dir().join(format!("fsmcp-mig-{}", uuid::Uuid::new_v4()));
        let old = base.join("old/memory2.db");
        let blocker = base.join("blocker");
        let new = blocker.join("memory2.db");
        std::fs::create_dir_all(old.parent().expect("parent")).expect("mkdir");
        std::fs::write(&old, b"payload").expect("write");
        std::fs::write(&blocker, b"not a directory").expect("write blocker");

        assert_eq!(
            migrate(&old, &new),
            Migrated::Ambiguous {
                old: old.clone(),
                new: new.clone()
            }
        );
        assert!(old.exists(), "the original must survive a failed migration");
        assert_eq!(std::fs::read(&old).expect("read"), b"payload");
        assert!(!new.exists(), "no partial file may be left at the new path");
        std::fs::remove_dir_all(&base).ok();
    }

    /// The CQ-1 cleanup arm: `copy` succeeded but `remove_file(old)` failed, so a complete
    /// duplicate exists at `new` and must be removed - otherwise every later startup would see
    /// two candidates and report a conflict that never resolves.
    ///
    /// Windows-only because this is the one way to provoke that exact shape without injecting a
    /// filesystem seam: a handle opened with `share_mode(FILE_SHARE_READ)` lets `copy` read the
    /// file while denying the DELETE access that `rename` and `remove_file` both need. Unix has
    /// no equivalent (an open file is still unlinkable), so there that arm is verified by reading.
    #[test]
    #[cfg(windows)]
    fn migrate_removes_the_leftover_when_the_original_cannot_be_unlinked() {
        use std::os::windows::fs::OpenOptionsExt;
        // Readers allowed, deleters and renamers refused.
        const FILE_SHARE_READ: u32 = 0x0000_0001;

        let base = std::env::temp_dir().join(format!("fsmcp-mig-{}", uuid::Uuid::new_v4()));
        let old = base.join("old/memory2.db");
        let new = base.join("new/memory2.db");
        std::fs::create_dir_all(old.parent().expect("parent")).expect("mkdir");
        std::fs::write(&old, b"payload").expect("write");

        let handle = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&old)
            .expect("hold the original open");

        let outcome = migrate(&old, &new);
        drop(handle);

        assert_eq!(
            outcome,
            Migrated::Ambiguous {
                old: old.clone(),
                new: new.clone()
            }
        );
        assert!(old.exists(), "the original must survive");
        assert_eq!(std::fs::read(&old).expect("read"), b"payload");
        assert!(
            !new.exists(),
            "the duplicate left by the successful copy must be cleaned up"
        );
        std::fs::remove_dir_all(&base).ok();
    }
}
