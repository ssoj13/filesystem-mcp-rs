//! Who this process is, for anything that must not be confused with another instance.
//!
//! A pid is not enough: the OS reuses pids, so `fsmcp-<pid>` would eventually splice two
//! processes' logs into one file, and wave 1 already had to fix a scratch name keyed by pid
//! alone for the same reason. The id is generated once and never changes, so a file name and
//! any later record naming that file agree.
//!
//! Used by [`crate::core::logging`] to name this process's log file; wave 3's `sessions` table
//! will key its row by the same pair.

use std::sync::OnceLock;

/// A short, filename-safe, per-process identity: the first 32 bits of a v4 uuid, rendered as
/// eight lowercase hex digits. Long enough that two concurrent servers do not collide in
/// practice, short enough to read in a directory listing, and free of anything a filesystem
/// would object to.
///
/// Taken from the uuid's fields rather than by slicing its string form, which would be a
/// panicking index on a value this module does not construct itself.
pub fn id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| format!("{:08x}", uuid::Uuid::new_v4().as_fields().0))
}

/// This process's pid. Kept for diagnostics and for the human reading a directory listing —
/// never for identity on its own, because pids are reused.
pub fn pid() -> u32 {
    std::process::id()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The id is stable within a process — every caller must see the same string, or a log file
    /// name and the row that refers to it would disagree.
    #[test]
    fn id_is_stable_within_the_process() {
        assert_eq!(id(), id());
        assert!(!id().is_empty());
    }

    /// Short enough for a file name, long enough not to collide in practice, and containing
    /// nothing a filesystem would object to.
    #[test]
    fn id_is_filename_safe() {
        assert_eq!(id().len(), 8);
        assert!(id().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn pid_matches_the_process() {
        assert_eq!(pid(), std::process::id());
    }
}
