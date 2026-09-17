//! Who this process is, for anything that must not be confused with another instance.
//!
//! A pid is not enough: the OS reuses pids, so `fsmcp-<pid>` would eventually splice two
//! processes' logs into one file, and wave 1 already had to fix a scratch name keyed by pid
//! alone for the same reason. The id is generated once and never changes, so a file name and
//! any later record naming that file agree.
//!
//! Used by [`crate::core::logging`] to name this process's log file; wave 3's `sessions` table
//! must key its rows on the same triple the file name carries - day, pid, instance - and never on
//! the instance alone. See [`id`] for why.

use std::sync::OnceLock;

/// A short, filename-safe, per-process identity: the high 64 bits of a v4 uuid, rendered as
/// sixteen lowercase hex digits. Short enough to read in a directory listing, and free of
/// anything a filesystem would object to.
///
/// **This is a nonce, not a unique id, and it is not unique across time.** It is drawn fresh per
/// process with nothing remembering what was drawn before, so collisions follow the birthday
/// bound over however many values a reader is comparing. Among the handful of servers alive on
/// one machine that is nothing; over the rows of a table that accumulates, it is the whole
/// question. 64 bits puts the even-odds point at ~2^32 rows, which no such table reaches - but
/// the property that matters is the next paragraph, not the width.
///
/// **Any persistent key must be (day, pid, instance), never the instance alone.** That is what
/// the log file name already is - `fsmcp-<pid>-<instance>.log` under `<YYYY-MM-DD>/` - and a
/// stored row that refers to a log file has to be keyed the same way or it cannot name the file
/// it is about. A table keyed on the instance alone would also be keyed on the one part of the
/// triple that is random rather than observed.
///
/// Widened from 32 bits, which put even odds at ~65k rows. It cost eight characters in a file
/// name and removed the only reading under which this value could be mistaken for a primary key.
///
/// Taken from the uuid's halves rather than by slicing its string form, which would be a
/// panicking index on a value this module does not construct itself.
pub fn id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| format!("{:016x}", uuid::Uuid::new_v4().as_u64_pair().0))
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

    /// Short enough for a file name, wide enough that a table keyed partly on it does not meet
    /// the birthday bound, and containing nothing a filesystem would object to.
    #[test]
    fn id_is_filename_safe() {
        assert_eq!(
            id().len(),
            16,
            "64 bits, rendered without dropping leading zeroes"
        );
        assert!(id().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn pid_matches_the_process() {
        assert_eq!(pid(), std::process::id());
    }
}
