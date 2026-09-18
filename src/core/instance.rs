//! Who this process is, for anything that must not be confused with another instance.
//!
//! A pid is not enough: the OS reuses pids, so `fsmcp-<pid>` would eventually splice two
//! processes' logs into one file, and wave 1 already had to fix a scratch name keyed by pid
//! alone for the same reason. The id is generated once and never changes, so a file name and
//! any later record naming that file agree.
//!
//! Used by [`crate::core::paths::run_file`] to name every file a run leaves behind - its log, its
//! crash report and its tool-call counters - and carried inside the counters file as `run.pid` and
//! `run.instance`. A persistent key must be (day, pid, instance), never the instance alone; see
//! [`id`] for why.

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
/// **Any persistent key must be (day, pid, instance), never the instance alone.** A stored row
/// that refers to a run has to be keyed that way or it cannot name the run it is about; the
/// counters file records `pid` and `instance` side by side for exactly that reason. A table keyed on the instance alone would also be keyed on the one part of the
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

/// When this process started, fixed on first use and never moving afterwards.
///
/// The same kind of value as [`id`] and [`pid`]: a property of the run, not a reading of the
/// clock. That distinction is the whole point. Every file a run leaves behind is named through
/// [`crate::core::paths::run_file`], and if that helper read `SystemTime::now()` each time, the
/// log (named at startup), the crash report (named at the panic) and the counters (named at exit)
/// would carry three different stamps. They would then be three files nobody could tie back to
/// one run - which is exactly what the shared naming was introduced to make possible.
///
/// Two consequences worth stating, because both are relied on:
///
/// - **The counters are written to one path**, whether the panic hook writes them or the exit
///   path does. The hook leaves a partial file and the exit path overwrites it with the final
///   one, so a run leaves exactly one counters file without needing a latch to enforce it.
/// - **A run that outlives midnight keeps its directory**, since the dated directory is named for
///   the start. That is already the documented behaviour of the log file.
///
/// First use is early - `main` installs the panic hook and initialises logging before serving -
/// so the value is the process's start to within a few milliseconds. It is not read from the OS
/// process table: that costs a platform-specific lookup to sharpen a number whose only job is to
/// be the same for every caller.
pub fn started() -> std::time::SystemTime {
    static STARTED: OnceLock<std::time::SystemTime> = OnceLock::new();
    *STARTED.get_or_init(std::time::SystemTime::now)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The start instant never moves, which is what makes a run's log, crash report and counters
    /// share one name — and what keeps the counters to a single file, since the panic hook and
    /// the exit path resolve the same path from it.
    #[test]
    fn the_start_instant_never_moves() {
        let first = started();
        assert_eq!(first, started());
        // A clock read would differ across this gap on any real platform; a fixed value cannot.
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert_eq!(first, started(), "started() must not be a clock reading");
        assert!(
            first <= std::time::SystemTime::now(),
            "the run cannot have started in the future"
        );
    }

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
