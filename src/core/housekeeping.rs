//! Age-based retention for everything the server leaves on disk, and the lease that keeps dozens
//! of concurrent processes from all doing it at once.
//!
//! One mechanism serves `<state>/tmp` now and `<state>/logs` plus the statistics database in later
//! waves: three separate retention implementations would drift apart and each would need its own
//! concurrency story. A second caller needs nothing from this module but a different `kind` string
//! for [`lease_in`] and a different directory for [`sweep_dir`].
//!
//! Retention is housekeeping, never a precondition for serving: every failure here is reported and
//! swallowed, so a hostile `tmp/` cannot stop the server from starting.

use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::warn;

use crate::core::paths::{self, SubDir};

/// How often any one kind of housekeeping may run, across all processes on this machine.
///
/// Not configurable: it is an internal throttle on redundant work, not a retention policy. The
/// policy the user controls is the age limit ([`paths::tmp_keep_hours`]); how often the sweep
/// looks is this module's business.
const SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

/// Delete files under `<state>/tmp` older than `FS_MCP_TMP_KEEP_HOURS`, at most once per
/// [`SWEEP_INTERVAL`] across all processes. Returns the number of entries deleted, which is 0
/// when another process already swept within the interval.
///
/// Called once at startup from `main.rs`, after the server is built and before the transport
/// starts. Resolves the real state root and the real retention, then delegates to the injectable
/// cores below so the tests can drive time forward without sleeping or touching real state.
pub fn sweep_tmp(now: SystemTime) -> io::Result<usize> {
    let root = paths::state_dir()?;
    if !lease_in(&root, "tmp", SWEEP_INTERVAL, now)? {
        return Ok(0);
    }
    let max_age = Duration::from_secs(paths::tmp_keep_hours() * 3600);
    sweep_dir(&paths::sub_dir(SubDir::Tmp)?, max_age, now)
}

/// Delete entries directly in `dir` whose modification time is further in the past than `max_age`.
///
/// An entry that cannot be inspected or removed is logged and skipped rather than failing the
/// sweep: one locked scratch file (another live process is still writing its `run_command` log)
/// must not stop the other hundred from being reclaimed. A file dated in the future is kept -
/// `duration_since` yields zero there, which reads as "brand new", and that is the right bias for
/// a clock that disagrees with us.
///
/// Only `dir` cannot be listed at all is an error, because then nothing was swept and the caller
/// should say so.
fn sweep_dir(dir: &Path, max_age: Duration, now: SystemTime) -> io::Result<usize> {
    let mut deleted = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                warn!("Housekeeping: cannot read an entry of {}: {e}", dir.display());
                continue;
            }
        };
        let path = entry.path();
        let age = match entry.metadata().and_then(|m| m.modified()) {
            Ok(modified) => now.duration_since(modified).unwrap_or_default(),
            Err(e) => {
                warn!("Housekeeping: cannot stat {}: {e}", path.display());
                continue;
            }
        };
        if age <= max_age {
            continue;
        }
        // Scratch subdirectories exist (capture batches, extracted archives) and age as a unit.
        let removed = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match removed {
            Ok(()) => deleted += 1,
            Err(e) => warn!("Housekeeping: cannot remove {}: {e}", path.display()),
        }
    }
    Ok(deleted)
}

/// Claim the right to perform `kind` of housekeeping in `root` for the next `every`.
///
/// The lease is a marker file per kind holding the Unix timestamp of the last run, so the check is
/// one small read and needs no database, no lock and no cleanup. The timestamp is read from the
/// file's *contents* rather than its modification time so that `now` is the only clock involved:
/// a caller that injects a time is then answered entirely in terms of that time, instead of
/// comparing its injected value against a real mtime that the filesystem wrote behind its back.
///
/// A marker that is missing, unreadable or malformed is treated as expired. Two processes can
/// therefore both take the lease - both stat before either writes - and both sweep. That is
/// deliberate: this guards against fifty simultaneous directory walks, not against a second one,
/// and a redundant sweep only finds the files the first one already removed.
fn lease_in(root: &Path, kind: &str, every: Duration, now: SystemTime) -> io::Result<bool> {
    let marker = root.join(format!(".housekeeping-{kind}"));
    let stamp = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if let Ok(text) = std::fs::read_to_string(&marker)
        && let Ok(last) = text.trim().parse::<u64>()
        && stamp.saturating_sub(last) < every.as_secs()
    {
        return Ok(false);
    }
    std::fs::write(&marker, stamp.to_string())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Files past the age limit go; fresh ones stay.
    #[test]
    fn sweep_deletes_only_old_files() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let tmp = scratch.path().join("tmp");
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let old = tmp.join("old.log");
        std::fs::write(&old, b"x").expect("write");
        let day = Duration::from_secs(24 * 3600);

        // Nothing is old enough yet.
        assert_eq!(sweep_dir(&tmp, day, SystemTime::now()).expect("sweep"), 0);
        assert!(old.exists());

        // Seen from 48 hours in the future, the file is past the cutoff.
        let later = SystemTime::now() + Duration::from_secs(48 * 3600);
        assert_eq!(sweep_dir(&tmp, day, later).expect("sweep"), 1);
        assert!(!old.exists());
    }

    /// A stale scratch directory ages out as a unit, like a file.
    #[test]
    fn sweep_removes_stale_directories() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let tmp = scratch.path().join("tmp");
        let stale = tmp.join("capture-batch");
        std::fs::create_dir_all(&stale).expect("mkdir");
        std::fs::write(stale.join("shot.png"), b"x").expect("write");

        let later = SystemTime::now() + Duration::from_secs(48 * 3600);
        let day = Duration::from_secs(24 * 3600);
        assert_eq!(sweep_dir(&tmp, day, later).expect("sweep"), 1);
        assert!(!stale.exists(), "the whole directory must go");
    }

    /// A directory that does not exist is an error, not a silent success: nothing was swept, and
    /// the caller has to be able to say so.
    #[test]
    fn sweep_reports_an_unlistable_directory() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let missing = scratch.path().join("nope");
        let err = sweep_dir(&missing, Duration::from_secs(1), SystemTime::now())
            .expect_err("a missing directory must be reported");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    /// The first caller takes the lease; the second is refused until the interval elapses.
    #[test]
    fn lease_admits_one_caller_per_interval() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        let every = Duration::from_secs(3600);
        let now = SystemTime::now();

        assert!(lease_in(root, "tmp", every, now).expect("first"));
        assert!(!lease_in(root, "tmp", every, now).expect("second"));
        assert!(lease_in(root, "tmp", every, now + Duration::from_secs(3601)).expect("later"));
    }

    /// Each kind of housekeeping holds its own lease, so wave 2's log retention is not silenced
    /// for an hour by the scratch sweep that ran a moment earlier.
    #[test]
    fn leases_are_independent_per_kind() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        let every = Duration::from_secs(3600);
        let now = SystemTime::now();

        assert!(lease_in(root, "tmp", every, now).expect("tmp"));
        assert!(lease_in(root, "logs", every, now).expect("logs"));
        assert!(!lease_in(root, "logs", every, now).expect("logs again"));
    }

    /// A corrupted marker must not wedge housekeeping off forever: it reads as expired, the lease
    /// is granted, and the marker is rewritten with a timestamp that parses.
    #[test]
    fn a_malformed_marker_is_treated_as_expired() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        let marker = root.join(".housekeeping-tmp");
        std::fs::write(&marker, b"not a timestamp").expect("write");
        let now = SystemTime::now();

        assert!(lease_in(root, "tmp", Duration::from_secs(3600), now).expect("granted"));
        assert!(!lease_in(root, "tmp", Duration::from_secs(3600), now).expect("now held"));
    }
}
