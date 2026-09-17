//! Age-based retention for everything the server leaves on disk, and the lease that keeps dozens
//! of concurrent processes from all doing it at once.
//!
//! One mechanism serves `<state>/tmp` now and `<state>/logs` plus the statistics database in later
//! waves: three separate retention implementations would drift apart and each would need its own
//! concurrency story. A second caller needs nothing from this module but a different `kind` string
//! for the lease and a different directory for [`sweep_dir`], both of which are `pub(crate)`.
//!
//! Retention is housekeeping, never a precondition for serving: every failure here is reported and
//! swallowed, so a hostile `tmp/` cannot stop the server from starting.
//!
//! **The sweep deletes other processes' scratch, so its age rule is a safety property, not a
//! detail.** `<state>/tmp` holds the live blob spool of every server running on this machine, and
//! an MCP server lives as long as its client - a day is unremarkable. A directory's own mtime
//! advances only when its *direct* children change, so a spool whose writes all land in
//! `sessions/` looks frozen at the moment it was created. Ageing a directory by its own mtime
//! would therefore hand a day-old, busy spool to `remove_dir_all`. [`newest_mtime`] ages a
//! directory by the newest mtime anywhere in its tree instead, and that rule lives here rather
//! than in any one writer because every future scratch subdirectory has the same shape.

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

/// How deep [`newest_mtime`] will descend before giving up on a subtree.
///
/// Scratch trees are one or two levels deep in practice. The cap exists so that a pathological
/// directory cannot overflow the stack, which would abort the process before the transport ever
/// started - the one outcome housekeeping must never cause. Hitting it is an error, so the entry
/// is kept rather than deleted on an incomplete reading of its age.
const MAX_DEPTH: u32 = 64;

/// What one sweep did. The three cases are distinct because a caller may need to act on them
/// differently: wave 3's statistics compaction has to know whether to reschedule itself, and
/// "another process is handling it" is not the same answer as "there was nothing to delete".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sweep {
    /// The sweep ran and reclaimed this many entries (possibly zero).
    Ran(usize),
    /// Another process swept within [`SWEEP_INTERVAL`]; nothing was examined.
    LeaseHeld,
    /// Retention is switched off for this directory (`FS_MCP_TMP_KEEP_HOURS=0`).
    Disabled,
}

/// Delete entries under `<state>/tmp` older than `FS_MCP_TMP_KEEP_HOURS`, at most once per
/// [`SWEEP_INTERVAL`] across all processes.
///
/// Called once at startup from `main.rs`, after the server is built and before the transport
/// starts. Resolves the real state root and the real retention, then delegates to the injectable
/// cores below so the tests can drive time forward without sleeping or touching real state.
pub fn sweep_tmp(now: SystemTime) -> io::Result<Sweep> {
    let hours = paths::tmp_keep_hours();
    if hours == 0 {
        return Ok(Sweep::Disabled);
    }
    let root = paths::state_dir()?;
    if !lease_due(&root, "tmp", SWEEP_INTERVAL, now) {
        return Ok(Sweep::LeaseHeld);
    }
    // `tmp_keep_hours` is clamped, so this cannot overflow; saturating anyway keeps the property
    // local instead of depending on a constant in another module staying small.
    let max_age = Duration::from_secs(hours.saturating_mul(3600));
    let deleted = sweep_dir(&paths::sub_dir(SubDir::Tmp)?, max_age, now)?;
    // Stamped only now: a sweep that failed to list its directory has not done the hour's work,
    // and the next process to start should retry rather than be turned away for an hour.
    //
    // A marker that cannot be written is reported here rather than returned, because by this point
    // the sweep HAS run and files are gone; propagating would make the caller report the whole
    // thing as skipped, which is the one description that is untrue. The consequence is only that
    // the next process to start will sweep again this interval.
    if let Err(e) = lease_done(&root, "tmp", now) {
        warn!(
            "Housekeeping: swept {deleted} entries but could not record the lease: {e}; \
             another process may sweep again within the hour"
        );
    }
    Ok(Sweep::Ran(deleted))
}

/// Delete entries directly in `dir` whose newest content is further in the past than `max_age`.
///
/// An entry that cannot be inspected or removed is logged and skipped rather than failing the
/// sweep: one locked scratch file (another live process is still writing its `run_command` log)
/// must not stop the other hundred from being reclaimed. Only `dir` itself being unlistable is an
/// error, because then nothing was swept and the caller has to be able to say so.
///
/// One Windows wrinkle, so it is not rediscovered as a bug: `file_type` reports a directory
/// symlink as not-a-directory, so a stale one is passed to `remove_file`, which refuses to unlink
/// a directory symlink there. The entry is warned about and kept - the classification is wrong,
/// the outcome is safe, and the link's target is never touched either way.
///
/// Every decision is biased towards keeping. An entry whose age cannot be established is kept; an
/// entry dated in the future is kept (`duration_since` yields zero there, which reads as "brand
/// new", the right answer for a clock that disagrees with us); an entry exactly `max_age` old is
/// kept, so the boundary is "older than", as the setting's name promises. Deleting live state is
/// unrecoverable, keeping a stale file costs disk.
pub(crate) fn sweep_dir(dir: &Path, max_age: Duration, now: SystemTime) -> io::Result<usize> {
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
        // `DirEntry::file_type` describes the entry itself, so a symlink is classified as a
        // symlink and removed with `remove_file` - never followed into whatever it points at.
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) => {
                warn!("Housekeeping: cannot type {}: {e}", path.display());
                continue;
            }
        };
        let age = match newest_mtime(&path, 0) {
            Ok(newest) => now.duration_since(newest).unwrap_or_default(),
            Err(e) => {
                warn!("Housekeeping: cannot age {}: {e}", path.display());
                continue;
            }
        };
        if age <= max_age {
            continue;
        }
        // Scratch subdirectories exist (blob spools, capture batches) and age as a unit.
        let removed = if file_type.is_dir() {
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

/// The newest modification time anywhere in `path`'s tree, `path` itself included.
///
/// This is what makes a directory's age mean "nothing in here has been touched since", which is
/// the only reading under which deleting another process's spool is safe. See the module doc for
/// why the directory's own mtime does not answer that question.
///
/// Symlinks are stat'd, never followed: `symlink_metadata` gives the link's own timestamp, and
/// recursion happens only for a real directory, so a link into a live tree can neither keep this
/// entry alive nor lead the walk outside `<state>/tmp`. That also makes cycles impossible.
///
/// Any failure - an unreadable child, a tree deeper than [`MAX_DEPTH`] - is an error rather than a
/// partial answer, because a partial answer here is an *under*estimate of newness and would argue
/// for deletion.
fn newest_mtime(path: &Path, depth: u32) -> io::Result<SystemTime> {
    if depth > MAX_DEPTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is nested deeper than {MAX_DEPTH} levels", path.display()),
        ));
    }
    let meta = std::fs::symlink_metadata(path)?;
    let mut newest = meta.modified()?;
    if meta.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let child = newest_mtime(&entry?.path(), depth + 1)?;
            newest = newest.max(child);
        }
    }
    Ok(newest)
}

/// Whether `kind` of housekeeping is due in `root`, i.e. whether more than `every` has passed
/// since the last completed run.
///
/// The lease is a marker file per kind, `<root>/.housekeeping-<kind>`, holding the Unix timestamp
/// of the last completed run. The check is one small read, and needs no database, no lock and
/// nothing to clean up after a killed process.
///
/// The timestamp is read from the file's **contents**, not its modification time, so that `now` is
/// the only clock involved: a caller that injects a time is then answered entirely in terms of
/// that time, instead of comparing its injected value against an mtime the filesystem wrote behind
/// its back. The practical consequence for anyone operating this: **a lease is reset by deleting
/// the marker file, not by `touch`ing it.**
///
/// A marker that is missing, unreadable, malformed, or dated in the future reads as expired. The
/// future case matters in practice - one VM snapshot restore or one backwards NTP step would
/// otherwise stamp a time a year ahead and switch retention off until the wall clock caught up.
///
/// Two processes can both find the work due - both read before either writes - and both sweep.
/// That is deliberate: this guards against fifty simultaneous directory walks, not against a
/// second one, and the loser merely finds the files the winner already removed.
pub(crate) fn lease_due(root: &Path, kind: &str, every: Duration, now: SystemTime) -> bool {
    let Some(marker) = marker_path(root, kind) else {
        return false;
    };
    let stamp = unix_secs(now);
    let Ok(text) = std::fs::read_to_string(&marker) else {
        return true;
    };
    match text.trim().parse::<u64>() {
        Ok(last) if last <= stamp => stamp - last >= every.as_secs(),
        _ => true,
    }
}

/// Record that `kind` of housekeeping completed in `root` at `now`, starting the next interval.
///
/// Separate from [`lease_due`] so the marker is written only once the work has actually succeeded;
/// stamping on the way in would let a sweep that failed to list its directory silence the next
/// hour's attempts.
pub(crate) fn lease_done(root: &Path, kind: &str, now: SystemTime) -> io::Result<()> {
    let marker = marker_path(root, kind).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("housekeeping kind must be a bare name, got {kind:?}"),
        )
    })?;
    std::fs::write(&marker, unix_secs(now).to_string())
}

/// The marker file for `kind`, or `None` when `kind` is not a bare name.
///
/// `kind` is a compile-time constant at every call site, so a separator in it is a programming
/// error rather than input - but `"../x"` would escape the state root entirely, and that is worth
/// one cheap check rather than trusting that no future caller ever builds the string.
///
/// A plain runtime check, deliberately not a `debug_assert!` beside it: the two would be redundant,
/// and the assert would make the behaviour differ between profiles, so the test covering it could
/// only run in the profile nobody tests in.
fn marker_path(root: &Path, kind: &str) -> Option<std::path::PathBuf> {
    if kind.is_empty() || kind.contains(std::path::is_separator) || kind.contains("..") {
        warn!("Housekeeping: refusing a lease for the invalid kind {kind:?}");
        return None;
    }
    Some(root.join(format!(".housekeeping-{kind}")))
}

/// `now` as whole seconds since the Unix epoch. A time before the epoch saturates to 0, which
/// reads as "very long ago" and so errs towards letting housekeeping run.
fn unix_secs(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: Duration = Duration::from_secs(24 * 3600);
    const HOUR: Duration = Duration::from_secs(3600);

    /// Files past the age limit go; fresh ones stay.
    #[test]
    fn sweep_deletes_only_old_files() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let tmp = scratch.path().join("tmp");
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let old = tmp.join("old.log");
        std::fs::write(&old, b"x").expect("write");

        // Nothing is old enough yet.
        assert_eq!(sweep_dir(&tmp, DAY, SystemTime::now()).expect("sweep"), 0);
        assert!(old.exists());

        // Seen from 48 hours in the future, the file is past the cutoff.
        let later = SystemTime::now() + Duration::from_secs(48 * 3600);
        assert_eq!(sweep_dir(&tmp, DAY, later).expect("sweep"), 1);
        assert!(!old.exists());
    }

    /// A directory is aged by the newest thing inside it, not by its own mtime.
    ///
    /// This is the live-blob-spool case: `ContentPlane` creates its root once at startup and then
    /// only ever writes into `sessions/`, so the root's own mtime stays frozen at process start
    /// however busy the spool is. The child is written *after* the directory is aged, which is the
    /// arrangement where parent and child mtimes disagree - the previous version of this test
    /// created the child first, and so could not see the difference.
    #[test]
    fn a_directory_is_aged_by_its_newest_content() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let tmp = scratch.path().join("tmp");

        // A spool whose owner died, or was never busy: nothing in the tree is newer than the
        // directory itself.
        let idle = tmp.join("filesystem-mcp-rs-blobs-4242");
        std::fs::create_dir_all(idle.join("sessions")).expect("mkdir");

        // A spool whose owner is alive and staging bytes. Both directories were created at the
        // same instant - that is exactly the real case, since a long-lived server's spool root
        // keeps the mtime it was born with - and only the leaf is fresh.
        let busy = tmp.join("filesystem-mcp-rs-blobs-7777");
        let live = busy.join("sessions/live.part");
        std::fs::create_dir_all(live.parent().expect("parent")).expect("mkdir");
        std::fs::write(&live, b"x").expect("write");
        let born = filetime_now(&idle);
        set_mtime(&live, born + 2 * HOUR);

        // 25 hours after both were created, with a day's retention: the idle tree is 25 h stale,
        // the busy tree's newest content is 23 h old. Ageing a directory by its own mtime would
        // delete both - which is the bug this pins.
        let later = born + Duration::from_secs(25 * 3600);
        assert_eq!(sweep_dir(&tmp, DAY, later).expect("sweep"), 1);
        assert!(!idle.exists(), "the idle spool must be reclaimed");
        assert!(
            live.is_file(),
            "a spool with live content must survive, however old its own directory is"
        );
    }

    /// An entry exactly at the limit is kept: the setting says "older than", and the bias
    /// everywhere in this module is towards keeping.
    #[test]
    fn an_entry_exactly_at_the_limit_is_kept() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let tmp = scratch.path().join("tmp");
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let file = tmp.join("edge.log");
        std::fs::write(&file, b"x").expect("write");
        let born = filetime_now(&file);

        assert_eq!(sweep_dir(&tmp, DAY, born + DAY).expect("sweep"), 0);
        assert!(file.exists(), "age == max_age must not delete");
        // One second past the limit it does go, so the test above pins the boundary and not
        // merely the fact that nothing is ever deleted.
        let past = born + DAY + Duration::from_secs(1);
        assert_eq!(sweep_dir(&tmp, DAY, past).expect("sweep"), 1);
    }

    /// A file dated in the future is kept: `duration_since` reads it as brand new, which is the
    /// right bias when a clock disagrees with us.
    #[test]
    fn a_future_dated_file_is_kept() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let tmp = scratch.path().join("tmp");
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let file = tmp.join("tomorrow.log");
        std::fs::write(&file, b"x").expect("write");

        // "Now" a week before the file was written.
        let earlier = SystemTime::now() - Duration::from_secs(7 * 24 * 3600);
        assert_eq!(sweep_dir(&tmp, DAY, earlier).expect("sweep"), 0);
        assert!(file.exists());
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
        let now = SystemTime::now();

        assert!(lease_due(root, "tmp", HOUR, now), "first");
        lease_done(root, "tmp", now).expect("stamp");
        assert!(!lease_due(root, "tmp", HOUR, now), "second");
        assert!(
            lease_due(root, "tmp", HOUR, now + Duration::from_secs(3601)),
            "later"
        );
    }

    /// Work that fails leaves the lease untaken, so the next process retries instead of being
    /// turned away for an hour.
    #[test]
    fn an_uncommitted_lease_does_not_block_the_next_caller() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        let now = SystemTime::now();

        assert!(lease_due(root, "tmp", HOUR, now));
        // ... the sweep failed here, so `lease_done` was never reached.
        assert!(lease_due(root, "tmp", HOUR, now), "must still be due");
    }

    /// Each kind of housekeeping holds its own lease, so wave 2's log retention is not silenced
    /// for an hour by the scratch sweep that ran a moment earlier.
    #[test]
    fn leases_are_independent_per_kind() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        let now = SystemTime::now();

        lease_done(root, "tmp", now).expect("stamp tmp");
        assert!(!lease_due(root, "tmp", HOUR, now));
        assert!(lease_due(root, "logs", HOUR, now), "logs is a separate lease");
    }

    /// A corrupted marker must not wedge housekeeping off forever: it reads as expired.
    #[test]
    fn a_malformed_marker_is_treated_as_expired() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        std::fs::write(root.join(".housekeeping-tmp"), b"not a timestamp").expect("write");

        assert!(lease_due(root, "tmp", HOUR, SystemTime::now()));
    }

    /// Nor may a marker from the future, which one VM snapshot restore or one backwards NTP step
    /// is enough to produce. Read literally it would switch retention off for a year.
    #[test]
    fn a_future_marker_is_treated_as_expired() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        let now = SystemTime::now();
        lease_done(root, "tmp", now + Duration::from_secs(365 * 24 * 3600)).expect("stamp");

        assert!(lease_due(root, "tmp", HOUR, now), "a future stamp is expired");
    }

    /// A `kind` that would escape the state root is refused rather than joined onto it, in every
    /// build profile.
    #[test]
    fn an_escaping_kind_is_refused() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        assert!(!lease_due(scratch.path(), "../escape", HOUR, SystemTime::now()));
        assert!(lease_done(scratch.path(), "../escape", SystemTime::now()).is_err());
    }

    /// The recorded mtime of a file just written, which is what the sweep will compare against.
    /// Read from the filesystem rather than assumed to be `SystemTime::now()`: timestamp
    /// granularity varies per filesystem, and a boundary test cannot afford to guess.
    fn filetime_now(path: &Path) -> SystemTime {
        std::fs::metadata(path)
            .and_then(|m| m.modified())
            .expect("mtime")
    }

    /// Stamp `path` with an explicit modification time.
    ///
    /// The age tests need a parent and a child whose mtimes differ by hours. Writing them in
    /// sequence cannot produce that, and would leave the difference at the mercy of the
    /// filesystem's timestamp granularity - coarse enough on some filesystems that the two would
    /// be equal and the test would prove nothing.
    fn set_mtime(path: &Path, when: SystemTime) {
        let file = std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open for set_times");
        file.set_times(std::fs::FileTimes::new().set_modified(when))
            .expect("set mtime");
    }
}
