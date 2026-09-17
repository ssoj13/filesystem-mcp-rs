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

use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{info, warn};

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

/// How recently a log file must have been written to count as possibly still in use.
///
/// **This, not the pid set, is what makes deleting another process's log safe.** The pid set
/// answers "is that process running" only as well as the process listing behind it, and a listing
/// can be short in ways this process cannot detect: under Linux `hidepid=2`, inside a restricted
/// container, or seen from a foreign pid namespace, a sibling server owned by another user is
/// simply invisible. Our own pid - the one entry [`trust_listing`] can check for - stays visible
/// in every one of those cases, so such a listing passes every check this module can make while
/// reading "that server is gone". A file's own mtime is the single piece of evidence none of
/// those conditions can take away, and it is weighed per file, so it costs nothing elsewhere.
///
/// A day, not an hour. The window has to bound the gap between two writes by a server that is
/// *alive*, and an MCP server is idle for exactly as long as its client is idle: overnight is
/// ordinary and an hour bounds nothing. A day is the same reading of "unremarkable" that
/// `FS_MCP_TMP_KEEP_HOURS` already defaults to. What it costs is only that a log whose process
/// really did exit becomes reclaimable a day later than it used to - and both rules that consult
/// this are bounds on disk rather than promises about it ([`sweep_by_budget`] is a soft limit by
/// construction), so a day of latency for a rule that holds without a trustworthy process table
/// is cheap.
///
/// **What it still does not cover**, said plainly rather than papered over: a live server that
/// logs nothing at all for longer than this window, on a host where the listing is *also*
/// truncated, is indistinguishable from a dead one by any evidence this process can gather.
/// Closing that needs a liveness signal the process table cannot hide - an OS-level lock held on
/// the log file for as long as it is open - which is a change to the writer, not to the sweep.
const LIVE_WINDOW: Duration = Duration::from_secs(24 * 3600);

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
    match lease_due(&root, "tmp", SWEEP_INTERVAL, now) {
        Lease::Due => {}
        Lease::Held => return Ok(Sweep::LeaseHeld),
        // Unreachable with the literal above, and loud on purpose if a later wave passes a name
        // that cannot address a marker: silently never sweeping is how a disk fills up.
        Lease::InvalidKind => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "housekeeping: \"tmp\" was refused as a lease name",
            ));
        }
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

/// Reclaim `<state>/logs`: dated directories past `FS_MCP_LOG_KEEP_DAYS`, then, if the tree is
/// still over `FS_MCP_LOG_MAX_MB`, the oldest log files until it is not.
///
/// Called once at startup from `main.rs`, beside [`sweep_tmp`] and through the same lease with
/// `kind = "logs"`, so the two kinds of housekeeping neither silence nor wait for each other.
/// This resolves the real retention, the real state root and the real process table; every
/// decision made with them lives in [`sweep_logs_in`], which the tests drive directly.
///
/// **Both knobs switch off at zero**, following `FS_MCP_TMP_KEEP_HOURS`: a retention setting
/// whose zero empties the directory is a foot-gun, and with dozens of processes it would fire on
/// every start. They switch off independently - only with both at zero is there nothing at all
/// to do, which is the one case that reports [`Sweep::Disabled`].
///
/// **The size budget is a soft limit.** It stops at the first file it may not delete, because a
/// log a running server is appending to is worth more than the megabytes it occupies: on Windows
/// the unlink fails anyway, but on Unix it succeeds and the server goes on writing into an
/// unlinked inode, so the operator loses the evidence with nothing anywhere to say so. A tree
/// can therefore sit over its budget for as long as the processes filling it keep running.
pub fn sweep_logs(now: SystemTime) -> io::Result<Sweep> {
    let keep_days = crate::core::logging::keep_days();
    // Saturating, never a bare `*`: the knob is in MiB and everything below it counts bytes, so
    // `FS_MCP_LOG_MAX_MB=<u64::MAX>` parses cleanly, survives the reader, and would overflow
    // this conversion - a debug panic in housekeeping, before the transport starts, which is the
    // one outcome this module must never cause. `core::logging` clamps the value as well; the
    // clamp lives in one module and the arithmetic in another, so both are deliberate. An absurd
    // budget then means "never sweep", which is the right reading of it.
    let max_bytes = crate::core::logging::max_mb().saturating_mul(1024 * 1024);
    // Deliberately the same condition [`sweep_logs_in`] checks: asked here so that a server with
    // retention switched off pays neither the state-root resolution nor the process enumeration
    // below, and asked there so the core is honest on its own. Do not "simplify" either away.
    //
    // This copy is knowingly untested, and `cargo mutants` reports it as such: reaching it means
    // a real state root and a real process table, and the behaviour it guards is pinned on the
    // core by `both_knobs_at_zero_disable_the_log_sweep`. An honest note beats a contrived seam.
    if keep_days == 0 && max_bytes == 0 {
        return Ok(Sweep::Disabled);
    }
    let root = paths::state_dir()?;
    let dir = paths::sub_dir(SubDir::Logs)?;
    // Taken once for the whole sweep rather than per file: one process snapshot is the cost, and
    // a set that changed halfway through could judge one directory dead by a rule the next
    // directory is spared by.
    //
    // Also knowingly untested for the same reason - this call IS the real process table. What it
    // decides with the answer is pinned by `trust_listing`'s tests and by the `live: None` case
    // of `a_refused_process_listing_still_stamps_the_lease`.
    sweep_logs_in(&root, &dir, keep_days, max_bytes, now, live_pids().as_ref())
}

/// The whole of [`sweep_logs`]'s decision, against a state root, a log directory and a pid set
/// supplied by the caller, so that the tests exercise the lease and both rules without a real
/// state directory or a real process table.
///
/// `live` is `None` when the process listing could not be trusted (see [`live_pids`]). That is a
/// **completed pass whose answer was "keep everything"**, not an abandoned one, so it still
/// stamps the lease: `hidepid=2`, a restricted container and a foreign pid namespace are
/// permanent conditions, and leaving the lease untaken would make every start of every server on
/// such a host pay a full process enumeration - on exactly the hosts where that enumeration is
/// already restricted.
pub(crate) fn sweep_logs_in(
    root: &Path,
    dir: &Path,
    keep_days: u64,
    max_bytes: u64,
    now: SystemTime,
    live: Option<&HashSet<u32>>,
) -> io::Result<Sweep> {
    if keep_days == 0 && max_bytes == 0 {
        return Ok(Sweep::Disabled);
    }
    match lease_due(root, "logs", SWEEP_INTERVAL, now) {
        Lease::Due => {}
        Lease::Held => return Ok(Sweep::LeaseHeld),
        // Unreachable with the literal above, and loud on purpose for the same reason as in
        // `sweep_tmp`: silently never sweeping is how a disk fills up.
        Lease::InvalidKind => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "housekeeping: \"logs\" was refused as a lease name",
            ));
        }
    }
    let mut deleted = 0;
    // An untrusted listing deletes nothing at all: with no way to tell a live server's logs from
    // an abandoned one's, neither rule may run, and the pass falls through to the stamp below.
    if let Some(live) = live {
        if keep_days > 0 {
            let today = crate::core::logging::utc_day(now);
            deleted += sweep_log_dirs(dir, keep_days, &today, live, now)?;
        }
        if max_bytes > 0 {
            deleted += sweep_by_budget(dir, max_bytes, now, live)?;
        }
    }
    // Stamped only after the work, and a failure to stamp is reported rather than returned, for
    // exactly the reasons spelled out in `sweep_tmp`.
    if let Err(e) = lease_done(root, "logs", now) {
        warn!(
            "Housekeeping: reclaimed {deleted} log entries but could not record the lease: {e}; \
             another process may sweep again within the hour"
        );
    }
    Ok(Sweep::Ran(deleted))
}

/// The pids running on this machine, this process's own included, or `None` when they cannot be
/// listed.
///
/// Reuses the crate's existing process listing rather than adding a second way to ask the same
/// question. The cost is one process snapshot, paid at most once an hour across every server on
/// the machine, because the lease is taken before this is called.
///
/// `None` rather than an empty set on failure, and the caller then deletes nothing: an empty set
/// reads as "no process is alive", which would hand every log file on the machine to the sweep.
///
/// **A listing that does not contain the process doing the listing is not a listing**, and is
/// refused. With both patterns `None` the call has no real error path, so `Err` is the failure
/// that cannot happen; the one that can is an `Ok` holding too FEW pids. Own pid is the one entry
/// this process can check for, so it is the test for the whole listing rather than something to
/// paper over by inserting it. That judgement is [`trust_listing`], which is pure and tested;
/// this function is only the wiring that fetches the listing for it.
///
/// Read [`trust_listing`] for how far that goes, because it is narrower than it sounds: it
/// catches an enumeration that came back empty or wholesale wrong, and it cannot catch one
/// truncated by `hidepid=2`, a restricted container or a foreign pid namespace, every one of
/// which leaves our own pid visible. Deletion is kept safe under those by [`LIVE_WINDOW`].
fn live_pids() -> Option<HashSet<u32>> {
    let found = match crate::tools::process::search_processes(None, None) {
        Ok(found) => found,
        Err(e) => {
            warn!("Housekeeping: cannot list processes ({e}); leaving the logs alone");
            return None;
        }
    };
    trust_listing(
        found.into_iter().map(|p| p.pid).collect(),
        crate::core::instance::pid(),
    )
}

/// `pids` if it can be trusted to say which logs are abandoned, `None` if it cannot.
///
/// The rule, and the whole of it: **a listing that does not contain `own` - the process doing the
/// listing - is not a listing.** Split out from [`live_pids`] because it is the judgement, while
/// that function is only the fetch: as a pure function it can be tested in both directions, and
/// `cargo mutants` reported the fused version as a place where the trust rule could be deleted
/// outright with the suite still green.
///
/// **What this catches is an enumeration that failed wholesale** - an empty set, or one from a
/// listing so restricted that not even the caller appears in it. That is worth catching, because
/// an empty set reads as "nothing on this machine is alive" and would hand every log file on it
/// to the sweep at once.
///
/// **It does not catch a truncated listing, and must not be read as if it did.** `hidepid=2`, a
/// restricted container and a foreign pid namespace all leave this process's own pid plainly
/// visible - `/proc/self` exists under `hidepid=2`, and a pid is always visible inside its own
/// namespace - so a listing holding our own user's processes and none of another user's passes
/// here intact. Nor can the log tree be cross-examined for the missing pids: a tree legitimately
/// accumulates the pids of servers that have exited, so "a pid named in the tree that is not in
/// the listing" is the *ordinary* state of a healthy machine, and a rule refusing on it would
/// switch the sweep off permanently after the first server ever exited. Absent-because-hidden
/// and absent-because-dead are not distinguishable from in here at all.
///
/// That ambiguity is therefore answered per file rather than per listing, where it is harmless
/// because both readings call for the same action: [`LIVE_WINDOW`] keeps any log written recently
/// enough to belong to something still running, whatever the process table says about it.
///
/// The set is returned untouched on success. Nothing is inserted into it, deliberately: inserting
/// `own` is precisely what would hide the signal this rule reads.
fn trust_listing(pids: HashSet<u32>, own: u32) -> Option<HashSet<u32>> {
    if !pids.contains(&own) {
        warn!(
            "Housekeeping: the process listing does not include this process; it cannot be \
             trusted to say which logs are abandoned, so the logs are left alone"
        );
        return None;
    }
    Some(pids)
}

/// Delete `<logs>/<YYYY-MM-DD>` directories more than `keep_days` days older than `today`.
///
/// A dated directory carries its age in its NAME, so it is read from there and not from
/// [`newest_mtime`], which would walk every log file on the machine on every cold start.
///
/// Everything this cannot account for is kept, and said so in the log:
/// - a name that is not `YYYY-MM-DD` was not written by [`crate::core::logging`], and since this
///   function deletes, an unreadable name is a reason to stop rather than to improvise;
/// - `today`, and any directory dated ahead of it, stays whatever `keep_days` says;
/// - a directory holding a log file whose pid is in `live`, one modified within [`LIVE_WINDOW`],
///   or any entry that is not a log file this module recognises, stays whole. **A server running
///   since before the retention window keeps its entire start-day directory**: it is still
///   writing into the file it opened there, and on Unix deleting it would succeed silently and
///   cost the operator every line that process logs from then on.
pub(crate) fn sweep_log_dirs(
    dir: &Path,
    keep_days: u64,
    today: &str,
    live: &HashSet<u32>,
    now: SystemTime,
) -> io::Result<usize> {
    // A malformed `today` would make every directory look infinitely old, so it is an error
    // rather than a sweep carried out against an unusable reference point.
    let Some(today) = day_number(today) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("housekeeping: {today:?} is not a YYYY-MM-DD date"),
        ));
    };
    let mut deleted = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                warn!(
                    "Housekeeping: cannot read an entry of {}: {e}",
                    dir.display()
                );
                continue;
            }
        };
        let path = entry.path();
        match entry.file_type() {
            // Only dated directories are this sweep's business; a stray file directly under
            // `logs/` is somebody else's and stays where it is.
            Ok(file_type) if file_type.is_dir() => {}
            Ok(_) => {
                warn!(
                    "Housekeeping: {} is not a log directory; kept",
                    path.display()
                );
                continue;
            }
            Err(e) => {
                warn!("Housekeeping: cannot type {}: {e}", path.display());
                continue;
            }
        }
        let Some(day) = day_number(&entry.file_name().to_string_lossy()) else {
            warn!(
                "Housekeeping: {} is not named for a date; kept rather than guessed at",
                path.display()
            );
            continue;
        };
        // Positive before the cast, so the comparison against `keep_days` is exact; today and
        // anything dated ahead of it fall out here.
        let age = i64::from(today) - i64::from(day);
        if age <= 0 || (age as u64) <= keep_days {
            continue;
        }
        match is_reclaimable(&path, live, now) {
            Ok(true) => {}
            Ok(false) => {
                info!(
                    "Housekeeping: {} is past the retention window but still in use; kept",
                    path.display()
                );
                continue;
            }
            Err(e) => {
                warn!("Housekeeping: cannot inspect {}: {e}", path.display());
                continue;
            }
        }
        match std::fs::remove_dir_all(&path) {
            Ok(()) => deleted += 1,
            Err(e) => warn!("Housekeeping: cannot remove {}: {e}", path.display()),
        }
    }
    Ok(deleted)
}

/// Whether every entry of a dated log directory is the quiet log of a process that has exited.
///
/// `false` covers "a live process is writing in there", "something in there was written within
/// [`LIVE_WINDOW`]" and "there is something in there I do not recognise" alike: all three call for the
/// same response, which is to leave the directory alone. An unreadable directory or entry is an
/// error, never a partial reading - a partial one would be an argument for deletion.
///
/// The two checks are not interchangeable, and it matters which one carries the weight. `live`
/// comes from a process listing, and a listing can be truncated in ways no check inside this
/// process can detect (see [`trust_listing`]); the mtime is the file speaking for itself, and no
/// process table can contradict it. So [`LIVE_WINDOW`] is what closes the hole, and removing it
/// would reopen it outright, while `live` only makes the sweep quicker to reclaim logs it is
/// already entitled to. Keep both, but do not read the pid check as a safety net.
fn is_reclaimable(dir: &Path, live: &HashSet<u32>, now: SystemTime) -> io::Result<bool> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        match pid_of(&entry.file_name().to_string_lossy()) {
            Some(pid) if !live.contains(&pid) => {}
            _ => return Ok(false),
        }
        // A future-dated file reads as brand new, the same bias `sweep_dir` applies to a clock
        // that disagrees with us, and an unreadable timestamp keeps the directory outright.
        let quiet = entry
            .metadata()
            .and_then(|m| m.modified())
            .map(|m| now.duration_since(m).unwrap_or_default())?;
        if quiet < LIVE_WINDOW {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Delete the oldest log files under `dir` until the tree fits in `max_bytes`, sparing every
/// file that may still be in use. Returns how many were removed.
///
/// The age rule alone does not cap a directory: one chatty process at `trace` can fill a disk
/// well inside the retention window, and it does it inside *today's* directory, which the date
/// rule protects. This is the second bound, and unlike the first it may reach into today.
///
/// **It is a soft limit.** A file is spared when its pid is in `live`, when its name is not one
/// [`crate::core::logging`] wrote, or when it was modified within [`LIVE_WINDOW`]. Its size
/// still counts against the budget, so a tree of live logs stays over the limit rather than
/// being forced under it - deleting a log that is being appended to fails on Windows and
/// silently succeeds on Unix, where the writer then logs into an unlinked inode, and the budget
/// is not worth that. Only files inside date-named directories are weighed or removed, for the
/// same reason [`sweep_log_dirs`] deletes nothing else: the rest of `<state>/logs` is not this
/// module's to judge.
pub(crate) fn sweep_by_budget(
    dir: &Path,
    max_bytes: u64,
    now: SystemTime,
    live: &HashSet<u32>,
) -> io::Result<usize> {
    let mut total: u64 = 0;
    let mut oldest_first: Vec<(SystemTime, u64, std::path::PathBuf)> = Vec::new();
    for day in std::fs::read_dir(dir)? {
        let day = match day {
            Ok(day) => day,
            Err(e) => {
                warn!(
                    "Housekeeping: cannot read an entry of {}: {e}",
                    dir.display()
                );
                continue;
            }
        };
        // Silently, not with a warning: `sweep_log_dirs` has already reported anything odd here
        // this run, and a second copy of every complaint helps nobody.
        if day_number(&day.file_name().to_string_lossy()).is_none() {
            continue;
        }
        let listing = match std::fs::read_dir(day.path()) {
            Ok(listing) => listing,
            Err(e) => {
                warn!("Housekeeping: cannot list {}: {e}", day.path().display());
                continue;
            }
        };
        for file in listing {
            let file = match file {
                Ok(file) => file,
                Err(e) => {
                    warn!("Housekeeping: cannot read {}: {e}", day.path().display());
                    continue;
                }
            };
            let path = file.path();
            // `symlink_metadata`, so a link's own size is weighed and its target is never
            // followed out of the log tree - the rule [`newest_mtime`] follows for the same
            // reason.
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(e) => {
                    warn!("Housekeeping: cannot measure {}: {e}", path.display());
                    continue;
                }
            };
            if !meta.is_file() {
                continue;
            }
            total = total.saturating_add(meta.len());
            // A file dated in the future reads as brand new here, which is the same bias
            // `sweep_dir` applies to a clock that disagrees with us.
            let modified = meta.modified();
            let spared = match (pid_of(&file.file_name().to_string_lossy()), &modified) {
                // Not a name this module wrote, or a timestamp that cannot be read: weighed,
                // never deleted.
                (None, _) | (_, Err(_)) => true,
                (Some(pid), Ok(modified)) => {
                    live.contains(&pid)
                        || now.duration_since(*modified).unwrap_or_default() < LIVE_WINDOW
                }
            };
            if let Ok(modified) = modified
                && !spared
            {
                oldest_first.push((modified, meta.len(), path));
            }
        }
    }
    if total <= max_bytes {
        return Ok(0);
    }
    oldest_first.sort_by_key(|(modified, ..)| *modified);
    let mut deleted = 0;
    for (_, len, path) in oldest_first {
        if total <= max_bytes {
            break;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {
                total = total.saturating_sub(len);
                deleted += 1;
            }
            Err(e) => warn!("Housekeeping: cannot remove {}: {e}", path.display()),
        }
    }
    if total > max_bytes {
        info!(
            "Housekeeping: {} still holds {total} bytes against a {max_bytes}-byte budget; \
             the rest belongs to processes that may still be writing",
            dir.display()
        );
    }
    Ok(deleted)
}

/// A `YYYY-MM-DD` directory name as a Julian day number, or `None` for anything else.
///
/// A day number rather than a `Duration`: subtracting two of them gives whole days across month
/// ends and leap years, where counting hours would drift. The format is strict - four digits,
/// two, two, and a real calendar date - because the caller deletes what this recognises.
fn day_number(name: &str) -> Option<i32> {
    let (year, rest) = name.split_once('-')?;
    let (month, day) = rest.split_once('-')?;
    if year.len() != 4 || month.len() != 2 || day.len() != 2 {
        return None;
    }
    // On its own, `parse` would accept a sign on any of the three fields.
    if !name.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        return None;
    }
    let date = time::Date::from_calendar_date(
        year.parse().ok()?,
        time::Month::try_from(month.parse::<u8>().ok()?).ok()?,
        day.parse().ok()?,
    )
    .ok()?;
    Some(date.to_julian_day())
}

/// The pid in a `fsmcp-<pid>-<instance>.log` name, or `None` for any other name.
///
/// The pid only ever asks whether that process is still running, so a pid the OS has since
/// handed to something else merely keeps a file that could have gone - the direction this module
/// errs in everywhere.
///
/// **Known and deliberate:** a dead server's directory whose pid has been reused by an unrelated
/// live process is held for as long as that unrelated process runs, which can be indefinitely.
/// Keeping costs disk, deleting costs the operator their evidence, and telling the two apart
/// would mean recording process start times - a second identity mechanism beside
/// [`crate::core::instance`], for a case that costs one file.
///
/// Note precisely how far that goes, because the consolation is narrower than it first looks:
/// [`sweep_by_budget`] spares a file when its pid is live **or** it is fresh, an OR, so freshness
/// only ever adds sparing and never overrides a live pid. A colliding file is therefore pinned
/// under BOTH rules however quiet it becomes. What bounds the damage is only that the collision
/// is per pid: every other file in the tree stays reclaimable, so the budget still converges on
/// the rest and a whole tree cannot be frozen by one reused pid.
fn pid_of(name: &str) -> Option<u32> {
    let (pid, instance) = name.strip_prefix("fsmcp-")?.split_once('-')?;
    instance.ends_with(".log").then_some(())?;
    pid.parse().ok()
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
                warn!(
                    "Housekeeping: cannot read an entry of {}: {e}",
                    dir.display()
                );
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
            format!(
                "{} is nested deeper than {MAX_DEPTH} levels",
                path.display()
            ),
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
pub(crate) fn lease_due(root: &Path, kind: &str, every: Duration, now: SystemTime) -> Lease {
    let Some(marker) = marker_path(root, kind) else {
        return Lease::InvalidKind;
    };
    let stamp = unix_secs(now);
    let Ok(text) = std::fs::read_to_string(&marker) else {
        return Lease::Due;
    };
    match text.trim().parse::<u64>() {
        Ok(last) if last <= stamp && stamp - last < every.as_secs() => Lease::Held,
        _ => Lease::Due,
    }
}

/// Whether a lease lets the work run now.
///
/// Three outcomes rather than a bool, because "that is not a usable lease name" is a programming
/// error while "somebody else is doing it" is the ordinary case, and the two call for opposite
/// responses. As a bool the first collapsed into the second: a caller passing a bad `kind` was
/// told the work was already in hand and skipped it forever, silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lease {
    /// The interval has elapsed, or there is no usable marker to say otherwise: do the work.
    Due,
    /// A run completed within the interval: skip.
    Held,
    /// `kind` is not a bare name, so no marker file can be addressed for it.
    InvalidKind,
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
    // Written to a private name and renamed into place, never truncated where a reader can see
    // it: `fs::write` opens with truncate, so a concurrent `lease_due` could read the marker in
    // the instant it is empty and take that as "no usable marker", i.e. sweep again immediately.
    // The rename is atomic on both platforms, so every reader sees either the old stamp or the
    // new one. Wave 3's compaction needs that same guarantee from this file.
    let pending = sidecar_name(&marker);
    std::fs::write(&pending, unix_secs(now).to_string())?;
    std::fs::rename(&pending, &marker).inspect_err(|_| {
        // The stamp never landed, so the next process simply sweeps again. The scratch file is
        // the only lasting trace and it sits in the state root, which nothing sweeps by age.
        if let Err(e) = std::fs::remove_file(&pending) {
            warn!("Housekeeping: left {} behind: {e}", pending.display());
        }
    })
}

/// `marker` with `.<uuid>.tmp` appended: the private name [`lease_done`] writes before renaming.
///
/// A uuid rather than the pid, for the same reason `run_command`'s stream logs carry one: a pid
/// separates two processes but not two concurrent calls inside one, which would then share the
/// scratch file and put one's partial write under the other's rename. The damage would be a
/// spurious `Err` rather than a corrupt marker, but the name is cheap and the rule is the same
/// one everywhere: a file two writers can reach must not be named by something they share.
fn sidecar_name(marker: &Path) -> std::path::PathBuf {
    let mut name = marker.as_os_str().to_os_string();
    name.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
    std::path::PathBuf::from(name)
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

        assert_eq!(lease_due(root, "tmp", HOUR, now), Lease::Due, "first");
        lease_done(root, "tmp", now).expect("stamp");
        assert_eq!(lease_due(root, "tmp", HOUR, now), Lease::Held, "second");
        assert_eq!(
            lease_due(root, "tmp", HOUR, now + Duration::from_secs(3601)),
            Lease::Due,
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

        assert_eq!(lease_due(root, "tmp", HOUR, now), Lease::Due);
        // ... the sweep failed here, so `lease_done` was never reached.
        assert_eq!(
            lease_due(root, "tmp", HOUR, now),
            Lease::Due,
            "must still be due"
        );
    }

    /// Each kind of housekeeping holds its own lease, so wave 2's log retention is not silenced
    /// for an hour by the scratch sweep that ran a moment earlier.
    #[test]
    fn leases_are_independent_per_kind() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        let now = SystemTime::now();

        lease_done(root, "tmp", now).expect("stamp tmp");
        assert_eq!(lease_due(root, "tmp", HOUR, now), Lease::Held);
        assert_eq!(
            lease_due(root, "logs", HOUR, now),
            Lease::Due,
            "logs is a separate lease"
        );
    }

    /// A corrupted marker must not wedge housekeeping off forever: it reads as expired.
    #[test]
    fn a_malformed_marker_is_treated_as_expired() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        std::fs::write(root.join(".housekeeping-tmp"), b"not a timestamp").expect("write");

        assert_eq!(lease_due(root, "tmp", HOUR, SystemTime::now()), Lease::Due);
    }

    /// Nor may a marker from the future, which one VM snapshot restore or one backwards NTP step
    /// is enough to produce. Read literally it would switch retention off for a year.
    #[test]
    fn a_future_marker_is_treated_as_expired() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        let now = SystemTime::now();
        lease_done(root, "tmp", now + Duration::from_secs(365 * 24 * 3600)).expect("stamp");

        assert_eq!(
            lease_due(root, "tmp", HOUR, now),
            Lease::Due,
            "a future stamp is expired"
        );
    }

    /// A `kind` that would escape the state root is refused rather than joined onto it, in every
    /// build profile - and is reported as its own outcome, not as `Held`. Read as "somebody else
    /// is sweeping", a bad name would switch the work off silently and forever.
    #[test]
    fn an_escaping_kind_is_refused() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        assert_eq!(
            lease_due(scratch.path(), "../escape", HOUR, SystemTime::now()),
            Lease::InvalidKind
        );
        assert!(lease_done(scratch.path(), "../escape", SystemTime::now()).is_err());
    }

    /// A reader must never catch the marker mid-write. `fs::write` truncates in place, so a
    /// concurrent `lease_due` could read it empty and take that as "no usable marker" - i.e.
    /// sweep again immediately, which is the thing the lease exists to prevent.
    #[test]
    fn stamping_a_lease_leaves_no_scratch_file_behind() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        let now = SystemTime::now();

        lease_done(root, "tmp", now).expect("stamp");
        lease_done(root, "tmp", now).expect("stamp again over the existing marker");

        let left: Vec<String> = std::fs::read_dir(root)
            .expect("list")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != ".housekeeping-tmp")
            .collect();
        assert!(
            left.is_empty(),
            "the rename must leave nothing over: {left:?}"
        );
        assert_eq!(lease_due(root, "tmp", HOUR, now), Lease::Held);
    }

    /// A dated directory is aged by its name; today's and tomorrow's are never touched.
    ///
    /// The future-dated directory is the case the `age <= 0` guard exists for: a negative age
    /// cast to `u64` becomes enormous and would argue for deletion. Today's alone would not pin
    /// it, since an age of zero already satisfies the ordinary `<= keep_days` comparison.
    #[test]
    fn log_directories_age_by_their_name() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let now = SystemTime::now();
        for day in ["2026-09-01", "2026-09-16", "2026-09-17", "2026-09-18"] {
            let d = dir.path().join(day);
            std::fs::create_dir_all(&d).expect("mkdir");
            let log = d.join("fsmcp-1-aaaaaaaa.log");
            std::fs::write(&log, b"x").expect("write");
            // Quiet for two days, so only the date rule has anything to say about them.
            set_mtime(&log, now - 2 * DAY);
        }
        let deleted =
            sweep_log_dirs(dir.path(), 14, "2026-09-17", &HashSet::new(), now).expect("sweep");
        assert_eq!(deleted, 1, "only 2026-09-01 is older than 14 days");
        assert!(dir.path().join("2026-09-17").is_dir(), "today must survive");
        assert!(dir.path().join("2026-09-16").is_dir());
        assert!(
            dir.path().join("2026-09-18").is_dir(),
            "a directory dated in the future must survive, not read as infinitely old"
        );
    }

    /// A directory whose name is not a date is left alone rather than guessed at.
    #[test]
    fn an_unexpected_directory_name_is_not_deleted() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let odd = dir.path().join("not-a-date");
        std::fs::create_dir_all(&odd).expect("mkdir");
        assert_eq!(
            sweep_log_dirs(
                dir.path(),
                0,
                "2026-09-17",
                &HashSet::new(),
                SystemTime::now()
            )
            .expect("sweep"),
            0
        );
        assert!(odd.is_dir());
    }

    /// An expired directory whose files belong to a process that is still running stays: on Unix
    /// the unlink would succeed and the server would go on writing into an unlinked inode, losing
    /// the operator's evidence with no error anywhere.
    #[test]
    fn an_expired_directory_with_a_live_writer_is_kept() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let old = dir.path().join("2026-09-01");
        std::fs::create_dir_all(&old).expect("mkdir");
        let log = old.join("fsmcp-4242-aaaaaaaa.log");
        std::fs::write(&log, b"x").expect("write");
        // Quiet for two days, so the pid is the only thing keeping this directory.
        let now = SystemTime::now();
        set_mtime(&log, now - 2 * DAY);

        let live = HashSet::from([4242]);
        assert_eq!(
            sweep_log_dirs(dir.path(), 14, "2026-09-17", &live, now).expect("sweep"),
            0
        );
        assert!(old.is_dir(), "a live process's directory must survive");
        // The same directory goes once nothing in it is alive, so the test above pins the
        // liveness rule and not merely the fact that nothing is ever deleted.
        assert_eq!(
            sweep_log_dirs(dir.path(), 14, "2026-09-17", &HashSet::new(), now).expect("sweep"),
            1
        );
    }

    /// A file written within [`LIVE_WINDOW`] keeps its directory whatever the pid set says.
    ///
    /// This is the check that carries the safety property, and the only one that survives a
    /// process listing this module cannot tell is short - `hidepid=2`, a container, a foreign pid
    /// namespace - where the writer's pid is simply absent and the directory would otherwise look
    /// abandoned.
    #[test]
    fn an_expired_directory_written_to_just_now_is_kept() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let old = dir.path().join("2026-09-01");
        std::fs::create_dir_all(&old).expect("mkdir");
        let log = old.join("fsmcp-4242-aaaaaaaa.log");
        std::fs::write(&log, b"x").expect("write");

        // Nothing is alive as far as the listing is concerned, and the directory is a fortnight
        // past the window - only the mtime stands between it and `remove_dir_all`.
        let now = SystemTime::now();
        assert_eq!(
            sweep_log_dirs(dir.path(), 14, "2026-09-17", &HashSet::new(), now).expect("sweep"),
            0
        );
        assert!(old.is_dir(), "a directory being written to must survive");
        // Two days of quiet later it is reclaimed, so the assertion above pins the window and
        // not merely the fact that nothing is ever deleted.
        assert_eq!(
            sweep_log_dirs(dir.path(), 14, "2026-09-17", &HashSet::new(), now + 2 * DAY)
                .expect("sweep"),
            1
        );
    }

    /// The budget deletes oldest first, and stops before anything written within
    /// [`LIVE_WINDOW`] or belonging to a process that is still running.
    #[test]
    fn the_size_budget_spares_live_files() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let day = dir.path().join("2026-09-17");
        std::fs::create_dir_all(&day).expect("mkdir");
        let old = day.join("fsmcp-1-old.log");
        let live = day.join("fsmcp-2-live.log");
        std::fs::write(&old, vec![b'x'; 4096]).expect("write");
        std::fs::write(&live, vec![b'x'; 4096]).expect("write");
        let now = SystemTime::now();
        set_mtime(&old, now - 2 * DAY);

        // Pid 1 is still running: its log is two days quiet and the budget is exceeded, and it
        // is still not the budget's to take. This is the idle-but-alive server, which the
        // mtime rule alone does not protect.
        assert_eq!(
            sweep_by_budget(dir.path(), 4096, now, &HashSet::from([1])).expect("budget"),
            0,
            "a running process's log is never budgeted away, however quiet it has been"
        );
        assert!(old.exists());

        // Once it has exited, it is the first to go - and the budget still stops there.
        let deleted = sweep_by_budget(dir.path(), 4096, now, &HashSet::new()).expect("budget");
        assert_eq!(deleted, 1);
        assert!(!old.exists(), "the oldest file goes first");
        assert!(
            live.exists(),
            "a file written within the live window is never budgeted away"
        );
    }

    /// Only a real, fully-spelled calendar date is recognised, because what this function
    /// recognises is what the sweep deletes.
    #[test]
    fn only_a_real_date_is_recognised() {
        assert!(day_number("2026-09-17").is_some());
        // A day apart is a day apart across a month end, which an hour count would have to
        // rediscover.
        let (sep30, oct1) = (day_number("2026-09-30"), day_number("2026-10-01"));
        assert_eq!(oct1.zip(sep30).map(|(a, b)| a - b), Some(1));
        for odd in [
            "2026-13-01", // no such month
            "2026-02-30", // no such day
            "20260917",   // the separators carry the field widths
            "2026-9-17",  // unpadded
            "+026-09-17", // a sign would parse as a number but is not a date name
            "not-a-date",
            "",
        ] {
            assert_eq!(day_number(odd), None, "{odd:?}");
        }
    }

    /// A pid is read only from a name this module's writer produced; anything else is unknown,
    /// and unknown means untouchable.
    #[test]
    fn a_pid_is_read_only_from_our_own_file_names() {
        assert_eq!(pid_of("fsmcp-4242-aaaaaaaa.log"), Some(4242));
        for odd in [
            "fsmcp-4242.log",          // no instance id
            "fsmcp-4242-aaaaaaaa.txt", // not a log
            "server-4242-aaaaaaaa.log",
            "fsmcp--aaaaaaaa.log",
            "fsmcp-nope-aaaaaaaa.log",
        ] {
            assert_eq!(pid_of(odd), None, "{odd:?}");
        }
    }

    /// A listing this process cannot trust is a completed pass that kept everything, so it
    /// stamps the lease. Without the stamp, a host where the process table is permanently
    /// restricted - `hidepid=2`, a container, a foreign pid namespace - would pay a full process
    /// enumeration on every start of every server, which is the one thing the lease exists to
    /// prevent, on exactly the hosts that can least afford it.
    #[test]
    fn a_refused_process_listing_still_stamps_the_lease() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        let logs = root.join("logs");
        std::fs::create_dir_all(&logs).expect("mkdir");
        let now = SystemTime::now();

        assert_eq!(
            sweep_logs_in(root, &logs, 14, 4096, now, None).expect("sweep"),
            Sweep::Ran(0),
            "an untrusted listing deletes nothing"
        );
        assert_eq!(
            lease_due(root, "logs", SWEEP_INTERVAL, now),
            Lease::Held,
            "the pass completed, so the next process must not repeat it this interval"
        );
    }

    /// With both knobs at zero there is nothing to do, and the lease is not spent saying so.
    #[test]
    fn both_knobs_at_zero_disable_the_log_sweep() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        let logs = root.join("logs");
        std::fs::create_dir_all(&logs).expect("mkdir");
        let now = SystemTime::now();

        assert_eq!(
            sweep_logs_in(root, &logs, 0, 0, now, Some(&HashSet::new())).expect("sweep"),
            Sweep::Disabled
        );
        assert_eq!(lease_due(root, "logs", SWEEP_INTERVAL, now), Lease::Due);
        // Each knob switches off on its own, so one at zero still leaves a pass to run.
        assert_eq!(
            sweep_logs_in(root, &logs, 0, 4096, now, Some(&HashSet::new())).expect("sweep"),
            Sweep::Ran(0)
        );
    }

    /// A listing holding this process is trusted, and handed back exactly as it came.
    #[test]
    fn a_listing_containing_us_is_trusted_intact() {
        let pids = HashSet::from([1, 4242, 7777]);
        assert_eq!(
            trust_listing(pids.clone(), 4242),
            Some(pids),
            "the set must come back untouched - nothing is inserted into it"
        );
    }

    /// A listing that cannot see the process doing the listing is refused outright.
    ///
    /// This is `hidepid=2`, a restricted container, a foreign pid namespace: the call succeeds
    /// and returns a short list, and trusting it would make a live server's log look abandoned.
    #[test]
    fn a_listing_without_us_is_refused() {
        assert_eq!(trust_listing(HashSet::from([1, 7777]), 4242), None);
        assert_eq!(
            trust_listing(HashSet::new(), 1),
            None,
            "an empty listing is not a listing either"
        );
    }

    /// A live sibling the process listing cannot see keeps its whole start-day directory.
    ///
    /// This is the case [`trust_listing`] is often misread as covering and cannot: server B runs
    /// as another user, or in another pid namespace, so our listing simply does not name it -
    /// while naming us, which is all that check can test for. B started twenty days ago, past any
    /// ordinary `keep_days`, and last logged two hours ago because its client has been quiet.
    ///
    /// Nothing but [`LIVE_WINDOW`] stands between that directory and `remove_dir_all`, and on
    /// Unix the unlink of an open file succeeds silently: B would go on writing into an unlinked
    /// inode and the operator would lose every line from that moment with no error anywhere. So
    /// this test fails the instant the window is shortened back below a live server's idle gap -
    /// which is exactly what it is here to prevent.
    #[test]
    fn a_live_siblings_directory_survives_a_listing_that_cannot_see_it() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        let logs = root.join("logs");
        let now = SystemTime::now();
        let start_day = crate::core::logging::utc_day(now - 20 * DAY);
        let sibling = write_log(
            &logs,
            &start_day,
            "fsmcp-4242-aaaaaaaa.log",
            4096,
            now - 2 * HOUR,
        );

        // A listing that passes every check this module can make: it contains the process doing
        // the listing. It just does not contain 4242, because 4242 is not ours to see.
        let own = crate::core::instance::pid();
        let live = trust_listing(HashSet::from([own]), own).expect("a listing naming us is taken");

        assert_eq!(
            sweep_logs_in(root, &logs, 14, 0, now, Some(&live)).expect("sweep"),
            Sweep::Ran(0),
            "a directory whose log was written within the live window is not this sweep's to take"
        );
        assert!(
            sibling.is_file(),
            "a live server's log must survive a listing that cannot see the server"
        );
    }

    /// The same sibling, against the budget rule, which reaches into today and so gets there
    /// faster. A budget of one byte is unsatisfiable on purpose: the rule must still refuse to
    /// close the gap with a file that was written two hours ago.
    #[test]
    fn the_budget_spares_a_live_sibling_the_listing_cannot_see() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        let logs = root.join("logs");
        let now = SystemTime::now();
        let today = crate::core::logging::utc_day(now);
        let sibling = write_log(
            &logs,
            &today,
            "fsmcp-4242-aaaaaaaa.log",
            4096,
            now - 2 * HOUR,
        );

        let own = crate::core::instance::pid();
        let live = trust_listing(HashSet::from([own]), own).expect("a listing naming us is taken");

        assert_eq!(
            sweep_logs_in(root, &logs, 0, 1, now, Some(&live)).expect("sweep"),
            Sweep::Ran(0),
            "the budget is a soft limit and stops at a file that may still be written to"
        );
        assert!(sibling.is_file(), "the sibling's current log must survive");
    }

    /// With the budget off, the date rule runs alone - and the count it returns is the count of
    /// directories it actually removed.
    ///
    /// The fixture deliberately leaves a stale, dead-pid file in TODAY's directory: with the
    /// budget off nothing may weigh it, so a guard that let the budget run with a zero limit
    /// would take it and the count would be wrong.
    #[test]
    fn the_date_rule_runs_alone_when_the_budget_is_off() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        let logs = root.join("logs");
        let now = SystemTime::now();
        // Named from `now`, never from the real calendar, so this test cannot rot.
        let today = crate::core::logging::utc_day(now);
        let long_ago = crate::core::logging::utc_day(now - 30 * DAY);

        let expired = write_log(
            &logs,
            &long_ago,
            "fsmcp-1-aaaaaaaa.log",
            4096,
            now - 2 * DAY,
        );
        let current = write_log(&logs, &today, "fsmcp-2-bbbbbbbb.log", 4096, now - 2 * DAY);

        assert_eq!(
            sweep_logs_in(root, &logs, 14, 0, now, Some(&HashSet::new())).expect("sweep"),
            Sweep::Ran(1),
            "one directory removed, and the count must say one"
        );
        assert!(!expired.exists(), "the expired directory goes");
        assert!(
            current.is_file(),
            "with the budget off nothing is weighed, however stale and however dead its pid"
        );
    }

    /// With the date rule off, the budget runs alone - oldest first, stopping the moment the
    /// tree fits, and reporting exactly what it removed.
    ///
    /// The fixture deliberately leaves an expired directory: with `keep_days = 0` the date rule
    /// may not touch it, so a guard that let it run with a zero limit would take it too.
    #[test]
    fn the_budget_runs_alone_when_the_date_rule_is_off() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let root = scratch.path();
        let logs = root.join("logs");
        let now = SystemTime::now();
        let today = crate::core::logging::utc_day(now);
        let long_ago = crate::core::logging::utc_day(now - 30 * DAY);

        let expired = write_log(
            &logs,
            &long_ago,
            "fsmcp-1-aaaaaaaa.log",
            4096,
            now - 2 * DAY,
        );
        let older = write_log(&logs, &today, "fsmcp-2-bbbbbbbb.log", 4096, now - 3 * DAY);
        let newer = write_log(&logs, &today, "fsmcp-3-cccccccc.log", 4096, now - 2 * DAY);

        // Three files, 12 KiB, against an 8 KiB budget: the oldest goes and the tree then fits.
        assert_eq!(
            sweep_logs_in(root, &logs, 0, 8192, now, Some(&HashSet::new())).expect("sweep"),
            Sweep::Ran(1),
            "one file removed, and the count must say one"
        );
        assert!(!older.exists(), "the oldest file goes first");
        assert!(newer.is_file(), "the budget stops as soon as the tree fits");
        assert!(
            expired.is_file(),
            "with the date rule off an expired directory is untouchable, whatever its age"
        );
    }

    /// Write `<logs>/<day>/<name>` of `size` bytes, stamped at `when`, creating the directory.
    /// Returns the file's path - the directory is its parent, which is what the date-rule
    /// assertions look at.
    fn write_log(
        logs: &Path,
        day: &str,
        name: &str,
        size: usize,
        when: SystemTime,
    ) -> std::path::PathBuf {
        let dir = logs.join(day);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(name);
        std::fs::write(&path, vec![b'x'; size]).expect("write");
        set_mtime(&path, when);
        path
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
