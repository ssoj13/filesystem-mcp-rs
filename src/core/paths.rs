//! The one place that knows where this server keeps state.
//!
//! Everything durable and scratch lives under a single per-user root,
//! `~/.filesystem-mcp-rs/`, identically on Windows, macOS and Linux. State used to be
//! spread over four roots (`data_local_dir`, `data_dir`, two different temp subdirs), two
//! of which differ per OS and per Windows account, which made "where is it?" unanswerable.
//!
//! No other module may call `dirs::*`, `std::env::temp_dir` or `std::env::home_dir`; tests take
//! scratch space from `tempfile::TempDir` instead. That rule is not a convention here - the test
//! `paths_are_centralized` in `src/core/paths_guard.rs` scans every `.rs` file under `src/` and
//! `tests/` and fails the build on any call site not listed in that module's `ALLOWED`, so the
//! drift cannot come back quietly. `ALLOWED` is not only this file: `src/mcp_setup/types.rs` and
//! `src/mcp_setup/host.rs` are cleared for `dirs::home_dir`, because the installer locates *other*
//! applications' config files. With `paths_guard.rs` itself, which names the spellings it forbids,
//! `ALLOWED` has four entries - so the call appears in four files, not one.
//!
//! The guard sees only this repo's tree under `src/` and `tests/`. A path resolved inside a
//! dependency, in a `build.rs` (crate root, outside both roots) or through a macro expansion is
//! invisible to it; `build.rs` is the concrete near-miss, since the crate has none today and one
//! added later would be unguarded. That module's doc records the further spellings it cannot see.

use std::io;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::env_spec;

/// A subdirectory of the state root. One variant per kind of state the server keeps,
/// so the names exist once instead of being spelled at each call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubDir {
    /// Per-process log files, one per run under a dated directory
    /// (see [`crate::core::logging`]).
    Logs,
    /// Downloaded OCR models.
    #[cfg(feature = "ctl-ocr")]
    Ocrs,
    /// Saved window layouts.
    #[cfg(feature = "ctl-input")]
    Layouts,
    /// Computer-control safety state.
    #[cfg(feature = "ctl-input")]
    Safety,
    /// Crash reports, one file per panic under a dated directory (see `install_panic_hook`).
    Panics,
    /// Tool-call counters, one file per run under a dated directory
    /// (see [`crate::tools::stats`]).
    ///
    /// Apart from [`SubDir::Logs`] deliberately: the counters are a table written once, and
    /// mixing them into the running narrative of a log would mean grepping one out of the other.
    Stats,
    /// Scratch: captures, `run_command` output, temporary scripts. Swept by age.
    Tmp,
}

impl SubDir {
    /// Directory name on disk.
    pub fn as_str(&self) -> &'static str {
        match self {
            SubDir::Logs => "logs",
            #[cfg(feature = "ctl-ocr")]
            SubDir::Ocrs => "ocrs",
            #[cfg(feature = "ctl-input")]
            SubDir::Layouts => "layouts",
            #[cfg(feature = "ctl-input")]
            SubDir::Safety => "safety",
            SubDir::Panics => "panics",
            SubDir::Stats => "stats",
            SubDir::Tmp => "tmp",
        }
    }
}

/// The state root, created if missing.
pub fn state_dir() -> io::Result<PathBuf> {
    resolve_root(env_spec::get("FS_MCP_STATE_DIR").map(PathBuf::from))
}

/// Path of a file directly in the state root (`stats.db`, `memory2.db`).
/// The root is created; the file is not.
pub fn db_path(name: &str) -> io::Result<PathBuf> {
    Ok(state_dir()?.join(name))
}

/// A subdirectory of the state root, created if missing.
pub fn sub_dir(kind: SubDir) -> io::Result<PathBuf> {
    resolve_sub(env_spec::get("FS_MCP_STATE_DIR").map(PathBuf::from), kind)
}

/// Path for a file this run writes once:
/// `<state>/<kind>/<YYYY-MM-DD>/<machine>_<stamp>_<instance>.<ext>`.
///
/// The dated directory is created; the file is not. Three subsystems write such a file - the log
/// ([`SubDir::Logs`]), a crash report ([`SubDir::Panics`]) and the tool-call counters
/// ([`SubDir::Stats`]) - and they all come through here, so the host name, the timestamp format
/// and the directory layout exist once. A change to any of them cannot reach two of the three and
/// miss the third.
///
/// **The stamp names the run, not the moment of the call.** It comes from
/// [`crate::core::instance::started`], fixed once per process, so a run's log, crash report and
/// counters share one stem and differ only in their directory and extension - which is what makes
/// the three correlatable at all. A helper reading the clock per call would hand the log the
/// startup instant, the crash report the panic instant and the counters the exit instant, and
/// nothing in the name would tie them together.
///
/// It also means the counters have **one** path per run: the panic hook writes a partial file and
/// the exit path overwrites it with the final one, so no latch is needed to keep a run to one
/// counters file.
///
/// **Uniqueness comes from the name itself, not from coordination.** Nothing consults a lock, a
/// pid or another process's files. Three parts carry it, and each covers what the others cannot:
/// the host name separates machines sharing a state root, the millisecond stamp separates runs on
/// one machine, and [`crate::core::instance::id`] separates the case the stamp cannot - a client
/// launching a dozen servers at once, which start inside the same millisecond routinely. That
/// last one is why the instance is in the name at all: without it two such servers resolve the
/// identical path, and the counters writer truncates rather than appends, so one run's whole
/// report would be destroyed in silence by the other.
///
/// The host name sanitises many-to-one (`a_b` and `a-b` both give `a-b`), so two differently
/// named hosts sharing one state root can still meet; the instance covers that too.
///
/// This is what replaced wave 2's retention layer: that layer existed only to decide whether
/// another process's file was safe to delete, a question nobody now asks.
pub fn run_file(kind: SubDir, ext: &str) -> io::Result<PathBuf> {
    run_file_at(
        env_spec::get("FS_MCP_STATE_DIR").map(PathBuf::from),
        kind,
        ext,
        crate::core::instance::started(),
    )
}

/// [`run_file`] against an explicit root and instant, so the naming can be tested against a
/// `TempDir` and a fixed clock instead of the real state root and the real time of day.
fn run_file_at(
    root: Option<PathBuf>,
    kind: SubDir,
    ext: &str,
    when: std::time::SystemTime,
) -> io::Result<PathBuf> {
    let dated = resolve_sub(root, kind)?.join(utc_day(when));
    mkdir(&dated)?;
    Ok(dated.join(format!(
        "{}_{}_{}.{ext}",
        machine(),
        stamp(when),
        crate::core::instance::id()
    )))
}

/// This host's name, reduced to characters every filesystem accepts.
///
/// `unknown` rather than an error when the name cannot be read, or survives sanitising as
/// nothing: a file that cannot be named is a file that does not exist, and neither logging nor a
/// crash report may be the reason the server fails. `_` is folded away with everything else, so
/// the separator in the file name stays unambiguous.
fn machine() -> String {
    let safe: String = sysinfo::System::host_name()
        .unwrap_or_default()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if safe.is_empty() {
        "unknown".to_owned()
    } else {
        safe
    }
}

/// `when` in UTC as `YYYYMMDD-HHMMSS-mmm`.
///
/// UTC and hand-formatted for the same reasons as [`utc_day`], and fixed-width in every field so
/// that a plain lexical sort of a directory listing is a sort by time.
///
/// A clock no calendar can describe falls back to the raw nanosecond count rather than to a
/// fixed word: the stamp is the only thing keeping two files apart, so it must stay unique.
fn stamp(when: std::time::SystemTime) -> String {
    let Some(t) = calendar(when) else {
        return epoch_nanos(when).to_string();
    };
    let d = t.date();
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}-{:03}",
        d.year(),
        u8::from(d.month()),
        d.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    )
}

/// `when` in UTC as `YYYY-MM-DD`, the name of the directory a file written then belongs in.
///
/// UTC, matching wave 1's rule that stored time is UTC: a directory named in local time would
/// jump around under a machine that travels or changes offset twice a year. Formatted by hand
/// rather than through `time`'s format descriptions, which would need a feature this crate does
/// not enable for three integers.
pub(crate) fn utc_day(when: std::time::SystemTime) -> String {
    let Some(t) = calendar(when) else {
        return "unknown-date".to_owned();
    };
    let d = t.date();
    format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
}

/// `when` as a calendar date and time in UTC, or `None` for a clock so far from the epoch that
/// no calendar describes it.
///
/// Fallible on purpose, where the obvious `OffsetDateTime::from(SystemTime)` is not: that one
/// adds a `Duration` to the epoch and **panics** on overflow. [`run_file`] is reachable from the
/// panic hook, and a panic inside a panic hook aborts the process with no diagnostic at all - the
/// one failure mode a crash report exists to prevent.
fn calendar(when: std::time::SystemTime) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp_nanos(epoch_nanos(when)).ok()
}

/// `when` as nanoseconds from the Unix epoch, negative before it, saturating instead of failing.
///
/// Saturation is unreachable from a real `SystemTime` - it would take a clock 10^22 years out -
/// and is written this way only so that no arm of this can panic.
fn epoch_nanos(when: std::time::SystemTime) -> i128 {
    match when.duration_since(std::time::UNIX_EPOCH) {
        Ok(since) => i128::try_from(since.as_nanos()).unwrap_or(i128::MAX),
        Err(before) => i128::try_from(before.duration().as_nanos()).map_or(i128::MIN, |n| -n),
    }
}

/// How long a file under [`SubDir::Tmp`] may survive before the housekeeping sweep deletes it.
///
/// Lives here rather than in the sweep because this module owns `<state>/tmp` and therefore its
/// retention policy; the sweep is only the thing that acts on it. An unparseable value is
/// reported and the default applied: refusing to start over a malformed cleanup interval would
/// be a worse outcome than keeping scratch files for the standard day.
///
/// **Zero means retention is off**, not "delete everything now". A knob set to zero reading as
/// "destroy all scratch immediately" is a foot-gun, and with dozens of concurrent servers it
/// would reclaim live spools on every start; "switch it off" is also the only thing an operator
/// plausibly means by 0. The caller ([`crate::core::housekeeping::sweep_tmp`]) applies that.
///
/// The result is clamped to [`TMP_KEEP_HOURS_MAX`] so that no caller can overflow converting it
/// to a duration: in debug that overflow panics, and a panic in housekeeping would keep the
/// transport from ever starting.
pub fn tmp_keep_hours() -> u64 {
    let hours = match env_spec::get("FS_MCP_TMP_KEEP_HOURS") {
        None => TMP_KEEP_HOURS_DEFAULT,
        Some(raw) => raw.parse().unwrap_or_else(|_| {
            warn!(
                "FS_MCP_TMP_KEEP_HOURS is not a whole number of hours ({raw}); using {TMP_KEEP_HOURS_DEFAULT}"
            );
            TMP_KEEP_HOURS_DEFAULT
        }),
    };
    if hours > TMP_KEEP_HOURS_MAX {
        warn!(
            "FS_MCP_TMP_KEEP_HOURS={hours} exceeds the {TMP_KEEP_HOURS_MAX}-hour maximum; using that instead"
        );
        return TMP_KEEP_HOURS_MAX;
    }
    hours
}

/// The retention applied when `FS_MCP_TMP_KEEP_HOURS` is unset.
///
/// The registry in [`crate::env_spec`] advertises this same number to the user as the key's
/// default, and the two must not drift: a table that promises 24 while the code keeps 72 is
/// worse than no table. `EnvVar::default` is a `&'static str`, so the values cannot be one
/// declaration; `env_spec`'s `state_keys_are_registered_once_and_described_correctly` asserts
/// they agree instead.
pub const TMP_KEEP_HOURS_DEFAULT: u64 = 24;

/// The longest retention accepted, one year.
///
/// An upper bound exists so the value can always be converted to a `Duration` without overflow,
/// and a year is where "keep it longer" stops being distinguishable from "keep it forever" for a
/// scratch directory. Anything above is clamped with a warning rather than refused: a silly
/// number in an environment variable must not stop the server from starting.
pub const TMP_KEEP_HOURS_MAX: u64 = 24 * 365;

/// Resolve and create the root. Split from [`state_dir`] so tests can inject an override
/// without mutating the process environment.
fn resolve_root(override_dir: Option<PathBuf>) -> io::Result<PathBuf> {
    let root = resolve_root_from(override_dir, dirs::home_dir())?;
    mkdir(&root)?;
    Ok(root)
}

/// Resolve a subdirectory and create it. Split for the same reason as [`resolve_root`].
fn resolve_sub(override_dir: Option<PathBuf>, kind: SubDir) -> io::Result<PathBuf> {
    let dir = resolve_root(override_dir)?.join(kind.as_str());
    mkdir(&dir)?;
    Ok(dir)
}

/// `create_dir_all` that names the directory it could not create.
///
/// A bare `std::fs` error carries only the reason, so with `FS_MCP_STATE_DIR` unset the operator
/// read `Cannot prepare the server state directory: Access is denied. (os error 5)` and had no
/// way to tell which directory was refused - the one thing they need in order to fix it.
///
/// The syscall runs on every call, deliberately. Remembering "this process already created it"
/// would save one `stat` on operations that go on to write a file anyway, and in exchange a state
/// directory removed under a running server would never be recreated - every capture, every
/// `run_command` and every blob write failing until restart. A process-local flag cannot assert a
/// fact about a filesystem other processes and people also touch. If this ever measures, cache
/// the resolved [`PathBuf`], which this process does own, not the directory's existence.
fn mkdir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| io::Error::new(e.kind(), format!("Cannot create {}: {e}", dir.display())))
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
    /// The data was not moved and is still at `old`. `cause` says which of the two very different
    /// situations this is, because the advice an operator needs differs completely between them.
    Ambiguous {
        old: PathBuf,
        new: PathBuf,
        cause: Cause,
    },
}

/// Why a migration ended up [`Migrated::Ambiguous`].
///
/// The distinction exists because only one of these two means there is anything at `new`. Three of
/// [`migrate`]'s four refusal paths are `Failed`, and in all three `new` does not exist - either it
/// never did, or the cleanup removed it - so a message telling the operator to "delete the one you
/// do not want" would send them after a file that is not there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cause {
    /// A file exists at both paths. Only a human can say which set of data to keep.
    BothExist,
    /// The move was attempted and could not be completed; the string is the underlying reason.
    /// Nothing exists at `new`.
    Failed(String),
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
/// and a partial `new` *that this call created* is removed, so `Ambiguous` means literally what it
/// says: after a failed migration the only file that exists is the original.
///
/// **Concurrency.** Dozens of these servers start at once, so two of them reading `(old=true,
/// new=false)` in the same instant is the ordinary case. Two rules make the loser harmless, and
/// both are load-bearing: the copy fallback opens the destination with `create_new`, so it can
/// never write into a file another process put there; and the cleanup runs only while `old` still
/// exists, because `old` being gone means another process completed the move and the file at `new`
/// is *its* data. The earlier code removed `new` by existence alone, which on Unix deleted the
/// winner's freshly migrated database while the winner went on writing to the unlinked inode.
///
/// The `rename` itself replaces a destination that appears inside that same window (both
/// platforms do), and that is left as it is: a file can only appear at `new` while `old` still
/// exists if another process is mid-copy from *this same* `old`, so the bytes that end up at
/// `new` are the same either way. Refusing it would need link-and-unlink semantics that std does
/// not offer portably, for no difference in outcome.
///
/// Coverage note, precisely. The cross-volume `copy` fallback is never entered *by that route* on
/// a single-volume test machine, so the copy step itself is verified by inspection only; on
/// Windows a handle that denies DELETE makes `rename` fail and drives the same fallback, which is
/// how the two arms below are reached. The cleanup that removes a leftover `new` is covered by
/// `migrate_removes_the_leftover_when_the_original_cannot_be_unlinked`, and the `!old.exists()`
/// guard that skips it by `migrate_loser_that_already_created_the_destination_leaves_it_alone`;
/// both are `#[cfg(windows)]`, and on Unix those two arms are verified by reading. The
/// `Occupied` race outcome is covered on every platform through [`Hooks::before_move`], and the
/// parent-creation failure returns before any of this and is covered separately.
pub fn migrate(old: &Path, new: &Path) -> Migrated {
    migrate_with(old, new, Hooks::NONE)
}

/// Test seams for [`migrate_with`]: the two points at which another process's move can land
/// inside this one.
///
/// They exist so that the losing side of a two-server race can be driven deterministically - a
/// test puts the winner's `rename` exactly in a window this call has already passed. A real race
/// is the same code path arrived at by timing, and reproducing it by timing would give a test
/// that fails once in a thousand runs: no gate at all. Production passes [`Hooks::NONE`], whose
/// no-ops the optimiser removes.
///
/// Two points rather than one because the two race outcomes are reached from different places. A
/// winner that finishes before the `rename` leaves the loser's copy refused as `Occupied`; one
/// that finishes after the loser has already created the destination leaves it failing on the
/// *source*, which is the only way into the `Io` arm's `!old.exists()` guard.
#[derive(Clone, Copy)]
struct Hooks<'a> {
    /// Runs after the decision to move and before the `rename` is attempted.
    before_move: &'a dyn Fn(),
    /// Runs after the copy fallback has created the destination and before it opens the source.
    after_create: &'a dyn Fn(),
}

impl Hooks<'_> {
    /// What production passes: both points do nothing.
    const NONE: Self = Self {
        before_move: &|| {},
        after_create: &|| {},
    };
}

/// [`migrate`], with hooks at the points another process's move can interleave.
fn migrate_with(old: &Path, new: &Path, hooks: Hooks<'_>) -> Migrated {
    let ambiguous = |cause: Cause| Migrated::Ambiguous {
        old: old.to_path_buf(),
        new: new.to_path_buf(),
        cause,
    };
    // `FS_MCP_STATE_DIR` pointed at the legacy directory: one file, already in place. Falling
    // through would report `BothExist`, whose remedy - "keep one, delete the other" - names the
    // same path twice and cannot be carried out.
    if old == new {
        return Migrated::FreshStart;
    }
    if old.is_dir() {
        let why = "migrate() moves single files, not directories";
        warn!("Refusing to migrate {}: {why}", old.display());
        return ambiguous(Cause::Failed(why.to_string()));
    }
    match (old.exists(), new.exists()) {
        (true, false) => {
            if let Some(parent) = new.parent()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                warn!("Cannot create {}: {e}", parent.display());
                return ambiguous(Cause::Failed(format!(
                    "cannot create {}: {e}",
                    parent.display()
                )));
            }
            (hooks.before_move)();
            if std::fs::rename(old, new).is_ok() {
                info!("Migrated {} -> {}", old.display(), new.display());
                return Migrated::Moved;
            }
            match copy_into_a_new_file(old, new, hooks.after_create) {
                Ok(()) => {
                    info!("Migrated (copied) {} -> {}", old.display(), new.display());
                    Migrated::Moved
                }
                // Another process created `new` between our check and our copy. Whether that is
                // a conflict or a completed migration is answered by `old`: a process that
                // finished the move took the original with it.
                Err(CopyFailed::Occupied) => {
                    if old.exists() {
                        ambiguous(Cause::BothExist)
                    } else {
                        info!(
                            "{} was already migrated to {} by another instance",
                            old.display(),
                            new.display()
                        );
                        Migrated::FreshStart
                    }
                }
                Err(CopyFailed::Io(e)) => {
                    warn!(
                        "Failed to migrate {} -> {}: {e}",
                        old.display(),
                        new.display()
                    );
                    // `old` gone means another instance moved it while this one was copying, so
                    // whatever is at `new` now is that instance's data and must not be touched.
                    // The bias is deliberate: mistaking our own partial for a winner's file
                    // leaves a truncated copy the next start reports as a conflict, while the
                    // opposite mistake destroys the user's only database.
                    if !old.exists() {
                        warn!(
                            "{} was moved by another instance mid-copy; leaving {} untouched",
                            old.display(),
                            new.display()
                        );
                        return Migrated::FreshStart;
                    }
                    // Our own partial, or a complete copy whose `remove_file(old)` failed. Either
                    // way it must go: a truncated database would be opened as real data, and a
                    // complete duplicate would make every later startup report a conflict forever.
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
                    ambiguous(Cause::Failed(e.to_string()))
                }
            }
        }
        (true, true) => ambiguous(Cause::BothExist),
        (false, _) => Migrated::FreshStart,
    }
}

/// Why [`copy_into_a_new_file`] did not complete. `Occupied` is separate from `Io` because it is
/// the only outcome that means the file at the destination belongs to somebody else.
enum CopyFailed {
    /// The destination already existed, so nothing was written.
    Occupied,
    /// The copy itself failed. The destination, if any, was created by this call.
    Io(io::Error),
}

/// Copy `old` onto a destination **this call creates**, then remove `old`.
///
/// `create_new` is the whole point: `fs::copy` would happily truncate a file another server had
/// just migrated into place, and the failure that followed would then be cleaned up by deleting
/// the user's data. Refusing to write into an existing file makes that impossible by
/// construction rather than by timing.
///
/// The contents are flushed with `sync_all` before `old` is removed, so a crash between the two
/// cannot leave a destination whose bytes are still only in the page cache.
fn copy_into_a_new_file(old: &Path, new: &Path, after_create: &dyn Fn()) -> Result<(), CopyFailed> {
    let mut dst = match std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(new)
    {
        Ok(dst) => dst,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Err(CopyFailed::Occupied),
        Err(e) => return Err(CopyFailed::Io(e)),
    };
    after_create();
    let mut src = std::fs::File::open(old).map_err(CopyFailed::Io)?;
    io::copy(&mut src, &mut dst).map_err(CopyFailed::Io)?;
    dst.sync_all().map_err(CopyFailed::Io)?;
    drop(dst);
    drop(src);
    std::fs::remove_file(old).map_err(CopyFailed::Io)
}

/// The files sqlite keeps beside a database. `-shm` is shared memory and is rebuilt on open;
/// `-wal` holds transactions that are committed but not yet in the database file, and is the
/// whole reason this module needs a sqlite-aware migration.
const SQLITE_SIDECARS: [&str; 2] = ["-wal", "-shm"];

/// `db` with `suffix` appended to its file name - `memory2.db` + `-wal` = `memory2.db-wal`,
/// which is how sqlite names them (an appended suffix, not a replaced extension).
fn sidecar(db: &Path, suffix: &str) -> PathBuf {
    let mut name = db.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// [`migrate`] for a sqlite database: the database and its write-ahead log move as one, or
/// nothing moves at all.
///
/// `memory2.db` runs in WAL mode and MCP hosts kill stdio servers without ceremony, so finding a
/// `-wal` holding committed-but-uncheckpointed transactions is the ordinary state, not a crash
/// artefact. Moving the database alone drops those transactions silently: the user's memory
/// store is there and its newest entries are not.
///
/// **Why checkpoint rather than move the group.** Moving three files cannot be made atomic, so
/// every ordering has a failure that leaves split state - and a database separated from its
/// `-wal` is worse than no migration at all, because it looks like success. Checkpointing folds
/// the log into the database *before* anything moves, which reduces the problem to the
/// single-file move [`migrate`] already gets right, race and all. It also gives Unix the
/// protection Windows gets from file sharing: a checkpoint that cannot complete is exactly the
/// signal that another instance is using the database, so the refusal below is not a
/// conservative guess - it is sqlite telling us.
///
/// A checkpoint that cannot be *proved* complete refuses the move and reports [`Cause::Failed`],
/// which disables the memory tools with the message naming the old path. That is deliberate: the
/// alternative is moving a database we cannot vouch for. A file that is not a database at all
/// takes the same path, and says so.
///
/// After the move, both locations are cleared of sidecars. At the old location they are empty
/// leftovers of the checkpoint; at the new one they can only be strays from an earlier crash,
/// since this call's own log was folded in and this process is the one that just won the move -
/// and sqlite would otherwise replay a foreign log into the database that landed there.
pub fn migrate_sqlite(old: &Path, new: &Path) -> Migrated {
    // Only the branch that actually moves a file needs any of this; every other outcome
    // (identical paths, a directory, nothing to do, a conflict) is `migrate`'s to report.
    if old == new || old.is_dir() || !old.exists() || new.exists() {
        return migrate(old, new);
    }
    if let Err(why) = checkpoint(old) {
        warn!("Refusing to migrate {}: {why}", old.display());
        return Migrated::Ambiguous {
            old: old.to_path_buf(),
            new: new.to_path_buf(),
            cause: Cause::Failed(why),
        };
    }
    let outcome = migrate(old, new);
    if outcome == Migrated::Moved {
        for suffix in SQLITE_SIDECARS {
            discard(&sidecar(old, suffix));
            discard(&sidecar(new, suffix));
        }
    }
    outcome
}

/// Fold `db`'s write-ahead log into the database file, or say why that could not be done.
///
/// `wal_checkpoint` reports contention in its result row rather than as an error - `busy` is the
/// first column - so a plain `Ok` proves nothing and both have to be checked. The size of any
/// surviving `-wal` is checked afterwards as well: `TRUNCATE` leaves it at zero bytes, and a
/// non-empty one would mean transactions are still only in the log whatever the pragma said.
///
/// **The database is opened without `SQLITE_OPEN_CREATE`, and that is load-bearing.** The caller
/// checks `old.exists()` and then calls this, so a racing winner can rename the file away in
/// between; `Connection::open` would then *create* an empty database at the legacy path. The
/// checkpoint of that empty file succeeds, [`migrate`] is handed `(old = true, new = true)` and
/// reports [`Cause::BothExist`] - the memory tools disabled over a zero-byte file this process
/// invented, repeated at every start until a human deletes it. A missing file must be an error,
/// not a creation. Dropping `SQLITE_OPEN_URI` along with it is a small bonus: a legacy path is a
/// path, and nothing should read `?` in it as a parameter list.
fn checkpoint(db: &Path) -> Result<(), String> {
    let held = |e| format!("{}: {e}", db.display());
    let flags =
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = rusqlite::Connection::open_with_flags(db, flags)
        .map_err(|e| format!("cannot open it as a sqlite database: {}", held(e)))?;
    // Ride out a lock another instance is holding for a moment rather than refusing at once.
    conn.execute_batch("PRAGMA busy_timeout = 2000;")
        .map_err(|e| format!("cannot configure the database: {}", held(e)))?;
    let busy: i64 = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .map_err(|e| format!("cannot checkpoint its write-ahead log: {}", held(e)))?;
    drop(conn);
    if busy != 0 {
        return Err(IN_USE.to_string());
    }
    match std::fs::metadata(sidecar(db, "-wal")) {
        Ok(meta) if meta.len() > 0 => Err(format!(
            "its write-ahead log is still {} bytes after a checkpoint, so it holds transactions \
             the database file does not",
            meta.len()
        )),
        _ => Ok(()),
    }
}

/// What [`checkpoint`] reports when sqlite says the log could not be folded in because another
/// process holds the database.
///
/// A named constant so the test pinning that refusal can assert on the *reason* and not merely on
/// the outcome: on Windows a held database also fails the move through file sharing, which
/// produces the same `Cause::Failed` shape for an entirely different reason.
const IN_USE: &str = "its write-ahead log could not be checkpointed because the database is in \
                      use by another process";

/// Delete a file that is known to hold nothing of value, reporting a failure without acting on
/// it. A leftover sidecar is harmless beside the database it belongs to; the caller's reason for
/// removing it is in [`migrate_sqlite`].
fn discard(path: &Path) {
    if path.exists()
        && let Err(e) = std::fs::remove_file(path)
    {
        warn!("Could not remove the stale {}: {e}", path.display());
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
#[cfg(feature = "ctl-input")]
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
///
/// A failed move disables the store for the same reason - the data is somewhere the server no
/// longer reads - but the remedy is the opposite, so the two get different messages. The common
/// failure is a second instance of this server holding the legacy database open, which is the
/// *normal* state on an upgrade: the installed server is running when the new one first starts.
pub fn memory_db_decision(m: Migrated) -> MemoryDbDecision {
    match m {
        Migrated::Moved | Migrated::FreshStart => MemoryDbDecision::Use,
        Migrated::Ambiguous {
            old,
            new,
            cause: Cause::BothExist,
        } => MemoryDbDecision::Disabled(format!(
            "Memory tools disabled: a memory database exists both at {} and at {}. \
             Keep the one you want, delete or rename the other, then restart.",
            old.display(),
            new.display()
        )),
        // Deliberately says nothing about the new path: there is no file there to act on.
        Migrated::Ambiguous {
            old,
            cause: Cause::Failed(why),
            ..
        } => MemoryDbDecision::Disabled(format!(
            "Memory tools disabled: the memory database is still at {}, because moving it into \
             the state directory failed: {why}. The usual cause is another instance of this \
             server still running and holding the file open; stop it and restart.",
            old.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run file is `<state>/<kind>/<YYYY-MM-DD>/<machine>_<stamp>.<ext>`, dated directory made.
    ///
    /// Against a `TempDir` and a fixed instant, so the assertion is about the naming rule rather
    /// than about today's date, and so no test creates anything under the real state root.
    #[test]
    fn a_run_file_is_named_for_the_machine_and_the_time_under_a_dated_directory() {
        let base = tempfile::TempDir::new().expect("scratch dir");
        let when = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_789_000_000_123);
        let p = run_file_at(Some(base.path().to_path_buf()), SubDir::Logs, "log", when)
            .expect("run file");

        let dated = p.parent().expect("dated dir");
        assert_eq!(dated.file_name().expect("name"), "2026-09-10");
        assert!(dated.is_dir(), "the dated directory must be created");
        assert_eq!(
            dated.parent().expect("kind dir").file_name().expect("name"),
            "logs",
            "the kind names the directory"
        );
        assert!(!p.exists(), "the file itself is the caller's to create");

        let name = p.file_name().expect("name").to_string_lossy().into_owned();
        assert_eq!(
            name,
            format!(
                "{}_20260910-002640-123_{}.log",
                machine(),
                crate::core::instance::id()
            )
        );
    }

    /// The kind is the only thing that changes between the three writers, and the extension is
    /// the caller's. A regression that ignored either would put crash reports in with the logs.
    ///
    /// The shared stem is a real property and not an artefact of passing one `when`: production
    /// callers reach [`run_file`], which takes its instant from
    /// [`crate::core::instance::started`] - fixed once per process and pinned stable by that
    /// module's `the_start_instant_never_moves`. The three writers therefore see the same value
    /// this test hands them here.
    #[test]
    fn the_kind_and_the_extension_are_the_only_things_the_caller_chooses() {
        let base = tempfile::TempDir::new().expect("scratch dir");
        let when = crate::core::instance::started();
        let root = base.path().to_path_buf();
        let log = run_file_at(Some(root.clone()), SubDir::Logs, "log", when).expect("log");
        let panic = run_file_at(Some(root.clone()), SubDir::Panics, "log", when).expect("panic");
        let stats = run_file_at(Some(root), SubDir::Stats, "json", when).expect("stats");

        assert_eq!(log.file_name(), panic.file_name(), "same run, same stem");
        assert_ne!(
            log.parent(),
            panic.parent(),
            "different kind, different dir"
        );
        assert!(
            stats.extension().expect("ext") == "json" && log.extension().expect("ext") == "log"
        );
    }

    /// Two runs that start in the same millisecond on one host still get different files.
    ///
    /// This is the case the stamp alone cannot separate and the reason the instance is in the
    /// name: a client launching several servers at once starts them inside one millisecond
    /// routinely, and the counters writer truncates rather than appends, so a shared path means
    /// one run's report silently destroys the other's. Asserted through the parts rather than by
    /// spawning two processes - `id()` is per-process, so a second run cannot be had in-process -
    /// which is what `instance`'s own tests cover from the other side.
    #[test]
    fn the_stem_separates_two_runs_that_start_in_the_same_millisecond() {
        let base = tempfile::TempDir::new().expect("scratch dir");
        let when = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_789_000_000_123);
        let p = run_file_at(Some(base.path().to_path_buf()), SubDir::Stats, "json", when)
            .expect("run file");
        let name = p.file_name().expect("name").to_string_lossy().into_owned();

        let id = crate::core::instance::id();
        assert!(
            name.contains(id),
            "{name} must carry the instance, or two runs starting in one millisecond collide"
        );
        // Everything except the instance is shared by such a pair, so the instance is the only
        // thing keeping them apart - state that as an assertion rather than as a comment.
        assert_eq!(
            name.replace(id, "OTHER-RUN"),
            format!("{}_20260910-002640-123_OTHER-RUN.json", machine()),
            "only the instance may differ between two runs of the same millisecond"
        );
    }

    /// The host name is usable as a file name component, whatever the machine is called.
    #[test]
    fn the_machine_name_is_never_empty_and_never_carries_the_separator() {
        let m = machine();
        assert!(!m.is_empty());
        assert!(!m.contains('_'), "{m}");
        assert!(
            m.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.'),
            "{m}"
        );
    }

    /// A clock no calendar can describe still names a file, and neither helper panics doing it.
    ///
    /// Both are reachable from the panic hook, where a second panic aborts the process with no
    /// diagnostic at all, so this pins the fallible conversion that
    /// `OffsetDateTime::from(SystemTime)` would not have given us.
    #[test]
    fn an_impossible_clock_is_named_rather_than_panicked_on() {
        // ~8712 years past the epoch: outside `time`'s ±9999-year range, inside what a platform
        // `SystemTime` can hold. A platform that cannot hold it has nothing to prove here.
        let Some(far) = std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(1 << 38))
        else {
            return;
        };
        assert_eq!(utc_day(far), "unknown-date");
        assert_eq!(stamp(far), epoch_nanos(far).to_string());
        assert_ne!(
            stamp(far),
            stamp(far + std::time::Duration::from_millis(1)),
            "the fallback must still tell two instants apart"
        );
    }

    /// The stamp is UTC, fixed-width, and resolves to the millisecond - the resolution that
    /// keeps two servers started in the same second apart.
    #[test]
    fn the_stamp_resolves_to_the_millisecond() {
        let when = std::time::UNIX_EPOCH + std::time::Duration::from_millis(1_789_000_000_123);
        assert_eq!(stamp(when), "20260910-002640-123");
        assert_ne!(
            stamp(when),
            stamp(when + std::time::Duration::from_millis(1))
        );
    }

    /// The override wins over the home directory, and the root is created on demand.
    /// This is also the seam every other test uses to avoid touching the real home dir.
    #[test]
    fn override_redirects_root_and_creates_it() {
        let base = tempfile::TempDir::new().expect("scratch dir");
        let tmp = base.path().join("state");
        let root = resolve_root(Some(tmp.clone())).expect("root resolves");
        assert_eq!(root, tmp);
        assert!(tmp.is_dir(), "root must be created on demand");
    }

    /// Every subdirectory hangs off the root under its documented name.
    #[test]
    fn subdirs_hang_off_root() {
        let base = tempfile::TempDir::new().expect("scratch dir");
        let tmp = base.path().join("state");
        let logs = resolve_sub(Some(tmp.clone()), SubDir::Logs).expect("logs dir");
        assert_eq!(logs, tmp.join("logs"));
        assert!(logs.is_dir());
        assert_eq!(SubDir::Tmp.as_str(), "tmp");
    }

    /// A usable root does not imply a usable subdirectory.
    ///
    /// `main` validates the state root before logging is initialised and refuses to start
    /// without it, so "the root is unusable" is not a state the rest of the process can observe.
    /// A subdirectory under a perfectly good root is another matter - here `logs` already exists
    /// as a plain file - and that is the failure
    /// [`crate::core::logging::target_for`] degrades on. Pinned here so the degradation path
    /// over there is not mistaken for dead code and deleted.
    #[test]
    fn a_usable_root_can_still_have_an_unusable_subdir() {
        let base = tempfile::TempDir::new().expect("scratch dir");
        let root = base.path().join("state");
        resolve_root(Some(root.clone())).expect("the root itself is fine");
        std::fs::write(root.join("logs"), b"not a directory").expect("write");
        assert!(
            resolve_sub(Some(root), SubDir::Logs).is_err(),
            "a file where the subdirectory belongs must be an error, not a silent success"
        );
    }

    /// Scratch files land under the state root's `tmp/`, never in the OS temp directory.
    /// This pins the location the scratch call sites (captures, annotations, `run_command`
    /// stream logs, the temporary `.bat`, the blob spool) resolve through, and fails loudly
    /// if `SubDir::Tmp` is ever renamed out from under them.
    #[test]
    fn tmp_is_inside_the_state_root() {
        let base = tempfile::TempDir::new().expect("scratch dir");
        let root = base.path().join("state");
        let tmp = resolve_sub(Some(root.clone()), SubDir::Tmp).expect("tmp dir");
        assert_eq!(tmp, root.join("tmp"));
        assert!(tmp.starts_with(&root));
        assert!(tmp.is_dir(), "tmp must be created on demand");
    }

    /// A root that cannot be created names itself in the error. The reason alone - "Access is
    /// denied. (os error 5)" - leaves an operator with `FS_MCP_STATE_DIR` unset unable to tell
    /// which directory was refused, which is the one fact they need.
    #[test]
    fn uncreatable_root_names_the_directory() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let blocker = scratch.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").expect("write blocker");
        let root = blocker.join("state");

        let err = resolve_root(Some(root.clone())).expect_err("a file cannot host a directory");
        let msg = err.to_string();
        assert!(msg.contains(&root.display().to_string()), "{msg}");
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

    /// Two databases must disable the memory store rather than pick a file, and must name both.
    #[test]
    fn ambiguous_memory_db_disables_the_store() {
        let decision = memory_db_decision(Migrated::Ambiguous {
            old: PathBuf::from("/old/memory2.db"),
            new: PathBuf::from("/new/memory2.db"),
            cause: Cause::BothExist,
        });
        match decision {
            MemoryDbDecision::Disabled(msg) => {
                assert!(msg.contains("/old/memory2.db") && msg.contains("/new/memory2.db"));
            }
            other => panic!("expected Disabled, got {other:?}"),
        }
        assert!(matches!(
            memory_db_decision(Migrated::Moved),
            MemoryDbDecision::Use
        ));
        assert!(matches!(
            memory_db_decision(Migrated::FreshStart),
            MemoryDbDecision::Use
        ));
    }

    /// A failed move must describe what actually happened. The old message claimed a database
    /// existed at both paths and told the operator to delete one of them - but the cleanup in
    /// [`migrate`] removes anything at the new path, so that advice pointed at a file that is not
    /// there. This is the common case, not an exotic one: on an upgrade the installed server is
    /// usually still running and holding the legacy database open.
    #[test]
    fn failed_migration_names_the_old_path_and_nothing_to_delete() {
        let decision = memory_db_decision(Migrated::Ambiguous {
            old: PathBuf::from("/old/memory2.db"),
            new: PathBuf::from("/new/memory2.db"),
            cause: Cause::Failed(
                "The process cannot access the file because it is being used by another process. \
                 (os error 32)"
                    .to_string(),
            ),
        });
        let MemoryDbDecision::Disabled(msg) = decision else {
            panic!("a failed move must disable the store");
        };
        assert!(msg.contains("/old/memory2.db"), "{msg}");
        assert!(
            msg.contains("os error 32"),
            "the reason must survive: {msg}"
        );
        assert!(
            msg.contains("still running"),
            "the usual remedy must be named: {msg}"
        );
        assert!(
            !msg.contains("/new/memory2.db"),
            "nothing exists at the new path, so it must not be mentioned: {msg}"
        );
        assert!(
            !msg.contains("delete"),
            "there is no second file to delete: {msg}"
        );
    }

    /// The shape every refusal that is *not* "two files exist" must have: both paths carried, and
    /// a `Failed` cause whose reason is non-empty, since that reason is what the operator is told.
    fn assert_failed_migration(outcome: Migrated, old: &Path, new: &Path) {
        match outcome {
            Migrated::Ambiguous {
                old: o,
                new: n,
                cause: Cause::Failed(why),
            } => {
                assert_eq!(o, old);
                assert_eq!(n, new);
                assert!(!why.is_empty(), "a failure must say why");
            }
            other => panic!("expected Ambiguous/Failed, got {other:?}"),
        }
    }

    /// Old file present, new absent: the data moves and the old path is gone.
    #[test]
    fn migrate_moves_when_unambiguous() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let base = scratch.path().join("mig");
        let old = base.join("old/memory2.db");
        let new = base.join("new/memory2.db");
        std::fs::create_dir_all(old.parent().expect("parent")).expect("mkdir");
        std::fs::write(&old, b"payload").expect("write");

        assert_eq!(migrate(&old, &new), Migrated::Moved);
        assert!(!old.exists(), "old path must be gone after a move");
        assert_eq!(std::fs::read(&new).expect("read"), b"payload");
    }

    /// Both present: refuse to guess, touch nothing.
    #[test]
    fn migrate_refuses_when_both_exist() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let base = scratch.path().join("mig");
        let old = base.join("old/memory2.db");
        let new = base.join("new/memory2.db");
        for p in [&old, &new] {
            std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
            std::fs::write(p, b"payload").expect("write");
        }

        match migrate(&old, &new) {
            Migrated::Ambiguous {
                old: o,
                new: n,
                cause: Cause::BothExist,
            } => {
                assert_eq!(o, old);
                assert_eq!(n, new);
            }
            other => panic!("expected Ambiguous/BothExist, got {other:?}"),
        }
        assert!(old.exists() && new.exists(), "neither file may be touched");
    }

    /// Nothing to migrate, and nothing conjured into existence while finding that out.
    #[test]
    fn migrate_reports_fresh_start() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let base = scratch.path().join("mig");
        let old = base.join("old.db");
        let new = base.join("new.db");
        assert_eq!(migrate(&old, &new), Migrated::FreshStart);
        assert!(!old.exists() && !new.exists(), "nothing may be created");
        assert!(!base.exists(), "the parent may not be created either");
    }

    /// The losing side of a race between two servers must never remove the winner's file.
    ///
    /// Dozens of these servers start concurrently, so two of them observing `(old=true,
    /// new=false)` at the same instant is ordinary, not exotic. The hook runs exactly where the
    /// winner's `rename` lands: after this call has made its decision and before it acts on it.
    /// Before the fix, the loser's `copy` failed with NotFound and the cleanup then removed `new`
    /// *because it existed* - i.e. it deleted the database the winner had just migrated and was
    /// already writing to.
    #[test]
    fn migrate_loser_of_a_race_leaves_the_winners_file_alone() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let base = scratch.path().join("mig");
        let old = base.join("old/memory2.db");
        let new = base.join("new/memory2.db");
        std::fs::create_dir_all(old.parent().expect("parent")).expect("mkdir");
        std::fs::write(&old, b"the user's memories").expect("write");

        // The winner completes its move in the window this call has already passed.
        let outcome = migrate_with(
            &old,
            &new,
            Hooks {
                before_move: &|| {
                    std::fs::create_dir_all(new.parent().expect("parent")).expect("mkdir");
                    std::fs::rename(&old, &new).expect("the winner's move");
                },
                ..Hooks::NONE
            },
        );

        assert_eq!(outcome, Migrated::FreshStart, "the move is already done");
        assert_eq!(
            std::fs::read(&new).expect("the winner's file must survive"),
            b"the user's memories"
        );
    }

    /// The same race resolved one step later, which is the only way into the `Io` arm's
    /// `!old.exists()` guard - the branch that actually performs a delete.
    ///
    /// Here the loser gets as far as *creating* the destination before the winner's move lands on
    /// top of it. The loser then fails opening the source, which is gone, and must read that as
    /// "another instance finished the move" and leave the file alone. Removing it by existence
    /// alone - which the pre-fix code did - deletes the winner's database while the winner is
    /// already writing to it.
    ///
    /// Windows-only, and for the same reason as
    /// `migrate_removes_the_leftover_when_the_original_cannot_be_unlinked`: the copy fallback is
    /// only entered when `rename` fails, and on a single-volume machine the sole way to make it
    /// fail is a handle opened with `share_mode(FILE_SHARE_READ)`, which denies the DELETE access
    /// `rename` needs. Unix reaches this arm only across volumes, which no test here can set up,
    /// so there it stays verified by reading.
    #[test]
    #[cfg(windows)]
    fn migrate_loser_that_already_created_the_destination_leaves_it_alone() {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;

        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let base = scratch.path().join("mig");
        let old = base.join("old/memory2.db");
        let new = base.join("new/memory2.db");
        std::fs::create_dir_all(old.parent().expect("parent")).expect("mkdir");
        std::fs::create_dir_all(new.parent().expect("parent")).expect("mkdir");
        std::fs::write(&old, b"the user's memories").expect("write");

        // Holding `old` this way is what makes the loser's `rename` fail and so drives it into
        // the copy fallback. The winner cannot move the file until the handle goes, so the hook
        // releases it: that instant IS the winner completing its move.
        let handle = std::cell::RefCell::new(Some(
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(&old)
                .expect("hold the original open"),
        ));

        let outcome = migrate_with(
            &old,
            &new,
            Hooks {
                // The loser has created `new` and is about to read `old`. The winner's rename
                // replaces the loser's empty file and takes the source with it.
                after_create: &|| {
                    drop(handle.borrow_mut().take());
                    std::fs::rename(&old, &new).expect("the winner's move");
                },
                ..Hooks::NONE
            },
        );

        assert_eq!(outcome, Migrated::FreshStart, "the move is already done");
        assert!(!old.exists(), "the winner took the original with it");
        assert_eq!(
            std::fs::read(&new).expect("the winner's file must survive"),
            b"the user's memories",
            "the loser must not delete what the winner just migrated"
        );
    }

    /// The other half of the C1 fix: the copy fallback can never write into a file it did not
    /// create. `fs::copy`, which this replaced, would have truncated the file below and then -
    /// on the failure that followed - deleted it.
    #[test]
    fn a_copy_never_targets_an_existing_file() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let old = scratch.path().join("old.db");
        let new = scratch.path().join("new.db");
        std::fs::write(&old, b"ours").expect("write");
        std::fs::write(&new, b"another instance's data").expect("write");

        match copy_into_a_new_file(&old, &new, &|| {}) {
            Err(CopyFailed::Occupied) => {}
            Err(CopyFailed::Io(e)) => panic!("expected Occupied, got {e}"),
            Ok(()) => panic!("a copy must refuse an existing destination"),
        }
        assert_eq!(
            std::fs::read(&new).expect("read"),
            b"another instance's data",
            "the existing file must be untouched"
        );
        assert!(old.exists(), "and the source must still be there");
    }

    /// `FS_MCP_STATE_DIR` pointed at the legacy directory makes the two paths the same file.
    /// Read as `(true, true)` that is `BothExist`, whose message asks the operator to delete one
    /// of two identical paths - an instruction nobody can carry out. There is one file and it is
    /// already where it belongs.
    #[test]
    fn migrate_reports_fresh_start_when_the_paths_are_the_same() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let path = scratch.path().join("memory2.db");
        std::fs::write(&path, b"payload").expect("write");

        assert_eq!(migrate(&path, &path), Migrated::FreshStart);
        assert_eq!(std::fs::read(&path).expect("read"), b"payload");
    }

    /// Write a WAL-mode database at `path` holding one row, and leave it in the state a killed
    /// process leaves behind: the row committed into the `-wal`, nothing checkpointed into the
    /// database file. That is the NORMAL state of `memory2.db`, because MCP hosts terminate
    /// stdio servers without ceremony.
    ///
    /// Produced by copying the live db/`-wal` pair out from under an open connection, which is
    /// what a kill does; closing the connection first would checkpoint and prove nothing.
    fn write_db_with_an_uncheckpointed_wal(path: &Path, note: &str) {
        let live = path.with_extension("live");
        let conn = rusqlite::Connection::open(&live).expect("open");
        conn.execute_batch("PRAGMA journal_mode=WAL;").expect("wal");
        conn.execute_batch("CREATE TABLE note(t TEXT);")
            .expect("schema");
        conn.execute("INSERT INTO note(t) VALUES (?1)", [note])
            .expect("insert");
        // Snapshot the pair while the connection is open, i.e. before any checkpoint.
        std::fs::copy(&live, path).expect("copy db");
        let wal = sidecar(&live, "-wal");
        assert!(wal.is_file(), "the row must still be in the -wal");
        std::fs::copy(&wal, sidecar(path, "-wal")).expect("copy wal");
        drop(conn);
        // The snapshot's row must live ONLY in its `-wal`, or the tests below prove nothing.
        // Checked on a copy of the database file alone: opening the snapshot itself would
        // recover its log and so destroy the very state being set up.
        let probe = path.with_extension("probe");
        std::fs::copy(path, &probe).expect("copy the database file alone");
        assert!(
            read_note(&probe).is_none(),
            "the row must not be in the database file yet"
        );
    }

    /// The single row in `note`, or `None` if the table or the row is not there.
    fn read_note(path: &Path) -> Option<String> {
        let conn = rusqlite::Connection::open(path).ok()?;
        conn.query_row("SELECT t FROM note", [], |r| r.get::<_, String>(0))
            .ok()
    }

    /// A database is never separated from its `-wal`.
    ///
    /// Moving `memory2.db` alone silently drops every transaction that was committed but not yet
    /// checkpointed - the user finds their memory store present and its newest entries gone.
    #[test]
    fn migrate_sqlite_keeps_uncheckpointed_transactions() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let old = scratch.path().join("old/memory2.db");
        let new = scratch.path().join("new/memory2.db");
        std::fs::create_dir_all(old.parent().expect("parent")).expect("mkdir");
        write_db_with_an_uncheckpointed_wal(&old, "the last thing I was asked to remember");

        assert_eq!(migrate_sqlite(&old, &new), Migrated::Moved);
        assert_eq!(
            read_note(&new).as_deref(),
            Some("the last thing I was asked to remember"),
            "the committed transaction must survive the move"
        );
        assert!(!old.exists(), "the original must be gone");
        for suffix in SQLITE_SIDECARS {
            assert!(
                !sidecar(&old, suffix).exists(),
                "no {suffix} may be left behind at the old location"
            );
        }
    }

    /// A `-wal` stranded at the destination by an earlier crash must never be applied to the
    /// database that lands there: sqlite would replay frames from a different database into it.
    #[test]
    fn migrate_sqlite_discards_a_stale_wal_at_the_destination() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let old = scratch.path().join("old/memory2.db");
        let new = scratch.path().join("new/memory2.db");
        std::fs::create_dir_all(old.parent().expect("parent")).expect("mkdir");
        std::fs::create_dir_all(new.parent().expect("parent")).expect("mkdir");
        write_db_with_an_uncheckpointed_wal(&old, "ours");
        // Somebody else's WAL, left next to a database that no longer exists.
        let stray = scratch.path().join("stray.db");
        write_db_with_an_uncheckpointed_wal(&stray, "a different database");
        std::fs::rename(sidecar(&stray, "-wal"), sidecar(&new, "-wal")).expect("strand it");

        assert_eq!(migrate_sqlite(&old, &new), Migrated::Moved);
        assert!(
            !sidecar(&new, "-wal").exists(),
            "the stale sidecar must be gone before anything opens the database"
        );
        assert_eq!(read_note(&new).as_deref(), Some("ours"));
    }

    /// A database another instance is actively using is not moved at all: the operator is told
    /// the file is still at the old path and that something else is holding it. A partial move -
    /// the database here, its `-wal` there - is the one outcome that must be impossible.
    #[test]
    fn migrate_sqlite_refuses_a_database_in_use() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let old = scratch.path().join("old/memory2.db");
        let new = scratch.path().join("new/memory2.db");
        std::fs::create_dir_all(old.parent().expect("parent")).expect("mkdir");
        write_db_with_an_uncheckpointed_wal(&old, "in use");

        // A reader mid-transaction is what "another instance is running" looks like to sqlite:
        // the checkpoint cannot truncate the WAL while that snapshot is live.
        let reader = rusqlite::Connection::open(&old).expect("open");
        reader
            .execute_batch("BEGIN; SELECT * FROM note;")
            .expect("read txn");

        let outcome = migrate_sqlite(&old, &new);
        assert_failed_migration(outcome.clone(), &old, &new);
        // Pinned on the REASON, not just the shape. On Windows a held database also fails the
        // move through file sharing - `remove_file` cannot unlink an open file - which produces
        // the same `Cause::Failed` for an entirely different reason and would let this test pass
        // while the checkpoint refusal it names had rotted away.
        match outcome {
            Migrated::Ambiguous {
                cause: Cause::Failed(why),
                ..
            } => assert_eq!(why, IN_USE, "the checkpoint must be what refused the move"),
            other => panic!("expected Ambiguous/Failed, got {other:?}"),
        }
        assert!(old.exists(), "the database must stay where it is");
        assert!(!new.exists(), "and nothing may appear at the destination");
        assert!(
            sidecar(&old, "-wal").exists(),
            "least of all a database separated from its -wal"
        );
        drop(reader);
        assert_eq!(read_note(&old).as_deref(), Some("in use"));
    }

    /// Checkpointing a path that is not there must not bring it into being.
    ///
    /// `Connection::open` carries `SQLITE_OPEN_CREATE`. Between `migrate_sqlite`'s `old.exists()`
    /// check and this call a racing winner can rename the file away, and the loser would then
    /// create an empty database at the legacy path: the checkpoint of it succeeds, `migrate` sees
    /// a file at both paths and reports `BothExist`, and the memory tools stay disabled over a
    /// zero-byte file this process invented - at every start, until a human deletes it.
    #[test]
    fn checkpointing_a_missing_database_does_not_create_one() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let absent = scratch.path().join("memory2.db");

        checkpoint(&absent).expect_err("a missing database must be an error");
        assert!(!absent.exists(), "and must not have been created");
        for suffix in SQLITE_SIDECARS {
            assert!(!sidecar(&absent, suffix).exists(), "nor any {suffix}");
        }
    }

    /// The same thing through the public entry point: the loser of a race whose winner renames the
    /// database away in the window before the checkpoint must report "already migrated", not
    /// conjure a conflict out of a file it created itself.
    #[test]
    fn migrate_sqlite_loser_does_not_invent_a_conflict() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let old = scratch.path().join("old/memory2.db");
        let new = scratch.path().join("new/memory2.db");
        std::fs::create_dir_all(old.parent().expect("parent")).expect("mkdir");
        std::fs::create_dir_all(new.parent().expect("parent")).expect("mkdir");
        write_db_with_an_uncheckpointed_wal(&old, "ours");
        // The winner completes the whole move first; this process then runs with a stale view.
        for suffix in SQLITE_SIDECARS {
            let side = sidecar(&old, suffix);
            if side.exists() {
                std::fs::rename(&side, sidecar(&new, suffix)).expect("move the sidecar too");
            }
        }
        std::fs::rename(&old, &new).expect("the winner's move");

        assert_eq!(migrate_sqlite(&old, &new), Migrated::FreshStart);
        assert!(!old.exists(), "nothing may be created at the legacy path");
        assert_eq!(read_note(&new).as_deref(), Some("ours"));
    }

    /// A directory is refused outright: `fs::copy` cannot copy one and `fs::remove_file` cannot
    /// remove one, so the cross-volume path would corrupt what the same-volume path moved fine.
    #[test]
    fn migrate_refuses_a_directory() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let base = scratch.path().join("mig");
        let old = base.join("old_dir");
        let new = base.join("new_dir");
        std::fs::create_dir_all(old.join("inner")).expect("mkdir");

        assert_failed_migration(migrate(&old, &new), &old, &new);
        assert!(old.join("inner").is_dir(), "the directory must be intact");
        assert!(!new.exists(), "nothing may be created at the new path");
    }

    /// When the new parent cannot be created the original must survive untouched. This is the
    /// portable stand-in for the failure handling around the cross-volume copy: a plain file sits
    /// where `new`'s parent directory would go, so `create_dir_all` cannot succeed.
    #[test]
    fn migrate_keeps_the_original_when_the_new_parent_cannot_be_created() {
        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let base = scratch.path().join("mig");
        let old = base.join("old/memory2.db");
        let blocker = base.join("blocker");
        let new = blocker.join("memory2.db");
        std::fs::create_dir_all(old.parent().expect("parent")).expect("mkdir");
        std::fs::write(&old, b"payload").expect("write");
        std::fs::write(&blocker, b"not a directory").expect("write blocker");

        assert_failed_migration(migrate(&old, &new), &old, &new);
        assert!(old.exists(), "the original must survive a failed migration");
        assert_eq!(std::fs::read(&old).expect("read"), b"payload");
        assert!(!new.exists(), "no partial file may be left at the new path");
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

        let scratch = tempfile::TempDir::new().expect("scratch dir");
        let base = scratch.path().join("mig");
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

        assert_failed_migration(outcome, &old, &new);
        assert!(old.exists(), "the original must survive");
        assert_eq!(std::fs::read(&old).expect("read"), b"payload");
        assert!(
            !new.exists(),
            "the duplicate left by the successful copy must be cleaned up"
        );
    }
}
