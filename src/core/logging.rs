//! What this process logs, and where it writes it.
//!
//! One file per process, `<state>/logs/<YYYY-MM-DD>/fsmcp-<pid>-<instance>.log`, on by default in
//! every transport mode. Dozens of these servers run at once on one machine, so there is no
//! shared log file — and therefore no rotation to arbitrate: a new process is a new file, a new
//! day is a new directory. `tracing-appender` exists to rotate a shared file and is deliberately
//! not used.
//!
//! A process that outlives midnight keeps the file it opened at startup. That is the cost of
//! having exactly one writer path: reopening would mean a second one plus the rotation mechanism
//! this design exists to avoid, and the file is still found by the day the process started. The
//! retention sweep must therefore never delete a file whose process is still alive, however old
//! the directory holding it looks.
//!
//! **stdio never writes to stderr.** Any stderr output during the handshake closes the connection
//! in MCP clients, so under stdio the file is the only sink — and if it cannot be opened, this
//! process runs without logs rather than breaking the transport. Only stream transport, whose
//! stderr nobody is parsing, gets a console sink. That rule lives in [`sinks`], one pure function
//! over a [`Plan`], so it can be asserted directly instead of being inferred from a variant name.
//!
//! The decision ([`target_for`]) is separate from carrying it out ([`init_logging`]): a process
//! can install a global subscriber only once, so everything worth testing takes its inputs as
//! arguments — including the log directory, which tests supply from a `TempDir`.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::env_spec;

/// Transport mode for MCP server
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// stdio transport (default) - for local MCP clients
    Stdio,
    /// Streamable HTTP transport - for remote/web access
    Stream,
}

/// What logging this process will do.
///
/// Decided from the transport, `--log` and `FS_MCP_LOG`, separately from performing it, and
/// returned by [`init_logging`] so the caller can report where the log went — `main` logs it as
/// the first line of the file, and wave 3's `health` section will name the same path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Write to this file only. Every stdio run lands here.
    File(PathBuf),
    /// Write to this file and to stderr. Stream transport only.
    FileAndStderr(PathBuf),
    /// Write to stderr only: stream transport whose file could not be opened at all. Never
    /// reachable under stdio, where stderr would close the connection.
    Stderr,
    /// No subscriber at all: `FS_MCP_LOG=off`, or stdio with no usable file. When it is the
    /// second, [`degraded_reason`] says which failure caused it.
    Disabled,
}

impl std::fmt::Display for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Plan::File(p) => write!(f, "file {}", p.display()),
            Plan::FileAndStderr(p) => write!(f, "file {} and stderr", p.display()),
            Plan::Stderr => write!(f, "stderr only"),
            Plan::Disabled => write!(f, "disabled"),
        }
    }
}

/// The sinks a plan asks for: the file to append to, if any, and whether stderr is written.
///
/// The handshake rule is expressed here, in one pure function, rather than spread over the arms
/// of [`install`]: a plan reachable under stdio must never come back with `true`, and
/// `stdio_never_writes_to_stderr` asserts exactly that. A rule that only existed inside the
/// installer could not be checked at all — a process installs a subscriber once, so no test can
/// run the installer twice — which is how a test can end up pinning a variant's *name* while the
/// behaviour it is named for goes unguarded.
fn sinks(plan: &Plan) -> (Option<&Path>, bool) {
    match plan {
        Plan::File(p) => (Some(p), false),
        Plan::FileAndStderr(p) => (Some(p), true),
        Plan::Stderr => (None, true),
        Plan::Disabled => (None, false),
    }
}

/// Decide the plan, then carry it out, returning what was actually done.
///
/// Infallible on purpose: logging must never prevent the transport from starting, so there is no
/// error for the caller to propagate. Every degradation — an unopenable file, an unusable state
/// directory, a subscriber someone else already installed — is reported through the returned
/// [`Plan`] and [`degraded_reason`] instead. Called once, from `main`.
pub fn init_logging(mode: TransportMode, log_file: Option<String>) -> Plan {
    let level = level();
    let plan = install(target_for(mode, log_file, level.as_deref()), level.as_deref());
    // After the subscriber exists, so these reach the file in every mode that has one.
    if let Some(complaint) = level.as_deref().and_then(level_complaint) {
        tracing::warn!("{complaint}");
    }
    if let Some(reason) = degraded_reason() {
        tracing::warn!("logging degraded: {reason}");
    }
    plan
}

/// Decide the plan against the real state directory.
///
/// Resolves `<state>/logs` (creating it) and hands the rest to [`target_for_in`]; an unusable
/// state directory arrives there as `None`. The directory is resolved even when `--log` names a
/// file elsewhere, which costs one empty directory and keeps this wrapper to one behaviour.
pub fn target_for(mode: TransportMode, log_file: Option<String>, level: Option<&str>) -> Plan {
    let root = crate::core::paths::sub_dir(crate::core::paths::SubDir::Logs);
    target_for_in(root.as_deref().ok(), mode, log_file, level)
}

/// Decide the plan. `root` is `<state>/logs`, or `None` when the state directory is unusable;
/// `level` is the raw `FS_MCP_LOG` value (already blank-filtered).
///
/// Takes the log directory as an argument, like [`crate::core::paths`]'s own resolvers, so the
/// decision can be tested against a `TempDir` instead of creating directories under the real
/// state root on every `cargo test`.
fn target_for_in(
    root: Option<&Path>,
    mode: TransportMode,
    log_file: Option<String>,
    level: Option<&str>,
) -> Plan {
    if level.is_some_and(|v| v.eq_ignore_ascii_case("off")) {
        return Plan::Disabled;
    }
    // An explicit path is the operator's choice and overrides the per-process default; the
    // per-process file is only the default location, not a rule about where logs may go.
    let file = match log_file {
        Some(p) => PathBuf::from(p),
        None => match root.map(|r| log_path_in(r, &today())) {
            Some(Ok(p)) => p,
            // The state directory is unusable, or the dated directory under it cannot be made.
            // stdio still must not touch stderr, so it runs without logs rather than breaking
            // the handshake; stream can still say so.
            Some(Err(_)) | None => {
                return match mode {
                    TransportMode::Stdio => Plan::Disabled,
                    TransportMode::Stream => Plan::Stderr,
                };
            }
        },
    };
    match mode {
        TransportMode::Stdio => Plan::File(file),
        TransportMode::Stream => Plan::FileAndStderr(file),
    }
}

/// Install the global subscriber for `plan`, returning the plan that is actually in force.
///
/// A file that cannot be opened degrades rather than fails: the process keeps the sinks it could
/// build, which under stdio is none at all. A subscriber already installed by someone else leaves
/// this process with nothing of its own, which is [`Plan::Disabled`] too — the returned plan
/// describes what this call did, not what it wanted.
fn install(plan: Plan, level: Option<&str>) -> Plan {
    let (path, to_stderr) = sinks(&plan);
    let path = path.map(Path::to_path_buf);
    let file = match &path {
        Some(p) => match open(p) {
            Ok(f) => Some(f),
            Err(e) => {
                note_degraded(format!("cannot open the log file {}: {e}", p.display()));
                None
            }
        },
        None => None,
    };
    let to_file = file.is_some();
    if !to_file && !to_stderr {
        return Plan::Disabled;
    }
    let installed = tracing_subscriber::registry()
        .with(filter(level))
        .with(to_stderr.then(|| fmt::layer().with_writer(std::io::stderr)))
        .with(file.map(|f| fmt::layer().with_writer(f).with_ansi(false)))
        .try_init()
        .is_ok();
    if !installed {
        note_degraded("a global tracing subscriber was already installed".to_string());
        return Plan::Disabled;
    }
    match (path, to_file, to_stderr) {
        (Some(p), true, true) => Plan::FileAndStderr(p),
        (Some(p), true, false) => Plan::File(p),
        (_, false, true) => Plan::Stderr,
        _ => Plan::Disabled,
    }
}

/// Why logging is weaker than it was asked to be, if it is.
///
/// Under stdio a [`Plan::Disabled`] caused by an unopenable file is otherwise indistinguishable
/// from `FS_MCP_LOG=off`, and the `io::Error` explaining it — a read-only state directory, a full
/// disk, a `--log` pointing at a directory — has nowhere to go: stderr is forbidden and the file
/// is the thing that failed. It is kept here instead of being written to a second, bespoke
/// channel, because wave 3's `health` section already reports where this process's log went and
/// is the one place that should answer this question.
///
/// Set at most once: the first failure is the one that shaped the plan.
pub fn degraded_reason() -> Option<&'static str> {
    DEGRADED.get().map(String::as_str)
}

/// Record why logging degraded. See [`degraded_reason`].
fn note_degraded(reason: String) {
    // A later failure cannot change the plan already chosen, so the first reason is the answer;
    // `set` returning the value back on a second call is exactly the behaviour wanted here.
    if DEGRADED.set(reason).is_err() {
        // Nothing to do and nowhere to say it: the channel this would use is the one that failed.
    }
}

static DEGRADED: OnceLock<String> = OnceLock::new();

/// The level applied when neither `FS_MCP_LOG` nor `RUST_LOG` says otherwise.
///
/// `info`, not `warn`: every event this module exists to make visible — "Migrated X -> Y",
/// "memory tools disabled", "removed N stale scratch files" — is logged at `info`, so a
/// warn-only default would hide exactly the record an operator goes looking for when something
/// seems wrong. [`crate::env_spec`] advertises this string as the key's default and
/// `logging_keys_are_registered_and_agree_with_the_code` asserts the two agree.
pub const LEVEL_DEFAULT: &str = "info";

/// How many days of dated log directories the housekeeping sweep keeps.
///
/// Two weeks is long enough to cover "it started misbehaving some time last week" and short
/// enough that the directory stays browsable. **Zero switches the sweep off**, following
/// [`crate::core::paths::TMP_KEEP_HOURS_DEFAULT`]'s convention: a retention knob whose zero
/// destroys data is a foot-gun, and with dozens of processes it would fire on every start.
pub const KEEP_DAYS_DEFAULT: u64 = 14;

/// The longest log retention accepted, ten years.
///
/// Clamped for the same reason as [`crate::core::paths::TMP_KEEP_HOURS_MAX`]: the sweep turns
/// this into a `Duration`, and an absurd value from the environment must not overflow that —
/// in debug an overflow panics, and a panic in housekeeping would keep the transport from ever
/// starting. [`MAX_MB_DEFAULT`] needs no such bound: it is only ever compared against a sum of
/// file sizes, where an absurd budget simply means "never sweep".
pub const KEEP_DAYS_MAX: u64 = 365 * 10;

/// Total size budget for `<state>/logs`, in MiB, beyond which the sweep deletes oldest first.
///
/// A second bound because age alone does not cap a directory: one chatty process at `trace` can
/// fill a disk well inside [`KEEP_DAYS_DEFAULT`]. **Zero switches the budget off**, as above.
pub const MAX_MB_DEFAULT: u64 = 512;

/// The configured `FS_MCP_LOG` value, or `None` when it is unset or blank.
///
/// The one reader of the key, so no second caller can disagree about what blank means. It
/// returns an `Option` rather than falling back to [`LEVEL_DEFAULT`] because unset is not the
/// same as `info` here: [`filter`] consults `RUST_LOG` in between, and a reader that defaulted
/// eagerly would quietly take that step away.
pub fn level() -> Option<String> {
    env_spec::get("FS_MCP_LOG")
}

/// How many days of dated log directories to keep; `0` means never sweep by age.
///
/// Lives beside the module that owns the logs, the way [`crate::core::paths::tmp_keep_hours`]
/// lives beside the directory it governs, and is read by the housekeeping sweep.
///
/// The sweep that consumes it is wave 2's next task; until it lands, the key is registered and
/// documented but nothing in the binary calls this, hence the marker. Remove it with the sweep.
#[allow(dead_code)]
pub fn keep_days() -> u64 {
    let days = whole_number("FS_MCP_LOG_KEEP_DAYS", KEEP_DAYS_DEFAULT);
    if days > KEEP_DAYS_MAX {
        tracing::warn!(
            "FS_MCP_LOG_KEEP_DAYS={days} exceeds the {KEEP_DAYS_MAX}-day maximum; using that instead"
        );
        return KEEP_DAYS_MAX;
    }
    days
}

/// The total MiB budget for `<state>/logs`; `0` means no budget. See [`MAX_MB_DEFAULT`].
///
/// Unused until the sweep lands, like [`keep_days`].
#[allow(dead_code)]
pub fn max_mb() -> u64 {
    whole_number("FS_MCP_LOG_MAX_MB", MAX_MB_DEFAULT)
}

/// Read a numeric `FS_MCP_*` key, complaining about a malformed value and carrying on.
///
/// Refusing to start over a mistyped retention interval would be a worse outcome than applying
/// the standard one — and the complaint reaches the log file, which by this point exists.
fn whole_number(key: &str, default: u64) -> u64 {
    match env_spec::get(key) {
        None => default,
        Some(raw) => raw.parse().unwrap_or_else(|_| {
            tracing::warn!("{key} is not a whole number ({raw}); using {default}");
            default
        }),
    }
}

/// What is wrong with an `FS_MCP_LOG` value, if anything, phrased for the operator who set it.
///
/// Two ways to get nothing when you wanted `debug`, and neither announces itself:
///
/// - the value does not parse at all, so [`filter`] silently falls through to `RUST_LOG`/`info`;
/// - the value parses, but as a *target* rather than a level. `EnvFilter` reads a bare word it
///   does not recognise as "enable everything from the target named `bogus`", which switches the
///   rest of the log off entirely — verified live: `FS_MCP_LOG=bogus-level` produced an empty
///   log file and no complaint. A word carrying no `=` or `,` is meant as a level, so one that
///   is not a level is a typo, not a target selector.
///
/// Pure, so both traps are covered by tests; installing the subscriber they would warn through
/// is not testable in-process.
fn level_complaint(raw: &str) -> Option<String> {
    if EnvFilter::try_new(raw).is_err() {
        return Some(format!(
            "FS_MCP_LOG={raw} is not a filter this build understands; ignoring it"
        ));
    }
    // `LevelFilter`, not `Level`: it is the one that also accepts `off`, which is a value this
    // module answers earlier and must never report as a typo.
    let looks_like_a_level = !raw.contains('=') && !raw.contains(',');
    if looks_like_a_level && raw.parse::<tracing::level_filters::LevelFilter>().is_err() {
        return Some(format!(
            "FS_MCP_LOG={raw} is not a level; it reads as a target filter, which would switch \
             the rest of the log off, so it is ignored. Use trace, debug, info, warn, error or off"
        ));
    }
    None
}

/// The level filter: `FS_MCP_LOG` first, then `RUST_LOG`, then [`LEVEL_DEFAULT`].
///
/// A value [`level_complaint`] objects to is *not* used — it falls through to the next source,
/// rather than stopping the server. That is not only politeness: honouring `FS_MCP_LOG=bogus`
/// would build a filter that enables nothing but the target `bogus`, which would also swallow
/// [`init_logging`]'s warning about it. Verified live: before this fallback the run produced a
/// zero-byte log file and said nothing anywhere. The complaint now arrives at `info`.
fn filter(level: Option<&str>) -> EnvFilter {
    if let Some(raw) = level
        && level_complaint(raw).is_none()
        && let Ok(f) = EnvFilter::try_new(raw)
    {
        return f;
    }
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(LEVEL_DEFAULT))
}

/// Open a log file for appending, creating its parent directory if the caller named one that
/// does not exist yet (`--log some/where/x.log`).
fn open(path: &Path) -> std::io::Result<std::fs::File> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// `<root>/<YYYY-MM-DD>/fsmcp-<pid>-<instance>.log`, directory created.
///
/// The dated directory is made here rather than at open time so that a root which cannot hold it
/// is discovered while the plan is still being decided, instead of after the plan has promised a
/// file it cannot place.
fn log_path_in(root: &Path, day: &str) -> std::io::Result<PathBuf> {
    let dir = root.join(day);
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(format!(
        "fsmcp-{}-{}.log",
        crate::core::instance::pid(),
        crate::core::instance::id()
    )))
}

/// Today in UTC as `YYYY-MM-DD`.
///
/// UTC, matching wave 1's rule that stored time is UTC: a directory named in local time would
/// jump around under a machine that travels or changes offset twice a year. Formatted by hand
/// rather than through `time`'s format descriptions, which would need a feature this crate does
/// not enable for three integers.
fn today() -> String {
    let d = time::OffsetDateTime::now_utc().date();
    format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A log directory of our own, so no test resolves - or creates - anything under the real
    /// state root. The same seam `core::paths` gives its own tests.
    fn scratch() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("tempdir")
    }

    /// The name carries both pid and instance id, and lives under a dated directory, so two
    /// concurrent servers — or one pid reused tomorrow — never share a file.
    #[test]
    fn file_name_is_unique_per_process_and_dated() {
        let dir = scratch();
        let p = log_path_in(dir.path(), "2026-09-17").expect("path");
        let parent = p.parent().expect("parent");
        assert_eq!(parent.file_name().expect("name"), "2026-09-17");
        let name = p.file_name().expect("name").to_string_lossy().into_owned();
        assert!(name.starts_with("fsmcp-"), "{name}");
        assert!(
            name.contains(&crate::core::instance::pid().to_string()),
            "{name}"
        );
        assert!(name.contains(crate::core::instance::id()), "{name}");
        assert!(name.ends_with(".log"), "{name}");
    }

    /// `FS_MCP_LOG=off` means no subscriber and no file — the only way to opt out.
    #[test]
    fn off_disables_everything() {
        let dir = scratch();
        for mode in [TransportMode::Stdio, TransportMode::Stream] {
            let plan = target_for_in(Some(dir.path()), mode, None, Some("off"));
            assert!(matches!(plan, Plan::Disabled), "{plan:?}");
            assert_eq!(sinks(&plan), (None, false));
        }
        // Not even an explicit `--log` reopens the door.
        let plan = target_for_in(
            Some(dir.path()),
            TransportMode::Stream,
            Some("x.log".into()),
            Some("OFF"),
        );
        assert!(matches!(plan, Plan::Disabled), "{plan:?}");
    }

    /// stdio never gets a stderr sink, whatever else is configured — stderr during the handshake
    /// closes the connection in MCP clients.
    ///
    /// Asserted through [`sinks`], the function the installer actually consumes, so that adding a
    /// stderr layer to any stdio path fails this test. Pinning the variant name alone would not:
    /// `Plan::File` would still be `Plan::File` with a stderr layer bolted onto it.
    #[test]
    fn stdio_never_writes_to_stderr() {
        let dir = scratch();
        let stdio = [
            target_for_in(Some(dir.path()), TransportMode::Stdio, None, None),
            target_for_in(
                Some(dir.path()),
                TransportMode::Stdio,
                Some("x.log".into()),
                None,
            ),
            target_for_in(Some(dir.path()), TransportMode::Stdio, None, Some("off")),
            // The degraded branch: no usable state directory at all.
            target_for_in(None, TransportMode::Stdio, None, None),
        ];
        for plan in &stdio {
            assert!(!sinks(plan).1, "stdio must never write to stderr: {plan:?}");
        }
        assert!(matches!(stdio[0], Plan::File(_)), "{:?}", stdio[0]);
        assert!(matches!(stdio[1], Plan::File(_)), "{:?}", stdio[1]);

        // Stream is the only mode that may, and does.
        let stream = target_for_in(Some(dir.path()), TransportMode::Stream, None, None);
        assert!(matches!(stream, Plan::FileAndStderr(_)), "{stream:?}");
        assert!(sinks(&stream).1);
    }

    /// With no usable state directory, stdio goes quiet and stream keeps the one channel it has.
    /// Neither refuses to start, which is the whole point of the degradation.
    #[test]
    fn an_unusable_state_directory_degrades_per_transport() {
        assert_eq!(
            target_for_in(None, TransportMode::Stdio, None, None),
            Plan::Disabled
        );
        assert_eq!(
            target_for_in(None, TransportMode::Stream, None, None),
            Plan::Stderr
        );
        // An explicit `--log` needs no state directory, so it survives one being unusable.
        assert!(matches!(
            target_for_in(None, TransportMode::Stdio, Some("x.log".into()), None),
            Plan::File(_)
        ));
    }

    /// An explicit `--log` path wins over the per-process file, because an operator who names a
    /// file is asking for that file.
    #[test]
    fn explicit_path_overrides_the_default() {
        let dir = scratch();
        let named = dir.path().join("explicit.log");
        match target_for_in(
            Some(dir.path()),
            TransportMode::Stdio,
            Some(named.to_string_lossy().into_owned()),
            None,
        ) {
            // `file_name`, not `Path::ends_with`: the latter compares whole components and would
            // read differently for a path spelled with the other platform's separator.
            Plan::File(p) => assert_eq!(p.file_name().expect("name"), "explicit.log"),
            other => panic!("expected File, got {other:?}"),
        }
    }

    /// Every sink combination is reachable and reads back as itself, so [`install`] cannot
    /// misinterpret a plan it was handed.
    #[test]
    fn sinks_describe_every_plan() {
        let p = PathBuf::from("x.log");
        assert_eq!(sinks(&Plan::File(p.clone())), (Some(p.as_path()), false));
        assert_eq!(
            sinks(&Plan::FileAndStderr(p.clone())),
            (Some(p.as_path()), true)
        );
        assert_eq!(sinks(&Plan::Stderr), (None, true));
        assert_eq!(sinks(&Plan::Disabled), (None, false));
    }

    /// The reason a degraded run gives is kept and readable; under stdio it is the only record
    /// that exists, since the channel that would have carried it is the one that failed.
    #[test]
    fn the_degradation_reason_is_kept() {
        note_degraded("first".to_string());
        note_degraded("second".to_string());
        assert_eq!(
            degraded_reason(),
            Some("first"),
            "the first failure is the one that shaped the plan"
        );
    }

    /// A typo'd level must be called out, because both of its failure modes are silent: one
    /// falls back to `info`, the other switches logging off by reading as a target name.
    #[test]
    fn a_mistyped_level_is_complained_about() {
        // Verified live before this test existed: this value produced an empty log file.
        let bogus = level_complaint("bogus-level").expect("a bare non-level must complain");
        assert!(bogus.contains("bogus-level"), "{bogus}");
        assert!(bogus.contains("target filter"), "{bogus}");
        assert!(
            level_complaint("hyper=notalevel").is_some(),
            "an unparseable filter must complain"
        );

        // Real values, left alone: the plain levels, and the env-filter syntax an operator who
        // knows what they are doing is entitled to use.
        for ok in ["trace", "DEBUG", "info", "warn", "error", "info,hyper=warn", "fsmcp=debug"] {
            assert_eq!(level_complaint(ok), None, "{ok}");
        }
        // `off` never reaches here - it is answered by `target_for_in` - but it is a level, so it
        // must not be reported as a typo either.
        assert_eq!(level_complaint("off"), None);
    }

    /// A rejected value must not reach the filter, or the warning about it would be filtered out
    /// by the very directive it is complaining about - which is what happened before this test.
    #[test]
    fn a_rejected_level_is_not_used_as_a_filter() {
        let built = filter(Some("bogus-level")).to_string();
        assert!(
            !built.contains("bogus-level"),
            "a typo must not become a target directive: {built}"
        );
        // A good value is still honoured.
        assert!(filter(Some("warn")).to_string().contains("warn"));
    }

    /// A retention knob reads as a whole number, keeps `0` — which means "never sweep", not
    /// "delete everything now" — and survives a typo by applying the default instead of
    /// refusing to start.
    ///
    /// Exercised through a probe key rather than the real ones so it cannot collide with a
    /// value the developer running the suite happens to have exported.
    #[test]
    fn a_retention_knob_parses_or_falls_back() {
        let key = "FS_MCP_LOGGING_NUMBER_PROBE";
        assert_eq!(whole_number(key, 7), 7, "unset means the default");
        // SAFETY: single-threaded test over a variable private to it.
        for (raw, want) in [("3", 3), ("0", 0), ("  5  ", 5), ("", 7), ("soon", 7), ("-1", 7)] {
            unsafe { std::env::set_var(key, raw) };
            assert_eq!(whole_number(key, 7), want, "{raw:?}");
        }
        unsafe { std::env::remove_var(key) };
    }

    /// An absurd age is clamped rather than handed to a `Duration` conversion that would
    /// overflow, and `0` switches the sweep off rather than arming it on every start.
    #[test]
    fn keep_days_is_bounded_and_max_mb_defaults() {
        let key = "FS_MCP_LOG_KEEP_DAYS";
        // SAFETY: single-threaded test; no other test reads these keys.
        unsafe { std::env::remove_var(key) };
        assert_eq!(keep_days(), KEEP_DAYS_DEFAULT);
        unsafe { std::env::set_var(key, (KEEP_DAYS_MAX + 1).to_string()) };
        assert_eq!(keep_days(), KEEP_DAYS_MAX);
        unsafe { std::env::set_var(key, "0") };
        assert_eq!(keep_days(), 0, "0 must switch the sweep off, not empty the directory");
        unsafe { std::env::remove_var(key) };

        unsafe { std::env::remove_var("FS_MCP_LOG_MAX_MB") };
        assert_eq!(max_mb(), MAX_MB_DEFAULT);
    }

    /// The dated directory is the one the rest of the design keys on, so its shape is pinned:
    /// ten characters, `YYYY-MM-DD`.
    #[test]
    fn today_is_an_iso_date() {
        let d = today();
        assert_eq!(d.len(), 10, "{d}");
        assert_eq!(d.match_indices('-').count(), 2, "{d}");
        assert!(d.chars().all(|c| c.is_ascii_digit() || c == '-'), "{d}");
    }
}
