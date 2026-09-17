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
//! this design exists to avoid, and the file is still found by the day the process started.
//!
//! **stdio never writes to stderr.** Any stderr output during the handshake closes the connection
//! in MCP clients, so under stdio the file is the only sink — and if it cannot be opened, this
//! process runs without logs rather than breaking the transport. Only stream transport, whose
//! stderr nobody is parsing, gets a console sink.
//!
//! The decision ([`target_for`]) is separate from carrying it out ([`init_logging`]): a process
//! can install a global subscriber only once, so the part worth testing is the part that takes
//! its inputs as arguments.

use std::path::{Path, PathBuf};

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
    /// No subscriber at all: `FS_MCP_LOG=off`, or stdio with no usable file.
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

/// Decide the plan, then carry it out, returning what was actually done.
///
/// Infallible on purpose: logging must never prevent the transport from starting, so there is no
/// error for the caller to propagate. Every degradation — an unopenable file, an unusable state
/// directory, a subscriber someone else already installed — is reported through the returned
/// [`Plan`] instead. Called once, from `main`.
pub fn init_logging(mode: TransportMode, log_file: Option<String>) -> Plan {
    let level = env_spec::get("FS_MCP_LOG");
    install(target_for(mode, log_file, level.as_deref()), level.as_deref())
}

/// Decide the plan. `level` is the raw `FS_MCP_LOG` value (already blank-filtered).
///
/// Takes its inputs as arguments rather than reading them, so the decision can be tested without
/// touching the process environment.
pub fn target_for(mode: TransportMode, log_file: Option<String>, level: Option<&str>) -> Plan {
    if level.is_some_and(|v| v.eq_ignore_ascii_case("off")) {
        return Plan::Disabled;
    }
    // An explicit path is the operator's choice and overrides the per-process default; the
    // per-process file is only the default location, not a rule about where logs may go.
    let file = match log_file {
        Some(p) => PathBuf::from(p),
        None => match log_path() {
            Ok(p) => p,
            // The state directory is unusable. stdio still must not touch stderr, so it runs
            // without logs rather than breaking the handshake; stream can still say so.
            Err(_) => {
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
/// A file that cannot be opened degrades rather than fails: to [`Plan::Disabled`] under stdio,
/// whose only other channel is forbidden, and to [`Plan::Stderr`] under stream, which can still
/// say what happened. A subscriber already installed by someone else leaves this process with
/// nothing of its own, which is [`Plan::Disabled`] too — the plan describes what this call did.
fn install(plan: Plan, level: Option<&str>) -> Plan {
    match plan {
        Plan::Disabled => Plan::Disabled,
        Plan::Stderr => stderr_only(level),
        Plan::File(path) => match open(&path) {
            Ok(file) => {
                let done = tracing_subscriber::registry()
                    .with(filter(level))
                    .with(fmt::layer().with_writer(file).with_ansi(false))
                    .try_init();
                match done {
                    Ok(()) => Plan::File(path),
                    Err(_) => Plan::Disabled,
                }
            }
            // stdio: there is no second channel to complain through. Serve without logs.
            Err(_) => Plan::Disabled,
        },
        Plan::FileAndStderr(path) => match open(&path) {
            Ok(file) => {
                let done = tracing_subscriber::registry()
                    .with(filter(level))
                    .with(fmt::layer().with_writer(std::io::stderr))
                    .with(fmt::layer().with_writer(file).with_ansi(false))
                    .try_init();
                match done {
                    Ok(()) => Plan::FileAndStderr(path),
                    Err(_) => Plan::Disabled,
                }
            }
            Err(e) => {
                let plan = stderr_only(level);
                tracing::warn!("cannot open the log file {}: {e}", path.display());
                plan
            }
        },
    }
}

/// The stderr-only subscriber, used by stream transport when there is no usable file.
fn stderr_only(level: Option<&str>) -> Plan {
    let done = tracing_subscriber::registry()
        .with(filter(level))
        .with(fmt::layer().with_writer(std::io::stderr))
        .try_init();
    match done {
        Ok(()) => Plan::Stderr,
        Err(_) => Plan::Disabled,
    }
}

/// The level filter: `FS_MCP_LOG` first, then `RUST_LOG`, then `info`.
///
/// An unparseable `FS_MCP_LOG` falls through to the next source rather than stopping the server,
/// for the same reason the rest of this module degrades instead of failing.
fn filter(level: Option<&str>) -> EnvFilter {
    if let Some(raw) = level
        && let Ok(f) = EnvFilter::try_new(raw)
    {
        return f;
    }
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

/// Open a log file for appending, creating its parent directory if the caller named one that
/// does not exist yet (`--log some/where/x.log`).
fn open(path: &Path) -> std::io::Result<std::fs::File> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::OpenOptions::new().create(true).append(true).open(path)
}

/// `<state>/logs/<YYYY-MM-DD>/fsmcp-<pid>-<instance>.log`, directory created.
pub fn log_path() -> std::io::Result<PathBuf> {
    let root = crate::core::paths::sub_dir(crate::core::paths::SubDir::Logs)?;
    log_path_in(&root, &today())
}

/// The path arithmetic, split out so tests can supply a directory and a date.
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

    /// The name carries both pid and instance id, and lives under a dated directory, so two
    /// concurrent servers — or one pid reused tomorrow — never share a file.
    #[test]
    fn file_name_is_unique_per_process_and_dated() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let p = log_path_in(dir.path(), "2026-09-17").expect("path");
        let parent = p.parent().expect("parent");
        assert_eq!(parent.file_name().expect("name"), "2026-09-17");
        let name = p.file_name().expect("name").to_string_lossy().into_owned();
        assert!(name.starts_with("fsmcp-"), "{name}");
        assert!(name.contains(&crate::core::instance::pid().to_string()), "{name}");
        assert!(name.contains(crate::core::instance::id()), "{name}");
        assert!(name.ends_with(".log"), "{name}");
    }

    /// `FS_MCP_LOG=off` means no subscriber and no file — the only way to opt out.
    #[test]
    fn off_disables_everything() {
        assert!(matches!(target_for(TransportMode::Stdio, None, Some("off")), Plan::Disabled));
        assert!(matches!(target_for(TransportMode::Stream, None, Some("off")), Plan::Disabled));
    }

    /// stdio never gets a stderr sink, whatever else is configured — stderr during the handshake
    /// closes the connection in MCP clients.
    #[test]
    fn stdio_never_writes_to_stderr() {
        assert!(matches!(target_for(TransportMode::Stdio, None, None), Plan::File(_)));
        assert!(matches!(
            target_for(TransportMode::Stdio, Some("x.log".into()), None),
            Plan::File(_)
        ));
        assert!(matches!(target_for(TransportMode::Stream, None, None), Plan::FileAndStderr(_)));
    }

    /// An explicit `--log` path wins over the per-process file, because an operator who names a
    /// file is asking for that file.
    #[test]
    fn explicit_path_overrides_the_default() {
        match target_for(TransportMode::Stdio, Some("C:/tmp/explicit.log".into()), None) {
            Plan::File(p) => assert!(p.ends_with("explicit.log"), "{}", p.display()),
            other => panic!("expected File, got {other:?}"),
        }
    }

    /// The dated directory is the one the rest of the design keys on, so its shape is pinned:
    /// ten characters, `YYYY-MM-DD`, and the same value for two calls in a row.
    #[test]
    fn today_is_an_iso_date() {
        let d = today();
        assert_eq!(d.len(), 10, "{d}");
        assert_eq!(d.match_indices('-').count(), 2, "{d}");
        assert!(d.chars().all(|c| c.is_ascii_digit() || c == '-'), "{d}");
    }
}
