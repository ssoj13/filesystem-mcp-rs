//! Tool-call statistics: which of this server's tools are used, which fail and how.
//!
//! The whole subsystem is three steps. At startup [`collect::Collector`] is built from the
//! router's own tool list with **every tool at zero**, which is what makes the unused tail fall
//! out for free: a tool nobody called is a row of zeros, not a row that is missing. During the
//! run each finished call adds integers to that map, on a path that cannot fail. At exit the map
//! is written once, as JSON, to `<state>/stats/<YYYY-MM-DD>/<machine>_<stamp>.json`.
//!
//! Nothing is aggregated here and nothing is deleted here. Reading a week of runs is reading that
//! directory, which this server's own `grep_files` and `read_json` already do better than a
//! bespoke query tool would.
//!
//! [`collect`] holds the map, [`outcome`] decides which of the five outcome columns a finished
//! call lands in, and this module owns the one file the run leaves behind.

pub mod collect;
pub mod outcome;

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use serde_json::{Value, json};
use tracing::warn;

use crate::core::paths::{self, SubDir};
use crate::env_spec;
use collect::Collector;

/// The JSON layout version, so a reader can tell a file written by this build from one written
/// by a build that moved a field. Bumped when a field changes meaning, not when one is added.
const SCHEMA: u32 = 1;

/// Whether statistics are collected when `FS_MCP_STATS` is unset.
///
/// On: a server whose usage nobody can see is the problem this subsystem exists to fix, and the
/// cost is a mutex and some integer adds on the hot path. `env_spec` advertises this same default
/// as the string `on`, and its tests assert the two agree.
pub const ENABLED_DEFAULT: bool = true;

/// Is the statistics subsystem switched on?
///
/// Anything other than an explicit off-word is on, and an unrecognised value is reported and
/// treated as [`ENABLED_DEFAULT`]: refusing to start over a typo in a telemetry knob would be a
/// far worse outcome than collecting counters the operator meant to switch off.
pub fn enabled() -> bool {
    let Some(raw) = env_spec::get("FS_MCP_STATS") else {
        return ENABLED_DEFAULT;
    };
    match raw.to_ascii_lowercase().as_str() {
        "on" | "true" | "1" | "yes" => true,
        "off" | "false" | "0" | "no" => false,
        other => {
            warn!("FS_MCP_STATS is not on|off ({other}); using {ENABLED_DEFAULT}");
            ENABLED_DEFAULT
        }
    }
}

/// Everything about the run that is not a counter, fixed at startup.
///
/// Carried beside the counters because a table of call counts with no idea which server, which
/// client or which working directory produced it cannot be compared with anything.
#[derive(Debug, Clone)]
pub struct Identity {
    /// This process's id. Together with `instance` it identifies the run inside its log line too.
    pub pid: u32,
    /// The process nonce, the same one the log file name and `panic.log` carry.
    pub instance: String,
    /// `stdio` or `stream`: the two are used by different clients for different work, and a
    /// latency that looks alarming under one is normal under the other.
    pub transport: &'static str,
    /// This build's version, so a change in the numbers can be attributed to a release.
    pub version: &'static str,
    /// The directory the server was started in, which is what most relative paths resolved
    /// against and therefore what the run was actually about.
    pub cwd: Option<PathBuf>,
    /// When the process began serving.
    pub started: SystemTime,
}

/// How the run ended, which is the one thing about the file that cannot be known at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The transport returned and the process is leaving normally.
    Exit,
    /// The panic hook is writing: the process is on its way down with a backtrace in
    /// `<state>/panics/`, and this file is what says what it had been doing.
    Panic,
}

impl Ending {
    fn as_str(self) -> &'static str {
        match self {
            Ending::Exit => "exit",
            Ending::Panic => "panic",
        }
    }
}

/// The counters and identity of the run in progress, or nothing when statistics are off.
///
/// A process-global because the panic hook is a `'static` closure that is handed no server: the
/// alternative is a crash report with no record of what the server had been doing, which is
/// exactly the case this subsystem is most wanted for. Written once, at startup, before any tool
/// call can arrive.
static ACTIVE: OnceLock<Active> = OnceLock::new();

/// What [`ACTIVE`] holds.
struct Active {
    collector: Arc<Collector>,
    identity: Identity,
    /// The client that completed the handshake, learned after [`install`] and therefore not part
    /// of [`Identity`]. Absent under the HTTP transport, where one process serves many clients
    /// and no single name would be true.
    client: OnceLock<(String, String)>,
}

/// Adopt this run's collector and identity, so that the exit path and the panic hook can both
/// write the file.
///
/// Called once, from `run`, and ignored on a second call: a second installation would mean two
/// tables disagreeing about the same process, and the first one is the one every tool call is
/// already counting into.
pub fn install(collector: Arc<Collector>, identity: Identity) {
    let _already_installed = ACTIVE.set(Active {
        collector,
        identity,
        client: OnceLock::new(),
    });
}

/// Record which client completed the handshake.
///
/// Separate from [`install`] because it is only knowable afterwards, and a `OnceLock` because
/// under stdio there is exactly one client per process; the first answer is the true one and a
/// later call cannot improve on it.
pub fn note_client(name: String, version: String) {
    if let Some(active) = ACTIVE.get() {
        let _first_client_wins = active.client.set((name, version));
    }
}

/// Write this run's counters to `<state>/stats/<YYYY-MM-DD>/<machine>_<stamp>.json`.
///
/// Returns the path so the caller can log it. Does nothing and reports nothing when statistics
/// are off, because then there is no [`ACTIVE`] to write.
///
/// **A `SIGKILL` takes the counters with it and nothing here can change that**: the process is
/// gone before any code of ours runs, so there is no file, and inventing a periodic write to
/// narrow that window would be reintroducing the flush this design exists without.
pub fn write(ending: Ending, ended: SystemTime) -> io::Result<Option<PathBuf>> {
    let Some(active) = ACTIVE.get() else {
        return Ok(None);
    };
    let path = paths::run_file(SubDir::Stats, "json")?;
    let report = report(active, ending, ended);

    // A run resolves one path, so a later write replaces an earlier one. That is what keeps a run
    // to a single file, and for counters it is almost always an improvement: they only ever grow,
    // so the later snapshot is the fuller one.
    //
    // Except when the later one is empty. `try_snapshot` gives up rather than block, and reports
    // that honestly as `locked` with no rows - so a second panic on the thread holding the counter
    // lock, or a panic after the exit path has already written, would replace a complete report
    // with one that knows nothing. A report that could not read the table therefore refuses to
    // overwrite a file that is already there; it still writes when there is nothing to lose.
    if !worth_writing(&report, path.exists()) {
        return Ok(None);
    }
    std::fs::write(&path, report.to_string())?;
    Ok(Some(path))
}

/// Would writing `report` over a file that `exists` leave more information than it removes?
///
/// Pure, and separate from [`write`], because the interesting case is a decision and not a file:
/// [`write`] reads a process-global that a test can set only once per binary, while this can be
/// asked every combination in one test.
fn worth_writing(report: &Value, exists: bool) -> bool {
    let blind = report["totals"]["locked"] == Value::Bool(true);
    !(blind && exists)
}

/// The file's contents.
///
/// Split from [`write`] so that the shape is a thing the tests can assert without a state root to
/// write into.
fn report(active: &Active, ending: Ending, ended: SystemTime) -> Value {
    let id = &active.identity;
    // `try_snapshot`, not a blocking read: on the panic path this runs on the thread that
    // panicked, which may be the thread holding the counter lock, and a blocking read there would
    // hang the process instead of reporting the crash. An empty table is a worse answer than the
    // real one and a far better one than no file at all, so `locked` says which was written.
    let table = active.collector.try_snapshot();
    let health = active.collector.health();

    let tools: serde_json::Map<String, Value> = table
        .iter()
        .flat_map(|t| t.iter())
        .map(|(name, c)| {
            (
                name.to_string(),
                json!({
                    "calls": c.calls(),
                    "ok": c.ok,
                    "err_flagged": c.err_flagged,
                    "err_params": c.err_params,
                    "err_internal": c.err_internal,
                    "deferred": c.deferred,
                    "ns_total": c.ns_total,
                    "ns_max": c.ns_max,
                    "content_bytes": c.content_bytes,
                }),
            )
        })
        .collect();

    json!({
        "schema": SCHEMA,
        "run": {
            "pid": id.pid,
            "instance": id.instance,
            "transport": id.transport,
            "version": id.version,
            "cwd": id.cwd.as_ref().map(|p| p.to_string_lossy().into_owned()),
            "client": active.client.get().map(|(name, version)| json!({
                "name": name,
                "version": version,
            })),
            "started": rfc3339(id.started),
            "ended": rfc3339(ended),
            "ending": ending.as_str(),
        },
        "totals": {
            "calls": health.calls,
            "unknown_shape": health.unknown_shape,
            "tools": tools.len(),
            "locked": table.is_none(),
        },
        "tools": tools,
    })
}

/// An instant as RFC 3339, the spelling `panic.log` already uses for the same job.
fn rfc3339(when: SystemTime) -> String {
    humantime::format_rfc3339(when).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use outcome::Outcome;
    use serial_test::serial;

    /// Set a key for the duration of `body`, then restore it. The reader goes through the real
    /// process environment, so these tests must be serialised against each other.
    fn with_env(key: &str, value: Option<&str>, body: impl FnOnce()) {
        let previous = std::env::var(key).ok();
        // SAFETY: the `#[serial]` attribute keeps these tests from running concurrently with each
        // other, and no other thread in the test binary reads this key.
        unsafe {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        body();
        unsafe {
            match previous {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }

    #[test]
    #[serial]
    fn the_switch_reads_both_spellings_and_survives_a_typo() {
        with_env("FS_MCP_STATS", None, || assert!(enabled()));
        with_env("FS_MCP_STATS", Some("off"), || assert!(!enabled()));
        with_env("FS_MCP_STATS", Some("OFF"), || assert!(!enabled()));
        with_env("FS_MCP_STATS", Some("on"), || assert!(enabled()));
        with_env("FS_MCP_STATS", Some("maybe"), || {
            assert_eq!(enabled(), ENABLED_DEFAULT, "a typo must not switch it off")
        });
    }

    /// An `Active` of our own, so that no test depends on - or installs - the process-global one.
    fn active(tools: &[&str]) -> Active {
        Active {
            collector: Arc::new(Collector::new(tools)),
            identity: Identity {
                pid: 4321,
                instance: "0123456789abcdef".to_owned(),
                transport: "stdio",
                version: "9.9.9",
                cwd: Some(PathBuf::from("/work")),
                started: SystemTime::UNIX_EPOCH,
            },
            client: OnceLock::new(),
        }
    }

    /// A tool nobody called is a row of zeros, not a missing row.
    ///
    /// This is the property the whole feature is for: the file has to answer "what does nobody
    /// use", and a table that only grew rows on first use could never answer it.
    #[test]
    fn every_tool_appears_even_when_it_was_never_called() {
        let a = active(&["read_text_file", "grep_files", "write_file"]);
        a.collector
            .record_interned(a.collector.intern("grep_files"), Outcome::Ok, 7, 3);

        let v = report(&a, Ending::Exit, SystemTime::UNIX_EPOCH);
        let tools = v["tools"].as_object().expect("tools");
        assert_eq!(
            tools.len(),
            3,
            "all three, not just the one that was called"
        );
        assert_eq!(tools["write_file"]["calls"], 0);
        assert_eq!(tools["write_file"]["ns_total"], 0);
        assert_eq!(tools["grep_files"]["calls"], 1);
        assert_eq!(tools["grep_files"]["ok"], 1);
        assert_eq!(tools["grep_files"]["ns_total"], 7);
        assert_eq!(tools["grep_files"]["ns_max"], 7);
        assert_eq!(tools["grep_files"]["content_bytes"], 3);
        assert_eq!(v["totals"]["tools"], 3);
        assert_eq!(v["totals"]["calls"], 1);
        assert_eq!(v["totals"]["locked"], false);
    }

    /// The identity reaches the file, and an unknown client is absent rather than invented.
    #[test]
    fn the_run_names_itself_and_says_how_it_ended() {
        let a = active(&["read_text_file"]);
        let v = report(&a, Ending::Panic, SystemTime::UNIX_EPOCH);

        assert_eq!(v["schema"], SCHEMA);
        assert_eq!(v["run"]["pid"], 4321);
        assert_eq!(v["run"]["instance"], "0123456789abcdef");
        assert_eq!(v["run"]["transport"], "stdio");
        assert_eq!(v["run"]["version"], "9.9.9");
        assert_eq!(v["run"]["cwd"], "/work");
        assert_eq!(v["run"]["ending"], "panic");
        assert_eq!(v["run"]["started"], "1970-01-01T00:00:00Z");
        assert!(
            v["run"]["client"].is_null(),
            "a client nobody announced must not be guessed at"
        );

        a.client
            .set(("claude-code".to_owned(), "2.1.0".to_owned()))
            .expect("first client");
        let v = report(&a, Ending::Exit, SystemTime::UNIX_EPOCH);
        assert_eq!(v["run"]["client"]["name"], "claude-code");
        assert_eq!(v["run"]["client"]["version"], "2.1.0");
        assert_eq!(v["run"]["ending"], "exit");
    }

    /// A table that cannot be read - the panic-on-the-locking-thread case - still produces a
    /// file, and that file says the counters are missing rather than reporting zeros as fact.
    #[test]
    fn a_locked_table_is_reported_as_locked_rather_than_as_empty() {
        let a = active(&["read_text_file"]);
        let held = a.collector.hold_for_test();

        let v = report(&a, Ending::Panic, SystemTime::UNIX_EPOCH);
        assert_eq!(v["totals"]["locked"], true);
        assert_eq!(v["tools"].as_object().expect("tools").len(), 0);
        assert_eq!(v["run"]["pid"], 4321, "the identity is still written");

        drop(held);
        assert_eq!(
            report(&a, Ending::Panic, SystemTime::UNIX_EPOCH)["totals"]["locked"],
            false
        );
    }

    /// A report that could not read the counters never replaces one that could.
    ///
    /// A run resolves one path, so writes to it replace each other - which is what keeps a run to
    /// one file, and is normally an improvement, counters being monotonic. The exception is a
    /// report whose `try_snapshot` gave up: it carries no rows, and two orderings reach it after a
    /// good report is already on disk - a second panic on the thread holding the lock, and a panic
    /// after the exit path has written. Either would replace the whole table with nothing.
    ///
    /// It still writes when there is nothing to lose, because an honest `locked: true` file beats
    /// no file at all.
    #[test]
    fn a_blind_report_refuses_to_overwrite_a_sighted_one() {
        let a = active(&["read_text_file"]);

        let held = a.collector.hold_for_test();
        let blind = report(&a, Ending::Panic, SystemTime::UNIX_EPOCH);
        drop(held);
        let sighted = report(&a, Ending::Exit, SystemTime::UNIX_EPOCH);

        assert_eq!(blind["totals"]["locked"], true, "fixture check");
        assert_eq!(sighted["totals"]["locked"], false, "fixture check");

        assert!(
            !worth_writing(&blind, true),
            "a blind report must not clobber a file that is already there"
        );
        assert!(
            worth_writing(&blind, false),
            "with no file yet, a locked report is better than none"
        );
        assert!(
            worth_writing(&sighted, true),
            "a full report always replaces an earlier one: counters only grow"
        );
        assert!(worth_writing(&sighted, false));
    }

    /// The file lands under a dated directory named for this run, and is valid JSON on disk.
    #[test]
    #[serial]
    fn the_file_is_written_under_the_state_root_and_parses_back() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        with_env(
            "FS_MCP_STATE_DIR",
            Some(&dir.path().to_string_lossy()),
            || {
                let a = active(&["grep_files"]);
                let path = paths::run_file(SubDir::Stats, "json").expect("path");
                std::fs::write(
                    &path,
                    report(&a, Ending::Exit, SystemTime::UNIX_EPOCH).to_string(),
                )
                .expect("write");

                assert!(path.starts_with(dir.path()), "{}", path.display());
                assert_eq!(path.extension().and_then(|e| e.to_str()), Some("json"));
                let back: Value =
                    serde_json::from_str(&std::fs::read_to_string(&path).expect("read"))
                        .expect("the file must parse as JSON");
                assert_eq!(back["tools"]["grep_files"]["calls"], 0);
            },
        );
    }
}
