//! Tool-call statistics: which of this server's tools are used, which fail and how.
//!
//! Counters accumulate in memory keyed by `(tool, 10-minute bucket)` and a background task
//! flushes *deltas* into one shared SQLite file under the state root, where `instance_id` is part
//! of every primary key so that the dozens of server processes alive at once never write the
//! same row. [`db`] holds the schema and the single door onto that file.
//!
//! This module holds the configuration readers, beside the subsystem they govern, the way
//! [`crate::core::paths::tmp_keep_hours`] lives beside the directory it governs. They are the
//! only readers of their keys, so no second caller can disagree about what blank or zero means.
//! The keys themselves are registered once in [`crate::env_spec`], which asserts that the
//! defaults it advertises are the constants below.

// This is the first task of the wave: the database and its configuration exist, and the
// collector, the flush task, the session row, the read tools and the retention sweep that call
// into them are the tasks that follow. Until then every item here is dead in the eyes of a
// binary crate, which has no external consumers for `pub` to satisfy.
//
// `expect`, deliberately, not `allow`: once the last item is wired up nothing here is dead any
// more, the expectation goes unfulfilled, and `-D warnings` turns that into a build failure - so
// the suppression cannot outlive the reason for it. Delete this attribute when it complains.
//
// Scoped to `not(test)` because the two builds disagree: the tests below already exercise every
// item, so under `cfg(test)` nothing is dead and an unconditional `expect` would be unfulfilled
// from the day it was written, failing `cargo clippy --all-targets`.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the rest of wave 3; see the comment above"
    )
)]

pub mod collect;
pub mod db;
pub mod flush;
pub mod outcome;

use std::path::PathBuf;

use tracing::warn;

use crate::core::paths;
use crate::env_spec;

/// File name of the statistics database within the state root.
///
/// One spelling, because `FS_MCP_STATS_DB` overrides the whole path and everything else must
/// agree on where the default is.
const DB_FILE_NAME: &str = "stats.db";

/// Whether statistics are collected when `FS_MCP_STATS` is unset.
///
/// On: a server whose usage nobody can see is the problem this wave exists to fix, and the cost
/// is a mutex and some integer adds on the hot path. `env_spec` advertises this same default as
/// the string `on`, and its tests assert the two agree.
pub const ENABLED_DEFAULT: bool = true;

/// Seconds between flushes when `FS_MCP_STATS_FLUSH_SEC` is unset.
///
/// A crash loses at most one interval of counters, so this is the bound on what a `SIGKILL`
/// costs; five seconds trades a negligible amount of data for roughly one transaction per
/// process per five seconds against the shared write lock.
pub const FLUSH_SECS_DEFAULT: u64 = 5;

/// The largest flush interval accepted, one hour.
///
/// The interval becomes a `Duration` and is compared against elapsed time, so an unbounded value
/// would overflow that arithmetic; beyond an hour it is also indistinguishable from "off", which
/// `FS_MCP_STATS=off` already expresses honestly.
pub const FLUSH_SECS_MAX: u64 = 3600;

/// Days of 10-minute detail kept when `FS_MCP_STATS_DETAIL_DAYS` is unset.
///
/// Two weeks answers "what changed since last sprint" at full resolution; older buckets are
/// compacted into `tool_daily`, which stays for years in a few megabytes. Matches
/// [`crate::core::logging::KEEP_DAYS_DEFAULT`] so that a log file and the detail rows describing
/// the same run expire together.
pub const DETAIL_DAYS_DEFAULT: u64 = 14;

/// The largest detail retention accepted, ten years.
///
/// Same reason as [`FLUSH_SECS_MAX`]: the value is converted to a span of seconds before it is
/// compared against a bucket, and an unbounded one overflows that conversion - which in a debug
/// build is a panic inside housekeeping, before the transport starts.
pub const DETAIL_DAYS_MAX: u64 = 3650;

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

/// Where the statistics database lives: `FS_MCP_STATS_DB` if set, else `<state>/stats.db`.
///
/// Goes through [`crate::core::paths`] like every other path in this server, so that pointing
/// `FS_MCP_STATE_DIR` somewhere else moves this file with everything else. Fails only when the
/// state root itself cannot be created, which the caller reports as the reason statistics are
/// off rather than treating as fatal.
pub fn db_file() -> std::io::Result<PathBuf> {
    match env_spec::get("FS_MCP_STATS_DB") {
        Some(explicit) => Ok(PathBuf::from(explicit)),
        None => paths::db_path(DB_FILE_NAME),
    }
}

/// Seconds between flushes of the in-memory delta into the database.
///
/// Zero is *not* "disabled" here - this is an interval, not a retention knob - so it is clamped
/// up to one second; switching statistics off is what `FS_MCP_STATS=off` is for.
pub fn flush_secs() -> u64 {
    let secs = whole_number("FS_MCP_STATS_FLUSH_SEC", FLUSH_SECS_DEFAULT, FLUSH_SECS_MAX);
    secs.max(1)
}

/// How many days of 10-minute detail rows to keep before compacting them into daily totals;
/// `0` means never compact, matching `FS_MCP_TMP_KEEP_HOURS` and `FS_MCP_LOG_KEEP_DAYS`.
///
/// Read by the housekeeping sweep, which owns the lease and does the deleting.
pub fn detail_days() -> u64 {
    whole_number(
        "FS_MCP_STATS_DETAIL_DAYS",
        DETAIL_DAYS_DEFAULT,
        DETAIL_DAYS_MAX,
    )
}

/// The operator's free-text label for this process, stored on its `sessions` row.
///
/// Unset is the normal case and is not a default in disguise: a blank label means the row simply
/// carries none, which is why this returns an `Option` rather than an empty string.
pub fn label() -> Option<String> {
    env_spec::get("FS_MCP_STATS_LABEL")
}

/// Read a whole-number knob, bounded by `max`.
///
/// One function for both numeric knobs so the two cannot drift in how they treat a typo or an
/// absurd value; the same shape as `core::logging`'s `retention`, which does this for the log
/// sweep. An unparseable value is reported and the default applied - a malformed telemetry knob
/// must never be a reason the server refuses to start.
fn whole_number(key: &str, default: u64, max: u64) -> u64 {
    let value = match env_spec::get(key) {
        None => default,
        Some(raw) => raw.parse().unwrap_or_else(|_| {
            warn!("{key} is not a whole number ({raw}); using {default}");
            default
        }),
    };
    if value > max {
        warn!("{key}={value} exceeds the maximum of {max}; using that instead");
        return max;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// Set a key for the duration of `body`, then restore it. The readers go through the real
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

    /// The two numeric knobs differ deliberately in how they read zero: the retention knob
    /// follows the house `0 = disabled` convention, the interval cannot.
    #[test]
    #[serial]
    fn zero_disables_retention_but_never_the_flush_interval() {
        with_env("FS_MCP_STATS_DETAIL_DAYS", Some("0"), || {
            assert_eq!(detail_days(), 0)
        });
        with_env("FS_MCP_STATS_FLUSH_SEC", Some("0"), || {
            assert_eq!(flush_secs(), 1, "an interval of zero would spin")
        });
    }

    #[test]
    #[serial]
    fn absurd_and_malformed_values_fall_back_rather_than_overflow() {
        with_env(
            "FS_MCP_STATS_DETAIL_DAYS",
            Some("18446744073709551615"),
            || assert_eq!(detail_days(), DETAIL_DAYS_MAX),
        );
        with_env("FS_MCP_STATS_FLUSH_SEC", Some("soon"), || {
            assert_eq!(flush_secs(), FLUSH_SECS_DEFAULT)
        });
        with_env("FS_MCP_STATS_DETAIL_DAYS", None, || {
            assert_eq!(detail_days(), DETAIL_DAYS_DEFAULT)
        });
    }

    /// An explicit path wins outright.
    ///
    /// Only the override branch is exercised here: the other one is
    /// [`crate::core::paths::db_path`], which `core::paths` already tests against its own
    /// `TempDir`. Pointing `FS_MCP_STATE_DIR` at a scratch directory from inside this binary
    /// would move the state root for whatever else happens to be running at that moment, and a
    /// second spelling of that file name would be one more thing that can drift - so the name
    /// itself is pinned instead.
    #[test]
    #[serial]
    fn the_database_path_honours_the_override() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let explicit = dir.path().join("elsewhere.db");
        with_env("FS_MCP_STATS_DB", Some(&explicit.to_string_lossy()), || {
            assert_eq!(db_file().expect("explicit path"), explicit)
        });
        assert_eq!(DB_FILE_NAME, "stats.db", "the documented default file name");
    }

    #[test]
    #[serial]
    fn a_blank_label_is_no_label() {
        with_env("FS_MCP_STATS_LABEL", Some("   "), || {
            assert_eq!(label(), None)
        });
        with_env("FS_MCP_STATS_LABEL", Some(" build-box "), || {
            assert_eq!(label().as_deref(), Some("build-box"))
        });
    }
}
