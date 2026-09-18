//! Tool-call statistics: which of this server's tools are used, which fail and how.
//!
//! Counters accumulate in memory, keyed by tool, for the life of the process and are never
//! persisted: this subsystem answers "what is this server actually doing" from the log it
//! already writes, and nothing else. [`collect`] holds the map, [`outcome`] decides which of
//! the five outcome columns a finished call lands in, and every `FS_MCP_STATS_EVERY` calls -
//! and once more on the way out - the table is written to the log as one line per tool.
//!
//! This module holds the configuration readers, beside the subsystem they govern, the way
//! [`crate::core::paths::tmp_keep_hours`] lives beside the directory it governs. They are the
//! only readers of their keys, so no second caller can disagree about what blank or zero means.
//! The keys themselves are registered once in [`crate::env_spec`], which asserts that the
//! defaults it advertises are the constants below.

pub mod collect;
pub mod outcome;

use tracing::warn;

use crate::env_spec;

/// Whether statistics are collected when `FS_MCP_STATS` is unset.
///
/// On: a server whose usage nobody can see is the problem this subsystem exists to fix, and the
/// cost is a mutex and some integer adds on the hot path. `env_spec` advertises this same default
/// as the string `on`, and its tests assert the two agree.
pub const ENABLED_DEFAULT: bool = true;

/// Calls between log dumps when `FS_MCP_STATS_EVERY` is unset.
///
/// Small enough that a short session still says something before it exits, large enough that a
/// busy server does not spend its log on itself: at 200, a table of ~250 tools costs one block of
/// lines per few minutes of real use. `env_spec` advertises this same number, and its tests
/// assert the two agree.
pub const DUMP_EVERY_DEFAULT: u64 = 200;

/// The largest dump interval accepted, a million calls.
///
/// Beyond this the dump is indistinguishable from off, which `0` already expresses honestly; the
/// bound exists so that a fat-fingered value cannot silently mean "never" while the key still
/// reads as enabled.
pub const DUMP_EVERY_MAX: u64 = 1_000_000;

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

/// How many calls between log dumps; `0` means never dump, and the counters are still kept.
///
/// Unlike an interval in seconds, zero here is meaningful and is honoured: counting costs a mutex
/// and some adds, while the dump costs a line of log per tool, so an operator may reasonably want
/// the first without the second - `FS_MCP_STATS=off` is what switches off both.
///
/// An unparseable value is reported and the default applied: a malformed telemetry knob must
/// never be a reason the server refuses to start.
pub fn dump_every() -> u64 {
    let value = match env_spec::get("FS_MCP_STATS_EVERY") {
        None => DUMP_EVERY_DEFAULT,
        Some(raw) => raw.parse().unwrap_or_else(|_| {
            warn!("FS_MCP_STATS_EVERY is not a whole number ({raw}); using {DUMP_EVERY_DEFAULT}");
            DUMP_EVERY_DEFAULT
        }),
    };
    if value > DUMP_EVERY_MAX {
        warn!(
            "FS_MCP_STATS_EVERY={value} exceeds the maximum of {DUMP_EVERY_MAX}; using that instead"
        );
        return DUMP_EVERY_MAX;
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

    /// Zero is honoured rather than clamped: it is the documented way to keep counting without
    /// spending log lines on it, and a reader that quietly turned it into "every call" or "every
    /// 200 calls" would make the key a lie.
    #[test]
    #[serial]
    fn zero_disables_the_dump_without_disabling_the_counters() {
        with_env("FS_MCP_STATS_EVERY", Some("0"), || {
            assert_eq!(dump_every(), 0);
            assert!(enabled(), "counting is a separate switch");
        });
    }

    #[test]
    #[serial]
    fn absurd_and_malformed_dump_intervals_fall_back_rather_than_overflow() {
        with_env("FS_MCP_STATS_EVERY", Some("18446744073709551615"), || {
            assert_eq!(dump_every(), DUMP_EVERY_MAX)
        });
        with_env("FS_MCP_STATS_EVERY", Some("often"), || {
            assert_eq!(dump_every(), DUMP_EVERY_DEFAULT)
        });
        with_env("FS_MCP_STATS_EVERY", None, || {
            assert_eq!(dump_every(), DUMP_EVERY_DEFAULT)
        });
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
}
