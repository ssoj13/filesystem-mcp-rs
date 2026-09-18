//! Tool-call statistics: which of this server's tools are used, which fail and how.
//!
//! Counters accumulate in memory, keyed by tool, for the life of the process and are never
//! persisted: this subsystem answers "what is this server actually doing" from the log it
//! already writes, and nothing else. [`collect`] holds the map, [`outcome`] decides which of
//! the five outcome columns a finished call lands in.
//!
//! This module holds the configuration readers, beside the subsystem they govern, the way
//! [`crate::core::paths::tmp_keep_hours`] lives beside the directory it governs. They are the
//! only readers of their keys, so no second caller can disagree about what blank or zero means.
//! The keys themselves are registered once in [`crate::env_spec`], which asserts that the
//! defaults it advertises are the constants below.

// Not everything here has a non-test consumer yet: the dump that reads the table is the next
// commit, and until it lands `Collector::health` and the counters it reports are exercised only
// by the tests below.
//
// `expect`, deliberately, not `allow`: once the dump is wired up nothing here is dead any more,
// the expectation goes unfulfilled, and `-D warnings` turns that into a build failure - so the
// suppression cannot outlive the reason for it. Delete this attribute when it complains.
//
// Scoped to `not(test)` because the two builds disagree: the tests already exercise every item,
// so under `cfg(test)` nothing is dead and an unconditional `expect` would be unfulfilled from
// the day it was written, failing `cargo clippy --all-targets`.
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "read by the log dump; see the comment above")
)]

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
}
