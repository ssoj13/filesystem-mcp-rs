//! Single source of truth for every `FS_MCP_*` environment variable.
//!
//! Three consumers used to hardcode their own copy of this knowledge, and they had already
//! drifted apart (the hint text advertised a 12 ms typing floor while the code used 30). All
//! three read this table now:
//!
//! - [`crate::setup`] — what `install` writes into the client's `mcpServers.env`,
//! - the `SUPPORTED ENV` block appended to the agent's context file,
//! - `filesystem-mcp-rs --list-env`, the answer to "which keys does this build support?".
//!
//! The table is filtered by the features compiled in, so a build without `s3-tools` neither
//! writes nor advertises `FS_MCP_S3_ALLOW_LIST`.

/// One configurable environment variable.
pub struct EnvVar {
    pub key: &'static str,
    /// Value `install` writes into the config. Empty means "written, but unset": the key is
    /// visible so the user knows the knob exists, and [`get`] treats blank as absent.
    pub default: &'static str,
    /// One line, shown in `--list-env` and in the agent hint block.
    pub help: &'static str,
}

/// Every variable this build understands, grouped by subsystem in presentation order.
///
/// One `vec!` per group rather than one growing list: each group is feature-gated as a whole,
/// which keeps the gating at the group boundary instead of on every element.
pub fn vars() -> Vec<EnvVar> {
    let mut v = paths_vars();
    v.extend(log_vars());
    #[cfg(feature = "stats-tools")]
    v.extend(stats_vars());
    v.extend(net_vars());
    v.extend(memory_vars());
    v.extend(ctl_vars());
    v
}

/// Where the server keeps its state, and how long scratch files survive there.
///
/// Listed first because it describes where everything the other groups name actually lives:
/// `FS_MCP_MEMORY_DB` and the ocrs cache are both resolved relative to this root.
fn paths_vars() -> Vec<EnvVar> {
    vec![
        EnvVar {
            key: "FS_MCP_STATE_DIR",
            default: "",
            help: "State directory for every file this server owns; must be absolute. Blank = ~/.filesystem-mcp-rs.",
        },
        EnvVar {
            key: "FS_MCP_TMP_KEEP_HOURS",
            default: "24",
            help: "Delete scratch under <state>/tmp older than this many hours. 0 = never sweep.",
        },
    ]
}

/// What this server writes about itself, and how long those logs stay.
///
/// Immediately after [`paths_vars`] because all three are resolved beneath the state root it
/// describes: one file per process under `<state>/logs/<YYYY-MM-DD>/`. Each default is owned by
/// a constant in [`crate::core::logging`], which
/// `logging_keys_are_registered_and_agree_with_the_code` asserts these strings match.
fn log_vars() -> Vec<EnvVar> {
    vec![
        EnvVar {
            key: "FS_MCP_LOG",
            default: crate::core::logging::LEVEL_DEFAULT,
            help: "Level for this server's log under <state>/logs: trace|debug|info|warn|error, or `off`. Bare words are levels; a target filter needs `=` or `,` (info,hyper=warn).",
        },
        EnvVar {
            key: "FS_MCP_LOG_KEEP_DAYS",
            default: "14",
            help: "Delete dated log directories under <state>/logs older than this many days. 0 = never sweep by date; FS_MCP_LOG_MAX_MB still applies.",
        },
        EnvVar {
            key: "FS_MCP_LOG_MAX_MB",
            default: "512",
            help: "Total size budget (MiB) for <state>/logs; oldest files are deleted first once it is exceeded. 0 = no budget.",
        },
    ]
}

/// What this server records about its own tool calls, and how long that detail stays.
///
/// Immediately after [`log_vars`] because both describe what the server writes about itself
/// beneath the state root, and because `FS_MCP_STATS_DETAIL_DAYS` deliberately mirrors
/// `FS_MCP_LOG_KEEP_DAYS`: a log file and the detail rows describing the same run expire
/// together. Each default is owned by a constant in [`crate::tools::stats`], which
/// `stats_keys_are_registered_and_agree_with_the_code` asserts these strings match.
#[cfg(feature = "stats-tools")]
fn stats_vars() -> Vec<EnvVar> {
    vec![
        EnvVar {
            key: "FS_MCP_STATS",
            default: "on",
            help: "Count tool calls, outcomes and latency per tool: on | off.",
        },
        EnvVar {
            key: "FS_MCP_STATS_DB",
            default: "",
            help: "SQLite file the counters are written to. Blank = <state>/stats.db.",
        },
        EnvVar {
            key: "FS_MCP_STATS_FLUSH_SEC",
            default: "5",
            help: "How often in-memory counters are written out (seconds); a crash loses at most this much. Minimum 1.",
        },
        EnvVar {
            key: "FS_MCP_STATS_DETAIL_DAYS",
            default: "14",
            help: "Keep 10-minute detail in <state>/stats.db for this many days, then compact it into daily totals. 0 = never compact.",
        },
        EnvVar {
            key: "FS_MCP_STATS_LABEL",
            default: "",
            help: "Free-text label recorded on this process's session row. Blank = none.",
        },
    ]
}

// `vec![]` cannot express these: an element carrying `#[cfg(...)]` is not valid inside the
// macro, and clippy cannot see that each push here is conditional.
#[allow(clippy::vec_init_then_push)]
fn net_vars() -> Vec<EnvVar> {
    #[allow(unused_mut)]
    let mut v = Vec::new();
    #[cfg(feature = "http-tools")]
    v.push(EnvVar {
        key: "FS_MCP_HTTP_ALLOW_LIST",
        default: "*",
        help: "Outbound HTTP host allowlist, comma-separated. `*` allows every host.",
    });
    #[cfg(feature = "s3-tools")]
    v.push(EnvVar {
        key: "FS_MCP_S3_ALLOW_LIST",
        default: "*",
        help: "S3 bucket allowlist, comma-separated. `*` allows every bucket.",
    });
    v
}

fn memory_vars() -> Vec<EnvVar> {
    vec![
        EnvVar {
            key: "FS_MCP_MEMORY_ACCESS_MODE",
            default: "enforce_private_only",
            help: "Memory visibility: allow_all | enforce_private_only | enforce_visibility.",
        },
        EnvVar {
            key: "FS_MCP_MEMORY_DB",
            default: "",
            help: "SQLite file for the memory tools. Blank = ~/.filesystem-mcp-rs/memory2.db.",
        },
    ]
}

#[allow(clippy::vec_init_then_push)]
fn ctl_vars() -> Vec<EnvVar> {
    #[allow(unused_mut)]
    let mut v = Vec::new();
    #[cfg(any(feature = "ctl-input", feature = "ctl-uia"))]
    v.extend([
        EnvVar {
            key: "FS_MCP_CTL_TYPE_MODE",
            default: "paste",
            help: "key_type strategy: paste (clipboard, ~100x faster) | chars (per-char unicode).",
        },
        EnvVar {
            key: "FS_MCP_CTL_TYPE_INTERVAL_MS",
            default: "30",
            help: "chars-mode per-char delay (ms). Below ~25 ms Win11 mangles runs into repeats.",
        },
        EnvVar {
            key: "FS_MCP_CTL_ARM_TTL_MS",
            default: "30000",
            help: "How long one `arm` call keeps the input tools unlocked (ms).",
        },
        EnvVar {
            key: "FS_MCP_CTL_OPS_PER_MIN",
            default: "240",
            help: "Runaway cap on executed input ops per minute.",
        },
        EnvVar {
            key: "FS_MCP_CTL_BACKEND",
            default: "",
            help: "Pin the desktop backend. Blank = auto-detect; `null` disables input (testing).",
        },
    ]);
    #[cfg(feature = "ctl-ocr")]
    v.push(EnvVar {
        key: "FS_MCP_CTL_OCRS_MODELS_DIR",
        default: "",
        help: "Cache dir for the downloaded ocrs models. Blank = ~/.filesystem-mcp-rs/ocrs.",
    });
    v
}

/// Read a variable, treating a blank or whitespace-only value as unset.
///
/// `install` writes optional keys as empty strings so the user can see them, which means every
/// reader must agree that empty is not a value — otherwise `FS_MCP_MEMORY_DB=""` would become a
/// literal empty path and the memory store would fail to open.
pub fn get(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The `SUPPORTED ENV` block used by the agent context file and `--list-env`.
pub fn render_table() -> String {
    let all = vars();
    let width = all.iter().map(|v| v.key.len()).max().unwrap_or(0);
    let mut out = String::from(
        "== SUPPORTED ENV (this server's `env` block; blank = unset; arg > env > default) ==\n",
    );
    for v in &all {
        let shown = if v.default.is_empty() {
            "(unset)"
        } else {
            v.default
        };
        out.push_str(&format!(
            "{:<width$}  {:<22}  {}\n",
            v.key,
            shown,
            v.help,
            width = width
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_unique_and_prefixed() {
        let mut seen = std::collections::BTreeSet::new();
        for v in vars() {
            assert!(v.key.starts_with("FS_MCP_"), "{} lacks the prefix", v.key);
            assert!(seen.insert(v.key), "{} listed twice", v.key);
        }
    }

    /// The two spellings that correctly anchor a location to the current state root: the
    /// literal path, and the `<state>` placeholder used when the text names something beneath
    /// it. Anything else describes a directory this server no longer writes to.
    const STATE_ANCHORS: [&str; 2] = ["~/.filesystem-mcp-rs", "<state>"];

    /// Does this help text describe *where something lives*?
    ///
    /// Deliberately a positive test for location-shaped text rather than a denylist of the
    /// spellings that happened to be wrong once: a denylist only catches what someone already
    /// thought of, so the next per-OS directory nobody has written down yet would sail straight
    /// through one. Over-matching is the safe direction here - a false positive
    /// costs an author one reworded sentence, a false negative ships an operator to the wrong
    /// directory.
    fn names_a_location(help: &str) -> bool {
        let lower = help.to_ascii_lowercase();
        lower.contains('/')
            || lower.contains('\\')
            || lower.contains('%')
            || [".db", ".log", ".jsonl"].iter().any(|e| lower.contains(e))
            || lower
                .split(|c: char| !c.is_ascii_alphabetic())
                .any(|w| matches!(w, "dir" | "dirs" | "directory" | "folder"))
    }

    /// Every key is registered exactly once, any key naming a location anchors it to the state
    /// root, and the advertised tmp retention matches the one the code actually applies.
    ///
    /// The memory and ocrs help strings survived the move to `~/.filesystem-mcp-rs` by a full
    /// wave, pointing operators at directories the server had stopped touching. The invariant
    /// below is what stops the next one.
    #[test]
    fn state_keys_are_registered_once_and_described_correctly() {
        let all = vars();
        for key in ["FS_MCP_STATE_DIR", "FS_MCP_TMP_KEEP_HOURS"] {
            assert_eq!(all.iter().filter(|v| v.key == key).count(), 1, "{key}");
        }

        // A detector that returned false for everything would make the loop below vacuous, so
        // pin both directions on it first, including the exact strings this wave had to fix.
        for stale in [
            "SQLite file for the memory tools. Blank = <local data>/filesystem-mcp-rs/memory2.db.",
            "Cache dir for the downloaded ocrs models. Blank = <data>/computer-mcp-rs/ocrs.",
            "Blank = %LOCALAPPDATA%\\filesystem-mcp-rs.",
            "Blank = ~/Library/Application Support/filesystem-mcp-rs.",
        ] {
            assert!(
                names_a_location(stale),
                "not detected as a location: {stale}"
            );
            assert!(
                !STATE_ANCHORS.iter().any(|a| stale.contains(a)),
                "wrongly accepted as anchored: {stale}"
            );
        }
        assert!(
            !names_a_location(
                "Memory visibility: allow_all | enforce_private_only | enforce_visibility."
            ),
            "a mode list is not a location"
        );

        for v in &all {
            if names_a_location(v.help) {
                assert!(
                    STATE_ANCHORS.iter().any(|a| v.help.contains(a)),
                    "{} describes a location without anchoring it to the state root: {}",
                    v.key,
                    v.help
                );
            }
        }

        // The invariant above has one loophole: deleting the location from a help string also
        // satisfies it. Pin the key this wave came to fix so silence cannot pass for a fix.
        let mem = all
            .iter()
            .find(|v| v.key == "FS_MCP_MEMORY_DB")
            .expect("memory db key");
        assert!(
            mem.help.contains("~/.filesystem-mcp-rs/memory2.db"),
            "stale help: {}",
            mem.help
        );

        // Two values that must agree, made to prove it rather than asked to.
        let tmp = all
            .iter()
            .find(|v| v.key == "FS_MCP_TMP_KEEP_HOURS")
            .expect("tmp keep hours key");
        assert_eq!(
            tmp.default,
            crate::core::paths::TMP_KEEP_HOURS_DEFAULT.to_string(),
            "advertised default disagrees with core::paths::tmp_keep_hours"
        );
    }

    /// Each logging key is registered once, its help names the state root where a path is
    /// implied, documents the only opt-out and the `0 = never sweep` convention, and every
    /// advertised default is the one the code actually applies.
    ///
    /// The same drift guard as the tmp key above, for the three knobs wave 2 adds: a table that
    /// promises `warn` while the code logs at `info` sends an operator hunting for a record that
    /// is there all along.
    #[test]
    fn logging_keys_are_registered_and_agree_with_the_code() {
        let all = vars();
        for key in ["FS_MCP_LOG", "FS_MCP_LOG_KEEP_DAYS", "FS_MCP_LOG_MAX_MB"] {
            assert_eq!(all.iter().filter(|v| v.key == key).count(), 1, "{key}");
        }

        let level = all
            .iter()
            .find(|v| v.key == "FS_MCP_LOG")
            .expect("level key");
        // Trivially true today, because the `EnvVar` holds the constant itself rather than a
        // copy of its text. It is kept, not deleted: the moment someone re-inlines `"info"`
        // here it becomes the same load-bearing drift guard as the tmp assertion below, firing
        // when `LEVEL_DEFAULT` next changes. The property it cannot reach - that the advertised
        // default is a level the filter actually applies - is asserted in `core::logging`'s
        // `the_advertised_default_level_is_one_the_filter_applies`.
        assert_eq!(level.default, crate::core::logging::LEVEL_DEFAULT);
        assert!(
            level.help.contains("off"),
            "the only way to opt out must be documented: {}",
            level.help
        );
        // The trap an operator finds the hard way: a bare word is read as a LEVEL, so a
        // RUST_LOG-style target needs `=` or `,` to be taken as one.
        assert!(level.help.contains('='), "{}", level.help);

        for (key, default) in [
            (
                "FS_MCP_LOG_KEEP_DAYS",
                crate::core::logging::KEEP_DAYS_DEFAULT,
            ),
            ("FS_MCP_LOG_MAX_MB", crate::core::logging::MAX_MB_DEFAULT),
        ] {
            let v = all.iter().find(|v| v.key == key).expect(key);
            assert_eq!(v.default, default.to_string(), "{key}");
            // `contains("0 =")`, not `contains('0')`: the latter is satisfied by the `0` in a
            // number anywhere in the sentence, which is not the convention being pinned.
            assert!(
                v.help.contains("0 ="),
                "a retention knob must document that 0 disables it: {}",
                v.help
            );
        }
    }

    /// Each statistics key is registered once, its advertised default is the constant the code
    /// actually applies, the retention knob documents the `0 = disabled` convention, and the one
    /// key naming a file anchors it to the state root.
    ///
    /// The same drift guard as the two above. `FS_MCP_STATS` is the interesting one: its default
    /// is advertised as a word and applied as a `bool`, so the assertion runs the word through
    /// the meaning the reader gives it rather than comparing two spellings.
    #[cfg(feature = "stats-tools")]
    #[test]
    fn stats_keys_are_registered_and_agree_with_the_code() {
        use crate::tools::stats;

        let all = vars();
        for key in [
            "FS_MCP_STATS",
            "FS_MCP_STATS_DB",
            "FS_MCP_STATS_FLUSH_SEC",
            "FS_MCP_STATS_DETAIL_DAYS",
            "FS_MCP_STATS_LABEL",
        ] {
            assert_eq!(all.iter().filter(|v| v.key == key).count(), 1, "{key}");
        }

        let find = |key: &str| {
            all.iter()
                .find(|v| v.key == key)
                .unwrap_or_else(|| panic!("{key} is not registered"))
        };

        for (key, default) in [
            ("FS_MCP_STATS_FLUSH_SEC", stats::FLUSH_SECS_DEFAULT),
            ("FS_MCP_STATS_DETAIL_DAYS", stats::DETAIL_DAYS_DEFAULT),
        ] {
            assert_eq!(find(key).default, default.to_string(), "{key}");
        }

        // The advertised word must be one the switch understands, not merely a word that happens
        // to look affirmative.
        let switch = find("FS_MCP_STATS");
        assert!(
            matches!(switch.default, "on" | "off"),
            "the switch must advertise a word its reader understands: {}",
            switch.default
        );
        assert_eq!(
            switch.default == "on",
            stats::ENABLED_DEFAULT,
            "advertised default disagrees with tools::stats::enabled"
        );

        // `contains("0 =")`, not `contains('0')`: the latter is satisfied by the `0` in a number
        // anywhere in the sentence, which is not the convention being pinned.
        let detail = find("FS_MCP_STATS_DETAIL_DAYS");
        assert!(
            detail.help.contains("0 ="),
            "a retention knob must document that 0 disables it: {}",
            detail.help
        );

        // The flush interval is NOT a retention knob and must not claim the same convention:
        // zero there is clamped up to one second, because an interval of zero would spin.
        let flush = find("FS_MCP_STATS_FLUSH_SEC");
        assert!(
            !flush.help.contains("0 ="),
            "an interval is not a retention knob: {}",
            flush.help
        );

        // The location invariant above would also be satisfied by deleting the path from the
        // help; pin the one key that names the database file.
        let db = find("FS_MCP_STATS_DB");
        assert!(
            db.help.contains("<state>/stats.db"),
            "stale help: {}",
            db.help
        );
    }

    #[test]
    fn blank_and_whitespace_read_as_unset() {
        let key = "FS_MCP_ENV_SPEC_BLANK_PROBE";
        // SAFETY: single-threaded test over a variable private to it.
        unsafe { std::env::set_var(key, "   ") };
        assert_eq!(get(key), None);
        unsafe { std::env::set_var(key, " value ") };
        assert_eq!(get(key).as_deref(), Some("value"));
        unsafe { std::env::remove_var(key) };
    }

    /// A registered key that no source reads is a typo or a leftover. (The reverse direction —
    /// a key read but unregistered — cannot be checked here: sources gated out of this build
    /// still contain their literals.)
    #[test]
    fn every_registered_key_is_read_somewhere_in_the_sources() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut haystack = String::new();
        collect(&src, &mut haystack);
        for v in vars() {
            // env_spec.rs itself is where the literal is declared; require a second mention.
            let hits = haystack.matches(v.key).count();
            assert!(hits >= 2, "{} is registered but never read", v.key);
        }
    }

    fn collect(dir: &std::path::Path, out: &mut String) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && let Ok(text) = std::fs::read_to_string(&p)
            {
                out.push_str(&text);
            }
        }
    }
}
