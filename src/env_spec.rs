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
    v.extend(stats_vars());
    v.extend(policy_vars());
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
    vec![EnvVar {
        key: "FS_MCP_LOG",
        default: crate::core::logging::LEVEL_DEFAULT,
        help: "Level for this server's log under <state>/logs: trace|debug|info|warn|error, or `off`. Bare words are levels; a target filter needs `=` or `,` (info,hyper=warn).",
    }]
}

/// What this server records about its own tool calls.
///
/// Immediately after [`log_vars`] because both describe what the server writes about itself: one
/// file per run, the log under `<state>/logs` and the counters under `<state>/stats`. The default
/// is owned by a constant in [`crate::tools::stats`], which
/// `stats_keys_are_registered_and_agree_with_the_code` asserts these strings match.
fn stats_vars() -> Vec<EnvVar> {
    vec![EnvVar {
        key: "FS_MCP_STATS",
        default: "on",
        help: "Count tool calls, outcomes and latency per tool: on | off.",
    }]
}

fn policy_vars() -> Vec<EnvVar> {
    vec![EnvVar {
        key: "FS_MCP_SESSION_FOOTER_EVERY",
        default: crate::core::agent_policy::FOOTER_EVERY_DEFAULT_STR,
        help: "MCP lock reminder: first tool result, then every N tool calls. 0 = off.",
    }]
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
    #[cfg(feature = "ctl-input")]
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
    ]);
    // Registered as widely as it is read. `driver::backend()` consults it in every control build,
    // including one whose only domain is OCR, notifications or clipboard file lists - so listing it
    // only for the input domains left those builds steered by a variable that `--list-env` and the
    // installed agent context file never mentioned. The registry's own guard cannot catch this: it
    // checks that every registered key is read, not that every key read is registered.
    #[cfg(feature = "ctl-any")]
    v.push(EnvVar {
        key: "FS_MCP_CTL_BACKEND",
        default: "",
        help: "Pin the desktop backend. Blank = auto-detect; `null` disables input (testing).",
    });
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
    /// The same drift guard as the tmp key above, for the one knob wave 2 leaves: a table that
    /// promises `warn` while the code logs at `info` sends an operator hunting for a record that
    /// is there all along.
    #[test]
    fn logging_keys_are_registered_and_agree_with_the_code() {
        let all = vars();
        assert_eq!(
            all.iter().filter(|v| v.key == "FS_MCP_LOG").count(),
            1,
            "FS_MCP_LOG must be registered exactly once"
        );

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
    }

    /// The statistics key is registered once and its advertised default is the meaning the code
    /// actually applies.
    ///
    /// The same drift guard as the keys above. `FS_MCP_STATS` is the interesting one: its default
    /// is advertised as a word and applied as a `bool`, so the assertion runs the word through
    /// the meaning the reader gives it rather than comparing two spellings.
    #[test]
    fn stats_keys_are_registered_and_agree_with_the_code() {
        use crate::tools::stats;

        let all = vars();
        let find = |key: &str| {
            all.iter()
                .find(|v| v.key == key)
                .unwrap_or_else(|| panic!("{key} is not registered"))
        };
        assert_eq!(
            all.iter().filter(|v| v.key == "FS_MCP_STATS").count(),
            1,
            "FS_MCP_STATS must be registered exactly once"
        );

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
    ///
    /// **This file is excluded from the search rather than discounted by a threshold.** The
    /// earlier form counted mentions across all of `src/` and demanded two, on the reasoning that
    /// one of them is the declaration here. That is only true for a key mentioned exactly once in
    /// this file: `FS_MCP_STATS` appears five times in it - the declaration, a rustdoc, and three
    /// lines of a neighbouring test - so it cleared the bar with room to spare and would have
    /// gone on clearing it if its reader had been deleted outright. Excluding this file makes the
    /// count mean what the test name says: at least one reader somewhere else.
    #[test]
    fn every_registered_key_is_read_somewhere_in_the_sources() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut haystack = String::new();
        collect(&src, &mut haystack);
        for v in vars() {
            let hits = haystack.matches(v.key).count();
            assert!(hits >= 1, "{} is registered but never read", v.key);
        }
    }

    /// The other direction: a key the sources read must appear in the table.
    ///
    /// The guard above checks registered-then-read, and its doc long claimed the reverse could not
    /// be checked because a source gated out of this build still sits on disk. That is true of a
    /// *compiler*, and this test is a grep: it scans the text for `FS_MCP_*` literals regardless of
    /// which features are on, and asks whether each one is in `vars()` under **some** feature. So
    /// the half it can reach - "read but registered nowhere at all" - it reaches without a build
    /// matrix. `FS_MCP_CTL_BACKEND` was exactly that shape for a while: `driver::backend()`
    /// consulted it in every control build while the table listed it only for the input domains,
    /// so `--list-env` and the installed agent context never mentioned the variable steering the
    /// backend.
    ///
    /// The half it cannot reach is a key that *is* registered but under a narrower gate than it is
    /// read. Nothing textual can see that; only building a configuration where the two disagree
    /// shows it.
    #[test]
    fn every_key_the_sources_read_is_registered() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut haystack = String::new();
        collect(&src, &mut haystack);

        // Every key this build does not compile is still in the table's text, so read the
        // declarations from this file rather than from `vars()`, which is feature-dependent.
        let declared = std::fs::read_to_string(src.join("env_spec.rs")).expect("read env_spec.rs");

        let mut missing: Vec<String> = Vec::new();
        let bytes = haystack.as_bytes();
        let mut i = 0;
        while let Some(at) = haystack[i..].find("FS_MCP_") {
            let start = i + at;
            let mut end = start;
            while end < bytes.len()
                && (bytes[end].is_ascii_uppercase()
                    || bytes[end].is_ascii_digit()
                    || bytes[end] == b'_')
            {
                end += 1;
            }
            let key = &haystack[start..end];
            // `FS_MCP_*` in prose, and `starts_with("FS_MCP_")` in code, leave the bare prefix
            // behind; a key needs a name after it. The blank-handling probe owns a key of its own
            // and is deliberately unregistered.
            if key != "FS_MCP_"
                && key != "FS_MCP_ENV_SPEC_BLANK_PROBE"
                && !declared.contains(&format!("key: \"{key}\""))
                && !missing.iter().any(|m| m == key)
            {
                missing.push(key.to_owned());
            }
            i = end.max(start + 1);
        }
        assert!(
            missing.is_empty(),
            "read by the sources but absent from the registry, so `--list-env` and the installed              agent context never mention them: {missing:?}"
        );
    }

    /// Every `.rs` file under `dir`, concatenated, **except this one** - the registry is where
    /// the key literals are declared, so counting them would be counting the declaration.
    fn collect(dir: &std::path::Path, out: &mut String) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs")
                && p.file_name().is_some_and(|n| n != "env_spec.rs")
                && let Ok(text) = std::fs::read_to_string(&p)
            {
                out.push_str(&text);
            }
        }
    }
}
