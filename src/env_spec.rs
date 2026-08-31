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
    let mut v = net_vars();
    v.extend(memory_vars());
    v.extend(ctl_vars());
    v
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
            help: "SQLite file for the memory tools. Blank = <local data>/filesystem-mcp-rs/memory2.db.",
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
        help: "Cache dir for the downloaded ocrs models. Blank = <data>/computer-mcp-rs/ocrs.",
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
