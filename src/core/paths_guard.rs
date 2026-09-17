//! Enforces invariant I1 of the state-directory design: only `core::paths` decides where state
//! lives. A convention nobody checks is a convention that decays within months, so this module
//! turns it into a property the build checks on every `cargo test`.
//!
//! The module is test-only; it contains no runtime code and is compiled out of release builds.

#[cfg(test)]
mod tests {
    use std::path::{MAIN_SEPARATOR, Path};

    /// Text that means "this file resolves a platform directory by itself".
    ///
    /// `dirs::` is matched as a whole prefix rather than a list of specific accessors: the narrow
    /// list (`data_dir`, `data_local_dir`) would let `dirs::home_dir().join(".filesystem-mcp-rs")`
    /// walk straight around the resolver while the guard stayed silent.
    const FORBIDDEN: &[&str] = &["dirs::", "temp_dir("];

    /// Files allowed to name a platform directory, each with the exact spellings it may use and
    /// the reason it is exempt. A file is excused only for the strings listed with it, so a file
    /// cleared for `dirs::home_dir` still trips the guard on `dirs::data_dir()`.
    ///
    /// Per-file exemption strings rather than a blanket per-file pass: the installer legitimately
    /// needs `home_dir` to find *other* applications' config files, and nothing more. Expressing
    /// that costs one extra slice per entry, which is far less machinery than the hole a blanket
    /// exemption would leave open.
    const ALLOWED: &[(&str, &[&str])] = &[
        // The resolver itself: it owns `dirs::home_dir` for the root and the `legacy_*` helpers
        // that locate data left by pre-2026-09 builds.
        ("core/paths.rs", &["dirs::"]),
        // This guard has to spell the forbidden strings in order to search for them.
        ("core/paths_guard.rs", &["dirs::", "temp_dir("]),
        // The installer locates OTHER applications' config files (Claude, Cursor, ...) under the
        // user's home; that is not this server's state and has nothing to do with the state root.
        ("mcp_setup/types.rs", &["dirs::home_dir"]),
        // Same reason: finds `~/.cargo/bin` to report where the binary was installed.
        ("mcp_setup/host.rs", &["dirs::home_dir"]),
    ];

    /// Every `.rs` file under `src/` must get its state locations from `core::paths`.
    ///
    /// Scratch space in tests is no exception: `tempfile::TempDir` gives a unique directory that
    /// is removed even when an assertion unwinds, so no test needs `std::env::temp_dir` either.
    #[test]
    fn paths_are_centralized() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        visit(&src, &src, &mut offenders);
        assert!(
            offenders.is_empty(),
            "state paths must come from core::paths (tests: use tempfile::TempDir); \
             offenders: {offenders:#?}"
        );
    }

    /// Walk `dir`, appending `path:line: text` for every line that names a platform directory
    /// without being exempt. Unreadable entries are skipped rather than failing the test: the
    /// guard reports drift in the source it can see, and a read error is a local tooling problem.
    fn visit(root: &Path, dir: &Path, offenders: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                visit(root, &path, offenders);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace(MAIN_SEPARATOR, "/");
            let exempt: &[&str] = ALLOWED
                .iter()
                .find(|(file, _)| *file == rel)
                .map_or(&[], |(_, spellings)| *spellings);
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (i, line) in text.lines().enumerate() {
                if FORBIDDEN.iter().any(|f| line.contains(f))
                    && !exempt.iter().any(|e| line.contains(e))
                {
                    offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
                }
            }
        }
    }
}
