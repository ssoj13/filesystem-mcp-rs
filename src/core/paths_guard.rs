//! Enforces invariant I1 of the state-directory design: only `core::paths` decides where state
//! lives. A convention nobody checks is a convention that decays within months, so this module
//! turns it into a property the build checks on every `cargo test`.
//!
//! The check is textual, over every `.rs` file under `src/` and `tests/`. Two limits are known and
//! deliberately not closed: aliasing the crate (`use dirs as d;` then `d::data_dir()`) and
//! splitting a call across lines both slip past, because catching them needs a `syn` AST pass that
//! is disproportionate for drift which would have to be deliberate evasion rather than someone
//! reaching for the obvious `dirs::data_dir()`. And an exemption clears the whole line it matches,
//! not just the spelling it names, so one line carrying two different forbidden spellings is
//! excused by either - no such line exists, and writing one takes effort.
//!
//! The check also knows only the spellings in `FORBIDDEN`, so reaching the same directories through
//! the environment - `env::var("HOME")`, `env::var("APPDATA")`, `env::var("TEMP")` - passes
//! silently. None exist today, and unlike the two evasions above this one could happen by accident,
//! so it is the gap worth remembering when reviewing anything that builds a path from a variable.
//!
//! The module is test-only; it contains no runtime code and is compiled out of release builds.

#[cfg(test)]
mod tests {
    use std::path::{MAIN_SEPARATOR, Path, PathBuf};

    /// Directories scanned, relative to the crate root. Every `ALLOWED` key is prefixed with the
    /// root it lives in, so `src/core/paths.rs` and a hypothetical `tests/core/paths.rs` can never
    /// be confused for one another.
    const ROOTS: &[&str] = &["src", "tests"];

    /// Text that means "this file resolves a platform directory by itself".
    ///
    /// `dirs::` is matched as a whole prefix rather than a list of specific accessors: the narrow
    /// list (`data_dir`, `data_local_dir`) would let `dirs::home_dir().join(".filesystem-mcp-rs")`
    /// walk straight around the resolver while the guard stayed silent. It also catches a
    /// `use dirs::home_dir;` import, and with it the bare calls that would follow.
    ///
    /// `env::home_dir` is listed separately because `std::env::home_dir()` is a live std API and
    /// the obvious way to do the same thing without reaching for the crate at all.
    const FORBIDDEN: &[&str] = &["dirs::", "temp_dir(", "env::home_dir"];

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
        ("src/core/paths.rs", &["dirs::"]),
        // This guard has to spell the forbidden strings in order to search for them.
        (
            "src/core/paths_guard.rs",
            &["dirs::", "temp_dir(", "env::home_dir"],
        ),
        // The installer locates OTHER applications' config files (Claude, Cursor, ...) under the
        // user's home; that is not this server's state and has nothing to do with the state root.
        ("src/mcp_setup/types.rs", &["dirs::home_dir"]),
        // Same reason: finds `~/.cargo/bin` to report where the binary was installed.
        ("src/mcp_setup/host.rs", &["dirs::home_dir"]),
    ];

    /// Every `.rs` file under `src/` and `tests/` must get its state locations from `core::paths`.
    ///
    /// Scratch space in tests is no exception: `tempfile::TempDir` gives a unique directory that
    /// is removed even when an assertion unwinds, so no test needs `std::env::temp_dir` either.
    #[test]
    fn paths_are_centralized() {
        let mut offenders = Vec::new();
        for root in ROOTS {
            let dir = crate_root().join(root);
            visit(root, &dir, &dir, &mut offenders);
        }
        assert!(
            offenders.is_empty(),
            "state paths must come from core::paths (tests: use tempfile::TempDir); \
             offenders: {offenders:#?}"
        );
    }

    /// An exemption for a file that no longer exists is a hole waiting for the next file of that
    /// name to walk into it, so a stale `ALLOWED` key fails the build rather than sitting unread.
    ///
    /// A key must also live under one of [`ROOTS`]: `benches/x.rs` could name a real file and still
    /// be dead, because [`visit`] never walks there and so never consults it.
    #[test]
    fn allowed_entries_all_exist() {
        let dead: Vec<&str> = ALLOWED
            .iter()
            .map(|(file, _)| *file)
            .filter(|file| {
                !crate_root().join(file).is_file()
                    || !ROOTS.iter().any(|r| file.starts_with(&format!("{r}/")))
            })
            .collect();
        assert!(
            dead.is_empty(),
            "ALLOWED names files that do not exist or are outside {ROOTS:?}, so the exemption is \
             never consulted; delete these entries: {dead:#?}"
        );
    }

    /// The crate root, which both `ROOTS` and the `ALLOWED` keys are relative to.
    fn crate_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// Walk `dir`, appending `root/path:line: text` for every line that names a platform directory
    /// without being exempt. A file that cannot be read is reported too: an unreadable file is the
    /// one case where staying silent is indistinguishable from finding it clean.
    fn visit(root_name: &str, root: &Path, dir: &Path, offenders: &mut Vec<String>) {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                offenders.push(format!("{}: cannot list directory: {e}", dir.display()));
                return;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                visit(root_name, root, &path, offenders);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let rel = format!(
                "{root_name}/{}",
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace(MAIN_SEPARATOR, "/")
            );
            let exempt: &[&str] = ALLOWED
                .iter()
                .find(|(file, _)| *file == rel)
                .map_or(&[], |(_, spellings)| *spellings);
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) => {
                    offenders.push(format!("{rel}: cannot read, so cannot be cleared: {e}"));
                    continue;
                }
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
