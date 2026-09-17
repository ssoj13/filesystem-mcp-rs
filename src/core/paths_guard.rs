//! Enforces invariant I1 of the state-directory design: only `core::paths` decides where state
//! lives, and no doc line tells the reader otherwise. A convention nobody checks is a convention
//! that decays within months, so this module turns both into properties the build checks on every
//! `cargo test`.
//!
//! Two lists, applied to different things. [`FORBIDDEN`] catches *code* that resolves a platform
//! directory by itself, on any line. [`DOC_STALE`] catches *prose* that still names a location
//! this server abandoned, and is applied only to `///` lines - because a `///` line is not merely
//! a comment: clap renders it as `--help`, so a stale one is a wrong answer shipped to an
//! operator. `--memory-db`'s help was stale for a full wave and nothing mechanical noticed.
//! `//!` module docs are deliberately *not* scanned by the second list; they narrate history
//! ("the pre-2026-09 location was ...") where naming an abandoned directory is the point.
//!
//! [`DOC_STALE`] is applied to `.md` files as well, because the rename that prompted all of this
//! left `README.md`'s environment table pointing at the old location while every `///` line in the
//! tree had already been corrected - and that table is what a user actually reads. Markdown has no
//! `///` to key on, so every line of a `.md` is scanned: all of it is prose aimed at a reader. The
//! `.md` files that legitimately name an abandoned location are *records* - this wave's own spec
//! and plan, the working notes describing this guard - and are listed in [`MD_ALLOWED`].
//!
//! [`DOC_STALE`] has to stay a denylist. `env_spec`'s positive rule - every location-shaped help
//! string must contain the state root - works there because that corpus is eleven curated
//! strings; over free-form doc prose it would flag hundreds of innocent lines.
//!
//! The check is textual, over every `.rs` file under `src/` and `tests/`. Two limits are known and
//! deliberately not closed: aliasing the crate (`use dirs as d;` then `d::data_dir()`) and
//! splitting a call across lines both slip past, because catching them needs a `syn` AST pass that
//! is disproportionate for drift which would have to be deliberate evasion rather than someone
//! reaching for the obvious `dirs::data_dir()`. And an exemption clears the whole line it matches,
//! not just the spelling it names, so one line carrying two different forbidden spellings is
//! excused by either - no such line exists, and writing one takes effort.
//!
//! Reaching the same directories through the environment is in `FORBIDDEN` too, in its three
//! `env::var` spellings: unlike the two evasions above, that one could happen by accident. Only
//! those literal spellings are caught, so a variable name held in a `const` still slips past -
//! the same textual limit as everywhere else here.
//!
//! The scan sees only this repo's own tree under `src/` and `tests/`. A path resolved inside a
//! dependency, in a `build.rs` (which lives at the crate root, outside both), or produced by a
//! macro expansion is invisible to it. `build.rs` is the concrete near-miss: the crate has none
//! today, and one added later would be unguarded.
//!
//! The module is test-only; it contains no runtime code and is compiled out of release builds.

#[cfg(test)]
mod tests {
    use std::path::{MAIN_SEPARATOR, Path, PathBuf};

    /// Directories scanned, relative to the crate root. Every `ALLOWED` key is prefixed with the
    /// root it lives in, so `src/core/paths.rs` and a hypothetical `tests/core/paths.rs` can never
    /// be confused for one another.
    const ROOTS: &[&str] = &["src", "tests"];

    /// Directory names never walked when looking for Markdown. The `.md` scan starts at the crate
    /// root rather than at [`ROOTS`], because the file this rule exists to catch (`README.md`)
    /// sits there - which means it also walks into everything else that accumulates at a crate
    /// root, and only this repo's own prose is ours to keep current.
    ///
    /// Dot-directories go with them, as a rule rather than a list: `.git`, `.superpowers` and
    /// `.omc` all hold agent scratch and tool state, all three are gitignored, and the next tool
    /// to drop a `.md` somewhere would otherwise fail this test for a file nobody here wrote.
    /// The cost is that `.github/` is unscanned too; nothing in it describes our state layout.
    const MD_SKIP: &[&str] = &["target", "node_modules"];

    /// Whether [`visit_md`] walks into `dir`: not build output, not vendored code, not tool state.
    fn md_skipped(dir: &Path) -> bool {
        dir.file_name().is_some_and(|n| {
            let name = n.to_string_lossy();
            name.starts_with('.') || MD_SKIP.contains(&name.as_ref())
        })
    }

    /// Text that means "this file resolves a platform directory by itself".
    ///
    /// `dirs::` is matched as a whole prefix rather than a list of specific accessors: the narrow
    /// list (`data_dir`, `data_local_dir`) would let `dirs::home_dir().join(".filesystem-mcp-rs")`
    /// walk straight around the resolver while the guard stayed silent. It also catches a
    /// `use dirs::home_dir;` import, and with it the bare calls that would follow.
    ///
    /// `env::home_dir` is listed separately because `std::env::home_dir()` is a live std API and
    /// the obvious way to do the same thing without reaching for the crate at all.
    ///
    /// The three `env::var` spellings close the one bypass that could happen by *accident*:
    /// reading `APPDATA`, `TEMP` or `HOME` and joining onto it reaches exactly the directories
    /// this module exists to keep out, and unlike aliasing the `dirs` crate it needs no intent to
    /// evade. Three entries are cheaper than the paragraph that used to document the gap.
    const FORBIDDEN: &[&str] = &[
        "dirs::",
        "temp_dir(",
        "env::home_dir",
        "env::var(\"APPDATA\")",
        "env::var(\"TEMP\")",
        "env::var(\"HOME\")",
    ];

    /// Spellings of locations this server no longer writes to, refused in `///` doc lines.
    ///
    /// Each entry is a place state used to live before the 2026-09 move to `~/.filesystem-mcp-rs`:
    /// `<local data>` and `%LOCALAPPDATA%` for the memory database, `computer-mcp-rs` for the
    /// computer-control state, `Application Support` for the macOS spelling of both, and
    /// `system data dir` for the prose form. A doc line naming one of them is either describing
    /// the current layout wrongly or is history that belongs in a `//!` module doc.
    const DOC_STALE: &[&str] = &[
        "system data dir",
        "<local data>",
        "computer-mcp-rs",
        "%LOCALAPPDATA%",
        "Application Support",
    ];

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

    /// Files allowed to spell a [`DOC_STALE`] location in a `///` line, with the reason. Same
    /// shape and same per-string discipline as [`ALLOWED`].
    const DOC_ALLOWED: &[(&str, &[&str])] = &[
        // This guard has to spell the stale locations in order to search for them.
        ("src/core/paths_guard.rs", DOC_STALE),
        // The resolver's `legacy_ctl_audit` exists precisely to find the one irreplaceable file
        // left under the old `computer-mcp-rs` directory; its doc must be able to name it.
        ("src/core/paths.rs", &["computer-mcp-rs"]),
        // Same: documents that the layouts left in the old directory are NOT migrated, which the
        // reader cannot act on unless the directory is named.
        (
            "src/tools/computer/driver/portable.rs",
            &["computer-mcp-rs"],
        ),
        // These name OTHER applications' config locations (Claude, Cursor, ...), not this
        // server's state - the whole point of those two functions. Known, bounded cost: an
        // exemption clears the whole line, so a doc about OUR state written in this file and
        // spelling one of those two would also pass. Nothing in it describes our state today.
        (
            "src/mcp_setup/clients/mod.rs",
            &["%LOCALAPPDATA%", "Application Support"],
        ),
    ];

    /// Markdown files allowed to spell a [`DOC_STALE`] location, relative to the crate root, with
    /// the exact spellings each may use. Same per-string discipline as [`DOC_ALLOWED`].
    ///
    /// Every entry is a *record* rather than a description of the current layout: a document that
    /// says where state used to live, written at a point in time and wrong to "correct" later.
    /// `README.md` is deliberately absent - it is the table users read, and its going stale is the
    /// reason this rule exists.
    const MD_ALLOWED: &[(&str, &[&str])] = &[
        // This wave's design doc: its inventory table IS the pre-move layout, which is its point.
        (
            "docs/superpowers/specs/2026-09-17-state-dir-logging-stats-design.md",
            &["computer-mcp-rs"],
        ),
        // The plan that produced this wave: quotes the code it replaced, old paths and all.
        (
            "docs/superpowers/plans/2026-09-17-state-dir-unification.md",
            &["computer-mcp-rs", "<local data>"],
        ),
        // The working notes describe this very guard, so they have to name what it catches.
        (
            "CLAUDE.md",
            &["<local data>", "computer-mcp-rs", "%LOCALAPPDATA%"],
        ),
    ];

    /// A Markdown line naming an abandoned location is an offence unless the file is cleared for
    /// that spelling. Unlike [`doc_offence`] there is no `///` prefix to key on; see the module
    /// doc for why every line of a `.md` is fair game.
    fn md_offence(line: &str, exempt: &[&str]) -> bool {
        DOC_STALE.iter().any(|s| line.contains(s)) && !exempt.iter().any(|e| line.contains(e))
    }

    /// The `.md` rule catches the exact line that went stale this wave - `README.md`'s environment
    /// table - and leaves a corrected one alone.
    #[test]
    fn md_denylist_catches_a_stale_readme_row() {
        // `FS_MCP_MEMORY_DB`'s row as it read before this wave corrected it.
        let stale =
            "| `FS_MCP_MEMORY_DB` | *(unset)* | Memory database path. Unset = system data dir |";
        assert!(md_offence(stale, &[]), "the denylist must catch: {stale}");
        // Prose, not only table rows: markdown has no `///` marker to key on.
        assert!(md_offence(
            "Models are cached under `<data>/computer-mcp-rs/ocrs`.",
            &[]
        ));

        // Correctly anchored prose is not an offence.
        assert!(!md_offence(
            "| `FS_MCP_MEMORY_DB` | *(unset)* | Unset = `~/.filesystem-mcp-rs/memory2.db` |",
            &[]
        ));
        // An exemption clears the spelling it names, and only that one.
        assert!(!md_offence(stale, &["system data dir"]));
        assert!(md_offence(stale, &["computer-mcp-rs"]));
    }

    /// No `.md` file outside [`MD_ALLOWED`] may point the reader at an abandoned location.
    #[test]
    fn docs_name_the_current_location() {
        let mut offenders = Vec::new();
        visit_md(&crate_root(), &crate_root(), &mut offenders);
        assert!(
            offenders.is_empty(),
            "Markdown must name the current state location (~/.filesystem-mcp-rs); a file that \
             RECORDS where state used to live belongs in MD_ALLOWED with its reason; \
             offenders: {offenders:#?}"
        );
    }

    /// Walk `dir` for `.md` files, appending `path:line: text` for every unexempt stale line.
    /// Mirrors [`visit`] minus the [`FORBIDDEN`] pass: a `.md` file holds no code to guard.
    fn visit_md(root: &Path, dir: &Path, offenders: &mut Vec<String>) {
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
                if !md_skipped(&path) {
                    visit_md(root, &path, offenders);
                }
                continue;
            }
            if path.extension().is_none_or(|e| e != "md") {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace(MAIN_SEPARATOR, "/");
            let exempt: &[&str] = MD_ALLOWED
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
                if md_offence(line, exempt) {
                    offenders.push(format!(
                        "{rel}:{}: doc names an abandoned location: {}",
                        i + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    /// Every `.rs` file under `src/` and `tests/` must get its state locations from `core::paths`,
    /// and no `///` line may point the reader at a location this server abandoned.
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
            "state paths must come from core::paths (tests: use tempfile::TempDir), and doc \
             lines must name the current location; offenders: {offenders:#?}"
        );
    }

    /// A `///` line naming an abandoned location is an offence unless the file is cleared for
    /// that exact spelling. Applied to doc lines only; see this module's doc for why.
    ///
    /// Split out as a pure function so the rule can be checked against known-bad and known-good
    /// lines without a corpus on disk: `doc_denylist_catches_a_stale_help_line` is what fails if
    /// [`DOC_STALE`] is ever emptied.
    fn doc_offence(line: &str, exempt: &[&str]) -> bool {
        line.trim_start().starts_with("///")
            && DOC_STALE.iter().any(|s| line.contains(s))
            && !exempt.iter().any(|e| line.contains(e))
    }

    /// The doc denylist catches the exact class of line that went stale this wave - a clap
    /// `--help` doc comment pointing at the pre-move location - and leaves correct ones alone.
    #[test]
    fn doc_denylist_catches_a_stale_help_line() {
        // `--memory-db`'s help as it read before this wave corrected it.
        let stale = "/// SQLite file for the memory tools. Blank = <local data>/memory2.db.";
        assert!(doc_offence(stale, &[]), "the denylist must catch: {stale}");
        // The `--log` shape, which goes stale the moment wave 2 wires `SubDir::Logs`.
        assert!(doc_offence(
            "    /// Log file. Blank = the system data dir.",
            &[]
        ));
        assert!(doc_offence(
            "/// Cache dir: <data>/computer-mcp-rs/ocrs.",
            &[]
        ));
        assert!(doc_offence("/// Client config under %LOCALAPPDATA%.", &[]));

        // Correctly anchored prose is not an offence.
        assert!(!doc_offence(
            "/// SQLite file for the memory tools. Blank = ~/.filesystem-mcp-rs/memory2.db.",
            &[]
        ));
        // Only `///` lines are scanned: `//!` narrates history, and code is the other list's job.
        assert!(!doc_offence(
            "//! The pre-2026-09 root was <local data>/x.",
            &[]
        ));
        assert!(!doc_offence("    let legacy = \"computer-mcp-rs\";", &[]));
        // An exemption clears the spelling it names, and only that one.
        assert!(!doc_offence(stale, &["<local data>"]));
        assert!(doc_offence(stale, &["computer-mcp-rs"]));
    }

    /// An exemption for a file that no longer exists is a hole waiting for the next file of that
    /// name to walk into it, so a stale key in either list fails the build rather than sitting
    /// unread.
    ///
    /// A key must also live under one of [`ROOTS`]: `benches/x.rs` could name a real file and still
    /// be dead, because [`visit`] never walks there and so never consults it.
    #[test]
    fn allowed_entries_all_exist() {
        let dead: Vec<&str> = ALLOWED
            .iter()
            .chain(DOC_ALLOWED.iter())
            .map(|(file, _)| *file)
            .filter(|file| {
                !crate_root().join(file).is_file()
                    || !ROOTS.iter().any(|r| file.starts_with(&format!("{r}/")))
            })
            .collect();
        assert!(
            dead.is_empty(),
            "ALLOWED/DOC_ALLOWED name files that do not exist or are outside {ROOTS:?}, so the \
             exemption is never consulted; delete these entries: {dead:#?}"
        );
    }

    /// The same rule for [`MD_ALLOWED`], whose keys are relative to the crate root instead of to
    /// [`ROOTS`]. A spec or plan renamed later must not leave its exemption behind for the next
    /// document of that name to inherit.
    #[test]
    fn md_allowed_entries_all_exist() {
        let dead: Vec<&str> = MD_ALLOWED
            .iter()
            .map(|(file, _)| *file)
            .filter(|file| !crate_root().join(file).is_file())
            .collect();
        assert!(
            dead.is_empty(),
            "MD_ALLOWED names files that do not exist, so the exemption is never consulted; \
             delete these entries: {dead:#?}"
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
            let doc_exempt: &[&str] = DOC_ALLOWED
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
                if doc_offence(line, doc_exempt) {
                    offenders.push(format!(
                        "{rel}:{}: doc names an abandoned location: {}",
                        i + 1,
                        line.trim()
                    ));
                }
            }
        }
    }
}
