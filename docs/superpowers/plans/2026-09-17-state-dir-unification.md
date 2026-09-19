# Wave 1 — Unified State Directory Implementation Plan


> **Superseded — kept as a record of intent, not as a description of the code.**
>
> Wave 1 shipped essentially as planned. Two later changes moved past it: `panic.log` in the state root became one crash report per panic under `<state>/panics/`, and the naming of every per-run file moved into a single helper, `core::paths::run_file`.
>
> The body below is left exactly as it was written, because a plan edited after the fact stops
> being evidence of what was decided and why. For what the code actually does now, read
> `README.md`, `CLAUDE.md` and the rustdoc on the modules named there.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move every piece of `filesystem-mcp-rs` durable and scratch state under one per-user root, `~/.filesystem-mcp-rs/`, identical on Windows, macOS and Linux, with an explicit migration for existing data.

**Architecture:** A single resolver module `core::paths` owns the root and every subdirectory; all other code asks it for paths and never calls `dirs::*` or `std::env::temp_dir()` itself. A guard test enforces that rule mechanically so the "just put it here" class of drift cannot come back. Migration of pre-existing files is explicit per location: move when unambiguous, refuse and report when two candidates exist, create fresh when neither does.

**Tech Stack:** Rust edition 2024, `dirs` crate (already a dependency), `tracing`, inline `#[cfg(test)] mod tests` (this repo's convention — see `src/mcp_setup/tests.rs`, `src/tools/computer/tests.rs`).

**Spec:** `docs/superpowers/specs/2026-09-17-state-dir-logging-stats-design.md` (§3 I1/I9, §4)

## Global Constraints

- The state root is `~/.filesystem-mcp-rs/`, resolved via `dirs::home_dir()`, **identical on all three platforms**. No `data_dir()`, `data_local_dir()` or per-OS branching.
- **No silent fallbacks.** Today `main.rs:7614` degrades to `PathBuf::from(".")` when the home directory cannot be resolved, which silently writes a database into whatever directory the agent happened to start in. Unresolvable home is an error that is reported, not papered over.
- Never discard errors with `let _ =`. Propagate with `?`, or handle explicitly and log with `warn!`.
- Avoid `unwrap()` / `expect()` outside tests; avoid indexing that can panic.
- Rustdoc on every new public item: what it is, why it exists, where it is used.
- Do not use `git reset` or revert files via git.
- Commit messages are conventional and describe the substance of the change. No agent co-authorship trailers.
- `FS_MCP_*` variables exist **only** in `src/env_spec.rs`; readers go through `env_spec::get` (blank = unset).
- Gates: plain `cargo test` and `cargo clippy --all-targets -- -D warnings`. There is no lib target, so `--lib` cannot run; `--bin filesystem-mcp-rs` runs only the unit tests and silently skips `tests/integration.rs` and `tests/http_transport.rs`, so it is never the gate. A `--bin filesystem-mcp-rs <filter>` run below is a per-task iteration aid, not acceptance.

---

### Task 1: `core::paths` — the single resolver

**Files:**
- Create: `src/core/paths.rs`
- Modify: `src/core/mod.rs` (add `pub mod paths;`)
- Test: inline `#[cfg(test)] mod tests` in `src/core/paths.rs`

**Interfaces:**
- Consumes: nothing (first task).
- Produces:
  - `pub fn state_dir() -> std::io::Result<PathBuf>` — the root, created on demand.
  - `pub fn db_path(name: &str) -> std::io::Result<PathBuf>` — a file directly in the root.
  - `pub fn sub_dir(kind: SubDir) -> std::io::Result<PathBuf>` — a created subdirectory.
  - `pub enum SubDir { Logs, Ocrs, Layouts, Safety, Tmp }` with `pub fn as_str(&self) -> &'static str`.
  - Override key `FS_MCP_STATE_DIR` (blank = default) — how tests redirect the root; registered in Task 6.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The override wins over the home directory, and the root is created on demand.
    /// This is also the seam every other test uses to avoid touching the real home dir.
    #[test]
    fn override_redirects_root_and_creates_it() {
        let tmp = std::env::temp_dir().join(format!("fsmcp-paths-{}", uuid::Uuid::new_v4()));
        let root = resolve_root(Some(tmp.clone())).expect("root resolves");
        assert_eq!(root, tmp);
        assert!(tmp.is_dir(), "root must be created on demand");
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Every subdirectory hangs off the root under its documented name.
    #[test]
    fn subdirs_hang_off_root() {
        let tmp = std::env::temp_dir().join(format!("fsmcp-paths-{}", uuid::Uuid::new_v4()));
        let logs = resolve_sub(Some(tmp.clone()), SubDir::Logs).expect("logs dir");
        assert_eq!(logs, tmp.join("logs"));
        assert!(logs.is_dir());
        assert_eq!(SubDir::Tmp.as_str(), "tmp");
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// An unresolvable home is an error, never a silent fallback to the current directory:
    /// falling back would scatter databases into whatever directory an agent started in.
    #[test]
    fn unresolvable_home_is_an_error() {
        let err = resolve_root_from(None, None).expect_err("must not fall back");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(err.to_string().contains("FS_MCP_STATE_DIR"));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --bin filesystem-mcp-rs core::paths -- --nocapture`
Expected: FAIL to compile — `resolve_root`, `resolve_sub`, `resolve_root_from`, `SubDir` do not exist.

- [ ] **Step 3: Write the implementation**

```rust
//! The one place that knows where this server keeps state.
//!
//! Everything durable and scratch lives under a single per-user root,
//! `~/.filesystem-mcp-rs/`, identically on Windows, macOS and Linux. State used to be
//! spread over four roots (`data_local_dir`, `data_dir`, two different temp subdirs), two
//! of which differ per OS and per Windows account, which made "where is it?" unanswerable.
//!
//! No other module may call `dirs::*` or `std::env::temp_dir()`; `paths_are_centralized`
//! in `src/core/paths_guard.rs` enforces that mechanically.

use std::io;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::env_spec;

/// A subdirectory of the state root. One variant per kind of state the server keeps,
/// so the names exist once instead of being spelled at each call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubDir {
    /// Per-process log files (wave 2).
    Logs,
    /// Downloaded OCR models.
    Ocrs,
    /// Saved window layouts.
    Layouts,
    /// Computer-control safety state.
    Safety,
    /// Scratch: captures, `run_command` output, temporary scripts. Swept by age.
    Tmp,
}

impl SubDir {
    /// Directory name on disk.
    pub fn as_str(&self) -> &'static str {
        match self {
            SubDir::Logs => "logs",
            SubDir::Ocrs => "ocrs",
            SubDir::Layouts => "layouts",
            SubDir::Safety => "safety",
            SubDir::Tmp => "tmp",
        }
    }
}

/// The state root, created if missing.
pub fn state_dir() -> io::Result<PathBuf> {
    resolve_root(env_spec::get("FS_MCP_STATE_DIR").map(PathBuf::from))
}

/// Path of a file directly in the state root (`stats.db`, `memory2.db`, `panic.log`).
/// The root is created; the file is not.
pub fn db_path(name: &str) -> io::Result<PathBuf> {
    Ok(state_dir()?.join(name))
}

/// A subdirectory of the state root, created if missing.
pub fn sub_dir(kind: SubDir) -> io::Result<PathBuf> {
    resolve_sub(env_spec::get("FS_MCP_STATE_DIR").map(PathBuf::from), kind)
}

/// Resolve and create the root. Split from [`state_dir`] so tests can inject an override
/// without mutating the process environment.
fn resolve_root(override_dir: Option<PathBuf>) -> io::Result<PathBuf> {
    let root = resolve_root_from(override_dir, dirs::home_dir())?;
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

/// Resolve a subdirectory and create it. Split for the same reason as [`resolve_root`].
fn resolve_sub(override_dir: Option<PathBuf>, kind: SubDir) -> io::Result<PathBuf> {
    let dir = resolve_root(override_dir)?.join(kind.as_str());
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Pure path arithmetic: the override wins, otherwise `<home>/.filesystem-mcp-rs`.
///
/// Returns an error rather than falling back to the current directory: a silent fallback
/// would put a database wherever the agent happened to start, and the resulting
/// "my memory disappeared" bug costs far more than a loud failure at startup.
fn resolve_root_from(override_dir: Option<PathBuf>, home: Option<PathBuf>) -> io::Result<PathBuf> {
    if let Some(dir) = override_dir {
        return Ok(dir);
    }
    match home {
        Some(h) => Ok(h.join(".filesystem-mcp-rs")),
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Cannot resolve the home directory; set FS_MCP_STATE_DIR to choose the state directory explicitly",
        )),
    }
}
```

Add to `src/core/mod.rs`, keeping the list alphabetical:

```rust
pub mod paths;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --bin filesystem-mcp-rs core::paths`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add src/core/paths.rs src/core/mod.rs
git commit -m "feat(paths): single resolver for the per-user state directory"
```

---

### Task 2: migration of pre-existing state

**Files:**
- Modify: `src/core/paths.rs` (add the migration function + tests)

**Interfaces:**
- Consumes: `SubDir`, `state_dir` from Task 1.
- Produces: `pub fn migrate(old: &Path, new: &Path) -> Migrated`,
  `pub enum Migrated { Moved, FreshStart, Ambiguous { old: PathBuf, new: PathBuf } }`,
  `pub fn legacy_local_dir() -> Option<PathBuf>`, `pub fn legacy_ctl_dir() -> Option<PathBuf>`.

`Ambiguous` is deliberately **not** an automatic choice: when both an old and a new database
exist, picking one silently binds the server to possibly the wrong data, and the user spends
days wondering where their notes went.

- [ ] **Step 1: Write the failing tests**

```rust
/// Old file present, new absent: the data moves and the old path is gone.
#[test]
fn migrate_moves_when_unambiguous() {
    let base = std::env::temp_dir().join(format!("fsmcp-mig-{}", uuid::Uuid::new_v4()));
    let old = base.join("old/memory2.db");
    let new = base.join("new/memory2.db");
    std::fs::create_dir_all(old.parent().expect("parent")).expect("mkdir");
    std::fs::write(&old, b"payload").expect("write");

    assert_eq!(migrate(&old, &new), Migrated::Moved);
    assert!(!old.exists(), "old path must be gone after a move");
    assert_eq!(std::fs::read(&new).expect("read"), b"payload");
    std::fs::remove_dir_all(&base).ok();
}

/// Both present: refuse to guess, touch nothing.
#[test]
fn migrate_refuses_when_both_exist() {
    let base = std::env::temp_dir().join(format!("fsmcp-mig-{}", uuid::Uuid::new_v4()));
    let old = base.join("old/memory2.db");
    let new = base.join("new/memory2.db");
    for p in [&old, &new] {
        std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        std::fs::write(p, b"payload").expect("write");
    }

    match migrate(&old, &new) {
        Migrated::Ambiguous { old: o, new: n } => {
            assert_eq!(o, old);
            assert_eq!(n, new);
        }
        other => panic!("expected Ambiguous, got {other:?}"),
    }
    assert!(old.exists() && new.exists(), "neither file may be touched");
    std::fs::remove_dir_all(&base).ok();
}

/// Nothing to migrate.
#[test]
fn migrate_reports_fresh_start() {
    let base = std::env::temp_dir().join(format!("fsmcp-mig-{}", uuid::Uuid::new_v4()));
    assert_eq!(migrate(&base.join("old.db"), &base.join("new.db")), Migrated::FreshStart);
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --bin filesystem-mcp-rs core::paths`
Expected: FAIL to compile — `migrate` / `Migrated` do not exist.

- [ ] **Step 3: Write the implementation**

```rust
/// Outcome of migrating one location from its pre-2026-09 home to the state root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Migrated {
    /// The old location existed and was moved to the new one.
    Moved,
    /// Neither location existed: the caller starts fresh.
    FreshStart,
    /// Both existed, or the move failed. Nothing was touched.
    Ambiguous { old: PathBuf, new: PathBuf },
}

/// Move `old` to `new` when that is unambiguous.
///
/// `rename` is instantaneous within a volume; across volumes it fails with a platform-specific
/// error, so we fall back to copy + remove. A failed copy leaves the original untouched and is
/// reported as `Ambiguous`, which is the honest answer: the data is still at the old path.
pub fn migrate(old: &Path, new: &Path) -> Migrated {
    let ambiguous = || Migrated::Ambiguous { old: old.to_path_buf(), new: new.to_path_buf() };
    match (old.exists(), new.exists()) {
        (true, false) => {
            if let Some(parent) = new.parent()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                warn!("Cannot create {}: {e}", parent.display());
                return ambiguous();
            }
            if std::fs::rename(old, new).is_ok() {
                info!("Migrated {} -> {}", old.display(), new.display());
                return Migrated::Moved;
            }
            match std::fs::copy(old, new).and_then(|_| std::fs::remove_file(old)) {
                Ok(()) => {
                    info!("Migrated (copied) {} -> {}", old.display(), new.display());
                    Migrated::Moved
                }
                Err(e) => {
                    warn!("Failed to migrate {} -> {}: {e}", old.display(), new.display());
                    ambiguous()
                }
            }
        }
        (true, true) => ambiguous(),
        (false, _) => Migrated::FreshStart,
    }
}

/// The pre-2026-09 root for files that lived in `data_local_dir`, used only to find data left
/// by older builds. Never used for new writes.
pub fn legacy_local_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("filesystem-mcp-rs"))
}

/// The pre-2026-09 root for computer-control state, which used `data_dir` under the name of
/// the crate this module was extracted from. Never used for new writes.
pub fn legacy_ctl_dir() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("computer-mcp-rs"))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --bin filesystem-mcp-rs core::paths`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add src/core/paths.rs
git commit -m "feat(paths): explicit migration with no silent choice when both locations exist"
```

---

### Task 3: rewire the durable call sites

**Files:**
- Modify: `src/main.rs:7473-7476` (panic log), `src/main.rs:7610-7623` (memory database)
- Modify: `src/tools/computer/ocrs_local.rs:37-39`, `src/tools/computer/safety.rs:220-222`,
  `src/tools/computer/driver/portable.rs` (layouts)

**Interfaces:**
- Consumes: `paths::db_path`, `paths::sub_dir`, `paths::migrate`, `paths::legacy_local_dir`, `Migrated`.
- Produces: `pub enum MemoryDbDecision { Use, Disabled(String) }` and
  `pub fn memory_db_decision(m: Migrated) -> MemoryDbDecision`. After this task no durable state
  is written outside the state root.

- [ ] **Step 1: Write the failing test**

In `src/core/paths.rs` tests — the memory store's refusal is the behaviour worth pinning:

```rust
/// An ambiguous memory database must disable the memory store rather than pick a file.
#[test]
fn ambiguous_memory_db_disables_the_store() {
    let decision = memory_db_decision(Migrated::Ambiguous {
        old: PathBuf::from("/old/memory2.db"),
        new: PathBuf::from("/new/memory2.db"),
    });
    match decision {
        MemoryDbDecision::Disabled(msg) => {
            assert!(msg.contains("/old/memory2.db") && msg.contains("/new/memory2.db"));
        }
        other => panic!("expected Disabled, got {other:?}"),
    }
    assert!(matches!(memory_db_decision(Migrated::Moved), MemoryDbDecision::Use));
    assert!(matches!(memory_db_decision(Migrated::FreshStart), MemoryDbDecision::Use));
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --bin filesystem-mcp-rs core::paths::tests::ambiguous_memory_db_disables_the_store`
Expected: FAIL to compile — `memory_db_decision` / `MemoryDbDecision` do not exist.

- [ ] **Step 3: Implement the decision and rewire the call sites**

In `src/core/paths.rs`:

```rust
/// What the caller should do with the memory database after migration.
#[derive(Debug)]
pub enum MemoryDbDecision {
    /// Open the database at the new path.
    Use,
    /// Do not open anything; report this message to the operator.
    Disabled(String),
}

/// Two memory databases mean two different sets of the user's notes. Choosing one silently is
/// how "where did my memories go" bugs are born, so the store stays off until a human decides
/// which file to keep.
pub fn memory_db_decision(m: Migrated) -> MemoryDbDecision {
    match m {
        Migrated::Moved | Migrated::FreshStart => MemoryDbDecision::Use,
        Migrated::Ambiguous { old, new } => MemoryDbDecision::Disabled(format!(
            "Memory tools disabled: a memory database exists both at {} and at {}. \
             Keep the one you want, delete or rename the other, then restart.",
            old.display(),
            new.display()
        )),
    }
}
```

In `src/main.rs`, replace the panic-log path (`main.rs:7473-7476`). The panic hook must not
itself panic, so an unresolvable root means the hook gives up quietly:

```rust
        let Ok(panic_log) = core::paths::db_path("panic.log") else {
            return;
        };
```

Replace the memory database block (`main.rs:7610-7623`):

```rust
        // Explicit path wins; otherwise the state root, migrating any pre-2026-09 database.
        let db_path = match args
            .memory_db
            .or_else(|| env_spec::get("FS_MCP_MEMORY_DB").map(PathBuf::from))
        {
            Some(explicit) => Some(explicit),
            None => match core::paths::db_path("memory2.db") {
                Ok(new) => {
                    let migrated = match core::paths::legacy_local_dir() {
                        Some(legacy) => core::paths::migrate(&legacy.join("memory2.db"), &new),
                        None => core::paths::Migrated::FreshStart,
                    };
                    match core::paths::memory_db_decision(migrated) {
                        core::paths::MemoryDbDecision::Use => Some(new),
                        core::paths::MemoryDbDecision::Disabled(msg) => {
                            warn!("{msg}");
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!("Memory tools disabled: cannot resolve the state directory: {e}");
                    None
                }
            },
        };
        if let Some(db_path) = db_path {
            info!("Memory v2 access mode: {}", access_mode);
            match SqliteMemoryStore::new(db_path, access_mode) {
                Ok(store) => server.memory_store = Some(Arc::new(store)),
                Err(e) => warn!("Failed to initialize memory v2 store: {}", e),
            }
        }
```

In `src/tools/computer/ocrs_local.rs:37-39` replace the `dirs::data_dir()` chain with
`crate::core::paths::sub_dir(crate::core::paths::SubDir::Ocrs)`, and update the module doc at
`ocrs_local.rs:8` to name the new location. Models are re-downloadable, so no migration is
attempted and the old directory is left for manual cleanup. Do the same for `safety.rs:220-222`
(`SubDir::Safety`) and the layouts path in `driver/portable.rs`, updating the doc comments at
`portable.rs:70` and `portable.rs:105`.

- [ ] **Step 4: Run the tests**

Run: `cargo test && cargo clippy --all-targets -- -D warnings`
Expected: PASS; clippy clean apart from the pre-existing `line_edit.rs:64` warning.

- [ ] **Step 5: Commit**

```bash
git add src/core/paths.rs src/main.rs src/tools/computer/
git commit -m "refactor(paths): durable state moves under the per-user state root"
```

---

### Task 4: rewire the scratch call sites

**Files:**
- Modify: `src/tools/computer/capture.rs:179`, `src/tools/computer/annotate.rs:100`,
  `src/main.rs:7806-7818` (`prepare_stream_paths`), `src/tools/process.rs:762` (temporary `.bat`)

**Interfaces:**
- Consumes: `paths::sub_dir(SubDir::Tmp)`.
- Produces: no new API; after this task nothing is written to the OS temp directory.

- [ ] **Step 1: Write the test that pins the location**

```rust
/// Scratch files land under the state root's tmp/, not in the OS temp directory.
#[test]
fn tmp_is_inside_the_state_root() {
    let root = std::env::temp_dir().join(format!("fsmcp-tmp-{}", uuid::Uuid::new_v4()));
    let tmp = resolve_sub(Some(root.clone()), SubDir::Tmp).expect("tmp dir");
    assert_eq!(tmp, root.join("tmp"));
    assert!(tmp.starts_with(&root));
    std::fs::remove_dir_all(&root).ok();
}
```

- [ ] **Step 2: Run it**

Run: `cargo test --bin filesystem-mcp-rs core::paths::tests::tmp_is_inside_the_state_root`
Expected: PASS already (Task 1 provides `resolve_sub`). It guards the rewiring that follows and
fails loudly if `SubDir::Tmp` is renamed. The real red gate for this task is Task 5.

- [ ] **Step 3: Rewire**

In `capture.rs:179` and `annotate.rs:100` replace `std::env::temp_dir().join("computer-mcp-rs")`
with `crate::core::paths::sub_dir(crate::core::paths::SubDir::Tmp)?`, propagating with `?` in the
surrounding `Result`-returning function.

In `main.rs:7806-7818` replace the default and the comment above it, which describes the old
behaviour:

```rust
    // Auto-generated stream logs go to the server's own tmp/ under the state root, so they
    // never litter the working directory and are swept by the same retention as every other
    // scratch file. Callers wanting them elsewhere set `stream_dir` explicitly.
    let dir = match args.stream_dir {
        Some(ref dir) => PathBuf::from(dir),
        None => core::paths::sub_dir(core::paths::SubDir::Tmp)
            .map_err(internal_err("Failed to resolve the state directory"))?,
    };
```

In `process.rs:762` replace `std::env::temp_dir()` with the same `SubDir::Tmp` directory.

- [ ] **Step 4: Run the tests**

Run: `cargo test && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/tools/computer/capture.rs src/tools/computer/annotate.rs src/main.rs src/tools/process.rs
git commit -m "refactor(paths): scratch files move to the state root's tmp/"
```

---

### Task 5: the guard test that keeps the rule true

**Files:**
- Create: `src/core/paths_guard.rs`
- Modify: `src/core/mod.rs`

**Interfaces:**
- Consumes: nothing at runtime; the module is test-only.
- Produces: the test `paths_are_centralized`.

This task converts a convention into a property. Without it the next person who needs a
directory reaches for `temp_dir()` and the whole class of drift returns.

- [ ] **Step 1: Write the failing test**

```rust
//! Enforces invariant I1 of the state-directory design: only `core::paths` decides where state
//! lives. A convention nobody checks is a convention that decays within months.

#[cfg(test)]
mod tests {
    use std::path::{Path, MAIN_SEPARATOR};

    /// Files allowed to name a platform directory, with the reason each one is exempt.
    const ALLOWED: &[&str] = &[
        // The resolver itself, including the legacy_* helpers used only to find old data.
        "core/paths.rs",
        // This guard names the forbidden strings in order to search for them.
        "core/paths_guard.rs",
        // Test scaffolding that needs a throwaway directory outside the state root.
        "mcp_setup/host.rs",
        "mcp_setup/tests.rs",
    ];

    const FORBIDDEN: &[&str] = &["data_local_dir", "data_dir(", "temp_dir("];

    #[test]
    fn paths_are_centralized() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        visit(&src, &src, &mut offenders);
        assert!(
            offenders.is_empty(),
            "state paths must come from core::paths; offenders: {offenders:#?}"
        );
    }

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
            if ALLOWED.contains(&rel.as_str()) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (i, line) in text.lines().enumerate() {
                if FORBIDDEN.iter().any(|f| line.contains(f)) {
                    offenders.push(format!("{rel}:{}: {}", i + 1, line.trim()));
                }
            }
        }
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --bin filesystem-mcp-rs paths_are_centralized`
Expected: FAIL at first, listing any call site Tasks 3-4 missed. That list is this task's value.

- [ ] **Step 3: Fix every offender the test reports**

Replace each with the matching `core::paths` accessor. Only genuine test scaffolding may join
`ALLOWED`, and only with a comment saying why. Do not widen `ALLOWED` to silence production code.

- [ ] **Step 4: Run the whole suite**

Run: `cargo test && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/paths_guard.rs src/core/mod.rs
git commit -m "test(paths): enforce that only core::paths resolves state locations"
```

---

### Task 6: register the new variables and correct the stale help text

**Files:**
- Modify: `src/env_spec.rs` — `vars()` at `:28-33`, new `fn paths_vars()`, `memory_vars()` help at
  `:64-67`, ocrs help at `:107`

**Interfaces:**
- Produces: `FS_MCP_STATE_DIR`, `FS_MCP_TMP_KEEP_HOURS` in the registry.

Reviewer's note: `FS_MCP_STATE_DIR` is an addition to the spec. The resolver needs a seam that
tests and unusual setups can redirect without touching `$HOME`; without it every path test would
have to mutate the process environment.

- [ ] **Step 1: Write the failing test**

```rust
/// Every key is registered exactly once, and any key naming a path describes where that path
/// actually is now.
#[test]
fn state_keys_are_registered_once_and_described_correctly() {
    let all = vars();
    for key in ["FS_MCP_STATE_DIR", "FS_MCP_TMP_KEEP_HOURS"] {
        assert_eq!(all.iter().filter(|v| v.key == key).count(), 1, "{key}");
    }
    let mem = all.iter().find(|v| v.key == "FS_MCP_MEMORY_DB").expect("memory db key");
    assert!(mem.help.contains("~/.filesystem-mcp-rs"), "stale help: {}", mem.help);
    assert!(!all.iter().any(|v| v.help.contains("<data>")), "stale <data> help text remains");
}
```

- [ ] **Step 2: Run it**

Run: `cargo test --bin filesystem-mcp-rs env_spec`
Expected: FAIL — the keys are missing and the memory help still says `<local data>`.

- [ ] **Step 3: Implement**

```rust
/// Where the server keeps its state, and how long scratch files survive there.
fn paths_vars() -> Vec<EnvVar> {
    vec![
        EnvVar {
            key: "FS_MCP_STATE_DIR",
            default: "",
            help: "State directory for every file this server owns. Blank = ~/.filesystem-mcp-rs.",
        },
        EnvVar {
            key: "FS_MCP_TMP_KEEP_HOURS",
            default: "24",
            help: "Delete scratch files under <state>/tmp older than this many hours.",
        },
    ]
}
```

Extend `vars()`; the group goes first because it describes where everything else lives:

```rust
pub fn vars() -> Vec<EnvVar> {
    let mut v = paths_vars();
    v.extend(net_vars());
    v.extend(memory_vars());
    v.extend(ctl_vars());
    v
}
```

Correct the two stale help strings:

```rust
            help: "SQLite file for the memory tools. Blank = ~/.filesystem-mcp-rs/memory2.db.",
```

```rust
        help: "Cache dir for the downloaded ocrs models. Blank = ~/.filesystem-mcp-rs/ocrs.",
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --bin filesystem-mcp-rs env_spec && cargo run -- --list-env`
Expected: PASS; `--list-env` shows both new keys and no `<data>` text.

- [ ] **Step 5: Commit**

```bash
git add src/env_spec.rs
git commit -m "feat(env): register state-dir keys and correct stale path help text"
```

---

### Task 7: sweep `tmp/` by age, once per interval across all processes

**Files:**
- Create: `src/core/housekeeping.rs`
- Modify: `src/core/mod.rs`, `src/main.rs` (call the sweep before the transport starts)

**Interfaces:**
- Consumes: `paths::state_dir`, `paths::sub_dir`, `env_spec::get`.
- Produces: `pub fn sweep_tmp(now: SystemTime) -> io::Result<usize>` (files deleted) and the
  injectable cores `fn sweep_dir(dir: &Path, max_age: Duration, now: SystemTime)` and
  `fn lease_in(root: &Path, kind: &str, every: Duration, now: SystemTime) -> io::Result<bool>`.

The lease exists because fifty processes starting at once must not all walk the same directory.
Wave 3 reuses it for statistics compaction — one retention mechanism, not three.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    /// Files past the age limit go; fresh ones stay.
    #[test]
    fn sweep_deletes_only_old_files() {
        let root = std::env::temp_dir().join(format!("fsmcp-sweep-{}", uuid::Uuid::new_v4()));
        let tmp = root.join("tmp");
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let old = tmp.join("old.log");
        std::fs::write(&old, b"x").expect("write");
        let day = Duration::from_secs(24 * 3600);

        // Nothing is old enough yet.
        assert_eq!(sweep_dir(&tmp, day, SystemTime::now()).expect("sweep"), 0);
        assert!(old.exists());

        // Seen from 48 hours in the future, the file is past the cutoff.
        let later = SystemTime::now() + Duration::from_secs(48 * 3600);
        assert_eq!(sweep_dir(&tmp, day, later).expect("sweep"), 1);
        assert!(!old.exists());
        std::fs::remove_dir_all(&root).ok();
    }

    /// The first caller takes the lease; the second is refused until the interval elapses.
    #[test]
    fn lease_admits_one_caller_per_interval() {
        let root = std::env::temp_dir().join(format!("fsmcp-lease-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("mkdir");
        let every = Duration::from_secs(3600);
        let now = SystemTime::now();

        assert!(lease_in(&root, "tmp", every, now).expect("first"));
        assert!(!lease_in(&root, "tmp", every, now).expect("second"));
        assert!(lease_in(&root, "tmp", every, now + Duration::from_secs(3601)).expect("later"));
        std::fs::remove_dir_all(&root).ok();
    }
}
```

- [ ] **Step 2: Run them**

Run: `cargo test --bin filesystem-mcp-rs core::housekeeping`
Expected: FAIL to compile — `sweep_dir` / `lease_in` do not exist.

- [ ] **Step 3: Implement**

```rust
//! Age-based retention for everything the server leaves on disk, and the lease that keeps dozens
//! of concurrent processes from all doing it at once.
//!
//! One mechanism serves `tmp/` now and `logs/` plus the statistics database in later waves:
//! three separate retention implementations would drift apart and each would need its own
//! concurrency story.

use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime};

use tracing::warn;

use crate::core::paths::{self, SubDir};
use crate::env_spec;

/// Delete files under `<state>/tmp` older than `FS_MCP_TMP_KEEP_HOURS`, at most once an hour
/// across all processes. Returns the number of files deleted (0 when another process holds the
/// lease).
pub fn sweep_tmp(now: SystemTime) -> io::Result<usize> {
    let root = paths::state_dir()?;
    if !lease_in(&root, "tmp", Duration::from_secs(3600), now)? {
        return Ok(0);
    }
    let hours = env_spec::get("FS_MCP_TMP_KEEP_HOURS")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(24);
    sweep_dir(&paths::sub_dir(SubDir::Tmp)?, Duration::from_secs(hours * 3600), now)
}

/// Delete entries in `dir` whose modification time is further in the past than `max_age`.
/// An entry that cannot be inspected or removed is logged and skipped: retention must never
/// abort startup.
fn sweep_dir(dir: &Path, max_age: Duration, now: SystemTime) -> io::Result<usize> {
    let mut deleted = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let age = match entry.metadata().and_then(|m| m.modified()) {
            Ok(modified) => now.duration_since(modified).unwrap_or_default(),
            Err(e) => {
                warn!("Cannot stat {}: {e}", path.display());
                continue;
            }
        };
        if age <= max_age {
            continue;
        }
        let removed = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match removed {
            Ok(()) => deleted += 1,
            Err(e) => warn!("Cannot remove {}: {e}", path.display()),
        }
    }
    Ok(deleted)
}

/// Claim the right to perform `kind` of housekeeping for the next `every`.
///
/// The lease is the modification time of a marker file, so the check is one stat and needs no
/// database. A lost race means one extra sweep, which is harmless — this guards against fifty
/// simultaneous directory walks, not against a second one.
fn lease_in(root: &Path, kind: &str, every: Duration, now: SystemTime) -> io::Result<bool> {
    let marker = root.join(format!(".housekeeping-{kind}"));
    if let Ok(modified) = marker.metadata().and_then(|m| m.modified())
        && now.duration_since(modified).unwrap_or_default() < every
    {
        return Ok(false);
    }
    let stamp = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    std::fs::write(&marker, stamp.to_string())?;
    Ok(true)
}
```

Add `pub mod housekeeping;` to `src/core/mod.rs` and call it once in `main.rs`, just before the
transport starts, where failure is reported but never fatal:

```rust
    match core::housekeeping::sweep_tmp(std::time::SystemTime::now()) {
        Ok(n) if n > 0 => info!("Housekeeping: removed {n} stale scratch files"),
        Ok(_) => {}
        Err(e) => warn!("Housekeeping skipped: {e}"),
    }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test && cargo clippy --all-targets -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/housekeeping.rs src/core/mod.rs src/main.rs
git commit -m "feat(housekeeping): leased age-based sweep for the scratch directory"
```

---

### Task 8: end-to-end check and working notes

**Files:**
- Modify: `CLAUDE.md` ("Key layout facts")

- [ ] **Step 1: Full suite and a real run**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo run -- --list-env`
Expected: PASS; `--list-env` lists the new keys.

- [ ] **Step 2: Verify the tree on a real machine**

Start the server once in stdio mode, stop it, then confirm `~/.filesystem-mcp-rs/` exists and
holds `memory2.db` (moved, if one existed) and `tmp/`. Confirm the old
`<data_local>/filesystem-mcp-rs/memory2.db` is gone after the move, and that nothing new was
written to the OS temp directory during the run.

- [ ] **Step 3: Record the outcome in CLAUDE.md**

Under "Key layout facts": `core::paths` is the only resolver, the tree, and the fact that
`paths_are_centralized` enforces it. Remove any statement that the new layout contradicts. A few
lines of facts, not prose.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: record the unified state directory in the working notes"
```

---

## Self-review notes

- **Spec coverage:** §4's tree (Task 1), migration including the ambiguous case (Tasks 2-3),
  `tmp/` sweep with a lease (Task 7), I1 enforced mechanically (Task 5), registry and help-text
  corrections (Task 6). Waves 2-3 (`logs/`, `stats.db`) are out of scope here by design;
  `SubDir::Logs` and `lease_in` exist so those waves plug in without reopening this one.
- **Addition beyond the spec:** `FS_MCP_STATE_DIR`, justified in Task 6.
- **Type consistency:** `SubDir`, `Migrated`, `MemoryDbDecision` are spelled identically in every
  task; `sweep_dir`/`lease_in` are the injectable cores, `sweep_tmp` the caller.
- **Known follow-up, not in this wave:** `memory_v2` never sets `journal_size_limit`
  (`memory_v2/sqlite.rs:209`), so its `-wal` grows unboundedly with dozens of open processes.
