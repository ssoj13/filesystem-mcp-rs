# Wave 2 — Per-Process Logging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give this server logging that works when dozens of its processes run at once: one log file per process under `~/.filesystem-mcp-rs/logs/`, on by default in every transport mode, with retention under the housekeeping lease wave 1 built.

**Architecture:** No shared log file, therefore no rotation: a new process is a new file, a new day is a new directory. The stderr prohibition that protects the stdio handshake is untouched — only the file sink is added. Retention reuses `core::housekeeping`'s lease with a new `kind`, and ages a dated directory by its NAME rather than by walking its tree.

**Tech Stack:** Rust edition 2024, `tracing` 0.1 + `tracing-subscriber` 0.3.23 (`env-filter`, `fmt`), `time` 0.3 (`formatting`), `uuid` v4 — all already dependencies. No `tracing-appender`: it exists to rotate a shared file, which is the design this wave rejects.

**Spec:** `docs/superpowers/specs/2026-09-17-state-dir-logging-stats-design.md` §5 (and §3's invariants I1, I2, I6, I9)

## Global Constraints

- Every path comes from `core::paths`. `paths_are_centralized` (src/core/paths_guard.rs) fails the build on `dirs::`, `temp_dir(`, `env::home_dir`, `env::var("HOME"/"APPDATA"/"TEMP")` outside its ALLOWED list, and on `///` or `*.md` lines naming an abandoned location. Your files will not be on that list.
- **stdio must never write to stderr.** Any stderr output during the handshake closes the connection in MCP clients (`src/core/logging.rs:27-28`). This wave adds a FILE sink; it does not relax that rule.
- No silent fallbacks: if the log file cannot be opened, say so through the one channel that still works and keep serving — logging must never prevent the transport from starting.
- Never discard errors with `let _ =`; avoid `unwrap()`/`expect()` outside tests; avoid panicking indexing.
- `FS_MCP_*` keys live only in `src/env_spec.rs`; readers go through `env_spec::get` (blank = unset). A registered key must have a real reader — `every_registered_key_is_read_somewhere_in_the_sources` enforces it.
- Tests use `tempfile::TempDir`, never `std::env::temp_dir()`, and never write into the real `~/.filesystem-mcp-rs/`.
- Gates: plain `cargo test` and `cargo clippy --all-targets -- -D warnings`. There is no lib target, so `--lib` cannot run; `--bin filesystem-mcp-rs` runs only the unit tests and silently skips `tests/integration.rs` and `tests/http_transport.rs`, so it is never the gate. A `--bin filesystem-mcp-rs <filter>` run below is a per-task iteration aid, not acceptance.
- Rustdoc on every public item: what it is, why it exists, where it is used. No agent co-authorship trailers in commits.

---

### Task 1: `core::instance` — the process identity

**Files:**
- Create: `src/core/instance.rs`
- Modify: `src/core/mod.rs`
- Test: inline `#[cfg(test)] mod tests`

**Interfaces:**
- Produces: `pub fn id() -> &'static str` (a stable short id, unique per process) and `pub fn pid() -> u32`.

Wave 3 needs exactly this for its `sessions` table, and wave 1 already learned the lesson the hard way: `logs/fsmcp-<pid>` alone would splice two processes' files together after a pid is reused, and `sidecar_name` keyed by pid alone had to be fixed for the same reason.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The id is stable within a process — every caller must see the same string, or a log file
    /// name and the row that refers to it would disagree.
    #[test]
    fn id_is_stable_within_the_process() {
        assert_eq!(id(), id());
        assert!(!id().is_empty());
    }

    /// Short enough for a file name, long enough not to collide in practice, and containing
    /// nothing a filesystem would object to.
    #[test]
    fn id_is_filename_safe() {
        assert_eq!(id().len(), 8);
        assert!(id().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn pid_matches_the_process() {
        assert_eq!(pid(), std::process::id());
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --bin filesystem-mcp-rs core::instance`
Expected: FAIL to compile — the module does not exist.

- [ ] **Step 3: Implement**

```rust
//! Who this process is, for anything that must not be confused with another instance.
//!
//! A pid is not enough: the OS reuses pids, so `fsmcp-<pid>` would eventually splice two
//! processes' logs into one file, and wave 1 already had to fix a scratch name keyed by pid
//! alone for the same reason. The id is generated once and never changes, so a file name and
//! any later record naming that file agree.

use std::sync::OnceLock;

/// A short, filename-safe, per-process identity. Eight hex digits of a v4 uuid: enough that two
/// concurrent servers do not collide, short enough to read in a directory listing.
pub fn id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| uuid::Uuid::new_v4().simple().to_string()[..8].to_string())
}

/// This process's pid. Kept for diagnostics — never for identity, because pids are reused.
pub fn pid() -> u32 {
    std::process::id()
}
```

Add `pub mod instance;` to `src/core/mod.rs`, alphabetically.

- [ ] **Step 4: Run the tests** — `cargo test --bin filesystem-mcp-rs core::instance` → PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add src/core/instance.rs src/core/mod.rs
git commit -m "feat(instance): stable per-process identity for log files and later records"
```

---

### Task 2: logging that is on by default and never shared

**Files:**
- Modify: `src/core/logging.rs` (rewrite of the four init functions)
- Modify: `src/main.rs` (the `init_logging` call site and `--log`'s doc comment at `main.rs:156`)
- Test: inline in `src/core/logging.rs`

**Interfaces:**
- Consumes: `core::paths::sub_dir(SubDir::Logs)`, `core::instance::{id, pid}`, `env_spec::get`.
- Produces: `pub fn init_logging(mode: TransportMode, log_file: Option<String>) -> Result<LogTarget, Box<dyn Error>>` where `pub enum LogTarget { File(PathBuf), FileAndStderr(PathBuf), Stderr, Disabled }` — the caller reports it, and wave 3's `health` section will name the file.
- Produces: `pub fn log_path() -> std::io::Result<PathBuf>` — `<state>/logs/<YYYY-MM-DD>/fsmcp-<pid>-<instance>.log`.

The behaviour change that matters: in stdio with no `--log`, this crate currently installs NO subscriber at all (`logging.rs:32`), so every `warn!` is discarded — which is why wave 1 had to defer three visibility findings to this wave. A file sink is safe for the handshake; only stderr is not.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The name carries both pid and instance id, and lives under a dated directory, so two
    /// concurrent servers — or one pid reused tomorrow — never share a file.
    #[test]
    fn file_name_is_unique_per_process_and_dated() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let p = log_path_in(dir.path(), "2026-09-17").expect("path");
        let parent = p.parent().expect("parent");
        assert_eq!(parent.file_name().expect("name"), "2026-09-17");
        let name = p.file_name().expect("name").to_string_lossy().into_owned();
        assert!(name.starts_with("fsmcp-"), "{name}");
        assert!(name.contains(&crate::core::instance::pid().to_string()), "{name}");
        assert!(name.contains(crate::core::instance::id()), "{name}");
        assert!(name.ends_with(".log"), "{name}");
    }

    /// `FS_MCP_LOG=off` means no subscriber and no file — the only way to opt out.
    #[test]
    fn off_disables_everything() {
        assert!(matches!(target_for(TransportMode::Stdio, None, Some("off")), Plan::Disabled));
        assert!(matches!(target_for(TransportMode::Stream, None, Some("off")), Plan::Disabled));
    }

    /// stdio never gets a stderr sink, whatever else is configured — stderr during the handshake
    /// closes the connection in MCP clients.
    #[test]
    fn stdio_never_writes_to_stderr() {
        assert!(matches!(target_for(TransportMode::Stdio, None, None), Plan::File(_)));
        assert!(matches!(
            target_for(TransportMode::Stdio, Some("x.log".into()), None),
            Plan::File(_)
        ));
        assert!(matches!(target_for(TransportMode::Stream, None, None), Plan::FileAndStderr(_)));
    }

    /// An explicit `--log` path wins over the per-process file, because an operator who names a
    /// file is asking for that file.
    #[test]
    fn explicit_path_overrides_the_default() {
        match target_for(TransportMode::Stdio, Some("C:/tmp/explicit.log".into()), None) {
            Plan::File(p) => assert!(p.ends_with("explicit.log"), "{}", p.display()),
            other => panic!("expected File, got {other:?}"),
        }
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --bin filesystem-mcp-rs core::logging`
Expected: FAIL to compile — `log_path_in`, `target_for`, `Plan` do not exist.

- [ ] **Step 3: Implement**

Keep `TransportMode` as it is. Replace the rest with a decision function that takes its inputs as arguments (so tests need no environment), plus the sink construction:

```rust
/// What logging this process will do. Decided from the transport, `--log` and `FS_MCP_LOG`,
/// separately from performing it, so the decision is testable without touching the environment
/// or installing a global subscriber (which a process can only do once).
#[derive(Debug)]
pub enum Plan {
    /// Write to this file only. Every stdio run lands here.
    File(PathBuf),
    /// Write to this file and to stderr. Stream transport only.
    FileAndStderr(PathBuf),
    /// No subscriber at all: `FS_MCP_LOG=off`.
    Disabled,
}

/// Decide the plan. `level` is the raw `FS_MCP_LOG` value (already blank-filtered).
pub fn target_for(mode: TransportMode, log_file: Option<String>, level: Option<&str>) -> Plan {
    if level.is_some_and(|v| v.eq_ignore_ascii_case("off")) {
        return Plan::Disabled;
    }
    // An explicit path is the operator's choice and overrides the per-process default; the
    // per-process file is only the default location, not a rule about where logs may go.
    let file = match log_file {
        Some(p) => PathBuf::from(p),
        None => match log_path() {
            Ok(p) => p,
            // The state directory is unusable. stdio still must not touch stderr, so it runs
            // without logs rather than breaking the handshake; stream can still say so.
            Err(_) => {
                return match mode {
                    TransportMode::Stdio => Plan::Disabled,
                    TransportMode::Stream => Plan::Stderr,
                };
            }
        },
    };
    match mode {
        TransportMode::Stdio => Plan::File(file),
        TransportMode::Stream => Plan::FileAndStderr(file),
    }
}

/// `<state>/logs/<YYYY-MM-DD>/fsmcp-<pid>-<instance>.log`, directory created.
pub fn log_path() -> std::io::Result<PathBuf> {
    let root = crate::core::paths::sub_dir(crate::core::paths::SubDir::Logs)?;
    log_path_in(&root, &today())
}

/// The path arithmetic, split out so tests can supply a directory and a date.
fn log_path_in(root: &Path, day: &str) -> std::io::Result<PathBuf> {
    let dir = root.join(day);
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(format!(
        "fsmcp-{}-{}.log",
        crate::core::instance::pid(),
        crate::core::instance::id()
    )))
}
```

Add a `Plan::Stderr` variant for the stream-without-state-dir case, `today()` using `time`'s
`OffsetDateTime::now_utc()` formatted `YYYY-MM-DD` (UTC, matching wave 1's rule that stored time is
UTC), and rewrite `init_logging` to build the subscriber from the plan, returning the plan so
`main` can report where the log went. A file that cannot be opened degrades to `Disabled` in stdio
and to `Stderr` in stream, with the reason carried in the returned value — never a panic, never a
refusal to start.

A long-running process keeps the file it opened at startup even after midnight. That is
deliberate: reopening would mean a second writer path and a rotation mechanism, which is what this
design exists to avoid. State it in the module doc.

- [ ] **Step 4: Run the tests** — `cargo test --bin filesystem-mcp-rs core::logging` → PASS.

- [ ] **Step 5: Wire `main.rs`**

Report the returned plan at `info!` immediately after initialisation (the first line in the file
then says which file it is), and correct `--log`'s clap doc at `main.rs:156` to say that logging
goes to `~/.filesystem-mcp-rs/logs/<date>/` by default and that this flag overrides the location.
The `///`-line denylist added in wave 1 will catch that comment if it later goes stale.

- [ ] **Step 6: Commit**

```bash
git add src/core/logging.rs src/main.rs
git commit -m "feat(logging): a log file per process, on by default, never shared"
```

---

### Task 3: register the logging keys

**Files:**
- Modify: `src/env_spec.rs` (new `fn log_vars()`, extended into `vars()`)
- Modify: `src/core/logging.rs` (the readers — policy lives with the module that owns logs)

**Interfaces:**
- Produces: `FS_MCP_LOG` (default `info`), `FS_MCP_LOG_KEEP_DAYS` (`14`), `FS_MCP_LOG_MAX_MB` (`512`),
  and in `core::logging` the readers `level()`, `keep_days()`, `max_mb()` plus their
  `*_DEFAULT` constants.

Two rules wave 1 established and this task must follow: a registered key needs a REAL reader, not
an exemption (`every_registered_key_is_read_somewhere_in_the_sources`); and the constant and the
registry default must be asserted equal rather than kept in step by a comment — copy the pattern
from `TMP_KEEP_HOURS_DEFAULT` (`src/core/paths.rs`, asserted in `src/env_spec.rs`).

The default level is `info`, not `warn` as the spec drafted. The whole reason this wave exists is
that useful events were invisible: "Migrated X -> Y", "memory tools disabled", "removed N stale
scratch files" are all `info!`, and a `warn`-only default would hide exactly the record an operator
wants when something looks wrong. Update §5 of the spec to match.

- [ ] **Step 1: Write the failing test**

```rust
/// Each logging key is registered once, its help names the state root where a path is implied,
/// and the level default agrees with the constant the code actually uses.
#[test]
fn logging_keys_are_registered_and_agree_with_the_code() {
    let all = vars();
    for key in ["FS_MCP_LOG", "FS_MCP_LOG_KEEP_DAYS", "FS_MCP_LOG_MAX_MB"] {
        assert_eq!(all.iter().filter(|v| v.key == key).count(), 1, "{key}");
    }
    let level = all.iter().find(|v| v.key == "FS_MCP_LOG").expect("level key");
    assert_eq!(level.default, crate::core::logging::LEVEL_DEFAULT);
    assert!(level.help.contains("off"), "the only way to opt out must be documented");
    let keep = all.iter().find(|v| v.key == "FS_MCP_LOG_KEEP_DAYS").expect("keep key");
    assert_eq!(keep.default, crate::core::logging::KEEP_DAYS_DEFAULT.to_string());
    let max = all.iter().find(|v| v.key == "FS_MCP_LOG_MAX_MB").expect("max key");
    assert_eq!(max.default, crate::core::logging::MAX_MB_DEFAULT.to_string());
}
```

- [ ] **Step 2: Run it** — FAIL: the keys and the constants do not exist.

- [ ] **Step 3: Implement**

```rust
/// Where this server's own logs go and how long they stay.
fn log_vars() -> Vec<EnvVar> {
    vec![
        EnvVar {
            key: "FS_MCP_LOG",
            default: crate::core::logging::LEVEL_DEFAULT,
            help: "Log level for this server's own log file (error|warn|info|debug|trace). \
                   `off` disables logging entirely. Logs live in ~/.filesystem-mcp-rs/logs/.",
        },
        EnvVar {
            key: "FS_MCP_LOG_KEEP_DAYS",
            default: "14",
            help: "Delete log directories under ~/.filesystem-mcp-rs/logs/ older than this many days.",
        },
        EnvVar {
            key: "FS_MCP_LOG_MAX_MB",
            default: "512",
            help: "Total budget for ~/.filesystem-mcp-rs/logs/; oldest files are deleted first.",
        },
    ]
}
```

Extend `vars()` with `v.extend(log_vars());` after `paths_vars()`. In `core::logging`, add the three
constants and the three readers, each going through `env_spec::get` and falling back to its
constant — a malformed value logs a warning and uses the default rather than failing startup.

- [ ] **Step 4: Run** — `cargo test --bin filesystem-mcp-rs env_spec` → PASS, and `cargo run -- --list-env` shows the three keys.

- [ ] **Step 5: Commit**

```bash
git add src/env_spec.rs src/core/logging.rs
git commit -m "feat(env): register the logging keys with readers that own their defaults"
```

---

### Task 4: log retention under the existing lease

**Files:**
- Modify: `src/core/housekeeping.rs` (a `logs` kind alongside `tmp`)
- Modify: `src/main.rs` (the startup sweep call)

**Interfaces:**
- Consumes: `lease_due`/`lease_done` (already `pub(crate)`), `core::logging::{keep_days, max_mb}`.
- Produces: `pub fn sweep_logs(now: SystemTime) -> io::Result<Sweep>`, and the shared
  `fn sweep_by_budget(dir, max_bytes) -> io::Result<usize>`.

Three things wave 1 recorded specifically for this task, all of them load-bearing:

1. **Do not reuse `newest_mtime` here.** It walks an entry's whole tree, and a dated log directory
   would mean walking every log file on every cold start. A `logs/<YYYY-MM-DD>/` directory carries
   its age in its NAME — parse it, and fall back to mtime only for a directory whose name is not a
   date (which should not exist, and which the sweep must therefore not delete blindly).
2. **The lease `kind` must be `"logs"`, not a second lease mechanism.** Invariant I9 is already
   honestly reduced to "one lease, one age rule"; adding a second lease would finish it off.
3. **A live process's own log file must survive.** The sweep runs at startup in every process, so
   without care the newest server would delete the file another server is writing to. The date rule
   protects today's directory, but the SIZE budget does not — it deletes oldest-first until under
   the limit, and could walk into today. Exclude the current process's own file explicitly, and
   treat a file whose mtime is within the last hour as live regardless of the budget; say in the
   doc that the budget is therefore a soft limit, which is the honest description.

- [ ] **Step 1: Write the failing tests**

```rust
/// A dated directory is aged by its name, and today's is never touched.
#[test]
fn log_directories_age_by_their_name() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    for day in ["2026-09-01", "2026-09-16", "2026-09-17"] {
        let d = dir.path().join(day);
        std::fs::create_dir_all(&d).expect("mkdir");
        std::fs::write(d.join("fsmcp-1-aaaaaaaa.log"), b"x").expect("write");
    }
    let deleted = sweep_log_dirs(dir.path(), 14, "2026-09-17").expect("sweep");
    assert_eq!(deleted, 1, "only 2026-09-01 is older than 14 days");
    assert!(dir.path().join("2026-09-17").is_dir(), "today must survive");
    assert!(dir.path().join("2026-09-16").is_dir());
}

/// A directory whose name is not a date is left alone rather than guessed at.
#[test]
fn an_unexpected_directory_name_is_not_deleted() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let odd = dir.path().join("not-a-date");
    std::fs::create_dir_all(&odd).expect("mkdir");
    assert_eq!(sweep_log_dirs(dir.path(), 0, "2026-09-17").expect("sweep"), 0);
    assert!(odd.is_dir());
}

/// The budget deletes oldest first, and stops before anything written in the last hour.
#[test]
fn the_size_budget_spares_live_files() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let day = dir.path().join("2026-09-17");
    std::fs::create_dir_all(&day).expect("mkdir");
    let old = day.join("fsmcp-1-old.log");
    let live = day.join("fsmcp-2-live.log");
    std::fs::write(&old, vec![b'x'; 4096]).expect("write");
    std::fs::write(&live, vec![b'x'; 4096]).expect("write");
    set_mtime(&old, SystemTime::now() - Duration::from_secs(48 * 3600));

    let deleted = sweep_by_budget(dir.path(), 4096, SystemTime::now()).expect("budget");
    assert_eq!(deleted, 1);
    assert!(!old.exists(), "the oldest file goes first");
    assert!(live.exists(), "a file written in the last hour is never budgeted away");
}
```

- [ ] **Step 2: Run them** — FAIL to compile: `sweep_log_dirs`, `sweep_by_budget` do not exist.

- [ ] **Step 3: Implement** the two cores plus `sweep_logs(now)`, which takes the `"logs"` lease,
  applies the date rule, then the budget, and returns `Sweep::{Ran,LeaseHeld,Disabled}` exactly as
  `sweep_tmp` does (`FS_MCP_LOG_KEEP_DAYS=0` means disabled, matching `FS_MCP_TMP_KEEP_HOURS`).
  Call it from `main.rs` beside the `tmp` sweep, where a failure cannot prevent startup.

- [ ] **Step 4: Run** — `cargo test --bin filesystem-mcp-rs core::housekeeping` → PASS.

- [ ] **Step 5: Commit**

```bash
git add src/core/housekeeping.rs src/main.rs
git commit -m "feat(housekeeping): retain logs by date and by budget under the same lease"
```

---

### Task 5: close the three visibility debts wave 1 deferred

**Files:**
- Modify: `src/main.rs`, `src/tools/computer/safety.rs` (comments and wording only, unless a message is genuinely unreachable)
- Test: an integration-style test in `tests/` if one can be written without a live server

Wave 1 deferred three findings to this wave on the explicit grounds that per-process file logging
would make them visible. Now prove it, one at a time, and correct any comment that still says the
message is lost:

1. `safety.rs` — the audit-log warnings ("auditing is DISABLED for the lifetime of this process").
   Wave 1 moved `init_gate` after `init_logging` for this; confirm the ordering still holds and the
   warning now reaches the file.
2. `main.rs` — the memory-store refusal when two databases exist, and the new migration-failure
   message naming the running instance.
3. `core::housekeeping` — sweep failures and "removed N stale scratch files".

For each: state in your report HOW you verified it (a real run with the file inspected, not
reasoning), and paste the lines from the log file.

- [ ] **Step 1** Run the server in stdio mode with a deliberately broken state (e.g. `FS_MCP_STATE_DIR` pointing at a path you make read-only, or a second `memory2.db` staged at the new location) and capture the log file contents.
- [ ] **Step 2** Fix any comment that still claims a message goes nowhere — `main.rs`'s `init_gate` comment names plain stdio as the case where the warning is lost, which this wave changes.
- [ ] **Step 3** Commit: `docs(logging): record that the deferred visibility cases now land in the log`

---

### Task 6: documentation, guard, and the end-to-end check

**Files:**
- Modify: `README.md` (the env table gains the three keys and the logs location), `CLAUDE.md`, `CHANGELOG.md`, `docs/superpowers/specs/2026-09-17-state-dir-logging-stats-design.md` (§5: the level default is `info`; the file-per-process naming; retention as built)

- [ ] **Step 1** Update the docs. The `///` and `*.md` denylists added in wave 1 will fail the build if any of them still describe the OS temp dir or an abandoned location — run the gates and let the guard check your work.
- [ ] **Step 2** END-TO-END, reported honestly: start the server in stdio, stop it, and verify `~/.filesystem-mcp-rs/logs/<today>/fsmcp-<pid>-<id>.log` exists and contains the startup lines; start a SECOND server while the first runs and verify two distinct files with no interleaving; verify nothing was written to stderr in stdio mode (capture it and assert it is empty — this is the rule that protects the handshake); verify the `tmp` and `logs` sweeps both took their leases.
- [ ] **Step 3** Full gates: `cargo test && cargo clippy --all-targets -- -D warnings`.
- [ ] **Step 4** Commit: `docs: record per-process logging in the notes, README and spec`

---

## Self-review notes

- **Spec coverage:** §5's file-per-process naming (Task 2), default-on including stdio (Task 2),
  retention under the shared lease (Task 4), the env keys (Task 3), the deferred visibility debts
  (Task 5), docs (Task 6). The spec's `warn` default is deliberately changed to `info` and the spec
  is updated in Task 3 rather than left contradicting the code — wave 1 learned that cost twice.
- **Deviation from the spec, stated:** `FS_MCP_LOG` default `info`.
- **Type consistency:** `Plan` is spelled the same in Tasks 2 and 3; `Sweep` is wave 1's existing
  enum, reused unchanged; `LEVEL_DEFAULT`/`KEEP_DAYS_DEFAULT`/`MAX_MB_DEFAULT` are asserted against
  the registry in Task 3.
- **Known limits to state, not to fix:** a process keeps its start-of-day file past midnight; the
  size budget is soft, because a live file is never deleted to satisfy it.
