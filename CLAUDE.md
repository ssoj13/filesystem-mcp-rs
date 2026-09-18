# CLAUDE.md — filesystem-mcp-rs (working notes)

## What this is
Rust MCP server (rmcp 3.1.3 + axum, tokio, edition 2024): filesystem, grep, run_command,
process mgmt, S3, HTTP, screenshots (xcap), clipboard (arboard), memory (SQLite), and computer
control (26 ctl-tools behind ctl-* features). **132 tools on a default build, 2026-09-17** — the
count depends on which features are compiled in, so re-derive it (`tools/list` over a stdio
handshake) rather than trusting this line; `--list-features` says which groups this build has. Published crate, consumed from GitHub (ssh ref).
Build: `cargo build` / test: `cargo test` / lint: `cargo clippy --all-targets -- -D warnings`.
Format: `cargo fmt --check` is a gate (CI runs it on Linux only). The crate was reflowed once in
`90a3e7a`, listed in `.git-blame-ignore-revs` — never hand-wrap against rustfmt, run it.
The test gate is **plain `cargo test`**, never `--bin filesystem-mcp-rs`. There is no lib target, so
`--lib` cannot run; but `--bin` silently skips `tests/integration.rs` and `tests/http_transport.rs`
(three binaries: unit + integration + http_transport). `--bin <filter>` is fine to iterate on one
unit module; it is not the gate. The gate is 637 tests: 569 unit + 64 integration + 4 http.
`cargo mutants --in-diff <diff>` is how this project checks whether the tests actually test
anything — a surviving mutant is a line no assertion pins. It builds its baseline from HEAD, so it
needs a COMMITTED, compiling tree: commit first, then run. `mutants.out/` is gitignored.
CI (`.github/workflows/ci.yml`) runs all three gates; clippy runs on every OS, because half this
crate is behind `#[cfg(windows)]` and a Linux-only pass never sees the driver.

## Key layout facts
- Tools live in `src/tools/*.rs`, registered via `#[cfg(feature = "...")]` in `src/tools/mod.rs`.
- Feature flags in Cargo.toml: `http-tools`, `s3-tools`, `screenshot-tools` (dep:image, xcap, arboard),
  `computer-tools` umbrella + `ctl-input/uia/ocr/notify/clip-files` (ctl-uia implies ctl-input).
  All four are in `default` since 2026-08-30 — computer-tools included.
- `src/env_spec.rs` is the ONE registry of `FS_MCP_*` vars. `install` writes them all into the
  client config (blank = unset), the hint block renders from it, `--list-env` prints it. Never
  hardcode an env key or its default anywhere else; readers must go through `env_spec::get`
  (blank/whitespace = unset) or a blank config value becomes a literal empty path/mode.
- **Per-process logging** (`src/core/logging.rs`, wave 2): on by default in every transport at
  `info`, one file per process at `<state>/logs/<YYYY-MM-DD>/<machine>_<timestamp>.log` (host
  name from `sysinfo`, `unknown` if it cannot be read; the stamp carries milliseconds so two
  servers starting in the same second cannot collide). No shared file, therefore no rotation and
  no `tracing-appender`. `--log <FILE>` overrides the path; `FS_MCP_LOG=off` is the only opt-out.
  **stdio still never touches stderr** — that rule lives in the pure `sinks(&Plan)`, so any stdio
  path gaining a stderr sink fails a test. **Nothing deletes a log, ever** — there is no log
  retention; `core::housekeeping` sweeps `<state>/tmp` only. `FS_MCP_LOG_KEEP_DAYS`/`_MAX_MB` are
  vestigial: still registered in `env_spec`, read by `core::logging` so the registry's own test
  passes, acted on by nothing. Remove the registry entries and those readers together.
- Any live run of the binary must point `FS_MCP_STATE_DIR` at a temp directory, or it writes into
  the developer's real `~/.filesystem-mcp-rs/`. The suite does this for every server it spawns.
- `src/tools/computer/` — self-contained computer-control module (extractable; recipe in mod.rs):
  driver/mod.rs = OS seam (imp backend selection, portable types, Caps), safety/input/win/capture/
  steps/wait/uia/ocr/ocrs_local/find/clip/notify + server_*.rs (per-domain #[tool_router] impls).
- v0.2.1: BUG.md resolved (tolerant ContentRef, line/column errors, 64 KiB inline/chunk limits).
- State lives under ONE root, `~/.filesystem-mcp-rs/`, same on every OS: `memory2.db`, plus
  `tmp/` (captures, run_command stream logs, temp scripts - swept by age,
  `FS_MCP_TMP_KEEP_HOURS`, default 24), `ocrs/`, `layouts/`, `safety/`, and three that are written
  once per run and never swept: `logs/`, `panics/` (one crash report per panic) and `stats/` (the
  tool-call counters as JSON, wave 3). All three are named
  `<YYYY-MM-DD>/<machine>_<timestamp>.<ext>` by the one helper `core::paths::run_file(kind, ext)`
  - the only place the host name, the timestamp format and the dated directory exist.
  `FS_MCP_STATE_DIR` moves the root and must be absolute. The OS temp dir is no longer used.
- `src/core/paths.rs` is the ONLY resolver. `paths_are_centralized` (src/core/paths_guard.rs) fails
  the build on `dirs::*` / `temp_dir(` / `env::home_dir` outside its ALLOWED list, and on any `///`
  line naming an abandoned location (`<local data>`, `computer-mcp-rs`, `%LOCALAPPDATA%`, ...).
  It scans only `src/` and `tests/` - a `build.rs` or a dependency would be invisible to it.
- `memory2.db` migrates from the old data dir on first start; if it exists in BOTH places, or the
  move fails, nothing moves and the memory tools stay OFF. Refusing to CHOOSE between two databases
  is deliberate - do not "fix" that. `Migrated::Ambiguous` carries a `Cause` so the two cases get
  different advice; a failed move is usually an older instance still holding the file open.

## Verified facts (do not re-derive)
- rmcp 3.1.3 (Cargo.toml:26 - these notes said 3.1.4 until 2026-09-17): with_structured is fs's own WithStructured trait (main.rs); ToolRouter::merge exists;
  tool_router attr takes router=/vis=/server_handler=; rmcp CANNOT cfg-gate #[tool] methods in one
  impl (S1 spike) — per-domain routers + ToolRouter::merge.
- windows 0.62: SendInput(&[INPUT], i32); IsWindow(Option<HWND>); GetProcessDpiAwarenessContext
  REMOVED — use GetThreadDpiAwarenessContext; HWND is !Send — never return from spawn_blocking.
- xcap 0.9.8 Window::id() == hwnd.0 as u32. No from_hwnd ctor.
- windows-future 0.3: no blocking .get(); use futures::executor::block_on(op.into_future()).
- uiautomation 0.25: element_from_handle(Handle::from(hwnd)); UIMatcher::new(automation).from(el)
  .depth(d).timeout(ms).find_all(); get_bounding_rectangle() -> f32 Rect.

## ctl-t API quirks (verified live)
- capture CapTarget accepts ALL cursor shapes: {cursor:{size:N}}, {cursor:N}, {size:N} via
  CursorSize untagged enum (4813941). Wire-shape mismatch killed nested form until this fix.
- key_type: paste mode (default) 100x faster than unicode; focus-gated (refused if focus moved).
- chars-mode typing below ~25ms mangles runs (last-char repeats, deterministic) — 30ms verified.
- Unicode typing drops chars at 3ms interval in Win11 Notepad — paste mode (default) or ≥30ms.

## Third-party bugs found (do not rediscover)
1. `omc ask grok` broken on Windows (DEP0190 + bare -p). Workaround: direct headless grok.
2. grok 1.0.5 headless `-p` HANGS in non-TTY (3× verified). Interactive TUI works.
3. filesystem-mcp write_file `content` must be ContentRef object (bare string → inline tolerated
   since 0.2.1, but canonical form is ContentRef object).

## Session notes (FIFO, prune when stale)
- 2026-09-17: `shell:"bash"` on Windows no longer trusts PATH. `resolve_shell_program` →
  `bash_candidates()` (git `--exec-path` cached in a OnceLock → `git.exe` location → install roots
  → PATH) → `pick_bash()` (pure, unit-tested) which REFUSES a System32/SysWOW64/WindowsApps
  bash.exe (the WSL launcher: eats `$var`, drops the `env` map, Windows paths invalid). Live-probed:
  `/proc/version` reports `MINGW64_NT`, cwd is the real path, `env` arrives.
- 2026-09-14: bug5 `run_command` — reject leftover `$NAME` in command/args; failFast default true;
  `pwsh` vs `powershell.exe`; `install` snapshots process PATH into every client env (no registry).
  Workaround remains: script file + `-File` if the host already stripped `$`. 492 tests green.
- 2026-08-30: env config overhaul. computer-tools now default; `src/env_spec.rs` registry feeds
  install-env + hints + new `--list-env`; `FS_MCP_MEMORY_ACCESS_MODE`/`_DB` and `FS_MCP_CTL_BACKEND`
  now read via `env_spec::get` (empty string used to crash the server / kill the memory store).
  Verified: build+clippy clean (only pre-existing line_edit.rs:64 warning), 547 tests green,
  project-scope install writes all 10 keys and the SUPPORTED ENV block. Non-Windows build of
  computer-tools NOT verified — cross-check from this host fails in ring/aws-lc-sys/wayland-sys
  (missing native toolchain, fails identically without computer-tools, so not a regression).
- 2026-08-30: capture CapTarget shape fix — CursorSize untagged enum ({cursor:{size}}, {cursor:N},
  {size:N}); 4/4 forms verified live. v0.2.1 deployed to .cargo/bin (md5 867e065e). Pushed 4813941.
- 2026-08-29: driver abstraction landed (driver/mod.rs as OS seam). Live probe found cursor-target
  wire-shape bugs; CursorSize enum fixes all forms. 26 ctl-tools, 464 tests green.
- PLAN2.md — design doc for computer control (3 planners + critic §10 + forks §11 resolved).
- grok 1.0.5 headless `-p` HANGS in non-TTY (3× verified). `omc ask grok` also broken. Do not retry.
