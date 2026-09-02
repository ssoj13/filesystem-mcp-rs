# AGENTS.md — filesystem-mcp-rs (working notes)

## What this is
Rust MCP server (rmcp 3.1.4 + axum, tokio, edition 2024), 130 tools: filesystem, grep, run_command,
process mgmt, S3, HTTP, screenshots (xcap), clipboard (arboard), memory (SQLite), and computer
control (26 ctl-tools behind ctl-* features). Published crate, consumed from GitHub (ssh ref).
Build: `cargo build` / test: `cargo test` / lint: `cargo clippy`.

## Key layout facts
- Tools live in `src/tools/*.rs`, registered via `#[cfg(feature = "...")]` in `src/tools/mod.rs`.
- Feature flags in Cargo.toml: `http-tools`, `s3-tools`, `screenshot-tools` (dep:image, xcap, arboard),
  `computer-tools` umbrella + `ctl-input/uia/ocr/notify/clip-files` (ctl-uia implies ctl-input).
  All four are in `default` since 2026-08-30 — computer-tools included.
- `src/env_spec.rs` is the ONE registry of `FS_MCP_*` vars. `install` writes them all into the
  client config (blank = unset), the hint block renders from it, `--list-env` prints it. Never
  hardcode an env key or its default anywhere else; readers must go through `env_spec::get`
  (blank/whitespace = unset) or a blank config value becomes a literal empty path/mode.
- `src/tools/computer/` — self-contained computer-control module (extractable; recipe in mod.rs):
  driver/mod.rs = OS seam (imp backend selection, portable types, Caps), safety/input/win/capture/
  steps/wait/uia/ocr/ocrs_local/find/clip/notify + server_*.rs (per-domain #[tool_router] impls).
- v0.2.1: BUG.md resolved (tolerant ContentRef, line/column errors, 64 KiB inline/chunk limits).

## Verified facts (do not re-derive)
- rmcp 3.1.4: with_structured is fs's own WithStructured trait (main.rs); ToolRouter::merge exists;
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
