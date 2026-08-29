# CLAUDE.md — filesystem-mcp-rs (working notes)

## What this is
Rust MCP server (rmcp 3.1.3 + axum, tokio, edition 2024), ~90 tools: filesystem, grep, run_command,
process mgmt, S3, HTTP, screenshots (xcap), clipboard (arboard), memory (SQLite). Published crate,
consumed from GitHub (ssh ref). Build: `cargo build` / test: `cargo test` / lint: `cargo clippy`.

## Key layout facts
- Tools live in `src/tools/*.rs`, registered via `#[cfg(feature = "...")]` in `src/tools/mod.rs`.
- Feature flags in Cargo.toml: `http-tools`, `s3-tools`, `screenshot-tools` (dep:image, xcap, arboard).
- `WindowInfo` (screenshot.rs) carries only xcap id/title/app_name/rect/is_minimized — NO hwnd/pid/exe.
- BUG.md — documented upstream serialization bug (see below).

## TODO
- [ ] PLAN2.md — computer-control suite (input/win/UIA/OCR). 3 planners done (arch: separate
      repo cglibs/computer-mcp-rs lib+bin; api: 20-tool surface; rust: windows-rs deps + risk table).
      Critic pass in progress. uiautomation crate = 0.25.0 (NOT 0.7.x as planner claimed).
- [ ] After implementation waves: update this file FIFO-style.

## Third-party bugs found (do not rediscover)
1. **`omc ask grok` broken on Windows** (omc 4.15.10 wrapper + grok 1.0.5): wrapper concatenates args
   unescaped into a shell (DEP0190) → any multi-word prompt splits at the inner shell →
   `unexpected argument '<word>'` from grok. Also `--prompt-file` through omc fails:
   omc always appends bare `-p` → clap `a value is required for '--single <PROMPT>'`.
   Workaround used: direct headless `grok --prompt-file ... --output-format plain`.
2. **filesystem-mcp write_file `content` must be a ContentRef object** `{"kind":"inline","text":...}`;
   a plain string (or a JSON-encoded-string of the object) fails with `expected internally tagged
   enum ContentRef`. Same caller-side serialization pitfall documented in BUG.md.

## Session notes (FIFO, prune when stale)
- 2026-08-29: computer-control FOLDED IN as `src/tools/computer/` (self-contained module,
  extraction recipe in mod.rs). Features: computer-tools umbrella + ctl-input/uia/ocr/notify/
  clip-files (ctl-uia implies ctl-input). 22 tools via per-domain #[tool_router(router=...,
  vis="pub(crate)")] + ToolRouter::merge (rmcp CANNOT cfg-gate #[tool] methods in one impl —
  S1 spike). Gate: safety::init_gate/gate() OnceLock. --ctl-ops-per-min CLI. Matrix: default +
  every ctl-* alone = green; clippy clean (only pre-existing line_edit.rs j-loop warning);
  452 tests + canary PASS. Unicode typing drops chars at 3ms interval in Win11 Notepad —
  paste mode (default) or ≥10ms; see PLAN2 §6.7.
- rmcp 3.1.3 facts: with_structured is fs's own WithStructured trait (main.rs), ToolRouter::merge
  exists, tool_router attr takes router=/vis=/server_handler=.
- 2026-08-28: computer-control planning DONE → PLAN2.md final (3 planners + self critic §10 + forks §11 resolved). Separate repo cglibs/computer-mcp-rs (lib+bin), 20 tools, uiautomation=0.25.
- grok 1.0.5 headless `-p` HANGS in non-TTY (3× verified, zero stdout/stderr; `doctor`/`models` instant). Interactive TUI works. Do not retry headless grok on this box. `omc ask grok` also broken (see above).
