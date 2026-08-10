# BUG3 — filesystem-mcp-rs issues (exr-rs / cryptomatte session)

Issues found while using MCP from `cglibs/exr-rs` (cryptomatte port), 2026-08-10.
Same format as `BUG2.md`.

---

## BUG3-001: `write_file` / `CallMcpTool` — abort mid-flight on large UTF-8 payloads

- **Status:** fixed (root cause) — Content Plane SSOT
- Large payloads: `blob_begin` / `blob_append` / `blob_finalize`, then `write_file` with `{kind:"blob",id}`. Inline ContentRef hard-capped at 8 KiB (`inline_too_large`).

---

## BUG3-002: `edit_file` — `Failed to parse arguments string as JSON object`

- **Status:** fixed (root cause) — `oldText`/`newText` are ContentRef; large rewrites go through blob + `write_file`, not mega JSON edits.

---

## BUG3-003: `run_command` + `python -c` patching corrupts string literals / NUL bytes

- **Status:** fixed (root cause) — escape hatch removed; `stdin` is ContentRef; text mode rejects NULs; large scripts = write via blob then exec file.

---

## BUG3-004: `grep_files` — intermittent `server: Required` / `toolName: Required`

- **Status:** documented (host/agent wiring) — not a server bug
- Host `CallMcpTool` requires top-level `server` + `toolName`. Putting them only inside `arguments` (or omitting them) yields these errors.
- Guidance: `src/docs/mcp_policy.md` section **CallMcpTool wiring (host)**.

---

## Fix summary

Introduced `src/core/content_plane.rs` as SSOT for payload ingress. Breaking: no bare-string `content`/`stdinData`/`stdinFile`/`data` shims.
