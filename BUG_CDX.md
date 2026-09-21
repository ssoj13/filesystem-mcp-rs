# Codex-facing filesystem MCP diagnostic issue — 2026-09-21

## Missing-file `read_text_file(head)` emits an internal stack trace

- Reproduce: call `filesystem-mcp-rs/read_text_file` with `{"path":"C:/projects/projects.rust.cg/cgprojs/oh-my-harness/BUG3.md","head":1}` before that file exists. Repeated with missing `C:/projects/projects.rust.cg/cglibs/filesystem-mcp-rs/BUG_CDX.md`.
- Observed: a JSON-RPC `-32603` error says `Failed to read head: The system cannot find the file specified. (os error 2)`, then returns a full internal stack trace (including `aws_lc_0_39_0_jent_entropy_switch_notime_impl`).
- Expected: the file should still be reported as missing, but through a concise typed not-found diagnostic with no internal stack trace.
- Impact: a routine existence probe produces noisy, implementation-leaking output and obscures the actionable path. This is a diagnostic-quality bug, **not** a claim that a nonexistent file should be readable.
- Workaround: use directory listing or a prior existence check, then read an existing file. Preserve normal not-found semantics while improving the error response.

## Missing executable `run_command` emits an internal stack trace

- Reproduce on Windows: call `filesystem-mcp-rs/run_command` with `{"command":"actionlint .github/workflows/test.yml","cwd":"C:/projects/projects.openfx/_ak/ofx-rs","mode":"sync"}` when `actionlint` is not installed or not on `PATH`.
- Observed: JSON-RPC `-32603` with `Failed to spawn command: actionlint`, followed by an internal stack trace (including `aws_lc_0_39_0_jent_entropy_switch_notime_impl`).
- Expected: a concise typed executable-not-found error naming `actionlint` without the internal stack trace. The missing executable itself is expected, not a functional failure of the command runner.
- Impact: ordinary tool-availability checks generate noisy internals and make useful diagnostics harder to spot.
- Workaround: check executable availability before invoking `run_command`; do not treat missing optional `actionlint` as a CI validation result.

## Transient Windows mapped-section error during `edit_file`

- Observed on 2026-09-21: `filesystem-mcp-rs/edit_file` returned Windows OS error 1224 (`The requested operation cannot be performed on a file with a user-mapped section open`) while editing `C:/projects/projects.openfx/_ak/ofx-rs/crates/ofx-host/src/host_core.rs`.
- Immediate retry succeeded; no file corruption was observed. Reproduction conditions are unknown, so this is a transient incident, not evidence of a deterministic server fault.
- Suggested follow-up: return a concise typed, retryable diagnostic for this OS error and investigate contention with open Windows file mappings before considering any retry policy. Do not silently repeat writes whose completion is uncertain.

## Empty-directory `delete_path` refusal emits an internal stack trace

- Date: 2026-09-21.
- Reproduce: after confirming `C:/projects/projects.rust.cg/cglibs/maya-rs/third_party` exists and is empty, call `filesystem-mcp-rs/delete_path` with `{"path":"C:/projects/projects.rust.cg/cglibs/maya-rs/third_party"}` and omit `recursive`.
- Observed: JSON-RPC `-32602` correctly refuses directory deletion without `recursive=true`, but includes a full internal stack trace with `aws_lc_0_39_0_jent_entropy_switch_notime_impl`.
- Impact: an expected argument error exposes noisy server internals and obscures the one actionable correction. Refusal itself is appropriate; the stack trace is the defect.
- Safe fallback: verify the resolved target is within the intended workspace, confirm directory contents, then call `delete_path` with `recursive=true` only when deletion is authorized. This succeeded for the empty directory.

## Missing-directory `list_directory` emits an internal stack trace

- Date: 2026-09-21.
- Reproduce: call `filesystem-mcp-rs/list_directory` with `{"path":"C:/projects/projects.rust.cg/cglibs/maya-rs/docs/.old"}` before that directory exists.
- Observed: JSON-RPC `-32603` reports OS error 3 (`The system cannot find the path specified`) and includes a full internal stack trace with `aws_lc_0_39_0_jent_entropy_switch_notime_impl`.
- Impact: a routine existence check produces noisy server internals. The missing directory is an expected user error; exposing the stack trace is the server defect.
- Safe fallback: inspect the parent directory first with `list_directory`, create the missing directory with `create_directory` when intended, then list it. This succeeded.

## `run_command` shell-operator refusal emits an internal stack trace

- Date: 2026-09-21.
- Reproduce: call `filesystem-mcp-rs/run_command` with `command:"(Invoke-RestMethod -Uri 'http://127.0.0.1:9876/api/status' -Method Get) | ConvertTo-Json -Depth 5"`, `mode:"managed"`, and no `shell`.
- Observed: JSON-RPC `-32603` correctly refuses an unquoted `|` while shell is off, but includes a full internal stack trace. The command was invalid for this mode; exposing the stack is the server defect.
- Impact: expected argument validation fills the tool result with implementation internals and obscures the actionable `shell` hint.
- Safe fallback: pass `shell:"pwsh"` for PowerShell pipelines. The same command succeeded with that option.

## `mouse_drag` pressed at the old cursor position

- Date: 2026-09-21.
- Reproduce: put the cursor away from a draggable control, then call `mouse_drag` with `from` on that control and `to` elsewhere. The cursor follows the requested path, but the control does not acquire the drag. In `src/tools/computer/driver/win32/input.rs`, the first `SendInput` event used `MOUSEEVENTF_LEFTDOWN` with `dx/dy` but no `MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK`.
- Observed impact: Windows ignores `dx/dy` on the button-only event, so the button goes down where the cursor was before the call. Later move events visibly trace the path without dragging the intended target. The timed-drag test checked duration and focus, not target acquisition.
- Safe fallback for an installed older server: move the cursor to `from` first with `mouse_click` and `clicks:0`, then call `mouse_drag` with a nonzero `duration_ms`. Source fix moves to `from` before pressing.

## `edit_file` no-match validation emits an internal stack trace

- Date: 2026-09-21.
- Reproduce: call `edit_file` on `src/tools/computer/server_input.rs` with four literal edits, two of which use text absent from the file (for example, the absent wording “Settle at from with button down (ms)”).
- Observed impact: the tool correctly applies no edits and reports `2 of 4 edits produced zero matches`, but the expected validation error includes a full internal stack trace. No file corruption was observed.
- Safe fallback: re-read the exact source text and retry with matching literals; keep the edit atomic on no-match. Return a concise validation error without a stack trace.
