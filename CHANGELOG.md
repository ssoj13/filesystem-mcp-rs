# Changelog

## [Unreleased]

### Fixes — `edit_file` / `grep_files` host-drop (bug.md)

- **`edit_file` / `bulk_edits` `oldText`/`newText` accept a UTF-8 string again** (`TextOrRef`). ContentRef objects still work for blobs. Hosts (Grok) drop nested `{kind:inline,text}` — especially when `text` contains `{` — and the call died as `missing field newText`. Short snippets are strings; `write_file` / `stdin` stay ContentRef-only.
- Missing `newText` now names the contract (send a string or ContentRef) instead of a bare serde missing-field.
- **`grep_files.path`** defaults to empty and aliases `root` / `dir` / `directory`. Empty path is a readable `invalid_params`, not `missing field path`. `filePattern` / `glob` / `include` / `file_pattern` all bind.

### Breaking — Content Plane SSOT

- **Payload ingress is unified behind `ContentRef`** (`src/core/content_plane.rs`). `write_file.content`, `write_binary.data`, and `run_command.stdin` are ContentRef objects (`inline` / `base64` / `path` / `blob`), not bare strings. `edit_file` / `bulk_edits` snippets are `TextOrRef` (string **or** ContentRef). Inline/base64 hard-capped at 8 KiB.
- **New tools:** `blob_begin`, `blob_append`, `blob_finalize`, `blob_stat` for chunked staging of large agent-authored content. Pass `{kind:blob,id}` into write/edit/run.
- **Removed:** `run_command.stdinData` / `stdinFile` (use `stdin` ContentRef). Bare-string `write_file.content` / base64-string `write_binary.data`.
- **Why:** Hosts mangle or abort mid-flight on large nested UTF-8 in tool-argument JSON; agents then fall back to `python -c` and corrupt files. Control plane stays small; bytes move via path or blob sessions.

### `read_pdf` quality contract (BUG2-001)

- Default **`normalize=true`**: treat ZWSP runs as word separators and join short spaced glyph fragments (`Ta ble` + ZWSP → `Table of`).
- Structured **`quality`**: `score`, `warnings`, `suspiciousTokens`, density ratios. Low score / `extraction_quality_degraded` / `suspicious_encoding_tokens` means agents must not treat the extract as source of truth (broken ToUnicode maps are not reconstructible).
- Optional **`includeRaw`** returns unnormalized `rawText`.

### Fixes — correctness audit (BH-07 … BH-33)

A systematic bug hunt over the whole tool surface. The common theme is **silent data loss reported as success**: a tool returned `exitCode: 0` / `identical: true` / an empty-but-clean result while it had actually dropped, corrupted, or fabricated data. Each item below is a real defect that a caller could not have detected from the response.

**Files & editing**

- **`edit_file`/`edit_lines`/`extract_lines`/`bulk_edits` no longer rewrite a file as UTF-8/LF** (BH-07). Editing a CRLF, UTF-8-BOM, or legacy-codepage file silently re-encoded the *whole* file. New `TextFile` primitive in `fs_ops` records the source encoding, BOM, and newline convention; text is LF-normalized in memory for uniform matching and `encode()` restores the original representation on write. `ensure_roundtrippable()` refuses a file that did not decode losslessly instead of writing back `U+FFFD`. Read-only paths (`read_text_file`, grep) keep the lenient reader.
- **`write_file` staging temp name is now unique** (BH-07). The temp name was derived from the file stem, so `config.json` and `config.yaml` written concurrently both staged to `config.tmp_mcp_write` and one write's bytes could land under the other's name. The name now carries pid + a per-process counter, and a failed rename cleans up the staging file.
- **`move_file` no longer silently overwrites an existing destination** (BH-08). It documented "fails if destination exists", but `fs::rename` overwrote. It now rejects an existing destination.
- **`copy_file` no longer destroys the file on a self-copy** (BH-08). With `source == destination` the overwrite step deleted the destination (= the source), then the copy failed — the file was gone. Self-copy is now rejected up front, and a file copy stages into a temp sibling and atomically renames into place, so a failed or partial copy can never truncate a pre-existing destination.
- **`expand_fancy` no longer mangles non-ASCII replacements** (BH-18). It iterated *bytes* and cast each with `b as char` (Latin-1), turning Cyrillic replacements into mojibake; a zero-width fancy match advanced the cursor by a raw `+1`, splitting a codepoint (panic). Both now operate on chars/`len_utf8`.
- **`edit_lines` no longer silently drops snake_case `end_line`** (mangled-method replace). Under `rename_all = "camelCase"`, LLMs sending `end_line` / `dry_run` / `file_pattern` / … had those keys ignored, so a range replace became a single-line splice and left the old tail in place. Added serde aliases (same pattern as BH-09) across the edit/extract/bulk family and related args (`edit_file`, `extract_lines`, `extract_symbols`, `bulk_edits`, grep/search/tree `exclude_patterns` / `file_pattern`). Overlapping `edit_lines` ranges are now rejected up front with a clear error instead of failing later with a confusing out-of-range after shrink.

**Grep**

- **After-context is no longer attributed to the wrong file** (BH-10). Parallel workers shared one `Vec` and appended after-context to its global last element, so under threads the trailing context of file A could attach to a match from file B — fabricated output lines. `ContentSink` now owns a per-file match buffer and flushes a file's matches into the shared state as one contiguous in-order batch. Test: 200 files × 10 runs, deterministic failure on the old code.
- **Grep argument aliases from the ripgrep/built-in-`Grep` vocabulary are honored** (BH-09). `glob` was silently dropped (widening the search to the whole tree) and `head_limit` was ignored. Added serde aliases — `glob`/`include` → `filePattern`, `head_limit`/`limit`/`maxCount` → `maxMatches`, `-i`/`ignoreCase` → `caseInsensitive`, `-A`/`-B`/`after`/`before` → `contextAfter`/`contextBefore`, plus accept-and-ignore `lineNumbers`/`-n`. Deliberately *not* `deny_unknown_fields`, which would break those clients.
- **`count` mode respects `maxMatches` and reports the true total** (BH-23). Counts were unbounded and `matchesFound` came back as `0`; a CAS count budget now bounds them and feeds `total_matches`, and `FilesWithoutMatch` stops after the first match proof.
- **`filesSearched`/`bytesSearched` count only files actually searched** (BH-24). They were incremented at enumeration time, so binary, unreadable, and skipped files (and their sizes) were reported as searched. `filesSeen` remains the candidate counter.
- **A fancy-engine runtime error no longer looks like "no more matches"** (BH-11). The match loop did `Err(_) => break` — a silent partial result. Errors now propagate; multiline anchors are aligned with the regex engine.
- **A huge `contextAfter` no longer panics the grep worker** (BH-31). The fancy path's context window used unchecked arithmetic (`usize::MAX` via the string form overflowed); now `saturating_add` + clamp.
- **An unknown `engine` value errors instead of silently falling back to `regex`** (BH-18c), which previously surfaced as a confusing "invalid pattern" error for a valid fancy pattern.
- Removed the legacy `grep::grep_files` path (BH-25): dead in production, reachable only from 9 tests, which now exercise `grep_files_fast`.

**`run_command` / process**

- **Command output is no longer lost while the call reports success** (BH-13). Three I/O failure paths were swallowed: `open_output_file` used `.ok()` (an unopenable `stdout_file` yielded no writer while the inline retain window was still trimmed on the assumption the file held the rest), the capture tasks flattened errors with `unwrap_or_default()`, and the detached drain discarded its `Result`. All three now propagate; any failure sets `captureTruncated` instead of an empty-but-successful result.
- **`envPrepend` + `envAppend` now stack, and `clearEnv` is honored** (BH-14). Env composition re-read `std::env::var` after `env_clear` (re-injecting the server's environment) and append overwrote the prepend result. The environment is now composed as a single map.
- **Argument boundaries survive shell mode** (BH-15). The argv vector was joined with spaces, so a spaced or metacharacter-bearing argument split into several. Each argument is now quoted per target shell (sh/bash single-quote, pwsh single-quote, cmd double-quote) before joining.
- **`outputFilter` no longer fails open** (BH-26). An exclude-only filter was inert (`is_active()` ignored `exclude`), `max_lines` counted non-content lines and was checked too late (`max_lines: 0` still emitted content), and an invalid filter regex was silently dropped. An empty `include` now means "match all, then exclude"; an invalid regex errors.
- **A failed `kill_process` no longer unregisters the process** (BH-27). On Windows `force: false` is a no-op, so the manager forgot a still-live orphan.
- **Multi-line `cmd` commands are no longer mojibake'd** (BH-28). The generated `.bat` is UTF-8 but cmd read it in the console code page — the non-ASCII limitation noted under the BUG5 fix below. The script now emits `chcp 65001 >nul`, so that limitation is gone.
- **`timeout_ms` + `kill_after_ms` no longer wrap** (BH-32): unchecked add could produce a tiny deadline and kill the child instantly; now `saturating_add`.
- **`cwd` accepts `workingDir`/`working_dir`/`workdir`/`dir` aliases.** The unknown key was silently dropped by serde and the child ran in the session's primary directory — the root cause of a stale-build report.
- **`file_touch` now advances mtime on Windows.** An append-open without writing bytes is a no-op for NTFS mtime, so build tools (cargo) never saw the touch; mtime is now set explicitly via `set_times`. The Unix branch is unchanged.

**HTTP / S3 / watch / PDF / memory / compare**

- **A truncated download is never published as success** (BH-17). `http_download`/`http_download_batch` wrote an incomplete file under a success response when the body exceeded `maxBytes`; the same for `s3_get` with an `output_path`. Both now fail hard without writing, and the error tells the caller to raise `maxBytes`.
- **`watch_file` no longer reports a sibling's change as the target's** (BH-19). It watches the parent directory; the callback now filters `event.paths` by the target file name.
- **`tail_file` follow mode actually returns content** (BH-19). `follow_content` was built and then discarded by the handler — follow was a silent no-op. The result now carries `followContent`/`followLines`. Byte-mode tail could also seek into the middle of a multibyte codepoint and mis-decode the window; leading UTF-8 continuation bytes are now dropped so the window starts on a char boundary. The blocking watcher thread parked for `timeout + 1s` and could not be aborted (`JoinHandle::abort()` cannot stop `spawn_blocking` work), holding a blocking-pool slot; it now waits on a stop channel.
- **`read_pdf` honors the `pages` argument** (BH-22). It advertised page ranges, parsed the range, and then returned the entire document — with `maxChars` truncation the requested pages were often absent from the result. Page text is now selected via the form-feed (`\x0C`) separators `pdf-extract` emits; when no separators are present it fails loudly rather than silently returning the whole document under a range request.
- **`mem_search` no longer hides authorized results** (BH-20). SQL `LIMIT` was applied *before* the visibility/type/tag/access filters (which run in Rust), so the newest N rows could monopolize the limit even when every one of them was filtered out — a search that should have returned 10 items returned 0. It now over-fetches and paginates newest-first (`ORDER BY created_at DESC, id DESC` for a total order, so `OFFSET` paging can't skip or duplicate) until `limit` authorized items or store exhaustion.
- **`mem_update` can no longer write an illegal scope/visibility pair** (BH-21), e.g. `visibility: session` with no `session_id`, which made the item permanently unreadable under `enforce_visibility`. `update` now runs the same `validate_scope_for_visibility` check as `put`.
- **`compare_directories` no longer reports `identical: true` for a tree it could not read** (BH-30). Entries whose metadata failed were silently dropped; enumeration errors are now threaded into `DirCompareResult.errors`, which forces `identical: false`.

**LLM streaming (`ai_messages*`)**

- **The OpenAI-compatible `/chat/completions` SSE parser was rewritten** as a pure, unit-tested incremental `SseParser` (BH-16), fixing four silent-data defects: tool-call deltas were keyed by the *optional* `id` field, so every argument fragment after the first delta was dropped and the `tool_use` was emitted with `{}` (now keyed by the *required* `index`); each network chunk was decoded with `from_utf8_lossy` independently, so a multibyte codepoint split across two chunks became `U+FFFD` (raw bytes are now buffered and only complete frames decoded); frames were split on `\n\n` only (now `\r\n\r\n` too); malformed data frames and unparsable tool arguments were silently dropped (now surfaced as errors).

### Fixes

- **`run_command` with `shell:"cmd"` now runs every line of a multi-line command** (`BUG5.md`): a newline-separated command under `shell:"cmd"` (and `shell:true`/default on Windows, which resolve to cmd) executed ONLY the first line and silently discarded the rest, returning `exitCode: 0` as if the whole script ran. Root cause: the command line was handed to `cmd.exe` verbatim as `cmd /C "<string>"`, and `cmd /C` does not treat embedded newlines as statement separators (unlike a `.bat` file or PowerShell `-Command`) — so `bash`/`pwsh` were unaffected, only cmd. A multi-line cmd command is now materialized as a temporary `.bat` (which cmd executes line-by-line) and run as `cmd /C "<bat>"`. A RAII guard removes the temp file on drop and is kept alive until the child exits in every run mode (foreground, detached with/without a process manager) — cmd reads the batch lazily, so removing it early would truncate the command. cmd is detected via the internal `windows_raw_arg` flag (not a string compare); single-line cmd and the bash/pwsh paths are unchanged (no regression); a temp-file write failure surfaces via `?` instead of silently falling back to the broken path. This also fixes the report's secondary symptom — a single fragile `&&` chain containing `set "PATH=...;%PATH%"` (parentheses in the expanded value) plus `>nul` redirects, which now runs cleanly as ordinary batch lines. Multi-line cmd therefore follows **batch semantics**, documented in the tool: the exit code is that of the LAST line, `for` needs `%%i` (not `%i`), and a failing middle line does not stop later lines (no implicit `&&` — chain with `&&` for fail-fast). Note: the `.bat` is written as UTF-8, so a non-ASCII multi-line command may be misread on a non-UTF-8 console — a limitation of the multi-line path only (single-line cmd stays verbatim via the wide API).
- **`run_command` no longer returns empty inline `stdout` for default calls** (`bug2.md`): a default call (e.g. `{ command: "...", shell: "pwsh" }`) returned `stdout: ""` with `stdoutTotalLines: 0` and `exitCode: 0` — looking like success while the output existed only in the stream log file. Root cause: `streamOutput` defaults to `true`, and the MCP layer mapped that to `capture_output = !use_file_streaming = false`, routing capture through the discard-only `Drain` path — so streaming-to-file and inline-capture were wrongly treated as mutually exclusive, contradicting the tool's own docs which promised inline output. They are now **decoupled**: output is always captured for the inline result *and* teed to the log file. To stay context- and memory-safe, the inline result is bounded by default to the last ~200 lines / 16 KB (a ring buffer; the full output always remains in the log file and `stdoutTotalLines` always reports the true count); `stdoutHead`/`stdoutTail`/`outputFilter` override the bound, and a call with no log-file fallback keeps the full output inline. The report's "corrupted persistent shell" theory was a misdiagnosis — there is no persistent shell (every call is a fresh spawn); the empty `stdout` was the capture/stream coupling, not a pipe race.
- **`run_command` capture no longer silently drops output on a slow post-exit drain.** After the process exited, stdout/stderr were collected under a hard 500 ms timeout whose expiry was swallowed by `unwrap_or_default()` — producing an empty result indistinguishable from genuine no-output. The post-exit drain budget is now a generous 5 s (both streams drained concurrently via `tokio::join!`, so the budget does not stack), and if it is ever exceeded — e.g. a lingering grandchild still holds the pipe's write end open (an inherited handle on Windows) — the result now carries `captureTruncated: true` (plus a `⚠` line in the text output) instead of masquerading as clean empty success.
- **`run_command` now auto-splits a full command line passed via `command`** (`fsmcp_bug.md` #2): calling `{ command: "cargo test -p foo --release" }` with no `args` and `shell` unset previously failed with `Failed to spawn command: cargo test -p foo --release`, because the whole string was taken as the literal program name. When `args` is empty and `shell` is false, `command` is now parsed as a command line — quote-aware, with backslashes preserved verbatim so Windows paths survive — and the first token becomes the program, the rest its arguments. The split is deterministic (no filesystem probing); a program path that itself contains spaces must be quoted, the same rule every shell uses. Passing explicit `args`, or `shell: true`, bypasses the split entirely. This was misdiagnosed in the report as managed-mode-specific: managed mode changes only progress reporting, never command construction or spawning, so the same failure occurred in sync mode.

### New features

- **`run_command` now emits a non-fatal hint when a pipeline is run without a shell.** With `shell:false` (the default) a command line passed via `command` is split into program + argv, so shell operators (`|`, `;`, `&&`, `>`, `<`, backtick) are handed to the program as *literal arguments* rather than interpreted — e.g. `git tag | grep v1` runs `git` with `|` and `grep` as arguments and returns a confusing exit code. When the whole command sits in `command` (no explicit `args`), no shell is requested, and a *top-level* (unquoted) operator is present, the result now carries a `hint` field (plus a `⚠ hint:` line in the text output) advising `shell:"bash"`. Purely advisory: nothing is rejected — operators inside quotes and any explicit `args` are never flagged — so existing calls that legitimately pass operators as literal arguments (`rg "a|b"`, `find -name "*|*"`) are unaffected. Closes the silent-pipe ergonomics gap that kept resurfacing (it was caller misuse, not a spawn bug, so the fix is a guard-rail hint rather than changed execution).
- **`run_command` `shell` now accepts a named shell, cross-platform** (`fsmcp_bug.md` #1): the field takes a bool as before (`true` = platform default `cmd /C` on Windows / `sh -c` on Unix, `false` = no shell) plus shell names — `"bash"` (`bash -c`, git bash on Windows), `"pwsh"` (`pwsh -NoProfile -Command`), and explicit `"cmd"`/`"sh"`. This fixes the root pain behind bug #1: on Windows `cmd.exe` does not treat `;` as a command separator and lacks unix tools, so pipelines like `a | tail -n 5; b` failed; running them under `shell: "bash"` makes them behave the same on Windows, macOS, and Linux. Named shells must be on `PATH`. Verbatim `raw_arg` handling stays scoped to `cmd.exe` (which needs it); bash/pwsh use standard argument escaping. Deserialization is tolerant (`true`/`false`/`1`/`0`/`"bash"`/…), and the `shell` type now lives in `core::serde` as `ShellArg`/`ShellKind`.

### Internal

- **The MCP client-setup matrix is now a shared crate, vendored into `src/mcp_setup/`.** The matrix (18 agents) moved out into `mcp-setup-rs` — one source of truth for setup logic across our MCP servers instead of a per-repo copy; this repo now only declares its own key, env, and docs (`src/setup.rs`). Because `mcp-setup-rs` is a **private** repo and crates.io rejects git dependencies (every dependency of a published crate must itself exist on crates.io), it is **vendored** rather than linked: a verbatim copy lives in `src/mcp_setup/`, with the private repo as upstream. The only edit to the vendored sources is mechanical (`crate::` → `crate::mcp_setup::`); `src/mcp_setup/VENDOR.md` records the pinned commit and the resync procedure. Fixes belong upstream, never in the vendored copy. Other consumers (`shotgrid-mcp-rs`, …) keep using it as a git dependency — they are not published to crates.io.
- **Upgraded `rmcp` 1.7 → 2.2** (and refreshed the rest of the dependencies). `Content`/`RawContent`/`Annotated` collapsed into `ContentBlock`, and `ProgressNotificationParam` became non-exhaustive, so it is now built through its constructor. `roots` is deprecated by SEP-2577 but has no replacement yet and is still how a client hands us its workspace, so the two call sites keep it behind a scoped `allow` with an explanation.
- **`Cargo.toml` `repository`/`homepage` pointed at `memory-mcp-rs`** (BH-33); corrected to `filesystem-mcp-rs`.
- The `run_command` serde fixture omitted `outputFilter` and `mode` — the two fields with the most fragile wire contract (BH-29); both are now covered by tests. Fully de-duplicating the wire type into `core` remains a follow-up.

### Known follow-ups

Deliberately deferred, tracked in `CDX_VERIFIED.md`: unification of the fancy and regex grep paths behind a shared `Searcher` (the fancy path still reads whole files, ignoring `heapLimitMb` and `encoding`, with an ad-hoc NUL binary heuristic); streaming S3 bodies and `s3_put` instead of buffering whole transfers in RAM; unbounded managed-mode progress buffering in `run_command`; the memory actor/ACL model.

---

## [0.1.20] - 2026-05-31

### Fixes

- **`run_command` shell mode mangled Windows paths** (BUG #1/#2 from `bug.md`): with `shell: true`, embedded paths like `type "C:\dir\file"` failed with `ERROR_INVALID_NAME` (os error 123), and even fully double-escaped paths still broke for `type`/`copy`/`if exist`. Root cause: `std::process::Command` escapes each argument with the MSVCRT convention (`"`→`\"`, doubled backslashes before a quote), which `cmd.exe` does not parse the same way — so the wrapped command line arrived corrupted. The wrapped line is now handed to `cmd.exe` verbatim via `raw_arg` on Windows, so `cmd /C <line>` is parsed exactly as if typed at the prompt. Non-shell spawns keep normal escaping (ordinary programs follow the MSVCRT convention). Forward-slash relative paths (BUG #2) were a symptom of the same escaping and are fixed by the same change. Note: a single-backslash path inside the JSON `command` string is still the caller's responsibility (JSON requires `\\`); the fix covers everything after JSON decoding.
- **`which` rejected the `name` field** (BUG #5): `{ "name": "naga" }` failed with `missing field "command"`. `name` is now accepted as an alias for `command`, matching the Unix `which <name>` mental model.
- **`run_command` no longer litters the working directory with stream logs.** Auto-created `run_command_<ts>_stdout.log` / `_stderr.log` files previously landed in `cwd` whenever it was set (i.e. almost always), accumulating by the dozen and never being cleaned up. They now always go to the OS temp dir (`<temp>/filesystem-mcp`) unless `stream_dir` is set explicitly. Cross-platform: `%TEMP%` on Windows, `$TMPDIR`/`/tmp` on Unix. Existing log files are left untouched.

### Docs

- **`run_command` tool schema now warns about JSON backslash escaping** (BUG #1 caller-side mitigation): the `command` field doc and tool description explain that single backslashes in a JSON string are consumed before reaching the server, and advise doubling them (`"C:\\dir\\file"`) or using forward slashes.
- Clarified that `run_command` returns stdout/stderr inline (full output by default; trimmed only with `stdout_tail`/`head` or a filter) in addition to the stream log files (BUG #4), so a follow-up file read is optional.

### Internal

- **Dropped the `r2d2_sqlite` dependency.** Its only role was a ~15-line `r2d2::ManageConnection` impl for rusqlite, now inlined as `SqliteManager` in `tools/memory_v2/sqlite.rs`. This lifted the `rusqlite ^0.39` ceiling `r2d2_sqlite` imposed, so `rusqlite` is back on `0.40` (single `libsqlite3-sys 0.38`; the previous mix of 0.37/0.38 was a hard `links = "sqlite3"` resolver conflict after a dependency bump). `r2d2` (generic pool) and the `SqliteCustomizer` are unchanged.
- Updated `aes` 0.9.0 → 0.9.1 in the lockfile; 0.9.0 (pulled transitively by `zip 8.6.0`) was yanked from crates.io.
- Refreshed all dependencies to their latest stable versions (`cargo update`). `zip` stays at `8.6.0` (the current stable; `9.0.0-pre2` is a pre-release and not adopted).

---

## [0.1.19] - 2026-05-28

### Breaking

- `bulk_edits` output schema changed. `results` now contains ONLY modified files (plus diffs). Unchanged files are no longer enumerated. New top-level fields:
  - `scannedFiles`, `modifiedFiles[]`, `errorResults[]`, `diffsTruncated`, `engine`, `editsSummary[]`.
  - Per-file diffs are truncated to 4000 chars; total structured payload capped at ~200K to prevent MCP transport overflow.
  - Each modified file entry now also carries `matchesPerEdit[]` and `appliedPerEdit[]` for migration safety.
  - `editsSummary[]` aggregates across all files: `totalMatches`, `totalApplied`, `filesWithMatches` per edit. Catches silent no-op edits in batches of thousands of files.

### Fixes

- **Cascading-duplicate bug in `bulk_edits`** (BUG #1 from `bug.md`): edits with overlapping `oldText` patterns no longer duplicate inserted text. All edits now apply to a frozen snapshot of each file; overlapping match spans are resolved by `longest-span wins; earlier edit wins on ties`.
- **`grep_files` rejected `\n` in pattern** (BUG #2): added `multiline` flag. When true, the searcher operates whole-buffer and patterns may span lines.
- **`grep_files` lacked look-around** (BUG #3): added `engine: "fancy"` (powered by `fancy-regex`). Supports `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`, and `\1` backreferences. Default `engine: "regex"` retains linear-time guarantees.
- **`bulk_edits` giant JSON output** (BUG #4): see breaking-change list above.
- **`cwd` description ambiguity** (BUG #5): rewritten in both tool description and JSON schema field doc.

### New features

- **`grep_files`** gained: `multiline`, `fixedStrings`, `wholeWord`, `maxDepth`, `maxFilesize`, `encoding`, `heapLimitMb`, `engine` (regex/fancy). CRLF handling is now ALWAYS enabled in the matcher (was opt-in; now baked in because the cost is zero on `\n`-only files and `$` anchors were silently broken on Windows files).
- **`grep_context`** brought to API parity: `fixedStrings`, `wholeWord`, `maxDepth`, `maxFilesize`, `engine` (regex/fancy). Multi-line patterns work natively (the matcher already reads each file whole, so no separate flag is required).
- **`bulk_edits`** gained: `engine` (regex/fancy), `editsSummary` output for per-edit visibility, aggregated `failOnNoMatch` errors (lists ALL no-match edits at once instead of stopping at the first).

### Internal

- Added `fancy-regex 0.16` dependency.
- `EditOutcome` struct replaces the `(String, String)` tuple return of `apply_edits`.
- `EditEngine` / `GrepEngine` enums added.
- Clippy clean under `--all-targets -- -D warnings` across the whole crate (previously ≈25 pre-existing warnings cleared).

---

## [0.1.17] - 2026-05-25

### Breaking — Memory v2 (`mem_*`)

Memory tools now use a strict, flat argument shape. Update callers once; behavior stays predictable afterward.

- **Required fields**: `workspaceId`, `actorId`, and nested `item`. Optional: `tenantId`, `appId`, `topicId`, `sessionId`, `runId`, `actorType`, etc.
- **Removed shortcuts**: `"scope": "my-project"` and `"actor": "claude"` are rejected.
- **No stringified `item`**: pass a JSON object, not an escaped JSON string. Published schemas for `mem_*` are strict (no object-or-string `oneOf`).
- **`item.content`**: JSON object/array or plain string. A JSON-looking **string** is stored as text, not auto-parsed.
- **`mem_get_summary` default level** is now `workspace` — `{ workspaceId, actorId }` works without `topicId`.

Migration example:

```json
{
  "workspaceId": "vfx-rs",
  "actorId": "cursor",
  "item": { "itemType": "task", "content": { "status": "open" } }
}
```

Summary recall (default workspace level):

```json
{ "workspaceId": "vfx-rs", "actorId": "cursor" }
```

Topic/session/run levels still require the matching scope id:

```json
{
  "workspaceId": "vfx-rs",
  "actorId": "cursor",
  "topicId": "pt-debug",
  "level": "topic"
}
```

### Added — MCP session lock

- **Session lock on every tool response**: short text footer plus `_mcpSessionLock` / `_mcpPolicy` in structured output, nudging agents to use this server for file and shell work.
- **`mcp_setup` / `install`**: Karpathy-style rules and MCP policy/workflow templates written into client config (`CLAUDE.md`, `AGENTS.md`, Cursor/Codex/Gemini/Qwen hints, etc.).
- **`--no-session-footer`**: CLI flag to omit the footer (integration tests; production default unchanged).
- **`install` defaults**: writes `FS_MCP_HTTP_ALLOW_LIST=*` and `FS_MCP_S3_ALLOW_LIST=*` when not overridden, so HTTP/S3 tools work after a fresh install.

### Added — `run_command` and tooling

- **`run_command` snake_case aliases**: `timeout_ms`, `stream_output`, `output_filter`, etc. alongside camelCase.
- **`src/tools/memory_v2/mcp_args.rs`**: shared strict arg types, handlers, and validation for all `mem_*` tools.
- Early validation for `mem_get_summary` scope ids → `invalid_params` (-32602) instead of internal error (-32603).

### Fixed

- **`run_command` head/tail/filter**: when `stdout_head`, `stdout_tail`, `stderr_head`, `stderr_tail`, or `output_filter` is set, output is always captured inline. Previously, streaming mode could return empty snippets while logs were still written to disk.
- **`run_command` `cwd` description**: example path used escaped quotes (`\"C:/projects/repo\"`), which led agents to emit unquoted Windows paths and invalid JSON.
- **`grep_files` description**: `pattern` (content regex) and `filePattern` (file-name glob) are documented separately with examples, so agents stop passing bare globs in the wrong field.

### Changed

- Tool descriptions and server / `seq_think` instructions updated for strict memory API and workspace-first summary recall.
- README: user-facing release notes; strict `mem_*` contract documented.

### Removed

- `struct_or_json_string_or_shortcut_from_value` and related tests (scope/actor shortcuts).
- LLM coercion on `mem_*` tools (stringified `item`, shortcut scope/actor).
- Err.md regression tests for stringified `mem_put.item` (behavior intentionally dropped).

### Tests

- Integration: `get_summary_workspace_round_trip`, `run_command_accepts_llm_json_shapes`, `session_footer_appended_by_default`.
- Integration: `run_command_cwd_description_uses_plain_quotes`, `grep_files_description_separates_pattern_from_file_pattern`.
- Unit: memory v2 edge cases (legacy shortcuts, stringified `item`, bad UUIDs, schema strictness); `run_command` deserialization fixtures; head/tail capture regression (`test_head_overrides_capture_false`).

---

## [0.1.11 – 0.1.16] - 2026-01-17 … 2026-05-19

Releases between 0.1.11 and 0.1.16 shipped incrementally; this section groups the user-visible changes from that period.

### Added — `run_command` overhaul (from 0.1.15)

- **Execution modes** (`mode`):
  - `sync` (default): wait for completion; heartbeat every ~30s avoids MCP client timeout on long builds
  - `managed`: wait with progress snippets every ~10s
  - `detached`: background run, returns PID immediately (replaces `background: true`)
- **Progress heartbeat** via MCP `notifications/progress` during long runs.
- **Process tree kill** on timeout/cancel (parent and children, e.g. `cargo build` → `rustc`).
- **Process group isolation**: `setpgid` (Unix), `CREATE_NEW_PROCESS_GROUP` (Windows).
- **Shell mode** (`shell: true`): pipes, `&&`, redirects via `cmd /C` or `sh -c`.
- **stdinData**, **envPrepend** / **envAppend**, **outputFilter** (include/exclude/context), **stdoutHead** / **stderrHead**, timestamps and line counts in responses.
- **kill_process** `tree: true` kills an entire process tree.

### Added — System, network, and documents

- **Wave2 tools** (always on): `port_users`, `net_connections`, `port_available`, `proc_tree`, `proc_env`, `proc_files`, `disk_usage`, `sys_info`, `file_diff`, `file_touch`, `env_*`, `which`, `clipboard_*` (clipboard requires screenshot feature).
- **HTTP tools** (feature): `http_request`, `http_request_batch`, `http_download`, `http_download_batch`; `--http-allowlist-domain` / `FS_MCP_HTTP_ALLOW_LIST`.
- **S3 tools** (feature): list/stat/get/put/delete/copy/presign + batch ops; `s3_list_buckets`; `--s3-allowlist-bucket` / `FS_MCP_S3_ALLOW_LIST`.
- **Screenshot tools** (feature): monitors, windows, screen/window/region capture, clipboard copy.
- **LLM tools** (needs API keys): `ai_messages_*`, `ai_count_tokens_*` (from llm-mcp-rs).
- **XLSX / DOCX**: `xlsx_read`, `xlsx_info`, `docx_read`, `docx_info`.
- **grep_context**: matches that require nearby terms within a word/char window.
- **Memory v2 ACL modes**: `enforce_private_only` (default), `allow_all`, `enforce_visibility` via `--memory-access-mode` / `FS_MCP_MEMORY_ACCESS_MODE`.
- **FlexBool**: booleans accept `true`, `"true"`, `"1"`, `1`, etc.
- **Project layout**: `src/core` + `src/tools` plugin-style organization.

### Enhanced

- **LLM-friendly JSON parsing** on non-memory tools: objects/maps/arrays may be sent as JSON strings; `vec_or_string` for list fields; Draft-07 `oneOf` hints on schemas where applicable (`run_command`, HTTP, S3, edit tools, LLM tools).
- **run_command**: stream stdout/stderr to log files while running; improved tool descriptions and server instructions.
- **bulk_edits**: `failOnNoMatch` (default false).
- **grep_files**: include/exclude file patterns in MCP args.
- **Flex type macros**: unified `FlexU32` / `FlexUsize` / `FlexU64` / `FlexI32` helpers.

### Fixed

- **Symlink escape check**: canonicalize symlink parent (macOS `/tmp` → `/private/tmp`).
- **CI**: artifact uploads for all platforms; checkout/upload-artifact v5.

### Dependencies (0.1.15)

- `tokio-util` 0.7 (CancellationToken), `libc` 0.2 (Unix setpgid).

### Tests

- Process: 23 tests (modes, filter, head/tail, env prepend/append, shell, cancellation).
- Wave2: 29 tests; XLSX: 6; DOCX: 3; FlexBool: 10; LLM coercion fixtures.
- Unicode coverage in new tests (Russian, Chinese, emoji).
- Total reached ~275 unit tests by end of this period.

---

## [0.1.10] - 2026-01-17

### Added

- **Hash algorithms**: MurmurHash3 (128-bit) and SpookyHash V2 (128-bit).
- **Partial hashing**: `file_hash` supports `offset` and `length` for file regions.

### Enhanced

- **file_hash**: md5, sha1, sha256, sha512, xxh64, murmur3, spooky.
- **search_files**: `fileType`, `minSize`, `maxSize` in MCP API.
- **JSON responses**: additional structured fields on compare, watch, hash, read_json, read_pdf.

### Fixed

- Removed unused methods in grep, hash, watch, process, search modules.
- Updated LLM tool descriptions.

### Tests

- 4 new hash tests; total 168 unit tests.

---

## [0.1.9] - 2026-01-17

### Added

**File comparison and hashing:** `file_hash`, `file_hash_multiple`, `compare_files`.

**Advanced file ops:** `compare_directories`, `tail_file`, `watch_file`, `read_json`, `read_pdf`.

**Utilities:** `archive_extract`, `archive_create`, `file_stats`, `find_duplicates`.

**Process management:** `run_command`, `kill_process`, `list_processes`, `search_processes`.

### Enhanced

**grep_files:** `invertMatch`, files-without-match mode, count mode.

**search_files:** type, size, and modification time filters.

**directory_tree:** `maxDepth`, `showSize`, `showHash`.

### Tests

~80 new unit tests; total 54 → 158.

### Dependencies

`sha1`, `sha2`, `md-5`, `xxhash-rust`, `pdf-extract`, `serde_json_path`, `zip`, `tar`, `flate2`, `notify`.

---

## [0.1.8] - 2026-01-11

### Fixed

- JSON Schema Draft 7 compatibility for Gemini and Qwen clients.

---

## [0.1.5] - 2024-12-30

### Fixed

- **grep_files**: searching a single file path (not a directory) no longer returns zero matches.

---

## [0.1.4] - Previous

- Initial release: read/write/edit, grep, search, binary ops, bulk edits.
