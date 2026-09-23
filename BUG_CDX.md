# Codex MCP issue log

## 2026-09-21 — filesystem MCP tools unavailable to one team agent

During parallel work in `ofx-rs`, the palette subagent reported that filesystem MCP tools disappeared from its available tool list, while the root and documentation agents could still call the same server successfully. This blocked that agent from performing the required MCP-only file work; the root agent took over palette code ownership.

This is a reported per-agent tool-availability failure, not evidence of a server-wide outage. Preserve the affected agent's tool-discovery transcript and compare per-agent tool listings/session initialization to determine whether the capability was omitted, disconnected, or filtered. Reproduce with two concurrent agents, then verify that both retain `filesystem-mcp-rs` tools throughout their turns.

## 2026-09-22 — invalid edit regex exposes an internal stack trace

Reproduction: call `mcp__filesystem_mcp_rs__edit_file` with `isRegex: true` and `oldText: "(\\s+star_micros: [^,\\n]+,\\n)(\\s+)(?!(?:fake_stars:))"` against an existing Rust file. The pattern uses unsupported lookahead, which is an expected caller error.

Observed impact: the tool correctly reports a regex parse error but then returns a full internal `Stack backtrace` beginning with `aws_lc_0_39_0_jent_entropy_switch_notime_i`. Internal stack details are exposed for a routine invalid input.

Safe fallback: use a supported regex without lookaround or an exact `oldText` replacement. Return the parser error without an internal stack trace.

The same issue recurs when a batch of literal `edit_file` replacements contains a nonexistent `oldText`: reproduction was a four-edit call against `src/purse.rs` where edit #4 searched for `let caps = p.caps(Principal::User(1)).await.unwrap();`. The tool reported `1 of 4 edits produced zero matches` and appended a full stack trace. This is another expected caller error; the safe fallback is to re-read the file and retry only matching edits.

## 2026-09-22 — run_command validation exposes an internal stack trace

Reproduction: call `mcp__filesystem_mcp_rs__run_command` with `command: "powershell"`, `args: ["-NoProfile", "-Command", "$root=[IO.Path]::GetFullPath('C:\\projects\\projects.rust.cg\\cgprojs\\opengram-rs'); Write-Output $root"]`, and a valid workspace `cwd`. A `$NAME` token in command arguments is deliberately rejected by the tool, so the input error is expected.

Observed impact: the validation error reports the `$root` token and then appends a full internal `Stack backtrace` beginning with `aws_lc_0_39_0_jent_entropy_switch_notime_impl`.

Safe fallback: pass the PowerShell script as a `stdin` ContentRef with `args: ["-NoProfile", "-Command", "-"]`. Return validation errors without internal stack traces.

Additional reproduction (2026-09-22 PDT): call `run_command` with `command: "powershell"`, `args: ["-NoProfile", "-Command", <inline script containing $exe, $repo, and $p>]`. Two attempts returned the expected MCP `-32602` safety rejection, but also a full internal `Stack backtrace` containing `aws_lc_0_39_0_jent_entropy_switch_notime_impl` and OS frames. No process was spawned. Pass the script through `stdin: {kind: "inline", text: script}` with `args: ["-NoProfile", "-Command", "-"]`, or use a script file.

## 2026-09-22 — memory relation scope error exposes an internal stack trace

Reproduction: call `mcp__filesystem_mcp_rs__mem_link` with `workspaceId: "C:\\projects\\projects.rust.cg\\cgprojs\\cryptobot-rs"`, `actorId: "codex-root"`, and `relation: {fromItemId: "a121eafa-ecd8-4137-8f5d-3ec13f464666", toItemId: "db972c3b-a49b-4029-87e9-88f1a0e53d32", relationType: "continued_by"}`. The first item is absent from that actor scope, so a not-found error is expected.

Observed impact: the tool reports `fromItemId ... not found in scope` and then exposes a full internal `Stack backtrace` beginning with `aws_lc_0_39_0_jent_entropy_switch_notime_impl`.

Safe fallback: use `mem_get` or `mem_search` in the correct scope before linking; return a concise not-found result without an internal stack trace.

## 2026-09-22 — memory update scope error exposes an internal stack trace

Reproduction: call `mcp__filesystem_mcp_rs__mem_update` with `workspaceId: "cryptobot-rs"`, `actorId: "codex-root"`, `id: "db972c3b-a49b-4029-87e9-88f1a0e53d32"`, and a valid summary `item`. The item was created under a different workspace scope, so `not found in scope` is an expected caller error.

Observed impact: the tool returns the expected not-found message followed by a full internal `Stack backtrace` beginning with `aws_lc_0_39_0_jent_entropy_switch_notime_impl`.

Safe fallback: create a new memory item in the intended scope with `mem_put`, or resolve the original scope before `mem_update`. Return a concise scope error without an internal stack trace.

## 2026-09-22 — search_processes validation exposes an internal stack trace

Reproduction: call `mcp__filesystem_mcp_rs__search_processes({pattern: "cargo|nvcc|cl.exe"})`. The tool requires `name_pattern` or `cmdline_pattern`; using `pattern` is an expected caller error.

Observed impact: the tool returns MCP error `-32602` explaining that both supported filters are absent, then exposes a full internal `Stack backtrace` containing `aws_lc_0_39_0_jent_entropy_switch_notime_impl`.

Safe fallback: call `search_processes({name_pattern: "cargo|nvcc|cl\\.exe"})` or set `cmdline_pattern`. Return the validation error without a stack trace.

## 2026-09-22 — grep_context validation exposes an internal stack trace

Reproduction: call `mcp__filesystem_mcp_rs__grep_context({path: "C:\\projects\\projects.rust.cg\\cgprojs\\cryptobot-rs\\Cargo.lock", pattern: 'name = "cudaforge"', before: 1, after: 10})`. The tool requires nonempty `nearbyPatterns`; `before` and `after` are not its context argument names. This is an expected caller error.

Observed impact: the tool returns MCP error `-32602` explaining the missing nearby terms, then exposes a full internal `Stack backtrace` containing `aws_lc_0_39_0_jent_entropy_switch_notime_impl`.

Safe fallback: call `grep_files` for a plain search, or supply `nearbyPatterns` and use `contextBefore`/`contextAfter`. Return the validation error without a stack trace.

## 2026-09-22 — managed run_command times out before its requested deadline

Reproduction: call `mcp__filesystem_mcp_rs__run_command({command: "python", args: ["bootstrap.py", "build", "--debug"], cwd: "C:\\projects\\projects.rust.cg\\cgprojs\\cryptobot-rs", mode: "managed", timeoutMs: 900000, streamOutput: false})` while building the project.

Observed impact: after 300 seconds, the tool returned `timed out awaiting tools/call after 300s` with a full internal `Stack backtrace`, despite the requested 900,000 ms timeout. The spawned `python bootstrap.py` process (PID 45632) and child `cargo x build` process (PID 48236) continued running after that response. The caller lost the command's exit status and log handle, and a retry could overlap the active build.

Safe fallback: start the build detached with explicit stdout and stderr file paths, then poll its process and log files until it exits. Check for an existing build before starting another. The tool should honor the requested timeout or return a durable process handle without exposing an internal stack trace.

## 2026-09-22 — edit_file no-match error exposes an internal stack trace

Reproduction: call `mcp__filesystem_mcp_rs__edit_file` on `crates/cryptobot-nodes/src/pipeline.rs` with a literal `oldText` that differs from the file after rustfmt (for example, an expected multiline `scene.get("tmp.archive.remaining")` layout). A zero-match edit is an expected caller error.

Observed impact: the tool returns `Failed to apply edits: 1 of 1 edits produced zero matches` and then a full internal `Stack backtrace` beginning with `aws_lc_0_39_0_jent_entropy_switch_notime_impl`.

Safe fallback: re-read the current lines and retry with an exact literal match. The server should return a concise no-match result without its internal stack trace.

Additional reproduction (2026-09-22 PDT): send a three-edit literal `edit_file` request against `cryptobot-rs/crates/cryptobot-core/src/jobs/redb_store.rs`. In the third edit, use `oldText` containing `b"_- ."` where the source at the time contained `b"_-."`. The expected response is a clean no-match error without applying any of the three edits. The observed response reports the no-match and includes a full internal stack trace with `aws_lc` entropy and OS frames. This exposes implementation details for an ordinary caller typo. Re-read the exact current lines and retry with corrected literal text; verify the file before retrying so no partial write is accepted.

Additional reproduction (2026-09-22 PDT): call `mcp__filesystem_mcp_rs__edit_file` on `cryptobot-rs/crates/cryptobot-core/src/orders/paper_broker.rs` with `dryRun: true` and three literal edits. Use identity replacements for `use rust_decimal::Decimal;` and `use std::collections::HashMap;`, then set edit #3 to `oldText: "let mut wallet = if let Some(lane) = lane.as_ref() {"` and `newText: "let wallet = if let Some(lane) = lane.as_ref() {"`. The third old text is absent. The expected result is a concise `zero matches` validation error, with no edits applied. The observed result reports `1 of 3 edits produced zero matches` and appends a full internal `Stack backtrace`. Re-read the current source, retry one exact edit at a time, and verify the file after each edit. The server should omit its internal backtrace for a routine no-match error.

## 2026-09-22 — memory cross-scope target error exposes an internal stack trace

Reproduction: create a memory item under `workspaceId: "C:\\projects\\projects.rust.cg\\cgprojs\\cryptobot-rs"` with `mem_put`. Then call `mcp__filesystem_mcp_rs__mem_link({workspaceId:"C:\\projects\\projects.rust.cg\\cgprojs\\cryptobot-rs",actorId:"codex:/root",relation:{fromItemId:"818635ce-582f-4db3-9143-e135fd4a4bd2",relationType:"continues",toItemId:"be9f5b43-39e2-450e-8749-5f4cda9f3e12"}})`. The source item exists in the absolute-path workspace; the target item exists under the distinct `cryptobot-rs` workspace. A scope not-found result is expected. A repeat with another target UUID from the other workspace produced the same class of error.

Observed impact: instead of a concise scope error, the tool returns MCP `-32603` with `toItemId ... not found in scope` and a full internal `Stack backtrace` (24 frames). The caller learns internal stack details for a routine invalid relation.

Safe fallback: use one canonical `workspaceId` for related items, verify each item's scope with `mem_get`, and avoid links across workspaces. The server should report the expected scoped not-found error without a backtrace.
