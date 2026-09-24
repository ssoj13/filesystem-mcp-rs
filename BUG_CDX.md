# Codex MCP issue log

## 2026-09-21 — filesystem MCP tools unavailable to one team agent

During parallel work in `ofx-rs`, the palette subagent reported that filesystem MCP tools disappeared from its available tool list, while the root and documentation agents could still call the same server successfully. This blocked that agent from performing the required MCP-only file work; the root agent took over palette code ownership.

This is a reported per-agent tool-availability failure, not evidence of a server-wide outage. Preserve the affected agent's tool-discovery transcript and compare per-agent tool listings/session initialization to determine whether the capability was omitted, disconnected, or filtered. Reproduce with two concurrent agents, then verify that both retain `filesystem-mcp-rs` tools throughout their turns.

## 2026-09-22 — invalid edit regex exposes an internal stack trace

Reproduction: call `mcp__filesystem_mcp_rs__edit_file` with `isRegex: true` and `oldText: "(\\s+star_micros: [^,\\n]+,\\n)(\\s+)(?!(?:fake_stars:))"` against an existing Rust file. The pattern uses unsupported lookahead, which is an expected caller error.

Observed impact: the tool correctly reports a regex parse error but then returns a full internal `Stack backtrace` beginning with `aws_lc_0_39_0_jent_entropy_switch_notime_i`. Internal stack details are exposed for a routine invalid input.

Safe fallback: use a supported regex without lookaround or an exact `oldText` replacement. Return the parser error without an internal stack trace.

Additional reproduction (2026-09-23 PDT): call `mcp__filesystem_mcp_rs__edit_file` on `squarebob-rs/AGENTS.md` with `isRegex: true` and `oldText: "(?s)\\A# AGENTS\\.md.*?(?=<!-- gitnexus:start -->)"`. The unsupported lookahead is an expected caller error. The tool returned the regex parse error plus a full internal `Stack backtrace` beginning with an `aws_lc` frame. No edit was applied. Safe fallback: use an exact literal replacement or a regex without lookaround; return the parse error without internal frames.

The same issue recurs when a batch of literal `edit_file` replacements contains a nonexistent `oldText`: reproduction was a four-edit call against `src/purse.rs` where edit #4 searched for `let caps = p.caps(Principal::User(1)).await.unwrap();`. The tool reported `1 of 4 edits produced zero matches` and appended a full stack trace. This is another expected caller error; the safe fallback is to re-read the file and retry only matching edits.

## 2026-09-22 — run_command validation exposes an internal stack trace

Reproduction: call `mcp__filesystem_mcp_rs__run_command` with `command: "powershell"`, `args: ["-NoProfile", "-Command", "$root=[IO.Path]::GetFullPath('C:\\projects\\projects.rust.cg\\cgprojs\\opengram-rs'); Write-Output $root"]`, and a valid workspace `cwd`. A `$NAME` token in command arguments is deliberately rejected by the tool, so the input error is expected.

Observed impact: the validation error reports the `$root` token and then appends a full internal `Stack backtrace` beginning with `aws_lc_0_39_0_jent_entropy_switch_notime_impl`.

Safe fallback: pass the PowerShell script as a `stdin` ContentRef with `args: ["-NoProfile", "-Command", "-"]`. Return validation errors without internal stack traces.

Additional reproduction (2026-09-22 PDT): call `run_command` with `command: "powershell"`, `args: ["-NoProfile", "-Command", <inline script containing $exe, $repo, and $p>]`. Two attempts returned the expected MCP `-32602` safety rejection, but also a full internal `Stack backtrace` containing `aws_lc_0_39_0_jent_entropy_switch_notime_impl` and OS frames. No process was spawned. Pass the script through `stdin: {kind: "inline", text: script}` with `args: ["-NoProfile", "-Command", "-"]`, or use a script file.

Additional reproduction (2026-09-23 PDT): call `run_command({command:"powershell",args:["-NoProfile","-Command","Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('cargo.exe','rustc.exe') -and $_.CommandLine -like '*cryptobot-rs*' } | Select-Object Name,ProcessId,ParentProcessId,CommandLine | Format-List"],cwd:"C:\\projects\\projects.rust.cg\\cgprojs\\cryptobot-rs",mode:"sync"})`. The expected safety rejection for `$_` returned MCP `-32602` plus a full internal `Stack backtrace` with `aws_lc` frames; the process did not start. Use `search_processes({cmdline_pattern:"cryptobot-rs"})` or pass the script via `stdin` ContentRef.

Additional reproduction (2026-09-23 PDT): call `run_command` with `command:"powershell"`, `args:["-NoProfile","-Command",<read-only Get-CimInstance Win32_OperatingSystem and Win32_PageFileUsage script assigning $os and $pf>]`, and `cwd:"C:\\projects\\projects.rust.cg\\cgprojs\\cryptobot-rs"`. The expected `-32602` safety rejection for `$os` also included a full internal `Stack backtrace` through `BaseThreadInitThunk` and `RtlUserThreadStart`; no process started. A variable-free `Get-CimInstance ... | Select-Object ...` query succeeded. The script can also be supplied by `stdin` ContentRef.

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

Additional reproduction (2026-09-23 PDT): submit 14 literal `edit_file` replacements against `cryptobot-rs/DIAGRAMS.md`; edits #8 and #14 have no current match. The expected caller-error response is a concise no-match list with no file mutation. The tool returned MCP `-32603` and a full internal `Stack backtrace`; it was unclear from the response whether earlier replacements had been applied. Re-read `DIAGRAMS.md`, confirm the current text, then retry only exact matches in smaller batches and verify the final diff. This is the same server defect, not a missing-file error.

## 2026-09-22 — memory cross-scope target error exposes an internal stack trace

Reproduction: create a memory item under `workspaceId: "C:\\projects\\projects.rust.cg\\cgprojs\\cryptobot-rs"` with `mem_put`. Then call `mcp__filesystem_mcp_rs__mem_link({workspaceId:"C:\\projects\\projects.rust.cg\\cgprojs\\cryptobot-rs",actorId:"codex:/root",relation:{fromItemId:"818635ce-582f-4db3-9143-e135fd4a4bd2",relationType:"continues",toItemId:"be9f5b43-39e2-450e-8749-5f4cda9f3e12"}})`. The source item exists in the absolute-path workspace; the target item exists under the distinct `cryptobot-rs` workspace. A scope not-found result is expected. A repeat with another target UUID from the other workspace produced the same class of error.

Observed impact: instead of a concise scope error, the tool returns MCP `-32603` with `toItemId ... not found in scope` and a full internal `Stack backtrace` (24 frames). The caller learns internal stack details for a routine invalid relation.

Safe fallback: use one canonical `workspaceId` for related items, verify each item's scope with `mem_get`, and avoid links across workspaces. The server should report the expected scoped not-found error without a backtrace.

## 2026-09-23 — run_command rejects a valid PowerShell script containing `$n`

Reproduction: call `mcp__filesystem__run_command` with `{"command":"$n=''; Get-Content Cargo.lock | ForEach-Object { if ($_ -match '^name = \"([^\"]+)\"') { $n=$Matches[1] }; if ($_ -match '^source = \"git\\+.*github.com/ssoj13/') { Write-Output \"$n $_\" } }","cwd":"C:\\projects\\projects.rust.cg\\cglibs\\squarebob-rs"}`. The PowerShell script is valid and reads `Cargo.lock` without modifying files.

Observed impact: the tool rejects the call with MCP `-32602`, claiming `command/args contain $n — MCP host may delete NAME tokens before spawn`, and appends a full internal Rust `Stack backtrace`. The requested read-only lockfile inspection never starts. This is a false-positive command validation plus internal stack disclosure, distinct from an expected missing-file or syntax error.

Safe fallback: use filesystem MCP `read_text_file` to read `Cargo.lock` and parse it in the tool orchestration JavaScript, or place the PowerShell script in a file and invoke that file through `run_command`. The server should accept valid scripts or provide an equivalent safe script input without exposing internal frames.

Additional reproduction (2026-09-23 PDT): call `mcp__filesystem__run_command({command:"powershell",args:["-NoProfile","-Command","$f=Get-Content src/ntfs.rs; $f[385..445]; $f=Get-Content src/lib.rs; $f[0..75]"],cwd:"C:\\projects\\projects.rust.cg\\cglibs\\fscan-rs",shell:"none"})`. The valid read-only script was rejected with MCP `-32602` and a 24-line internal `Stack backtrace`; the command did not execute. Safe fallback: use `read_text_file` for the two source ranges. This is the same `$NAME` validation defect and stack disclosure.

## 2026-09-23 — managed run_command ends at 300 seconds despite 30-minute timeout

Reproduction: call `mcp__filesystem__run_command({command:"python bootstrap.py b",cwd:"C:\\projects\\projects.rust.cg\\cglibs\\squarebob-rs",mode:"managed",timeoutMs:1800000,outputFilter:{include:["error","warning","failed","Compiling","BUILD","Updating","Finished"],maxLines:80},stderrTail:40,stdoutTail:20})` while the command runs longer than five minutes.

Observed impact: after about 300 seconds the tool returned MCP `timed out awaiting tools/call after 300s` plus a full internal stack trace, despite the requested 1,800,000 ms timeout. The caller lost the command result and exit status. Whether the process remained alive after the MCP timeout was not established and must be checked before any retry. This reproduces the timeout class first logged on 2026-09-22 with a different command and requested duration.

Safe fallback: if available, run long work in detached mode with explicit output log paths, then poll process status and logs until exit. Before retrying, inspect whether the original command or child processes are still running; do not kill unrelated processes. The server should honor the requested timeout or return a durable process handle without exposing an internal stack trace.

## 2026-09-23 — search_processes parameter validation exposes an internal stack trace

Reproduction: call `mcp__filesystem_mcp_rs__search_processes({pattern:"cargo|rustc"})`. The documented arguments are `name_pattern` and `cmdline_pattern`; `pattern` is an invalid caller argument.

Observed impact: the server returns `-32602: search_processes was called with neither name_pattern nor cmdline_pattern` followed by a full internal `Stack backtrace` (20 frames, including `aws_lc_0_39_0_jent_entropy_switch_notime_impl` and OS thread frames). The invalid argument is an expected user error; exposing the stack is the server defect and adds noise and implementation details to the result.

Safe fallback: call `search_processes({name_pattern:"cargo|rustc"})`, which succeeds. The server should return a concise validation error without a backtrace.

## 2026-09-23 — filesystem MCP capabilities unavailable to two team agents

Reproduction: in two independent `osl-rs` subagent scopes, inspect advertised capabilities and invoke `tools.mcp__filesystem__read_text_file`, `tools.mcp__filesystem__mem_get_summary`, or `tools.mcp__filesystem__seq_think` through `functions.exec`. The capabilities appeared in metadata, but invocation returned `TypeError: tools.mcp__filesystem__read_text_file is not a function` or `MCP tool not available to model`; the same class of failure affected the memory and sequential-thinking calls. The root agent and a third documentation subagent successfully invoked the filesystem MCP during the same team task.

Observed impact: two delegates could not use the mandatory filesystem, memory, or sequential-thinking MCP tools. This is a per-agent capability routing/availability defect, not evidence of a filesystem-mcp-rs server-wide outage. No internal server stack trace was observed for this case.

Safe fallback: route mandatory MCP operations through a team agent whose MCP calls work, or use read-only PowerShell inspection temporarily and have the working agent perform verified writes. Preserve the affected agents' capability listings and call results; compare initialization and routing across agent scopes.
