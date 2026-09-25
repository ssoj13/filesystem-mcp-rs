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

Additional reproduction (2026-09-23 PDT, `osl-rs` documentation update): call `mcp__filesystem__edit_file` on `BUG_HUNT_REPORT.md` with six literal edits, four existing `oldText` strings and two absent strings (`src/codegen.rs:1625-1652` and `src/codegen.rs:2398-2508`). The tool returned MCP `-32603`, `2 of 6 edits produced zero matches`, followed by a full internal `Stack backtrace`. A second call on `plan3.md` with the same six edits returned `4 of 6 edits produced zero matches` and another backtrace. The no-match result is an expected caller error; the stack disclosure is the server defect. Impact: routine source-reference maintenance produced noisy internal diagnostics, and edit atomicity required re-reading. Safe fallback: send only replacements confirmed to exist in each file, then re-read each changed document. This is the same error-response defect as the earlier literal-edit reproduction.

Additional reproduction (2026-09-23 PDT, `osl-rs` thin-layer port): call `mcp__filesystem__edit_file` with eight literal edits on `src/bsdf_ext/thinlayer.rs`; the final `oldText` differs from the current rustfmt indentation. The expected `1 of 8 edits produced zero matches` error also included a 24-frame internal stack trace. Impact: internal stack disclosure and uncertainty about batch atomicity during LUT integration. Safe fallback: read the exact current lines and retry smaller verified edit batches, then inspect the diff. No changes were applied by the failed call.

## 2026-09-22 — run_command validation exposes an internal stack trace

Reproduction: call `mcp__filesystem_mcp_rs__run_command` with `command: "powershell"`, `args: ["-NoProfile", "-Command", "$root=[IO.Path]::GetFullPath('C:\\projects\\projects.rust.cg\\cgprojs\\opengram-rs'); Write-Output $root"]`, and a valid workspace `cwd`. A `$NAME` token in command arguments is deliberately rejected by the tool, so the input error is expected.

Observed impact: the validation error reports the `$root` token and then appends a full internal `Stack backtrace` beginning with `aws_lc_0_39_0_jent_entropy_switch_notime_impl`.

Safe fallback: pass the PowerShell script as a `stdin` ContentRef with `args: ["-NoProfile", "-Command", "-"]`. Return validation errors without internal stack traces.

Additional reproduction (2026-09-23 PDT, `osl-rs`): `mcp__filesystem__run_command({command:"powershell",args:["-NoProfile","-Command","$env:CARGO_HOME"],cwd:"C:\\projects\\projects.rust.cg\\cglibs\\osl-rs",mode:"sync",timeoutMs:10000})` triggered the expected `-32602` guard (`command/args contain $env — host may delete NAME tokens before spawn`) but also returned a full internal `Stack backtrace` with `aws_lc_0_39_0_jent_entropy_switch_notime_impl` frames. Impact: internal stack disclosure for a routine rejected caller input. Safe fallback: pass the PowerShell script through `stdin` ContentRef, or use filesystem read/list APIs. This is the same validation response defect.

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

Additional reproduction (2026-09-23 PDT, `osl-rs`): a seven-edit `mcp__filesystem__edit_file` call against `src/oso.rs` included edit #3 with `oldText: "let mval = decode_oso_value(parts[2].trim());\n                    // Special-case: lockgeom sets interpolation lock"`. That text depended on edit #1 in the same batch and was absent from the pre-edit file. The server returned MCP `-32603`, `Failed to apply edits: 1 of 7 edits produced zero matches`, and a full internal `Stack backtrace` ending in `BaseThreadInitThunk`. Impact: ordinary batch dependency/no-match exposed internal frames and left edit atomicity unclear. Safe fallback: re-read source, split dependent edits into sequential calls, and verify each diff. This is the same error-response defect.

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

Additional reproduction (2026-09-23 PDT, `cryptobot-rs`): call `mcp__filesystem_mcp_rs__run_command` in `mode:"sync"` for `target\\release\\cryptobot.exe backtest --csv data/candles --from 2019-01-01 --until 2019-01-08 --sweep-mode rsi,trend,combo --sweep-workers 2 --trailing --stop-loss --cooldown --daily-loss`, with `timeoutMs:900000`, `stdoutFile:"target\\plan16-train-week.out"`, and `stderrFile:"target\\plan16-train-week.err"`. After 300 seconds the MCP call returned `timed out awaiting tools/call after 300s` and an internal stack trace. A subsequent `search_processes` found the exact `cryptobot.exe` command still running as PID 37604; its output logs remained readable. Impact: the caller lost the exit status and could accidentally start a duplicate expensive backtest if it retried blindly. Safe fallback: check the exact process command line and logs, let that process finish, then use detached mode and short process/log polls for future long runs. This confirms the existing 300-second timeout defect also affects `mode:"sync"` while the child can survive the MCP timeout.

## 2026-09-23 — search_processes parameter validation exposes an internal stack trace

Reproduction: call `mcp__filesystem_mcp_rs__search_processes({pattern:"cargo|rustc"})`. The documented arguments are `name_pattern` and `cmdline_pattern`; `pattern` is an invalid caller argument.

Observed impact: the server returns `-32602: search_processes was called with neither name_pattern nor cmdline_pattern` followed by a full internal `Stack backtrace` (20 frames, including `aws_lc_0_39_0_jent_entropy_switch_notime_impl` and OS thread frames). The invalid argument is an expected user error; exposing the stack is the server defect and adds noise and implementation details to the result.

Safe fallback: call `search_processes({name_pattern:"cargo|rustc"})`, which succeeds. The server should return a concise validation error without a backtrace.

## 2026-09-23 — filesystem MCP capabilities unavailable to two team agents

Reproduction: in two independent `osl-rs` subagent scopes, inspect advertised capabilities and invoke `tools.mcp__filesystem__read_text_file`, `tools.mcp__filesystem__mem_get_summary`, or `tools.mcp__filesystem__seq_think` through `functions.exec`. The capabilities appeared in metadata, but invocation returned `TypeError: tools.mcp__filesystem__read_text_file is not a function` or `MCP tool not available to model`; the same class of failure affected the memory and sequential-thinking calls. The root agent and a third documentation subagent successfully invoked the filesystem MCP during the same team task.

Observed impact: two delegates could not use the mandatory filesystem, memory, or sequential-thinking MCP tools. This is a per-agent capability routing/availability defect, not evidence of a filesystem-mcp-rs server-wide outage. No internal server stack trace was observed for this case.

Safe fallback: route mandatory MCP operations through a team agent whose MCP calls work, or use read-only PowerShell inspection temporarily and have the working agent perform verified writes. Preserve the affected agents' capability listings and call results; compare initialization and routing across agent scopes.

Additional reproduction (2026-09-23): the `/root/hash_dedup` subagent called `tools.mcp__filesystem__run_command({command:'cargo',args:['fmt','--all'],cwd:'C:\\projects\\projects.rust.cg\\cglibs\\osl-rs',mode:'sync',timeoutMs:120000})` and received `MCP tool filesystem/run_command is not available to the model`. Calling the alias `mcp__filesystem_mcp_rs__run_command` returned `MCP tool filesystem-mcp-rs/run_command is not available to the model`. Its `ALL_TOOLS` listing had no `mcp__filesystem` entries, and `read_text_file` invocation raised `TypeError: ... is not a function`. The root agent still had MCP access and ran `cargo fmt --all` through it. Impact: the delegate could not perform mandatory MCP formatting verification. Safe fallback: have the root or another agent with working MCP perform the file and shell calls; do not treat this as a server-wide outage or bypass an active MCP session lock.

Additional reproduction (2026-09-23, second `osl-rs` continuation): three newly spawned subagents (`thinlayer`, `dict_parity`, `oso_struct`) attempted `tools.mcp__filesystem__seq_think`, `tools.mcp__filesystem__read_text_file`, and `tools.mcp__filesystem__grep_files` through `functions.exec`. Calls returned `MCP tool filesystem-mcp-rs/seq_think is not available to the model`, `MCP tool filesystem/read_text_file is not available to the model`, or `TypeError: tools.mcp__filesystem__grep_files is not a function`; one agent observed the tools in `ALL_TOOLS` before they disappeared. The root agent successfully read and edited files through the same MCP server during this period. Impact: all three delegates could not perform assigned source audits or fixes under the mandatory MCP-only policy. Safe fallback: have the root agent with working routing perform file and shell operations, while delegates review excerpts supplied by root; compare per-agent capability registration and routing lifetimes. This is not an expected missing-file error.

## 2026-09-23 — edit_file unsupported regex backreference exposes internal stack trace

Reproduction: call `mcp__filesystem__edit_file` with `path: "C:/projects/projects.rust.cg/cglibs/osl-rs/src/optimizer.rs"` and one edit with `isRegex: true`, `replaceAll: true`, `oldText: "(make_inert_nop\\(&mut ir\\.opcodes\\[([^\\]]+)\\]\\);)\\n\\s*ir\\.opcodes\\[\\2\\]\\.nargs = 0;"`, and `newText: "$1"`. The Rust regex engine does not support the `\\2` backreference, so rejection of the pattern is an expected caller error.

Observed impact: the tool returned MCP `-32603` for the unsupported backreference and appended a full internal `Stack backtrace`. A routine invalid pattern exposed implementation details and obscured whether any edit occurred.

Safe fallback: read the exact current lines and use literal `oldText`/`newText` edits or a supported regex without backreferences; verify the file after the call. The server should report the regex error without internal frames.

## 2026-09-23 — grep_context missing nearbyPatterns exposes internal stack trace

Reproduction: call `mcp__filesystem__grep_context({path:"C:/projects/projects.rust.cg/cglibs/osl-rs/src/symbol.rs",pattern:"fn reset",contextLines:12})`. This omits the required `nearbyPatterns`; the invalid argument is an expected caller error.

Observed impact: the tool returned MCP `-32602` for the missing nearby terms and appended a full internal `Stack backtrace`. The requested source inspection did not run.

Safe fallback: use `grep_files` for a plain context search, or call `grep_context` with nonempty `nearbyPatterns` and its documented `contextBefore`/`contextAfter` arguments. The server should return a concise validation error without internal frames.

## 2026-09-23 — grep_files invalid regex exposes internal stack trace

Reproduction: call `tools.mcp__filesystem__grep_files({path:"C:/projects/projects.rust.cg/cglibs/osl-rs/src",pattern:"optimize(",maxMatches:80})`. The unclosed group in `optimize(` is an invalid caller pattern; a regex parse error is expected.

Observed impact: the tool returned MCP `-32603` with `Grep failed: Invalid regex pattern: ... unclosed group` and a full internal `Stack backtrace` (frames 0–18). Source inspection did not run. The server defect is the internal stack disclosure for an ordinary invalid query.

Safe fallback: escape the parenthesis as `optimize\\(` or use a literal-safe search, then verify the matches. The server should return a concise regex error without internal frames.

## 2026-09-23 — edit_file joins the following CRLF line after a multiline replacement

Reproduction: on `cryptobot-rs/AGENTS.md` (CRLF working copy), call `mcp__filesystem_mcp_rs__edit_file` with `oldText: "      -> commit_pending_orders -> paper broker -> wallet sample -> inference_tick_at"` and `newText: "      -> commit_pending_orders -> JobFilter.terminal=false before clone/sort\n      -> paper broker -> wallet sample -> inference_tick_at"`. Read lines 319–321 afterward with `read_text_file`.

Observed impact: the replacement unexpectedly joined the next existing line, yielding `-> inference_tick_at     -> scoped or legacy equity sample...` on one line. A second `edit_file` attempt to repair the two lines again joined the following `-> Report` line. The tool returned a successful diff both times; without a readback, a dataflow diagram would have remained malformed. This was a valid literal replacement, so the join is a tool defect rather than an invalid caller argument.

Safe fallback: use `edit_lines` with explicit `line` and `endLine` for multiline changes on CRLF files, then immediately read the affected lines and check `git diff --check`. That operation repaired the diagram without joining the next line.

## 2026-09-23 — write_file binary validation exposes internal stack trace

Reproduction: call `mcp__filesystem__write_file` with `path: "C:\\projects\\projects.rust.cg\\cglibs\\osl-rs\\src\\thinlayer_energy.bin"` and `content: {kind: "base64", data: <valid base64 of a 32,768-byte f32 LUT containing NUL bytes>}`. The server rejects a NUL at byte offset 4 with MCP `-32602 nul_in_text`; rejecting binary through a text-only operation is an expected validation result.

Observed impact: the validation error also included a full internal stack trace. The binary LUT was not written. The defect is the internal stack disclosure for routine invalid input, not the NUL rejection.

Safe fallback: store the numeric LUT in a UTF-8 Rust source file, or use a documented binary-capable filesystem tool; verify the written table size and checksum. The server should return a concise validation error without internal frames.

## 2026-09-23 — disk_usage cannot resolve an existing Windows workspace path

Reproduction: call `mcp__filesystem__disk_usage({path:"C:\\projects\\projects.rust.cg\\cglibs\\osl-rs"})` on the existing workspace. The same path is readable through `read_text_file`, and PowerShell `Get-PSDrive -Name C` reports drive C with 7,002,324,992 bytes free.

Observed impact: the tool returned MCP `-32603: No disk found for path: C:\\projects\\projects.rust.cg\\cglibs\\osl-rs` plus a full internal stack trace. Disk inspection could not be performed through the dedicated MCP tool. This is a valid existing path, not an expected missing-file error.

Safe fallback: use `mcp__filesystem__run_command` with native PowerShell `Get-PSDrive -Name C` for a read-only capacity check. The server should normalize Windows paths and report errors without internal frames.

## 2026-09-24 — edit_file zero-match error exposes internal stack trace during documentation refresh

Reproduction: call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cgprojs/cryptobot-rs/AGENTS.md` with an `oldText` containing the stale GitNexus sentence `3,738 graph nodes, 10,095 relationships, 300 execution flows at the latest forced reindex`, while the current line says `4,281 graph nodes and 12,377 relationships`. The literal does not match, so a concise zero-match caller error is expected.

Observed impact: the server returned MCP `-32603`, a zero-match edit error, and a full internal `Stack backtrace` (25 frames). No file change was applied. The defect is internal stack disclosure for an ordinary stale-text error, not the expected match failure; this is another reproduction of the existing `edit_file` error-response issue.

Safe fallback: re-read the current line with `read_text_file`, then use `edit_lines` on its verified line number and inspect the diff. Return the no-match diagnostic without internal frames.

Additional reproduction (2026-09-24, `osl-rs` documentation): call `mcp__filesystem__edit_file` on `C:/projects/projects.rust.cg/cglibs/osl-rs/BUG_HUNT_REPORT.md` with two literal edits, the second using `oldText: "row below).\n## Unfinished code and compatibility"` while the file contains a backtick-delimited phrase before `row below).`. The expected zero-match validation returned MCP `-32603` and a full internal `Stack backtrace` (frames 0–24). Impact: an ordinary stale literal created noisy implementation-detail output; the batch applied no edit. Safe fallback: re-read the exact current lines and retry one verified literal edit at a time, then inspect the diff. This is another reproduction of the same server error-response defect, not a separate missing-file or validation defect.

Additional reproduction (2026-09-24, `osl-rs` documentation relocation): call `mcp__filesystem__edit_file` on `C:/projects/projects.rust.cg/cglibs/osl-rs/docs/.plans/DIAGRAMS.md` with two literal edits, first replacing `](AGENTS.md` and second replacing nonexistent `](README.md`. The second edit has no match; a concise caller error is expected. The server returned MCP `-32603` with `1 of 2 edits produced zero matches` and an internal `Stack backtrace` (frames 0–24); no edit was applied. Safe fallback: inspect each document's link inventory and issue only matching edits, then read the result. This is the same stack-disclosure defect, not a separate zero-match defect.

## 2026-09-24 — run_command command-not-found exposes internal stack trace

Reproduction: call `mcp__filesystem__run_command({command:"clang++",args:["--version"],cwd:"C:\\projects\\projects.rust.cg\\cglibs\\osl-rs",mode:"sync",timeoutMs:10000})` when `clang++` is absent from PATH. The same result occurs for `g++`. A concise command-not-found error is expected.

Observed impact: the server returned MCP `-32603 Failed to spawn command: clang++` followed by an internal `Stack backtrace` (frames 0–10), preventing compiler discovery through the tool. The missing executable is an expected caller/environment condition; the internal stack disclosure is the defect.

Safe fallback: use an installed compiler such as `cl`, or run a read-only PATH check through PowerShell. The server should return a concise spawn error without internal frames.

## 2026-09-24 — edit_lines overlap validation exposes internal stack trace

Reproduction: call `mcp__filesystem_mcp_rs__edit_lines` on `cryptobot-rs/.bughunt/plan16.md` with two edits targeting the same original line 135, one `replace` and one `insert_after`. The operations overlap, so rejecting the caller request without changing the file is expected.

Observed impact: the server returned MCP `-32603` with an overlap error and a full internal `Stack backtrace`. No edit was applied. The defect is disclosure of internal frames for a routine edit-validation failure, not the overlap rejection.

Safe fallback: submit the dependent edits in separate `edit_lines` calls, re-read the affected region between them, and verify the diff. The server should return a concise overlap diagnostic without internal frames.

## 2026-09-24 — run_command PowerShell variable validation exposes internal stack trace

Reproduction: call `mcp__filesystem__run_command({command:"powershell",args:["-NoProfile","-Command","Get-ChildItem -LiteralPath 'C:\\Users\\joss1\\.cargo\\git\\checkouts' -Directory -Name | Where-Object { $_ -match 'oiio|vfx' } | Select-Object -First 10"],cwd:"C:/projects/projects.rust.cg/cglibs/osl-rs",mode:"managed",timeoutMs:30000})`. The server rejects the `$_` token before spawning PowerShell. A concise validation error is expected for this host policy.

Observed impact: MCP `-32602` said `command/args contain $_` and included a full internal `Stack backtrace` (frames 0–24). The read-only dependency inventory did not run. The defect is stack disclosure on an expected rejected argument, not the token policy itself.

Safe fallback: use `search_files` on a narrow path, or pass the PowerShell script through the documented stdin ContentRef or a script file. The server should report the token restriction without internal frames.

## 2026-09-24 — mem_link out-of-scope item exposes internal stack trace

Reproduction: call `mcp__filesystem__mem_link` with `workspaceId:"C:/projects/projects.rust.cg/cglibs/osl-rs"`, `actorId:"texture_metadata"`, and `relation:{fromItemId:"eb65b8c8-ba91-4cde-817f-60fc94e241c7",relationType:"continues",toItemId:"785fafad-b434-460f-a0ce-48eb10a989f2"}`. The target item is outside the actor's visible scope; a concise not-found error is expected.

Observed impact: MCP `-32603` reported `toItemId ... not found in scope` and included an internal `Stack backtrace` (frames 0–24). No relation was created. The defect is internal frame disclosure for expected scope validation, not the rejection.

Safe fallback: link only IDs returned by `mem_put` or `mem_search` in the same visible scope. A relation between two new visible items then succeeded. The server should return the scope error without internal frames.

## 2026-09-25 — filesystem MCP callable absent in delegated agents

Reproduction: spawn an `explorer` sub-agent for the `usd-rs` parity audit; in that agent's `functions.exec`, call `tools.mcp__filesystem__read_text_file({path:"D:\\projects\\vfx.ref\\OpenUSD\\README.md",head:10,line_numbers:true})`. The tool appears in `ALL_TOOLS`, but the call raises `TypeError: tools.mcp__filesystem__read_text_file is not a function`. A second agent observed the same for `tools.mcp__filesystem__seq_think` and `search_files`; its Promise-based attempt reported `MCP tool filesystem/... is not available to the model`. The root agent's same namespace is callable in this session.

Observed impact: delegated read-only analysis cannot follow the required filesystem-MCP workflow. This is a tool-exposure failure in delegated agents, not a missing file or an expected caller error. No data was modified by the failed calls.

Safe fallback: the root agent uses working filesystem-MCP calls for reads and writes; affected delegated agents use read-only PowerShell commands for their inventories and report exact paths and lines. Restore callable bindings for advertised filesystem tools in delegated agents.

## 2026-09-25 — edit_file unmatched edit exposes internal stack trace

Reproduction: call `mcp__filesystem__edit_file` on `usd-rs/crates/usd/usd-sdf/src/path.rs` with two literal edits, where the second `oldText` incorrectly expects `"/Foo:Bar",` followed by a differently indented closing `];`. The expected response is a concise zero-match error, with no file change.

Observed impact: MCP `-32603` reported `1 of 2 edits produced zero matches` and a full `Stack backtrace` (frames 0–24). The input mismatch is an expected caller error; disclosure of internal frames is the server defect. No edit was applied.

Safe fallback: re-read the exact lines, submit literal edits separately, and verify the diff. The server should omit internal frames for ordinary edit validation failures.

## 2026-09-25 — locate_search missing query exposes internal stack trace

Reproduction: call `mcp__filesystem__locate_search({path:"D:\\projects",query:"",mode:"contains",limit:5,waitMs:30000})`. A nonempty query is required for `contains`, so rejecting this caller input is expected.

Observed impact: the server returned MCP `-32602: mode requires query` followed by an internal `Stack backtrace` (frames 0–24). The empty query is an expected user error; disclosure of internal frames is the server defect. The lookup did not run.

Safe fallback: provide a nonempty query, or omit `mode` and `query` when listing indexed names. The server should return a concise validation error without internal frames.

Follow-up (2026-09-25, source-level check): `cargo test --no-default-features --features locate-tools --test integration locate_invalid_query_returns_concise_protocol_error` passed. The server's direct stdio JSON-RPC response contains only `-32602` and `mode requires query`; it does not contain `Stack backtrace`. The internal frames in the observed tool output are added by the MCP tool host when it formats a failed call. The empty query remains an expected caller error, not a `filesystem-mcp-rs` server defect. Keep this reproduction for host-side triage.

## 2026-09-25 — locate_search fails with database locked during active scan

Reproduction: start `mcp__filesystem__locate_refresh({path:"D:\\projects",waitMs:30000})` while the D: locate index is building, then call `mcp__filesystem__locate_search({path:"D:\\projects",query:"projects",mode:"contains",kind:"directories",limit:10,waitMs:1000})`. Repeat the search while `locate_status` reports `state:"building"`. Both attempts returned the same failure.

Observed impact: a valid locate query fails with MCP `-32603: Index queue failed: database is locked({"error":"database is locked"})` and an internal `Stack backtrace` (frames 0–24), so indexed lookup is unavailable during the scan. This is a server concurrency/error-handling defect, not invalid user input.

Safe fallback: wait for `locate_status` to report a completed index before querying, or use `list_directory` / `search_files` for a live lookup. The server should queue or read safely during indexing and return concise errors without internal frames.

Additional reproduction: after `locate_status({path:"D:\\projects",waitMs:1000})` reported `state:"partial"` with `completedSeq:0`, call `locate_refresh({path:"D:\\projects",requestId:"37096-18d89be84d7622cc-0",waitMs:30000})`. It returned `-32603: Index refresh failed: database is locked` with the same internal stack trace, preventing a retry.

Follow-up (2026-09-25): the database lock is a server concurrency problem; the stack frames appear in the MCP host's failed-call formatting. A separate direct stdio integration test confirms that a normal `locate_search` validation error contains no stack frames, so frame attribution for this lock error should be checked at the host boundary before treating it as a second server defect.

Source fix (2026-09-25): `ensure_index` and idempotent `request_refresh` now read the existing queue/receipt before asking SQLite for a writer lock. A completed traversal with inaccessible entries records `partial` without a minute-by-minute retry loop; the first scan keeps its usable entries, and a later partial refresh keeps the previous published generation. Regression tests and the full `cargo test` suite pass. The running installed MCP process has not been replaced or re-tested against `D:\projects`.
