<!-- 2026-10-01: Additional expected-input stack-leak reproduction: filesystem-mcp-rs copy_file source C:/projects/projects.rust.cg/cglibs/ofx-rs/target/fix-viewer-plan-contract/host/src/host_core.rs to target/verify-viewer-plan-contract/host/src/host_core.rs with overwrite:true. Caller omitted crates/ofx-host; missing path rejection was expected. Observed -32603 Failed to stat source with full native Stack backtrace (aws_lc, BaseThreadInitThunk). Impact: internal trace disclosure, no copy. Safe fallback: read exact paths from author manifest, then copy crates/ofx-host/src/host_core.rs; retry succeeded. -->
# filesystem-mcp-rs tool failures

## 2026-10-25 � detached run_command accepts missing log parents then silently loses the run

- **Exact reproduction:** With `D:/_ai/lgpt/work/staging/shared-scope` existing but its `missing-output-parent` child absent, call `run_command({command:"rustc",args:["--version"],cwd:"C:/projects/projects.rust.cg/cglibs/egui-widgets-rs",mode:"detached",timeoutMs:60000,stdoutFile:"D:/_ai/lgpt/work/staging/shared-scope/missing-output-parent/repro-stdout.log",stderrFile:"D:/_ai/lgpt/work/staging/shared-scope/missing-output-parent/repro-stderr.log"})`. The response reports `background:true,pid:51560,killed:false,timedOut:false` and both log paths. After completion, the PID is absent, the child directory still does not exist, and neither log exists. The earlier real invocation `cargo test -p soluwell-panels --lib signal_inspection::tests -- --test-threads=1` behaved identically with new output parent `D:/_ai/lgpt/work/runs/20261025-shared-scope-panels` (reported PID61164).
- **Observed impact:** A nonexistent output parent is an expected caller input error; accepting the detached run without validating/opening the log destinations and then providing no failure/completion receipt is the defect. The caller cannot distinguish a successful external command from a background setup failure and must not infer success from the initial response. A synchronous `rustc --version` with output files directly in the existing `shared-scope` parent completes with exit0 and captures its output.
- **Safe fallback:** Explicitly `create_directory` for all output parents before launching, poll the exact owned process and logs, and keep a completion/exit-code receipt for long detached commands. Never repeat while the original process remains alive. Server-side: validate/open output sinks before acknowledging the detached task, or persist a visible asynchronous failure/completion state.


## 2026-10-24 � edit_file zero-match error exposes a native stack during lgpt-rs docs update

- **Additional 2026-10-25 window-close recurrence:** An owned native window with ID35914756 disappeared before cleanup. `win_close({target:{id:35914756}})` returned the expected `no_match` as MCP -32602 plus a full internal `Stack backtrace` (frames0..25, including aws_lc and BaseThreadInitThunk). A window disappearing before close is expected lifecycle behavior; the defect is internal stack disclosure and noisy error output. Safe fallback: refresh the window inventory and verify the owned process state; if the window and its owned processes have already exited, cleanup is complete and no repeated close is needed. The orchestrator verified that no owned lgpt/xtask processes remained. This records the observed failure without an additional reproduction or source change.

- **Additional 2026-10-25 lgpt-rs recurrence:** `edit_file` on `C:/projects/projects.rust.cg/ai/lgpt-rs/crates/gui/src/signal_inspection.rs` with absent literal oldText `pub(crate) const DISPLAY_UNIT: &str = DISPLAY_UNIT;` returned the expected no-match rejection plus a full internal `Stack backtrace` (frames0..25, including aws_lc_jent and BaseThreadInitThunk). The actual initializer remained a string literal. This was a caller's invalid edit request; the defect is noisy internal trace disclosure, not rejection. Safe fallback: `read_text_file` first, then retry the verified exact literal. No additional reproduction run or source change was required.

- **Exact reproduction:** Call `edit_file` with `path="C:/projects/projects.rust.cg/ai/lgpt-rs/HANDOFF.md"`, `dryRun=true`, and one literal edit from `DOCS_NO_MATCH_SENTINEL_20261024` to `unused`. The marker is absent. The same response occurred for a real batch whose final oldText omitted a backtick.
- **Observed impact:** Rejecting an unmatched edit is expected caller-error handling; the server defect is appending a full `Stack backtrace` (26 frames including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`) to the MCP -32603 response. No file changed; the earlier batch rejection was atomic.
- **Safe fallback:** Re-read exact source text, correct the literal, and apply a small verified edit. Keep native traces in server logs and return a concise structured no-match error to the client. Do not tolerate a miss with `failOnNoMatch=false` when the intended edit is required.

- **Additional 2026-10-24 WarpBro reproduction:** `mcp__filesystem__edit_file` on `C:/projects/projects.rust.cg/cglibs/warpbro-rs/src/app_actions.rs` with a five-edit batch containing literal oldText `                self.colour.set_sel(&selection);\n                self.commit_colour_selection(selection, edit_frame)?;` and replacement `                self.commit_colour_selection(selection.clone(), edit_frame)?;\n                self.colour.set_sel(&selection);` failed because the actual second line still lacked `edit_frame`. Observed the expected zero-match rejection plus full native stack. The complete batch was atomic (verified by re-read); no source changes from the failed batch. Safe fallback: re-read the current exact block and retry only verified literals; the corrected batch succeeded.

## 2026-10-13 UTC (2026-10-12 local) � live PID tree kill fails, HTTP allowlist error leaks internal stack

- Reproduction: `search_processes({cmdline_pattern:"render-trial.ts serve --port 43874"})` observed live Bun PID51152; `kill_process({pid:51152,tree:true,force:false})` returned `success:false,killedCount:0,"No processes found in tree"`. Immediate process search still observed PID51152 and the port remained occupied; restarting verified server failed EADDRINUSE. Impact: managed lifecycle recovery could not stop a verified root process. Safe fallback: recheck exact owned PID, then `kill_process({pid:51152,tree:false,force:true})`; observed success killedCount1, new Bun PID118580 listens on the same localhost port. No unrelated processes were targeted.
- Reproduction: `http_request({url:"http://127.0.0.1:43874/cosines.html",method:"HEAD",timeoutMs:10000})`. Domain rejection `HTTP domain '127.0.0.1' is not in allowlist` is expected policy behavior, not a domain-access defect. Observed response also exposed a full native Stack backtrace with aws_lc_jent_entropy, BaseThreadInitThunk and RtlUserThreadStart. Impact: internal trace disclosure on expected policy error. Safe fallback: respect HTTP tool allowlist and verify the already authorized compiled local trial through prescribed CUA browser observation; do not retry domain variants or alter allowlist.


## 2026-10-03 � long run_command transport timeout exposes an internal stack

- **Additional exact recurrence (2026-10-07, far-rs integrated cohort):** `run_command({command:"cargo",args:["build","-p","far-rs","--bin","far-rs","--locked","-j1"],cwd:"C:/Temp/far-c1c-verify-tree",env:{CARGO_TARGET_DIR:"C:/Temp/far-c1b-sys-target",TEMP:"D:/Temp/far-c1a-sys-scratch",TMP:"D:/Temp/far-c1a-sys-scratch"},mode:"sync",timeoutMs:600000,stdoutFile:"C:/Temp/far-size-bin-build-out.log",stderrFile:"C:/Temp/far-size-bin-build-err.log",stdoutTail:1,stderrTail:25})` failed at the 300-second MCP transport limit, with the same 25-frame internal stack. A second exact recurrence used `wsl.exe -d Ubuntu --cd /mnt/c/Temp/far-c1c-verify-tree -- env CARGO_TARGET_DIR=/home/joss/far-rs-net-target cargo test -p far-vfs -p far-fileops --lib --locked -j1 -- --test-threads=2`, the same mode/runtime limit and explicit `far-cohort-linux-vfs-fileops-test-{out,err}.log` paths.
- **Observed impact:** Both calls lost their final exit result while commands continued. The Windows log later recorded `Finished` in 6m26s and process inspection confirmed that owned build had exited. The Linux log recorded a completed test executable with 97 passes and 36 failures; those scenario failures are code/contract evidence, not a filesystem-server defect. The transport failure and internal stack disclosure are the defects.
- **Safe fallback:** Inspect the explicit logs and actual owned process state without touching unrelated builds. Before subsequent long gates, use a filesystem `run_command` PowerShell stdin wrapper that writes the actual external command exit code to a unique completion file; inspect that file after transport loss. Repeat only once the original process is confirmed finished, and never infer exit 0 from a transport failure.

- **Exact reproduction:** `run_command` with command `python`, args `["-u", "-c", "import bootstrap,sys; sys.exit(bootstrap.run(['cargo','oxide','test','--','--release','--','--test-threads=1'])[0])"]`, cwd `C:/projects/projects.rust.cg/cglibs/frac-rs`, mode `managed`, timeoutMs `600000`, stdoutTail `5`, stderrTail `10`, and env `PYTHONDONTWRITEBYTECODE=1`, `CARGO_NET_GIT_FETCH_WITH_CLI=true`, `GIT_SSH_COMMAND=C:/Windows/System32/OpenSSH/ssh.exe`.
- **Observed impact:** The MCP caller timed out after 300 s despite the requested 600 s command timeout, returned `timed out awaiting tools/call after 300s` and a 25-frame internal native stack, and provided no final command result or log paths. A long-running test is not itself a server defect; stack disclosure and missing lifecycle information on transport failure are the defects. The test process continued and its logs subsequently completed.
- **Safe fallback:** Find the narrow timestamp-matched run_command logs using filesystem tools, read their final summaries, and inspect process state without terminating unrelated builds. Use explicit stdoutFile/stderrFile and shorter managed calls or detached launch/polling for future long jobs.
- **Additional exact reproduction on 2026-10-06, ffmpeg-rs F7:** `run_command({command:"pwsh",args:["-NoProfile","-File","C:/Temp/f7-build-tests.ps1"],shell:"pwsh",mode:"managed",timeoutMs:3600000,stdoutFile:"C:/projects/projects.rust.cg/cglibs/ffmpeg-rs/.agents/plan10/logs/f7_build_tests.log",stderrFile:"C:/projects/projects.rust.cg/cglibs/ffmpeg-rs/.agents/plan10/logs/f7_build_tests.err"})` returned tool-call failure `timed out awaiting tools/call after 300s` plus 25 native frames, including aws_lc, BaseThreadInitThunk, and RtlUserThreadStart. The script runs `cargo test --workspace --release --no-run --message-format short` with `CARGO_BUILD_JOBS=3`, `CARGO_INCREMENTAL=0`, one `CARGO_TARGET_DIR=C:/Temp/f7_target`, and processor affinity 255.
- **Additional observed impact and evidence:** The requested one-hour command runtime did not prevent the shorter five-minute transport deadline. The caller lost the final exit status while compilation continued; no duplicate build was started. Independent read-only inspection found the script still running (pwsh PID 34420) and three rustc workers using `f7_target` under cargo PID 71992. The stderr log was created at `2026-10-07T01:18:04Z` and subsequently modified at `2026-10-07T01:29:34Z`, size 13431 bytes, beyond the 300-second call deadline; stdout remained empty. This is a transport/lifecycle failure, not a command runtime timeout or missing-path input error. Internal stack disclosure is an additional clear server defect; the underlying transport-limit cause is not asserted.
- **Additional safe fallback:** Continue monitoring the existing process and explicit logs through short read-only control calls; recover its actual completion status before treating the build as successful. For subsequent long work, use an explicit completion marker carrying the command exit status and short managed control calls. Do not infer exit 0 from a transport timeout or empty stdout, and do not launch another copy while the original is alive.

- **Additional exact reproduction (2026-10-06, scoped F7 process inventory):** After two successful file reads in exec cell `155`, the coordinator called `mcp__filesystem_mcp_rs__search_processes({cmdline_pattern:"f7-build-tests.ps1"})`. It returned `timed out awaiting tools/call after 300s` and 25 native stack frames, including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`. The cell eventually returned ToolError; no fresh process inventory was obtained.
- **Additional observed impact:** This scoped inspection timed out during the running prebuild and blocked confirmation of current PIDs. It is an observed tool/transport failure, not a nonexistent-file caller error. The cause of the delay is not established; exposing the full internal trace is the existing diagnostic defect. No source changes or new build were started by this call.
- **Additional safe fallback:** Inspect the known owned root with `proc_tree({pid:20048})` and fresh completion logs, or use filesystem `run_command` with native `Get-Process -Id 20048`. Reconfirm ownership/lifecycle from the existing logs and actual completion marker; a disappeared PID is an expected race. Do not kill unrelated processes or launch a duplicate build.

- **Additional exact recurrence (2026-10-06, F7 content-key build, exec 175):** `mcp__filesystem_mcp_rs__run_command({command:"pwsh",args:["-NoProfile","-File","C:/Temp/f7-build-tests.ps1"],mode:"managed",timeoutMs:7200000,stdoutFile:"C:/projects/projects.rust.cg/cglibs/ffmpeg-rs/.agents/plan10/logs/f7_build_tests_content_key.log",stderrFile:"C:/projects/projects.rust.cg/cglibs/ffmpeg-rs/.agents/plan10/logs/f7_build_tests_content_key.err"})` returned `timed out awaiting tools/call after 300s`, `isError:true`, and 25 internal native frames including aws_lc, BaseThreadInitThunk, and RtlUserThreadStart. No actual build exit result was returned.
- **Additional observed impact:** The RPC cell closed while the original build continued. The coordinator's bounded native inventory confirmed one original inner pwsh PID 91904 (parent 64100, created `2026-10-07T03:49:23.527484Z`) and three owned `f7_target` rustc workers progressing through different test targets. The stdout has no exit marker, stderr has no `Finished`, and the existing exit file predates this launch. This is the same transport/lifecycle failure plus internal stack disclosure; the delay's underlying cause is not asserted.
- **Additional safe fallback:** Monitor the original owned PID inventory, changing logs, and a fresh completion marker. Do not use the stale interrupted-build 101 marker as this run's result, infer success from cell closure, restart or duplicate the build, or kill unrelated processes.


- **Additional exact recurrence (2026-10-06, F7 reviewed-source build, exec 309):** `mcp__filesystem_mcp_rs__run_command({command:"pwsh",args:["-NoProfile","-File","C:/Temp/f7-build-tests-reviewed.ps1"],cwd:"C:/projects/projects.rust.cg/cglibs/ffmpeg-rs",shell:"none",timeoutMs:14400000,killAfterMs:1000,streamOutput:false,stdoutFile:"C:/projects/projects.rust.cg/cglibs/ffmpeg-rs/.agents/plan10/logs/f7_build_tests_reviewed.log",stderrFile:"C:/projects/projects.rust.cg/cglibs/ffmpeg-rs/.agents/plan10/logs/f7_build_tests_reviewed.err",stdoutTail:12,stderrTail:20})` (mode omitted) returned `timed out awaiting tools/call after 300s` plus 25 internal native frames, including aws_lc, BaseThreadInitThunk, and RtlUserThreadStart. It returned no actual build exit result despite the four-hour requested runtime limit.
- **Additional observed impact:** The coordinator's fresh inventory confirms the original owned root 67656 (started JSON UTC `2026-10-07T06:35:05.6204477Z`) and Cargo 25316 continue, with three owned rustcs (84488/101728/60008) at affinity 255. Reference processes are zero; free space is 54.94 GB at that snapshot; reviewed-build logs have no `Finished`. This is the same observed transport/lifecycle failure and stack disclosure; the transport deadline's cause is not established. Tool-call closure is not build completion or a pass.
- **Additional safe fallback:** Keep source frozen and monitor the original owned root/process tree, reviewed-build logs, started PID/UTC JSON, and unique fresh exit marker through short calls. Await actual completion; do not restart or duplicate the build, reuse stale markers, or infer success from the tool error.


## 2026-10-01 — Additional expected-error internal stack disclosures (phase 7)

- Exact reproduction reported by the read-only cache-contract planner: `search_files({path:"C:/projects/projects.rust.cg",pattern:"{AGENTS.md,CLAUDE.md}",excludePatterns:["**/target/**","**/.git/**","**/node_modules/**"],fileType:"file"})` reached its 300 s deadline and returned a full 25-frame native stack (aws_lc/BaseThreadInitThunk/RtlUserThreadStart). A broad inventory timing out is not by itself proof of a search defect; exposing internal frames in that error is the server defect. Impact: ancestor inventory was unavailable. Safe fallback: nonrecursive `list_directory` at each ancestor and narrowly scoped repository searches excluding worktrees; this succeeded.
- Exact reproduction reported by the scoped viewer-test author: `search_processes({query:"gitnexus"})` omitted documented `name_pattern`/`cmdline_pattern`; expected -32602 validation exposed a full 25-frame native stack. Caller argument error is distinct from stack disclosure. Impact: no process inspection ran, no process was killed. Safe fallback: use `name_pattern:"gitnexus"` and return a concise validation error.


## 2026-09-28 â€” Invalid `grep_files` regex exposes internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_files` with `path: "C:\\projects\\projects.rust.cg\\cglibs\\rez-rs\\src"`, `pattern: "validate_package_data("`, `filePattern: "*.rs"`, `contextBefore: 1`, `contextAfter: 3`, `maxMatches: 20`, and `lineNumbers: true`. The default regex parser rejects the unclosed `(` and returns an internal `Stack backtrace`.
- **Observed impact:** The malformed regex is an expected caller input error; leaking native server frames is a server defect. The search does not run and no files are changed.
- **Safe fallback:** Use `fixedStrings: true` for the literal pattern or escape the parenthesis as `\\(`. Return a concise regex validation error without internal stack frames.

## 2026-09-28 â€” Validation and stale-anchor errors expose internal stack traces

- **Reproduction A:** Call `mcp__filesystem_mcp_rs__run_command` with `command: "rg -n \"pub fn ...\" C:\\Users\\joss1\\.cargo\\registry\\src\\*"` after first assigning `$roots = Get-ChildItem ...` in a PowerShell command. The host rejects the `$roots` token before spawn and returns a full native `Stack backtrace`.
- **Observed impact A:** The environment-variable guard blocks the command before it runs; the expected validation rejection exposes internal server frames and excessive output. This is an argument-validation failure, not a defect in PowerShell or `rg`.
- **Safe fallback A:** Use a literal known registry path, or pass the script through stdin/a `.ps1` file as supported by `run_command`; return a concise validation error without native frames.
- **Reproduction B:** Call `mcp__filesystem_mcp_rs__edit_file` for `C:\\projects\\projects.rust.cg\\cglibs\\rez-rs\\src\\gui\\mod.rs` with five literal edits, the fifth targeting the stale text `eframe::egui::TopBottomPanel::top(\"top_panel\").show(ui,`. The tool reports that this one anchor matched zero lines and returns a full native `Stack backtrace`. The file was re-read and confirmed unchanged by that call.
- **Observed impact B:** One stale anchor prevents the multi-edit request from being applied and leaks internal frames. A zero-match anchor is an expected edit conflict; the server should return a concise structured error.
- **Safe fallback B:** Re-read the target, apply independently verified edits one at a time, and verify each diff. Return no native stack frames for a normal no-match result.

## 2026-09-27 â€” Internal stack trace on rejected shell argument

- Reproduction: call `mcp__filesystem__run_command` with `command: "powershell"` and `args: ["-NoProfile", "-Command", "$p='crates/usd/usd-pcp/src/cache.rs'; $lines=Get-Content -LiteralPath $p; for($i=970;$i -le 1020;$i++){ '{0}: {1}' -f ($i+1),$lines[$i] }"]` in `C:\projects\projects.rust.cg\cglibs\usd-rs`.
- Observed impact: the safety validation correctly rejects `$p` expansion, but the MCP error includes a full internal `Stack backtrace` with native frames instead of a concise validation error. No command is run.
- Additional reproduction on 2026-09-28: call `mcp__filesystem_mcp_rs__run_command` with `command: "wsl.exe"`, `args: ["-d", "Ubuntu", "--", "bash", "-lc", "printf 'release: '; . /etc/os-release && printf '%s %s\\n' "$PRETTY_NAME" "$VERSION_CODENAME"; ..."]` from the Nova Linux workspace. The host rejects `$PRETTY_NAME` before spawn and returns the same full native stack trace. No command is run.
- Additional observed impact: ordinary Bash environment-variable syntax is rejected by the guard; the inspection command cannot run as passed.
- Additional reproduction on 2026-09-28: call `mcp__filesystem_mcp_rs__run_command` with `command: "wsl.exe"`, `args: ["-d", "Ubuntu", "-u", "root", "--", "bash", "-lc", "â€¦ dpkg-query --showformat='${Conffiles}\\n' --show mc"]`. The host rejects `${Conffiles}` before spawn and returns the same full native stack trace. No command is run.
- Additional observed impact: dpkg's documented `${Field}` format placeholders are blocked by the shell-argument guard, preventing this metadata query as passed.
- Safe fallback: use `mcp__filesystem__read_text_file` or pass a script by stdin ContentRef or a `.ps1` file, as the validation message suggests.

- Additional exact reproduction on 2026-10-02, reported from the existing oidn-rs team tool record (not rerun): `mcp__filesystem_mcp_rs__run_command({"command":"powershell","args":["-NoProfile","-Command","$source='C:/projects/projects.rust.cg/cglibs/squarebob-rs/crates/pt-denoise-oidn/src/lib.rs'; $destination='C:/projects/projects.rust.cg/cglibs/squarebob-rs/target/oidn-contract-check/crates/pt-denoise-oidn/src/lib.rs'; Copy-Item -LiteralPath $source -Destination $destination; Get-FileHash -LiteralPath $source,$destination -Algorithm SHA256 | Select-Object Path,Hash | ConvertTo-Json -Compress"],"cwd":"C:/projects/projects.rust.cg/cglibs/squarebob-rs","mode":"sync","timeoutMs":10000,"stdoutHead":5,"stderrHead":10})`. The call is bounded between adjacent successful events 21:49:25.169 and 21:49:35.418 UTC; the rejected result has no own timestamp.
- Observed impact: expected -32602 shell-token validation rejected `$source` before spawn, explaining that the MCP host may delete NAME tokens and recommending stdin ContentRef or a script file. The defect is a full 25-frame internal stack disclosure including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk` and `RtlUserThreadStart`. No process spawned and no copy occurred.
- Verified safe fallback: two separate PowerShell commands using literal paths, first `Copy-Item` source to destination, then `Get-FileHash` on both literal paths. Both succeeded and SHA256 matched `0179E091EAB3A6A3AD0A81A9CBDE423A8D7462CE14FA730FC8C41AF5EDAF5504`. Preserve the concise expected validation; omit server frames.


## 2026-09-28 â€” `edit_file` no-match error includes an internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:\\projects\\projects.rust.cg\\cgprojs\\oh-my-harness\\BUG3.md` with a literal `oldText` that is not present (here, a guessed final excerpt). The tool correctly reports that the literal match count is zero, but also returns a full `Stack backtrace` with native frames.
- **Observed impact:** A normal stale-match/edit-conflict error exposes internal implementation details and produces an unnecessarily large response. The requested edit is not applied.
- **Safe fallback:** Re-read the target immediately before editing, use an exact known anchor or `failOnNoMatch=false` where appropriate, and verify the file afterward; return a concise structured no-match error without native stack frames.

## 2026-09-28 â€” `grep_context` empty-context error includes an internal stack trace

- **Reproduction:** Call `mcp__filesystem__grep_context` with `path: "C:\\projects\\projects.rust.cg\\cglibs\\rez-rs\\src\\builders\\mod.rs"`, `pattern: "variant_install_dir|pub fn build\\("`, and `contextLines: 12`, omitting `nearbyPatterns`. The tool rejects the empty nearby-pattern set and returns a full native `Stack backtrace`.
- **Observed impact:** An argument-validation error exposes internal frames and produces excessive output; no file operation occurs.
- **Safe fallback:** Use `grep_files` for a plain text search, or call `grep_context` with non-empty `nearbyPatterns`.

## 2026-09-28 â€” `edit_file` multi-edit no-match error includes an internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:\\projects\\projects.rust.cg\\cgprojs\\nova-linux-rs\\PLAN2.md` with five literal edits targeting `| | Ð¡Ð¸ÑÑ‚ÐµÐ¼Ð½Ñ‹Ðµ Ð¿Ð¾ÑÑ‚Ð°Ð²Ñ‰Ð¸ÐºÐ¸ |`, `| | ÐŸÐ¾Ð²ÑÐµÐ´Ð½ÐµÐ²Ð½Ñ‹Ð¹ Ð¸Ð½Ñ‚ÐµÑ€Ð°ÐºÑ‚Ð¸Ð²Ð½Ñ‹Ð¹ CLI |`, `| | Ð Ð°Ð·Ñ€Ð°Ð±Ð¾Ñ‚ÐºÐ° |`, `| | Ð¯Ð·Ñ‹ÐºÐ¾Ð²Ñ‹Ðµ toolchain-Ñ‹ |`, and `| | ÐšÐ°Ð½Ð´Ð¸Ð´Ð°Ñ‚Ñ‹ Ð½Ð° Ð¿Ñ€Ð¾Ð²ÐµÑ€ÐºÑƒ |`. These guessed strings are absent; the tool reports all five zero-match results and includes a full native `Stack backtrace`. No edit is applied.
- **Observed impact:** An ordinary stale-text/no-match error returns a large internal stack trace and wastes output; the requested text remains unchanged.
- **Safe fallback:** Re-read the exact target range immediately before editing and use an exact anchor from the returned content, then verify the result. Keep no-match errors concise and omit native stack frames.

## 2026-09-28 â€” Invalid `grep_files` regular expression includes an internal stack trace

- **Reproduction:** Call `mcp__filesystem__grep_files` with `path: "C:\\projects\\projects.rust.cg\\cglibs\\rez-rs\\src\\shell\\wrapper.rs"` and `pattern: "create_forwarding_script|create_wrapper("` using the default regex engine. The unclosed parenthesis is rejected as an invalid regular expression and the tool returns a full internal stack trace.
- **Observed impact:** A malformed search pattern is an expected input-validation error, but its response exposes native server frames and produces excessive output. No file is changed.
- **Safe fallback:** Use `fixedStrings: true` for literal searches or escape the parenthesis in regex mode; return a concise validation message without internal stack frames.

## 2026-09-28 â€” `grep_context` rejects omitted `nearbyPatterns` with an internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_context` with `{ path: "C:\\projects\\projects.rust.cg\\cglibs\\rez-rs\\_ref\\rez\\src\\rez\\package_test.py", pattern: "pre_test_commands", before: 5, after: 8 }` and omit `nearbyPatterns`. The call is rejected because `nearbyPatterns` is empty and returns a full internal stack trace.
- **Observed impact:** A normal argument-validation error exposes internal server frames and excessive output; the requested source context is not returned, and no file is changed.
- **Safe fallback:** Use `mcp__filesystem_mcp_rs__grep_files` for the symbol search, then `mcp__filesystem_mcp_rs__read_text_file` with a line offset and limit. Return a concise validation error without internal stack frames.


## 2026-09-28 â€” Invalid grep root and stale diagram edit expose internal stack traces

- **Reproduction A:** Call `mcp__filesystem_mcp_rs__grep_files` with `path: "C:/Users/joss1/.cargo/git/checkouts/nodes-rs-*"`, `pattern: "graph_changed"`, and `include: "*.rs"`. The wildcard is invalid in the root path; the tool returns `Invalid root path` plus a full native `Stack backtrace`.
- **Observed impact A:** The requested source search does not run because the path argument is malformed. That input error is an operator mistake; exposing the internal trace for it is a server error.
- **Safe fallback A:** List the parent directory first, then search under an exact discovered checkout path. Return a concise invalid-path response without native frames.
- **Reproduction B:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:\\projects\\projects.rust.cg\\cglibs\\rez-rs\\DIAGRAMS.md` with a two-edit request where the first literal anchor assumes `O[EditorWidget::ui]` and `P --> Q[...]` on separate lines. The actual Mermaid source is `O --> P[EditorWidget::ui]`; the stale first anchor yields zero matches and the tool returns a full native `Stack backtrace`.
- **Observed impact B:** The guessed anchor is an expected edit conflict and no part of the multi-edit request is applied; the server leaks internal frames for the normal no-match condition.
- **Safe fallback B:** Re-read the exact source lines and apply an exact matching edit. Keep zero-match errors concise and make multi-edit failure atomic and structured.


## 2026-09-28 â€” Regex edit without multiline anchor returns internal stack traces

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on each of `BUG_HUNT_REPORT.md`, `plan1.md`, `plan2.md`, and `plan3.md` with regex edit `{ oldText: "[ \\t]+$", newText: "", isRegex: true, replaceAll: true }`. All calls report zero matches and return full native stack traces. The same expression with the inline multiline flag `(?m)` matches and edits the intended trailing spaces.
- **Observed impact:** The no-match result follows from the regex lacking multiline mode, so the input pattern was incorrect; returning an internal stack trace for this ordinary no-match condition is a server defect.
- **Safe fallback:** Use `(?m)` for line-ending matches and verify with a dry run. Return concise structured no-match errors without native stack frames.

## 2026-09-28 â€” run_command rejects PowerShell variable syntax with internal stack trace

- **Reproduction:** Call filesystem MCP run_command with command `powershell`, args `["-NoProfile", "-Command", "git log --format=%ae | Sort-Object -Unique | ForEach-Object { if ($_ -match '@users\\.noreply\\.github\\.com$') { 'github-noreply-email' } }"]`, and a valid repository cwd. The host rejects the `$_` token before process launch, then returns a full native stack backtrace.
- **Observed impact:** The script is rejected before execution; the hostâ€™s precaution against variable expansion is understandable, but the validation response leaks internal native frames and excessive output. No repository files are changed.
- **Safe fallback:** Pass scripts through stdin or a temporary script file as the error suggests, and return concise validation errors without internal stack frames.

## 2026-09-28 â€” Multi-edit no-match leaks internal stack trace

- **Reproduction:** Call filesystem MCP edit_file on exiftool-rs CHANGELOG.md with five literal edits where the third oldText does not match the current file. The request reports one zero-match edit and returns a full native stack backtrace; no edit is applied.
- **Observed impact:** A stale edit anchor is an expected conflict, but the server response exposes internal native frames and excessive output. The multi-edit request is atomic and makes no changes.
- **Safe fallback:** Re-read the exact current text, apply only matching anchors, and return a concise structured zero-match error without internal stack frames.



## 2026-09-28 â€” edit_file literal no-match returns internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:\\projects\\projects.rust.cg\\cglibs\\rez-rs\\src\\serialise.rs` with literal edit `{ oldText: "fs::write(&path, \"name: ymlpkg\\\\\\\\n\").unwrap();", newText: "..." }`. The current Rust source line contained a different backslash count, so the anchor matched zero lines. The tool returned `Failed to apply edits: 1 of 1 edits produced zero matches` followed by native Rust stack frames.
- **Observed impact:** The stale literal anchor is an expected edit conflict; no source file was changed by the failed call. Returning the internal stack trace for a normal zero-match response is a server defect.
- **Safe fallback:** Re-read the exact line and use a line-number replacement; return a concise structured no-match error without native stack frames.

## 2026-09-28 â€” grep_context missing nearbyPatterns leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_context` with `{ path: "C:/projects/projects.rust.cg/cglibs/exiftool-rs", pattern: "root tests", filePattern: "**/*.md", contextBefore: 2, contextAfter: 2 }` and omit required `nearbyPatterns`. The server returns `grep_context was called with an empty nearbyPatterns` followed by a native Rust stack backtrace.
- **Observed impact:** The request is malformed because the required context term was omitted; the search does not run. Exposing internal frames for this expected argument-validation error is a server defect.
- **Safe fallback:** Use `grep_files` for ordinary searches or provide a non-empty `nearbyPatterns`; return a concise validation error without native frames.

## 2026-09-28 â€” Invalid `grep_files` regex with function parentheses returns internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_files` on `C:\\projects\\projects.rust.cg\\cglibs\\rez-rs\\src` with regex pattern `parse_tests_from_data(` and glob `**/*.rs`. The query is malformed (unclosed regex group), but the response includes a full internal Rust `Stack backtrace`. The query performs no file write.
- **Observed impact:** The invalid pattern is an expected caller error; exposing internal frames for it is a server defect and creates excessive output.
- **Safe fallback:** Search the literal token `parse_tests_from_data` without parentheses, use a properly escaped regex, or use `run_command` with `rg -F`; return a concise regex-validation error without native frames.

## 2026-09-28 â€” HTTP allowlist rejection includes an internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__http_request` with `{ method: "GET", url: "https://raw.githubusercontent.com/AcademySoftwareFoundation/rez/3.3.0/src/rez/version/_version.py", accept: "text/plain", maxBytes: 24000, timeoutMs: 30000 }`. The tool correctly rejects `raw.githubusercontent.com` because the domain is not in its allowlist, but returns a full internal Rust `Stack backtrace`.
- **Observed impact:** The allowlist denial is an expected policy outcome; exposing native server frames for it is a server defect. No HTTP request is made and no files are changed.
- **Safe fallback:** Use the vendored source at `_ref/rez` or the web fetch tool; configure an allowlist for any additional domain. Return a concise allowlist error without internal frames.
- **Additional reproduction:** Repeat with `url: "https://github.com/AcademySoftwareFoundation/rez/blob/3.3.0/src/rez/version/_version.py"` and `accept: "text/html"`. The server rejects `github.com` too and returns the same stack trace before making a request.

## 2026-09-28 â€” `run_command` process-spawn failure leaks native stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__run_command` with `{ command: "gitnexus status", cwd: "C:/projects/projects.rust.cg/cglibs/rez-rs", timeoutMs: 20000, stdoutHead: 40 }` in the current Windows session. The filesystem MCP host fails before process startup with `Failed to spawn command: gitnexus` and returns a full native Rust stack trace. No command runs and no repository files change.
- **Observed impact:** The unavailable executable is an environment/process-spawn failure; the server defect is exposing internal frames instead of a concise spawn error. GitNexus freshness and impact checks cannot be performed through this command in this environment.
- **Safe fallback:** Check executable availability with the server's `which` tool or use a configured GitNexus MCP/known executable path, then record that graph checks are unavailable if no executable exists. Return the OS spawn error without native stack frames.

## 2026-09-28 â€” Atomic `edit_file` mismatch leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` with multiple edits on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/builders/mod.rs`; make one `oldText` anchor not match the current source. The server reports `1 of 7 edits produced zero matches` and returns a native Rust stack backtrace. The atomic edit makes no changes.
- **Observed impact:** The stale anchor is an expected caller edit conflict. Exposing server frames for this ordinary no-match response is a server defect; no source file was changed by the failed call.
- **Safe fallback:** Re-read target text and apply only verified matching edits in smaller batches; return a concise no-match error without native stack frames.

## 2026-09-28 â€” `edit_file` zero-match validation leaks internal stack trace in Nova plan update

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cgprojs/nova-linux-rs/PLAN2.md` with seven literal edits; the third `oldText` is `- ÐÑƒÐ¶Ð½Ð¾ Ð²Ñ‹Ð±Ñ€Ð°Ñ‚ÑŒ Ñ„Ð¾Ñ€Ð¼Ð°Ñ‚ generation record Ð¸ Ð²Ð¾ÑÑÑ‚Ð°Ð½Ð¾Ð²Ð»ÐµÐ½Ð¸Ñ Nova-owned integrations; Ð¾Ð±Ñ‰Ð°Ñ Ñ‚Ñ€Ð°Ð½Ð·Ð°ÐºÑ†Ð¸Ñ Ñ apt Ð½Ðµ Ð¾Ð±ÐµÑ‰Ð°ÐµÑ‚ÑÑ.` while the actual file contains `- ÐžÐ¿Ñ€ÐµÐ´ÐµÐ»Ð¸Ñ‚ÑŒ generation record Ð¸ Ð²Ð¾ÑÑÑ‚Ð°Ð½Ð¾Ð²Ð»ÐµÐ½Ð¸Ðµ Nova-owned integrations; Ð¾Ð±Ñ‰Ð°Ñ Ñ‚Ñ€Ð°Ð½Ð·Ð°ÐºÑ†Ð¸Ñ Ñ apt Ð½Ðµ Ð¾Ð±ÐµÑ‰Ð°ÐµÑ‚ÑÑ.`. The tool returns `Failed to apply edits: 1 of 7 edits produced zero matches` followed by a full native Rust `Stack backtrace`. No edits from the request are applied.
- **Observed impact:** The stale anchor is an expected caller edit error. Returning the internal stack trace for it is a server defect and creates excessive output; the multi-edit request leaves the document unchanged.
- **Safe fallback:** Re-read the current target, retry only exact anchors in smaller verified batches, then reread the result. Return a concise structured no-match error without native frames.

## 2026-09-28 — Memory MCP rejects documented optional fields

- **Reproduction:** Call `mcp__filesystem_mcp_rs__mem_put` with required `workspaceId`, `actorId`, and `item`, plus `tags: ["tool-schema-check"]`. Tool metadata advertises `tags`, but the server returns `failed to deserialize parameters: unknown field `tags``. A separate call with documented `visibility` returned `unknown field `visibility``. A minimal call omitting both succeeds.
- **Observed impact:** Memory items cannot use advertised tags or visibility metadata through this tool surface; failed calls create no memory record. This is a server/schema mismatch, not invalid project content.
- **Safe fallback:** Use only accepted required fields and store classification in item content/title. Align the exposed schema with fields accepted by the server or support the advertised fields.

## 2026-09-28 — `grep_context` empty nearby pattern leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_context` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/cli/admin/memcache.rs` with `{ pattern: "poll|reset_stats|flush|stats", context_lines: 12 }` but omit `nearbyPatterns`. The tool returns `grep_context was called with an empty nearbyPatterns` followed by a full native Rust stack trace. No files are modified.
- **Observed impact:** The request is invalid because `grep_context` requires a non-empty nearby pattern; returning internal stack frames for this validation error is a server defect.
- **Safe fallback:** Use `grep_files` for a normal pattern search or provide a non-empty `nearbyPatterns`; return a concise argument validation error without native frames.

## 2026-09-28 — `run_command` variable-token validation leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__run_command` with PowerShell shell and a command that passes `dpkg-query -W -f='${Package} ${Version} ${Architecture}\\nDepends: ${Depends}\\n' ripgrep` to Ubuntu WSL. The host rejects the `${Package}` token before process startup and returns a full native Rust stack trace. No command runs.
- **Additional reproduction:** Call `mcp__filesystem_mcp_rs__run_command` with PowerShell shell and command text containing the Bash loop `for p in hello tree jq; do ... $p ...; done`. The host rejects `$p` before process startup with `command/args contain `$p`` and returns the same full native stack trace. No command runs.
- **Observed impact:** Blocking a potentially unsafe shell-variable token before spawn is expected protection; exposing internal frames for the validation rejection is a server defect. No system state changed.
- **Safe fallback:** Avoid `${NAME}` patterns in command text; query package fields with separate safe commands or pass a script through stdin/a file. Return a concise validation error without internal stack frames.

## 2026-09-28 — `grep_context` rejects unsupported window argument with stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_context` with `nearbyPatterns: ["Err(_) => continue"]` and unsupported `nearbyWindowLines: 5`, omitting the documented `nearbyWindowWords` or `nearbyWindowChars`. The server returns `grep_context was called without a window` followed by a full native Rust stack trace. No files are modified.
- **Observed impact:** The unsupported argument and missing required argument are caller errors; returning internal frames for argument validation is a server defect.
- **Safe fallback:** Use `grep_files` for a standard search or pass a supported window field; return a concise parameter validation error without stack frames.

## 2026-09-28 — `edit_file` zero-match error leaks stack trace during package provider update

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/resolve/solver.rs` with multiple literal edits, where one `oldText` is `Some(VariantSlice::new(entries))\n    }\n}\n\n// ---` but the current source has a different surrounding block. The tool returns `Failed to apply edits: 1 of 10 edits produced zero matches` followed by a full native Rust stack backtrace. The atomic edit request applies no changes.
- **Observed impact:** A stale source anchor is an expected caller edit error; returning internal stack frames for it is a server defect and produces excessive output. No source changes were applied.
- **Safe fallback:** Re-read the current source and retry smaller exact-anchor edits; return a concise structured no-match error without native frames.

## 2026-09-28 — `grep_context` missing nearby terms returns internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_context` with `path: "C:/projects/projects.rust.cg/cglibs/rez-rs/src/package/core.rs"`, `pattern: "from_data|requires"`, `context_before: 5`, `context_after: 12`, and `max_matches: 12`, without the required non-empty nearby term patterns. The server returns `grep_context was called with an empty nearbyPatterns` followed by a full native Rust stack trace. No files are changed.
- **Observed impact:** Omitting required context terms is a caller input error; returning internal native frames for this validation error is a server defect. The search does not run.
- **Safe fallback:** Use `grep_files` for a plain search, or call `grep_context` with its required nearby term patterns; return a concise parameter validation error without stack frames.

## 2026-09-28 — `edit_file` stale test anchor exposes internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/repository.rs` with two edits: a valid replacement of `if !path.is_dir() {` with `if !path_is_directory(&path)? {`, and a second literal `oldText` ending in the mistyped anchor `assert!(matches!(repo.scan_all(), Err(RezError::Version(_)));`. The test actually contains a different exact sequence, so edit #2 matches zero occurrences. The server rejects the atomic request and includes a full native Rust stack trace. No changes from that failed request were applied.
- **Observed impact:** A stale literal anchor is an expected edit conflict; exposing internal frames for it is a server defect. The atomic source update is rejected.
- **Safe fallback:** Re-read exact lines and apply independently verified edits separately; return a concise structured no-match error without native frames.

## 2026-09-28 — edit_file zero-match error leaks stack trace during Rex fixture correction

- **Reproduction:** Call mcp__filesystem_mcp_rs__edit_file on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/package/test.rs` with two literal edits. Each `oldText` anchor encodes four backslash characters before `n` in the Rust string fragments, while the actual file has two: the pre-test Python string and the package YAML string. The server returns `Failed to apply edits: 2 of 2 edits produced zero matches` followed by a full native Rust stack backtrace. The atomic request applies no changes.
- **Observed impact:** The anchors were stale due to incorrect backslash counting, an expected caller edit conflict. Exposing native stack frames for this no-match error is a server defect; the fixture remained unchanged by the failed call.
- **Safe fallback:** Re-read the exact line content and use the line-based edit tool for the two verified lines; return a concise structured no-match error without native frames.

## 2026-09-28 — edit_file zero-match error leaks stack trace during memcache test update

- **Reproduction:** Call mcp__filesystem_mcp_rs__edit_file on C:/projects/projects.rust.cg/cglibs/rez-rs/src/repository.rs with four literal edits to update memcache probe tests. The first two test anchors match, but the third anchor expects a NOT_STORED fixture followed by a second listener.accept() block that had drifted from the current source. The server returns `Failed to apply edits: 1 of 4 edits produced zero matches` followed by a full native Rust stack trace. The edit request applies no changes.
- **Observed impact:** The stale test anchor is an expected caller edit conflict; exposing internal frames for it is a server defect. Because the request is atomic, none of its otherwise matching edits were applied.
- **Safe fallback:** Re-read current lines and apply individually verified edits or use a line-range edit; return a concise structured no-match error without native frames.

## 2026-09-29 — `grep_files` invalid regex error leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_files` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/builders/mod.rs` with `pattern: "pub fn build("`, `context_lines: 3`, and `max_results: 60`. The unescaped opening parenthesis is an invalid regex; the server correctly identifies the regex parse error but includes a full native Rust backtrace in the failure result. No files are changed.
- **Observed impact:** An invalid search pattern is a caller input error; exposing internal stack frames for it is a server defect and creates excessive output. The search does not run.
- **Safe fallback:** Use the literal-safe pattern `pub fn build` or escape the parenthesis; return a concise pattern-validation error without native frames.

## 2026-09-29 — `grep_files` missing required path error leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_files` with only `{ pattern: "controlled reproducibility probe" }`, omitting required `path`. The tool returns `grep_files: missing or empty 'path' (root directory to search)` and then a full native `Stack backtrace` (including native frames such as `BaseThreadInitThunk` and `RtlUserThreadStart`). No file operation occurs.
- **Observed impact:** Omitting a required path is a caller argument error; exposing native implementation frames in the validation response is a server defect. The search does not run and no files are changed.
- **Safe fallback:** Supply an exact, non-empty repository root in `path`; return a concise missing-argument error without native stack frames.

## 2026-09-29 — edit tools expose internal stack trace for stale/overlapping edits

- **Reproduction:** During the rez-rs build-script edits, call `mcp__filesystem_mcp_rs__edit_file` on `src/shell/wrapper.rs` with the stale literal old function block for `create_forwarding_script(target_cmd: &str)`; the current function signature has already changed, so the server reports a zero-match edit and emits a full native stack trace. Separately, call `edit_lines` on the same file with two edits targeting the same line 899; the server reports an overlapping edit and emits a full native stack trace. Neither failed request changed the file.
- **Observed impact:** Stale anchors and overlapping line edits are expected caller conflicts; exposing internal native frames for those validation failures is a server defect. The attempted edit was rejected without changes.
- **Safe fallback:** Re-read the current exact lines, use one non-overlapping edit per call, and return concise structured stale-anchor/overlap errors without native stack frames.

## 2026-09-29 — `edit_file` stale serializer anchor leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/serialise.rs` with two literal edits: the first replaces the long-description branch in `dump_package_data_py`; the second removes `as_block_string` using an oldText block with misescaped Rust backslashes. The second anchor matches zero times; the server returns an atomic `1 of 2 edits produced zero matches` error followed by a full native Rust stack trace. Neither edit is applied.
- **Observed impact:** The stale string anchor is an expected caller conflict; exposing native implementation frames for it is a server defect. The atomic request leaves both source blocks unchanged.
- **Safe fallback:** Re-read exact lines and perform independently verified line edits; return a concise no-match error without stack frames.

## 2026-09-29 — `grep_context` missing required nearby-pattern input leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_context` with `{ path: "C:/projects/projects.rust.cg/cglibs/rez-rs/src", pattern: "PackageNotFound", contextBefore: 3, contextAfter: 3 }` and omit its required nearby pattern list. The server responds that `nearbyPatterns` is empty, followed by a full native Rust backtrace. No files are changed.
- **Observed impact:** This was a caller argument error; emitting internal native frames instead of a concise validation response is a server defect. The search does not run.
- **Safe fallback:** Use `grep_files` for a plain search or provide non-empty nearby terms when using `grep_context`.

## 2026-09-29 — HTTP fetch allowlist rejection leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__http_request` with `{ method: "GET", url: "https://docs.python.org/3/library/pprint.html", accept: "text/html", timeoutMs: 20000, maxBytes: 30000 }`. The server rejects the host as not allowlisted and includes a full native Rust backtrace. No request is sent and no files are changed.
- **Observed impact:** The domain rejection is expected allowlist behavior; exposing internal stack frames for the policy denial is a server defect. The fetch cannot retrieve that official documentation host.
- **Safe fallback:** Use an approved host or a separately available web retrieval tool; return a concise allowlist error without native frames.

## 2026-09-29 — run_command sanitizer rejection leaks stack trace

- **Reproduction:** Call mcp__filesystem_mcp_rs__run_command with a PowerShell script that assigns a temporary executable path to $probePath, pipes inline Rust source to rustc -o $probePath -, runs it, and removes it. The server rejects the command before spawn with “command/args contain $probePath — the MCP host may delete NAME tokens before spawn” and appends a full native Rust stack backtrace. No command starts and no temporary executable is created.
- **Observed impact:** This was a safe temporary probe; rejecting potentially sanitized variable tokens is a protective input policy, but returning native stack frames for that rejection is a server defect. The Rust float-format probe did not run.
- **Safe fallback:** Pass a script through stdin ContentRef or a temporary PowerShell script file, and return a concise sanitizer validation response without native frames.

## 2026-09-29 — `edit_file` unmatched anchor error leaks native stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/BUG_HUNT_REPORT.md` with two edits: the first expects a status-query sentence that is absent verbatim because the current report expresses that fact in a table entry; the second appends a follow-up section at the report's final line. The server rejects the request with `1 of 2 edits produced zero matches` and includes a full native Rust stack trace. The report remained unchanged by this failed request.
- **Observed impact:** The caller supplied a stale exact-text anchor, which is an expected edit conflict. Returning native stack frames for the mismatch is a server defect and adds excessive output. No file changes were applied by this request.
- **Safe fallback:** Re-read the exact current line and apply an independently verified append edit, then verify the resulting file with `read_text_file`; return a concise structured no-match error without native frames.

## 2026-09-29 — `edit_file` multi-edit no-match leaks native stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/repository.rs` with seven literal edits; the first six target current function blocks and the seventh expects `let fam_dir` immediately after the `unignore_package` signature, while the actual function first builds `ignore_file`. The server reports `1 of 7 edits produced zero matches` and appends a full native Rust stack trace. A follow-up `grep_files` confirmed none of the six matching edits were applied.
- **Observed impact:** The stale seventh anchor is a caller conflict, and atomic rejection is correct. Exposing internal stack frames for that validation error is a server defect; the multi-edit request made no source changes.
- **Safe fallback:** Re-read each target and batch only exact, verified anchors; return a concise no-match error without native frames.

## 2026-09-29 — `edit_file` unmatched exact anchor leaks native stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/python_vm.rs` with one literal replacement whose expected source line does not match the file's actual escaped raw-string contents. The request fails with `1 of 1 edits produced zero matches` and includes a full native Rust stack trace. No source change is applied.
- **Observed impact:** An exact-text mismatch is an expected editing conflict; returning native stack frames is a server defect and adds unnecessary internal details. The repository file remained unchanged by the rejected edit.
- **Safe fallback:** Re-read the exact current line with `read_text_file`, then use line-numbered editing on a verified line; return a concise structured no-match error without native frames.

## 2026-09-29 — `run_command` invalid output filter leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__run_command` with `{ command: "git", args: ["status", "--short", "--branch"], cwd: "C:/projects/projects.rust.cg/cglibs/rez-rs", outputFilter: { include: ["##", " M ", "A ", "??"], maxLines: 70 } }`. The invalid regular expression `##` is rejected by the regex parser (the error identifies a repetition operator without an expression); the MCP response returns `-32602` and includes a full internal Rust stack trace. The command does not run.
- **Observed impact:** The invalid regex is a caller input error; returning internal implementation frames for validation is a server defect. No repository files are changed.
- **Safe fallback:** Omit `outputFilter` for short commands or use a verified valid regex; return a concise invalid-filter error without internal stack frames.

## 2026-09-29 — `http_request` disallowed domain rejection leaks stack trace

- **Reproduction:** On 2026-09-29, call `mcp__filesystem_mcp_rs__http_request` with `url: "https://raw.githubusercontent.com/AcademySoftwareFoundation/rez/78e26236cdd65bc549db6b4e5782c70fe86ed5db/src/rez/config.py"`, `method: "GET"`, `accept: "text/plain"`, and `maxBytes: 30000`. The request is rejected because `raw.githubusercontent.com` is not allowlisted; the tool response includes a full Rust stack trace (including platform thread frames). No resource is fetched and no project files are changed.
- **Observed impact:** A disallowed domain is an expected policy rejection; disclosing internal stack frames in that response is a filesystem MCP server defect.
- **Safe fallback:** Use the vendored Rez checkout pinned at commit `78e26236cdd65bc549db6b4e5782c70fe86ed5db` for behavior comparison, or fetch the same official source via an approved browser tool. Return a concise allowlist rejection without internal frames.

## 2026-09-29 — `edit_file` stale plan anchor leaks native stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/plan5.md` with four literal edits, the first three matching the current tranche E bullets and the fourth expecting the stale text `- [ ] Re-run formatter check, default/no-default all-target checks, and full default/no-default test suites after source fixes.` The current bullet has different wording. The server reports `1 of 4 edits produced zero matches` and includes a full native Rust stack trace; atomic rejection applies none of the first three matches.
- **Observed impact:** The stale fourth anchor is an expected caller edit conflict; exposing native implementation frames is a server defect. The plan file was not modified by the rejected request.
- **Safe fallback:** Re-read current exact text and apply one verified edit at a time; return concise structured no-match errors without internal frames.

## 2026-09-29 — `grep_files` invalid regex leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_files({path:"C:\\projects\\projects.rust.cg\\cglibs\\rez-rs\\src\\serialise.rs", pattern:"serialize_data(", contextBefore:1, contextAfter:2, maxMatches:30})` without `fixedStrings:true` or a `filePattern`. The unescaped `(` is invalid as a regex; the tool reports an invalid pattern and includes a full internal Rust stack trace. No file is changed.
- **Observed impact:** The malformed regex is an expected caller input error. Exposing the server's internal stack trace is a filesystem MCP defect and adds unnecessary internal details; the search itself does not execute.
- **Safe fallback:** Use `pattern:"serialize_data\\("` or `fixedStrings:true`, then verify matches with `read_text_file`. Return a concise regex validation error without internal frames.

## 2026-09-29 — `mem_link` out-of-scope item error leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__mem_link` with `{ workspaceId: "C:/projects/projects.rust.cg/cglibs/rez-rs/", actorId: "/root/docs_accuracy", relation: { fromItemId: "e92a8807-1f4e-4ebc-98a8-55da45bef573", toItemId: "02709713-bf65-4a0a-87a2-e09e5737e0a9", relationType: "supports" } }`. The target item is not visible in the caller's scope. The tool returns `toItemId ... not found in scope` followed by a full native stack trace. No relation is created.
- **Observed impact:** A target unavailable in the current memory scope is a valid lookup/scope error; returning native implementation frames is a server defect. The relation request fails and leaks internals.
- **Safe fallback:** Link items only after confirming both IDs are visible in the same workspace/actor scope, or create an equivalent target item within that scope; return a concise not-found/scope error without native frames.

## 2026-09-29 — `edit_file` failed multi-edit anchor leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/shell/wrapper.rs` with two literal edits: first replace the existing line `        env_vars.sort_by(|(left, _), (right, _)| left.cmp(right));`; second replace the nonexistent line `    env_vars.sort_by(|left, right| left.0.cmp(&right.0));`. The tool reports `1 of 2 edits produced zero matches` and includes an internal native Rust stack trace. The request applies neither edit.
- **Observed impact:** The second anchor was an expected caller-side mismatch; returning the stack trace is a filesystem MCP server defect. The source file remained unchanged by the rejected multi-edit call.
- **Safe fallback:** Re-read exact lines and issue one verified edit per request, or use `failOnNoMatch=false` when an optional edit is intentional; return a concise no-match response without internal frames.


## 2026-09-29 — `extract_lines` reports an existing source file as empty and leaks stack trace

- **Reproduction:** In `C:/projects/projects.rust.cg/cglibs/rez-rs`, call `mcp__filesystem_mcp_rs__extract_lines` for `src/cli/repo/bind.rs` with `{ line: 96, endLine: 230, returnExtracted: true }`. The same file had just returned lines 1–99 successfully, but the next response said `Line 96 is out of range (file has 0 lines)` and included a full native stack trace. The file was not changed.
- **Observed impact:** The requested range is valid for the file, confirmed by the immediately preceding successful read. Returning a contradictory empty-file result and internal frames is a filesystem MCP server defect.
- **Safe fallback:** Retry with `read_text_file` or the same `extract_lines` request. If inconsistency persists, use `read_text_file` with offset and limit; return a concise read error without native frames.

## 2026-09-29 — `edit_file` rejects a copied existing literal and leaks stack trace

- **Reproduction:** Read the last line of `C:/projects/projects.rust.cg/cglibs/filesystem-mcp-rs/BUG_CDX.md` with `read_text_file(tail: 35)`, then pass the displayed last `Safe fallback` line as the sole literal `oldText` to `edit_file` on the same file. The server reported `1 of 1 edits produced zero matches` and returned a full internal stack trace. No edit was applied.
- **Observed impact:** The anchor was copied from the immediately preceding read of the same path. The mismatch may be caused by read/edit normalization; the native stack leak is a server defect, while the zero-match itself is not classified as a defect until normalization is checked.
- **Safe fallback:** Use `edit_lines` with a verified line number and read the file back. Return a concise no-match error without native frames.

## 2026-09-29 — `run_command` blocked variable token leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__run_command` with `command: "1..8 | ForEach-Object { cargo test --lib memcache_probe_does_not_cleanup_before_stored_confirmation -- --nocapture; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }"` and `shell: "powershell"`. The host rejects the command because it contains the protected `$LASTEXITCODE` token and returns a full native Rust stack trace before spawning PowerShell. No test process is started.
- **Observed impact:** Blocking a variable token is an expected command validation outcome; returning internal stack frames is a filesystem MCP server defect. No project files or processes are changed.
- **Safe fallback:** Run independent plain commands sequentially through the managed runner or pass an approved script via stdin/file; return a concise token-validation error without internal frames.


## 2026-09-29 — `edit_file` empty append anchor leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/BUG_HUNT_REPORT.md` with one literal edit whose `oldText` is the empty string and whose `newText` is non-empty report content. The server reports zero matches and returns an internal native Rust stack trace; no report content is written.
- **Observed impact:** An empty literal anchor that is absent from the file is an expected caller-side no-match. Returning internal stack frames is a filesystem MCP server defect. The report remained unchanged by the rejected edit.
- **Safe fallback:** Read the final report lines and replace a verified unique terminal paragraph with itself plus the appended content; return a concise no-match error without native frames.

## 2026-09-29 — `grep_files` invalid regex leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_files` with `{ path: "C:/projects/projects.rust.cg/cglibs/rez-rs/_ref/rez/src/rez/package_test.py", pattern: "return {", contextBefore: 1, contextAfter: 20, maxMatches: 6, lineNumbers: true }`. The unescaped `{` is invalid as a regex. The tool returns `Invalid regex pattern: regex parse error: (?:return {) ... repetition quantifier expects a valid decimal` followed by a Rust stack backtrace (frames 0–20 and Windows thread frames). The search does not run and no files change.
- **Observed impact:** The invalid regex is an expected caller input error; exposing native stack frames is a filesystem MCP server defect. No repository files or processes are changed.
- **Safe fallback:** Escape `{` in the regex (`return \\{`) or pass `fixedStrings: true`; return a concise regex-validation error without internal stack frames.

## 2026-09-29 — HTTP allowlist rejection leaks native stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__http_request` with `{ url: "https://raw.githubusercontent.com/AcademySoftwareFoundation/rez/3.3.0/src/rez/shells.py", method: "GET", responseType: "text" }`. The server rejects `raw.githubusercontent.com` as not allowlisted and returns a full native Rust stack trace (including Windows thread frames). No request is sent and no file is changed.
- **Observed impact:** The domain rejection is expected allowlist policy; returning internal implementation frames for it is a filesystem MCP server defect. The fetch fallback is unavailable for that host.
- **Safe fallback:** Use the checked-in Rez source under `_ref/rez` or an approved browser retrieval tool; return a concise allowlist error without native stack frames.

## 2026-09-29 — `run_command` protected-token validation leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__run_command` with `{ command: "python", args: ["-c", "from rez.shells import Shell; print(Shell.join(['echo', '$HOME']))"], cwd: "C:/projects/projects.rust.cg/cglibs/rez-rs/_ref/rez/src" }`. The host rejects the inline command because it contains `$HOME` and returns a full native Rust stack trace before spawning Python. No files are changed.
- **Observed impact:** Blocking an environment-variable token is expected sanitizer behavior; returning internal implementation frames for that rejection is a filesystem MCP server defect. The differential probe does not run.
- **Safe fallback:** Construct the token at runtime (`chr(36) + "HOME"`) or pass the script through stdin/file; return a concise sanitizer validation error without native stack frames.

## 2026-09-29 — `edit_file` unmatched Rust quoting anchor leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/shell/types.rs` with one literal edit targeting the current multi-line quote escaping expression around lines 155–157, but with a Rust-escaped `oldText` that differs from the stored raw-string delimiters. The tool returns `1 of 1 edits produced zero matches` followed by a full native Rust stack trace. The file remains unchanged.
- **Observed impact:** This was a stale/mismatched exact anchor; rejecting it is expected. Returning internal stack frames is a filesystem MCP server defect. No edit applied.
- **Safe fallback:** Re-read line-numbered source and use a verified line edit; return concise no-match errors without native frames.

## 2026-09-29 — `run_command` PowerShell environment token rejection leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__run_command` with `command: "powershell -Command \"$env:SHELL; $env:COMSPEC\""` and `shell: "powershell"`. The host rejects the protected `$env` token before PowerShell starts and returns an internal stack trace. No project files are changed.
- **Observed impact:** Blocking the protected variable token is expected sanitizer behavior; returning internal implementation frames for that rejection is a filesystem MCP server defect. The environment probe does not execute.
- **Safe fallback:** Use `env_list`/`env_get` for host environment metadata or pass a reviewed script through stdin/file without embedding protected variable tokens; return a concise validation error without native frames.


## 2026-09-29 — `edit_lines` overlapping operation rejection leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_lines` on `src/resolve/context.rs` with `edits` containing both `{ operation: "replace", line: 1598, text: "            Some(c) => {" }` and `{ operation: "replace", line: 1624, text: "                        let wrapped = if c.is_empty() {" }` plus `{ operation: "insert_after", line: 1624, text: "..." }`. The server rejects the overlapping operations with `Line edit failed: Overlapping edits` and returns a native Rust stack trace. No edit is applied. The same rejection was reproduced on `src/package/test.rs` by pairing a replace and insert_after at line 611.
- **Observed impact:** Overlapping operations are an expected caller error; returning internal stack frames is a filesystem MCP server defect. The rejected batch is atomic and makes no changes.
- **Safe fallback:** Submit non-overlapping edits or perform dependent edits in separate calls; return a concise overlap error without native frames.

## 2026-09-29 — `grep_files` empty path validation leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_files` with `{ path: "", pattern: "<literal search term>", fixedStrings: true }`. The server rejects the empty path as invalid and returns an internal native stack trace. No search runs and no files change.
- **Observed impact:** An empty path is an expected caller input error; exposing the server stack trace is a filesystem MCP server defect.
- **Safe fallback:** Pass a verified non-empty repository-relative or absolute path; return a concise path validation error without native frames.

## 2026-09-29 — `grep_context` empty `nearbyPatterns` rejection leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_context` with `{ path: "src/resolve/context.rs", pattern: "resolve_field_for_context", contextBefore: 8, contextAfter: 16, limit: 10 }` and omit `nearbyPatterns`. The server rejects the empty nearby-pattern set and returns a full native stack trace. No file operation runs.
- **Observed impact:** Omitting a required context term is a caller argument error; exposing native stack frames is a filesystem MCP server defect.
- **Safe fallback:** Use `grep_files` for the symbol search or provide non-empty `nearbyPatterns`; return a concise validation error without native frames.

## 2026-09-29 — `edit_file` stale plan anchor leaks stack trace

- **Reproduction:** Call mcp__filesystem_mcp_rs__edit_file on C:/projects/projects.rust.cg/cglibs/rez-rs/plan9.md with a four-edit batch that includes an anchor spelling `@early` with surrounding Markdown backticks, while the file's line reads `@early` without those backticks. The server reports `1 of 4 edits produced zero matches` and returns a full native Rust stack trace. The batch applies no plan edits.
- **Observed impact:** Rejecting a stale literal anchor is expected caller-error handling; returning internal stack frames is a filesystem MCP server defect. The rejected plan batch was atomic.
- **Safe fallback:** Re-read exact plan lines, then edit one verified unique anchor or a non-overlapping exact line; return a concise no-match error without internal frames.

## 2026-09-29 — `edit_file` stale context parser anchor leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/resolve/context.rs` with one literal replacement anchored on `impl ResolvedContext {` immediately followed by `from_json`; in the current source that `impl` is earlier and the supplied old-text block does not match. The server reports `1 of 1 edits produced zero matches` and returns a native Rust stack trace. No source edit is applied.
- **Observed impact:** The stale anchor is an expected caller-side mismatch; returning internal stack frames is a filesystem MCP server defect. The source file remained unchanged.
- **Safe fallback:** Re-read the exact line range and replace a unique block that is present; return a concise no-match error without native frames.

## 2026-09-29 — `run_command` variable-token guard leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__run_command` with `command: "wsl.exe"`, `args: ["--distribution", "Ubuntu", "--user", "joss", "--exec", "/bin/bash", "--noprofile", "--norc", "-c", "dpkg-query -W -f='${Status}\\n' hello 2>/dev/null || echo 'dpkg status: not installed'"]`. The host rejects the `${Status}` token before spawning WSL and returns a full native stack trace. No command is run.
- **Observed impact:** Blocking a variable token is expected sanitizer behavior; returning internal stack frames is a filesystem MCP server defect. This prevents the formatted dpkg status query from running.
- **Safe fallback:** Use `dpkg-query -l hello` or pass a script through stdin/file without a literal protected token. Return a concise validation error without native frames.

## 2026-09-29 — `grep_context` missing nearby patterns leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_context` with `{ path: "_ref/rez/src/rez/solver.py", pattern: "package_load_callback", before: 18, after: 30 }` and omit `nearbyPatterns`. The server rejects the empty nearby-pattern set with `grep_context was called with an empty nearbyPatterns` and returns a full native stack trace. No file edit occurs.
- **Observed impact:** Omitting a required nearby term is an expected caller input error; exposing the server's internal stack frames is a filesystem MCP server defect. The search did not run.
- **Safe fallback:** Use `grep_files` for a plain symbol search or supply a non-empty `nearbyPatterns`; return a concise argument error without native frames.

## 2026-09-29 — `edit_file` stale report anchor leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/BUG_HUNT_REPORT.md` with a five-edit batch. The first edit uses a literal anchor for the `.rxt` gap paragraph ending in “Verify runtime consumers and migration semantics before changing these fields.” The current source paragraph differs from that supplied anchor, so the server reports `1 of 5 edits produced zero matches` and returns a full native stack trace. No report edits are applied.
- **Observed impact:** Rejecting an outdated anchor is expected caller error; returning internal stack frames is a filesystem MCP server defect. The edit batch was atomic and left the report unchanged.
- **Safe fallback:** Re-read exact line-numbered paragraphs and use separate line-based replacements; return a concise no-match error without native frames.

## 2026-09-29 — `run_command` missing executable error leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__run_command` with `{ command: "gitnexus", args: ["status"], cwd: "C:/projects/projects.rust.cg/cglibs/rez-rs", timeoutMs: 10000, streamOutput: false }` on a host where `gitnexus` is not installed/on PATH. The server returns `Failed to spawn command: gitnexus` with a full internal Rust stack trace; no process starts.
- **Observed impact:** Reporting that an unavailable executable cannot be spawned is expected; leaking native internal stack frames is a filesystem MCP server defect. GitNexus freshness cannot be checked through this missing CLI.
- **Safe fallback:** Check executable availability with the MCP `which` tool and use a verified installed GitNexus MCP/CLI, or inspect source callsites and explicitly record that the graph check is unavailable. Return a concise spawn error without internal frames.

## 2026-09-29 — `http_request` rejects unallowlisted GitHub raw domain with stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__http_request` with `{ method: "GET", url: "https://raw.githubusercontent.com/nerdvegas/rez/3.3.0/src/rez/package_py_utils.py", accept: "text/plain", maxBytes: 100000, timeoutMs: 20000 }`. The allowlist rejects `raw.githubusercontent.com` before making a request and the tool returns a full native stack trace.
- **Observed impact:** Domain allowlist rejection is expected policy behavior; exposing internal stack frames is a filesystem MCP server defect. No HTTP request is made and no repository data changes.
- **Safe fallback:** Use vendored `_ref/rez` as the pinned authoritative source, or an explicitly available approved fetch/search tool; return a concise allowlist error without internal frames.

## 2026-09-29 — `edit_file` unmatched literal anchor leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/serialise.rs` with one literal edit whose old text is the test source declaration for `test_resolve_late_field_propagates_python_errors` and whose new text changes its escaped line breaks. The current declaration had two literal backslashes before each `n`; after rustfmt, the stale anchor supplied by the caller did not match. The server returned `1 of 1 edits produced zero matches` followed by a full native Rust stack trace. No source edit was applied.
- **Observed impact:** Rejecting the stale literal anchor is expected caller-error handling; returning internal stack frames is a filesystem MCP server defect. The source remained unchanged.
- **Safe fallback:** Re-read the exact line and use `edit_lines` with a verified line number, then read the file back. Return a concise no-match error without native frames.

## 2026-09-29 — `delete_path` WSL UNC scope rejection leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__delete_path` with `{ path: "\\\\wsl.localhost\\Ubuntu\\home\\joss\\.gnupg", recursive: true }`. The filesystem root validator rejects the WSL UNC path as outside allowed directories and returns a full native stack trace; the directory is not deleted.
- **Observed impact:** Denying access outside configured roots is expected policy behavior; exposing native implementation frames for the denial is a filesystem MCP server defect. No file was changed by this rejected request.
- **Safe fallback:** Use the filesystem server only within its configured Windows roots; for a verified WSL-local temporary artifact, perform cleanup with `run_command` inside the named WSL distro. Return a concise scope-denial error without native frames.

## 2026-09-29 — `grep_context` empty nearby patterns leak stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_context` with `{ path: "C:/projects/projects.rust.cg/cglibs/rez-rs/src/resolve/context.rs", pattern: "callback", around: "exec_rex_py" }` when the tool requires a non-empty `nearbyPatterns` field. The server rejects the empty nearby-pattern list and returns a full internal Rust stack trace. No files are changed.
- **Observed impact:** Rejecting a context search without nearby terms is expected argument validation; exposing native stack frames is a filesystem MCP server defect.
- **Safe fallback:** Use `grep_files` for a plain pattern search, or call `grep_context` with a verified non-empty nearby-pattern list. Return a concise validation error without internal frames.


## 2026-09-29 — `edit_file` batch with one unmatched literal leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/BUG_HUNT_REPORT.md` with eight literal replacements in one request. Seven old-text anchors exist, but one stale anchor is `(`context.rs:3866+).` while the actual line is `(`context.rs:3866+).` with a closing backtick before the parenthesis. The tool returns `1 of 8 edits produced zero matches` followed by a full native Rust stack trace. No edit is applied.
- **Observed impact:** Rejecting the unmatched literal anchor is expected; exposing native stack frames is a filesystem MCP server defect. The batch did not partially modify the report.
- **Safe fallback:** Re-read the exact source text, apply verified one-line edits with `edit_lines`, and read the file back. Return a concise no-match error without internal frames.


## 2026-09-29 — `grep_files` malformed regex rejection leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_files` with `{ path: "C:/projects/projects.rust.cg/cglibs/rez-rs/_ref/rez/src/rez", pattern: "def error(self", context_lines: 4 }`. The malformed regex is rejected with `Invalid regex pattern: regex parse error` and the response includes a full internal stack trace. No file operation runs.
- **Observed impact:** Rejecting a malformed regex is expected caller error handling; exposing internal stack frames is a filesystem MCP server defect. The search did not run and no project files changed.
- **Safe fallback:** Use a valid regex (escape `(` as `\\(`) or call with `fixedStrings: true`; return a concise pattern-validation error without native frames.


## 2026-09-29 — `grep_context` rejects valid plain search and leaks stack trace

- **Reproduction:** Call `mcp__filesystem__grep_context` with `{ path: "C:/projects/projects.rust.cg/cglibs/rez-rs/_ref/rez/src/rez", pattern: "extract", filePattern: "*.py", contextBefore: 2, contextAfter: 4, maxMatches: 30 }` and omit `nearbyPatterns`. The server reports `grep_context was called with an empty nearbyPatterns` and returns a full internal Rust stack trace. No files are changed.
- **Observed impact:** The caller wanted a plain pattern search; the required context terms are undocumented in the exposed schema, and the response leaks internal stack frames. The search did not run.
- **Safe fallback:** Use `grep_files` for plain searches or supply verified non-empty `nearbyPatterns`; return a concise validation error without internal stack frames.


## 2026-09-29 — `grep_files` malformed function pattern leaks stack trace

- **Reproduction:** Call `mcp__filesystem__grep_files` with `{ path: "C:/projects/projects.rust.cg/cglibs/rez-rs/_ref/rez/src/rez/bind", pattern: "def bind(", filePattern: "*.py", lineNumbers: true, maxMatches: 100 }` and omit `fixedStrings`. The regex parser rejects the unclosed group with `Invalid regex pattern` and returns a full internal Rust stack trace. No file operation runs.
- **Observed impact:** Rejecting malformed regex syntax is expected input validation; exposing internal frames is a filesystem MCP server defect. The search did not run.
- **Safe fallback:** Use `fixedStrings: true` or escape the opening parenthesis; return a concise regex-validation error without native frames.

## 2026-09-29 — `edit_file` stale multiline literal returns stack trace

- **Reproduction:** Call `mcp__filesystem__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/package/bind/mod.rs` with a literal old-text anchor containing the pip test's pre-rustfmt multiline closure, intended to insert an `os-` variant assertion. The source had already been formatted to a chained multiline expression, so the anchor matched zero locations. The tool returned `1 of 1 edits produced zero matches` followed by a native Rust stack trace; no source change was applied.
- **Observed impact:** Rejecting a stale anchor is expected caller-error handling; returning internal stack frames is a filesystem MCP server defect. The project source remained unchanged by this failed call.
- **Safe fallback:** Read the exact source lines after formatting and use a short verified anchor or `edit_lines`; read the file back after applying the edit. Return a concise no-match error without native frames.

## 2026-09-29 — `run_command` rejects Debian format placeholder and leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__run_command` with `command: "wsl.exe"`, `args: ["-d", "Ubuntu", "--", "bash", "-lc", "df -h /home; dpkg-query -W -f='${Package} ${Version}\\n' mc far2l 2>/dev/null || true; for p in /home/joss/nova-stage-mc/*.deb /home/joss/nova-stage-far2l/*.deb; do echo PACKAGE:$p; dpkg-deb -e \"$p\" /tmp/nova-control-review; for f in /tmp/nova-control-review/preinst /tmp/nova-control-review/postinst /tmp/nova-control-review/prerm /tmp/nova-control-review/postrm; do if test -f \"$f\"; then echo SCRIPT:$f; base64 -w0 \"$f\"; echo; fi; done; rm -rf /tmp/nova-control-review; done"]`. The host rejects the literal `${Package}` token before process spawn and includes a full native stack trace; the command does not run.
- **Observed impact:** The guard's rejection is expected for the protected token, but exposing internal frames is a filesystem MCP server defect. Package metadata and maintainer-script inspection did not execute.
- **Safe fallback:** Omit formatted dpkg placeholders and run smaller read-only commands, or pass a script through stdin/a file as supported by the tool. Return concise validation errors without internal native stack traces.

## 2026-09-29 — `edit_file` unmatched extraction anchor leaks stack trace

- **Reproduction:** Call `mcp__filesystem__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/builders/download.rs` with two literal edits: a valid import replacement and a second replacement using a stale download-function comment block containing an em dash that is absent from the file. The tool reports `1 of 2 edits produced zero matches` and returns a full native Rust stack trace; no edits are applied. Reproduction was confirmed by a successful subsequent import-only edit.
- **Observed impact:** Rejecting the mismatched literal is expected caller-error handling; leaking internal stack frames is a filesystem MCP server defect. The failed batch did not partially apply the valid first edit.
- **Safe fallback:** Re-read the exact source block and apply one small verified anchor at a time; read the file back after edits. Return a concise no-match error without native frames.

## 2026-09-29 — `edit_file` stale downloader anchor returns internal stack trace

- **Reproduction:** Call `mcp__filesystem__edit_file` for `C:/projects/projects.rust.cg/cglibs/rez-rs/src/builders/extraction.rs` with two literal edits: an import replacement that matches, followed by a stale multiline replacement whose path-separator anchor does not match the source text. The tool reports one zero-match edit and returns a full native Rust stack trace; no batch edit is applied.
- **Observed impact:** Rejecting a stale caller anchor is expected behavior. Returning implementation stack frames is a filesystem MCP server defect. Reading the file afterward confirmed it was unchanged.
- **Safe fallback:** Read exact source text and use one verified line-range edit; read the file back after the change. Return a concise no-match error without native stack frames.

## 2026-09-29 — `edit_file` stale regex anchor returns internal stack trace

- **Reproduction:** Call `mcp__filesystem__edit_file` for `C:/projects/projects.rust.cg/cglibs/rez-rs/src/builders/extraction.rs` with a regex replacement beginning at `let path = Path::new(&file_name);` and ending at `Ok(file_name)`, using a multiline regex that does not match the actual text. The tool reports zero matches and returns a full native Rust stack trace; no source change is applied.
- **Observed impact:** Rejecting the unmatched caller pattern is expected; leaking internal implementation frames is a filesystem MCP server defect. Reading the source afterward confirmed it was unchanged.
- **Safe fallback:** Use filesystem `edit_lines` with the verified line range; return a concise pattern mismatch without internal stack frames.

## 2026-09-29 — `edit_file` end-of-file anchor mismatch leaks stack trace

- **Reproduction:** Call `mcp__filesystem__edit_file` for `C:/projects/projects.rust.cg/cglibs/filesystem-mcp-rs/BUG_CDX.md` with a literal replacement whose old text is the final safe-fallback line plus an extra newline. The actual file ends at that line without the requested extra newline, so the tool rejects the anchor with `zero matches` and returns a full native Rust stack trace. The log file is unchanged.
- **Observed impact:** Rejecting the caller's unmatched end-of-file anchor is expected; exposing internal stack frames is a filesystem MCP server defect.
- **Safe fallback:** Use `edit_lines` after reading the exact last line; return a concise no-match error without internal frames.
## 2026-09-29 — `edit_file` partial batch applies successful edits before returning failure

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` for `C:/projects/projects.rust.cg/cglibs/rez-rs/BUG_HUNT_REPORT.md` with 15 literal replacements; 7 anchors matched and 8 anchors did not. The tool returned an error listing zero-match edits and a full native Rust stack trace. Reading the report afterward confirmed the 7 matching edits had already been applied while the call reported failure.
- **Observed impact:** The unmatched anchors are caller mistakes and should produce a validation error. Applying part of a batch while returning failure makes the final file state ambiguous; exposing internal frames is a separate filesystem MCP server defect.
- **Safe fallback:** Use single-anchor edits or line-based edits with fresh line numbers, then reread and verify every changed line. For batch operations, validate all anchors before applying any edit and return concise errors without native frames.

## 2026-09-29 — `run_command` input guard rejection leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem__run_command` with command text containing the protected `$LASTEXITCODE` token, for example `cargo fmt --all -- --check; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; git diff --check; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; cargo clippy --all-targets --all-features -- -D warnings`. The host rejects the token before process spawn and returns an internal native stack trace; none of the commands execute.
- **Observed impact:** Rejecting the protected token is expected caller-input handling. Returning internal frames is a filesystem MCP server defect. No project files or processes were changed by the rejected command.
- **Safe fallback:** Run each command in a separate `run_command` call and inspect its exit code; pass scripts through stdin or a file when sequencing is needed. Return a concise guard error without native stack frames.


## 2026-09-29 — `edit_file` stale anchor leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `nova/src/main.rs` with a batch of three literal edits where the first two match verified source blocks and the third requests the absent string `Current target and manifest identity do not match` without its actual Rust string-literal quoting. The server rejects edit #3 as zero matches and returns a full native Rust stack trace; read-back confirms none of the batch edits were applied.
- **Observed impact:** Rejecting a stale caller anchor is expected. Returning internal frames is a filesystem MCP server defect; the all-or-none result must still be verified because batch atomicity is not guaranteed across tool versions.
- **Safe fallback:** Submit only verified anchors, preferably one edit per call, then read back the source. Return a concise no-match validation error without internal frames.

## 2026-09-29 — `run_command` rejects PowerShell pipeline variable and leaks stack trace

- **Reproduction:** Call `mcp__filesystem__run_command` with `Select-String -Path src/repository.rs -Pattern 'fn load_repo_index' | ForEach-Object { '{0}:{1}' -f $_.LineNumber,$_.Line.Trim() }`. The host rejects the protected `$_` token before process spawn and returns a full native stack trace; the search does not run.
- **Observed impact:** Rejecting the protected token is expected caller-input handling. Returning internal frames is a filesystem MCP server defect. No files or processes changed.
- **Safe fallback:** Use filesystem MCP search/read tools, or pass the PowerShell script through stdin/file without a protected token. Return a concise guard error without native frames.

## 2026-09-29 — `run_command` protected environment syntax leaks stack trace

- **Reproduction:** Call `mcp__filesystem__run_command` with `command: "$env:CARGO_NET_OFFLINE='false'; cargo test test_late_decorator_preserves_annotated_multiline_function --lib"`, `cwd: "C:/projects/projects.rust.cg/cglibs/rez-rs"`, and `shell: "pwsh"`. The host rejects `$env` before spawning the process and returns a full internal stack trace. The cargo test does not run.
- **Observed impact:** The input guard's rejection is expected caller-input handling. Returning internal stack frames is a filesystem MCP server defect. No Cargo process or project file was changed by the rejected command.
- **Safe fallback:** Pass environment variables through the tool's `env` field and keep PowerShell variable syntax out of `command`; return a concise guard error without native frames.

## 2026-09-29 — `edit_file` verified report anchor rejection leaks stack trace

- **Reproduction:** After reading the final safe-fallback line at `C:/projects/projects.rust.cg/cglibs/filesystem-mcp-rs/BUG_CDX.md:504`, call `mcp__filesystem__edit_file` with a literal replacement using the displayed full line as `oldText`. The server reports `1 of 1 edits produced zero matches` and returns a native Rust stack trace; no edit is applied.
- **Observed impact:** Rejecting a genuinely absent literal is caller-input handling; this failure occurred after using the exact line returned by `read_text_file`, indicating a read/edit consistency or matching issue. The stack trace is a server defect. The report remained unchanged.
- **Safe fallback:** Re-read immediately and use `edit_lines` with verified line numbers; return a concise no-match error without internal stack frames.

## 2026-09-29 — `edit_file` unsupported look-ahead regex leaks stack trace

- **Reproduction:** Call `mcp__filesystem__edit_file` with `isRegex: true` and an oldText regex containing a look-ahead, such as `(?s)start.*?(?=end)`. The server correctly rejects the unsupported look-ahead regex but returns a full internal Rust stack trace; the edit is not applied.
- **Observed impact:** Rejecting unsupported regex syntax is expected validation. Exposing native stack frames is a filesystem MCP server defect. No project file was changed by this failed call.
- **Safe fallback:** Use a regex without look-around, or line-based edits after reading exact line numbers. Return a concise unsupported-regex validation error without internal frames.
## 2026-09-29 — `run_command` rejected `$paths` and leaked internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__run_command` with a PowerShell `command` that assigns `$paths = @('C:\projects\projects.rust.cg\cgprojs\nova-linux-rs', ...)` and loops over those paths. The host rejects `$paths` before spawning and returns a full native stack trace. No Git command runs.
- **Observed impact:** The environment-token guard's rejection is expected input validation; exposing native frames is a filesystem MCP defect. The repository check cannot run with this inline script.
- **Safe fallback:** Pass the script through `stdin` to `powershell -NoProfile -Command -`, or use separate Git invocations with literal paths; return a concise validation error without stack frames.

## 2026-09-29 — `edit_file` stale surrogate-test anchor returns stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/python_vm.rs` with two literal replacements whose anchors contain escaped Rust raw-string fragments for tests near line 987. The source contained unescaped raw-string quotes, so both anchors matched zero; the tool returned `2 of 2 edits produced zero matches` and a full internal Rust stack trace. No edits were applied by this call.
- **Observed impact:** Rejecting stale literal anchors is expected caller-error handling; returning internal stack frames is a filesystem MCP server defect. No project changes were applied by this failed call.
- **Safe fallback:** Re-read the exact lines and use `edit_lines` or exact raw-string anchors; read back the file after changes. Return a concise mismatch error without internal frames.

## 2026-09-29 — `edit_file` unmatched loader call anchor returns stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` for `C:/projects/projects.rust.cg/cglibs/rez-rs/src/serialise.rs` with ten literal edits, nine anchored to current loader code and a final replacement for `load_from_file(path, format)?`, which is absent. The tool reports `1 of 10 edits produced zero matches` and returns a full internal Rust stack trace; rereading confirmed this batch made no changes.
- **Observed impact:** A stale anchor is expected caller-error handling; leaking internal frames is a filesystem MCP server defect. No changes from this batch were applied.
- **Safe fallback:** Re-read the exact callsites, validate anchors in dry-run, and apply verified edits in small batches; return a concise no-match error without internal frames.

## 2026-09-29 — `edit_file` unmatched plan anchor returns stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/plan14.md` with the literal anchor “- [ ] Check parser behavior for empty argument groups and more than two separators against Rez's grouping implementation before making any further CLI changes.” The file contained that bullet without checkbox syntax. The tool returned “1 of 1 edits produced zero matches” with a full internal stack trace; no edit was applied.
- **Observed impact:** A stale literal anchor is caller error; exposing internal Rust stack frames for this expected mismatch is a filesystem MCP server defect. Project contents were unchanged by the failed request.
- **Safe fallback:** Re-read the exact line and use a verified literal or line-based edit; return a concise no-match response without internal frames.

## 2026-09-29 — managed Cargo command exceeds filesystem MCP call timeout

- **Reproduction:** Invoke `mcp__filesystem_mcp_rs__run_command` in managed mode from `C:/projects/projects.rust.cg/cglibs/rez-rs` with command `cargo test --all-features --all-targets -j 1` and `timeoutMs=1200000`. After approximately 300 seconds, the MCP call fails with “timed out awaiting tools/call after 300s” and returns a full internal stack trace without the command's exit code or log paths.
- **Observed impact:** The full test matrix's result is unavailable through this call. Process inspection found no remaining matching Cargo process; its exit result cannot be asserted from the failed response. The command-level timeout exceeds a fixed server-call timeout, which prevents managed mode from delivering completion data.
- **Safe fallback:** Use detached mode for long Cargo commands, then poll the managed-process list and read its stdout/stderr log paths; alternatively split independent test targets into calls shorter than the server timeout. Return the timeout as a concise tool error without stack frames.


## 2026-09-29 — `search_processes` invalid argument returns internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__search_processes` with `{pattern:"cargo|cmake|aws-lc|cc1|cl.exe|rustc",maxResults:60}`. The tool rejects the unsupported field names with MCP error `-32602` (“neither name_pattern nor cmdline_pattern”) but also returns a native stack trace containing `aws_lc_0_45_0_jent_entropy_switch_notime_impl`. The rejected call performs no process search.
- **Observed impact:** Rejecting an invalid tool argument is expected validation; exposing internal native frames in that validation response is a filesystem MCP server defect. No files or processes were changed by the rejected call.
- **Safe fallback:** Use the documented `name_pattern` and/or `cmdline_pattern` fields. Return a concise schema error without internal stack frames.

## 2026-09-29 — `write_file` inline-size rejection leaks internal stack trace

- **Reproduction:** Read `C:/projects/projects.rust.cg/cglibs/rez-rs/BUG_HUNT_REPORT.md` (147,556 bytes after preparing an append), then call `mcp__filesystem__write_file` for that path with `{ content: { kind: "inline", text: <complete existing report plus append> } }`. The server rejects it with `inline_too_large: 147556 bytes exceeds limit: 65536` and includes a full internal Rust stack trace. The report is not written by this rejected call.
- **Observed impact:** Rejecting inline content above the documented 64 KiB limit is expected input validation; returning native frames is a server defect. The failure did not modify the file.
- **Safe fallback:** Use `blob_begin`, append bounded chunks, `blob_finalize`, and pass the returned finalized blob `id` (not the session ID) to `write_file` as `{ kind: "blob", id }`. Re-read and verify the final bytes/hash.

### Additional reproduction — 2026-09-30

- **Reproduction:** Call mcp__filesystem__write_file for C:/projects/projects.rust.cg/cglibs/rez-rs/src/shell/types.rs with content.kind=inline containing the complete source plus prepared quoting edits, totaling 68,148 bytes. The response rejects the call with -32602, inline_too_large and limit 65536, followed by a full native stack backtrace ending in BaseThreadInitThunk/RtlUserThreadStart.
- **Observed impact:** Oversized inline content is expected caller-input validation; disclosure of the internal stack is the server defect. The rejected call did not write types.rs.
- **Safe fallback:** Re-read the source and apply exact surgical edit_file anchors; this fallback succeeded. For complete content, use blob_begin, blob_append chunks of at most 64 KiB, blob_finalize, then pass the returned finalized blob ID to write_file. Re-read the result and inspect its diff.

## 2026-09-29 — `write_file` invalid blob session ID leaks internal stack trace

- **Reproduction:** After `blob_begin` returns session ID `e97ffd54-f197-4f09-a6ac-861d8edf9a41`, append content and call `blob_finalize`. It returns finalized blob ID `fb68c685ab304733694b874e751a33735ae34e32da5b8cd0e48965d6cac301b6`. Call `write_file` with `{ content: { kind: "blob", id: "e97ffd54-f197-4f09-a6ac-861d8edf9a41" } }`. The server reports `blob_not_found` and emits a full internal Rust stack trace. No file write occurs. Retrying with the finalized blob ID succeeds.
- **Observed impact:** Passing a session ID where a finalized blob ID is required is a caller mistake; exposing native frames is a server defect. The target report remained unchanged until the correctly identified finalized blob was written.
- **Safe fallback:** Use the exact `id` returned by `blob_finalize`, then verify the resulting file. Return a concise missing-blob error without internal stack frames.

## 2026-09-29 — `edit_lines` applied a line edit at a different location than requested

- **Observed reproduction sequence:** In `rez-rs/src/package/bind/mod.rs`, read the current target around line 567 with `extract_lines`, then submit a single `edit_lines` replacement for the selected line. The resulting diff changed a blank line after the bind binary-directory block instead of the requested target and removed more than 60 lines from `write_bind_package`. The source was restored from the known repository baseline and the intended change was reapplied using a full read/transform/write with exact-count validation; the complete bind test suite then passed.
- **Reproduction limits:** The original structured `edit_lines` payload was not retained in the current tool trace, so this is an observed location mismatch, not a claim that the exact request can now be replayed. It is not classified as a verified deterministic server bug until the payload and a minimal repeat are available.
- **Observed impact:** A successful tool response did not correspond to the requested line edit and temporarily removed the package-writing implementation. This creates a material source-integrity risk.
- **Safe fallback:** Avoid line edits for this file. Read the full source, transform only a uniquely matched exact string, validate occurrence counts and resulting diff, write through a staged blob when over the inline limit, reread/hash the result, and run focused bind tests.

## 2026-09-29 — `edit_file` unmatched test anchor returns internal stack trace

- **Reproduction:** Call `mcp__filesystem__edit_file` for `C:/projects/projects.rust.cg/cglibs/rez-rs/src/python_vm.rs` with a literal replacement of the regression test line using an incorrectly escaped raw-string delimiter. The server reports `1 of 1 edits produced zero matches` and includes a full internal Rust stack trace. Re-reading confirmed the file was unchanged by this failed edit; the anchor was then corrected from the exact returned file line.
- **Observed impact:** An escaped/stale source anchor is caller error; exposing internal frames for a normal no-match result is a filesystem MCP server defect. No file mutation resulted from the failed call.
- **Safe fallback:** Read and serialize the exact source line, validate the literal target before editing, and return a concise mismatch response without internal frames.

## 2026-09-29 — `edit_file` batch with an unmatched edit returns internal stack trace

- **Reproduction:** Call `mcp__filesystem__edit_file` for `rez-rs/plan14.md` with four literal replacements in one batch; the second anchor describes the old `gitnexus-rs detect-changes` text but does not exactly match the file. The server returns “1 of 4 edits produced zero matches” and an internal Rust stack trace. Re-reading `plan14.md` confirmed this failed batch made no edits.
- **Observed impact:** A stale edit anchor is caller error; exposing internal frames for the no-match validation is a filesystem MCP server defect. The failed batch did not modify the target.
- **Safe fallback:** Re-read the current text, apply exact unique replacements one at a time (or preflight each anchor), then re-read and verify each result.

## 2026-09-29 — `edit_file` stale utility-reference anchor returns internal stack trace

- **Reproduction:** Call `mcp__filesystem__edit_file` for `rez-rs/plan14.md` to replace the utility reference using old text ending `src/util.rs:1-49).` instead of the actual text `src/util.rs:1-49).` (the supplied oldText omitted the literal Markdown backtick after the closing parenthesis; the file's oldText must include it). The server reports one unmatched edit and returns an internal Rust stack trace. The failed edit leaves the file unchanged; retrying with the exact anchor succeeds.
- **Observed impact:** The malformed anchor is caller error; leaking internal frames for the ordinary no-match result is a server defect. No mutation occurs on the failed call.
- **Safe fallback:** Read the exact source fragment including Markdown delimiters, make a single edit, and verify by re-reading.

## 2026-09-29 — `edit_file` log correction anchor mismatch returns internal stack trace

- **Reproduction:** After appending the utility-reference anchor issue above, call `mcp__filesystem__edit_file` on this log using the partial old-text anchor `The literal anchor omitted the closing backtick after the parenthesis.`; that sentence was not present because the original entry used a longer parenthetical. The server returns a no-match validation error with internal Rust frames; the log remains unchanged on the failed call.
- **Observed impact:** The stale partial anchor is caller error; the internal stack trace is an MCP server defect. No file change resulted from the failed call.
- **Safe fallback:** Read the exact current text and edit a unique smaller substring from that text, then verify the log.

## 2026-09-29 — `edit_file` unmatched Nova source anchors leak internal stack traces

- **Reproduction:** In `nova-linux-rs/nova/src/main.rs`, call `mcp__filesystem_mcp_rs__edit_file` with a batch containing the literal anchors `mod linux {\\n    use std::collections::BTreeMap;` and `             nova runtime-import <rootfs> <lock> <store>\\n\\\\n`. Neither anchor matches the actual newline / Rust line-continuation characters in the file. The server reports “2 of 3 edits produced zero matches” and returns full internal Rust frames. A second no-match call against `.gitignore` used `Thumbs.db\\n.gitnexus/` and similarly returned a full stack trace. The failed calls left all target files unchanged.
- **Observed impact:** The malformed escape sequences are caller errors; exposing internal stack frames for ordinary no-match validation is a filesystem MCP server defect. No partial source mutation occurred.
- **Safe fallback:** Re-read exact text, use a single exact anchor at a time, verify each result, and return a concise mismatch error without internal frames.

## 2026-09-29 — `edit_file` stale plan-tail anchor returns internal stack trace

- **Reproduction:** Call `mcp__filesystem__edit_file` for `rez-rs/plan14.md` replacing its old compatibility statement containing “vendored Rez 3.3.0 evidence”. That statement had already been updated in an earlier successful edit. The server returns a no-match validation response and internal Rust frames; the failed request leaves the plan unchanged, as confirmed by reading its tail.
- **Observed impact:** Reusing an obsolete anchor is caller error; leaking internal frames is an MCP server defect. No file change occurred.
- **Safe fallback:** Re-read the relevant section immediately before editing and skip changes already present.

## 2026-09-29 — `run_command` rejects shell variable token and leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__run_command` on Windows with `command: "wsl.exe"`, args `["-d","Ubuntu","-e","sh","-lc","for f in /usr/lib/x86_64-linux-gnu/Scrt1.o; do test -f \"$f\"; done"]`, and `shell: "none"`. The server correctly rejects the blocked `$f` token before spawning, but returns full internal Rust frames with the error.
- **Observed impact:** The command safety guard is expected; emitting internal stack frames for its validation rejection is a filesystem MCP server defect. The WSL shell did not run and no files changed.
- **Safe fallback:** Avoid shell variables in command arguments or pass a script through the documented stdin/file path; return a concise validation error without internal frames.

## 2026-09-29 — WSL UNC paths outside allowed roots leak stack traces

- **Reproduction:** Call `mcp__filesystem_mcp_rs__read_text_file` for `\\\\wsl.localhost\\Ubuntu\\tmp\\nova-mc-closure-20260929\\closure.lock` and `mcp__filesystem_mcp_rs__list_directory` for its `packages` subdirectory. The server correctly rejects both as outside configured allowed directories but emits a full internal Rust stack trace for each rejection.
- **Observed impact:** The UNC location is outside this MCP server's configured roots, so access denial is expected; exposing internal frames for path validation is a server defect. Neither read nor listing occurred.
- **Safe fallback:** Copy only the requested metadata into an allowed workspace path using `run_command`, then read it with the filesystem MCP; keep bulk archives in WSL's private `/tmp`. Return a concise access-denied response without internal frames.

- **Additional reproduction:** A subsequent attempt to append this entry by guessing a log anchor returned another no-match error with full internal Rust frames. The stale anchor did not modify the log. Re-read the exact current line and use it as the edit anchor.

## 2026-09-29 — `edit_file` batch mismatch leaks internal stack trace during Nova CLI update

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` for `nova-linux-rs/nova/src/main.rs` with two edits: insert a dispatcher arm before the exact `"runtime-import" => {\n                let rootfs` anchor, and replace a help block using an incorrectly escaped literal containing `\\n\\\\`. The server returns “1 of 2 edits produced zero matches” with full internal Rust stack frames. Re-reading confirms neither requested change was applied.
- **Observed impact:** The incorrectly serialized help anchor is caller error; leaking native frames for expected no-match validation is a filesystem MCP server defect. The dispatcher remains unchanged.
- **Safe fallback:** Re-read the source and make one unique exact edit per call; return a concise anchor mismatch without internal frames.

## 2026-09-29 — `edit_file` stale PLAN2 block anchor leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `nova-linux-rs/PLAN2.md` replacing the Section 18 verification bullets without including their actual source text and indentation. The server returns “1 of 1 edits produced zero matches” and a full internal Rust stack trace; rereading Section 18 confirms the plan was unchanged.
- **Observed impact:** The stale literal block is caller error; exposing internal frames for normal no-match validation is a filesystem MCP server defect. No plan changes were applied by the rejected call.
- **Safe fallback:** Read the exact current section immediately before editing and replace one exact bullet at a time; return a concise mismatch error without internal frames.


## 2026-09-29 — `locate_sql` child-directory inventory timed out with internal stack trace

- **Reproduction:** Run `mcp__filesystem_mcp_rs__locate_sql({under:"D:/_rez_install/bootstrap117",sql:"SELECT name,kind,files,dirs,size FROM fs_entries WHERE dir=under ORDER BY name",limit:100})`. The call exceeded its 120-second limit and returned a full internal stack trace. The locate index had already completed; no source files were changed by the query.
- **Observed impact:** The broad immediate-child inventory could not be retrieved through this query. The timeout is a tool failure; returning internal frames is a server defect. Narrower extension and size queries against the same indexed root succeeded.
- **Safe fallback:** Use selective, bounded queries (for example, filter by `name` or `ext`, group by extension/depth) and `directory_tree` for a small subtree; return a concise timeout response without internal frames.


## 2026-09-29 — `edit_file` stale log anchor returns internal stack trace during timeout logging

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/filesystem-mcp-rs/BUG_CDX.md` using an anchor copied from a truncated or reformatted tool response rather than the exact file contents. The server returns a zero-match error with full internal Rust frames; no edit is applied.
- **Observed impact:** The stale anchor is caller error; exposing internal frames for ordinary no-match validation is a filesystem MCP defect. Both failed append attempts left the log unchanged.
- **Safe fallback:** Read the exact tail immediately before editing, use a unique exact anchor or append with an end-of-file regex, then reread and verify.


## 2026-09-29 — `edit_file` zero-match batch response leaks stack trace while adding Nova audit command

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `nova/src/main.rs` with three edits: add `mod elf_audit;` after `mod deb_closure;`, add a `runtime-audit-elf` dispatch arm before `"runtime-import" => {`, and replace the help line using a literal string that does not match its escaped source text. The server reports “1 of 3 edits produced zero matches” and includes full Rust stack frames. The call applied no edits; rereading `main.rs` confirmed its original contents.
- **Observed impact:** The stale help anchor was caller error; returning internal frames for ordinary no-match validation is a server defect. No project source was changed by the rejected batch.
- **Safe fallback:** Re-read and copy the exact source anchor; issue one edit at a time and verify after each successful call. Return a concise no-match error without internal frames.

## 2026-09-29 — `read_text_file` conflicting pagination modes leak stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__read_text_file` with a path plus both `head: 40` and `tail: 40`. The server correctly rejects the incompatible modes but returns a full internal Rust stack trace.
- **Observed impact:** The pagination argument combination is caller error; exposing internal frames for this validation failure is a server defect. No file was read or changed by the rejected call.
- **Safe fallback:** Use only one of `head`, `tail`, or `offset`/`limit` per call; return a concise argument error without internal frames.

## 2026-09-29 — `edit_file` zero-match batch leaks stack trace during Nova integration CLI update

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `nova-linux-rs/nova/src/main.rs` with three edits: add `mod integrations;`, replace the `runtime-compose-deb` dispatch block, and replace the help usage line using a literal whose Rust string escaping does not match the source. The server reports “1 of 3 edits produced zero matches” and includes a full internal Rust stack backtrace. Re-reading `main.rs` confirmed that none of the three edits were applied.
- **Observed impact:** The mismatched help anchor was caller error; exposing internal frames for the expected no-match validation is a filesystem MCP server defect. The CLI source remained unchanged.
- **Safe fallback:** Re-read exact source anchors, apply one edit per call, and verify after each success. Return a concise no-match error without internal frames.

## 2026-09-29 — `edit_file` stale formatted anchor leaks stack trace in Nova CLI

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `nova-linux-rs/nova/src/main.rs` to replace the `--integrations` match arm using the pre-format two-line layout. `cargo fmt` had wrapped the assignment across lines. The server reports “1 of 1 edits produced zero matches” and returns internal Rust stack frames; rereading lines 173–176 shows the source unchanged.
- **Observed impact:** The old layout was a stale caller anchor; leaking internal frames for a normal no-match error is a filesystem MCP server defect. No source edit occurred.
- **Safe fallback:** Read the formatted block immediately before editing and replace its exact current text; return a concise no-match response without internal frames.

## 2026-09-29 — `run_command` rejects WSL probe and leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__run_command({command:"wsl -d Ubuntu -- bash -lc 'printf \\"distro=\\"; . /etc/os-release; echo \\"$PRETTY_NAME\\"; ls -ld /tmp/nova-mcfar2l-closure /tmp/nova-mcfar2l-closure/packages 2>&1; ls -ld /home/joss/nova-store/.runtimes'",cwd:"C:\\projects\\projects.rust.cg\\cgprojs\\nova-linux-rs",shell:"pwsh",timeoutMs:30000})`. The host rejects `$PRETTY_NAME` before spawn and includes a full internal Rust stack trace.
- **Observed impact:** The host token guard correctly prevents the command from running; this is not a command execution failure. Leaking internal frames for this validation response is a server defect. No WSL probe ran and no files changed.
- **Safe fallback:** Avoid shell `$NAME` tokens in inline command strings or pass the script through stdin/a file as the server recommends; return a concise validation error without internal frames.

## 2026-09-29 — `run_command` rejects shell variable and leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__run_command` with command `wsl -d Ubuntu -- bash -lc 'nova=/mnt/c/Users/joss1/AppData/Local/Temp/nova-integration; ...; "$nova" runtime-compose-deb ...'`, `cwd:"C:\\projects\\projects.rust.cg\\cgprojs\\nova-linux-rs"`, and `shell:"pwsh"`. The host rejects `$nova` before spawn and includes a full internal Rust stack trace.
- **Observed impact:** The inline shell variable triggered the host's safety guard, so no compose or validation command ran and no files changed. Returning internal frames for this argument validation is a server defect. This reproduces the `$NAME` token-guard issue recorded above with another shell variable.
- **Safe fallback:** Avoid `$NAME` tokens in inline command strings, repeat literal executable paths, or pass the script through stdin/a file; return a concise validation error without internal frames.

## 2026-09-29 — `read_text_file` allowlist rejection leaks internal stack trace for WSL UNC path

- **Reproduction:** Call `mcp__filesystem_mcp_rs__read_text_file({path:"\\\\wsl.localhost\\Ubuntu\\home\\joss\\nova-store\\mc\\runtime.ref"})` (the same call was made for `far2l/runtime.ref`). The server correctly rejects the UNC path as outside configured allowed directories and returns a full internal Rust stack trace.
- **Observed impact:** The path was outside the filesystem MCP allowlist, so access denial is expected caller-facing behavior; no file was read. Exposing internal frames for this denial is a server defect.
- **Safe fallback:** Use only paths under `list_allowed_directories`, or read WSL content through an authorized `run_command`; return a concise access-denied message without internal frames.

## 2026-09-29 — `edit_file` batch no-match leaks stack trace during Nova maintainer analyzer wiring

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `nova-linux-rs/nova/src/main.rs` with three literal edits adding the `maintainer_analysis` module, its CLI arm, and the help line. The module and dispatcher anchors were valid, but the help source literal was incorrectly escaped. The server reports “1 of 3 edits produced zero matches” and returns a full internal Rust stack trace; rereading confirms the batch applied none of its edits.
- **Observed impact:** The escaped help anchor was caller error; exposing internal frames for expected no-match validation is a filesystem MCP server defect. `main.rs` remains unchanged.
- **Safe fallback:** Read and copy the exact source anchor, make independent edits one at a time, and verify after each. Return a concise no-match error without internal frames.

## 2026-09-29 — `grep_files` invalid regular expression leaks stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__grep_files` with `pattern:"Candidate {"`, `path:"C:/projects/projects.rust.cg/cgprojs/nova-linux-rs/nova/src/linux"`, and `filePattern:"maintainer_analysis.rs"`. The regex is invalid because `{` is unescaped; the server returns “Invalid regex pattern” followed by a full internal Rust stack trace.
- **Observed impact:** The malformed regex was caller error and no search was performed. Returning internal frames for argument validation is a filesystem MCP server defect; no files changed.
- **Safe fallback:** Use `fixedStrings:true` for literal searches or escape regex metacharacters; return a concise validation error without internal frames.


## 2026-09-29 — Disk usage and stale-anchor responses expose internal stack traces

- **Reproduction A:** Call `mcp__filesystem__disk_usage({path: "D:\\"})` in the Windows session. It returns `No disk found for path: D:\\` followed by a full internal stack trace, while `mcp__filesystem__list_directory_with_sizes({path: "D:\\_rez_install\\bootstrap117\\0010.prep"})` succeeds. A PowerShell `Get-PSDrive -Name D` query confirms the D: drive and reports free space.
- **Observed impact A:** Disk capacity cannot be queried through this MCP call even though the path is accessible; the error also leaks native frames. No files were changed by the query.
- **Safe fallback A:** Use `Get-PSDrive -Name D` or `Get-Volume` through `run_command`; return a concise no-volume diagnostic without stack frames.

### Additional reproduction — 2026-10-01

- **Exact reproduction:** `mcp__filesystem__disk_usage({path:"C:/msgfs"})` and `mcp__filesystem__disk_usage({path:"C:\\"})` each return -32603 `No disk found` and a full internal native backtrace including aws_lc frames. The orchestrator verified the C: drive and existing C:/msgfs path; these are valid targets, not nonexistent-path caller errors.
- **Observed impact:** Path-specific capacity checks fail for an accessible drive/root, preventing reliable preflight through this call. Native-frame exposure is also a server defect. No files are changed by these read-only calls.
- **Safe fallback:** Use filesystem MCP run_command with Python shutil.disk_usage for the verified path, or call disk_usage({}) to list disks without its defective path lookup. Keep a concise path/volume diagnostic and omit internal frames.

- **Additional exact path-lookup reproduction (2026-10-01, storage preflight):** Root called `mcp__filesystem__disk_usage({path:"C:/projects/projects.rust.cg/cglibs/rez-rs/target"})` and `mcp__filesystem__disk_usage({path:"D:/_rez_install/bootstrap117"})`. Both existing paths returned -32603 `No disk found for path` plus a 25-frame internal stack. `disk_usage({})` succeeded enumerating C: and D:, and Python `shutil.disk_usage('C:\\')` / `shutil.disk_usage('D:\\')` through filesystem MCP run_command independently confirmed the drives. **Impact:** valid path-specific capacity preflight fails and exposes internals; these are server defects, not nonexistent-path caller errors. No files changed. **Safe fallback:** enumerate all disks without a path or use shutil.disk_usage through the same filesystem server. The owner's current verified free bytes were C:168474910720 and D:27878903808; these are a time-specific snapshot, not a reservation. The documentation agent records the owner's exact reproduction without rerunning it.

- **Reproduction B:** Call `mcp__filesystem__edit_file` on this log with an `oldText` copied from the final line returned by `read_text_file({path: "C:\\projects\\projects.rust.cg\\cglibs\\filesystem-mcp-rs\\BUG_CDX.md", tail: 18})`. The call reports one zero-match anchor and includes a full native stack trace; no edit is applied.
- **Observed impact B:** A stale/normalized text anchor prevents the append; returning internal stack frames for a normal edit conflict is a server defect. The file remains unchanged by that failed edit.
- **Safe fallback B:** Re-read the line range and append with `edit_lines` using a verified final line number; return a concise zero-match error without native frames.


## 2026-09-29 — Long managed `run_command` call times out at tool gateway with stack trace

- **Reproduction:** Call `mcp__filesystem__run_command` with `{command: "python bootstrap.py p", cwd: "C:\\projects\\projects.rust.cg\\cglibs\\rez-rs", shell: "powershell", mode: "managed", timeoutMs: 1200000, streamOutput: true}` while Cargo performs the first Windows Release build. After 300 seconds the caller receives `timed out awaiting tools/call after 300s` plus a full internal Rust stack trace, despite the requested command timeout being 1200000 ms.
- **Observed impact:** The caller loses the command result and cannot tell whether packaging completed. In this reproduction `target/release/rez.exe` was subsequently found, so at least the build side effect completed despite the missing final response. The timeout response leaks internal frames.
- **Safe fallback:** Run long builds detached with explicit stdout/stderr log paths and poll those logs/process state; report the gateway timeout separately from the child process exit code.

### Additional reproduction — 2026-09-30

- **Reproduction:** In `C:/projects/projects.rust.cg/cglibs/rez-rs`, call filesystem MCP `run_command` with `command: "python"`, `args: ["bootstrap.py", "package", "--force"]`, `env: { "CARGO_BUILD_JOBS": "1" }` and `timeoutMs: 600000`. While Cargo is still compiling the Release payload, the caller receives `timed out awaiting tools/call after 300s` followed by a full 25-frame native stack trace. The outer tools/call deadline is 300 seconds, distinct from the requested 600-second child-command timeout.
- **Observed impact:** The final exit/result is lost although the orchestrator's scoped process inspection still finds its Cargo process `52768` and rustc process `36820` running. The ongoing stderr log is `C:/Users/joss1/.filesystem-mcp-rs/tmp/run_command_1790823926851_75f82594-d143-4377-bf03-a84017c1ef3c_stderr.log`. This confirms the existing gateway-timeout issue on the current server; it does not establish a release failure or successful packaging. A finite transport deadline is expected, while leaking native frames and losing a resumable command result are defects.
- **Safe fallback:** Start long builds in detached mode with recorded log/process identity and poll those logs plus the owned process tree. Managed mode alone is insufficient for this reproduced deadline. After a transport timeout, inspect the existing build before any retry; do not restart a concurrent release build or kill unrelated processes. Report the gateway error separately from the child's eventual exit status.



## 2026-09-29 — `copy_file` directory destination conflict exposes internal stack trace

- **Reproduction:** Create `D:\\_rez_install\\bootstrap117\\0010.prep\\1055.rez-rs\\payload\\0.1.0` with `create_directory`, then call `copy_file` with that directory as `destination` and `C:\\projects\\projects.rust.cg\\cglibs\\rez-rs\\dist\\rez-rs\\0.1.0` as `source`, leaving `overwrite:false`. The server returns `Destination exists; set overwrite to true` and a full internal Rust stack trace.
- **Observed impact:** The operation was rejected and copied no payload. The conflict is expected from this API call, but exposing internal frames for it is a server defect.
- **Safe fallback:** Copy the three verified package files individually into the already-created version directory; return a concise destination-conflict error without internal frames.

## 2026-09-29 — `edit_file` batch with stale help anchor leaks stack trace during Nova app doctor wiring

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `nova-linux-rs/nova/src/main.rs` with three literal edits: add the `doctor` action to the `app` dispatcher, add `nova app doctor <store> [package]` to the help string, and insert the doctor functions before `fn rollback`. The dispatcher and rollback anchors match, but the help anchor is escaped incorrectly. The server reports “1 of 3 edits produced zero matches” and returns a full internal Rust stack trace; rereading confirms that none of the edits were applied.
- **Observed impact:** The help anchor was caller error; the atomic batch left the source unchanged. Leaking internal frames for a routine no-match conflict is a filesystem MCP server defect.
- **Safe fallback:** Read the exact formatted help source and retry each independent edit with verified anchors; return a concise no-match error without internal stack frames.


## 2026-09-29 — `edit_file` no-match while correcting escaped Rust character literal leaks stack trace

- **Reproduction:** After the doctor insertion, Rust reported that `line.split('\\\\t')` was an invalid multi-codepoint character literal. Call `mcp__filesystem_mcp_rs__edit_file` to replace `line.split('\\\\t')` with `line.split('\\t')`; the server reports “1 of 1 edits produced zero matches” and returns a full internal Rust stack trace. Re-reading `main.rs` showed the source line was unchanged.
- **Observed impact:** The correction anchor had one more escaped backslash than the actual source; this was caller error and no edit occurred. Returning internal frames for this routine no-match is a filesystem MCP server defect.
- **Safe fallback:** Read the numbered source line and use `edit_lines` with the verified line number; return a concise no-match error without internal stack frames.


## 2026-09-29 — `edit_file` stale formatted anchor leaks stack trace while adding doctor warning

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `nova/src/main.rs` to replace the activation-journal tail using a multiline literal anchor whose `.into()` line has no trailing comma. Current rustfmt output includes `.into(),`, so the server reports zero matches and returns a full internal Rust stack trace; no edit is applied.
- **Observed impact:** The anchor was stale because formatting had changed the comma; this was caller error. Returning internal frames for a routine no-match conflict is a filesystem MCP server defect. The intended doctor warning was not inserted by that failed call.
- **Safe fallback:** Re-read the exact formatted lines and apply the change with `edit_lines` using verified line numbers; return a concise no-match error without internal frames.


## 2026-09-29 — `run_command` rejects benign Bash path variable with stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__run_command` with `command:"wsl"` and args `[-d, Ubuntu, --, bash, -lc, "p=/home/joss/.cache/nova-doctor-validation; [ -d \"$p\" ]"]`. The MCP host rejects the command because it sees `$p` and returns `command/args contain '$p' — the MCP host may delete NAME tokens before spawn` followed by a full internal Rust stack trace; Bash is never started.
- **Observed impact:** The host protection prevents a potentially unsafe empty variable expansion, but the user-provided Bash variable was deliberate and the command did not execute. Exposing internal frames for this validation rejection is a server defect.
- **Safe fallback:** Use an explicit script passed as a file/stdin, or a fully literal path with no shell variable; return the concise host validation reason without internal frames.


## 2026-09-29 — UNC allowlist denial from Rez package repository leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem__list_directory({path:"\\\\msg\\fs\\software\\rez3\\tool\\rez-rs"})` and `mcp__filesystem__list_directory({path:"\\\\msg\\fs\\software\\rez3\\ext\\rez"})`. Both paths are outside the configured filesystem MCP allowlist. The server correctly denies access, but includes a full internal Rust stack trace.
- **Observed impact:** Repository contents were not read; this is expected access denial for paths outside the allowlist. Exposing native internal frames on that denial is a server defect. No files were changed by the failed calls.
- **Safe fallback:** Inspect the staged payload under the authorized `D:\\_rez_install\\bootstrap117\\0010.prep` tree, or configure an authorized share root before retrying; return a concise access-denied response without internal frames.

## 2026-09-29 — `edit_file` literal no-match leaks internal stack trace

- **Reproduction:** Call filesystem MCP `edit_file` on `rez-rs/BUG_HUNT_REPORT.md` with `oldText` set to `919 | The overall audit remains active. Outstanding compatibility and architecture work is itemized in `plan14.md`...` after reading the file with `line_numbers:true`. The editor returns “1 of 1 edits produced zero matches” and a full internal Rust stack trace. The displayed line number prefix is metadata and is not part of file contents; no document edit occurred.
- **Observed impact:** The anchor included a presentation-only line number, so the no-match was caller error and the target file remained unchanged. Returning internal frames for a routine no-match is a filesystem MCP server defect.
- **Safe fallback:** Use the exact unnumbered file text as the anchor (or append with a verified end-of-file operation); return a concise no-match error without internal frames.


## 2026-09-29 — `locate_search` missing-root validation leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem__locate_search` with `{query: "0040.rez_config"}` and omit `path`/`paths`. The server rejects the request with `path or paths is required` and returns a full internal Rust stack backtrace; no search runs. The exposed tool signature marks `path`, `paths`, and `query` optional, while the operation requires a root, so the machine-readable schema does not express this precondition. The original query also used the wrong folder name; the indexed directory is `1040.rez_config`.
- **Observed impact:** The omitted search root and mistyped directory were caller errors, including mine. Separately, the tool schema should require either `path` or `paths`, and the server should return a concise validation error instead of internal frames.
- **Safe fallback:** Supply the verified indexed root and exact directory name: `{path: "D:/_rez_install/bootstrap117/0010.prep", query: "1040.rez_config", mode: "contains", kind: "directories"}`. This corrected call returned one indexed directory match. For invalid requests, report the concise validation reason without native frames.


## 2026-09-30 — `run_command` rejects PowerShell status variable and leaks internal stack trace

- **Reproduction:** Call `mcp__filesystem__run_command` with `command: "cargo fmt; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }; cargo test --lib"`, `shell: "powershell"`, and the rez-rs workspace as `cwd`. The MCP host rejects the command because it detects `$LASTEXITCODE` as a variable token and returns the internal Rust stack trace; the command is never spawned.
- **Observed impact:** The inline PowerShell status check was caller-authored and is not required for the two validation commands. The server's stack trace exposure is a separate defect. No command ran and no files were changed by this failed call.
- **Safe fallback:** Run `cargo fmt` and `cargo test` as separate MCP commands, or pass a script through a file/stdin; return only the concise command-validation error.

## 2026-09-30 — edit_file unsupported look-ahead leaks internal stack trace

- **Reproduction:** Call mcp__filesystem__edit_file on C:/projects/projects.rust.cg/cglibs/rez-rs/docs/plans/plan17.md with edits [{oldText: "\\n\\n(?=\\| Final checks)", newText: "\\n", isRegex: true}]. The regex engine rejects look-ahead and the response includes a full native Stack backtrace ending in BaseThreadInitThunk and RtlUserThreadStart.
- **Observed impact:** Unsupported look-ahead is an expected caller pattern error; no edit is applied. Exposing internal native frames for that validation error is a server defect and produces excessive output.
- **Safe fallback:** Use the supported regex "\\n\\n\\| Final checks" with replacement "\\n| Final checks", or an exact literal anchor. The supported replacement succeeded. Return a concise regex validation error without internal stack frames.


## 2026-09-30 — managed `run_command` exceeds MCP call deadline and leaks native stack trace

- **Reproduction:** Call `mcp__filesystem_mcp_rs__run_command` with `command: "codex"`, args `["exec", "-m", "gpt-6.1-sol", "-c", "model_reasoning_effort=\"high\"", "-s", "read-only", "--ephemeral", "-o", "target/sol-direct-consult.md", "-"]`, an inline read-only architecture prompt, cwd `C:/projects/projects.rust.cg/cglibs/exr-rs`, `mode: "managed"`, and stdout/stderr files. The child runs longer than 300 seconds. Tool returns `timed out awaiting tools/call after 300s` followed by a full native Rust backtrace instead of a resumable managed-process result.
- **Observed impact:** The consultation completed and its output report/logs were preserved, but the caller lost process completion/exit metadata. A finite MCP deadline is expected; leaking native stack frames and not returning a managed-job handle is a server defect. The report must be checked before retrying to avoid duplicate work.
- **Safe fallback:** Run long commands in detached mode with explicit stdout/stderr files and an exit-status artifact, then inspect scoped process state and logs; never blindly restart a child after transport timeout. Return a concise timeout and process identity rather than internal frames.

## 2026-09-30 — `edit_file` zero-match batch leaks internal stack trace during Rez shell-output regression

- **Reproduction:** Call `mcp__filesystem_mcp_rs__edit_file` on `C:\\projects\\projects.rust.cg\\cglibs\\rez-rs\\src\\resolve\\context.rs` with three literal edits to correct escaped Rust strings in a newly inserted shell-output test. The first anchor matched; the second and third had excess escaping and matched zero lines. The server returned “2 of 3 edits produced zero matches” followed by a full internal Rust stack trace. Re-reading confirmed no edits from that batch were applied.
- **Observed impact:** The stale escaped anchors were caller error; no source change was made by this failed batch. Exposing internal frames for a normal no-match validation error is a filesystem MCP server defect.
- **Safe fallback:** Re-read the exact current lines, use `edit_lines` or one verified literal edit at a time, and return a concise no-match error without internal frames.

- **Additional observed reproduction (2026-10-01 UTC, portability overlapping anchors):** The owner's seven-edit batch on `C:/projects/projects.rust.cg/cglibs/rez-rs/tests/python_portability.rs` included edit 6 `{oldText:"    run_portable_python(true);",newText:"    run_portable_python(true, true);"}` and edit 7 `{oldText:"fn relocated_python_ignores_unrelated_host_python_homes() {\n    run_portable_python(true, true);\n}",newText:"<same block plus a new test>"}`. Edit 7 incorrectly matched an earlier edit's intended result instead of the original file; all batch anchors are checked against original content. The complete other batch edits/new test text are not reconstructed here. Expected caller error is an atomic no-match rejection, not sequential mutation. Observed -32603 `Failed to apply edits`, `1 of 7 edits produced zero matches` also exposes frames 0–24 of a native Stack backtrace including aws_lc/BaseThreadInitThunk/RtlUserThreadStart. The owner reread the original tail and confirmed no batch changes: this is **not** an atomicity bug. **Safe fallback:** reread original content, remove overlapping edit 6 and match edit 7 against original run_portable_python(true); the corrected retry succeeded. Return concise validation without internal frames.

### 2026-10-01 UTC — PowerShell variable validation stack trace, additional reproduction

- **Exact reproduction:** `run_command` with command `powershell`, args `["-NoProfile", "-Command", "Get-Process cargo,rustc,lld-link,link -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,CPU,@{Name='WorkingSetMB';Expression={[math]::Round($_.WorkingSet64/1MB)}} | ConvertTo-Json -Compress"]`, shell `none`, timeoutMs `30000`.
- **Observed impact:** The inline `$_` argument is rejected before spawn by the documented command-variable guard. That rejection is expected input validation; returning a full native stack trace (including unrelated native symbol names) is the reproducible server defect.
- **Safe fallback:** Pass the read-only script as inline stdin to `powershell -NoProfile -Command -`; the retry returned process information. Return the concise validation message without internal frames.

- **Additional reproduction (2026-09-30 local / 2026-10-01 UTC, exr-rs verification):** `mcp__filesystem_mcp_rs__run_command` with `command:"powershell.exe"`, `args:["-NoProfile","-Command", "& cargo clippy --locked --manifest-path crates/openexr-py/Cargo.toml --all-targets -- -D warnings *> 'C:/projects/projects.rust.cg/cglibs/exr-rs/target/final-python-clippy.log'\n$gateExit = $LASTEXITCODE\nSet-Content -LiteralPath 'C:/projects/projects.rust.cg/cglibs/exr-rs/target/final-python-clippy.exit' -Value $gateExit\nexit $gateExit"]`, cwd `C:/projects/projects.rust.cg/cglibs/exr-rs/target/gate-direct-final`, and mode `detached`, rejects `$gateExit` before spawn and exposes a full native stack backtrace. The argument rejection is expected caller validation; native frame exposure is the server defect. Passing the same wrapper through `stdin:{kind:"inline",text:...}` with args `["-NoProfile","-Command","-"]` started successfully as PID 36284 and preserves explicit completion status; no source edits or build ran from the rejected call.

### Additional expected-input stack-leak reproductions — 2026-10-01 UTC

These reproduce the existing validation/read-error stack-leak class; they do not establish a new filesystem mutation defect.

- **Additional exact reproduction (2026-10-06, ffmpeg-rs F7):** `mcp__filesystem_mcp_rs__read_text_file({path:"C:/projects/projects.rust.cg/cglibs/ffmpeg-rs/crates/av-test-golden/refs/av_test_golden",head:1})` targets an existing directory. The coordinator observed MCP -32603 `Failed to read head`, AccessDenied (os error 5), and 25 native stack frames including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`. Reading a directory as a file is an expected caller error; disclosing the full internal stack is the server defect. No file was read or changed. **Safe fallback:** `list_directory` confirms the directory and its record subdirectories; select and read an actual file. The documentation agent verified this listing without repeating the invalid read. Return concise structured wrong-kind/read diagnostics without native frames.

- **Exact reproduction (literal wildcard read):** `mcp__filesystem__read_text_file({path:"C:/Users/joss1/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/clap-4.6.*/src/_derive/mod.rs",head:3})`. The caller passed a wildcard where an exact file path is required. The inaccessible-path rejection is expected; returning a full native stack trace with aws_lc/BaseThreadInitThunk frames is the server defect. No file is read or changed. **Safe fallback:** enumerate the actual registry directory/file first with list_directory/search_files, then read the verified exact path; return a concise read error without native frames.
- **Exact reproduction (unsupported locate mode):** `mcp__filesystem__locate_search({path:"D:/_rez_install/bootstrap117",query:"python_setup",mode:"name",limit:10})`. Mode name is invalid: valid modes are exact/prefix/contains/glob/regex. The -32602 validation rejection is expected, while the full internal stack trace is the server defect. No scan or mutation occurs. **Safe fallback:** use mode contains with the verified root; return the concise mode validation error.
- **Exact reproduction (protected literal token):** `mcp__filesystem__run_command({command:"python",args:["-B","-c","print(\"${TMPDIR:-/tmp}\")"],cwd:"D:/_rez_install/bootstrap117",shell:"none"})`. The documented token guard rejects the argument before spawn; exposing a full stack trace is the server defect. No Python process runs from that rejected call. **Safe fallback:** args `["-B","-"]` with `stdin:{kind:"inline",text:"print(\"${TMPDIR:-/tmp}\")"}`; the owner confirms this retry succeeds. Preserve literal script data through stdin and return the concise guard message.

The owner's additional unsupported-lookaround report lacks an exact path/edit record; the existing regex-validation issue remains recorded above, and no invented reproduction is added.

- **Additional exact reproduction — 2026-10-01 UTC (memory UUID validation):** `mcp__filesystem__mem_get({actorId:"codex",workspaceId:"rez-rs",ids:["5c95d86a"]})` returns -32602 `Invalid ids[] UUID: invalid length: found 8` and a full 25-frame native stack trace including aws_lc/BaseThreadInitThunk/RtlUserThreadStart. I supplied a UUID prefix instead of the required full UUID; rejecting it is expected caller validation. Exposing native frames is the existing server defect; no memory record is read or changed by the rejected request. **Safe fallback:** obtain the complete UUID from the owner or a scoped memory search, then call mem_get; the complete-UUID retry succeeded. Return a concise UUID-validation error without internal frames.

- **Additional exact reproduction (2026-10-01 UTC, Python identity repair):** `mcp__filesystem__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/cli/admin/python.rs` with a five-edit batch whose second edit was `{oldText:"    let marker = std::env::var_os(REENTRY);[\\s\\S]*?    // Valid Rez commands",newText:"...",isRegex:true}`. Unescaped parentheses in the caller's regex produced zero matches. The server correctly rejected the entire batch, but returned a full native stack trace with aws_lc/BaseThreadInitThunk frames. Re-reading confirmed the file unchanged. **Safe fallback:** use the verified complete literal block; the corrected literal batch succeeded. No-match is caller error; internal stack exposure is the existing server defect.

- **Additional exact reproduction (2026-09-30 PDT / 2026-10-01 UTC, exr-rs gate liveness):** Twice called `mcp__filesystem_mcp_rs__run_command({command:"powershell",args:["-NoProfile","-Command","Get-Process | Where-Object { $_.ProcessName -like 'exr_util-*' } | Select-Object Id,ProcessName,CPU,WorkingSet64,StartTime | ConvertTo-Json -Compress"],cwd:"C:/projects/projects.rust.cg/cglibs/exr-rs",mode:"sync",stdoutHead:5,stderrTail:3})`. The protected `$_` token was correctly rejected before spawn with -32602 and an instruction to pass the script through stdin or a file. The response also included 25 native stack frames, including aws_lc/BaseThreadInitThunk/RtlUserThreadStart. Token rejection is expected caller validation; native stack exposure is the existing server defect. No process ran from either rejected call. **Safe fallback:** use args `["-NoProfile","-Command","-"]` with the same script in an inline stdin ContentRef; keep command arguments free of protected script tokens. Return the concise validation message without native frames.

- **Additional exact reproduction (2026-09-30 PDT / 2026-10-01 UTC, inline-content limit):** `mcp__filesystem_mcp_rs__write_file({path:'C:/projects/projects.rust.cg/cglibs/exr-rs/target/filesystem-inline-limit-stack-repro.txt',content:{kind:'inline',text:'a'.repeat(65537)}})` correctly rejects the 65,537-byte inline payload with -32602 `inline_too_large` (limit 65,536 bytes). The defect is the full native `Stack backtrace` returned for this routine caller size error, including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk` and `RtlUserThreadStart`; the size limit itself is expected validation. Full response evidence: `C:/projects/projects.rust.cg/cglibs/exr-rs/target/filesystem-inline-limit-stack-repro.json`, SHA256 `20a1b34495125c944b485f0320dcdcd6805c446ca27e7e9bc8049b87435ded0c`. **Observed impact:** internal native frames are disclosed and routine validation produces excessive output. **Safe fallback:** stage larger content using `blob_begin`, chunked `blob_append`, `blob_finalize`, then `write_file` with `{kind:'blob',id}`; check `isError`. This path successfully staged a 410,042-byte Python source manifest. Return the concise size-validation message without internal frames.

- **Additional observed reproduction (2026-10-01 UTC, package-help alias):** The owner's failed edit_file batch on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/main.rs` contained the literal oldText `#[command(name = "help-pkg")]`, while the actual line included `disable_version_flag = true`. The server returned -32603 with `0 matches` and a full native `Stack backtrace` ending in BaseThreadInitThunk/RtlUserThreadStart; the owner confirms no batch edits were applied before the corrected retry. The complete original batch was not retained, so it is not reconstructed here. **Minimal standalone reproducer supplied by the owner:** `mcp__filesystem__edit_file({path:"C:/projects/projects.rust.cg/cglibs/rez-rs/src/main.rs",edits:[{oldText:"#[command(name = \"help-pkg\")]",newText:"#[command(name = \"help-pkg\", alias = \"help\", disable_version_flag = true)]"}]})`; this minimal request was not rerun by the documentation agent. **Observed impact:** the stale anchor is caller error and should yield a concise no-match rejection; internal stack disclosure is the existing server defect. **Safe fallback:** reread the exact current declaration and replace its verified literal text while preserving disable_version_flag; the owner used that corrected retry. No source changes are authorized or performed by this report entry.

- **Additional exact reproduction (2026-10-01 UTC, documentation append):** `mcp__filesystem__edit_file` on this BUG_CDX.md with one whole-file literal replacement supplied a 129,937-byte inline argument. The server correctly returned -32602 inline_too_large (65,536-byte limit), but also exposed a 25-frame native backtrace including aws_lc/BaseThreadInitThunk/RtlUserThreadStart. This oversized argument was caller error; stack disclosure is the same server defect. The failed request made no change. **Safe fallback:** append with a short verified final-paragraph anchor, or use the documented blob staging API for large content; return only the size-validation diagnostic.

- **Additional exact reproduction (2026-10-01 UTC, root Make discovery):** The orchestrator called `mcp__filesystem__locate_search({path:"C:/Programs",query:"make.exe",mode:"name",kind:"file",limit:12,waitMs:0})`. Invalid mode `name` is expected caller error; the bounded diagnostic is `mode must be exact, prefix, contains, glob, or regex` (-32602). The observed response also disclosed a full 23-frame internal stack including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk` and `RtlUserThreadStart`. **Impact:** routine enum validation exposes native internals and excessive output; this is the existing stack-disclosure class, not a locate-index failure. **Safe fallback:** use `mode:"contains"` for the same search and return only the concise validation diagnostic. Evidence supplied by the root orchestrator; the documentation agent did not rerun the invalid request.

- **Additional exact reproductions (2026-10-01 UTC, root/worker cache and Make discovery):** (1) Root `mcp__filesystem__locate_search({paths:["C:/Programs","C:/msys64","C:/projects"],query:"make.exe",mode:"contains",kind:"file",limit:20,waitMs:0})` used invalid singular kind and received expected validation plus a full 25-frame internal stack. **Safe fallback:** use `kind:"files"`. (2) Worker `mcp__filesystem__locate_search({query:"*bigskysw*",limit:30})` omitted required paths and likewise received expected missing-path validation plus 25 internal frames. **Safe fallback:** provide an explicit verified paths array and a documented matching mode. These are caller parameter errors; returning native frames is the existing server stack-disclosure defect. **Impact:** ordinary input validation exposes internals and excessive output. Exact requests/observations supplied by root; documentation agent did not rerun invalid calls. No locate-index or skill defect is inferred.

- **Additional exact reproduction (2026-10-01, shared PowerShell completion literal proof):** Worker `mcp__filesystem__run_command({"command":"python","args":["-c","import pathlib,re,json\nr=pathlib.Path(r'C:/projects/projects.rust.cg/cglibs/rez-rs');s=(r/'src/shell/types.rs').read_text();f=s[s.index('pub fn exit_command'):s.index('/// Arguments for invoking this shell')];m=re.search(r'Self::PowerShell => \\{\\s*(\"(?:[^\"\\\\]|\\\\.)*\")',f); literal=json.loads(m.group(1)); assert literal.startswith('$__rez_rs_success = $?\\n'); assert 'PSVariable.GetValue' in literal; print('shared literal extracted and valid')"],"shell":"none","timeoutMs":10000,"stdoutTail":1500,"stderrTail":1500})` returned -32602 because command/args contain `$__rez_rs_success`, with the documented instruction to pass protected NAME-token scripts through stdin ContentRef or a file. The guard rejection is expected and the command did not run. The response also disclosed a full native `Stack backtrace` including aws_lc/BaseThreadInitThunk frames: this is the existing server stack-disclosure defect. **Impact:** routine input validation exposes internals and excessive output. **Safe fallback:** filesystem-write the same script as `target/powershell-completion-proof-20261001-1740/literal-proof.py`, then call run_command python with that file argument; the worker confirms exit0 in0.724s, run_command_1790880113364_e28d274e-ce40-4c35-955d-fb8fd2f5321b. The documentation agent records the supplied exact request without rerunning it.

## 2026-10-01 — custom run_command capture paths lose output and change benign exit status

- **Exact independent reproduction:** `mcp__filesystem_mcp_rs__run_command({command:"python",args:["-c","print('cpu-optimization-log-probe')"],cwd:"C:/projects/projects.rust.cg/cglibs/exr-rs",mode:"sync",stdoutFile:"C:/projects/projects.rust.cg/cglibs/exr-rs/target/docs-capture-probe.stdout.log",stderrFile:"C:/projects/projects.rust.cg/cglibs/exr-rs/target/docs-capture-probe.stderr.log",killAfterMs:10000,stdoutTail:3,stderrTail:3})`.
- **Observed:** existing target directory; call completed in 84 ms with exitCode 120, captureTruncated true, empty stdout/stderr, timedOut false and killed false. Both advertised log files were absent on an explicit existence check. The identical benign Python command without stdoutFile/stderrFile completed in 41 ms with exitCode 0, captureTruncated false and the expected line; automatic temporary stdout/stderr files existed with the correct content. This is a custom-capture failure, not an expected Python error or missing-input-file error. No explanation of the internal cause is inferred.
- **Impact:** callers lose diagnostics and cannot trust the altered exit status or advertised log paths. The owner also observed a GitNexus reanalyze call with custom paths return 101 with no output/log files or graph update; without custom paths it completed normally with exit 0. The documentation agent reproduced only the safe Python pair, not another index operation.
- **Safe fallback:** omit custom capture paths, inspect the tool's actual automatic log files, then copy those files through filesystem MCP to the desired evidence location. Alternatively, let an explicit Python subprocess wrapper own its output and exit-status files while the MCP call uses automatic capture. Check log existence and explicit completion status before retrying a stateful command.

- **Additional exact reproduction (2026-10-01 UTC, viewer ROI author):** `mcp__filesystem_mcp_rs__write_file({path:"C:/projects/projects.rust.cg/cglibs/exr-rs/target/fix-viewer-roi/crates/exr-view/src/tiles/file.rs",content:{kind:"inline",text:<73830 UTF-8 bytes of the current file, with one bounded test-channel rename>}})` returned expected -32602 `inline_too_large: 73830 bytes exceeds limit of 65536` and a full 25-frame native stack including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`. Oversized inline content is caller error; internal stack disclosure is the existing server defect. No write was applied. **Impact:** normal documented size validation leaks internals and excessive output. **Safe fallback:** use a short verified literal `edit_file` anchor for this small change (successful here), or documented blob staging for actual large writes. No server source edits performed.

- **Additional exact reproduction (2026-10-01, viewer cache-demand author):** `mcp__filesystem_mcp_rs__edit_file({path:'C:/projects/projects.rust.cg/cglibs/scancache-rs/target/fix-viewer-demand/src/cache/tests.rs',edits:[{oldText:'',newText:'',replaceAll:false}]})` returned expected zero-match validation and a full 25-frame native stack including aws_lc/BaseThreadInitThunk/RtlUserThreadStart. Empty edit anchors are caller error; the stack disclosure is the existing server defect. No edit was applied. **Observed impact:** ordinary input validation exposes internal frames and excessive output. **Safe fallback:** reread the current file and use a verified nonempty literal anchor, or a bounded write for replacement content. Return a concise validation diagnostic without native frames. This entry records the author's exact request and observed result; the documentation agent did not rerun the invalid call.

- **Additional exact reproduction (2026-10-01, OFX coordinate reference):** `mcp__filesystem_mcp_rs__http_request({method:"GET",url:"https://openfx.readthedocs.io/en/main/Guide/ofxCoordSystem.html",maxBytes:220000,timeoutMs:20000})` returns the expected domain-allowlist denial (-32602), but also a full 25-frame native stack. The domain denial is expected policy enforcement, not a server defect; exposing native internals for that routine denial is the existing stack-disclosure defect. **Observed impact:** blocked reference retrieval produces excessive output and exposes internal frames. **Safe fallback:** use the official web tool for the primary OpenFX documentation or inspect verified local OFX headers. This records the root's exact request and observation; the documentation agent did not rerun the invalid request or change server source.

- **Additional exact reproduction (2026-10-06, F7 env-order documentation):** `mcp__filesystem_mcp_rs__http_request({method:"GET",url:"https://doc.rust-lang.org/std/process/struct.Command.html#method.env",maxBytes:1048576,timeoutMs:20000})` returned expected `-32602: HTTP domain 'doc.rust-lang.org' is not in allowlist`, followed by 25 native frames including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`. Allowlist rejection is expected policy enforcement; full internal stack disclosure is another occurrence of this existing server defect. **Observed impact:** the primary reference could not be fetched through this tool, and routine denial exposed internals and excessive output. **Safe fallback:** the official web tool retrieved the same Rust std page and confirmed overwrite/Windows case semantics. No allowlist or server source was changed.

- **Additional exact reproduction (2026-10-07, ffmpeg-rs M8 reserve plan):** `mcp__filesystem_mcp_rs__http_request({method:"GET",url:"https://doc.rust-lang.org/std/vec/struct.Vec.html",timeoutMs:15000,maxBytes:2500000})` returned MCP -32602 `HTTP domain 'doc.rust-lang.org' is not in allowlist`, followed by native `Stack backtrace` frames 0..24 including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`. The allowlist denial is expected policy enforcement; internal stack disclosure repeats the existing server diagnostic defect. **Observed impact:** primary reference retrieval through the tool was blocked and routine denial exposed internal details; no source, configuration, or process was changed. **Safe fallback:** the official web tool retrieved the same Rust std documentation, confirming fallible reserve capacity/allocator errors and the existing ErrorKind representation. No allowlist bypass or server setting change was used.

- **Additional exact reproduction (2026-10-01, host pixel admission author):** `mcp__filesystem_mcp_rs__proc_tree({pid:54440})` raced completion of the author's own Cargo process, previously observed by `search_processes`. The call returned expected `-32603: Process 54440 not found`, followed by a full 25-frame native stack including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`. Process disappearance is an expected scheduling race; exposing native internals for this routine not-found error is another reproduction of the existing stack-disclosure defect, not evidence of a Cargo failure. **Observed impact:** routine process inspection produces excessive output and exposes internal frames. **Safe fallback:** use `search_processes`, recheck the current PID and command before inspection, and inspect the command's existing output logs after completion. No foreign process was killed and no server source was edited.







- **Additional exact reproduction (2026-10-01, recovered viewer source hash):** `mcp__filesystem_mcp_rs__file_hash({path:'C:/projects/projects.rust.cg/cglibs/agent-recovery/exr-view-phase7-20261001/sources/crates/exr-view/src/app.rs',algorithm:'sha256'})` used the wrong nested backup path; the actual recovered file is flat `sources/app.rs`. The expected caller path error returned `-32603: Cannot open file` plus a full 25-frame native Stack backtrace including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`. This is another variant of the existing server error-rendering stack-disclosure defect, not a missing-file defect or product hash mismatch. **Observed impact:** routine path rejection exposes internals and excessive output. **Safe fallback:** list the recovery directory, hash the verified flat path, and return concise file-open errors; the corrected paths matched all 16 source hashes. The documenting agent records the supplied exact request without rerunning the invalid call. No server source was edited.

- **Additional exact reproduction (2026-10-01, documentation dry-run):** `mcp__filesystem_mcp_rs__edit_file({path:'C:/projects/projects.rust.cg/cglibs/ofx-rs/crates/ofx-host/README.md',edits:[{oldText:'acceptance boundaries.\n\n\n \n```text',newText:'acceptance boundaries.\n\n## Smoke executable\n\n```text'}],dryRun:true})` used a stale whitespace anchor and correctly rejected zero matches without changing the file. The server additionally returned -32603 and a full 25-frame native stack (aws_lc/BaseThreadInitThunk/RtlUserThreadStart), reproducing the existing no-match error-rendering disclosure, not a dry-run mutation defect. **Impact:** excessive output/internal disclosure for an expected caller anchor error. **Safe fallback:** reread the exact blank lines and retry the verified literal; the corrected edit succeeded. No server source was changed.



## 2026-10-02 — Existing Windows drive root rejected by disk_usage, with internal stack disclosure

- **Exact reproduction:** Call `mcp__filesystem__disk_usage({path: "C:\\"})` on the Windows host whose active repository is `C:/projects/projects.rust.cg/cglibs/rez-rs`. The publication worker reported the failure, and the documentation agent independently reproduced it with the same argument.
- **Observed result:** MCP error `-32603: No disk found for path: C:\\`, followed by native frames 0–24, including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk` and `RtlUserThreadStart`.
- **Impact:** Disk capacity cannot be inspected using the existing drive-root path. This is not a nonexistent-file caller error: successful reads of the active C: repository establish that the drive exists. Returning an internal stack trace is independently a server defect.
- **Safe fallback:** Use `disk_usage({})` to inventory mounted disks, pass a verified existing directory below the root, or use `shutil.disk_usage` through the filesystem MCP command runner. No files were deleted and no processes were terminated by the reproduction.


### 2026-10-01 — additional stale-window variant of internal stack disclosure

- Reproduction: after the previously enumerated `exr-view` window ceased to exist, `mcp__filesystem_mcp_rs__win_focus({target:{id:140381488}})` returned `-32602: no_match: no visible window matches Id { id: 140381488 }`, followed by native frames 0–24 (`aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, `RtlUserThreadStart`). A fresh `win_list({query:{exe:"exr"}})` confirmed an empty window list.
- The stale ID is an expected caller/window-lifetime error. The defect is exposing the internal stack for that normal error, matching the previously recorded error-rendering class; this does not establish that the server closed the window.
- Impact: stale-window recovery emits internal native details instead of a concise domain error.
- Safe fallback: refresh `win_list` before focusing; stop the input burst on any failed focus and send no further mouse/key actions until the target's foreground state is verified. No file was deleted and no process was terminated to reproduce this variant.

- **Additional exact reproductions (2026-10-01 PDT / 2026-10-02 UTC, exr-view preferences review):** (1) `mcp__filesystem_mcp_rs__locate_search({path:"C:/projects/projects.rust.cg",query:"prefs",kind:"files",filters:{path:{include:"cglibs\\playa\\",exclude:["target","node_modules",".git"]}},limit:25})` failed with `invalid type: string ..., expected a sequence`. The exposed declaration advertises `filters.path.include: Array<string> | string`, so rejecting this scalar is a tool-contract defect. **Safe fallback:** pass `include:["cglibs\\playa\\"]`; that exact retry returned six indexed matches. (2) `locate_search({path:"C:/projects/projects.rust.cg",query:"playa",kind:"dir",limit:15,waitMs:0})` and, after arming, `key_tap({target:{id:14159458},key:"ctrl+,"})` returned full native backtraces for invalid kind / unknown key. Those invalid values are caller errors; exposing 25 native frames is the existing server stack-disclosure defect. **Impact:** the documented scalar filter cannot be used; ordinary validation emits excessive internal details. **Safe fallback:** use `kind:"directories"` and the observed Settings tab through guarded mouse input. Preserve concise validation diagnostics and omit internal stacks.


- **Additional exact reproduction (2026-10-01 PDT / 2026-10-02 UTC, rez-rs release process inspection):** Root called `mcp__filesystem__run_command` with `command:"powershell"` and `args:["-NoProfile","-Command","Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -eq 32592 -or $_.ParentProcessId -eq 32592 -or ($_.Name -eq 'rustc.exe' -and $_.CommandLine -like '*rez_rs*') } | Select-Object ProcessId,ParentProcessId,Name,WorkingSetSize | ConvertTo-Json -Compress"]`. The documented `-32602` rejection because command/args contain `$_` is expected caller validation. The response additionally disclosed full native frames 0–24, including aws_lc entropy, `BaseThreadInitThunk` and `RtlUserThreadStart`, reproducing the existing stack-disclosure defect. **Impact:** routine argument validation exposes internals and excessive output; it does not establish a release-build or process failure. **Safe fallback:** pass the identical script through stdin ContentRef with args `["-NoProfile","-Command","-"]`; root confirms that retry completed with exit 0. The documentation agent records the supplied observation without repeating the rejected command or stopping any process. No rez-rs documentation or server source was changed for this entry.

- **Additional exact reproduction (2026-10-01 PDT / 2026-10-02 UTC, playa native display host):** `mcp__filesystem_mcp_rs__edit_file({path:"C:/projects/projects.rust.cg/cglibs/playa/crates/playa-app/src/display_host.rs",edits:[{oldText:"        let app = self.creator.take()",newText:"        input.init_accesskit(event_loop, &window, self.proxy.clone());\\n        let app = self.creator.take()"}]})` after rustfmt split the old expression across lines. The literal no-match is an expected caller error; returning `-32603: Failed to apply edits: ... zero matches` followed by 25 native frames (including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, `RtlUserThreadStart`) reproduces the server stack-disclosure defect. The observed call contained four additional valid edits; no edits were applied. **Impact:** ordinary stale-text validation exposes internal details and excessive output. **Safe fallback:** re-read the formatted file and match the current multiline text; the retry applied correctly. Keep the concise no-match diagnostic and omit internal stacks.

- **Additional exact reproduction (2026-10-01 PDT / 2026-10-02 UTC, Playa runtime acceptance):** `mcp__filesystem_mcp_rs__http_request({method:"GET",url:"http://127.0.0.1:19876/api/health",timeoutMs:3000})` returned the expected domain-allowlist denial (-32602), plus a full native stack including aws_lc/BaseThreadInitThunk/RtlUserThreadStart. Denying a nonallowlisted local domain is expected policy; internal stack disclosure is the existing server defect. **Impact:** routine validation exposes internal details and excessive output. **Safe fallback:** run a local HTTP client through the filesystem command runner for the user's own isolated test process, retaining PID verification before mutations. No allowlist or server security setting was changed.


- **Additional exact reproduction (2026-10-02 UTC, existing rez-rs workspace disk usage):** `mcp__filesystem__disk_usage({path:"C:/projects/projects.rust.cg/cglibs/rez-rs"})` returns `-32603: No disk found for path: C:/projects/projects.rust.cg/cglibs/rez-rs` plus native frames 0–24, including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk` and `RtlUserThreadStart`. The root reported it and the documentation agent independently reproduced it once. A successful full read of `docs/plans/plan29.md` during the same operation establishes that this workspace exists. This extends the recorded drive-root failure to an existing directory, not a nonexistent-path caller error. **Impact:** capacity checks for a valid workspace fail and disclose excessive internal detail. **Safe fallback:** use Python `shutil.disk_usage` through filesystem MCP `run_command`; do not change or delete the directory to recover the capacity query. No files were deleted and no processes were stopped for this reproduction.


## 2026-10-01 — edit_file exposes internal backtrace for invalid caller regex

Reproduction: filesystem-mcp-rs edit_file with isRegex=true and oldText `let overview = TileId { level: top, tx: 0, ty: 0 };` (unescaped braces). The regex is a caller error; a concise invalid-pattern response is expected. Observed: MCP -32603 includes the regex parse diagnostic plus a full internal native Stack backtrace (aws_lc entropy symbol and BaseThreadInitThunk/RtlUserThreadStart). Impact: excessive internal implementation disclosure and noisy expected-error output; file was unchanged. Safe fallback: escape literal braces as `\{`/`\}`, or use literal edit mode. Keep invalid regex validation errors structured and omit native backtraces.

## 2026-10-01 PDT / 2026-10-02 UTC — native input guards expose internal backtraces during Playa acceptance

Exact requests and observations supplied by the controller; the documentation agent did not rerun
input against stale or closed windows. These variants extend the existing internal-stack disclosure
class. The guard results themselves are expected rejections, not established server defects.

- **Expired arming:** `win_focus({target:{id:3215286}})` and
  `mouse_click({target:{id:3215286},x:1150,y:1024})` returned `not_armed` after the arm expired,
  with a full 25-frame internal stack in each response. Requiring a fresh arm is expected.
- **Close followed by refresh:** `win_close({target:{id:2822070}})` returned MCP -32603,
  `window still alive after WM_CLOSE (app may show prompt)`, plus a 25-frame stack.
  The next `win_list({query:{exe:"playa"}})` returned `wins:[]`. This does not establish a
  close-timing defect: the application can finish closing between the two calls.
- **Guarded drag cursor mismatch:**
  `mouse_drag({target:{id:3215286},from:{x:1118,y:800},to:{x:1320,y:800},duration_ms:500})`
  returned `cursor did not reach target` with actual cursor `(1161,809)` and a 25-frame stack.
  Concurrent user cursor movement is possible; refusing the mismatched input is expected.
- **Closed target:** `win_focus({target:{id:3215286}})` returned `no_match` plus a 25-frame
  stack after the app window had closed. The stale window ID is expected caller error.

**Observed impact:** routine arm/target/cursor validation discloses internal native frames and
produces excessive output. The reproducible defect is raw backtrace exposure; none of these
observations proves the guard or window-management behavior itself is defective.

**Safe fallback:** refresh the window target and arm before authorized input, focus the verified
window immediately before that input, abort on focus/guard failure, and refresh window inventory
after a close response before concluding that the window remains. Return concise structured
validation/guard errors without native internal stacks.

## 2026-10-02 — Network repository path denial exposes internal stack

- **Exact reproduction:** Filesystem MCP `read_text_file({path:"M:/software/rez3.beta/tool/.lock.python-3.10",head:10,max_chars:1000})` returns MCP -32603 path validation denial for the resolved `\\\\?\\UNC\\msg\\fs\\software\\rez3.beta\\tool\\.lock.python-3.10` path, followed by 25 internal stack frames (0–24).
- **Observed impact:** The configured access restriction may be expected; this does not establish a path-validation defect or an active package lock. The reproducible reporting defect is the excessive internal backtrace disclosure.
- **Safe fallback:** Respect the access denial and inspect repository lock semantics in accessible project source. Do not bypass the restriction through a shell or claim the actual OS lock was checked. Return a concise structured access-denied response without native frames.

## 2026-10-01 PDT / 2026-10-02 UTC — observed win_geom resize reports success without changing geometry

- **Exact reproduction supplied by the controller:** arm for 120000 ms, focus window ID 109775954,
  then `win_geom({target:{id:109775954},w:1100,h:800})`. The call reported success but returned
  1400×900; a later `win_list` and native capture still showed unchanged 1400×900 geometry.
  This records one observed attempt, not a claim that all `win_geom` resize calls fail.
- **Observed impact:** success did not establish that the requested dimensions were applied.
  A subsequent physical border drag reached 1100×800. Read-only host review found initial
  builder sizing only once, a 64 pt minimum, and no forced recurring window size; the root cause
  of the tool's unchanged geometry remains unproven.
- **Safe fallback:** perform an authorized physical border drag and recheck actual geometry
  with refreshed window inventory and capture. Treat unchanged returned geometry as an
  unsuccessful resize rather than trusting the success status. No tool call was repeated
  against the later closed window; its stale-target stack variant is already logged above.



## 2026-10-01 PDT / 2026-10-02 UTC — oversized inline write error exposes internal stack

- **Exact reproduction:** `write_file` with inline text for `agent-recovery/phase34-team-20261001/app-metadata-tree-candidate.rs` of 161633 UTF-8 bytes returns MCP -32602 `inline_too_large: 161633 bytes exceeds limit of 65536`, followed by 24 native internal stack frames including aws_lc, BaseThreadInitThunk and RtlUserThreadStart.
- **Observed impact:** Exceeding the documented inline size is a caller error and its rejection is expected. The reporting defect is disclosure of a full internal native backtrace for that validation error.
- **Safe fallback:** Copy the existing source with `write_file({content:{kind:"path",path:...}})`, then apply the small literal edit through `edit_file`; both succeeded. Return a concise structured validation error without internal stack frames.

## 2026-10-02 — repeated validation backtrace exposure

- **Exact reproduction:** `edit_file` on `agent-worktrees/viewer-acceptance-20261002/plans/20261001-viewer-tiles-openfx.md` replacing absent literal `a-b-c-acceptance-follow-up-2026-10-02-final-gates-pending` with `a-b-c-acceptance-follow-up-2026-10-02-accepted` returns MCP -32603 zero-match rejection plus 25 internal native stack frames. A subsequent whole-file edit on this report with 160400-byte oldText returns expected inline_too_large rejection plus the same full backtrace.
- **Observed impact:** Both are caller validation errors; rejection is expected and no edit occurs. Internal native backtrace exposure is the reporting defect, already recorded on 2026-09-28 and reproduced again here.
- **Safe fallback:** Search before editing anchors; append through a small exact tail edit rather than whole-file literals. Return concise structured validation failures without native stacks.

## 2026-10-02 — HTTP validation and download errors expose internal backtraces

- **Exact reproduction:** During oidn-rs audit, `http_request({url:"https://raw.githubusercontent.com/RenderKit/oidn/master/core/unet_filter.cpp",method:"GET",maxBytes:90000})` returns expected MCP -32602 domain-not-in-allowlist rejection followed by 25 internal native frames (including aws_lc, BaseThreadInitThunk, RtlUserThreadStart). A team agent also observed `http_download` to `oidn-rs/bughunt/reference-v2.3.3/core/color.h` before its parent existed returning os error 3 with the same internal backtrace; the model agent reproduced this with `reference-v2.4.1/core/tza.cpp` and `tensor.h`. Downloading nonexistent upstream `common/math.h` returned expected HTTP404 followed by the same internal backtrace.
- **Observed impact:** Domain allowlist rejection and missing-parent rejection are expected caller/environment errors. Exposing internal native backtraces is the server reporting defect; no denoiser source was changed.
- **Safe fallback:** Fetch official pinned source through `gh api` invoked by filesystem `run_command`; create download parents before use. Return concise structured HTTP/file errors without internal stack frames.

## 2026-10-02 — oidn-rs absent edit anchor exposes internal backtrace

- **Exact reproduction:** Filesystem MCP `edit_file` with `dryRun:true` on `oidn-rs/DIAGRAMS.md` replacing absent literal `## End-to-end dataflow` with the same text returns expected zero-match MCP -32603 rejection plus 25 internal native stack frames.
- **Observed impact:** The absent anchor was a caller-side stale-heading mistake; rejection and unchanged file are correct. Internal backtrace disclosure is the reproducible server reporting defect, not the edit mismatch itself.
- **Safe fallback:** Re-read the full current document and edit a verified exact anchor; server should return concise structured mismatch diagnostics without internal frames.
- **Additional reproduction (2026-10-02):** After rustfmt of `squarebob-rs/examples/oidn_highlight_probe.rs`, an `edit_file` call using an obsolete multiline `else { 16.0 }` anchor returned the correct zero-match rejection accompanied by 25 internal native stack frames. Re-reading the formatted line and replacing its exact one-line anchor succeeded. The caller anchor mismatch is expected; disclosure of internal frames is the reporting defect.


## 2026-10-02 — delete_path validation exposes internal backtrace

- **Exact reproduction:** Call `delete_path({path:"C:\\projects\\projects.rust.cg\\cglibs\\frac-rs\\__pycache__"})` on an existing empty directory, omitting `recursive`. Repeated twice; each returns MCP -32602 `Refusing to delete directory without recursive=true` followed by 25 internal native stack frames, including aws_lc, BaseThreadInitThunk, and RtlUserThreadStart.
- **Observed impact:** Requiring recursive=true is expected caller validation, and the directory stays intact. Exposing a full native backtrace for that validation failure is the server reporting defect.
- **Safe fallback:** Verify the absolute directory is within the intended workspace and inspect its contents, then call delete_path with recursive=true. Server should return concise validation diagnostics without internal frames.

## 2026-10-02 — frac-rs edit validation exposes internal backtrace

- **Exact reproduction:** `edit_file` on `C:\\projects\\projects.rust.cg\\cglibs\\frac-rs\\src\\app.rs` with three literal edits, the third using absent `            if !self.viewport_visible`, returned MCP -32603 `1 of 3 edits produced zero matches` followed by 25 native internal stack frames including aws_lc, BaseThreadInitThunk and RtlUserThreadStart.
- **Observed impact:** The stale/incorrect anchor is a caller error; rejecting the whole edit without mutation is expected. Disclosure of internal native frames is the server defect.
- **Safe fallback:** Re-read current anchors and retry only the verified edits; this succeeded. Return concise structured validation diagnostics without internal frames.

## 2026-10-02 � locate_search invalid mode exposes internal backtrace

- **Exact reproduction:** `locate_search({paths:["C:/projects/projects.rust.cg"],query:"display_host.rs",mode:"name",limit:12})` returns MCP -32602 `mode must be exact, prefix, contains, glob, or regex` followed by 25 native internal frames including aws_lc, BaseThreadInitThunk and RtlUserThreadStart.
- **Observed impact:** The unsupported mode is a caller error and rejection is expected. Full internal backtrace disclosure is the server reporting defect.
- **Safe fallback:** Use documented `mode:"contains"`; when locate index has no entry, use filesystem MCP `run_command` with bounded `rg --files`. Return concise structured validation errors without native frames.

## 2026-10-02 � completed-process lookup exposes internal backtrace

- **Additional exact reproduction (rez-rs packaging):** `mcp__filesystem__proc_tree({pid:30700})` after the owned `python bootstrap.py p` completed returned expected MCP -32603 `Process 30700 not found` plus 25 internal native stack frames. The build stdout independently records exit 0 and the staged package. The missing process is an expected lifecycle outcome; the exposed stack repeats the server reporting defect. Safe fallback: read the captured build stdout/stderr for completion and refresh process inventory before requesting a tree. No process was terminated by this lookup.

- **Exact reproduction:** During oidn-rs native/PQ verification, the native agent called filesystem MCP `proc_tree({pid:30396})` after its Cargo process completed. The server returned expected process-not-found with MCP -32603, followed by 25 internal native stack frames.
- **Observed impact:** A missing/exited process is an expected lifecycle race, not a server discovery defect. Exposing the full internal native backtrace is the reproducible reporting defect; it obscures useful process state and leaks implementation details. No process was terminated.
- **Safe fallback:** Use `list_processes` to verify a process is live before requesting its tree; accept that it can still exit between calls. Treat absent processes as completed; return concise structured process-not-found without internal frames.
- **Additional exact reproduction (2026-10-02, OIDN repair verification):** `mcp__filesystem_mcp_rs__proc_tree({pid:41968})` after `list_processes` reported `cargo test -p oidn-cli --bin oidn-rs --locked --quiet` active for about 367 seconds. The process finished between calls. The server returned `isError:true`, MCP -32603 `Process 41968 not found`, and a full 24-frame internal backtrace including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`. Missing-process rejection is the expected lifecycle result; the backtrace disclosure repeats the server reporting defect. No process was stopped. The safe fallback was a refreshed process inventory and bounded stdout/stderr log reads.

## 2026-10-02 � oversized report write exposes internal backtrace

- **Exact reproduction:** Filesystem MCP `write_file` for BUG_CDX.md with 169053 bytes of inline content returns expected MCP -32602 `inline_too_large` (limit65536), followed by 25 internal native frames. No file change occurs.
- **Observed impact:** Inline size rejection is expected caller validation; internal backtrace disclosure repeats the reporting defect. Existing report entries remain intact.
- **Safe fallback:** Append with a small verified exact tail edit, or use documented blob staging for large replacement content; do not retry the oversized inline payload.

## 2026-10-02 � broad search timeout exposes internal backtrace

- **Exact reproduction:** `mcp__filesystem_mcp_rs__search_files({path:"C:/projects/projects.rust.cg",pattern:"**/recon_tree.rs"})` timed out awaiting tools/call after 300 seconds. Its error response included 25 internal native stack frames, including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`.
- **Observed impact:** A broad recursive query can legitimately exceed the tool deadline; timeout alone is not established as a traversal defect. Returning the full internal backtrace repeats the server reporting defect and obscures the useful timeout diagnostic.
- **Safe fallback:** Bound searches to the known repository and exclude build directories. Reading the exact known path `C:/projects/projects.rust.cg/cglibs/colmap-rs/crates/colmap-ui/src/panels/recon_tree.rs` succeeded immediately. Return a concise structured timeout with the query scope rather than internal frames.

## 2026-10-02 � unmatched edit exposes internal native backtrace

- **Exact reproduction:** `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/frac-rs/src/world.rs` with seven literal edits where edit #7 expected `scene.environment = serde_json::from_value(v["environment"].clone())\n                .map_err(|e| e.to_string())?;` but the current code wraps after the equals sign. The server correctly rejects atomically with `Failed to apply edits: 1 of 7 edits produced zero matches`, then exposes 25 internal frames including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`.
- **Observed impact:** A stale literal is an expected caller error; no source changes were applied. Returning a full internal native backtrace is the reproducible server reporting defect and obscures the actionable mismatch diagnostic.
- **Safe fallback:** Re-read the exact current lines and submit matching, bounded edits. Return the concise structured unmatched-edit diagnostic without native stack frames.

## 2026-10-02 � expected PowerShell token rejection exposes native backtrace

- **Exact reproduction:** `mcp__filesystem_mcp_rs__run_command({command:"powershell",args:["-NoProfile","-Command","Get-Process | Where-Object { $_.ProcessName -match 'frac|cargo|oxide' } | Select-Object Id,ProcessName,CPU,StartTime | ConvertTo-Json -Compress"],streamOutput:false})` returns MCP -32602 with the documented guard diagnostic for `$_`, followed by 25 internal native stack frames including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`.
- **Observed impact:** Rejecting the unsupported inline PowerShell token is expected caller validation. Exposing the full native backtrace is a server reporting defect; it obscures the useful fallback guidance. No process operation ran.
- **Safe fallback:** Use PowerShell `-Command -` with an inline stdin ContentRef or use a command without `$_` (for example `Get-Process -Name *frac*,*cargo*,*oxide*`). Return only the concise structured validation error.

## 2026-10-02 � long managed build transport timeout exposes native backtrace

- **Exact reproduction:** `mcp__filesystem_mcp_rs__run_command({command:"python",args:["-B","-c","import bootstrap, sys; sys.exit(bootstrap.run(['cargo','oxide','test','--','--release','--','--test-threads=1'])[0])"],cwd:"C:/projects/projects.rust.cg/cglibs/frac-rs",mode:"managed",timeoutMs:1200000,stdoutFile:"C:/projects/projects.rust.cg/cglibs/frac-rs/target/oidn-tests.out",stderrFile:"C:/projects/projects.rust.cg/cglibs/frac-rs/target/oidn-tests.err"})` returned `timed out awaiting tools/call after 300s` plus 25 internal native stack frames. Cargo completed compilation in 4m52s and had started tests when the transport timed out.
- **Observed impact:** The client transport deadline can legitimately precede the requested process deadline; this does not prove a process-timeout defect. Exposing internal native frames is the reporting defect. The tool reply gives no trustworthy final exit status, so test completion must be checked independently.
- **Safe fallback:** Read captured logs and refresh the process inventory before retrying; use detached mode with explicit completion logs for commands likely to exceed the transport deadline, or retry cached verification after confirming no owned build remains. Return a concise timeout diagnostic without internal stack frames.

## 2026-10-03 � unmatched widget edit exposes internal native backtrace

- **Exact reproduction:** `mcp__filesystem_mcp_rs__edit_file({path:"C:/projects/projects.rust.cg/cglibs/frac-rs/target/verification/attribute-layout/worktrees/egui-widgets-rs/crates/egui-attr-table/src/widget.rs",edits:[{oldText:"        self.emit",newText:"        self.emit",replaceAll:false}]})` returns expected atomic rejection `1 of 1 edits produced zero matches`, followed by 24 native frames including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`.
- **Observed impact:** The unmatched literal is a caller error and no edit applies. Exposing an internal native backtrace is the server reporting defect; it obscures the useful current-content diagnostic.
- **Safe fallback:** Re-read the file and submit only a matching bounded edit. For large-report appends, replace the verified final line with itself plus the new entry; preserve preceding content. Return the structured unmatched-edit message without native frames.
- **Additional reproduction (2026-10-03, frac UI geometry):** `edit_file` on `C:/projects/projects.rust.cg/cglibs/frac-rs/src/world_ui.rs` with two edits, the second expecting a multiline `section\n                .state\n                .table\n                .widths\n                .push(state.attribute_label_width);` while rustfmt had made it a single line. Atomic rejection correctly reported `1 of 2 edits produced zero matches`; the response then exposed 25 internal native frames including the aws_lc symbol, BaseThreadInitThunk and RtlUserThreadStart. A stale literal is caller error; backtrace disclosure is the repeated server reporting defect. Re-reading current matches and applying bounded exact edits succeeded; no partial source mutation occurred.

## 2026-10-03 � missing profiler command exposes internal native backtrace

- **Exact reproduction:** `mcp__filesystem_mcp_rs__run_command({command:"ncu",args:["--help"],mode:"sync",timeoutMs:10000,stdoutFile:"C:/projects/projects.rust.cg/cglibs/frac-rs/target/verification/ncu-help.stdout.log",stderrFile:"C:/projects/projects.rust.cg/cglibs/frac-rs/target/verification/ncu-help.stderr.log"})` returns MCP -32603 `Failed to spawn command ncu` with a full internal native backtrace including an aws_lc symbol and BaseThreadInitThunk.
- **Observed impact:** An unavailable command in the server PATH is an expected environment/caller error. Exposing native internal frames is the server reporting defect. No GPU profiling ran.
- **Safe fallback:** Resolve the command first and use the verified absolute launcher `C:/Program Files/NVIDIA Corporation/Nsight Compute 2026.3.1/ncu.bat`. The absolute launcher successfully returned version 2026.3.1.0 and help. Return a concise structured spawn error without native frames.

## 2026-10-03 � edit zero-match diagnostic exposes internal native backtrace

- **Additional reproduction:** `mcp__filesystem_mcp_rs__edit_file` on `rez-rs/tests/cli_integration.rs` with four literal edits rejected edit #4, whose expected formatted worker block differed from the actual source, and exposed 25 internal native frames. Readback confirmed the batch made no changes. The text mismatch is an expected caller error; internal stack disclosure is the server defect. Safe fallback: re-read the exact block, apply verified edits separately, and verify the result.

- **Additional reproduction:** `mcp__filesystem_mcp_rs__edit_file` on `rez-rs/src/cli/repo/cache.rs` expected a multiline `println!` while the current source used a single line. MCP -32603 returned the expected zero-match rejection plus 25 native frames. Exact readback followed by the corrected literal edit succeeded. This was a caller text mismatch; the defect remains internal stack disclosure, not the rejected edit.

- **Exact reproduction:** `mcp__filesystem__edit_file` on `rez-rs/src/resolve/context.rs` with literal `let args = serde_json::from_value::<Vec<String>>(` after rustfmt split the declaration across lines returned MCP -32603 zero-match validation plus 25 native frames including aws_lc and Windows thread symbols.
- **Observed impact:** Stale literal text is an expected caller error. Disclosing a native stack for that validation error is the server reporting defect. The failed batch made no file changes.
- **Safe fallback:** Re-read the exact formatted source and submit verified literal edits; that succeeded. Return concise structured zero-match diagnostics without internal frames.

## 2026-10-03 � invalid process regex exposes native backtrace

- **Exact reproduction:** `mcp__filesystem_mcp_rs__search_processes({name_pattern:"*frac*"})` rejects the glob-shaped pattern with `Invalid name pattern regex` and returns 25 native frames including an aws_lc symbol, BaseThreadInitThunk and RtlUserThreadStart.
- **Observed impact:** Supplying a glob where the tool expects regex is a caller error. Native backtrace disclosure is the server reporting defect. No process was modified.
- **Safe fallback:** Use the verified regex `name_pattern:"frac"`, which successfully returned the process inventory. Return the concise validation diagnostic without native frames.

## 2026-10-03 � unmatched rez shell edit exposes native backtrace

- **Exact reproduction:** `mcp__filesystem__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/shell/types.rs` with two literal edits; edit #2 expected 24-space indentation before `let value = arg.expanduser(None);` while current rustfmt output had 28 spaces. The server rejected atomically with `1 of 2 edits produced zero matches` and returned 25 internal native frames.
- **Observed impact:** The indentation mismatch is an expected caller error. Internal stack disclosure, including the aws_lc entropy symbol and Windows thread entry points, is the server reporting defect. Readback confirmed neither edit applied.
- **Safe fallback:** Re-read exact current lines, then apply matching bounded edits. Return only the structured mismatch diagnostic without native stack frames.

## 2026-10-03 � disk_usage cannot resolve an existing Windows child path

- **Additional reproduction:** `mcp__filesystem_mcp_rs__disk_usage({path:"C:\\projects\\projects.rust.cg\\cglibs\\rez-rs"})` again failed on the confirmed existing workspace path with MCP -32603 and a native backtrace during the current continuation. The immediate `disk_usage({})` fallback succeeded: C: 420.55 GB and D: 25.83 GB free. No cleanup was performed.

- **Exact reproduction:** `mcp__filesystem__disk_usage({path:"C:\\projects\\projects.rust.cg\\cglibs\\rez-rs"})` returns `No disk found for path` plus 25 internal native stack frames. The same path is the working directory of successful reads and commands. `disk_usage({})` immediately returns two NTFS mounts, including `C:\\`.
- **Observed impact:** The optional existing-path query fails despite an available containing disk, preventing direct free-space checks; full internal backtrace disclosure compounds the diagnostic failure. This is distinct from a nonexistent user path.
- **Safe fallback:** Query all disks without a path, select the verified containing mount, or obtain `shutil.disk_usage` through filesystem MCP run_command. Preserve existing files and return a concise structured resolution error without native frames.





## 2026-10-03: run_command expected dollar-token rejection exposes internal stack trace

Reproduction: filesystem run_command(command="python", args=["-c", "print('$KNOWN')"]) returns MCP -32602 validation rejection because dollar tokens must use stdin ContentRef. The validation rejection is expected; the appended 24-frame native Stack backtrace is a server defect. Observed twice during a read-only Rez shell audit. Impact: noisy internal diagnostics for ordinary invalid input. Safe fallback: run_command(command="python", args=["-"], stdin={kind:"inline",text:script}) avoids dollar-token argument expansion and preserves the script. Existing entries retained.

## 2026-10-03 � exited process lookup exposes internal native backtrace

- **Exact reproduction:** `mcp__filesystem__proc_tree({pid:43296})` after an owned Cargo wrapper exited returned MCP -32603 `Process 43296 not found` followed by 25 native frames, including aws_lc entropy and Windows thread entry points.
- **Observed impact:** Looking up an exited PID is an expected process-lifecycle/caller condition. The server defect is native backtrace disclosure for that ordinary lookup miss; no process was changed.
- **Safe fallback:** Read the wrapper's final stdout/stderr logs; if necessary, use a bounded read-only native process query through filesystem run_command. Return a concise structured not-found response without native frames.

## 2026-10-03 � Windows disk root lookup fails and exposes internal native backtrace

- **Exact reproduction:** `mcp__filesystem_mcp_rs__disk_usage({path:"C:\\"})` and the same request for `D:\\` each returned MCP -32603 `No disk found for path` followed by 25 internal native frames.
- **Observed impact:** Both drive roots exist; read-only Python `shutil.disk_usage('C:/')` and `shutil.disk_usage('D:/')` succeeded immediately through filesystem run_command (receipt `run_command_1791059292514_414875e2-0b24-4e6c-98a9-14db00ce12f0`). Root-path disk selection failed, and native backtrace disclosure is a separate reporting defect. No files or processes were modified.
- **Safe fallback:** Query `shutil.disk_usage` through filesystem run_command and return only bounded free/total space values; preserve the existing logs and avoid destructive cleanup based on a failed space query.

## 2026-10-03 � ordinary edit no-match exposes internal native backtrace

- **Exact reproduction:** `mcp__filesystem_mcp_rs__edit_file` on `frac-rs/Cargo.toml` with two edits: replace revision `6b1c6c7d53522b696f859af400e0b141aaab2ba5` with `00d90428d6c931b69b7117fd2a4cdf143d075413`, then match the new revision in the playa-engine dependency line. The server matches both edits against the original content; the second edit correctly reports zero matches, but returns MCP -32603 with 25 internal native stack frames (aws_lc entropy and Windows thread entries).
- **Observed impact:** The no-match is an expected caller error, not a mutation defect; rereading confirmed the file remained unchanged. Native backtrace disclosure for the ordinary edit error is the server defect and adds noisy internal diagnostics.
- **Safe fallback:** Re-read the file, match independent anchors from the original content or issue dependent edits sequentially. Return a concise structured no-match error without native frames; preserve existing report entries.

## 2026-10-03 � empty-directory delete validation exposes native backtrace

- **Exact reproduction (root-observed, not rerun):** `delete_path({path:"C:/projects/projects.rust.cg/cglibs/frac-rs/__pycache__",recursive:false})` on a known empty task-generated directory returned MCP -32602 `Refusing to delete directory without recursive=true`, followed by 25 native `Stack backtrace` frames including aws_lc and Windows thread entry points.
- **Observed impact:** Refusing a directory deletion without `recursive:true` is expected caller validation; the directory remained intact. Exposing the full native backtrace is the server reporting defect, not the refusal. The root had removed only its known generated `bootstrap.pyc` before checking the empty directory.
- **Verified safe fallback:** `list_directory` confirmed the directory was empty, and its resolved absolute path was verified inside the intended workspace. The root then successfully called `delete_path` with `recursive:true`. Do not reproduce the deletion or remove other files to investigate this report. Return concise structured validation diagnostics without internal frames.

## 2026-10-03 � PowerShell variable guard exposes native backtrace

- **Exact reproduction:** `run_command` with `command:"powershell"`, `args:["-NoProfile","-Command","Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'cargo|rustc|rustfmt|WarpBro|frac-rs|python|ncu|llc|clang|link' } | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json -Depth 3"]`. The request returned MCP -32602 explaining that command/args contain `$_`, followed by 25 internal native stack frames.
- **Observed impact:** Rejecting a script susceptible to MCP token expansion is expected validation; no command was spawned. The server defect is exposing the internal native backtrace for that expected validation failure.
- **Verified safe fallback:** Run `powershell -NoProfile -Command -` and pass the identical script via `stdin:{kind:"inline",text:script}`. The read-only process inventory then succeeded. Return concise validation diagnostics without native frames; preserve existing entries.




## 2026-10-03 � invalid memory UUID exposes internal stack trace

- **Exact reproduction (planner/root-observed; invalid request not rerun):** `mcp__filesystem__mem_get({workspaceId:"rez-rs",actorId:"native_builder_plan",ids:["dcaf20eb"]})` was observed around `2026-10-03T23:50Z` returning `Invalid ids[] UUID invalid length8`, followed by a 24-line internal `Stack backtrace` ending in `BaseThreadInitThunk` / `RtlUserThreadStart`. Evidence is the planner's actual MCP response; there is no shell receipt.
- **Observed impact:** The shortened identifier is an expected caller validation error: `mem_get` requires a full UUID. The server defect is disclosure of the internal stack trace for that ordinary input error, not rejection of the identifier. This adds noisy internal diagnostics; no memory mutation was requested.
- **Verified safe fallback:** Use `dcaf20eb-31de-48be-a779-81d7c6bfa881` with the same workspace/actor. The documentation agent's read returned `Retrieved 1 items` and the expected staging-review record. If the full identifier is unknown, use scoped `mem_search` first. Return a concise structured UUID-validation error without internal frames. Existing report entries are preserved.

## 2026-10-04 UTC � process-memory PowerShell validation exposes native stack

- **Exact reproduction (root-observed once; not rerun):** `run_command({command:"powershell",args:["-NoProfile","-Command","Get-Process -Name cargo,rustc,link -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,CPU,@{Name='WorkingSetMB';Expression={[math]::Round($_.WorkingSet64/1MB)}} | ConvertTo-Json -Compress"],cwd:"C:/projects/projects.rust.cg/cglibs/rez-rs",stdoutTail:5,stderrTail:3})` rejects inline `$_` because of host variable-expansion risk, then returns a full 25-frame internal native stack including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk` and `RtlUserThreadStart`.
- **Observed impact:** Rejection of the inline token is expected caller validation; no process-inspection command executes. The server defect is exposing internal native frames for that validation failure. This is another concrete occurrence of the previously recorded PowerShell variable-guard reporting defect; existing entries remain intact.
- **Safe fallback:** Use `run_command` with `command:"powershell"`, `args:["-NoProfile","-Command","-"]`, and the identical PowerShell script in `stdin:{kind:"inline",text:script}`. The root is using this ContentRef path. Return concise structured validation diagnostics without native frames; do not repeat the invalid request or modify processes to reproduce it.

## 2026-10-04 UTC � Rez copy-fixture no-match exposes native stack

- **Exact reproduction (runtime_fixture_repair-observed around 00:50 UTC; not rerun):** `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/rez-rs/src/package/ops.rs`, a four-edit batch, reports zero matches for edit 2. Its `oldText` was `format!("name: {}\\nversion: {}\\n", name, version)\n        )\n        .expect("write package.yaml");\n\n        // Variant 0: platform-linux`; `newText` added quoted version, `hashed_variants: false` and explicit Linux/Windows variants. The caller omitted the existing comma after `format!` in the old selector.
- **Observed impact:** The no-match is expected caller validation, and readback confirmed no batch edits occurred. The server defect is the accompanying 25-frame native `Stack backtrace`, including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk` and `RtlUserThreadStart`. This is another exact occurrence of the existing edit no-match reporting defect.
- **Verified safe fallback:** Read the actual source, use unique surrounding context including its existing comma, then edit and verify the result. The agent's corrected selector succeeded. A separate duplicate-selector ambiguity was not established as a server defect and is not included in this finding. Preserve all prior entries; return a concise no-match diagnostic without internal frames.

## 2026-10-04 UTC � Nsight BAT launcher spawn failure exposes native stack

- **Exact reproduction:** `run_command({command:"ncu",args:["--version"],cwd:"C:/projects/projects.rust.cg/cglibs/frac-rs",stdoutTail:8})` resolves the installed Nsight `ncu.BAT` and returns MCP -32603, `Failed to spawn command: ncu`, with 25 native stack frames including aws_lc, BaseThreadInitThunk and RtlUserThreadStart.
- **Observed impact:** Directly spawning a BAT wrapper without a shell is an expected launcher limitation; exposing the internal native backtrace is the server defect. Profiling did not start.
- **Verified safe fallback:** Invoke `C:/Program Files/NVIDIA Corporation/Nsight Compute 2026.3.1/target/windows-desktop-win7-x64/ncu.exe` directly. The identical `--version` request succeeded with exit 0 and version 2026.3.1.0. Return a concise structured spawn diagnostic, preserving existing report entries.

## 2026-10-04 UTC � WarpBro stale selector no-match exposes native stack

- **Exact reproduction:** `edit_file` on `C:/projects/projects.rust.cg/cglibs/frac-rs/src/render_bench.rs` with three literal edits; edit 2 expected `.unwrap_or("world-bench");` followed by dimensions and `let mut position = 3usize;`. The actual parser had already been corrected to a conditional position. MCP -32603 reported edit 2 zero matches followed by 25 native frames including aws_lc, BaseThreadInitThunk and RtlUserThreadStart.
- **Observed impact:** The stale selector is an expected caller error; readback confirmed the original parser remained intact. The defect is native internal stack disclosure, another occurrence of the existing no-match reporting issue.
- **Safe fallback:** Reread the actual source and apply only necessary uniquely anchored edits. The parser fix was already present, so abandon that redundant edit; return a concise structured no-match diagnostic. Preserve prior report entries.


## 2026-10-03 � OFX runtime edit selector mismatch exposes native stack

- **Exact reproduction:** `mcp__filesystem_mcp_rs__edit_file({path:"C:/projects/projects.rust.cg/cglibs/ofx-rs/crates/ofx-runtime/src/effect.rs",edits:[{oldText:"    /// Interactive (a viewer frame an edit may abort) or Export (must finish, waited for by edits).\n    /// Request draft",newText:"    /// Request draft"}]})` while the file has a field declaration between those comments. The server returned MCP -32603, "1 of 1 edits produced zero matches", followed by 25 internal native stack frames, including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk` and `RtlUserThreadStart`.
- **Observed impact:** The inaccurate selector is an expected caller error. The server defect is disclosing the full internal backtrace for a routine no-match validation error. No edit was applied.
- **Verified safe fallback:** Reread the actual lines, target the unique adjacent `/// The same render of class` comment at the draft builder, and move that comment to the proper class builder. The corrected two-edit request succeeded. Return only a concise structured selector-mismatch diagnostic. Existing report entries are preserved.



## 2026-10-03 � run_command variable guard exposes internal stack

- **Exact reproduction:** `run_command` with command `powershell`, args `[-NoProfile, -Command, "Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'cargo|rustc|python' } | Select-Object ProcessId,ParentProcessId,Name,CommandLine | Format-List"]`, cwd `C:/projects/projects.rust.cg/cglibs/frac-rs`, mode `sync`. Returned MCP -32602 rejecting the `$_` token, followed by 25 native stack frames including aws_lc, BaseThreadInitThunk and RtlUserThreadStart.
- **Observed impact:** Rejecting the unsupported variable token is an expected validation guard. Exposing a full internal stack for that validation is a server defect. No shell was launched.
- **Safe fallback:** Use a variable-free command (`Get-Process cargo,rustc,python -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,CPU`) or place the script in a file and invoke `powershell -File` as advised. The variable-free command returned the running process inventory. Return a concise validation diagnostic without native frames; preserve existing report entries.

## 2026-10-03 � CUDA regeneration edit no-match exposes native stack

- **Exact reproduction:** `edit_file` on `C:/projects/projects.rust.cg/cglibs/ofx-rs/fx/ofx-fractal/kernels/regenerate.py` with four literal edits: model tuple fast/full to fast/full/direct; `oldText:"_PARAMS\\\\[840\\\\]"` to 872; 210-float to 218-float; parameter_floats210 to218. Edit2 incorrectly contained doubled backslashes, whereas the Python source regex uses one per bracket. MCP -32603 returned zero matches for edit2 followed by 25 native stack frames including aws_lc, BaseThreadInitThunk and RtlUserThreadStart.
- **Observed impact:** Rejecting the inaccurate literal selector is expected caller validation and no batch edit occurred. The defect is exposing the internal native stack for that ordinary validation failure.
- **Verified safe fallback:** Reread the source, use the unique literal `840` to `872` alongside the other three edits, then verify the diff. The corrected request succeeded. Preserve earlier entries and return concise structured no-match diagnostics without internal frames.

## 2026-10-03 � missing copy source exposes internal stack

- **Exact reproduction:** `copy_file({source:"C:/projects/projects.rust.cg/cglibs/ofx-rs/target/release/ofx_effects_bundle.dll",destination:"C:/projects/projects.rust.cg/cglibs/ofx-rs/target/ofx-effects-before-cuda.dll",overwrite:false})` returned MCP -32603, `Failed to stat source` / OS error 3, followed by 25 native frames including aws_lc, BaseThreadInitThunk and RtlUserThreadStart.
- **Observed impact:** The nonexistent source is an expected caller path error. The server defect is disclosure of the internal stack for that ordinary error; no file was copied.
- **Safe fallback:** Verify the actual build artifact location with get_file_info or the build output before copying; abandon the copy if no earlier artifact exists. Return a concise structured missing-source error without native frames. Preserve all prior entries.

## 2026-10-03 � nonexistent command working directory exposes internal stack

- **Exact reproduction:** `run_command({command:"git",args:["status","--short","--branch"],cwd:"C:/projects/projects.rust.cg/cgprojs/playa",mode:"sync",timeoutMs:10000})` returned MCP -32603, "Working directory does not exist", followed by 25 native frames including aws_lc, BaseThreadInitThunk, and RtlUserThreadStart.
- **Observed impact:** The wrong working directory is an expected caller path error. Disclosing the internal stack for that error is a server defect; Git was not launched there.
- **Verified safe fallback:** `list_directory` under `C:/projects/projects.rust.cg/cglibs` identified the actual `C:/projects/projects.rust.cg/cglibs/playa` repository. The identical Git status command succeeded at that verified path. Return a concise structured working-directory diagnostic without native frames; preserve all existing entries.



## 2026-10-04 � long run_command exceeds MCP 300-second call deadline

- Exact reproduction: run_command(command="cargo", args=["test","-p","ofx-gen","-p","ofx-fractal","-p","ofx-flare","-p","ofx-noise","-p","ofx-density","-p","ofx-sim","-p","ofx-warp","-p","ofx-effects","--all-features"], cwd="C:/projects/projects.rust.cg/cglibs/ofx-rs", timeoutMs=1800000, stdoutTail=5000, stderrTail=3000), default mode. The MCP call failed after 300s with "timed out awaiting tools/call after 300s" and 25 native stack frames. Cargo continued and its streamed files remained readable.
- Observed impact: requested 30-minute process timeout cannot prevent the shorter transport deadline; caller loses the final exit code although the process continues. Internal stack exposure is unnecessary. This is not a missing-file/user validation error.
- Safe fallback: use detached execution with explicit stdout/stderr paths and a wrapper writing an exit-code file; poll logs/process state through filesystem MCP. For the current call, recovered logs run_command_1791127624988_0a833ba3-ae0a-4e45-9372-bcfa851dedc8_{stdout,stderr}.log and verified the existing process, without launching a duplicate or killing unrelated work.


## 2026-10-04 � locate_search missing-path validation exposes internal stack

- Exact reproduction: locate_search({query:"NatronRenderer.exe",kind:"file",limit:10}); the advertised schema marks path/paths optional. Returned -32602 "path or paths is required" followed by 25 native stack frames.
- Observed impact: missing scope is an expected caller validation error; leaking native internals for it is a server defect. The schema does not encode the required alternative path/paths constraint.
- Second reproduction: with path="C:/Programs" and kind="file", returned -32602 "kind must be all, files, or directories" with the same native stack. Expected invalid-enum caller error, unnecessary stack disclosure; schema advertises a generic string without enum values.
- Safe fallback: supply an explicit path scope and kind="files"; return concise validation diagnostics without the stack. Preserve existing entries.


## 2026-10-05 — edit_file oversized inline validation exposes internal stack

- Exact reproduction: edit_file on C:/projects/projects.rust.cg/cglibs/warpbro-rs/src/render.rs with a literal oldText containing the full 116603-byte file and similarly sized inline newText. Returned -32602 inline_too_large: 116603 bytes exceeds limit of 65536; stage with blob_begin/blob_append/blob_finalize, followed by 25 internal native stack frames including aws_lc, BaseThreadInitThunk and RtlUserThreadStart. Repeated request produced the same stack.
- Observed impact: enforcing the inline payload limit is expected caller validation; the defect is disclosure of the internal stack for that ordinary error. No edits occurred.
- Verified safe fallback: use staged blob/path payloads or smaller literal edits. This formatting restoration succeeded via UTF-8-aware Python through filesystem MCP after asserting only whitespace/trailing commas and the preserved regression differ. Return concise validation diagnostics without native frames. Existing report bytes are preserved.


## 2026-10-06 - disk_usage fails for an existing C: repository and exposes internal stack

- Exact reproduction: filesystem-mcp-rs disk_usage({"path":"C:/projects/projects.rust.cg/cglibs/rez-rs"}) twice returned -32603 "No disk found for path: C:/projects/projects.rust.cg/cglibs/rez-rs" followed by 25 native stack frames, including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart. get_file_info for the identical path succeeds and confirms isDirectory=true. disk_usage({}) returns only "All disks", with no disk data.
- Observed impact: the existing repository is not a missing-path caller error. Disk enumeration/path matching fails to supply capacity for a valid C: path; the full internal stack is an additional server defect. This blocked the preferred free-space probe during a cold rebuild after target cleanup.
- Verified safe fallback: Python shutil.disk_usage('C:/') via filesystem-mcp-rs run_command successfully returns available capacity without modifying any files. Keep the diagnostic concise and structured, normalize valid Windows paths, and preserve existing report entries.
- Additional exact reproduction on 2026-10-06 during ffmpeg-rs F7 resume: `disk_usage({path:"C:/Temp"})`, then `disk_usage({path:"C:\\"})`, each returned -32603 `No disk found for path` followed by 25 native stack frames. The failure affects both an existing directory and the C: drive root; this is the same disk enumeration/path-matching defect, not a missing-path caller error.
- Additional observed impact: the preferred free-space check before F7 build/recording work was unavailable, and each failure exposed the internal native stack.
- Additional verified safe fallback: filesystem-mcp-rs `run_command` with `shell:"pwsh"` and command `Get-PSDrive -Name C | Select-Object Name,Used,Free | Format-List` succeeded. The coordinator observed `Free = 159713538048` bytes at that check; capacity is a point-in-time result, not a reservation.

## 2026-10-06 - oversized edit validation again exposes an internal stack

- Exact reproduction: filesystem-mcp-rs edit_file({"path":"C:/projects/projects.rust.cg/cglibs/alembic-rs/tests/write_tests.rs","edits":[{"oldText":"<133279-byte full-file inline text>","newText":"<same file with three SubD Result unwraps>"}]}) returned -32602 inline_too_large with 25 internal stack frames including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk, and RtlUserThreadStart.
- Observed impact: exceeding the documented 65536-byte inline limit is an expected caller validation error; exposing a native internal stack for that error is the server defect. The file was unchanged by the rejected request.
- Verified safe fallback: three small literal edits applied through filesystem MCP edit_file succeeded. Stage large payloads with blob tools or use bounded edits; return ordinary validation diagnostics without internal frames. Existing entries are preserved.


## 2026-10-06 - oversized write_file validation exposes internal stack

- Exact reproduction: filesystem-mcp-rs write_file({path:"C:/projects/projects.rust.cg/cglibs/alembic-rs/src/material/schema.rs",content:{kind:"inline",text:"<87110-byte complete file with an appended regression module>"}}) returned -32602 inline_too_large (65536-byte limit), followed by 25 native internal stack frames including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart.
- Observed impact: enforcing the documented inline limit is expected caller validation. Disclosing the internal stack for that error is a server defect. The rejected write did not change the file.
- Verified safe fallback: bounded filesystem MCP edit_file with regex oldText "\\z" appended only the 3.3KB new test module successfully. Use bounded edits or staged blob payloads for larger writes; return concise structured validation errors without native frames. Existing entries are preserved.


## 2026-10-06 - concurrent edit no-match exposes internal stack

- Exact reproduction: edit_file on C:/projects/projects.rust.cg/cglibs/alembic-rs/src/ogawa/writer/schema/material.rs with oldText `params.properties = reader.getShaderParameters("r", "surface");` and newText `params.properties = reader.read_shader_params("r", "surface");` after the same correction had been applied by a collaborating agent. Returned -32603 zero matches followed by 25 native frames, including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart.
- Observed impact: the stale literal is an expected caller/concurrency error; the server defect is internal stack disclosure for ordinary validation. The rejected edit changed no source.
- Verified safe fallback: reread the bounded source region and confirm the desired correction is already present; do not retry the stale edit. Return concise structured no-match diagnostics without internal frames. Existing entries are preserved.


## 2026-10-06 - expected missing edit anchor exposes native stack

- Exact reproduction: edit_file on alembic-rs/crates/alembic-python/src/lib.rs used oldText `    m.add_class::<InputProperty>()?;` while the actual binding variable was `module`; the sixth edit had zero matches. The response included -32603 and 25 native stack frames (aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk, RtlUserThreadStart).
- Observed impact: missing literal anchor is an expected caller error, but disclosing native stack frames is a server defect. Atomic rejection preserved the source.
- Safe fallback: reread the bounded module-registration source and retry with the exact `module.add_class` anchor. Return concise no-match errors without stack disclosure.

- Additional reproduction on 2026-10-06 during ffmpeg-rs F7: `mcp__filesystem_mcp_rs__edit_file` targeted `C:/Temp/f7-build-tests.ps1` with a two-edit batch. Edit 1 used `oldText:"$ErrorActionPreference='Stop'"` and `newText:"$ErrorActionPreference='Stop'\n$PSNativeCommandUseErrorActionPreference=$false"`; edit 2 matched `exit $LASTEXITCODE` to add a completion marker (its full replacement body is not retained here). Edit 1 had zero matches because the actual line was `$ErrorActionPreference = 'Stop'`. The coordinator observed -32603 with 25 internal native frames and confirmed by reread that the rejected batch left the file unchanged.
- Additional observed impact: the guessed literal is an expected caller mismatch, and atomic rejection is correct; exposing the full internal stack is the server defect. No script update or execution occurred from the failed edit.
- Additional safe fallback: reread the exact current text and retry the intended bounded edit with its verified anchor. The coordinator performs this retry; return concise no-match diagnostics without internal frames.

- Additional reproduction on 2026-10-06 during the F7 lint documentation checkpoint: `mcp__filesystem_mcp_rs__edit_file({path:"C:/projects/projects.rust.cg/cglibs/ffmpeg-rs/.agents/plan10/HANDOFF.md",edits:<seven literal edits>})` returned `-32603: Failed to apply edits: 2 of 7 edits produced zero matches`. Edit 2 changed `### Current action � env-order fix after the failed content-key build` to `### Current action � fresh full build after reviewed env/lint fixes`; edit 6 incorrectly used that new heading as `oldText` in the same batch, changing it to `### Current action � await the launched reviewed-source build`. Edit 7 likewise anchored the replacement paragraph beginning `Strict Clippy passed. Next: complete fresh runtime validation` produced by an earlier edit. Both anchors were absent in the original file; the server matches the batch against that original text. Its response also exposed 25 native frames including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`.
- Additional observed impact: the dependent-anchor mismatch is expected caller error; atomic rejection was correct. Full rereads confirmed all twelve intended documentation files were unchanged before retry. The internal stack disclosure remains the existing server defect, not a failed-build or source-code defect.
- Additional safe fallback: reread the complete current files, combine dependent replacements into verified original-text anchors, apply the corrected edits, and compare complete readbacks with the exact intended content. This retry succeeded for all twelve documents; no server source/configuration or build was changed.

- Additional expected-edit recurrence (2026-10-07, ffmpeg-rs graph feature wiring; coordinator-supplied observation): `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/cglibs/ffmpeg-rs/crates/av-graph/Cargo.toml` supplied four literal edits. Edit 3 used `oldText` ``# `EncCodec::Av1` IR variant + the `build.rs` parse arm + the `EncodeMuxSink` ``; the actual line began `# no rav1e is fetched. The ...`, so it had zero matches. The response was MCP -32603 with the full native `Stack backtrace` frames 0..24, including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`. Coordinator readback confirmed no file mutation.
- Additional observed impact: a nonmatching literal is an expected caller error and atomic rejection is correct; full internal-stack disclosure is the existing server defect. No build/test or runtime result follows from this edit failure. This entry records the supplied occurrence without repeating it.
- Additional safe fallback: reread the exact current anchor, verify each bounded replacement against the original file, and reapply through filesystem MCP `edit_file`; preserve existing entries and return concise mismatch diagnostics without internal frames.

## 2026-10-06 - managed run_command still exceeds the 300-second MCP call deadline

- Exact reproduction: filesystem-mcp-rs run_command(command="cargo", args=["test","--offline","--workspace","--all-features","--no-fail-fast","--lib","--test","ogawa_streaming_allocations","--test","layer_allocations","--test","hdf5_structure_parity","--test","typed_scalar_defaults_parity","--test","plain_array_extent_parity","--test","typed_property_parity","--test","layer_parity","--test","layer_reader_parity","--test","layer_owned_readers","--","--include-ignored"], cwd="C:/projects/projects.rust.cg/cglibs/alembic-rs", mode="managed", timeoutMs=1200000, stdoutFile="target/stream-focused5.stdout.log", stderrFile="target/stream-focused5.stderr.log", env CARGO_HOME="C:/Temp/alembic-rs-cargo-home-20261006", CARGO_BUILD_JOBS="1", CARGO_INCREMENTAL="0", CARGO_TARGET_DIR="C:/Temp/alembic-rs-full-audit-20261006", ALEMBIC_LAYER_REFERENCE and ALEMBIC_LAYER_REFERENCE_EXE set to repo target/full-reference-hdf/layer_reference.exe). The MCP call returned "timed out awaiting tools/call after 300s" with 25 internal native frames, including aws_lc_0_45_0_jent_entropy_switch_notime_impl.
- Observed impact: the shorter transport deadline loses the final command result even in explicitly managed mode with a 20-minute process timeout. Saved stdout remained empty and stderr contained only compilation lines. Subsequent list_processes for cargo/rustc/link/ogawa_streaming/alembic- each returned count=0; neither success nor a test failure can be inferred. Internal stack disclosure is additional server defect, not a caller path/validation error. This extends the existing 2026-10-04 long-command reproduction to managed mode.
- Safe fallback: verify no matching process remains before restarting; launch a detached wrapper with explicit Cargo stdout/stderr files and a separate exit-code marker, then inspect those files/process state through filesystem MCP. Do not launch a duplicate or kill unrelated processes. Preserve all existing report entries.


- Additional exact reproduction of the existing missing-process stack-disclosure defect (2026-10-06, alembic-rs documentation verification): `mcp__filesystem_mcp_rs__proc_tree({pid:85524})` after the coordinator's own managed Cargo command returned `timedOut:true`, `killed:true`, `exitCode:null` returned MCP -32603 `Process 85524 not found`, followed by 25 native frames including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`. A disappeared terminated process is an expected lifecycle outcome; exposing the native backtrace is the server defect. Impact: noisy internal disclosure during routine owned-process verification; this does not indicate a source or test failure. Safe fallback: preserve the managed command's timeout verdict, infer no test result from compilation-only logs, and use a detached retry with explicit stdout/stderr and an exit marker. Do not kill unrelated processes.
- Scope qualification for the managed-command entry above: `list_processes` inventories detached commands tracked by this filesystem server session; it is not an OS-wide Cargo/child-process inventory. Its empty filtered result cannot prove absence of managed Cargo or Rustup/compiler descendants. Inspect a known owned tree while it exists, or use OS process inspection through filesystem `run_command`, and rely on the explicit completion marker for the retry verdict. Existing entries are preserved.


## 2026-10-06 � unavailable npx command exposes internal stack during Markdown lint

- **Exact reproduction:** `mcp__filesystem_mcp_rs__run_command({command:"npx.cmd",args:["--yes","markdownlint-cli","README.md","PROMPT.md","TODO.md","IDEAS_70.md","plans/20261006-70-extension/plan.md","--disable","MD013","MD033","MD029","MD060"],cwd:"C:/projects/projects.rust.cg/cgprojs/blender_shaders_b",timeoutMs:60000,stdoutTail:20,stderrTail:30})` returns MCP -32603 `Failed to spawn command: npx.cmd` with a 25-frame internal native backtrace including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`. `which({command:"npx.cmd"})` confirms `Command 'npx.cmd' not found in PATH`.
- **Observed impact:** The unavailable executable is an expected caller/environment error, so lint never starts. The server defect is the internal stack disclosure for that routine spawn failure, repeating the existing expected-error diagnostic issue; no document mutation occurs.
- **Verified safe fallback:** Run the same Markdown lint arguments through available `bunx`; `run_command` succeeds with exit 0 and empty stdout/stderr. Check command availability first and return concise structured spawn diagnostics without native frames. Preserve all existing report entries.


- Additional expected-edit recurrence, 2026-10-06, Blender extension docs: edit_file for C:/projects/projects.rust.cg/cgprojs/blender_shaders_b/plans/20261006-70-extension/plan.md supplied four edits, including changing all original unchecked checkbox markers and then matching a checked future-render marker that did not yet exist in original content. The server correctly rejected edit 3 with zero matches and left the plan unchanged, but exposed MCP -32603 plus 24 internal frames (aws_lc, BaseThreadInitThunk, RtlUserThreadStart). This caller edit-dependency mistake is distinct from the stack-disclosure defect. Verified safe fallback: reread the full plan and use independent original anchors plus an explicit checked acceptance block; corrected edit succeeded, and future-render remains unchecked.
- Additional diagnostic recurrence, 2026-10-06: attempting to append that reproduction to BUG_CDX.md with the exact Cyrillic plan anchor in inline newText was rejected as unrepresentable in the file's original windows-1252 encoding, with MCP -32603 and 25 internal native frames. Refusing an incompatible encoding write is expected and preserved existing bytes; the internal backtrace disclosure is the defect. Safe fallback: record the same reproduction in ASCII without transcoding or rewriting the existing report. Preserve all existing entries and return concise edit/encoding diagnostics without native frames.


- Additional expected-edit recurrence (2026-10-07, OFX documentation): edit_file on C:/projects/projects.rust.cg/cglibs/ofx-rs/docs/plan0.md supplied 13 literal edits. Edit 2 anchored `  The migration is\n  complete in code. Native application comparison remains item **4.6**;`, while the original had `The migration is` at the end of the descriptor-span paragraph. The server correctly rejected the zero-match batch atomically but exposed MCP -32603 and 25 native stack frames including aws_lc, BaseThreadInitThunk and RtlUserThreadStart. The no-match is an expected caller error; the internal stack disclosure is the server defect. Readback confirmed the file unchanged. Safe fallback: use exact reread anchors, verify every replacement locally against the original, retry bounded edits, and preserve prior entries.

- Additional expected-regex recurrence (2026-10-07, Playa Markdown lint): edit_file on C:/projects/projects.rust.cg/cglibs/playa/CHANGELOG.md used regex oldText `^(### [^\\n]+)\\n(?=- )`, isRegex:true, replaceAll:true. The default regex engine correctly rejected unsupported look-ahead but exposed MCP -32603 and 25 native stack frames. Invalid regex is an expected caller error; stack disclosure is the existing server defect. The batch left the file unchanged. Safe fallback: derive exact literal heading anchors from the full read and apply those verified replacements; preserve existing entries.


## 2026-10-07 - expected PowerShell token rejection again discloses internal stack

- **Exact reproduction (coordinator-supplied observation):** filesystem-mcp-rs `run_command({command:"powershell.exe",args:["-NoProfile","-NonInteractive","-Command","Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'gitnexus|filesystem|codex' } | Select-Object ProcessId,ParentProcessId,Name,CommandLine | ConvertTo-Json -Depth3"]})` returned MCP -32602 rejecting the `$_` token in command arguments, followed by a full native internal stack including aws_lc frames.
- **Observed impact:** The token rejection is expected argument validation and the script did not execute. Exposing internal native frames for that ordinary rejection is the recurring server defect; it is not evidence of a failed process inventory script or GitNexus database defect.
- **Verified safe fallback (coordinator receipt):** pass the identical script as stdin `ContentRef {kind:"inline",text:script}`, with PowerShell arguments `["-NoProfile","-NonInteractive","-Command","-"]`. This executed successfully. The documentation agent records the supplied reproduction without repeating the rejected call or touching processes; existing entries are preserved.

- Additional observed content mutation (2026-10-07): the documentation agent appended the reproduction above with edit_file oldText regex \\z, isRegex:true and inline newText containing the literal PowerShell variable dollar-sign underscore. Full readback showed that variable missing twice: Where-Object stored `{ .Name -match ... }` and the quoted rejected-token field was empty. The tool returned success. All prior report content remained identical. This is an observed exact-diagnostic mutation beyond the expected run_command validation; its host/server source is not established. Safe fallback: replace only the newly added reproduction paragraph using a base64 ContentRef and verify the exact literal by full readback. No rejected shell command was repeated and no process was touched.


## 2026-10-07 - stale OFX pump edit anchor exposes native stack

- **Exact reproduction (agent-supplied observation):** `edit_file` on `C:/projects/projects.rust.cg/cglibs/ofx-rs/crates/ofx-host-egui/src/pump.rs` with three literal edits included stale multiline `oldText` `self.blocked.clear();\n        if self.pen_owner` after rustfmt. The server reported a zero-match edit through MCP -32603, followed by 25 native frames including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk` and `RtlUserThreadStart`.
- **Observed impact:** The stale pattern is an expected caller error. The atomic batch left source unchanged; returning the full internal native backtrace is the recurring server defect. This record preserves the supplied observation without repeating the failing edit.
- **Safe fallback:** Re-read the exact current source, verify each original literal anchor, and edit the bounded block with matching text. Preserve prior report entries and return concise mismatch diagnostics without native frames.


## 2026-10-07 - detached command log paths absent after completion

- **Exact reproduction:** `run_command({command:"python",args:["scripts/standard_matrix.py","--plan"],cwd:"C:/projects/projects.rust.cg/cglibs/ofx-rs/",mode:"detached",timeoutMs:900000,stdoutFile:"C:/projects/projects.rust.cg/cglibs/ofx-rs/tmp/docs_standard_matrix_stdout.log",stderrFile:"C:/projects/projects.rust.cg/cglibs/ofx-rs/tmp/docs_standard_matrix_stderr.log",stdoutTail:12,stderrTail:12})` returned started PID 78456 with those log paths. `list_processes({filter:"python"})` showed the command running at 36 seconds, then no tracked command after completion. Both promised paths returned structured `not_found` before and after completion, while docs/STANDARD_MATRIX.md had been regenerated (219 implemented rows, zero listed gaps).
- **Observed impact:** The requested detached log files were unavailable, so this call supplied no final exit status or diagnostics. Reading missing files returns an expected concise error; the observed defect is the command result advertising unavailable output artifacts. Generated documents alone establish their contents, not a complete successful CLI exit.
- **Safe fallback:** Run the serialized checker through a PowerShell stdin script that redirects the child process output itself to a known file and writes a separate explicit exit marker. Inspect both artifacts; do not infer a successful gate from the absence of a tracked process. Preserve existing entries.

- Fallback qualification for the detached-log entry above: the PowerShell stdin detached attempt also left its direct output/exit files absent and yielded no completion receipt. That attempt is not verified. A serialized synchronous Python checker with functions-level yielding returned actual completion after 38.248 seconds and exit 1 (`stale: docs/STANDARD_MATRIX.md` after concurrent source changes). Prefer that verified diagnostic path or a prewritten script invoked by file; an absent artifact cannot be treated as a passed check.

## 2026-10-07 - render-profile edit mismatch discloses native stack

- **Exact reproduction:** `mcp__filesystem__edit_file` on `C:/projects/projects.rust.cg/cglibs/warpbro-rs/src/world.rs` with a literal edit whose `oldText` is `        let settings = editor\n        .document` and identical `newText`, in a ten-edit batch. The actual file has no such anchor. The server returned MCP -32603, "1 of 10 edits produced zero matches", and a full 25-frame native backtrace including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`.
- **Observed impact:** The unmatched literal is an expected caller error; disclosing internal native frames for it is the server defect. Verified readback showed the batch was atomic and did not apply the other nine edits.
- **Safe fallback:** Re-read current source, remove the erroneous literal, apply the nine verified edits, and verify the returned diff/readback. This corrected batch succeeded. Preserve concise mismatch diagnostics without internal stack frames.

- Additional exact reproduction from the UI agent in this same session: `edit_file` on `C:/projects/projects.rust.cg/cglibs/warpbro-rs/src/render_profiles_ui.rs` with a seven-edit batch whose final literal anchor was `        }\n    });\n    if role != before && let Some(role) = role {`. After rustfmt, the `&&` continuation had moved onto another line. Expected zero-match rejection again returned the full native stack (frames 0�24, including the same aws_lc symbol). Atomic no-change readback was confirmed; re-reading the exact anchor and retrying succeeded.

- Additional exact reproduction (2026-10-07, render-profile documentation): edit_file on C:/projects/projects.rust.cg/cglibs/warpbro-rs/docs/render-profiles.md used five literal edits; edit 3 expected the intermediate string "Render & Viewport & Viewport", absent from original content. The atomic batch correctly rejected that dependent anchor with zero matches, but returned MCP -32603 plus 25 internal native frames (aws_lc, BaseThreadInitThunk, RtlUserThreadStart). The missing anchor is expected caller error; native stack disclosure is the recurring server defect. Readback confirmed no mutation. Safe fallback: match each edit against original file content, remove dependent overlapping replacements, and retry verified independent anchors. The corrected three-edit batch succeeded. Existing entries preserved.


- Additional exact reproduction (2026-10-07, simulation CUDA unload): edit_file on C:/projects/projects.rust.cg/cglibs/ofx-rs/crates/ofx-effects/src/sim/physarum.rs and reaction_diffusion.rs used literal oldText `fn unload(&mut self, _suites: &Suites) -> Result<()> {\n        self.suites = None;`. The actual blocks also reset parametric_available first. Both correctly reported zero matches but exposed MCP -32603 plus the full native frames 0-24 (aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk, RtlUserThreadStart). The stale literal is expected caller error; disclosing internal stack frames is the recurring server defect. No edits applied on either mismatch. Safe fallback: re-read current blocks, anchor the actual first parametric_available statement, apply the bounded edit and verify readback. The corrected two edits succeeded. Existing entries preserved.


- Additional exact reproduction (2026-10-07, procedural CUDA cancellation tests): `edit_file` on `C:/projects/projects.rust.cg/cglibs/ofx-rs/crates/ofx-noise/src/tests.rs` and `src/caustics/tests.rs` submitted both literal anchors `let abort = || polls.fetch_add(1, Ordering::Relaxed) >= 15;` and the same line with threshold `25` to each file. Each file contains only its own threshold, so atomic zero-match rejection was expected. Both failures exposed MCP -32603 and all 25 native frames including the aws_lc symbol, BaseThreadInitThunk and RtlUserThreadStart. The caller's mismatched batch is not a server defect; native stack disclosure is the existing defect. No batch edits applied. Safe fallback: read each file and submit only its existing literal; both corrected single-anchor edits succeeded and rustfmt passed. Existing entries preserved.

- Same recurrence during the 2026-10-07 CUDA lint fix: edit_file on ofx-rs/crates/ofx-sim/src/fluid.rs expected the literal doc comment `/// Uniform block: cells x/y, boundary, active emitters, four offsets (in words), then frame constants and the`, while the actual comment began `/// The uniform block of fluid.wgsl for one pass of frame`. Expected atomic zero-match failure again returned the same full 25-frame native stack. Corrected exact current anchor succeeded; no source change on mismatch. Safe fallback remains verify readback before matching and return concise validation errors.

- Additional exact reproduction (2026-10-07, 2D CUDA chunk limit): edit_file on ofx-rs/crates/ofx-fractal/src/cuda2d.rs expected single-line width.checked_mul(chunk_rows).ok_or(RenderError::WorkLimit) after rustfmt had split it over three lines. Expected atomic zero-match rejection disclosed all native stack frames including aws_lc and Windows thread functions. Safe fallback: re-read the formatted source, match the exact multiline block, verify successful diff. Existing entries preserved.


## 2026-10-07 - disk_usage rejects an existing Windows child path and discloses native stack

- **Exact reproduction:** `disk_usage({path:"C:/Temp"})`, followed by `disk_usage({path:"C:\\Temp"})`, through filesystem-mcp-rs. The same existing directory was successfully used as the working directory of `run_command` and as the root of successful file reads. Both calls returned MCP -32603, `No disk found for path`, and native stack frames 0�24 including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`.
- **Observed impact:** A valid child directory could not be mapped to its C: volume. This is a server defect, rather than reading a nonexistent path; exposing the internal native backtrace is also a defect.
- **Safe fallback:** `disk_usage({})` succeeded and reported both C: and D: mounts with their available bytes. Use this verified all-volume result and choose the appropriate mount; preserve existing entries.


## 2026-10-07 - oversized inline write exposes native stack

- **Exact reproduction:** `mcp__filesystem__write_file` for `C:/projects/projects.rust.cg/cglibs/rez-rs/Cargo.lock` with `content:{kind:"inline",text:<227066-byte UTF-8 lockfile>}`. The server correctly rejected the payload with MCP -32602 `inline_too_large` (limit 65536), but also returned 25 native backtrace frames including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`.
- **Observed impact:** The oversized payload is an expected caller error. Exposing the internal stack is the server defect; the rejected write did not modify the file.
- **Safe fallback:** Stage chunks of at most 64 KiB using `blob_begin`, `blob_append`, `blob_finalize`, then pass `content:{kind:"blob",id}` to `write_file` and verify exact readback. Preserve a concise size-limit error without native frames. Existing entries preserved.


- Additional exact reproduction (2026-10-07, OFX CUDA pool hooks): edit_file on ofx-rs/crates/ofx-cuda/src/driver.rs supplied seven literal edits; edit 5 expected the pre-rustfmt single-line driver(free_sync, operation) call, while rustfmt had expanded it. Atomic zero-match rejection was expected and readback confirmed no edits applied, but MCP -32603 disclosed all native stack frames including aws_lc and Windows thread functions. Stale caller text is not a server defect; native stack disclosure is the recurring server defect. Safe fallback: reread the current block, match independent exact original anchors, apply the corrected batch and verify readback. Existing entries preserved.


## 2026-10-07 � Internal native stack exposed for directory deletion without recursive flag

Reproduction: after `list_directory` confirmed an empty `C:/projects/projects.rust.cg/cglibs/rez-rs/_ref`, call filesystem `delete_path` with `{"path":"C:/projects/projects.rust.cg/cglibs/rez-rs/_ref"}` and omit `recursive`. The server returns expected invalid-argument -32602 (`Refusing to delete directory without recursive=true`) followed by a 25-frame internal native stack including aws_lc and Windows thread entry points.

Impact: the missing recursive flag is caller error; disclosing the internal stack for this expected validation failure is the server defect. No deletion occurred.

Safe fallback: verify the resolved target remains inside the intended workspace, list its contents, then call `delete_path` with the exact path and `recursive:true`. The confirmed empty directory was deleted successfully.


## 2026-10-07 � Internal stack disclosure on OS sharing violation during directory rename

Reproduction: `move_file({source:"C:/projects/projects.rust.cg/cglibs/rez-rs",destination:"C:/projects/projects.rust.cg/cglibs/old.rez-rs"})` while another process holds the workspace directory. Expected OS error 32 (file in use) is returned with a 25-frame native stack. A subsequent destination-exists validation rejection also exposed the same stack. Directory locking/destination collision are expected conditions; internal stack disclosure is the server defect. No rename occurred.

Safe fallback: do not continue dependent mutations after a failed move. Preserve the existing directory handle; move verified direct child entries using native PowerShell within the checked sibling workspace paths, retain the old Git directory, and copy the already byte-verified clean snapshot into the original directory.


Additional reproduction on 2026-10-07: `run_command` rejects PowerShell script text in command arguments containing `$ErrorActionPreference` with the expected recommendation to use a stdin ContentRef or script file, but exposes the same 25-frame native stack. The safety rejection is expected; stack disclosure is the server defect. Passing the same script via inline stdin to `powershell -NoProfile -Command -` succeeds safely.

Additional reproduction on 2026-10-07 (OFX chunk formatting): edit_file on
`ofx-rs/crates/ofx-fractal/src/cuda2d.rs` with literal oldText
`\n\n                    // SAFETY:` had no match because the current comment block
contained intervening text. The expected atomic zero-match caller error disclosed
25 internal native frames. No mutation occurred. Stale/missing caller text is not
a server defect; native stack disclosure is the recurring defect. Safe fallback:
reread each current block, verify its exact anchor before issuing an edit, then
verify the changed file. Existing entries preserved.

Additional exact reproduction (2026-10-07, far-rs size-sort acceptance setup): `run_command` with `command:"powershell.exe"`, `args:["-NoProfile","-NonInteractive","-Command",<script below>]`, `cwd:"C:/Temp/far-c1c-verify-tree"`, `mode:"sync"`, `timeoutMs:10000` rejected the script before spawn:

```powershell
$caseRoot = Join-Path 'C:\Temp' ('far-size-scene-' + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $caseRoot, (Join-Path $caseRoot 'a_small'), (Join-Path $caseRoot 'z_large') | Out-Null; [IO.File]::WriteAllBytes((Join-Path $caseRoot 'a_small\a.bin'), [byte[]](1..8)); [IO.File]::WriteAllBytes((Join-Path $caseRoot 'z_large\z.bin'), [byte[]](1..64)); [IO.File]::WriteAllBytes((Join-Path $caseRoot 'm.bin'), [byte[]](1..3)); Write-Output $caseRoot
```

The expected -32602 validation explains that command arguments containing `$caseRoot` may undergo host expansion and recommends stdin ContentRef or a script file. The recurring server defect is disclosure of all 25 internal native frames, including aws_lc, BaseThreadInitThunk and RtlUserThreadStart. No process or fixture was created by the rejected calls. Safe fallback: pass this same script as inline stdin to `powershell.exe -NoProfile -NonInteractive -Command -`; that invocation succeeded, created the isolated acceptance directory, and printed its absolute path. Existing entries preserved.


## 2026-10-07 � ffmpeg-rs edit_file size rejection exposes an internal stack

- Exact reproduction: read ffmpeg-rs `CHANGELOG.md` (200165 UTF-8 bytes), then call edit_file with one edit whose oldText is that complete content and newText replaces the current checkpoint's publication sentence; dryRun is omitted. Server rejects with -32602 inline_too_large (limit65536), including 25 native stack frames (aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk, RtlUserThreadStart).
- Impact: the documented size rejection is expected caller error; disclosure of the full internal stack is the server defect. No changelog mutation occurred in the rejected call.
- Safe fallback: apply a small exact original-text anchor within the inline limit, then read back the updated checkpoint. Existing report entries are preserved.

Additional exact reproduction (2026-10-07, OFX native CUDA pool source): filesystem-mcp-rs
write_file for `ofx-rs/crates/ofx/src/cuda_ofx.rs` with an inline 111654-byte UTF-8
payload correctly rejected the documented 65536-byte limit, but disclosed 25 native
stack frames. The size error is expected caller error; internal stack disclosure is
the server defect. No write occurred. Safe fallback: blob_begin, blob_append chunks
under 40 KiB, blob_finalize and write_file with a blob reference; that write succeeded
and source readback was verified. Existing report entries are preserved.

Additional exact reproduction (2026-10-07, far-rs common queued admission source): `write_file({path:"C:/Temp/far-c1c-verify-tree/crates/far-sys/src/task.rs",content:{kind:"inline",text:<78339-byte UTF-8 source>}})` correctly refused the documented 65536-byte inline limit, but exposed 25 internal native stack frames. The size rejection is expected caller error; stack disclosure is the server defect. No source write occurred in the rejected call. Safe fallback: `blob_begin({})`, three `blob_append` text chunks of at most 30000 bytes, `blob_finalize`, then `write_file` with `{kind:"blob",id:<returned sha256>}`; the complete 78339-byte source write succeeded. Existing report entries preserved.

Additional exact reproduction (2026-10-07, far-rs queued-admission Linux gate): `run_command({command:"powershell",args:["-NoProfile","-NonInteractive","-Command","-"],cwd:"C:/Temp/far-c1c-verify-tree",mode:"sync",timeoutMs:600000,stdin:{kind:"inline",text:"& wsl.exe -d Ubuntu --cd /mnt/c/Temp/far-c1c-verify-tree env CARGO_TARGET_DIR=/home/joss/far-rs-net-target cargo test -p far-sys -p far-vfs -p far-fileops --lib --locked -j1 -- --test-threads=1\n$farGateExit=$LASTEXITCODE\n[System.IO.File]::WriteAllText('C:/Temp/far-queued-linux-tests2-exit.txt',[string]$farGateExit)\nexit $farGateExit\n"},stdoutFile:"C:/Temp/far-queued-linux-tests2-out.log",stderrFile:"C:/Temp/far-queued-linux-tests2-err.log"})` returned the same 300-second transport timeout and 25 native stack frames. Actual test execution continued (Linux PID2516), with the deep-tree worker using CPU; no duplicate gate was started. Later the WSL kernel recorded systemd poweroff and distribution restart, and the distinct Windows completion marker recorded exit1. That interruption is not asserted to be caused by the MCP server; no full test pass is claimed. Safe fallback: short read-only log/process inspection, explicit exit receipts, and detached long gates. A separate single original deep-tree scenario was stopped with SIGINT after obtaining its debugger stack; its native exit2 is an intentional stopped diagnostic, not a test pass. Existing entries preserved.

## 2026-10-07 � proc_tree discloses an internal stack for a completed process

Exact reproduction: after the rez-rs detached gate runner had exited, call `proc_tree({pid:105656})`. The server returns expected process-not-found error -32603 followed by 25 internal native stack frames, including aws_lc, BaseThreadInitThunk and RtlUserThreadStart.

Impact: a process exiting before inspection is an expected condition; disclosure of the full internal stack is the server defect. The error alone does not explain why the runner exited or establish a successful test result.

Safe fallback: use `search_processes` to check currently live commands, then inspect the runner's stdout/stderr logs and explicit exit receipts. Restart an interrupted gate with a sufficient timeout and a durable exit receipt; do not infer success from process absence. Existing entries preserved.

## 2026-10-08 � OFX edit_file zero-match validation exposes native stack

Additional reproduction (2026-10-08): edit_file on
ofx-rs/crates/ofx-effects/src/common/filter.rs with a nine-edit batch; edits 8 and
9 depended on sequential matching. Edit 8 changed the working_color test call
to include managed=true, and edit 9 matched that not-yet-present call. The server
correctly rejected the original-content zero match without mutation, but returned
MCP -32603 and 25 native internal frames (aws_lc/BaseThreadInitThunk/RtlUserThreadStart).
The dependent anchor is caller error; native stack disclosure is the defect.
Safe fallback: reread original source, transform dependent edits sequentially in
memory, write the complete checked source and verify readback.


Exact reproduction: edit_file on ofx-rs/crates/ofx-gen/src/fft/gpu.rs, edits matching
`    let mut cache = crate::wait_lock(&PIPELINES, || crate::check_cancel(cancel))?;`
and `    fn record_axis(`. The first anchor incorrectly includes a semicolon:
the actual expression continues with map_err on the next line. The expected
zero-match rejection returned MCP -32603 and 25 internal native frames.

Impact: the incorrect anchor is caller error; exposing the native stack is the
server defect. Readback confirmed the batch did not mutate the file.

Safe fallback: reread the complete expression, use its exact multiline anchor,
then verify readback. Existing report entries preserved.

## 2026-10-07 � MSVC edit_file zero-match failure exposes native stack

Exact reproduction: call edit_file on `C:/projects/projects.rust.cg/cglibs/rez-rs-packages/msvc_build_tools/14.44/build.py` with one batch that renames `REZRS_OFFLINE_MODE` to `REZ_OFFLINE`, then a dependent edit matching the renamed `_offline()` body. Batch matching uses original content, so the latter anchor is absent. The expected zero-match rejection returned MCP -32603 with a 25-frame internal native stack. Readback confirmed no mutation.

Impact: dependent/stale edit anchors are caller error; exposing internal native frames for that validation failure is the recurring server defect.

Safe fallback: re-read current source, match every batch anchor against the original content, or apply dependent edits sequentially; verify the final readback. Existing entries preserved.

Additional exact reproduction (2026-10-08, ffmpeg-rs writer README): edit_file on C:/projects/projects.rust.cg/cglibs/ffmpeg-rs/crates/av-format-movenc/README.md with three literal edits; edit #3 oldText was `Fragments and real mode/brand/remaining box/timescale policy remain pending.` while actual sentence uses lowercase `fragments` after a semicolon. Expected zero-match rejection returned -32603 and 25 internal native frames. Readback confirmed no mutation. Incorrect case is caller error; native stack disclosure is the server defect. Safe fallback: reread the exact sentence and use its original spelling, then verify readback. Existing entries preserved.

## 2026-10-08 � disk_usage rejects existing forward-slash Windows paths and discloses a stack

Exact reproduction: `disk_usage({path:"C:/Temp"})` and `disk_usage({path:"D:/Temp"})` both returned MCP -32603 `No disk found for path` and 25 internal native stack frames. Both paths exist and are used successfully by read_text_file/run_command in the same session. `disk_usage({})` immediately succeeded and listed C:\\ and D:\\, with 117.79 GiB and 12.30 GiB available respectively.

Impact: existing Windows paths using documented forward-slash spelling are not mapped to their actual disk; this is a server path-handling defect. Disclosure of native internal frames is an additional server defect, not an expected nonexistent-path user error.

Safe fallback: call `disk_usage({})`, select the actual mount point from the returned disks, and use the returned available_bytes for cleanup decisions. No deletion was needed. Existing report entries preserved.


## 2026-10-08 � far-rs dry-run zero-match error exposes native stack

Exact reproduction: call `edit_file({path:"C:/Temp/far-c1c-verify-tree/crates/far-vfs/src/providers/archive.rs",dryRun:true,edits:[{oldText:"impl ArchiveProvider {\n    /// THE provider",newText:"impl ArchiveProvider {\n    /// THE provider"}]})`. The anchor is absent because that comment follows another method in the existing impl. The expected zero-match validation returned MCP -32603 and 25 internal native stack frames, including aws_lc, BaseThreadInitThunk and RtlUserThreadStart. No source mutation occurred in the rejected dry run.

Impact: the incorrect anchor is caller error; disclosure of the internal native stack for a routine validation failure is the server defect.

Safe fallback: reread current source, omit unnecessary no-op edits, and apply exact existing anchors; verify the source readback. Existing report entries preserved.

## 2026-10-11 � Additional inline_too_large reproduction in Powers recovery

- Exact reproduction: write_file on C:/projects/projects.rust.cg/cgprojs/math_en/.claude/worktrees/agent-a2f45b37cd3458629/docs/design/part0-1-storyboard.md with {kind:inline,text:<83387-byte UTF-8 storyboard>}.
- Observed: -32602 inline_too_large correctly rejects the 65536-byte limit, but returns 25 native stack frames. Caller payload size is expected validation error; stack disclosure is the server defect already reproduced below.
- Impact: noisy internal diagnostic disclosure, no mutation from rejected call.
- Safe fallback: staged the same content using blob_begin/append/finalize; write_file with {kind:blob,id} succeeded and verified 83387 bytes. Existing entries preserved.

## 2026-10-08 � write_file inline_too_large returns internal stack trace

Reproduction: call filesystem-mcp-rs.write_file with path C:/Temp/far-c1c-verify-tree/crates/far-core/src/app/pending.rs and content {kind:"inline",text:<172255-byte Rust source>}. Repeat with net_copy.rs (102842 bytes) or far-fileops/src/copy.rs (110214 bytes).

Observed: the documented 65536-byte inline limit correctly rejects the request with inline_too_large, but the response includes a full 25-frame internal stack trace (aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk, RtlUserThreadStart). Limit rejection is an expected caller error; exposing the internal trace is the reproducible server defect. Files were not changed.

Impact: unnecessary internal diagnostic exposure and noisy tool output for routine validation errors.

Safe fallback: use edit_file with small exact replacements, or stage larger rewrites with the documented blob_begin/blob_append/blob_finalize flow before write_file.

## 2026-10-11 � edit_file no-match leaks internal stack trace

Reproduction: call edit_file on math_en/src/viz/scene/Instruments.tsx with a literal oldText containing backslash-escaped backticks where the actual source has plain backticks (the M8 4V196 SVG ruler line). One of five edits has no match. The expected caller error is `Failed to apply edits: 1 of 5 edits produced zero matches`; the server defect is returning a full internal 25-frame stack backtrace including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart. Re-read confirmed all edits were atomic and the file unchanged. Impact: internal diagnostic disclosure/noisy routine error. Safe fallback: read actual source and retry exact text or a narrowly anchored regex; do not log the mismatch itself as a server defect.

## 2026-10-11 � invalid regex validation exposes internal backtrace

Reproduction: edit_file with isRegex:true and oldText `const compact = code.replace([\\s\\S]*?return` (unescaped opening parenthesis), against math_en/astro.config.mjs. Expected caller error: unclosed regex group. Observed server defect: the validation error includes a full 25-frame internal stack backtrace. File remained unchanged. Impact: noisy internal diagnostic exposure. Safe fallback: escape the literal parenthesis or use exact text; re-read before retrying.




## 2026-10-11 � run_command spawn failure exposes internal backtrace

Reproduction: run_command with command C:/Program Files/Git/bin/bash.exe, args=[C:/Users/joss1/.codex/plugins/cache/claude-plugins-official/superpowers/6.4.1/skills/subagent-driven-development/scripts/task-brief, docs/superpowers/plans/2026-10-10-engine-addendum-6d-6e.md, 6g, .superpowers/sdd/2026-10-10-engine-addendum-6d-6e/task-6g-brief.md], cwd=C:/projects/projects.rust.cg/cgprojs/math_en, timeoutMs=10000. Observed: Failed to spawn command plus a full internal 25-frame stack backtrace. An unavailable executable is a caller/environment error; disclosing the internal trace is the server defect. Impact: noisy internal diagnostic exposure; extraction did not run. Safe fallback: available bun through filesystem run_command and equivalent fence/heading extraction; succeeded, writing a 13-line brief. Attempting to append via full-file write also reproduced the already logged inline-limit stack disclosure (264444 bytes); small edit_file append preserves existing entries safely.

## 2026-10-11 � http_request allowlist rejection discloses internal backtrace

Reproduction: http_request({method:'GET',url:'https://raw.githubusercontent.com/KhronosGroup/GLSL/main/chapters/variables.adoc',maxBytes:400000}) during math_en GLSL advisory. Observed by /root/holo_review: denied domain raw.githubusercontent.com plus full internal stack backtrace. Allowlist rejection is expected policy behavior; internal diagnostic exposure is the server defect. Impact: noisy routine rejection and internal trace disclosure; no source changed. Safe fallback: primary GLSL specification through permitted web tools, or locally installed primary dependency sources; do not weaken the network allowlist.


## 2026-10-11 \u2014 Additional stale-literal batch reproduction (math_en Task6f)

Reporter /root/viewport_size_modes called mcp__filesystem__edit_file on C:/projects/projects.rust.cg/cgprojs/math_en/src/i18n/ui.ts with two literal edits (isRegex absent): first oldText `  "viewport.reset": "Reset view",` inserted viewport.wide/full/wideTip/fullTip English keys before Reset view; second oldText `  "viewport.reset": "\u0421\u0431\u0440\u043e\u0441\u0438\u0442\u044c \u0432\u0438\u0434",` inserted the Russian equivalents before that stale literal. Exact new English values: Enlarge 2\u00d7; Full screen; Enlarge the viewport (Ctrl+Space). Escape restores normal size.; Fill the screen (F or Ctrl+Alt+Space). Escape restores normal size. Russian equivalents: \u0423\u0432\u0435\u043b\u0438\u0447\u0438\u0442\u044c \u0432 2 \u0440\u0430\u0437\u0430; \u041d\u0430 \u0432\u0435\u0441\u044c \u044d\u043a\u0440\u0430\u043d; \u0423\u0432\u0435\u043b\u0438\u0447\u0438\u0442\u044c \u043e\u043a\u043d\u043e (Ctrl+Space). Escape \u0432\u0435\u0440\u043d\u0451\u0442 \u043e\u0431\u044b\u0447\u043d\u044b\u0439 \u0440\u0430\u0437\u043c\u0435\u0440.; \u0420\u0430\u0437\u0432\u0435\u0440\u043d\u0443\u0442\u044c \u043d\u0430 \u0432\u0435\u0441\u044c \u044d\u043a\u0440\u0430\u043d (F \u0438\u043b\u0438 Ctrl+Alt+Space). Escape \u0432\u0435\u0440\u043d\u0451\u0442 \u043e\u0431\u044b\u0447\u043d\u044b\u0439 \u0440\u0430\u0437\u043c\u0435\u0440. Each newText retained its old reset line, with newline-separated keys in that order.

Observed error -32603: Failed to apply edits: 1 of 2 edits produced zero matches, followed by Stack backtrace and internal native frames including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart. Actual Russian source says \u0421\u0431\u0440\u043e\u0441 \u0432\u0438\u0434\u0430: unmatched stale literal is expected caller error; native-stack disclosure is the already reported server defect. Impact: avoidable internal diagnostic exposure/noisy output. Subsequent corrected batch diff confirmed both initial additions absent beforehand, so the failed batch was atomic/no source corruption observed. Safe fallback: read current source, correct Russian anchor to \u0421\u0431\u0440\u043e\u0441 \u0432\u0438\u0434\u0430, apply atomic batch and verify diff; do not weaken matching or accept stale anchors. No failing source mutation rerun was needed for this report.

Reporting fallback: an attempted append with literal Cyrillic failed safely because edit_file identified the existing BUG_CDX.md encoding as windows-1252: -32603 Failed to encode edited file, edited text contains characters the original encoding cannot represent; refusing to write to avoid corruption. A dryRun showed a diff but the write refused. The encoding refusal is expected data-preservation behavior; a full native stack backtrace was again disclosed (same frames as above). Existing bytes remained unchanged. This report uses ASCII Unicode escapes for exact non-ASCII literals to preserve the existing encoding; it does not convert/rewrite the whole report. New reproduction: regex EOF append oldText='\\z', isRegex=true, newText containing literal Cyrillic to BUG_CDX.md, versus successful ASCII-escaped entry.


## 2026-10-11 - Additional locate_search missing-root backtrace reproduction (math_en browser discovery)

Exact requests: mcp__filesystem_mcp_rs__locate_search({query:"firefox.exe",limit:12,waitMs:1000}), same with query:"ms-playwright", and query:"playwright". All three returned MCP -32602 "path or paths is required" plus full 25-frame native Stack backtrace including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart. Omitting a root is expected caller error; internal trace disclosure and schema path/paths both optional are the existing defect logged 2026-09-29/2026-10-04, not a new index failure. Impact: excessive internal diagnostics, no search ran. Safe fallback: explicit verified path C:/Users/joss1, query ms-playwright, limit12, waitMs1000 succeeded with two indexed directory matches; partial/stale index is discovery only, verify returned directories live before relying on them. Existing entries retained; no invalid calls repeated for logging.


## 2026-10-11 - Stale literal edit backtrace reproduction (math_en LC)

Reproduction: filesystem_mcp_rs edit_file path C:/projects/projects.rust.cg/cgprojs/math_en/src/viz/lessons/law-of-cosines.tsx, oldText="'proof-2':{hidden:step<7}", newText="'proof-2':{hidden:step<7,dim:step===9}". The requested dim was already present. Zero literal matches is expected caller error; returning MCP -32603 with 25 native Stack backtrace frames (including aws_lc, BaseThreadInitThunk, RtlUserThreadStart) is the existing server diagnostic-disclosure defect. Impact: noisy internal disclosure; no edit applied. Safe fallback: re-read source, confirm desired dim already exists, do not retry stale mutation. Existing reports retained.


## 2026-10-11 - HTTP allowlist denial discloses native backtrace (math_en)

Exact reproduction: filesystem_mcp_rs http_request {"method":"HEAD","url":"http://127.0.0.1:4481/math-course/ru/ground/law-of-cosines/","timeoutMs":10000,"maxBytes":256}. Expected policy denial: HTTP domain '127.0.0.1' is not in allowlist. Observed MCP -32602 includes full Stack backtrace frames0..24, including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart. The allowlist denial itself is expected, not a defect; native internal diagnostic disclosure is the reproducible existing defect class. Impact: internal implementation disclosure/noisy failure output; no HEAD performed, no HTTP200 claim. Safe fallback: do not bypass HTTP allowlist; rely on already captured authorized production browser evidence and read-only search_processes verification of existing preview PID45564/62656 Run4481. User can open the supplied local URL. All earlier report entries retained.


## 2026-10-11 - run_command PowerShell variable validation backtrace (litgpt-rs)

Exact reproduction (JSON Unicode escape preserves dollar token): run_command({"command":"pwsh","args":["-NoProfile","-Command","\u0024PSVersionTable.PSVersion.ToString()"],"streamOutput":false,"timeoutMs":10000}). Expected rejection: MCP -32602 variable in command/args, use stdin or file. Observed defect: full internal 25-frame Stack backtrace. Impact: noisy internal diagnostics; command did not run. Safe fallback: which pwsh, then verified .ps1 via -File. For filesystem writes construct dollar character at runtime (String.fromCharCode(36)) and encode ContentRef base64. Additional observed behavior: edit_file with regex EOF anchor strips dollar-name sequences from replacement text even supplied via base64, consistent with regex replacement capture interpolation; use literal anchors or escaped dollar replacement. A verified base64 write_file preserved all PowerShell variables. Existing entries preserved.


## 2026-10-11 - read_text_file sharing violation backtrace (litgpt-rs build log)

Exact reproduction: read_text_file({path:"C:/projects/projects.rust.cg/ai/litgpt-rs/target/resource-logs/20261011-220353-cold-build.stderr.log",tail:10,max_chars:2200}) while resource-monitor.ps1 opened the log using .NET File.Create. Expected environment error: Windows sharing violation os error32 because writer used FileShare.None. Observed server defect: MCP -32603 includes full internal 25-frame Stack backtrace. Sharing restriction is expected and not itself a filesystem server defect. Impact: noisy diagnostic disclosure; log could not be read during build. Safe fallback: close writer before reading; future writer uses File.Open Create/Write with FileShare.Read, verified live reads succeed. Existing entries preserved.


## 2026-10-11 - managed run exceeds host 300s call deadline (litgpt-rs)

Reproduction: run_command({command:"pwsh",args:["-NoProfile","-File","tools/resource-monitor.ps1","-Command","cargo","-ArgumentsJson","[\"build\",\"--workspace\",\"--locked\"]","-RunName","limited-build"],cwd:"C:/projects/projects.rust.cg/ai/litgpt-rs",mode:"managed",timeoutMs:1800000,outputFilter:{maxLines:4}}). Observed: MCP call fails with timed out awaiting tools/call after300s and full native25-frame backtrace, although requested command timeout is1800000ms. Resource JSONL continued past300s, so failure did not imply command completion. Impact: lost managed completion result and diagnostic disclosure; restarting blindly risks concurrent builds. Safe fallback: verify existing process/log progress, wait for its resource-monitor summary; for future long runs use mode detached and poll log/summary files via filesystem tools with short calls. Existing entries preserved.


## 2026-10-11 - run_command maxLines-only filter does not bound inline output (litgpt-rs)

Exact reproduction: run_command({command:"cargo",args:["tree","--locked","--target","x86_64-pc-windows-msvc","-e","features","-i","cubecl"],cwd:"C:/projects/projects.rust.cg/ai/litgpt-rs",stdoutFile:"C:/projects/projects.rust.cg/ai/litgpt-rs/target/resource-logs/dependency-features.txt",streamOutput:true,timeoutMs:10000,outputFilter:{maxLines:1}}). Observed stdoutTotalLines201 and inline stdout contains200 lines (first root line absent), rather than at most1. Earlier same command with maxLines80 and streamOutputfalse also returned201 lines. Valid bounded-output request is not a caller validation error; maxLines without include/exclude appears ineffective. Impact: unnecessarily large MCP output, while saved log is complete. Safe fallback: keep stream output in a known file, ignore inline content in orchestration, and read bounded head/tail via filesystem read_text_file. Existing entries preserved.


## 2026-10-12 - write_file inline size rejection leaks native backtrace (math_en sim-widget-rs)

- **Evidence scope:** Observed by worker `/root/sim_foundation_impl`; the coordinator/root did not reproduce the call. The retained worker tool transcript is the evidence; the failed call returned no standalone log path. This repeats the existing inline-limit/backtrace disclosure class.
- **Exact observed request:** `tools.mcp__filesystem_mcp_rs__write_file({path:"C:/projects/projects.rust.cg/cgprojs/math_en/.superpowers/sdd/sim-widget-rs/task-01-report.json",content:{kind:"inline",text:output}})`. The worker constructed `output=JSON.stringify(report_with_fix_rounds_and_duplicate_all48snapshot,null,2)+"\n"`: 75,478 JavaScript characters and 75,481 UTF-8 bytes.
- **Expected caller error:** The documented 65,536-byte inline limit rejects this oversized payload. The exact response starts `Mcp error: -32602: inline_too_large: 75481 bytes exceeds limit of 65536; stage with blob_begin/blob_append/blob_finalize and pass {kind:blob,id}` and includes structured `code:"inline_too_large"`. That size validation is expected user-input handling, not a server defect.
- **Observed server defect:** The same `isError:true` response includes `Stack backtrace:` frames 0 through 24: 0/1 `<unknown>`, 2 `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, 3 through 22 `<unknown>`, 23 `BaseThreadInitThunk`, 24 `RtlUserThreadStart`. Exposing the native internal stack for routine validation is the defect. No specific internal filesystem path is asserted beyond what this transcript shows.
- **Observed impact:** The write fails and exposes native implementation details with excessive diagnostic output. The worker's immediate `read_json` query `$.fix_rounds[0].status` returned null with `queryMatched:false`; the worker reports the pre-existing report remained intact. No source corruption or successful oversized write is claimed.
- **Safe reproduction/fallback:** To check the diagnostic independently, use a scratch path and `content:{kind:"inline",text:"x".repeat(75481)}`; expect a concise structured size rejection without native frames. Do not overwrite the production report for reproduction. For the intended large report, stage content with `blob_begin`, bounded `blob_append`, and `blob_finalize`, then use `write_file` with `content:{kind:"blob",id}` and verify readback. The worker reports blob staging succeeded for a compact 65,136-byte report; final blob write/readback were still pending when this evidence was supplied. Existing report bytes are preserved.


## 2026-10-12 - edit_file dependent literal rejection exposes native stack (math_en task02)

- **Evidence scope:** Observed by `/root/sim_runtime_impl`; not rerun by root or documentation agent. Evidence is the worker's retained tool transcript; no standalone tool log was supplied.
- **Exact request:** `mcp__filesystem_mcp_rs__edit_file` with path `C:/projects/projects.rust.cg/cgprojs/math_en/sim-widget-rs/crates/sim-runtime/src/lib.rs`, no `dryRun`, and these six edits:

```json
[
  {"oldText":"self.events","newText":"self.replay_events","replaceAll":true},
  {"oldText":"candidate.events","newText":"candidate.replay_events","replaceAll":true},
  {"oldText":"    events: VecDeque<SessionEvent>,","newText":"    replay_events: VecDeque<SessionEvent>,"},
  {"oldText":"            events: VecDeque::new(),","newText":"            replay_events: VecDeque::new(),"},
  {"oldText":"            events: self.replay_events.clone(),","newText":"            replay_events: self.replay_events.clone(),"},
  {"oldText":"audit_events","newText":"events","replaceAll":true}
]
```

- **Expected caller error:** Batch edits match independently against original text. Edit 5 depended on an earlier replacement and was absent, so rejecting the batch is expected. Exact response: `MCP -32603: Failed to apply edits: 1 of 6 edits produced zero matches`; the structured JSON reports the same error. The worker repeated the call with edit 5 shortened to `events: self.replay_events.clone()` and observed the same rejection.
- **Observed server defect:** The error then includes `Stack backtrace:` frames 0 through 24, with frame 2 `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, frame 23 `BaseThreadInitThunk`, frame 24 `RtlUserThreadStart`, and all other frames `<unknown>`. Native stack disclosure for the ordinary zero-match conflict is the defect; the absent literal itself is not a server bug.
- **Impact and limits:** The batch fails and emits excessive internal implementation details. Subsequent worker readback confirmed the file was unchanged; no partial source mutation is claimed. This tool incident is not runtime acceptance evidence.
- **Safe fallback:** Reread actual source and match every literal against the original content. Apply dependent transformations sequentially in memory, then use `write_file` with a valid ContentRef (blob staging if over the inline limit), or use separate corrected literal edits. Verify readback and the intended scoped diff. Existing entries remain intact.


## 2026-10-12 � grep_context routine validation exposes native stack (ofx-rs AE documentation)

- **Exact reproduction:** Call `mcp__filesystem_mcp_rs__grep_context({path:"C:/projects/projects.rust.cg/cglibs/ofx-rs/docs/plan0.md",pattern:"4.9",context:25})`.
- **Expected caller error:** The request omits `nearbyPatterns`; rejection with MCP `-32602` and a concise instruction to pass nearby terms or use `grep_files` is expected. This malformed request is not a server defect.
- **Observed server defect:** The same response includes `Stack backtrace:` frames 0 through 24; frame 2 is `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, 23 is `BaseThreadInitThunk`, 24 is `RtlUserThreadStart`, and the other frames are `<unknown>`. Internal native stack disclosure for routine validation is the defect.
- **Observed impact:** The read-only search fails and emits excessive implementation details. No mutation or lost source data occurred.
- **Safe fallback:** Read the relevant bounded range with `read_text_file({path:"C:/projects/projects.rust.cg/cglibs/ofx-rs/docs/plan0.md",offset:330,limit:65})` (succeeded), or use `grep_files` for a plain search. Supply actual nearby terms when using `grep_context`.

## 2026-10-12 � dependent edit_file literal stack disclosure recurs in lgpt-rs

- **Evidence scope:** Coordinator-supplied retained tool receipt; not rerun by the documentation agent. This repeats the math_en dependent-literal incident above.
- **Observed request:** `mcp__filesystem_mcp_rs__edit_file` on `C:/projects/projects.rust.cg/ai/litgpt-rs/crates/cli/src/bench.rs` with seven literal edits. The batch includes `oldText:"check_train_memory(a, &monitor, idle)?;"`, `newText:"check_train_memory(a, &monitor, idle, None)?;"`, `replaceAll:true`; its dependent seventh edit uses `oldText:"            check_train_memory(a, &monitor, idle, None)?;"`, `newText:"            check_train_memory(a, &monitor, idle, pool.snapshot())?;"`. The other five edits are not retained here and are not reconstructed.
- **Expected caller error:** Literals match independently against original content, so the seventh anchor is absent and zero-match batch rejection is expected. The receipt reports that edit 7 of 7 produced zero matches; readback confirmed the file remained unchanged.
- **Observed server defect:** The expected rejection includes a full native `Stack backtrace:` with frames 0 through 24, including frame 2 `aws_lc`, frame 23 `BaseThreadInitThunk`, and frame 24 `RtlUserThreadStart`. Exposing internal implementation frames for a routine conflict is the defect, not the dependent caller anchor.
- **Observed impact:** No source edit applied; excessive internal diagnostics were exposed. This does not establish a training failure or source corruption.
- **Safe fallback:** Reread the original text; apply dependent transformations sequentially in memory, then `write_file` and verify readback. The coordinator reports that this fallback succeeded. For an independent diagnostic reproduction, use a scratch copy with only the two dependent literals rather than mutating the production file. Preserve existing entries.



## 2026-10-12 � locate_search missing-path validation exposes native stack (ofx-rs AE SDK lookup)

- **Evidence scope:** Observed by the ofx-rs mac_adapter worker; documented from its supplied exact requests/results, not repeated by this documentation agent.
- **Exact reproduction:** Call `mcp__filesystem_mcp_rs__locate_search({query:"AE_Effect.h",limit:15})`.
- **Expected caller error:** The request has no `path` or `paths`; concise MCP `-32602` rejection with `path or paths is required` is expected. Omitting a required search root is caller error, not a server defect.
- **Observed server defect:** The response also contains `Stack backtrace:` frames 0 through 24; frame 2 is `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, 23 is `BaseThreadInitThunk`, 24 is `RtlUserThreadStart`, and the other frames are `<unknown>`. Internal native stack disclosure for routine validation is the defect.
- **Observed impact:** The read-only lookup fails and emits implementation details. No file mutation occurred.
- **Safe fallback:** Read the tool schema, then call `locate_search({path:"C:/projects",query:"AE_Effect.h",limit:20})`. The worker reports this corrected request succeeded with six matches, including the read-only SDK under `C:/projects/projects.openfx/ae25.6_61.64bit.AfterEffectsSDK`. Preserve existing report entries.


## 2026-10-12 � file_hash nonexistent file exposes native stack (math_en AA review)

- Exact reproduction: `mcp__filesystem_mcp_rs__file_hash({path:"C:/projects/projects.rust.cg/cgprojs/math_en/sim-widget-rs/crates/sim-render/src/shaders/owned_wrapper.wgsl"})`.
- Expected caller error: this guessed path does not exist; a concise missing-file error is correct. The caller should discover the path first.
- Observed server defect: MCP -32603 Cannot open file is followed by native Stack backtrace frames 0 through 24, including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart. Routine missing-file stack disclosure is the defect, not the missing path.
- Impact: read-only hash fails with excessive internal diagnostic details; no mutation occurred.
- Safe fallback: `search_files` with `**/*.wgsl` discovered `sim-widget-rs/crates/sim-render/shaders/material.wgsl`; hashing that actual file succeeded. The original logging write truncated earlier entries; the verified recovery is recorded below.


## 2026-10-13 UTC (2026-10-12 local) - logging rewrite from truncated read; prior report recovered

- **Incident scope:** Caller/agent logging workflow error, observed in math_en AA review. This is not a filesystem-mcp-rs server defect: the bounded read and requested overwrite behaved as requested. The missing-file native-stack defect above is a separate server diagnostic issue.
- **Exact recorded sequence:** At 2026-10-13T03:16:45.094Z the agent called read_text_file({path:"C:/projects/projects.rust.cg/cglibs/filesystem-mcp-rs/BUG_CDX.md",max_chars:30000}), then write_file({path,content:{kind:"inline",text:old+newEntry}}) using that bounded result. The read explicitly contained [truncated at 30000 chars, total 283814 chars]. Ignoring this marker and using a whole-file overwrite lost prior content. No destructive reproduction was rerun.
- **Observed impact:** The prior report had 283,814 bytes/decoded characters; the overwrite left 31,598 UTF-8 bytes (31,022 characters), including the truncation marker. The original new entry's claim that existing entries were preserved was false; it is corrected above.
- **Safe fallback:** Append with a uniquely verified literal tail or stage the full content via Content Plane after reading all pages and checking completeness. Back up raw bytes first, check the expected current hash before any whole-file restoration, and verify byte prefix/readback afterward. Never rebuild a file from a bounded head/tail or a result containing a truncation marker.
- **Recovery evidence:** Global writes were stopped. Documentation owner preserved BUG_CDX-corrupted-before-recovery.md, SHA256 26b862886ee5ab3580d3c05c6efe3f06deb4cb3fa93d7aacfeaf2a93af5f7651. The local Codex session write-body snapshot dfb71d660136c572f595ab09f9a0f9306dccf3af68c9c48d07fd00b4eb801010.txt included an uncommitted 948-character spawn entry from a rejected whole-file inline write; only that proposed suffix was removed. Reconstruction used 17 successful resolved MCP edit diffs and 2 confirmed ASCII append receipts in chronological order. Dry-run/failed Cyrillic writes were excluded; the successful server diffs preserve actual regex replacement behavior.
- **Exact checks:** Reconstructed prior length is 283,814 characters and reversible Windows-1252 bytes, including preserved undefined C1 byte mappings. The first 30,000 characters equal the preserved corrupt-file prefix; the complete 5,890-character tail captured at 03:16:30 matches. Before the later 1,378-character header insertion, raw prefix 272,902 bytes matches SHA256 121bd96fbc8c2c499c6012e0bdb22fbe1431c66ad0401fff2fecf72414eb50c5, and raw prefix 275,472 bytes matches SHA256 6d39e2ac593c3d9593f829d6ee223a3a5180fe25c0b86399069b762ed1c3a1d1. Reconstructed complete prior SHA256: a7b4f5f3d44cbfbe8421c61140bce6bef5dde87f3d5c141cba754e28630b9960.
- **Recovery receipt:** Scratch artifacts under math_en/.superpowers/sdd/sim-widget-rs/log-recovery include resolved-bug-tool-items.json, reconstruction-audit.json, raw-byte-proof.json, both ASCII append receipts, confirmed-prior-tail-031630.txt and reconstructed-prior-exact.bin. Verified binary restoration preserves every prior raw byte as a prefix, then appends the retained missing-file defect and this incident record. Existing mixed/legacy text is not silently re-encoded or repaired. Final byte count/hash/readback live in restoration-receipt.json; no product code or commit changed.


## 2026-10-12 local / 2026-10-13 UTC - edit_file indentation mismatch exposes native stack (ofx-rs rain ledger)

- Exact reproduction: filesystem-mcp-rs edit_file on C:/projects/projects.rust.cg/cglibs/ofx-rs/docs/plan0.md, with oldText "      there): digital rain after the 1999 film, a pure function of (seed, time, controls), CPU + WGPU." and a replacement adding the premultiplied Matrix Rain regression receipt. The anchor uses six leading spaces; the actual line uses four.
- Expected caller error: zero-match rejection is correct. This was an incorrect indentation anchor, not missing source data or a failed product render. The response reported "1 of 1 edits produced zero matches" and left the ledger unchanged.
- Observed server defect: the routine conflict also returned a native Stack backtrace, frames 0 through 24, including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart. This repeats the existing zero-match stack-disclosure defect; the caller mismatch itself is expected.
- Impact: the edit failed with excessive internal implementation details. No partial source mutation or data loss was observed.
- Safe fallback: reread the bounded ledger range, use its exact four-space anchor, and verify the diff. The corrected edit succeeded. This receipt is inserted as ASCII bytes at the verified original EOF; prior raw bytes are hash-checked as an unchanged prefix, preserving mixed legacy report encoding and all existing entries.


## 2026-10-13 - run_command PowerShell dollar-token validation exposes native stack (dokan-rs review)

- Exact reproduction: mcp__filesystem_mcp_rs__run_command({"command":"powershell","args":["-NoProfile","-Command","$deps = @('aws-sdk-s3','aws-config','tokio','gcloud-storage','suppaftp','dokan','toml'); foreach ($dep in $deps) { $r = Invoke-RestMethod -Uri ('https://crates.io/api/v1/crates/' + $dep) -Headers @{'User-Agent'='dokan-rs-project-review'}; [pscustomobject]@{name=$dep;latest=$r.crate.max_stable_version;updated=$r.crate.updated_at} | ConvertTo-Json -Compress }"],"cwd":"C:\\projects\\projects.rust.cg\\cgprojs\\dokan-rs","mode":"detached","timeoutMs":90000}).
- Expected caller error: -32602 rejection of $deps in command/args under the dollar-token guard; rejection itself is expected.
- Observed server defect: response adds Stack backtrace frames 0-24, including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk, RtlUserThreadStart.
- Impact: lookup rejected before spawn; internal native diagnostics disclosed; no project mutation.
- Safe fallback: powershell args [-NoProfile,-Command,-], script via stdin {kind:inline,text:script}; lookup succeeded. Preserve existing report bytes with append and verify prefix.


## 2026-10-13: run_command validation leaks native stack trace

Reproduction: run_command(command="powershell", args=["-NoProfile", "-Command", "$p = Get-Process -Id 54916 -ErrorAction Stop; $c = $p.CPU; Start-Sleep -Seconds 3; $p.Refresh()"], cwd="C:/projects/projects.rust.cg/ai/litgpt-rs"). Expected dollar-variable argv rejection returns MCP -32602 remediation, but also a full native Stack backtrace including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart. A Python -c argv containing this reproduction as literal text receives the same rejection. Impact: validation is expected; internal stack disclosure is a server defect. Safe fallback: stdin ContentRef for scripts and reproduction text. No rejected command ran.


## 2026-10-13 - run_command .cmd spawn validation exposes native stack (dokan-rs architecture plan)

- Evidence: observed by architecture_plan documentation agent; recorded from its exact request and response, not destructively rerun.
- Exact reproduction: run_command({command:"npx.cmd",args:["--yes","markdownlint-cli2","plans/20261013-opendal-cache/plan.md","--config","NUL"],cwd:"C:/projects/projects.rust.cg/cgprojs/dokan-rs",timeoutMs:60000,streamOutput:false}).
- Expected error: command launch rejected/missing executable; npx was not available in the server PATH. A concise launch error is expected.
- Observed server defect: -32603 spawn failure additionally returned full native Stack backtrace including aws_lc, BaseThreadInitThunk and RtlUserThreadStart.
- Impact: optional markdownlint check could not run; internal diagnostics disclosed. No plan content loss.
- Safe fallback: shell:true yields a concise missing-command error without native stack; verify Markdown structurally and git diff --check, or install/discover npx before rerunning. Existing report raw bytes preserved by append.


## 2026-10-13 - kill_process reports no kill for a live owned build tree

Reproduction: in ofx-rs, run_command detached launched python ../.buildlock/buildlock.py target/release/xtask.exe test -- --release -p ofx-noise --features wgpu rain -- --nocapture, PID 37144. kill_process({pid:37144,tree:true}) returned {killedCount:0,success:false}. The subsequent search_processes({name_pattern:"(?i)cargo|xtask|python",cmdline_pattern:"rain|buildlock"}) still listed that exact live parent 37144, child xtask 53748 and cargo 119820. This was not an already-exited PID. A subsequent run_command taskkill /PID 37144 /T /F succeeded and listed termination of that same parent and children.

Impact: the owned workspace-wide build continued holding buildlock after the MCP termination attempt; the narrow replacement build queued behind it. Safe fallback: confirm PID and exact owned command line with search_processes, then run native taskkill /PID <verified-owned-pid> /T /F through run_command. Do not kill unrelated builds; use unique output paths for replacement commands.


## 2026-10-13 - edit_file unsupported look-around leaks internal backtrace

- Exact reproduction: mcp__filesystem_mcp_rs__edit_file on C:/projects/projects.rust.cg/cgprojs/dokan-rs/src/cache/store.rs with edits=[{isRegex:true,oldText:"    /// Additional immutable snapshot obligation of a new write, under the source mutation gate.[\\s\\S]*?(?=    /// Unmaterialized obligation)",newText:""}]. A second reproduction used a test-function pattern with a look-ahead boundary.
- Observed impact: rejecting unsupported regex look-around is an expected caller input error. The response includes a full native Stack backtrace with aws_lc and Windows thread frames, which is a server defect; no file was edited.
- Safe fallback: use supported regex without look-around, retain the boundary text in the replacement, verify the unified diff and re-read. Return a concise validation error without native frames.


## 2026-10-13 - edit_file zero-match validation exposes native stack during EXR docs fold

- Exact reproduction: mcp__filesystem__edit_file on C:/projects/projects.rust.cg/cglibs/exr-rs/crates/exr-view/AGENTS.md with two literal edits in one request: edit 1 oldText="## Colour model (COLOR_PLAN.md, 2026-10-13)", newText="## Colour model (2026-10-13; completed plan folded into CHANGELOG.md)"; edit 2 oldText="## Colour model (2026-10-13; completed plan folded into CHANGELOG.md)\n", newText equal to that heading plus a local six-stage acceptance/release-pending paragraph. The second anchor is absent from the original file.
- Expected caller error: the batch was rejected with "1 of 2 edits produced zero matches", edit #2. Assuming sequential anchor visibility was a caller mistake. Readback confirmed the original heading remained; rejecting this edit is expected.
- Observed server defect: the rejection also returned a native Stack backtrace with frames 0-24, including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk, and RtlUserThreadStart. This repeats the existing expected-input stack-disclosure defect; no new root cause is asserted.
- Impact: an ordinary edit-precondition error disclosed internal native implementation details. No partial mutation or content loss was observed.
- Safe fallback: reread the file and issue one replacement anchored to its current heading, with the desired paragraph in that replacement. The corrected edit succeeded. This entry is appended as raw ASCII bytes with the previous report bytes verified as an unchanged prefix; existing entries and mixed legacy encoding are preserved.


## 2026-10-13 — S3 allowlist rejection exposes a native stack trace

- Exact reproduction: `mcp__filesystem_mcp_rs__s3_list_buckets({region:"us-west-1"})` with an empty server S3 allowlist.
- Observed result: MCP -32602, `S3 allowlist is empty; use FS_MCP_S3_ALLOW_LIST or --s3-allowlist-bucket`, followed by 25 internal native stack frames including aws_lc and Windows thread entrypoints.
- Impact: rejecting a request outside the configured allowlist is expected. Exposing internal stack frames for that expected rejection is a server diagnostic defect. No S3 request ran through this tool.
- Safe fallback: retain the server allowlist; use a separately authorized local AWS SDK for read-only account discovery, or configure approved buckets through the normal server setup. Return a concise policy error without a native backtrace.


## 2026-10-13 - edit_file multi-edit no-match still returns native stack trace (ofx-rs)

- Exact reproduction: mcp__filesystem_mcp_rs__edit_file on C:/projects/projects.rust.cg/cglibs/ofx-rs/.github/AGENTS.md with eight literal edits; edit #7 oldText was `(every plug-in ID in `bootstrap.py`, 34)`, newText `(every plug-in ID in `bootstrap.py`, 35)`. The literal was absent; other edits matched.
- Expected user error: reject the unmatched literal and leave the file unchanged. Observed server defect: MCP -32603 includes a full native Stack backtrace with aws_lc_0_45_0_jent_entropy_switch_notime_impl / BaseThreadInitThunk / RtlUserThreadStart. Internal diagnostics leak into the model output and add noise; no partial edit observed.
- Safe fallback: re-read and verify literal anchors before editing; replace the fully reviewed small document with write_file when appropriate. Existing report bytes preserved by append at verified EOF.

## 2026-10-13 - edit_file overlapping literal edits silently drop one edit

- Exact reproduction: write target/native_edit_overlap_probe.txt with inline text "a\nfn x\nb\n". Call mcp__filesystem_mcp_rs__edit_file with edits [{oldText:"a\nfn x",newText:"A\nfn x"},{oldText:"fn x",newText:"fn y"}]. Both anchors exist in the original file; the ranges overlap. The tool reports success/isError:false and a diff containing only a->A. Readback is "A\nfn x\nb\n": the second requested change is silently omitted.
- Expected caller conflict: overlapping ranges are ambiguous and may be rejected without changing the file. Server defect: reporting success while silently dropping a matching edit hides the conflict. The same pattern omitted newly requested Rust helper functions during a cache change; compilation detected missing helpers and the source was corrected.
- Observed impact: partial fulfillment without an error can leave code or configuration incomplete. This is distinct from existing expected-input stack-disclosure reports.
- Safe fallback: use non-overlapping anchors; issue dependent/overlapping edits in separate calls, inspect the diff, and reread the changed region before compiling. Existing report bytes are preserved by raw ASCII append.


## 2026-10-13 - Additional stack-disclosure reproductions (dokan-rs)

- Exact reproduction: edit_file on crates/dokan-mount/src/lib.rs with oldText creation_time: entry.metadata.modified.unwrap_or(UNIX_EPOCH), while actual text uses unwrap_or_else(SystemTime::now). The expected unmatched-anchor error includes the full internal Stack backtrace, including aws_lc_0_45_0_jent_entropy_switch_notime_impl. Re-read confirmed no partial edit.
- Related expected caller errors: run_command rejects variable-bearing PowerShell command/args with its interpolation guard; http_download rejects the official raw.githubusercontent.com/dokan-dev/dokan-rust/master/LICENSE URL under its allowlist. Both append full internal stacks to otherwise expected validation/policy errors.
- Impact: unnecessary native diagnostics and implementation details are exposed for caller errors. This extends the previously recorded stack-disclosure issue; it is not an unauthorized-operation failure.
- Safe fallback: re-read exact anchors; pass PowerShell code through stdin or a temporary .ps1; use allowed web tooling for source text and write_file for verified content.

## 2026-10-13 - disk_usage fails for an existing Windows workspace path

- Exact reproduction: call mcp__filesystem_mcp_rs__disk_usage with path C:/projects/projects.rust.cg/cgprojs/dokan-rs, then repeat with backslashes (C:\\projects\\projects.rust.cg\\cgprojs\\dokan-rs). Both return MCP -32603 "No disk found for path" with a full native stack trace.
- Expected behavior: resolve the existing workspace to its C: volume and report capacity/free space. This is not a nonexistent-path caller error: file_stats successfully measured target/debug/incremental under the same workspace; Win32_LogicalDisk reports the C: volume.
- Observed impact: the preferred free-space tool cannot diagnose a real disk-full build; internal stack frames also leak. A call with no path returns only "All disks" in text content.
- Safe fallback: use filesystem MCP run_command with PowerShell Get-CimInstance Win32_LogicalDisk and select DeviceID,Size,FreeSpace; measure only owned build artifacts with file_stats before cleanup.



## 2026-10-24 - disk_usage rejects existing maya-rs workspace and exposes native stack

- Evidence scope: the maya-rs coordinator supplied two identical observed requests/results; this documentation agent did not repeat the failed calls.
- Exact reproduction: mcp__filesystem_mcp_rs__disk_usage({path:"C:/projects/projects.rust.cg/cglibs/maya-rs"}) twice. Both return MCP -32603 "No disk found for path: C:/projects/projects.rust.cg/cglibs/maya-rs" followed by a full internal "Stack backtrace", including unknown frames, aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk, and RtlUserThreadStart.
- Expected behavior: resolve this existing repository to its C: volume and report capacity/free space. Reads, directory listing, and builds on the same path succeed. This is a server defect, not a nonexistent-path caller error; native stack disclosure is an additional diagnostic defect.
- Observed impact: the preferred disk-space tool cannot inspect the valid workspace. No filesystem corruption or product build failure is inferred from this tool error.
- Verified safe fallback: filesystem MCP run_command with PowerShell Get-PSDrive -Name C | Select-Object Name,Used,Free | ConvertTo-Json -Compress returned exit 0 and Free=232685322240 at the coordinator's check. Continue using this read-only volume query; measure owned artifacts before any cleanup.
- Existing report bytes, including legacy mixed encoding, are preserved as an unchanged prefix by raw ASCII append and prefix verification.


## 2026-10-24 - edit_file zero-match validation exposes native stack during maya-rs CPU golden repair

- Exact reproduction: mcp__filesystem_mcp_rs__edit_file on C:/projects/projects.rust.cg/cglibs/maya-rs/crates/aether-runtime/src/ops/mod.rs with a four-edit batch; edit #1 oldText was the literal `    /// Snapshot of every enum parameter's menu (\`operator.parameter[ordinal] token \\"label\\" -> Variant\`).`. The actual comment contains plain quote characters, so this over-escaped anchor is absent. The other three edits target enum_menus_match_golden, its UPDATE_GOLDEN branch, and its expected snapshot expression.
- Expected caller error: reject the unmatched literal. This escaping mismatch is an agent input error, not a source or server mutation defect. Readback confirmed that no edits in the rejected batch were applied.
- Observed server defect: MCP -32603 also returned a full native Stack backtrace (frames 0-25), including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk, and RtlUserThreadStart. This reproduces the already reported expected-input stack-disclosure defect.
- Observed impact: internal native diagnostics leaked into ordinary edit-precondition output; no source corruption was observed.
- Safe fallback: reread the exact anchor and submit plain quote characters in oldText. The corrected edit succeeded and source readback matched the intended changes. Existing report bytes were preserved by an EOF binary insertion.


## 2026-10-24 - edit_file unmatched-anchor stack disclosure in draco-rs

- Exact reproduction: call filesystem-mcp-rs edit_file on C:/projects/projects.rust.cg/cglibs/draco-rs/crates/draco-core/src/geom/build.rs with oldText/newText pairs: self.mesh.pc. -> self.mesh.pc().; mesh.pc.set_num_points( -> mesh.set_num_points(; m.pc.attr_mut( -> m.attr_mut(; self.mesh.pc().new_attr( -> self.mesh.new_attr(; self.mesh.pc().attr_mut( -> self.mesh.attr_mut(. The final two anchors are absent in the original file.
- Expected caller error: reject the two zero-match edit preconditions; dependent replacements were mistakenly combined in one batch by the agent. Readback confirmed the original file was unchanged.
- Observed server defect: the rejection also returns a full internal Stack backtrace (0-25), including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart. This repeats the existing ordinary-validation stack-disclosure issue, not a mutation-corruption claim.
- Observed impact: internal native diagnostics are exposed for expected invalid edit input.
- Safe fallback: reread the original anchors and submit independent edits against the original content, or separate dependent edits into sequential calls; verify readback and builds.

## 2026-10-24 - win_close no-match exposes internal native stack

- Exact reproduction: after the diagnostic WarpBro window disappeared, call arm({ttl_ms:30000}) and win_close({target:{id:49808690}}); repeat the same win_close. Both return no_match / no visible window matches Id, followed by a full native Stack backtrace (frames 0-25), including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart.
- Expected caller error: a stale or closed window handle has no match. This is expected state/input failure, not a window-closing defect. win_list({query:{exe:"WarpBro"}}) confirms an empty list.
- Observed server defect: the ordinary no-match error discloses internal native diagnostics. No product failure or source corruption is inferred.
- Safe fallback: refresh win_list before acting; treat an already closed window as complete. Preserve existing report entries.

## 2026-10-24 - kill_process tree leaves an owned oracle descendant alive

- Observed reproduction in draco-rs: detached run_command launched Python PID 48584, which ran buildlock -> cargo test -p draco-io --lib --test gltf_image_cpp -- --nocapture. The test spawned draco_oracle.exe load-dump under test/out/image-cpp-53456/. Called kill_process({pid:48584,tree:true,force:true}); response: "Killed 1 processes in tree rooted at PID 48584".
- Subsequent search_processes({name_pattern:"draco_oracle|gltf_image_cpp"}) still showed oracle PID 42020 for that exact scratch directory, later using 1978 MB. The original Rust test was gone; a later, separate test used image-cpp-23112, so the survivor belonged to the stopped run. This is an observed incomplete tree cleanup; the precise process-spawn race is not established.
- Impact: stopping an owned test can leave its malformed-input C++ oracle consuming memory. A missing/already-exited PID is an expected user error; a descendant surviving a requested tree kill is the reported lifecycle defect.
- Safe fallback: search for the exact owned scratch path and PID after stopping a test, then kill only that verified survivor. kill_process({pid:42020,tree:true,force:true}) returned killedCount 1. Final process search after the remaining owned test was stopped showed no oracle/test survivors. Do not kill unrelated cargo/oracle processes.


## 2026-10-24 - locate_search invalid kind leaks native stack during lgpt-rs GUI audit

- **Additional 2026-10-25 ofx-rs/WarpBro recurrence (coordinator-observed):** `locate_search({path:"C:/projects/projects.rust.cg",query:"warpbro-rs",kind:"dir",limit:10})` returned expected -32602, "kind must be all, files, or directories", followed by the full internal native Stack backtrace (frames 0-25, aws_lc symbols, BaseThreadInitThunk and RtlUserThreadStart). Invalid kind is our caller input error, not a server/search defect; diagnostic disclosure is the reproducible server defect. The tool schema exposes kind as a string without enumerating accepted values. Impact: internal native details and excessive output for routine validation; no mutation or index corruption observed. Safe fallback: repeat with kind:"directories"; it succeeded with the index ready and located C:/projects/projects.rust.cg/cglibs/warpbro-rs. This extends the existing stack-disclosure issue, not a new root cause.


- Exact reproduction: mcp__filesystem_mcp_rs__locate_search({query:"wgpu-fx-rs",path:"C:/projects/projects.rust.cg",limit:10,kind:"dir"}). Independently reproduced once by the docs agent after the coordinator reported it.
- Expected caller error: invalid singular kind returns -32602, "kind must be all, files, or directories". Rejecting kind:"dir" is correct validation, not a locate-index defect.
- Observed server defect: the validation response also includes a full internal Stack backtrace, frames 0-25, including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart. Routine invalid input discloses native implementation details and adds excessive output; no filesystem mutation or search corruption was observed.
- Verified safe fallback: repeat the same request with kind:"directories". It succeeded and returned C:/projects/projects.rust.cg/cglibs/wgpu-fx-rs. Keep validation errors concise and native traces in server logs.
- Preservation: appended ASCII bytes at verified EOF; SHA-256 of the preceding 309315 bytes was 9e3d9f91c8d8524c15f02540b18072a17d35fa277095cdc662b10c4d9cb1a70d before insertion. Existing report entries are retained.

## 2026-10-24 - create_archive duplicate leaf names expose an internal backtrace

- Reproduction: create_archive({paths:["C:/projects/projects.rust.cg/cglibs/draco-rs/test/out/image-cpp-53456","C:/projects/projects.rust.cg/cglibs/draco-rs/test/out/image-cpp-23112"],destination:"C:/projects/projects.rust.cg/cglibs/draco-rs/test/out/image-oracle-hangs.zip",format:"zip"}). Each input directory held image.bin, in.gltf and out.dump.
- Observed: -32603 "invalid Zip archive: Duplicate filename: image.bin" followed by a full native internal backtrace (including aws_lc symbols, BaseThreadInitThunk/RtlUserThreadStart). A partial 866-byte destination remained.
- Classification: rejecting duplicate archive entry names can be an expected argument/layout error; returning the internal backtrace is the server defect. Whether directory-root flattening is intended was not established.
- Impact: multi-directory archival cannot be assumed complete from the destination's existence. Original inputs were preserved.
- Safe fallback: archive each input directory separately, verify successful results before removing originals, and discard the measured partial output only. Preserve existing report entries.


## 2026-10-24 - missing debug xtask spawn error leaks native stack in lgpt-rs GUI diagnosis

- Exact minimal reproduction independently run once: mcp__filesystem_mcp_rs__run_command({command:"C:/projects/projects.rust.cg/ai/lgpt-rs/target/attn/debug/xtask.exe",cwd:"C:/projects/projects.rust.cg/ai/lgpt-rs",timeoutMs:10000,stdoutTail:3,stderrTail:3}). No arguments or child process were needed to reproduce the coordinator/Astra observation.
- Expected caller error: that debug executable is absent. Rejecting the wrong executable path with "Failed to spawn command" is correct; the missing path itself is not a server defect.
- Observed server defect: MCP -32603 also exposes a full internal Stack backtrace, frames 0-25, including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart. Routine launch validation discloses native internals. No process was launched by the failed request.
- Verified safe fallback: use the existing C:/projects/projects.rust.cg/ai/lgpt-rs/target/attn/release/xtask.exe (file existence rechecked), with the intended supported subcommand. Check the exact executable path before launching; no duplicate build is required for a path typo.
- Preservation: ASCII append at verified EOF; the preceding 311793 bytes had SHA-256 02a5aab77aa086228ea65231e7451b8ebc1e8009da70319edb24b96f3734ea08. Existing entries are retained.

## 2026-10-25 - edit_file zero-match validation again exposes native stack

- ofx-rs recurrence: edit_file({path:"C:/projects/projects.rust.cg/cglibs/ofx-rs/crates/ofx-runtime/src/device.rs",edits:[{oldText:"            use std::os::windows::io::AsRawHandle;\n            const CHILD:",newText:"            use std::os::windows::io::AsRawHandle;\n            use std::os::windows::process::CommandExt;\n            const CREATE_NO_WINDOW: u32 = 0x0800_0000;\n            const CHILD:"},{oldText:"                    .env(CHILD, name)\n                    .stdout",newText:"                    .env(CHILD, name)\n                    .creation_flags(CREATE_NO_WINDOW)\n                    .stdout"}]}). The second literal had stale indentation after rustfmt. Expected caller error: the unmatched replacement was rejected atomically (verified by rereading imports and builder). Server defect: -32603 additionally exposed the full native 0-25 stack including aws_lc and Windows thread symbols. Impact: noisy internal disclosure; no source corruption. Safe fallback verified: reread actual indentation and retry the exact atomic batch; it succeeded. Existing entries are preserved.

- Reproduction: edit_file on warpbro-rs/src/app.rs with an edits array containing oldText "            generation: 1,\n            nodes:" and newText "            revision: app.world.revision(),\n            nodes:"; that adjacent literal does not exist.
- Expected caller error: reject the unmatched replacement atomically. This rejection is correct and no edits from the batch were applied.
- Server defect: -32603 validation output also contains the full native Stack backtrace (0-25), aws_lc symbols and Windows thread entrypoints.
- Impact: unnecessary internal implementation disclosure and noisy tool output, not source corruption. Safe fallback: re-read the actual source, use verified exact literals, and retry the corrected atomic batch. Existing report entries are preserved.

## 2026-10-25 - http_request closed loopback endpoint returns generic failure and native stack

- Reproduction: http_request({method:"GET",url:"http://127.0.0.1:9877/api/health"}) while WarpBro is not running. A separate Get-Process WarpBro check returned no matching process.
- Expected external condition: connection cannot be established to a stopped local service. This is not an application or HTTP server defect.
- Observed server defect: -32603 reports duplicated generic "HTTP request failed: HTTP request failed" with the native 0-25 Stack backtrace, including aws_lc and Windows thread symbols, without a useful connection cause.
- Impact: loses the actionable network cause and exposes internal native stack detail. Safe fallback: use a short Python urllib/socket probe through run_command, handling an expected connection-refused result without a stack trace. Preserve existing entries.

## 2026-10-25 - edit_file no-match stack disclosure reproduced safely in cryptobot-rs

- Evidence scope: the cryptobot-rs coordinator reproduced this on an owned scratch file after a real unmatched edit failed. The documentation owner independently read the scratch file as `before\n` and checked that `failOnNoMatch` is absent from the exposed `edit_file` schema.
- Exact safe reproduction, performed sequentially:

```json
{"path":"C:/projects/projects.rust.cg/cgprojs/cryptobot-rs/target/plan19-mcp-edit-probe.txt","content":{"kind":"inline","text":"before\n"}}
```

Call `write_file` with the first request, then `edit_file` with this request:

```json
{"path":"C:/projects/projects.rust.cg/cgprojs/cryptobot-rs/target/plan19-mcp-edit-probe.txt","edits":[{"oldText":{"kind":"inline","text":"absent-cryptobot-plan19-probe"},"newText":{"kind":"inline","text":"after"}}]}
```

- Expected caller error: the old text is absent, so reject the edit and preserve the file. Readback remains `before\n`; no mutation or source corruption is claimed.
- Observed server defect: MCP -32603 reports `1 of 1 edits produced zero matches` followed by a 26-frame internal `Stack backtrace`, including `aws_lc_0_45_0_jent_entropy_switch_notime_impl`, `BaseThreadInitThunk`, and `RtlUserThreadStart`. The diagnostic hint names `failOnNoMatch`, which the exposed schema does not accept. This repeats the existing expected-input stack-disclosure issue.
- Observed impact: an ordinary edit-precondition error exposes native internals and excessive unstructured diagnostics. The rejection itself is expected; the internal stack and unusable parameter hint are the defects.
- Safe fallback: reread the exact current text, use verified literal anchors, split dependent edits into separate calls, inspect each diff, and reread afterward. Keep native traces in server logs and return a concise structured no-match error; do not add a source workaround or server fix to cryptobot-rs.
- Preservation: appended ASCII bytes at verified EOF; the preceding 321088 bytes had SHA-256 `d44311c649785a9050d04ef916f89e924f41848ce85ac2fcba5cc35e8ac20c40`. Existing entries and legacy encoding are preserved.


## 2026-10-25: edit_file invalid look-ahead regex discloses internal native backtrace

- Reproduction (twice during WarpBro cone fix): call edit_file with isRegex=true and oldText containing `(?=fn beam_sphere_entry\()`, e.g. `fn pixel_beam_slope\(half_width: f32,[\s\S]*?(?=fn beam_sphere_entry\()`. The Rust regex engine rejects look-around; this caller error is expected and both files remained unchanged.
- Observed server defect: the MCP -32603 response includes a 26-frame Stack backtrace, aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart. This is the existing expected-input error stack-disclosure class, independently reproduced on two edit_file calls.
- Impact: unsupported regex syntax exposes native implementation details and floods tool output; no source corruption is claimed.
- Safe fallback: consume and restore a verified literal trailing anchor (or use a literal oldText) instead of unsupported look-ahead, inspect each result, and reread afterward. Return concise structured regex validation errors and keep native stacks in server logs.
- Preservation: ASCII appended at verified EOF; previous 323260 bytes SHA-256 ae23358ddb3bd868588d24225e593b0702d482a32a44dd75bac48790c9fd1a32 retained.


## 2026-10-26 - grep_files unlimited mode returns contradictory match counters

- Exact reproduction (repeated twice by lgpt-rs root): grep_files({path:"C:/projects/projects.rust.cg/ai/lgpt-rs/crates/cli/src/swarm.rs",pattern:"allow\\(dead_code\\)",maxMatches:0}). The matching line is 23, `#![allow(dead_code)]`.
- Observed server defect: `matches` contains one row and `totalMatches` is 1, but `stats.matchesFound` is 0. Broader unlimited searches also returned nonempty rows with zero in that stats field. This is successful valid input; no missing-file or caller-argument error is involved.
- Impact: clients using stats.matchesFound can report a false clean scan. Returned evidence rows remained usable; no file mutation occurred.
- Safe fallback: use matches.length / totalMatches for content output; validate count-mode output separately and do not infer zero hits from the contradictory stats field. No source workaround was added to lgpt-rs.
- Preservation: ASCII appended at verified EOF. Previous 324522 bytes SHA-256 a3d095fc8518b36f9ea97c6edcf85de07e339ff5e99e938c6418fc9635cbd7df are retained.


## 2026-10-27 - disk_usage verified Windows-directory recurrence during render-rs audit

- Exact reproduction: disk_usage({"path":"C:/projects/projects.rust.cg/cglibs/render-rs"}); repeat with the same absolute path using Windows backslashes. The directory exists and was verified by list_directory/read_text_file/file_stats. Both calls return MCP -32603, "No disk found for path", followed by a 26-frame internal native Stack backtrace including aws_lc symbols, BaseThreadInitThunk and RtlUserThreadStart.
- Classification: this repeats the existing Windows disk/path resolution and internal-stack disclosure defect; it is not an expected nonexistent-path caller error. No filesystem mutation resulted from either failed request.
- Observed impact: capacity preflight on a valid workspace fails and emits excessive native diagnostics. The audit's separate cargo run encountered disk-full os error 112; no causal claim about disk_usage changing disk capacity is made.
- Verified safe fallback: disk_usage({}) succeeds and enumerates both C:\ and D:\ with capacities; select the volume by its mount_point, then use file_stats on the exact workspace/build directory before cleanup.
- Preservation: appended ASCII at verified EOF; all preceding bytes are retained.


## 2026-10-27 - grep_files unlimited counter recurrence during render-rs audit

- Exact reproduction: grep_files({path:"C:/projects/projects.rust.cg/cglibs/render-rs/crates/render-engine-pt",pattern:"^fn [a-z_]+\\(|^async fn [a-z_]+\\(|#\\[ignore",filePattern:"**/*{test,tests,regression,parity}*.rs",excludePatterns:["**/standard-surface/**","**/standard-surface-bsdf/**"],maxMatches:0}).
- Observed: successful valid-input result has totalMatches=121 and 121 returned matches, but stats.matchesFound=0. The PT reviewer observed the unlimited-mode discrepancy twice; the documentation owner independently repeated the exact request above. This repeats the existing 2026-10-26 counter defect, not a source-code issue.
- Impact: clients trusting stats.matchesFound can falsely label a nonempty scan clean. No evidence of missing result rows or file mutation was observed.
- Verified safe fallback: use returned matches.length and totalMatches for content output; do not infer an empty result from the contradictory telemetry field.
- Preservation: ASCII appended at verified EOF; all preceding bytes are retained.


## 2026-10-27 - R-04 dry-run edit no-match stack-disclosure recurrence in lgpt-rs

- Evidence scope: the R-04 worker reported two occurrences: an initial wrong literal using CapsShards and the intentional no-match dry run below. This documentation task does not repeat the failing request or print its stack again. The existing no-match stack-disclosure issue is already recorded above; this adds a distinct current reproduction, not a new root cause.
- Exact safe reproduction: edit_file({path:"C:/projects/projects.rust.cg/ai/lgpt-rs/scripts/augment_finance_and_jev.py",dryRun:true,edits:[{oldText:"__r04_intentional_no_match_probe__",newText:"__r04_intentional_no_match_probe__"}]}).
- Expected caller error: the literal is absent, so reject the edit without mutation. Worker readback established atomic rejection and no applied edits. A missing literal is not itself a server defect.
- Observed server defect: the ordinary no-match error also exposes a full internal native Stack backtrace, including aws_lc_0_45_0_jent_entropy_switch_notime_impl and BaseThreadInitThunk. Impact: internal diagnostic disclosure and excessive output for an expected edit precondition failure; no source corruption is claimed.
- Safe fallback: reread a bounded exact current source range, then perform one verified literal edit and reread its result. Do not weaken required matching, add a product workaround, or run another intentional failure merely to duplicate the stack. Return a concise structured no-match error and keep internal frames in server logs.
- Preservation: ASCII inserted at the verified original EOF; preceding 328011 bytes had SHA-256 09a1d7c5bd33e5bf80f123372d90c3e750f0e68b029a3159d7ef085d6130104c. Verify that prefix after writing; keep all prior entries and legacy encoding. This external log is not part of the lgpt-rs R-04 commit.


## 2026-10-27 - lgpt-rs existing workspace/data disk lookup and stack-disclosure recurrence

- Evidence scope: root observed three failures and supplied the exact requests. This records another occurrence of the existing disk/path lookup and internal-stack disclosure issue; the documentation task does not repeat the failing calls.
- Exact reproduction: disk_usage({path:"C:/projects/projects.rust.cg/ai/lgpt-rs"}) and disk_usage({path:"D:/_ai/lgpt"}) each return "No disk found for path" plus a full internal native Stack backtrace. Repeating the C: workspace path with Windows backslashes also fails. Both nested paths were already established as existing by successful source/data reads or command cwd use; this is not an expected nonexistent-path input error.
- Observed impact: valid workspace/data capacity preflight fails and emits internal diagnostics. No deletion or source mutation resulted, and no disk-capacity effect is attributed to the failed requests.
- Safe fallback, observed successful: call disk_usage({}) and select the returned C:\ or D:\ mount. Root's 2026-10-27 available-byte snapshot was C:198247870464 (184.63 GiB), D:344383950848 (320.73 GiB). No cleanup was needed. These are dated observations, not reservations; remeasure before later large work or owned-temp cleanup.
- Preservation: ASCII inserted at verified EOF; preceding 329856 bytes had SHA-256 c4438c1aad6aced34dc4255b936ab028f5a110f7d34680e177f28d99475b8548. Verify that prefix after writing. Keep all existing entries and legacy encoding; this external report is not an lgpt-rs source commit.


## 2026-10-27 - render-rs dry-run edit no-match exposes native stack

- Evidence scope: raster owner reproduced this expected-input failure twice and recorded artifact e55e267d-0fa0-4516-8cba-fa24137bdf64 in workspace render-rs, actor codex. The documentation owner read that record; no additional failing source edit is required.
- Exact safe reproduction: edit_file({path:"C:/projects/projects.rust.cg/cglibs/render-rs/crates/render-engine-pbr/src/pipelines.rs",dryRun:true,edits:[{oldText:'format!("{}\\n{}\\n{}", BRDF_LIB_WGSL, render_env::ENV_SAMPLE_WGSL, PBR_SHADER)',newText:"unused reproduction"}]}). At reproduction time rustfmt had split the format! call across lines, so the single-line literal had zero matches.
- Expected caller error: reject the absent literal without mutation. dryRun:true does not authorize any source write. The unmatched literal itself is not a server defect.
- Observed server defect: MCP -32603, "Failed to apply edits: 1 of 1 edits produced zero matches", followed by a full internal Stack backtrace (frames 0-25), including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart. This repeats the existing no-match diagnostic-disclosure defect.
- Impact: routine edit validation is elevated to an internal-error response and floods output with native implementation details. No source corruption is claimed.
- Safe fallback: reread the formatted current source, use the exact verified multiline needle, inspect the returned diff and reread the result. Keep filesystem MCP access; do not weaken the matching precondition or add a renderer workaround. Return concise structured no-match diagnostics and keep native traces in server logs.
- Preservation: appended ASCII bytes at the current verified EOF; the append operation checks that the entire prior byte prefix is unchanged. All existing entries and legacy encoding remain intact.


## 2026-10-27 - render-rs long operations outlive the host MCP deadline

- Evidence scope: coordinator observations; this report does not repeat heavy indexing/search requests. Exact index request: run_command({command:"gitnexus-rs",args:["analyze","C:/projects/projects.rust.cg/cglibs/usd-rs","--force"],cwd:"C:/projects/projects.rust.cg/cglibs/usd-rs",mode:"managed",timeoutMs:1200000}). The host returned "timed out awaiting tools/call after 300s" plus a full native Stack backtrace, while owned PID 25184 continued. Later process completion and graph_status confirmed HEAD cfcfaa8 indexed at 2026-10-27T10:52:37.
- Search observations: search_files under C:/projects/projects.rust.cg for **/CubeCL*/Cargo.toml, excluding target/.git/node_modules, hit the host 300-second deadline and emitted a native stack. The separate scoped cglibs search for **/cubecl-wgpu/Cargo.toml completed normally with no matches; it was not a second failure. Scoped inventory/preparation subsequently supplied the dependency source.
- Classification: an expected long-work/deadline limit may explain the timeout. The scheduling/server root cause is unproven. Observed issues are excessive internal-stack disclosure and loss of an actionable progress/process handle when an operation can continue beyond the host response. A timeout alone does not prove the filesystem server failed or the operation stopped.
- Impact: blind retries can repeat expensive work or overlap an index still running; diagnostics flood output and do not establish completion.
- Safe fallback: use scoped inventory and shorter managed steps; retain log paths and known owned process IDs, then poll logs/process state and graph_status before retrying. Preserve unrelated processes, never kill bun or arbitrary processes, and do not repeat a full index solely because the host call timed out.
- Preservation: ASCII appended through a locked stream; the entire prior byte prefix and SHA-256 are checked unchanged after writing. Existing entries and legacy encoding remain intact.


## 2026-10-27 - lgpt-rs recurrence of existing grep_context validation stack disclosure

- Existing class: the grep_context missing-nearbyPatterns entries above (including 2026-09-28 and 2026-10-12); this is another exact reproduction, not a new defect class.
- Exact reproduction, reported by /root/reviewer_ati03 and not rerun by documentation: grep_context({path:'C:/projects/projects.rust.cg/ai/lgpt-rs/docs/bughunt/analytic-2026-10-26-train-io.md',pattern:'A-TI-03|sampler|identity',contextBefore:3,contextAfter:7,maxResults:20}).
- Expected caller error: the request omits required nonempty nearbyPatterns and uses plain-search window fields; concise MCP -32602 empty-nearbyPatterns validation is expected. This wrong-schema call is not a search/server-logic defect.
- Observed server defect/impact: the validation response additionally discloses a full internal Stack backtrace through BaseThreadInitThunk/RtlUserThreadStart, producing excessive internal diagnostics during read-only review. No file mutation or product execution is claimed.
- Safe fallback: grep_files for the plain pattern, then read_text_file for the bounded relevant lines; if contextual matching is needed, use verified nonempty nearbyPatterns and documented window arguments. Do not rerun the malformed request or flood the console with the stack.


## 2026-10-27 - lgpt-rs recurrence of original-content batch no-match stack disclosure

- Existing class: atomic edit_file zero-match/internal-stack disclosure already recorded above (including dependent-original-content cases). This entry records another exact bounded request shape, not a new root cause.
- Evidence: /root/fix_ati04 supplied the actual request below and verified atomic readback; documentation did not rerun it. Date only: an earlier approximate clock time was not verified.
- Request shape: tools.mcp__filesystem_mcp_rs__edit_file({path:"C:/projects/projects.rust.cg/ai/lgpt-rs/crates/train/src/lib.rs",edits:[{oldText:"    /// R5 (`K03_PLAN` 1.3): a killed run",newText:{kind:"inline",text:<new ignored fixtures + original R5 prefix>}},{oldText:"            let mut current = || Trainer::new(",newText:"            let current = || Trainer::new("},{oldText:"            let mut repeated = Trainer::new(leftover, cfg.clone(), tcfg.clone()).unwrap();",newText:"            let repeated = Trainer::new(leftover, cfg.clone(), tcfg.clone()).unwrap();"}]}). The angle-bracket insertion is an intentionally symbolic payload description, not a fabricated full fixture body.
- Expected caller error: edit 3 matched only text introduced by edit 1, while batch literals match ORIGINAL file content independently. Rejecting that absent literal atomically is correct user-precondition handling. Worker readback confirmed neither the first fixture insertion nor the current cleanup applied; no partial edit or data loss is claimed.
- Observed server defect/impact: the routine no-match response also returned a full native Stack backtrace (frames 0-25, aws_lc entropy symbol and Windows thread entrypoints including BaseThreadInitThunk), disclosing internal diagnostics and generating excessive output. This is the recurring server defect, not incorrect atomic matching.
- Safe fallback: reread the original file, apply only independent verified original-text edits in one batch, and apply dependent edits sequentially after rereading each result. The worker reports that corrected original-text edits were applied afterward. Do not rerun the malformed request or print the full stack.


## 2026-10-27 - render-rs recurrence of original-content batch no-match stack disclosure

- Existing class: atomic edit_file no-match validation leaking an internal native backtrace; this is another observed request, not a new matching defect.
- Evidence: the render-rs coordinator supplied the actual 12-edit request and verified unchanged source after rejection. Documentation did not rerun it. Relevant request entries for C:/projects/projects.rust.cg/cglibs/render-rs/crates/render-engine-pt/pt-renderer/src/scene.rs were edit 10 {oldText:"PtScene::build_two_level(&meshes)",newText:"PtScene::build_two_level(&meshes, true)",replaceAll:true} and edit 12 {oldText:"let compact = PtScene::build_two_level(&meshes, true);",newText:"let compact = PtScene::build_two_level(&meshes, false);"}. The other entries independently changed scene packing.
- Expected caller error: edit 12 matched text that edit 10 would introduce, while batch literals are matched against original content. Atomic rejection with zero matches for edit 12 is correct; readback confirmed none of the batch applied. No partial write or source corruption is claimed.
- Observed server defect/impact: MCP -32603 "Failed to apply edits: 1 of 12 edits produced zero matches" was followed by full native Stack backtrace frames 0-25, including aws_lc_0_45_0_jent_entropy_switch_notime_impl, BaseThreadInitThunk and RtlUserThreadStart. Routine precondition failure flooded output with implementation details.
- Safe fallback, observed successful: reread current source, apply independent original-text edits together, then apply dependent edits sequentially and verify each result. Keep filesystem MCP access; do not weaken exact-match checks or rerun this malformed request. Keep native traces in server logs and return concise structured validation diagnostics.

## 2026-10-27 - render-rs recurrence of grep_context missing-nearbyPatterns stack disclosure

- Existing class: missing required nearbyPatterns is an expected grep_context schema error; internal-stack disclosure is the server defect. The same class is already recorded above for other sessions.
- Exact observed request shapes, reported by resource_admission: grep_context({path:"C:/projects/projects.rust.cg/cglibs/render-rs/crates/render-engine-pt/pt-core/src/gpu_data.rs",pattern:"pub struct GpuTriangleSceneData",contextLines:18,maxMatches:2}) and the same request with pattern:"pub struct RefitRanges". Both omitted required nearbyPatterns. Documentation did not reproduce either malformed call.
- Observed response/impact: expected MCP -32602 input validation additionally exposed a full native Stack backtrace, frames 0-25. No search-logic defect, source mutation or data loss is inferred from the invalid requests.
- Safe fallback, observed successful: use grep_files for an ordinary symbol search, then bounded read_text_file for its surrounding source. For actual contextual matching, first verify the tool schema and supply nonempty nearbyPatterns. Do not print the full trace or repeat invalid calls.
- Preservation for both entries: append ASCII at the exclusively locked current EOF and verify the entire preceding byte prefix and SHA-256 are unchanged. Keep all prior entries and legacy encoding.
