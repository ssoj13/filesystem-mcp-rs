# filesystem-mcp-rs tool failures

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

## 2026-09-29 — `edit_file` stale plan-tail anchor returns internal stack trace

## 2026-09-29 — `edit_file` unmatched Nova source anchors leak internal stack traces

- **Reproduction:** In `nova-linux-rs/nova/src/main.rs`, call `mcp__filesystem_mcp_rs__edit_file` with a batch containing the literal anchors `mod linux {\\n    use std::collections::BTreeMap;` and `             nova runtime-import <rootfs> <lock> <store>\\n\\\\n`. Neither anchor matches the actual newline / Rust line-continuation characters in the file. The server reports “2 of 3 edits produced zero matches” and returns full internal Rust frames. A second no-match call against `.gitignore` used `Thumbs.db\\n.gitnexus/` and similarly returned a full stack trace. The failed calls left all target files unchanged.
- **Observed impact:** The malformed escape sequences are caller errors; exposing internal stack frames for ordinary no-match validation is a filesystem MCP server defect. No partial source mutation occurred.
- **Safe fallback:** Re-read exact text, use a single exact anchor at a time, verify each result, and return a concise mismatch error without internal frames.

## 2026-09-29 — `edit_file` stale plan-tail anchor returns internal stack trace

- **Reproduction:** Call `mcp__filesystem__edit_file` for `rez-rs/plan14.md` replacing its old compatibility statement containing “vendored Rez 3.3.0 evidence”. That statement had already been updated in an earlier successful edit. The server returns a no-match validation response and internal Rust frames; the failed request leaves the plan unchanged, as confirmed by reading its tail.
- **Observed impact:** Reusing an obsolete anchor is caller error; leaking internal frames is an MCP server defect. No file change occurred.
- **Safe fallback:** Re-read the relevant section immediately before editing and skip changes already present.
