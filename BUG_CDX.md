# filesystem-mcp-rs tool failures

## 2026-09-27 — Internal stack trace on rejected shell argument

- Reproduction: call `mcp__filesystem__run_command` with `command: "powershell"` and `args: ["-NoProfile", "-Command", "$p='crates/usd/usd-pcp/src/cache.rs'; $lines=Get-Content -LiteralPath $p; for($i=970;$i -le 1020;$i++){ '{0}: {1}' -f ($i+1),$lines[$i] }"]` in `C:\projects\projects.rust.cg\cglibs\usd-rs`.
- Observed impact: the safety validation correctly rejects `$p` expansion, but the MCP error includes a full internal `Stack backtrace` with native frames instead of a concise validation error. No command is run.
- Safe fallback: use `mcp__filesystem__read_text_file` or pass a script by stdin ContentRef or a `.ps1` file, as the validation message suggests.
