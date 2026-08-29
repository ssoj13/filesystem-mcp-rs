## Filesystem MCP — session policy (mandatory)

**Session lock:** If this MCP server is connected, it is **ON for the whole task**.
**One** call to any tool here (`read_text_file`, `grep_files`, `search_files`, `edit_file`, `run_command`, …) means **all** file I/O, search, edits, and shell on allowed paths use **this MCP only** until the task ends.

### Do NOT use on allowed paths
Built-in or generic: `Read`, `Write`, `Edit`, `StrReplace`, `Grep`, `Glob`, `Delete`, `Shell` / `run_terminal_cmd`, or ad-hoc `cat` / `find` / `rg` when an MCP tool exists.

### CallMcpTool wiring (host)
Every MCP tool invocation must pass top-level **`server`** and **`toolName`** (required by the host). Omitting them yields intermittent errors like `server: Required` / `toolName: Required` — that is host/agent wiring, not a filesystem-mcp-rs bug. Never put those keys only inside `arguments`.

### Use instead
| Task | MCP tool |
|------|----------|
| Read file | `read_text_file` |
| Write file | `write_file` |
| Edit / replace | `edit_file`, `edit_lines`, `bulk_edits` |
| Find paths / recent files | `search_files` (e.g. `modifiedAfter`: `"17m 20s"`) |
| Search in contents | `grep_files`, `grep_context` |
| Shell / build | `run_command` (+ `tail_file` / `read_text_file` for logs) |


### Content Plane (large payloads)
Do **not** put large source into JSON tool args. Use:
1. `blob_begin` → `blob_append` (≤64 KiB chunks) → `blob_finalize` → `{kind:"blob", id}`
2. Or `{kind:"path", path}` for an allowlisted file already on disk
3. Small text only: `{kind:"inline", text}` (hard max 64 KiB)

`write_file` / `edit_file` / `run_command.stdin` / `write_binary` all take **ContentRef** objects — never bare mega-strings. Never patch large files via `python -c`.

### Engineering discipline
- **Do not guess the code. Re-check everything** — read, grep, search, or run before asserting paths, APIs, or behavior.
- **Verify** after edits (`read_text_file`, `grep_files`) and after commands (exit code + log tail).
- **Favor systematic fixes over quick hacks** — root cause, minimal correct change, no drive-by refactors.
