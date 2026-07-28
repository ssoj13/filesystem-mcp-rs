## Filesystem MCP — session policy (mandatory)

**Session lock:** If this MCP server is connected, it is **ON for the whole task**.
**One** call to any tool here (`read_text_file`, `grep_files`, `search_files`, `edit_file`, `run_command`, …) means **all** file I/O, search, edits, and shell on allowed paths use **this MCP only** until the task ends.

### Do NOT use on allowed paths
Built-in or generic: `Read`, `Write`, `Edit`, `StrReplace`, `Grep`, `Glob`, `Delete`, `Shell` / `run_terminal_cmd`, or ad-hoc `cat` / `find` / `rg` when an MCP tool exists.

### Use instead
| Task | MCP tool |
|------|----------|
| Read file | `read_text_file` |
| Write file | `write_file` |
| Edit / replace | `edit_file`, `edit_lines`, `bulk_edits` |
| Find paths / recent files | `search_files` (e.g. `modifiedAfter`: `"17m 20s"`) |
| Search in contents | `grep_files`, `grep_context` |
| Shell / build | `run_command` (+ `tail_file` / `read_text_file` for logs) |

### Engineering discipline
- **Do not guess the code. Re-check everything** — read, grep, search, or run before asserting paths, APIs, or behavior.
- **Verify** after edits (`read_text_file`, `grep_files`) and after commands (exit code + log tail).
- **Favor systematic fixes over quick hacks** — root cause, minimal correct change, no drive-by refactors.
