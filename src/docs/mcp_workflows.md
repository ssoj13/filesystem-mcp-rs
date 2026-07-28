### Common workflows (filesystem MCP)

**Paths by glob + metadata** → `search_files`. **Text inside files** → `grep_files` (not shell `rg`/`grep` via `run_command`).

#### `search_files` — files changed in a time window

`modifiedAfter` / `modifiedBefore`: **RFC3339** (`2024-01-01T12:00:00Z`) or **relative duration** (`17m 20s`, `17m20s`, `2h`, `7d`). Duration = cutoff at `now - span`.

| Goal | Parameters |
|------|------------|
| Touched in the last 17 minutes 20 seconds | `"modifiedAfter": "17m 20s"` |
| Older than 7 days | `"modifiedBefore": "7d"` |
| Between 1 hour and 10 minutes ago | `"modifiedAfter": "1h"`, `"modifiedBefore": "10m"` |

```json
{
  "path": ".",
  "pattern": "**/*",
  "fileType": "file",
  "excludePatterns": ["target/**", "node_modules/**"],
  "modifiedAfter": "17m 20s"
}
```

Also: `minSize` / `maxSize` (bytes), `fileType` (`file` | `dir` | `symlink` | `any`). Matches include `modified` (unix seconds).

#### `grep_files` — regex in file contents

```json
{
  "path": "src",
  "pattern": "TODO|FIXME",
  "filePattern": "**/*.rs",
  "excludePatterns": ["target/**"]
}
```

#### `read_text_file` — large logs / sources

`head`, `tail`, `offset` + `limit`, or `max_chars` — avoid loading entire huge files into context.

#### `run_command` — builds and noisy output

Keep `streamOutput: true` (default); read `stdoutFile` / `stderrFile` with `tail_file` or `read_text_file`. Long builds: `mode: "managed"`, `outputFilter` with error/warning regex. Shell pipelines: `shell: true`.

#### Session reminder

One MCP tool call = **MCP-only** for file/shell work until the task ends. Do not mix built-in Read/Grep/Shell with this server on the same paths. **Do not guess the code — re-check everything.**
