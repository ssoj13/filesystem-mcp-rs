# filesystem-mcp-rs

This is a Rust port of the [official JavaScript filesystem MCP server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem).
I did it for a number of reasons: partially for training both with MCPs and Rust,
partially because original version never worked for me in Codex and I wanted something that works everywhere,
and something I can control and fix and add some new features.

Rust allows for supereasy combining of any crates, so when I ported/created a dozen of MCPs, I decided to just merge some of them into a single useful toolkit.
It's not about "memory safety" or something like that, I'm doing that just because I can and having fun doing that.


To the bone:

> **Breaking — Content Plane SSOT.** `write_file` / `edit_file` / `write_binary` / `run_command.stdin` take a **ContentRef** object (`inline` / `base64` / `path` / `blob`), not a bare mega-string. Large payloads: `blob_begin` → `blob_append` (≤8 KiB) → `blob_finalize` → `{kind:"blob",id}`. Never `python -c` to dodge JSON. See [CHANGELOG.md](CHANGELOG.md).
>
> **`read_pdf` tells you when extraction is junk.** Default `normalize=true` repairs ZWSP / spaced glyphs; structured `quality.score` / `warnings` / `suspiciousTokens` flag broken ToUnicode maps — low score means do not treat the text as source of truth.
>
> **`edit_lines` no longer mangles range replaces** — snake_case keys like `end_line` / `dry_run` are accepted alongside camelCase (`endLine`, `dryRun`); overlapping edits fail up front instead of leaving a broken tail. Same alias pattern on `edit_file` / `extract_*` / `bulk_edits`. See [CHANGELOG.md](CHANGELOG.md).
>
> **v0.1.17** — **Scoped memory is stricter.** Memory tools now use a clear, flat shape (`workspaceId`, `actorId`, `item`). Old shortcuts like `"scope": "my-project"` no longer work — update your calls once and you get predictable behavior. Summaries default to the whole workspace, so a simple recall call works without extra IDs.
>
> **MCP session lock** — After any tool call, the server reminds the agent to keep using filesystem-mcp-rs for file and shell work (instead of built-in editor tools). That reduces “it worked in chat but broke on disk” drift. Install also embeds the same policy into client config files (`CLAUDE.md`, `AGENTS.md`, etc.).
>
> **`run_command` is easier for agents to get right** — snake_case options are accepted alongside camelCase; head/tail/filter output is reliable again; tool descriptions now spell out that paths like `cwd` must be quoted JSON strings. **`install`** sets permissive HTTP/S3 allowlists by default so outbound tools work out of the box (you can tighten them later).
>
> See [CHANGELOG.md](CHANGELOG.md) for the full list and migration examples.
>
> **v0.1.10–0.1.16** — A big stretch of quality-of-life work: a much stronger **`run_command`** (sync / managed / detached modes, progress during long builds, filtered output, safer process cleanup), **system utilities** (ports, processes, disk, env, diffs), optional **HTTP / S3 / screenshots**, **LLM / Excel / Word** helpers, **flexible JSON parsing** so common agent mistakes don’t fail the call, plus faster **hashing** and better **client compatibility** (Gemini, Qwen). See [CHANGELOG.md](CHANGELOG.md).
>
> **v0.1.8 and earlier** — Core filesystem tools, comparison, archives, watching files, and early process support. See CHANGELOG.md.

**LLM-friendly type coercion**: All parameters use flexible types that tolerate common LLM serialization quirks:
- **Numbers**: `42` and `"42"` both work (`FlexU32`, `FlexUsize`, etc.)
- **Booleans**: `true`, `"true"`, `"1"`, `1` all accepted (`FlexBool`)
- **Arrays**: `["a"]`, `"a"`, or a JSON string of an array (`vec_or_string`)
- **Nested objects/maps**: JSON object **or** JSON string containing that object — e.g. `run_command.outputFilter`, HTTP `headers` (not `mem_*` since 0.1.17)
- **Memory v2 (0.1.17+)**: strict flat args — `workspaceId`, `actorId`, `item` object only; see [CHANGELOG.md](CHANGELOG.md) for migration

## Capabilities
- Read: `read_text_file` (head/tail/offset/limit/max_chars/line_numbers), `read_media_file`, `read_multiple_files`, `read_json` (JSONPath), `read_pdf` (normalize + quality warnings)
- Write/Edit: `write_file`, `edit_file` (ContentRef + diff/dry-run), `edit_lines`, `bulk_edits`; large payloads via `blob_begin`/`blob_append`/`blob_finalize`
- Extract: `extract_lines` (cut lines), `extract_symbols` (cut characters)
- Binary: `read_binary`, `write_binary` (ContentRef), `extract_binary`, `patch_binary`
- FS ops: `create_directory`, `move_file`, `copy_file` (files/dirs, overwrite), `delete_path` (recursive)
- Hashing: `file_hash` (MD5/SHA1/SHA256/SHA512/XXH64/Murmur3/Spooky + offset/length), `file_hash_multiple` (batch + comparison)
- Comparison: `compare_files` (binary diff), `compare_directories` (tree diff)
- Archives: `archive_extract` (ZIP/TAR/TAR.GZ), `archive_create`
- Watch: `tail_file` (follow mode), `watch_file` (change events)
- Stats: `file_stats` (size/count by extension), `find_duplicates`
- Introspection: `list_directory`, `list_directory_with_sizes`, `get_file_info`, `directory_tree` (depth/size/hash)
- Search/roots: `search_files` (glob + type/size/time filters), `grep_files` (regex + exclude + invert/count modes), `grep_context` (context-aware), `list_allowed_directories`
- **Session lock:** any MCP tool call → use this server only for file/shell on allowed paths (built-in Read/Grep/Shell forbidden). **Do not guess the code — re-check everything.** Favor systematic fixes over quick hacks. Every tool response includes a reminder; `mcp-setup` embeds Karpathy rules + policy into `CLAUDE.md` / `AGENTS.md` at install.
- Process: `run_command` (3 modes: sync/managed/detached, progress heartbeat, output filter, shell mode, process tree kill), `kill_process` (tree kill), `list_processes`, `search_processes`
  - **`run_command` JSON**: use **camelCase** keys (`streamOutput`, `timeoutMs`) or **snake_case** aliases (`stream_output`, `timeout_ms`). `args` may be an array or a JSON string. **`cwd` must be a quoted string** — e.g. `"C:/projects/repo"` (forward slashes). Unquoted `C:\...` is invalid JSON and fails in the MCP client before the server runs.
- Network (feature): `http_request`, `http_request_batch`, `http_download`, `http_download_batch`
- S3 (feature): `s3_list_buckets`, `s3_list`, `s3_stat`, `s3_get`, `s3_put`, `s3_delete`, `s3_copy`, `s3_presign`, batch ops
- Screenshot (feature): `screenshot_list_monitors`, `screenshot_list_windows`, `screenshot_capture_screen`, `screenshot_capture_window`, `screenshot_capture_region`, `screenshot_copy_to_clipboard`
- Safety: allowlist/roots validation, escape protection, optional `--allow_symlink_escape`
- Wave2: `port_users`, `net_connections`, `port_available`, `proc_tree`, `proc_env`, `proc_files`, `disk_usage`, `sys_info`, `file_diff`, `file_touch`, `clipboard_*`, `env_*`, `which`
- Document: `xlsx_read`, `xlsx_info` (Excel), `docx_read`, `docx_info` (Word)
- AI/LLM: `ai_messages_gemini`, `ai_messages_cerebras`, `ai_messages_openai`, `ai_count_tokens_*` (needs API keys)
- Memory v2: `mem_put`, `mem_update`, `mem_link`, `mem_search`, `mem_get`, `mem_get_summary` with scoped SQLite-backed storage

## Environment Variables

### Core
| Variable | Description |
|----------|-------------|
| `FS_MCP_HTTP_ALLOW_LIST` | HTTP allowlist domains (comma/semicolon/whitespace separated). Use `*` to allow all |
| `FS_MCP_S3_ALLOW_LIST` | S3 allowlist buckets (comma/semicolon/whitespace separated). Use `*` to allow all |
| `FS_MCP_MEMORY_DB` | Memory database path (default: system data dir) |
| `FS_MCP_MEMORY_ACCESS_MODE` | Memory access mode: `enforce_private_only` (default), `allow_all`, or `enforce_visibility` |
| `DISABLE_THOUGHT_LOGGING` | Set to `true` to disable thought logging |

### LLM API Keys
| Variable | Description |
|----------|-------------|
| `LLM_MCP_GEMINI_API_KEY` | Gemini API key (or use `GEMINI_API_KEY`) |
| `LLM_MCP_CEREBRAS_API_KEY` | Cerebras API key (or use `CEREBRAS_API_KEY`) |
| `LLM_MCP_OPENAI_API_KEY` | OpenAI API key (or use `OPENAI_API_KEY`) |

### LLM Configuration
| Variable | Description |
|----------|-------------|
| `LLM_MCP_PROVIDERS` | Comma-separated list of enabled providers |
| `LLM_MCP_PROVIDER` | Default provider name |
| `LLM_MCP_PROVIDER_ENDPOINT` | Custom API endpoint URL |
| `LLM_MCP_PROVIDER_API_KEY` | Generic API key (for custom providers) |
| `LLM_MCP_PROVIDER_API_KEY_HEADER` | Custom header name for API key (default: `Authorization`) |
| `LLM_MCP_PROVIDER_API_KEY_PREFIX` | API key prefix (default: `Bearer `) |
| `LLM_MCP_MODEL_MAPPING` | Model name mappings (JSON format) |
| `LLM_MCP_BIG_MODEL` | Alias for "big" model |
| `LLM_MCP_SMALL_MODEL` | Alias for "small" model |
| `LLM_MCP_MAX_TOKENS_LIMIT` | Maximum tokens limit |
| `LLM_MCP_REQUEST_TIMEOUT` | Request timeout in seconds |
| `LLM_MCP_MAX_RETRIES` | Maximum retry attempts |
| `LLM_MCP_MAX_STREAMING_RETRIES` | Maximum streaming retry attempts |
| `LLM_MCP_RETRY_BACKOFF_MS` | Retry backoff in milliseconds |
| `LLM_MCP_STREAMING_RETRY_BACKOFF_MS` | Streaming retry backoff in milliseconds |
| `LLM_MCP_FORCE_DISABLE_STREAMING` | Set to `true` to disable streaming |
| `LLM_MCP_EMERGENCY_DISABLE_STREAMING` | Emergency streaming disable flag |

## Feature Flags

HTTP/S3/screenshot tools are enabled by default. To disable, build with `--no-default-features`.

```bash
cargo build
```

HTTP/S3 tools require allowlists at runtime (CLI flags or env vars):
- `--http-allowlist-domain example.com --http-allowlist-domain "*.example.org"`
- `--s3-allowlist-bucket my-bucket`
Alternatively via env vars (comma/semicolon/whitespace separated):
- `FS_MCP_HTTP_ALLOW_LIST=example.com,*.example.org` (use `*` to allow all)
- `FS_MCP_S3_ALLOW_LIST=my-bucket;other-bucket` (use `*` to allow all)

`filesystem-mcp-rs install` (mcp-setup) writes `FS_MCP_HTTP_ALLOW_LIST=*` and `FS_MCP_S3_ALLOW_LIST=*` into client MCP config by default. Override with `--http-allowlist-domain` / `--s3-allowlist-bucket` or `--env FS_MCP_HTTP_ALLOW_LIST=...`.

## Memory v2

The server now uses scoped memory v2 by default with a local SQLite database at `memory2.db`.

Tools:
- `mem_put`
- `mem_update`
- `mem_link`
- `mem_search`
- `mem_get`
- `mem_get_summary`

Memory access modes:
- `enforce_private_only`
  - Default. Only `private` records are restricted to creator, owner, or `system`.
- `allow_all`
  - No ACL enforcement inside the requested scope.
- `enforce_visibility`
  - Full visibility enforcement for `private`, `session`, `topic`, `workspace`, `app`, `tenant`, and `public_read`.

CLI:
```bash
filesystem-mcp-rs --memory-db C:/data/memory2.db --memory-access-mode enforce_private_only
```

Environment:
```bash
FS_MCP_MEMORY_DB=C:/data/memory2.db
FS_MCP_MEMORY_ACCESS_MODE=enforce_visibility
```

MCP client config example:
```json
{
  "command": "filesystem-mcp-rs",
  "args": ["--memory-access-mode", "enforce_private_only"],
  "env": {
    "FS_MCP_MEMORY_DB": "C:/data/memory2.db"
  }
}
```

Recommended defaults:
- local/single-user: `enforce_private_only`
- most relaxed/shared setup: `allow_all`
- stricter collaborative setup: `enforce_visibility`

## Screenshot Tools

Tools: `screenshot_list_monitors`, `screenshot_list_windows`, `screenshot_capture_screen`, `screenshot_capture_window`, `screenshot_capture_region`, `screenshot_copy_to_clipboard`

**Examples:**
```json
// List monitors
{"tool": "screenshot_list_monitors", "arguments": {}}

// List windows with title filter
{"tool": "screenshot_list_windows", "arguments": {"title_filter": "Chrome"}}

// Capture primary monitor to a file
{"tool": "screenshot_capture_screen", "arguments": {"output": "file", "path": "C:/temp/screen.png"}}

// Capture a window by title to base64
{"tool": "screenshot_capture_window", "arguments": {"title": "Terminal", "output": "base64"}}

// Capture a region on monitor 0
{"tool": "screenshot_capture_region", "arguments": {"monitor_id": 0, "x": 100, "y": 100, "width": 800, "height": 600, "output": "file", "path": "C:/temp/region.png"}}

// Copy an existing PNG to clipboard
{"tool": "screenshot_copy_to_clipboard", "arguments": {"path": "C:/temp/region.png"}}
```

## Wave2 Tools (System Utilities)

Cross-platform tools for network, process, system info, and utilities.

### Network Tools

#### `port_users` - Find Processes Using a Port
```json
{"tool": "port_users", "arguments": {"port": 8080}}
// Returns: [{"pid": 1234, "name": "node", "local_addr": "127.0.0.1:8080", ...}]
```

#### `net_connections` - List Network Connections
```json
{"tool": "net_connections", "arguments": {}}
{"tool": "net_connections", "arguments": {"pid": 1234}}  // Filter by process
```

#### `port_available` - Check if Port is Free
```json
{"tool": "port_available", "arguments": {"port": 3000}}
// Returns: {"port": 3000, "available": true}
```

### Process Tools

#### `proc_tree` - Process Tree
```json
{"tool": "proc_tree", "arguments": {}}  // Full tree
{"tool": "proc_tree", "arguments": {"root_pid": 1234}}  // Subtree from PID
```

#### `proc_env` - Process Environment Variables
```json
{"tool": "proc_env", "arguments": {"pid": 1234}}
```

#### `proc_files` - Open Files by Process
```json
{"tool": "proc_files", "arguments": {"pid": 1234}}
// Linux: /proc/pid/fd, macOS: lsof, Windows: limited info
```

### System Tools

#### `disk_usage` - Disk Space Info
```json
{"tool": "disk_usage", "arguments": {}}  // All disks
{"tool": "disk_usage", "arguments": {"path": "C:/"}}  // Specific mount
```

#### `sys_info` - System Information
```json
{"tool": "sys_info", "arguments": {}}
// Returns: CPU cores, total/used RAM, swap, OS name/version, hostname, uptime
```

### File Tools

#### `file_diff` - Compare Files (Unified Diff)
Compare two files using the `similar` crate. Returns git-compatible unified diff:
```json
{"tool": "file_diff", "arguments": {"path1": "old.txt", "path2": "new.txt"}}
{"tool": "file_diff", "arguments": {"path1": "a.rs", "path2": "b.rs", "context": 5}}
```
Returns:
- `unified_diff`: Standard unified diff format (can be applied with `patch -p0`)
- `hunks`: Structured JSON with changes (type: insert/delete/context, line numbers)
- `additions`, `deletions`: Change counts

#### `file_touch` - Create/Update File Timestamp
```json
{"tool": "file_touch", "arguments": {"path": "marker.txt"}}
{"tool": "file_touch", "arguments": {"path": "deep/nested/file.txt", "create_parents": true}}
```

### Utility Tools

#### `clipboard_read` / `clipboard_write`
Requires `screenshot-tools` feature (uses arboard crate):
```json
{"tool": "clipboard_read", "arguments": {}}
{"tool": "clipboard_write", "arguments": {"text": "Hello clipboard"}}
```

#### `env_get` / `env_set` / `env_remove` / `env_list`
Environment variables (current process only):
```json
{"tool": "env_get", "arguments": {"name": "PATH"}}
{"tool": "env_set", "arguments": {"name": "MY_VAR", "value": "hello"}}
{"tool": "env_remove", "arguments": {"name": "MY_VAR"}}
{"tool": "env_list", "arguments": {}}
```

#### `which` - Find Executable in PATH
```json
{"tool": "which", "arguments": {"command": "python"}}
// Returns: {"command": "python", "found": true, "path": "/usr/bin/python", "all_matches": [...]}
```

## Document Tools

### `xlsx_read` / `xlsx_info` - Excel Files
Read Excel spreadsheets via calamine (supports .xlsx, .xls, .ods):
```json
{"tool": "xlsx_info", "arguments": {"path": "data.xlsx"}}
// Returns: sheet names, row/column counts

{"tool": "xlsx_read", "arguments": {"path": "data.xlsx"}}
{"tool": "xlsx_read", "arguments": {"path": "data.xlsx", "sheet": "Sheet2", "range": "A1:D10"}}
```

### `docx_read` / `docx_info` - Word Documents
Read Word documents via docx-lite:
```json
{"tool": "docx_info", "arguments": {"path": "doc.docx"}}
{"tool": "docx_read", "arguments": {"path": "doc.docx"}}
```

## AI/LLM Tools

Integrated from llm-mcp-rs. Requires API keys via environment variables.

### Providers
- **Gemini**: `GEMINI_API_KEY` or `LLM_MCP_GEMINI_API_KEY`
- **Cerebras**: `CEREBRAS_API_KEY` or `LLM_MCP_CEREBRAS_API_KEY`
- **OpenAI**: `OPENAI_API_KEY` or `LLM_MCP_OPENAI_API_KEY`

### Tools
```json
// Send messages to LLM
{"tool": "ai_messages_gemini", "arguments": {"model": "gemini-pro", "messages": "Hello", "max_tokens": 1000}}
{"tool": "ai_messages_openai", "arguments": {"model": "gpt-4", "messages": [...], "max_tokens": 2000}}

// Count tokens
{"tool": "ai_count_tokens_gemini", "arguments": {"model": "gemini-pro", "messages": "Text to count"}}
```

## Advanced Editing Tools

### Content Plane (`ContentRef`) — required for write/edit payloads

Large or nested UTF-8 must **not** ride inside MCP tool-argument JSON. Every write path takes a ContentRef object:

| `kind` | Shape | Limit / notes |
|--------|--------|----------------|
| `inline` | `{ "kind": "inline", "text": "..." }` | max 8 KiB UTF-8 |
| `base64` | `{ "kind": "base64", "data": "..." }` | max 8 KiB decoded |
| `path` | `{ "kind": "path", "path": "..." }` | allowlisted file on disk |
| `blob` | `{ "kind": "blob", "id": "<sha256>" }` | from `blob_finalize` |

**Staging large content:** `blob_begin` → `blob_append` (≤8 KiB per chunk, `text` or `dataBase64`) → `blob_finalize` → pass `{kind:"blob",id}` to `write_file` / `edit_file` / `run_command.stdin` / `write_binary`. Optional `expectSha256` on `write_file` / finalize. `blob_stat` checks a finalized id.

```json
{"path": "notes.txt", "content": {"kind": "inline", "text": "hello"}}
{"path": "big.rs", "content": {"kind": "blob", "id": "<sha256 from blob_finalize>"}}
```

### `edit_lines` - Line-Based Surgical Edits
Precise editing by line numbers (1-indexed). Perfect when you know exact locations:
- **Operations**: `replace`, `insert_before`, `insert_after`, `delete`
- **Supports**: Single lines or ranges (startLine-endLine)
- **Use cases**: Fixing specific lines, adding imports at known positions, removing exact code blocks
- **Features**: Returns unified diff, dry-run mode for preview

### `bulk_edits` - Mass Search/Replace Across Files
Apply the same edits to multiple files at once. More efficient than editing files individually:
- **File selection**: Glob patterns (e.g., `*.rs`, `**/*.txt`, `src/**/*.js`)
- **Operations**: Search/replace text across all matching files
- **Regex support**: `isRegex: true` enables regex patterns with capture groups (`$1`, `$2`, etc.)
- **Replace all**: `replaceAll: true` replaces ALL occurrences, not just the first one
- **Error handling**: Continues on failure, reports errors per-file
- **Use cases**: Renaming functions/variables across codebase, updating imports, fixing typos everywhere, refactoring patterns
- **Features**: Returns summary with diffs, dry-run mode for preview
- **failOnNoMatch**: If true, files without matches return errors (default false)

**Examples:**
```json
// Literal replace all occurrences
{"oldText": "use crate::foo", "newText": "use crate::bar::foo", "replaceAll": true}

// Regex with capture groups (refactor imports)
{"oldText": "use crate::(cache_man|event_bus|workers)", "newText": "use crate::core::$1", "isRegex": true, "replaceAll": true}

// Rename function across codebase
{"oldText": "old_function_name", "newText": "new_function_name", "replaceAll": true}

// Update version in all Cargo.toml
{"oldText": "version = \"0\\.1\\.\\d+\"", "newText": "version = \"0.2.0\"", "isRegex": true}
```

### `search_files` - Path Search (Glob + Time/Size/Type)

Find files and directories by **path pattern** and metadata (not by text inside files — use `grep_files` for that):

- **pattern**: glob (`**/*.rs`, `src/**/*.txt`)
- **excludePatterns**: e.g. `target/**`, `node_modules/**`
- **fileType**: `file`, `dir`, `symlink`, `any` (default)
- **minSize** / **maxSize**: bytes
- **modifiedAfter** / **modifiedBefore**: RFC3339 timestamp or relative duration (`17m 20s`, `17m20s`, `2h`, `7d`) — duration means cutoff at `now - span`

**Examples:**

```json
// All regular files touched in the last 17 minutes 20 seconds
{
  "path": ".",
  "pattern": "**/*",
  "fileType": "file",
  "excludePatterns": ["target/**", "node_modules/**"],
  "modifiedAfter": "17m 20s"
}

// Rust sources modified in the last hour
{
  "path": "src",
  "pattern": "**/*.rs",
  "modifiedAfter": "1h"
}

// Files older than 7 days
{
  "path": ".",
  "pattern": "**/*",
  "fileType": "file",
  "modifiedBefore": "7d"
}
```

### `grep_files` - Content Search
Search for text/regex patterns **inside** file contents (not filenames):
- **Supports**: Regex patterns, case-insensitive search, context lines
- **File filtering**: Optional glob include/exclude patterns to limit scope
- **Returns**: Matching lines with file paths and line numbers
- **Use cases**: Finding code patterns, locating function definitions, searching across codebase
- **Note**: Do not use `rg`/`grep` via `run_command`; use `grep_files` or `search_files` instead

**Example:**
```json
{
  "path": ".",
  "pattern": "TODO|FIXME",
  "filePattern": "**/*.rs",
  "excludePatterns": ["target/**", "**/*.generated.rs"]
}
```

### `grep_context` - Context-Aware Search
Find a pattern only when specific terms appear nearby:
- **Nearby terms**: `nearbyPatterns` list (literal by default, regex if `nearbyIsRegex` true)
- **Window**: `nearbyWindowWords` and/or `nearbyWindowChars`
- **Direction**: `nearbyDirection` = before/after/both
- **Match mode**: `nearbyMatchMode` = any/all

**Example:**
```json
{
  "path": ".",
  "pattern": "error",
  "nearbyPatterns": ["timeout", "retry"],
  "nearbyWindowWords": 6,
  "nearbyDirection": "before",
  "filePattern": "**/*.log"
}
```

### `read_text_file` - Pagination for Large Files
Read files with flexible pagination options for handling large files:
- **`head`**: First N lines (like Unix head)
- **`tail`**: Last N lines (like Unix tail)
- **`offset` + `limit`**: Read N lines starting from line M (1-indexed pagination)
- **`max_chars`**: Truncate output to N characters (UTF-8 safe)
- **Returns**: `totalLines` in metadata for pagination planning

**Examples:**
```json
// Read lines 100-199 (page 2 with 100 lines per page)
{"path": "large.txt", "offset": 100, "limit": 100}

// First 50 lines
{"path": "large.txt", "head": 50}

// Last 20 lines
{"path": "large.txt", "tail": 20}

// Limit output size (useful for token limits)
{"path": "large.txt", "max_chars": 50000}

// Combine pagination with truncation
{"path": "large.txt", "offset": 1, "limit": 100, "max_chars": 10000}
```

## Extract Tools

### `extract_lines` - Cut Lines by Number
Remove lines from a file and optionally return extracted content:
- **Parameters**: `path`, `line` (1-indexed), `endLine` (optional), `dryRun`, `returnExtracted`
- **Examples**: Delete line 5, remove lines 10-20, preview deletion
- **Use cases**: Remove imports, delete code blocks, cut sections to paste elsewhere

### `extract_symbols` - Cut Characters by Position
Remove characters from a file by Unicode position:
- **Parameters**: `path`, `start` (0-indexed), `end` or `length`, `dryRun`, `returnExtracted`
- **Note**: Uses Unicode chars (safe for multibyte), not raw bytes
- **Use cases**: Remove headers, cut text blocks, extract specific ranges

## Binary Tools

All binary tools use base64 encoding for data transfer.

### `read_binary` - Read Bytes
Read bytes from a binary file at specified offset:
- **Parameters**: `path`, `offset`, `length`
- **Returns**: Base64-encoded data
- **Use cases**: Read binary headers, extract sections of images/executables

### `write_binary` - Write Bytes
Write bytes to a binary file:
- **Parameters**: `path`, `offset`, `data` (ContentRef in binary mode), `mode` (replace/insert)
- **Creates file if missing**
- **Use cases**: Patch executables, inject data, modify headers

### `extract_binary` - Cut Bytes
Remove bytes from a binary file and return them:
- **Parameters**: `path`, `offset`, `length`, `dryRun`
- **Returns**: Base64-encoded extracted data
- **Use cases**: Remove binary sections, cut data to relocate

### `patch_binary` - Find/Replace Binary Patterns
Search and replace binary patterns in a file:
- **Parameters**: `path`, `find` (base64), `replace` (base64), `all`
- **Use cases**: Patch executables, fix binary data, search-replace in non-text files

## Hashing Tools

### `file_hash` - Hash a File
Compute hash of a file with various algorithms:
- **Parameters**: `path`, `algorithm`, `offset`, `length`
- **Algorithms**: md5, sha1, sha256 (default), sha512, xxh64, murmur3, spooky
- **Returns**: `{hash, size, algorithm, offset, length}`
- **Partial hashing**: Use offset/length to hash only a portion of the file
- **Non-crypto**: murmur3/spooky are 128-bit fast hashes (great for checksums, deduplication)
- **Use cases**: Verify file integrity, detect changes, compare files without reading content

**Examples:**
```json
// Hash entire file with SHA256
{"path": "file.bin"}

// Hash with fast non-crypto algorithm
{"path": "large.bin", "algorithm": "xxh64"}

// Hash first 1KB only
{"path": "file.bin", "offset": 0, "length": 1024}

// Hash from position 512 to end
{"path": "file.bin", "offset": 512}
```

### `file_hash_multiple` - Hash Multiple Files
Hash multiple files and check if they match:
- **Parameters**: `paths[]`, `algorithm`
- **Returns**: `{results[], all_match}`
- **Use cases**: Verify file copies, check backup integrity, detect duplicate content

## Comparison Tools

### `compare_files` - Binary File Comparison
Compare two files byte-by-byte with detailed analysis:
- **Parameters**: `path1`, `path2`, `offset1`, `offset2`, `length`, `max_diffs`, `context_bytes`
- **Returns**: `{identical, size1, size2, hash1, hash2, first_diff_offset, total_diff_regions, match_percentage, diff_samples[]}`
- **Use cases**: Verify export/conversion parity, debug serialization, find binary differences

### `compare_directories` - Directory Tree Comparison
Compare two directory trees recursively:
- **Parameters**: `path1`, `path2`, `recursive`, `compareContent` (hash-based), `ignorePatterns[]`
- **Returns**: `{identical, only_in_first[], only_in_second[], different[], same_count, diff_count}`
- **Use cases**: Sync verification, backup validation, migration testing

## Watch Tools

### `tail_file` - Read End of File
Read the last N lines or bytes of a file:
- **Parameters**: `path`, `lines`, `bytes`, `follow`, `timeout_ms`
- **Returns**: `{content, lines_returned, file_size, truncated}`
- **Follow mode**: Wait for new content to be appended
- **Use cases**: Log monitoring, watching build output, debugging

### `watch_file` - Wait for File Changes
Block until a file changes or timeout:
- **Parameters**: `path`, `timeout_ms`, `events[]` (modify/create/delete)
- **Returns**: `{changed, event, new_size, elapsed_ms}`
- **Use cases**: Wait for build artifacts, monitor config changes

## JSON & PDF Tools

### `read_json` - Read JSON with Query
Read and query JSON files using JSONPath:
- **Parameters**: `path`, `query` (JSONPath like `$.store.book[0].title`), `pretty`
- **Returns**: `{result, query_matched, pretty}`
- **Use cases**: Extract config values, query API responses, parse structured data

### `read_pdf` - Extract PDF Text
Extract text content from PDF files:
- **Parameters**: `path`, `pages` (e.g., "1-5", "1,3,5"), `maxChars`, `normalize` (default true), `includeRaw` (default false)
- **Returns**: `{text, pagesCount, pagesExtracted[], truncated, charCount, normalized, quality{score, warnings, suspiciousTokens, ...}}`
- **Quality**: low `quality.score` or warnings like `extraction_quality_degraded` mean encoding maps failed — verify against a PDF viewer before trusting names/tables
- **Use cases**: Read documentation, extract report content

## Archive Tools

### `archive_extract` - Extract Archives
Extract ZIP, TAR, or TAR.GZ archives:
- **Parameters**: `path`, `destination`, `format` (auto-detect by extension), `files[]` (optional filter)
- **Returns**: `{extracted_count, files[]}`
- **Use cases**: Unpack downloads, extract specific files from archives

### `archive_create` - Create Archives
Create ZIP or TAR.GZ archives:
- **Parameters**: `paths[]`, `destination`, `format` (zip/tar.gz)
- **Returns**: `{path, size, file_count}`
- **Use cases**: Package files for backup, create distribution archives

## Statistics Tools

### `file_stats` - File/Directory Statistics
Get detailed statistics about files and directories:
- **Parameters**: `path`, `recursive`
- **Returns**: `{total_files, total_dirs, total_size, total_size_human, by_extension{}, largest_files[]}`
- **Use cases**: Analyze project size, find large files, understand codebase composition

### `find_duplicates` - Find Duplicate Files
Find files with identical content:
- **Parameters**: `path`, `min_size`, `by_content` (hash-based or size-only)
- **Returns**: `{duplicate_groups[], total_wasted_space}`
- **Use cases**: Cleanup disk space, find redundant files

## Process Management Tools

### `run_command` - Execute Commands with Full Lifecycle Control
Robust process execution for LLM workflows. Cross-platform (Windows/macOS/Linux).

**Execution modes (`mode`):**
| Mode | Behavior |
|------|----------|
| `sync` (default) | Wait for completion. Sends progress heartbeat every ~30s to prevent MCP client timeout. |
| `managed` | Wait for completion. Sends progress notifications with output snippets every ~10s. |
| `detached` | Return immediately with PID. Use `tail_file` on log files for output. |

**Parameters:**
- **Core**: `command`, `args[]`, `cwd`, `mode`, `shell`, `timeoutMs`, `killAfterMs`
- **Environment**: `env{}` (set/override), `envPrepend{}` (prepend to existing), `envAppend{}` (append to existing), `clearEnv`
- **Stdin**: `stdin` ContentRef (`inline`/`base64`/`path`/`blob`)
- **Output files**: `stdoutFile`, `stderrFile`, `streamOutput` (default: true), `streamDir`
- **Output control**: `stdoutHead`, `stdoutTail`, `stderrHead`, `stderrTail`
- **Output filter**: `outputFilter: {include[], exclude[], context, contextBefore, contextAfter, maxLines}` (grep-like regex filtering)

**Returns:** `{exitCode, stdout, stderr, pid, killed, timedOut, cancelled, durationMs, background, startedAt, finishedAt, stdoutFile, stderrFile, stdoutTotalLines, stderrTotalLines}`

**Key features:**
- **Progress heartbeat**: Prevents MCP client 120s timeout for long builds
- **Process tree kill**: On timeout/cancel, kills all child processes (cargo build -> rustc, etc.)
- **MCP cancellation**: Client can cancel, process tree is killed immediately
- **Shell mode**: `shell: true` wraps in `cmd /C` (Win) or `sh -c` (Unix) for pipes, `&&`, etc.
- **Output filter**: Grep-like filtering with include/exclude regex and context lines. Only affects inline results; full output always goes to log files.

**Examples:**
```json
// Quick command
{"command": "git", "args": ["status"]}

// Long build with managed progress
{"command": "cargo", "args": ["build", "--release"], "mode": "managed", "timeoutMs": 1200000}

// Filter build output for errors/warnings
{"command": "cargo", "args": ["build"], "outputFilter": {"include": ["error\\[", "warning\\["], "context": 2, "maxLines": 50}}

// Shell pipes
{"command": "cat file.txt | grep error | head -20", "shell": true}

// Background server
{"command": "npm", "args": ["start"], "mode": "detached"}

// Debug with RUST_LOG
{"command": "cargo", "args": ["test"], "env": {"RUST_LOG": "debug"}}

// Prepend to PATH
{"command": "python", "args": ["script.py"], "envPrepend": {"PATH": "C:/custom/bin;"}}

// Pipe string to stdin
{"command": "python", "args": ["script.py"], "stdin": {"kind": "inline", "text": "input data"}}

// Head + tail (first 5 lines + last 10 lines)
{"command": "cargo", "args": ["test"], "stdoutHead": 5, "stdoutTail": 10, "streamOutput": false}
```

### `kill_process` - Kill Process (with Tree Kill)
Terminate a process or entire process tree. Cross-platform:
- **Parameters**: `pid`, `force` (SIGKILL/TerminateProcess), `tree` (kill all child processes)
- **Returns**: `{pid, success, killedCount, tree}`
- **Use cases**: Stop runaway builds, terminate servers with all children

```json
// Kill single process
{"pid": 12345, "force": true}

// Kill entire process tree
{"pid": 12345, "force": true, "tree": true}
```

### `list_processes` - List Background Processes
List processes started by this server with `run_command(mode: 'detached')`:
- **Parameters**: `filter` (optional command name filter)
- **Returns**: `{processes[]}`
- **Note**: Only tracks processes started by THIS server session

### `search_processes` - Search System Processes
Search for running processes by name or command line regex. Cross-platform via sysinfo crate:
- **Parameters**: `name_pattern` (regex), `cmdline_pattern` (regex)
- **Returns**: `{processes[{pid, name, command_line, exe_path, memory_bytes, cpu_percent, status, user}], count}`
- **Examples**:
  - Find Chrome: `{name_pattern: "chrome"}`
  - Find by port: `{cmdline_pattern: "--port=3000"}`
  - Find Python scripts: `{name_pattern: "python", cmdline_pattern: "script\\.py"}`

## HTTP Tools (feature)

### `http_request` - General HTTP/HTTPS
Send requests with headers, cookies, query params, and body:

```json
{
  "method": "POST",
  "url": "https://api.example.com/v1/items",
  "headers": { "Authorization": "Bearer TOKEN", "Content-Type": "application/json" },
  "cookies": { "session": "abc123" },
  "query": { "page": "1" },
  "body": "{\"name\":\"demo\"}",
  "accept": "json",
  "timeoutMs": 20000
}
```

### `http_request_batch`
Run multiple requests in one call:

```json
{
  "requests": [
    { "id": "a", "method": "GET", "url": "https://example.com/a" },
    { "id": "b", "method": "GET", "url": "https://example.com/b" }
  ]
}
```

### `http_download` / `http_download_batch`
Download files to local paths:

```json
{ "url": "https://example.com/file.zip", "path": "downloads/file.zip" }
```

## S3 Tools (feature)

### `s3_list_buckets` - List Buckets
```json
{}
```

### `s3_list` - List Objects
```json
{ "bucket": "my-bucket", "prefix": "reports/", "maxKeys": 100 }
```

### `s3_get` / `s3_put`
```json
{ "bucket": "my-bucket", "key": "reports/2025.csv", "outputPath": "reports/2025.csv" }
```

```json
{ "bucket": "my-bucket", "key": "uploads/log.txt", "path": "logs/log.txt", "contentType": "text/plain" }
```

### `s3_delete` / `s3_copy` / `s3_presign`
```json
{ "bucket": "my-bucket", "key": "old/file.txt" }
```

```json
{ "sourceBucket": "my-bucket", "sourceKey": "a.txt", "destBucket": "my-bucket", "destKey": "b.txt" }
```

```json
{ "bucket": "my-bucket", "key": "uploads/file.bin", "method": "GET", "expiresInSeconds": 600 }
```

## Quick start
```bash
cargo build --release
```

## Troubleshooting

### JSON Schema draft compatibility
Some clients (qwen code, gemini-cli) validate tool schemas with Draft 7 only, while rmcp generates JSON Schema 2020-12 by default. This causes errors like:
```
no schema with key or ref "https://json-schema.org/draft/2020-12/schema"
```

Fix applied here: rewrite tool input schemas to Draft 7 at startup. This is done once when building the tool router (see `src/main.rs`) and includes:
- Force `$schema` to `http://json-schema.org/draft-07/schema#`
- Convert `$defs` -> `definitions`
- Rewrite `$ref` paths `#/$defs/...` -> `#/definitions/...`

This removes the Draft 2020-12 dependency from tool schemas so Draft 7 validators succeed. This is a per-server fix; other MCP servers will still need the same rewrite if they emit 2020-12.

## Transport Modes

filesystem-mcp-rs supports dual-mode transport:

### stdio Mode (Default)
Local MCP clients (Claude Desktop, Cursor, Codex):
- stdin/stdout communication
- **No stderr by default** (prevents client connection errors)
- File logging with `-l`

### HTTP Stream Mode
Remote access, web integrations, cloud deployments:
- HTTP server with SSE streaming
- MCP endpoint: `/mcp`
- Health check: `/health`
- Console logging enabled (optional file with `-l`)

## Usage Examples

### Get Help
```bash
filesystem-mcp-rs --help
filesystem-mcp-rs -V  # version
```

### stdio Mode
```bash
# Basic
filesystem-mcp-rs /projects /tmp

# With logging (writes to filesystem-mcp-rs.log)
filesystem-mcp-rs -l /projects

# Custom log file
filesystem-mcp-rs -l /var/log/mcp.log /projects
```

**Log location**: Current working directory or specified path

### HTTP Stream Mode
```bash
# Local (http://127.0.0.1:8000)
filesystem-mcp-rs -s

# Custom port
filesystem-mcp-rs -s -p 9000

# Network accessible
filesystem-mcp-rs -s -b 0.0.0.0 -p 8000

# With file logging
filesystem-mcp-rs -s -l server.log

# Production setup
filesystem-mcp-rs -s -b 0.0.0.0 -p 8000 -l /var/log/mcp-server.log
```

**Check health**:
```bash
curl http://localhost:8000/health
# Returns: OK
```

**Logs**: Console by default, file with `-l` flag

### All Options
```
Usage: filesystem-mcp-rs [OPTIONS] [DIRS...]

Arguments:
  [DIRS...]  Allowed directories

Options:
      --allow-symlink-escape  Follow symlinks outside allowed dirs
  -s, --stream                HTTP mode (default: stdio)
  -p, --port <PORT>           HTTP port [default: 8000]
  -b, --bind <ADDR>           Bind address [default: 127.0.0.1]
  -l, --log [<FILE>]          Log to file [default: filesystem-mcp-rs.log]
  -h, --help                  Print help
  -V, --version               Print version
```

## Tests
```bash
cargo test              # All tests (unit + integration + HTTP transport)
cargo test --test http_transport  # HTTP transport only
```

Tests:
- **222 unit tests** (was 158):
  - Core: hash (12), compare (18), duplicates (8), watch (6), json_reader (10), pdf_reader (10), archive (4), stats (4), process (23)
  - Text: line_edit (5), bulk_edit (7), edit (4), grep (6), search (5)
  - Binary: binary (10)
  - **New - wave2** (29): net (6), proc (5), sys (5), file (7), util (6)
  - **New - xlsx** (6): read, info, unicode support
  - **New - docx** (3): error handling
  - **New - llm** (5): transform, model mapping
- **39 integration tests**: file operations, search, grep, extract, binary, pagination
- **4 HTTP transport tests**: server startup, health, MCP endpoint
- **Unicode tested**: Russian (Привет), Chinese (你好), Emoji (🦀)

## Development

### Project Structure
```
src/
├── main.rs         - Entry point, CLI args, transport modes, MCP tools
├── core/
│   ├── allowed.rs  - Directory allowlist/validation
│   ├── logging.rs  - Transport-aware logging (stdio/stream)
│   ├── path.rs     - Path resolution, escape protection
│   └── format.rs   - Schema utilities
├── tools/
│   ├── fs_ops.rs      - File read/head/tail
│   ├── edit.rs        - Text-based edits + unified diff
│   ├── line_edit.rs   - Line-based surgical edits
│   ├── bulk_edit.rs   - Mass search/replace
│   ├── search.rs      - Glob search with excludes + type/size/time filters
│   ├── grep.rs        - Regex content search + invert/count modes
│   ├── binary.rs      - Binary file operations (read/write/extract/patch)
│   ├── hash.rs        - File hashing (MD5/SHA1/SHA256/SHA512/XXH64)
│   ├── compare.rs     - File and directory comparison
│   ├── watch.rs       - Tail file and watch for changes
│   ├── json_reader.rs - JSON reading with JSONPath queries
│   ├── pdf_reader.rs  - PDF text extraction
│   ├── archive.rs     - ZIP/TAR/TAR.GZ archive handling
│   ├── http_tools.rs  - HTTP/HTTPS requests + batch
│   ├── s3_tools.rs    - AWS S3 operations + batch
│   ├── stats.rs       - File/directory statistics
│   ├── duplicates.rs  - Duplicate file detection
│   ├── process.rs     - Process execution and management
│   ├── xlsx.rs        - Excel file reading (calamine)
│   ├── docx.rs        - Word document reading (docx-lite)
│   ├── llm/           - LLM provider integrations (Gemini, Cerebras, OpenAI)
│   └── wave2/         - System utilities:
│       ├── net.rs     - Network tools (port_users, net_connections, port_available)
│       ├── proc.rs    - Process tools (proc_tree, proc_env, proc_files)
│       ├── sys.rs     - System info (disk_usage, sys_info)
│       ├── file.rs    - File tools (file_diff, file_touch)
│       └── util.rs    - Utilities (clipboard, env_*, which)

tests/
├── integration.rs     - MCP tool integration tests
└── http_transport.rs  - HTTP server tests
```

### Adding HTTP Transport Tests
HTTP tests spawn server subprocess and verify endpoints:
```rust
#[tokio::test]
async fn test_http_server_health_check() {
    // Start server on random port
    // Poll /health until ready
    // Assert response
}
```

### Transport Modes Implementation
- **stdio**: `rmcp::transport::stdio()` - no stderr logging by default
- **HTTP**: `StreamableHttpService` + `LocalSessionManager` - SSE streaming

### Key Dependencies
- `rmcp 0.9.0` - MCP SDK (features: `transport-io`, `server`, `transport-streamable-http-server`)
- `axum 0.8` - HTTP server framework
- `tokio` - Async runtime

## Configure for Claude Code

### Prerequisites (Windows only)

**Important:** Claude Code on Windows requires git-bash. If git is installed but bash is not in PATH, set the environment variable:

```powershell
# PowerShell (run as user, not admin)
[Environment]::SetEnvironmentVariable('CLAUDE_CODE_GIT_BASH_PATH', 'C:\Program Files\Git\bin\bash.exe', 'User')
```

Or if git is installed elsewhere, find it with:
```powershell
where git.exe
# Example output: C:\Programs\Git\bin\git.exe
# Then set: C:\Programs\Git\bin\bash.exe
```

Restart your terminal after setting the variable.

### Installation

Build and install the binary:
```bash
cargo build --release
# Or install globally:
cargo install --path .
```

### Add MCP Server via CLI (Recommended)

**Unix/Linux:**
```bash
claude mcp add filesystem -- filesystem-mcp-rs /projects /tmp /home/user/work
```

**Windows (using full path):**
```bash
claude mcp add filesystem -- "C:/path/to/filesystem-mcp-rs/target/release/filesystem-mcp-rs.exe" "C:/projects"
```

**Important:** Do NOT use `--log-level` or other flags when adding via `claude mcp add` - they are not supported by the executable. Only pass directory paths.

### Manual Configuration (Alternative)

Edit `~/.config/claude-code/config.json` (Unix/Linux) or `C:\Users\<username>\.config\claude-code\config.json` (Windows):

**stdio mode (default):**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "filesystem-mcp-rs",
      "args": ["/projects", "/tmp"]
    }
  }
}
```

**stdio with logging:**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "filesystem-mcp-rs",
      "args": ["-l", "mcp-server.log", "/projects"]
    }
  }
}
```

**HTTP stream mode:**
```json
{
  "mcpServers": {
    "filesystem-http": {
      "command": "filesystem-mcp-rs",
      "args": ["-s", "-p", "8000", "-b", "127.0.0.1"]
    }
  }
}
```

**HTTP with custom port and logging:**
```json
{
  "mcpServers": {
    "filesystem-http": {
      "command": "filesystem-mcp-rs",
      "args": ["-s", "-p", "9000", "-l", "http-server.log"]
    }
  }
}
```

### Verify Connection

Check that the server is connected:
```bash
claude mcp list
# Should show: filesystem: ... - ✓ Connected
```

For Claude Desktop, use the same format in `claude_desktop_config.json`.

## Configure for Codex

Install the binary:
```bash
cargo install --path .
```

Edit `~/.codex/config.toml` (Unix/Linux) or `C:\Users\<username>\.codex\config.toml` (Windows):

**stdio mode (default):**
```toml
[mcp_servers.filesystem]
command = "filesystem-mcp-rs"
args = ["/projects", "/tmp"]
```

**stdio with logging:**
```toml
[mcp_servers.filesystem]
command = "filesystem-mcp-rs"
args = ["-l", "codex-mcp.log", "/projects"]
```

**HTTP stream mode:**
```toml
[mcp_servers.filesystem_http]
command = "filesystem-mcp-rs"
args = ["-s", "-p", "8000"]
```

**HTTP with custom settings:**
```toml
[mcp_servers.filesystem_http]
command = "filesystem-mcp-rs"
args = ["-s", "-b", "0.0.0.0", "-p", "9000", "-l", "http-codex.log"]
```

Note: Use forward slashes (`C:/path`) or double backslashes (`C:\\path`) in TOML strings on Windows.

## Symlink policy
- Default: paths are canonicalized; symlinks escaping the allowlist are rejected.
- `--allow_symlink_escape`: if a symlink itself is inside the allowlist, operations may follow it even if the target is outside.
- Tools always validate paths; no raw "operate on the link itself" mode yet. If you need non-follow (operate on the link inode), we can add an opt-in flag per tool.

## Structure
- `src/main.rs` — MCP server + tools
- `src/core/path.rs` — path validation/escape protection
- `src/tools/fs_ops.rs` — read/head/tail
- `src/tools/edit.rs`, `src/tools/diff.rs` — text-based edits + unified diff
- `src/tools/line_edit.rs` — line-based surgical edits
- `src/tools/bulk_edit.rs` — mass search/replace across files
- `src/tools/search.rs` — glob search with type/size/time filters
- `src/tools/grep.rs` — regex content search with invert/count modes
- `src/tools/binary.rs` — binary file operations (read/write/extract/patch)
- `src/tools/hash.rs` — file hashing (MD5/SHA1/SHA256/SHA512/XXH64)
- `src/tools/compare.rs` — file and directory comparison
- `src/tools/watch.rs` — tail file and watch for changes
- `src/tools/json_reader.rs` — JSON reading with JSONPath queries
- `src/tools/pdf_reader.rs` — PDF text extraction
- `src/tools/archive.rs` — ZIP/TAR/TAR.GZ archive handling
- `src/tools/http_tools.rs` — HTTP/HTTPS tools (feature)
- `src/tools/s3_tools.rs` — S3 tools (feature)
- `src/tools/stats.rs` — file/directory statistics
- `src/tools/duplicates.rs` — duplicate file detection
- `tests/integration.rs` — per-tool integration coverage

Open to extensions (non-follow symlink mode, extra tools).

## Original Project

This is a Rust port of the official [Model Context Protocol filesystem server](https://github.com/modelcontextprotocol/servers).

For the JavaScript version, see: https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem
