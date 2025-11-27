# filesystem-mcp-rs

Rust port of the [official JavaScript filesystem MCP server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem). Same MCP tool surface, rebuilt in Rust for speed and safety, while preserving protocol compatibility and path protections.

## Capabilities
- Read: `read_text_file` (head/tail), `read_media_file`, `read_multiple_files`
- Write/Edit: `write_file`, `edit_file` (diff + dry-run), `edit_lines` (line-based edits), `bulk_edits` (mass search/replace)
- FS ops: `create_directory`, `move_file`, `copy_file` (files/dirs, overwrite), `delete_path` (recursive)
- Introspection: `list_directory`, `list_directory_with_sizes`, `get_file_info`, `directory_tree`
- Search/roots: `search_files` (glob + exclude), `grep_files` (regex content search), `list_allowed_directories`
- Safety: allowlist/roots validation, escape protection, optional `--allow_symlink_escape`

## Advanced Editing Tools

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
- **Error handling**: Continues on failure, reports errors per-file
- **Use cases**: Renaming functions/variables across codebase, updating imports, fixing typos everywhere, refactoring patterns
- **Features**: Returns summary with diffs, dry-run mode for preview

### `grep_files` - Content Search
Search for text/regex patterns **inside** file contents (not filenames):
- **Supports**: Regex patterns, case-insensitive search, context lines
- **File filtering**: Optional glob patterns to limit scope
- **Returns**: Matching lines with file paths and line numbers
- **Use cases**: Finding code patterns, locating function definitions, searching across codebase

## Quick start
```bash
cargo build --release
```

## Transport Modes

filesystem-mcp-rs supports two transport modes:

### stdio Mode (Default)
For local MCP clients like Claude Desktop, Cursor, Codex, etc.
- Uses standard input/output for communication
- **No stderr output by default** (prevents connection issues)
- Enable file logging with `-l` flag

```bash
# Basic usage
filesystem-mcp-rs /path/to/allowed/dir

# With file logging (creates filesystem-mcp-rs.log)
filesystem-mcp-rs -l /path/to/allowed/dir

# Custom log file
filesystem-mcp-rs -l custom.log /path/to/allowed/dir

# Allow symlink escape
filesystem-mcp-rs --allow-symlink-escape /projects
```

### Streamable HTTP Mode
For remote access, web integrations, and cloud deployments.
- Starts HTTP server with MCP endpoint at `/mcp`
- Console logging enabled by default
- Optional file logging with `-l` flag
- Health check endpoint at `/health`

```bash
# Start HTTP server on default port (localhost:8000)
filesystem-mcp-rs -s

# Custom port
filesystem-mcp-rs -s -p 9000

# Accessible from network
filesystem-mcp-rs -s -b 0.0.0.0 -p 8000

# With file logging
filesystem-mcp-rs -s -l

# Custom log file
filesystem-mcp-rs -s -l myserver.log

# Full example with all options
filesystem-mcp-rs -s -b 0.0.0.0 -p 8000 -l server.log --allow-symlink-escape
```

Default HTTP endpoint: `http://127.0.0.1:8000/mcp`

### Command-line Flags

```
Usage: filesystem-mcp-rs [OPTIONS] [DIRS...]

Arguments:
  [DIRS...]  Allowed directories (fallback if client doesn't support roots)

Options:
      --allow-symlink-escape  Allow symlinks outside allowed dirs
  -s, --stream                Enable streamable HTTP mode (default: stdio)
  -p, --port <PORT>           HTTP port for stream mode [default: 8000]
  -b, --bind <ADDR>           Bind address for stream mode [default: 127.0.0.1]
  -l, --log [<FILE>]          Enable file logging. Optionally specify log file name [default: filesystem-mcp-rs.log]
  -h, --help                  Print help
  -V, --version               Print version
```

## Tests
```bash
cargo test   # integration + unit
```

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

**Unix/Linux:**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "filesystem-mcp-rs",
      "args": ["/projects", "/tmp", "/home/user/work"]
    }
  }
}
```

**Windows:**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "C:/path/to/filesystem-mcp-rs.exe",
      "args": ["C:/projects", "C:/temp", "D:/work"]
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

**Unix/Linux:**
```toml
[mcp_servers.filesystem]
command = "filesystem-mcp-rs"
args = ["/projects", "/tmp", "/home/user/work"]
```

**Windows:**
```toml
[mcp_servers.filesystem]
command = "filesystem-mcp-rs"
args = ["C:/projects", "C:/temp", "D:/work"]
```

Note: On Windows, use forward slashes (`C:/path`) or double backslashes (`C:\path`) in TOML strings.

## Symlink policy
- Default: paths are canonicalized; symlinks escaping the allowlist are rejected.
- `--allow_symlink_escape`: if a symlink itself is inside the allowlist, operations may follow it even if the target is outside.
- Tools always validate paths; no raw "operate on the link itself" mode yet. If you need non-follow (operate on the link inode), we can add an opt-in flag per tool.

## Structure
- `src/main.rs` — MCP server + tools
- `src/path.rs` — path validation/escape protection
- `src/fs_ops.rs` — read/head/tail
- `src/edit.rs`, `src/diff.rs` — text-based edits + unified diff
- `src/line_edit.rs` — line-based surgical edits
- `src/bulk_edit.rs` — mass search/replace across files
- `src/search.rs` — glob search with excludes
- `src/grep.rs` — regex content search inside files
- `tests/integration.rs` — per-tool integration coverage

Open to extensions (non-follow symlink mode, extra tools).

## Original Project

This is a Rust port of the official [Model Context Protocol filesystem server](https://github.com/modelcontextprotocol/servers).

For the JavaScript version, see: https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem
