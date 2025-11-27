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
- **10 unit tests**: line_edit, bulk_edit, roots parsing
- **19 integration tests**: file operations, search, grep
- **4 HTTP transport tests**: server startup, health, MCP endpoint

## Development

### Project Structure
```
src/
├── main.rs         - Entry point, CLI args, transport modes
├── logging.rs      - Transport-aware logging (stdio/stream)
├── allowed.rs      - Directory allowlist/validation
├── path.rs         - Path resolution, escape protection
├── fs_ops.rs       - File read/head/tail
├── edit.rs         - Text-based edits + unified diff
├── line_edit.rs    - Line-based surgical edits
├── bulk_edit.rs    - Mass search/replace
├── search.rs       - Glob search with excludes
└── grep.rs         - Regex content search

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
