# filesystem-mcp-rs

Rust port of the [official JavaScript filesystem MCP server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem). Same MCP tool surface, rebuilt in Rust for speed and safety, while preserving protocol compatibility and path protections.

## Capabilities
- Read: `read_text_file` (head/tail), `read_media_file`, `read_multiple_files`
- Write/Edit: `write_file`, `edit_file` (diff + dry-run), `edit_lines` (line-based edits), `bulk_edits` (mass search/replace)
- FS ops: `create_directory`, `move_file`, `copy_file` (files/dirs, overwrite), `delete_path` (recursive)
- Introspection: `list_directory`, `list_directory_with_sizes`, `get_file_info`, `directory_tree`
- Search/roots: `search_files` (glob + exclude), `grep_files` (regex content search), `list_allowed_directories`
- Safety: allowlist/roots validation, escape protection, optional `--allow_symlink_escape`

## Quick start
```bash
cd rust/filesystem-mcp-rs
cargo build
```

### Run the server (stdio MCP)
- Allow directories via CLI when the client doesn't send roots:
  ```bash
  cargo run -- <DIR1> <DIR2>
  ```
- Flags:
  - `--log-level info|debug|trace`
  - `--allow_symlink_escape` (default off; enables following symlinks that point outside allowlist)

Example:
```bash
cargo run -- --log-level debug --allow_symlink_escape /projects /tmp
```

If the client supports `roots/list`, you can omit dirs; otherwise pass allowed roots on the CLI.

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
- `src/edit.rs`, `src/diff.rs` — edits + unified diff
- `src/search.rs` — glob search with excludes
- `tests/integration.rs` — per-tool integration coverage

Open to extensions (non-follow symlink mode, extra tools).

## Original Project

This is a Rust port of the official [Model Context Protocol filesystem server](https://github.com/modelcontextprotocol/servers).

For the JavaScript version, see: https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem
