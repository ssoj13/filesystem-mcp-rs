# filesystem-mcp-rs

Rust port of the JavaScript filesystem MCP server (`../index.ts`). Same MCP tool surface, rebuilt in Rust for speed and safety, while preserving protocol compatibility and path protections.

## Capabilities
- Read: `read_text_file` (head/tail), `read_media_file`, `read_multiple_files`
- Write/Edit: `write_file`, `edit_file` (diff + dry-run)
- FS ops: `create_directory`, `move_file`, `copy_file` (files/dirs, overwrite), `delete_path` (recursive)
- Introspection: `list_directory`, `list_directory_with_sizes`, `get_file_info`, `directory_tree`
- Search/roots: `search_files` (glob + exclude), `list_allowed_directories`
- Safety: allowlist/roots validation, escape protection, optional `--allow_symlink_escape`

## Quick start
```bash
cd rust/filesystem-mcp-rs
cargo build
```

### Run the server (stdio MCP)
- Allow directories via CLI when the client doesn’t send roots:
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

Point the MCP server command to this crate (cwd must be `rust/filesystem-mcp-rs`).

Configuration for Claude Code: Edit the file `~/.config/claude-code/config.json` (on Unix/Linux) or `C:\Users\joss1\.config\claude-code\config.json` (on Windows).

Add the following configuration:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "cargo",
      "args": ["run", "--release", "--", "/path/you/allow"],
      "cwd": "/path/to/repo/rust/filesystem-mcp-rs"
    }
  }
}
```

To allow multiple directories, add them to the args array:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "cargo",
      "args": ["run", "--release", "--", "/path/one", "/path/two", "/path/three"],
      "cwd": "/path/to/repo/rust/filesystem-mcp-rs"
    }
  }
}
```

For Claude Desktop, use the same format in your `claude_desktop_config.json` file.

## Configure for Codex

Edit the Codex config file: `~/.codex/config.toml` (on Unix/Linux) or `C:\Users\<username>\.codex\config.toml` (on Windows).

Add the following MCP server configuration:

```toml
[mcp_servers.filesystem]
command = "cargo"
args = ["run", "--release", "--", "C:/projects"]
```

To allow multiple directories:

```toml
[mcp_servers.filesystem]
command = "cargo"
args = ["run", "--release", "--", "C:/projects", "C:/temp", "D:/work"]
```

Note: On Windows, use forward slashes (`C:/path`) or double backslashes (`C:\\path`) in TOML strings.

For the original JavaScript version, see: https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem

## Symlink policy
- Default: paths are canonicalized; symlinks escaping the allowlist are rejected.
- `--allow_symlink_escape`: if a symlink itself is inside the allowlist, operations may follow it even if the target is outside.
- Tools always validate paths; no raw “operate on the link itself” mode yet. If you need non-follow (operate on the link inode), we can add an opt-in flag per tool.

## Structure
- `src/main.rs` — MCP server + tools
- `src/path.rs` — path validation/escape protection
- `src/fs_ops.rs` — read/head/tail
- `src/edit.rs`, `src/diff.rs` — edits + unified diff
- `src/search.rs` — glob search with excludes
- `tests/integration.rs` — per-tool integration coverage

Open to extensions (non-follow symlink mode, extra tools).

