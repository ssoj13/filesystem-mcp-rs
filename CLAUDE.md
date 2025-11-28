# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**filesystem-mcp-rs** is a Rust port of the official JavaScript MCP (Model Context Protocol) filesystem server. It provides fast, safe, and protocol-compatible file operations for MCP clients like Claude Code, Cursor, and Codex.

**Key metrics:**
- Version: 0.1.2
- Edition: Rust 2024
- 21 MCP tools for file operations
- Dual transport: stdio (local) + HTTP Stream (remote)

## Build & Test Commands

```powershell
# Build release binary
cargo build --release

# Run all tests (unit + integration + HTTP transport)
cargo test

# Run specific test suite
cargo test --test integration
cargo test --test http_transport

# Run single test by name
cargo test test_http_server_health_check

# Check compilation without building
cargo check

# Format code
cargo fmt

# Lint
cargo clippy
```

**Binary location after build:** `target/release/filesystem-mcp-rs.exe` (Windows) or `target/release/filesystem-mcp-rs` (Unix)

## High-Level Architecture

### MCP Server Implementation

The server is built on the `rmcp` SDK (v0.9.1) with a tool-router pattern:

```rust
#[derive(Clone)]
struct FileSystemServer {
    allowed: AllowedDirs,           // Thread-safe allowed directories (Arc<RwLock<Vec<PathBuf>>>)
    tool_router: ToolRouter<Self>,  // Auto-generated MCP tool routing
    allow_symlink_escape: bool,     // Symlink escape policy
}
```

**Tool Router Pattern:**
- Each tool is an async method decorated with `#[tool]` attribute
- Schemas auto-generated via `serde_json::Value` parameters
- Returns `Result<ToolResponse>` with structured content

**21 MCP Tools Grouped by Category:**

| Category | Tools |
|----------|-------|
| **Read** | read_text_file, read_media_file, read_multiple_files |
| **Write/Edit** | write_file, edit_file, edit_lines, bulk_edits |
| **FS Ops** | create_directory, move_file, copy_file, delete_path |
| **List/Info** | list_directory, list_directory_with_sizes, get_file_info, directory_tree |
| **Search** | search_files (glob), grep_files (regex content search) |
| **Admin** | list_allowed_directories |

### Path Security Model (Multi-layered)

**Path validation flow (path.rs:resolve_validated_path):**

1. **Normalization:** Collapse `.` and `..` components
2. **Absolutization:** Convert relative paths to absolute via `current_dir()`
3. **Canonicalization:** Resolve symlinks when path exists
4. **Allowlist validation:** Check if path is within allowed directories
5. **Symlink escape protection:** Reject escapes unless `--allow-symlink-escape` flag set

**CRITICAL:** Every tool re-validates paths through this pipeline. No raw path operations.

**AllowedDirs (allowed.rs):** Thread-safe shared state using `Arc<RwLock<Vec<PathBuf>>>`. Supports dynamic updates via MCP `roots/list` notifications.

### Dual Transport Architecture

**1. stdio Mode (Default):**
- Communication: stdin/stdout JSON-RPC
- Logging: **NO stderr by default** (prevents MCP client handshake failures)
- Use `-l` flag for file logging
- Use case: Local MCP clients (Claude Code, Cursor, Codex)

**2. HTTP Stream Mode:**
- Server: Axum + SSE (Server-Sent Events)
- Endpoints: `/mcp` (MCP RPC), `/health` (health check)
- Logging: Console + optional file with `-l`
- Use case: Remote access, web integrations, cloud deployments

**Transport selection in main.rs:**
```rust
if args.stream_mode {
    run_stream_mode(server, bind, port).await?;
} else {
    run_stdio_mode(server).await?;
}
```

### Module Dependency Graph

```
main.rs (Server + all 21 tools)
├── allowed.rs (AllowedDirs management)
├── path.rs (Path validation) → allowed.rs
├── fs_ops.rs (File read, head/tail)
├── edit.rs (Text edits + diff) → diff.rs
├── line_edit.rs (Line-based edits) → diff.rs
├── bulk_edit.rs (Mass edits) → edit.rs, search.rs, fs_ops.rs
├── search.rs (Glob search) → path.rs, allowed.rs
├── grep.rs (Regex search) → path.rs, allowed.rs, fs_ops.rs
├── media.rs (Base64 encoding) → mime.rs
├── logging.rs (Transport-aware logging)
└── roots.rs (Roots deserialization)
```

**Design principle:** Modular separation of concerns. Each module has a single responsibility.

### Edit Operations Deep Dive

**Three edit modes (use appropriate tool based on use case):**

1. **edit_file (edit.rs):** Text-based search/replace
   - Finds old_string, replaces with new_string
   - Whitespace-tolerant fallback
   - Returns unified diff via `similar` crate
   - Use when: Replacing specific text snippets

2. **edit_lines (line_edit.rs):** Line-based surgical edits
   - Operations: Replace, Insert(Before/After), Delete
   - 1-indexed line numbers (user-friendly)
   - Supports ranges (startLine-endLine)
   - **CRITICAL:** Edits sorted descending to prevent line shift bugs
   - Use when: Editing exact line numbers (e.g., fixing import at line 5)

3. **bulk_edits (bulk_edit.rs):** Mass search/replace across files
   - Glob pattern to select files (e.g., `**/*.rs`)
   - Same edit applied to all matches
   - Per-file error handling (continues on failures)
   - Returns summary with per-file diffs
   - Use when: Refactoring function names across codebase

**All edit tools support dry-run mode:** Set `dryRun: true` to preview changes without writing.

### Search Architecture

**search_files (search.rs):**
- Uses `globset` crate for compiled glob patterns
- Recursive directory walk with `walkdir`
- Supports exclude patterns (e.g., `!node_modules/**`)
- Symlink-safe (follows policy from `allow_symlink_escape`)
- Returns: List of matching file paths

**grep_files (grep.rs):**
- Uses `regex` crate for pattern matching
- Searches **inside file contents** (not filenames)
- Optional glob pattern to filter files
- Context lines: `beforeContext`, `afterContext`
- Case-insensitive: `caseInsensitive: true`
- Max matches limit for performance
- Returns: Matching lines with file paths + line numbers

**Key difference:** `search_files` = find files by name patterns, `grep_files` = find content inside files.

### File Read Optimization

**read_text (fs_ops.rs) supports three modes:**

1. **Full read:** Load entire file into memory
2. **Head:** Stream first N lines (efficient for large files)
3. **Tail:** Last N lines using chunk-based backtracking
   - Reads 4KB chunks from end
   - Handles files with long lines
   - Avoids loading full file into memory

**Performance note:** Head/tail operations are streaming, not buffering entire files.

### Testing Strategy

**Test suites:**
- `tests/integration.rs`: 19 tests - MCP tool integration (file ops, search, grep, edits)
- `tests/http_transport.rs`: 4 tests - HTTP server startup, health check, MCP endpoint
- Unit tests: Embedded in modules (line_edit, bulk_edit, roots parsing)

**Integration test pattern:**
1. Spawn server subprocess (`cargo run`)
2. Communicate via stdin/stdout JSON-RPC
3. Perform MCP handshake (`initialize` → `initialized`)
4. Call tools and verify responses
5. Cleanup via `tempfile` auto-deletion

**HTTP test pattern:**
1. Spawn server with random port
2. Poll `/health` endpoint (500ms intervals, max 10s)
3. Verify GET 200 response "OK"
4. Test MCP endpoint reachability

## Key Dependencies

**MCP & Transport:**
- `rmcp 0.9.1` - MCP SDK (features: transport-io, server, macros, transport-streamable-http-server)
- `axum 0.8` - HTTP server framework

**Async Runtime:**
- `tokio 1.48.0` - Full features async runtime
- `async-recursion 1.1.1`, `async-trait 0.1.89`, `futures 0.3.31`

**File Operations:**
- `globset 0.4.18` - Compiled glob pattern matching
- `similar 2.7.0` - Unified diff generation
- `regex 1.12.2` - Regex pattern matching

**CLI & Logging:**
- `clap 4.5.53` - CLI argument parsing (derive macros)
- `tracing 0.1.41` + `tracing-subscriber 0.3.20` - Structured logging

## Running the Server

### stdio Mode (Local MCP Clients)

```powershell
# Basic
filesystem-mcp-rs C:\projects C:\temp

# With logging (writes to filesystem-mcp-rs.log in current directory)
filesystem-mcp-rs -l C:\projects

# Custom log file
filesystem-mcp-rs -l C:\logs\mcp.log C:\projects
```

**IMPORTANT:** In stdio mode, no stderr logging by default to prevent MCP client failures.

### HTTP Stream Mode (Remote Access)

```powershell
# Local server (http://127.0.0.1:8000)
filesystem-mcp-rs -s

# Custom port
filesystem-mcp-rs -s -p 9000

# Network accessible
filesystem-mcp-rs -s -b 0.0.0.0 -p 8000

# Production with logging
filesystem-mcp-rs -s -b 0.0.0.0 -p 8000 -l C:\logs\mcp-http.log
```

**Check health:**
```powershell
curl http://localhost:8000/health
# Returns: OK
```

## Development Workflow

### Adding a New Tool

1. **Add method to FileSystemServer (main.rs):**
   ```rust
   #[tool]
   async fn my_new_tool(&self, args: serde_json::Value) -> Result<ToolResponse> {
       // Implementation
   }
   ```

2. **Method signature requirements:**
   - Must be async
   - Takes `&self` and `serde_json::Value` args
   - Returns `Result<ToolResponse>`
   - Decorated with `#[tool]` attribute

3. **Path validation (if tool uses file paths):**
   ```rust
   let path = resolve_validated_path(
       &args["path"].as_str().unwrap(),
       &self.allowed,
       self.allow_symlink_escape
   )?;
   ```

4. **Add test to tests/integration.rs:**
   - Follow existing test pattern (spawn server, JSON-RPC call)
   - Verify response content and structure

### Adding a New Module

1. Create `src/my_module.rs`
2. Export in `src/main.rs`: `mod my_module;` (not `pub mod`)
3. Add unit tests in module if applicable
4. Add integration test if it's a user-facing feature

### Security Considerations

**Path validation is MANDATORY for all file operations:**
- Never use raw user-provided paths
- Always call `resolve_validated_path()` first
- Re-validate even if path was validated earlier (state may change)

**Symlink policy:**
- Default: Canonicalize paths, reject escapes
- `--allow-symlink-escape`: Allow escapes if symlink itself is in allowlist
- No "operate on symlink inode" mode yet (all operations follow symlinks)

**Error handling:**
- Use `anyhow::Result` for error propagation
- Provide context with `.context()` for user-friendly messages
- Don't leak sensitive path information in errors

## Common Pitfalls

1. **stdio mode stderr logging:** DO NOT enable stderr logging in stdio mode (breaks MCP handshake). Use `-l` for file logging instead.

2. **Line numbers in edit_lines:** 1-indexed (user-friendly), not 0-indexed (programmer-friendly).

3. **Edit operation ordering (line_edit.rs):** Edits MUST be sorted descending by line number to prevent line shifts. Already handled in code, but critical for understanding.

4. **Path separators on Windows:** Use forward slashes in code (`/`) or escape backslashes (`\\`). Rust's `Path` handles conversion.

5. **Allowlist updates:** When `roots/list` notification received, AllowedDirs is updated dynamically. Tools automatically use new allowlist without restart.

6. **HTTP transport tests timing:** Server startup takes time. Tests use polling with backoff (500ms intervals, max 10s). Don't reduce timeout below 5s.

## Performance Notes

- **Head/tail operations:** Streaming, not full file buffering
- **Glob compilation:** Patterns compiled once and reused
- **RwLock vs Mutex for AllowedDirs:** RwLock chosen for many-readers-few-writers pattern
- **Bulk edits:** More efficient than individual edit calls (single pass per file)
- **Tail optimization:** Chunk-based backtracking from file end (4KB chunks)

## MCP Protocol Details

**ServerHandler implementation:**
- `get_info()`: Returns server name, version, capabilities
- `on_roots_list_changed()`: Async handler for dynamic root updates
- Tool listing: Auto-generated from `#[tool]` decorated methods

**Tool response structure:**
- `content`: Array of text or JSON objects
- `isError`: Boolean flag for error responses
- Supports markdown formatting in text content

**Capabilities advertised:**
- tools: true (21 tools available)
- roots: true (supports dynamic root updates)

## Project Conventions

- **Rust edition:** 2024 (latest features)
- **Async:** Tokio runtime with `async/await`
- **Error handling:** `anyhow` for flexibility, `thiserror` for custom types
- **Logging:** `tracing` crate with structured spans
- **CLI:** `clap` derive macros (not builder pattern)
- **Testing:** Integration tests in `tests/`, unit tests in modules
