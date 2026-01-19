# Filesystem MCP - Codepaths & Architecture

## Overview

This is a Rust MCP (Model Context Protocol) server providing filesystem operations. It runs as a standalone binary communicating via stdin/stdout (stdio transport) or HTTP.

## Entry Points

```
main.rs
├── main() - Entry point
│   ├── parse CLI args (clap)
│   ├── setup logging (tracing)
│   ├── AllowedDirs::new() - initialize allowed paths
│   └── serve() / serve_http() - start MCP server
│
└── FileSystemServer struct
    ├── #[tool_router] - 50+ MCP tools
    ├── allowed: AllowedDirs - path whitelist
    ├── allow_symlink_escape: bool - security flag
    └── process_manager: ProcessManager - background tasks
```

## Path Security Model

```
User Path → resolve_path() → Validated Path
                ↓
    ┌─────────────────────────────┐
    │ 1. Canonicalize path        │
    │ 2. Check against AllowedDirs│
    │ 3. Detect symlink escapes   │
    │ 4. Return error if invalid  │
    └─────────────────────────────┘
```

## Module Responsibilities

### Core Path Handling
- `core/allowed.rs` - Thread-safe AllowedDirs storage
- `core/path.rs` - Path resolution, validation, symlink checks

### File I/O
- `tools/fs_ops.rs` - read_text_file, head/tail, encoding detection
- `tools/binary.rs` - Binary read/write/extract/patch operations
- `tools/edit.rs` - Text replacement (literal & regex)
- `tools/line_edit.rs` - Line-based editing (insert/replace/delete)
- `tools/bulk_edit.rs` - Multi-file search/replace
- `tools/diff.rs` - Unified diff generation

### Search & Analysis
- `tools/search.rs` - Glob-based file search with filters
- `tools/grep.rs` - Content search with regex + include/exclude globs
- `tools/hash.rs` - File hashing (MD5, SHA1, SHA256, SHA512, XXH64)
- `tools/compare.rs` - Binary file/directory comparison
- `tools/stats.rs` - Directory statistics
- `tools/duplicates.rs` - Duplicate file finder

### Format Support
- `tools/archive.rs` - ZIP/TAR/TAR.GZ extract/create
- `tools/json_reader.rs` - JSON read with JSONPath query
- `tools/pdf_reader.rs` - PDF text extraction

### Media
- `tools/screenshot.rs` - Screenshot capture + clipboard output

### Network
- `tools/http_tools.rs` - HTTP/HTTPS requests + batch downloads
- `tools/s3_tools.rs` - AWS S3 list/get/put/delete/copy/presign + batch ops

### Runtime
- `tools/process.rs` - Command execution, process management
- `tools/watch.rs` - File watching, tail -f functionality
- `core/logging.rs` - Tracing setup
- `core/format.rs` - JSON Schema draft conversion (2020-12 → Draft-07)

## Tool Response Pattern

All tools follow this pattern:

```rust
async fn tool_name(&self, args: Args) -> Result<CallToolResult, McpError> {
    // 1. Validate & resolve paths
    let path = self.resolve(&args.path).await?;
    
    // 2. Call module function
    let result = module::function(&path, ...)
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    
    // 3. Format text output
    let text = format!(...);
    
    // 4. Build JSON response
    Ok(CallToolResult {
        content: vec![Content::text(text)],
        structured_content: Some(json!({
            "field1": result.field1,
            "field2": result.field2,
        })),
        is_error: Some(false),
        meta: None,
    })
}
```

## Process Management

```
run_command(background: true)
    ↓
ProcessManager.register(pid, info)
    ↓
[Process runs in background]
    ↓
list_processes() → show tracked processes
kill_process(pid) → terminate
    ↓
ProcessManager.unregister(pid)
```

Notes:
- Background mode returns immediately with `pid`; stdout/stderr are only captured to files when `stdout_file`/`stderr_file` are provided.

## Known Issues & TODOs

No open items tracked as of this audit. See `BUGHUNT_REPORT.md` for resolved findings.

## Security Considerations

1. **Path Whitelist**: All paths validated against `AllowedDirs`
2. **Symlink Escape**: Optional detection via `allow_symlink_escape` flag
3. **Canonicalization**: Paths resolved to absolute before validation
4. **Process Isolation**: `sysinfo` crate for cross-platform process management
5. **No Shell Injection**: Direct command execution, args passed separately

## Configuration

CLI flags:
- `--allowed-dir <path>` - Add allowed directory (repeatable)
- `--allow-symlink-escape` - Allow symlinks outside allowed dirs
- `--port <port>` - HTTP mode port
- `--bind <addr>` - HTTP bind address

Environment:
- `RUST_LOG` - Tracing log level
