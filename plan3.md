# Bug Hunt Report #3 - filesystem-mcp-rs (FINAL)

## Executive Summary

Third comprehensive bug hunt session completed. Found and fixed **2 logic bugs**, removed **2 unused dependencies**, and fixed **16 clippy warnings**. All **86 tests passing**, clippy clean.

---

## Issues Found and Fixed

### 1. MEDIUM: Missing validation for `line=0` in `extract_lines`

**Location**: `src/main.rs:1366-1386`

**Problem**: When user passes `line=0` (invalid - lines are 1-indexed), the code used `saturating_sub(1)` which returned 0, causing the first line to be deleted unexpectedly.

**Fix Applied**: Added full validation for:
- `line == 0`
- `end_line == 0`
- `end_line < line` (invalid range)

---

### 2. MEDIUM: Missing validation for `line=0` in `edit_lines`

**Location**: `src/main.rs:1198-1220`

**Problem**: Same issue as extract_lines - `LineEditInstruction.line=0` was not validated.

**Fix Applied**: Added identical validation pattern before processing edits.

**Also updated**: `src/line_edit.rs:46-48` - Removed `saturating_sub` since validation now guarantees `line >= 1`.

---

### 3. Unused Dependencies Removed

| Dependency | Status |
|------------|--------|
| `thiserror = "1.0.69"` | **REMOVED** |
| `async-trait = "0.1.89"` | **REMOVED** |

---

### 4. Clippy Warnings Fixed (16 total)

| File | Warning Type | Count | Fix |
|------|-------------|-------|-----|
| `src/bulk_edit.rs` | `vec_init_then_push` | 8 | Use `vec![...]` directly |
| `tests/http_transport.rs` | `needless_borrow` | 4 | Remove `&` from `.args()` |
| `tests/integration.rs` | `bool_assert_comparison` | 2 | Use `assert!(!x)` instead of `assert_ne!(x, true)` |
| `tests/integration.rs` | `collapsible_if` | 2 | Use let chains |

---

## Verified Clean Areas

After deep analysis, these areas are confirmed correct:

| Handler | Status | Notes |
|---------|--------|-------|
| `extract_symbols` | OK | 0-indexed, proper clamping |
| `read_binary` | OK | Returns empty Vec for out-of-bounds |
| `write_binary` | OK | Creates padding as needed |
| `patch_bytes` | OK | Loop handles all edge cases |
| `grep_files` | OK | Uses `saturating_sub` for context |
| `head/tail` | OK | Handles trailing newlines correctly |

---

## Test Results

```
test result: ok. 48 passed; 0 failed (unit tests)
test result: ok. 4 passed; 0 failed (http_transport)
test result: ok. 34 passed; 0 failed (integration)

Total: 86 tests passing
Clippy: 0 warnings
```

---

## Files Modified

| File | Changes |
|------|---------|
| `src/main.rs` | +20 lines validation in `extract_lines`, +22 lines validation in `edit_lines` |
| `src/line_edit.rs` | Removed `saturating_sub`, added safety comment |
| `src/bulk_edit.rs` | 8 clippy fixes in tests |
| `tests/http_transport.rs` | 4 clippy fixes |
| `tests/integration.rs` | 4 clippy fixes |
| `Cargo.toml` | Removed 2 unused dependencies |

---

## Dataflow Diagram

```
                    ┌─────────────────────────────────────────────────────┐
                    │                    main.rs                          │
                    │  FileSystemServer - MCP protocol handler            │
                    │  - tool_router: Routes tool calls                   │
                    │  - allowed: AllowedDirs (shared state)              │
                    └────────────────────────┬────────────────────────────┘
                                             │
        ┌────────────────────────────────────┼────────────────────────────────────┐
        │                                    │                                    │
        ▼                                    ▼                                    ▼
┌───────────────────┐              ┌───────────────────┐              ┌───────────────────┐
│   path.rs         │              │   fs_ops.rs       │              │   edit.rs         │
│ resolve_validated │              │ read_text         │              │ apply_edits       │
│ _path()           │◄────────────►│ head/tail         │              │ FileEdit struct   │
│ - validates paths │              │                   │              │ - regex support   │
│ - symlink safety  │              │                   │              │ - replace_all     │
└───────────────────┘              └───────────────────┘              └───────────────────┘
        │                                    │                                    │
        │                                    │                                    │
        ▼                                    ▼                                    ▼
┌───────────────────┐              ┌───────────────────┐              ┌───────────────────┐
│   allowed.rs      │              │   search.rs       │              │   line_edit.rs    │
│ AllowedDirs       │              │ search_paths      │              │ apply_line_edits  │
│ - RwLock<Vec>     │              │ build_glob        │              │ LineEdit struct   │
│ - thread-safe     │              │                   │              │ ✓ FIXED           │
└───────────────────┘              └───────────────────┘              └───────────────────┘
                                             │
                                             ▼
                                   ┌───────────────────┐
                                   │   grep.rs         │
                                   │ grep_files        │
                                   │ GrepParams        │
                                   │ ✓ CLEAN           │
                                   └───────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ Supporting modules:                                                                      │
│ - diff.rs: unified_diff generation                                                      │
│ - format.rs: format_size for human-readable sizes                                       │
│ - mime.rs: MIME type detection by extension                                             │
│ - media.rs: read_media_base64 for images/audio                                          │
│ - binary.rs: read_bytes, write_bytes, extract_bytes, patch_bytes ✓ CLEAN               │
│ - bulk_edit.rs: bulk_edit_files for mass search/replace ✓ CLEAN                        │
│ - logging.rs: init_logging with stdio/stream mode support                               │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Memory MCP Update

Session findings have been logged to memory MCP for future reference.

---

## Session Complete

All identified issues have been resolved:
- ✅ 2 logic bugs fixed (`line=0` validation)
- ✅ 2 unused dependencies removed
- ✅ 16 clippy warnings fixed
- ✅ 86 tests passing
- ✅ Clippy clean
