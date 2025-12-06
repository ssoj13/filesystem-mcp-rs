# Bug Hunt Report #4 - filesystem-mcp-rs (FINAL)

## Executive Summary

Fourth comprehensive bug hunt session with parallel security/code review agents. Found and fixed **1 CRITICAL bug**, **2 MEDIUM bugs**, and cleaned up **stale comments**. All **86 tests passing**, clippy clean.

---

## CRITICAL Issues Fixed

### 1. [CRITICAL] Unicode Byte Slicing Panic in edit.rs

**Location**: `src/edit.rs:31, 93`

**Problem**: Code used `&edit.old_text[..200]` which slices by **bytes**, not characters. Multi-byte UTF-8 sequences (e.g., `ö` = `0xC3 0xB6`) would cause **panic** when the boundary falls mid-character.

**Example crash input**:
```
oldText: "ööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööööö..." (200+ ö characters)
```

**Fix Applied**:
```rust
/// Truncate string to max chars safely (Unicode-aware, no panic on multi-byte)
fn truncate_preview(s: &str, max_chars: usize) -> String {
    let char_count = s.chars().count();
    if char_count > max_chars {
        let truncated: String = s.chars().take(max_chars).collect();
        format!("{}... ({} chars total)", truncated, char_count)
    } else {
        s.to_string()
    }
}
```

---

## MEDIUM Issues Fixed

### 2. [MEDIUM] Blocking I/O in Async Context (path.rs)

**Location**: `src/path.rs:56, 78, 92`

**Problem**: Used synchronous `std::fs` operations (`canonicalize()`, `exists()`) inside async function. This blocks the tokio runtime thread and can cause latency spikes.

**Fix Applied**: Replaced with async equivalents:
- `normalized.canonicalize()` → `fs::canonicalize(&normalized).await`
- `parent.exists()` → `fs::metadata(parent).await.is_ok()`

---

### 3. [MEDIUM] Search Error Propagation (search.rs)

**Location**: `src/search.rs:36-41`

**Problem**: When one file in directory tree failed path validation, the **entire search failed** (error propagated with `?`).

**Fix Applied**: Changed to skip problematic files instead of failing:
```rust
if resolve_validated_path(...).await.is_err() {
    continue;  // Skip instead of fail
}
```

Also added graceful handling for `file_type()` errors (broken symlinks).

---

## Code Quality Improvements

### 4. Stale BUG Comments Cleaned Up

Removed outdated "BUG TEST" comments that described bugs already fixed in previous sessions:

| File | Change |
|------|--------|
| `src/edit.rs:127-131` | Removed 6-line BUG header, simplified to "Regression tests" |
| `src/line_edit.rs:201-205` | Removed 5-line BUG header |
| `src/grep.rs:210-213` | Removed 4-line BUG header |

---

## Security Audit Findings (Not Fixed - Documented)

The security agent identified these issues for future consideration:

| ID | Severity | Issue | Status |
|----|----------|-------|--------|
| S1 | HIGH | Symlink TOCTOU when `allow_symlink_escape=true` | BY DESIGN (flag disabled by default) |
| S2 | HIGH | No file size limit on read operations | DOCUMENTED |
| S3 | MEDIUM | Unbounded directory tree recursion | DOCUMENTED |
| S4 | MEDIUM | Temp file in target directory (predictable name) | DOCUMENTED |
| S5 | MEDIUM | Large offset in write_bytes can OOM | DOCUMENTED |
| S6 | MEDIUM | Windows case-insensitive path comparison | DOCUMENTED |

**Recommendation**: Add `MAX_FILE_SIZE` (100MB) limit in future update.

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
| `src/edit.rs` | +12 lines: `truncate_preview()` helper, updated 2 call sites |
| `src/path.rs` | Changed 3 blocking calls to async equivalents |
| `src/search.rs` | Error handling: skip on failure instead of propagate |
| `src/edit.rs` | Cleaned up stale BUG comments |
| `src/line_edit.rs` | Cleaned up stale BUG comments |
| `src/grep.rs` | Cleaned up stale BUG comments |

---

## Dataflow Diagram (Updated)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              main.rs                                         │
│  FileSystemServer - MCP protocol handler                                    │
│  - Validates all inputs before passing to modules                           │
│  - line=0 validation added for edit_lines/extract_lines                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────────┐     ┌───────────────────┐     ┌───────────────────┐
│   path.rs         │     │   fs_ops.rs       │     │   edit.rs         │
│ ✓ ASYNC I/O      │     │ read_text         │     │ ✓ UNICODE SAFE   │
│ - fs::canonicalize│     │ head/tail         │     │ truncate_preview()│
│ - fs::metadata    │     │                   │     │                   │
└───────────────────┘     └───────────────────┘     └───────────────────┘
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────────┐     ┌───────────────────┐     ┌───────────────────┐
│   allowed.rs      │     │   search.rs       │     │   line_edit.rs    │
│ AllowedDirs       │     │ ✓ GRACEFUL ERRORS│     │ apply_line_edits  │
│                   │     │ Skips bad files   │     │                   │
└───────────────────┘     └───────────────────┘     └───────────────────┘
                                    │
                                    ▼
                          ┌───────────────────┐
                          │   grep.rs         │
                          │ ✓ saturating_sub │
                          │ No underflow      │
                          └───────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Supporting modules (all clean):                                             │
│ - diff.rs, format.rs, mime.rs, media.rs, binary.rs, bulk_edit.rs, logging.rs│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Summary of All Bug Hunt Sessions

| Session | Issues Found | Issues Fixed |
|---------|--------------|--------------|
| #1 | Regex silent skip, trailing newline, dead code | All fixed |
| #2 | extract_lines trailing newline, 6 clippy warnings | All fixed |
| #3 | line=0 validation (2 places), unused deps, 16 clippy warnings | All fixed |
| #4 | Unicode panic, blocking I/O, search error propagation, stale comments | All fixed |

**Total Fixed Across All Sessions:**
- 5 logic bugs
- 2 security improvements
- 22 clippy warnings
- 2 unused dependencies removed
- 1 dead code file removed
- Multiple stale comments cleaned

---

## Awaiting Approval

All changes have been applied and verified:
- ✅ 86 tests passing
- ✅ Clippy clean
- ✅ No blocking I/O in async code
- ✅ Unicode-safe string operations
- ✅ Graceful error handling in search

Report saved to `plan4.md`.
