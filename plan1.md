# Bug Hunt Report & Refactoring Plan

## Status: Analysis Complete
**Date:** 2025-12-05
**Target:** `filesystem-mcp-rs`

## Executive Summary
The codebase is well-structured and adheres to Rust best practices. `cargo clippy` reports no warnings, and the test suite is passing. However, architectural analysis reveals a critical performance bottleneck in the `grep` tool and a potential correctness issue in the `tail` implementation for multibyte characters.

## Findings

### 1. Critical Performance Bottleneck in `grep_files` (`src/grep.rs`)
**Severity:** High
**Description:**
The `search_file` function uses `fs_ops::read_text` to load the **entire file content** into a `String` before processing.
```rust
// src/grep.rs:152
let content = match read_text(path).await { ... };
let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
```
**Impact:**
- **OOM Risk:** Searching large files (logs, databases) will cause Out-Of-Memory crashes.
- **Latency:** High memory allocation overhead even for files that shouldn't match.
**Solution:**
Refactor to use `tokio::io::AsyncBufReadExt::lines()` to stream the file line-by-line, maintaining a fixed-size buffer for context lines (`before_context`).

### 2. UTF-8 Corruption Risk in `tail` (`src/fs_ops.rs`)
**Severity:** Medium
**Description:**
The `tail` function reads the file backwards in 4KB chunks:
```rust
// src/fs_ops.rs:61
let read_size = CHUNK.min(pos as usize);
// ...
let mut chunk = vec![0u8; read_size];
file.read(&mut chunk).await?;
// ...
let text = String::from_utf8_lossy(&combined).into_owned();
```
**Impact:**
If a multibyte UTF-8 character spans the boundary between two 4KB chunks, it will be split. `String::from_utf8_lossy` will replace the invalid bytes with ``, corrupting the data.
**Solution:**
Ensure chunks align with UTF-8 boundaries or decode the `combined` buffer only after stitching, being careful about the boundary between the "head" of the tail and the rest of the file.

### 3. Stale Documentation/Comments
**Severity:** Low
**Description:**
Several tests in `src/edit.rs` and `src/grep.rs` contain comments like `// BUG TEST: ...`. The tests assert that the code behaves correctly (e.g., errors on no match), indicating the bugs are fixed.
**Impact:**
Confuses future maintainers about the state of the codebase.
**Solution:**
Remove "BUG TEST" markers and rename tests to reflect they are regression tests for fixed issues.

## Refactoring Plan

### Phase 1: Cleanup
- [ ] Remove stale "BUG TEST" comments in `src/edit.rs` and `src/grep.rs`.
- [ ] Rename associated tests to be descriptive regression tests.

### Phase 2: Performance (Grep)
- [ ] Refactor `grep_files` to use `BufReader` and `lines()`.
- [ ] Implement a ring buffer (Deque) to store `before_context` lines without keeping the whole file in memory.
- [ ] Optimize context collection to avoid cloning strings unless a match is found.

### Phase 3: Correctness (Tail)
- [ ] Write a failing test case for `tail` with multibyte characters split across the 4KB chunk boundary.
- [ ] Modify `tail` to handle UTF-8 boundaries correctly (e.g., by inspecting the last bytes of a chunk to see if they are incomplete UTF-8 sequences).

## Next Steps
Please approve this plan to proceed with Phase 1 (Cleanup) and Phase 2 (Grep Optimization). Phase 3 will be tackled if time permits or prioritized if critical.
