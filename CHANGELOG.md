# Changelog

## [0.1.10] - 2026-01-17

### Added
- **Hash algorithms**: MurmurHash3 (128-bit) and SpookyHash V2 (128-bit) - fast non-cryptographic hashes
- **Partial hashing**: `file_hash` now supports `offset` and `length` parameters for hashing file regions

### Enhanced
- **file_hash**: Extended algorithm list (md5, sha1, sha256, sha512, xxh64, murmur3, spooky)
- **search_files**: Exposed `fileType`, `minSize`, `maxSize` parameters in MCP API
- **JSON responses**: Added missing fields to structured output:
  - `compare_files`: diffSamples, file1Empty, file2Empty
  - `compare_directories`: errors
  - `watch_file`: timedOut
  - `hash_files`: error field per result
  - `read_json`: totalKeys, arrayLength
  - `read_pdf`: charCount

### Fixed
- Removed dead code: unused methods in grep.rs, hash.rs, watch.rs, process.rs, search.rs
- Updated LLM tool descriptions with new capabilities and examples

### Tests
- Added 4 new hash tests for Murmur3/Spooky algorithms
- Total: 168 unit tests

## [0.1.9] - 2026-01-17

### Added

**Priority 1 - File Comparison & Hashing:**
- `file_hash` - Hash files with MD5, SHA1, SHA256, SHA512, or XXH64. Supports offset/length for partial hashing.
- `file_hash_multiple` - Hash multiple files at once, returns `all_match` flag for quick comparison.
- `compare_files` - Binary file comparison with detailed diff analysis: offset, size difference, match percentage, diff samples.

**Priority 2 - Advanced File Operations:**
- `compare_directories` - Compare two directory trees recursively. Shows only_in_first, only_in_second, different files.
- `tail_file` - Read last N lines/bytes with optional follow mode for log monitoring.
- `watch_file` - Wait for file changes (modify/create/delete) with configurable timeout.
- `read_json` - Read JSON files with JSONPath query support. Returns pretty-printed results.
- `read_pdf` - Extract text from PDF files with page range selection.

**Priority 3 - Utilities:**
- `archive_extract` - Extract ZIP, TAR, TAR.GZ archives with optional file filtering.
- `archive_create` - Create ZIP or TAR.GZ archives from multiple files/directories.
- `file_stats` - Directory statistics: file counts, sizes by extension, largest files.
- `find_duplicates` - Find duplicate files by content hash or size only.

**Process Management (Cross-platform via sysinfo):**
- `run_command` - Execute shell commands with full control:
  - Custom working directory (cwd)
  - Environment variables injection (env)
  - Timeout with auto-kill (timeout_ms, kill_after_ms)
  - Redirect stdout/stderr to files
  - Read stdin from file
  - Tail output (stdout_tail, stderr_tail) - return only last N lines
  - Background execution with PID tracking
- `kill_process` - Kill process by PID using native API (SIGTERM/SIGKILL on Unix, TerminateProcess on Windows)
- `list_processes` - List background processes started by this server
- `search_processes` - Search system processes by name/cmdline regex. Returns: PID, name, command line, exe path, memory, CPU usage, status, user

### Enhanced

**grep_files improvements:**
- `invertMatch` - Show lines NOT matching the pattern (like grep -v)
- `filesWithoutMatch` - List files that don't contain the pattern (like grep -L)
- `countOnly` - Return only match counts per file (like grep -c)

**search_files improvements:**
- `fileType` - Filter by type: "file", "dir", or "symlink"
- `minSize` / `maxSize` - Filter by file size
- `modifiedAfter` / `modifiedBefore` - Filter by modification time (ISO8601 or relative like "1h", "2d")

**directory_tree improvements:**
- `maxDepth` - Limit tree traversal depth
- `showSize` - Include file sizes in output
- `showHash` - Include SHA256 hash for each file

### Tests Added
~80 new unit tests for new functionality:
- `hash.rs`: 12 tests (algorithms, partial hashing, multiple files)
- `compare.rs`: 18 tests (binary diff, directory comparison)
- `duplicates.rs`: 8 tests (content/size matching, filters)
- `watch.rs`: 6 tests (tail, follow mode, file watching)
- `json_reader.rs`: 10 tests (JSONPath queries, error handling)
- `pdf_reader.rs`: 10 tests (page parsing, text extraction)
- `archive.rs`: 4 tests (ZIP/TAR create/extract)
- `stats.rs`: 4 tests (recursive stats, largest files)
- `grep.rs`: 3 new tests (invert, count, files-without-match)
- `search.rs`: 5 new tests (type/size/time filters)
- `process.rs`: 14 tests (run_command, timeout, env, tail, background, search, kill errors)

Total: 54 → 158 unit tests (+193% growth)

### Dependencies Added
- `sha1`, `sha2`, `md-5`, `xxhash-rust` - Hashing algorithms
- `pdf-extract` - PDF text extraction
- `serde_json_path` - JSONPath queries
- `zip`, `tar`, `flate2` - Archive handling
- `notify` - File system watching

## [0.1.8] - 2026-01-11

### Fixed
- JSON Schema compatibility with Draft 7 for Gemini and Qwen clients

## [0.1.5] - 2024-12-30

### Fixed
- **grep_files**: Fixed rare bug where searching a single file path (not directory) returned zero matches. The function now correctly handles both file and directory paths. Previously, passing a file path like `/path/to/file.rs` would silently fail because the code tried to `read_dir()` on a file. This is an edge case since grep is typically used on directories, but it's now properly supported.

## [0.1.4] - Previous

- Initial release with filesystem operations
- read_text_file, write_file, edit_file, grep_files, search_files
- Binary file operations
- Bulk edits support
