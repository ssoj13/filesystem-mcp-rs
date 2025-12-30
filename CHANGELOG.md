# Changelog

## [0.1.5] - 2024-12-30

### Fixed
- **grep_files**: Fixed rare bug where searching a single file path (not directory) returned zero matches. The function now correctly handles both file and directory paths. Previously, passing a file path like `/path/to/file.rs` would silently fail because the code tried to `read_dir()` on a file. This is an edge case since grep is typically used on directories, but it's now properly supported.

## [0.1.4] - Previous

- Initial release with filesystem operations
- read_text_file, write_file, edit_file, grep_files, search_files
- Binary file operations
- Bulk edits support
