# BUG6 — CLI `allowed_dirs` Wiped by MCP `roots/list` & `--allow-symlink-escape` Traversal Gaps

## Summary

Two distinct issues in `src/main.rs`, `src/core/allowed.rs`, and `src/core/path.rs` cause unexpected
`Access denied - path outside allowed directories` errors even when the server is launched with
`filesystem-mcp-rs --allow-symlink-escape C:\ D:\`:

1. **Bug 1 (`refresh_roots` overwrites CLI `allowed_dirs`)**: When an MCP client (Antigravity, Cursor,
   Claude Code, etc.) emits `notifications/roots/list_changed`, `FileSystemServer::refresh_roots` calls
   `self.allowed.set(validated)`, which **replaces** the CLI `allowed_dirs` (`C:\`, `D:\`) with the
   client's single workspace root (e.g. `\\?\C:\projects\...\maya-rs`).
2. **Bug 2 (`--allow-symlink-escape` only checks the leaf component and ignores `NotFound` parents)**:
   In `resolve_validated_path` (`src/core/path.rs`), `--allow-symlink-escape` only works when the
   **leaf path itself** is an existing symlink. Any file or subdirectory **inside** a symlinked or
   junction directory (or any newly created file under a symlinked directory) is rejected.

---

## Bug 1: `refresh_roots` Replaces CLI `allowed_dirs` Instead of Merging or Respecting Explicit CLI Roots

### Evidence

1. `filesystem-mcp-rs install` (`src/setup.rs:100-130`) configures the server command line with:
   ```json
   "args": ["--allow-symlink-escape", "C:\\", "D:\\"]
   ```
   specifically so the server starts with full-disk access across mounted drives.
2. Process inspection confirms the server is spawned with those arguments:
   ```text
   filesystem-mcp-rs.exe --allow-symlink-escape C:\ D:\
   ```
3. At startup (`src/main.rs:8625`), `AllowedDirs::new(args.allowed_dirs)` populates `self.allowed`
   with `["\\\\?\\C:\\", "\\\\?\\D:\\"]`.
4. Immediately after handshake, the MCP client sends `notifications/roots/list_changed`
   (`src/main.rs:8390-8397`), which invokes `FileSystemServer::refresh_roots` (`src/main.rs:635-663`):
   ```rust
   let validated = self.parse_roots(&roots).await?;
   if !validated.is_empty() {
       self.allowed.set(validated).await;
   }
   ```
5. `AllowedDirs::set` (`src/core/allowed.rs:19-22`) overwrites `inner` completely:
   ```rust
   pub async fn set(&self, dirs: Vec<PathBuf>) {
       let mut guard = self.inner.write().await;
       *guard = normalize_many(dirs);
   }
   ```
6. As a result, `list_allowed_directories` drops `C:\` and `D:\` and reports only the active IDE
   workspace folder (`\\?\C:\projects\projects.rust.cg\cglibs\maya-rs`), denying access to sibling
   repositories or any other path on `C:\` / `D:\`.

### Recommended Fix

Preserve the initial CLI `allowed_dirs` as an immutable `base: Arc<Vec<PathBuf>>` inside `AllowedDirs`
(or union `base` + `roots` in `AllowedDirs::set` without duplicates):
- When `filesystem-mcp-rs` is started with no CLI directories (`[]`), `base` is empty and `set(roots)`
  behaves identically to today.
- When `filesystem-mcp-rs` is started with explicit CLI directories (`C:\`, `D:\`), `set(roots)` keeps
  `base` and appends any client roots not already covered.

---

## Bug 2: `--allow-symlink-escape` Fails on Files Inside Symlinked / Junction Directories and on New Files

### Evidence (`src/core/path.rs:56-113`)

Currently, `resolve_validated_path` handles `allow_symlink_escape` as follows:

```rust
match fs::canonicalize(&normalized).await {
    Ok(real) => {
        if !is_within_allowed(&real, &allowed_snapshot) {
            if allow_symlink_escape {
                let meta = fs::symlink_metadata(&normalized).await?;
                if meta.file_type().is_symlink() {
                    if let Some(parent) = normalized.parent() {
                        let canonical_parent = fs::canonicalize(parent)
                            .await
                            .unwrap_or_else(|_| parent.to_path_buf());
                        let canonical_link =
                            canonical_parent.join(normalized.file_name().unwrap_or_default());
                        if is_within_allowed(&canonical_link, &allowed_snapshot) {
                            return Ok(normalized);
                        }
                    }
                }
            }
            bail!(
                "Access denied - path outside allowed directories: {}",
                real.display()
            );
        }
        Ok(real)
    }
    Err(err) => {
        if err.kind() == std::io::ErrorKind::NotFound {
            // walks up to existing_parent, canonicalizes it, and checks:
            if !is_within_allowed(&parent_real, &allowed_snapshot) {
                bail!(
                    "Access denied - parent directory outside allowed directories: {}",
                    parent_real.display()
                );
            }
            Ok(normalized)
        }
        ...
    }
}
```

### Three Concrete Failure Modes

1. **Accessing a file inside a symlinked directory or Windows junction (`allowed/link_dir/file.txt`)**:
   - Suppose `allowed` contains `C:\workspace`, and `C:\workspace\ext_link` is a directory symlink or
     NTFS junction (`mklink /J`) pointing to `D:\shared\assets`.
   - Requesting `C:\workspace\ext_link\mesh.obj`:
     - `fs::canonicalize(&normalized)` resolves to `\\?\D:\shared\assets\mesh.obj` (outside `allowed`).
     - `fs::symlink_metadata(&normalized)` inspects `mesh.obj` (the leaf), which is a **regular file**,
       not a symlink (`meta.file_type().is_symlink() == false`).
     - Even if it checked `parent`, `fs::canonicalize(parent)` resolves `C:\workspace\ext_link` to
       `\\?\D:\shared\assets`, which is also outside `allowed`.
     - Result: `Access denied - path outside allowed directories: \\?\D:\shared\assets\mesh.obj`.

2. **Creating/writing a new file inside a symlinked directory (`allowed/link_dir/new_file.txt`)**:
   - `fs::canonicalize(&normalized)` returns `Err(NotFound)`.
   - The `NotFound` branch finds `existing_parent = C:\workspace\ext_link`, canonicalizes it to
     `parent_real = \\?\D:\shared\assets`, and checks `is_within_allowed(&parent_real, &allowed_snapshot)`
     without consulting `allow_symlink_escape` at all.
   - Result: `Access denied - parent directory outside allowed directories: \\?\D:\shared\assets`.

3. **Windows NTFS Junctions (`IO_REPARSE_TAG_MOUNT_POINT`)**:
   - On Windows, directory junctions created via `mklink /J` or Python/Rust junction helpers have
     `FILE_ATTRIBUTE_REPARSE_POINT` with `IO_REPARSE_TAG_MOUNT_POINT` rather than
     `IO_REPARSE_TAG_SYMLINK`. Depending on the Rust std / OS check used, leaf-only `is_symlink()`
     checks miss ancestor reparse points unless the path prefix is lexical-checked against an allowed
     directory before following the first symlink/reparse component.

### Recommended Fix for `resolve_validated_path` (`--allow-symlink-escape` Option Contract)

- **When `--allow-symlink-escape` is `false` (default)**: strict canonical containment (`real` path must
  be inside `allowed_snapshot`). Any symlink or junction pointing outside `allowed_snapshot` is denied.
- **When `--allow-symlink-escape` is `true` (opt-in flag)**:
  - Walk the components of `normalized` from the root (or longest matching allowed directory prefix).
  - Verify that the lexical prefix up to the **first** symlink / NTFS junction (`IO_REPARSE_TAG_MOUNT_POINT`
    or `IO_REPARSE_TAG_SYMLINK`), canonicalized up to that parent, resides within `allowed_snapshot`
    (with no `..` escaping above the allowed root prior to entering the symlink/junction).
  - Once a symlink/junction inside `allowed_snapshot` is entered, allow both reading existing files/subdirs
    and creating new files (`NotFound` branch) inside the target tree.
