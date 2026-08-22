//! File utilities - file_diff, file_touch.

use anyhow::{Context, Result};
use serde_json::{Value, json};
use similar::{ChangeTag, TextDiff};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::time::SystemTime;

/// Compare two files and return diff
pub fn file_diff(path1: &Path, path2: &Path, context_lines: usize) -> Result<Value> {
    let content1 =
        fs::read_to_string(path1).with_context(|| format!("Failed to read {}", path1.display()))?;
    let content2 =
        fs::read_to_string(path2).with_context(|| format!("Failed to read {}", path2.display()))?;

    let diff = TextDiff::from_lines(&content1, &content2);

    let mut hunks = Vec::new();
    let mut additions = 0;
    let mut deletions = 0;
    let mut current_hunk: Vec<Value> = Vec::new();
    let mut hunk_start_old = 0;
    let mut hunk_start_new = 0;

    for change in diff.iter_all_changes() {
        let tag = change.tag();
        let line_content = change.value();

        match tag {
            ChangeTag::Delete => {
                deletions += 1;
                if current_hunk.is_empty() {
                    hunk_start_old = change.old_index().unwrap_or(0);
                    hunk_start_new = change.new_index().unwrap_or(0);
                }
                current_hunk.push(json!({
                    "type": "delete",
                    "line": line_content.trim_end(),
                    "old_line_no": change.old_index().map(|i| i + 1)
                }));
            }
            ChangeTag::Insert => {
                additions += 1;
                if current_hunk.is_empty() {
                    hunk_start_old = change.old_index().unwrap_or(0);
                    hunk_start_new = change.new_index().unwrap_or(0);
                }
                current_hunk.push(json!({
                    "type": "insert",
                    "line": line_content.trim_end(),
                    "new_line_no": change.new_index().map(|i| i + 1)
                }));
            }
            ChangeTag::Equal => {
                // Add context lines around changes
                if !current_hunk.is_empty() {
                    current_hunk.push(json!({
                        "type": "context",
                        "line": line_content.trim_end(),
                        "old_line_no": change.old_index().map(|i| i + 1),
                        "new_line_no": change.new_index().map(|i| i + 1)
                    }));

                    // Check if we should close hunk (context_lines equal lines in a row)
                    let equal_count = current_hunk
                        .iter()
                        .rev()
                        .take_while(|v| v.get("type").and_then(|t| t.as_str()) == Some("context"))
                        .count();

                    if equal_count > context_lines * 2 {
                        // Close hunk, trim trailing context
                        if !current_hunk.is_empty()
                            && let Some(last) = current_hunk.last()
                            && last.get("type").and_then(|t| t.as_str()) == Some("context")
                        {
                            // Drop trailing context beyond context_lines
                            current_hunk.truncate(current_hunk.len().saturating_sub(context_lines));
                            if current_hunk
                                .iter()
                                .any(|v| v.get("type").and_then(|t| t.as_str()) != Some("context"))
                            {
                                hunks.push(json!({
                                    "old_start": hunk_start_old + 1,
                                    "new_start": hunk_start_new + 1,
                                    "changes": current_hunk
                                }));
                            }
                            current_hunk = Vec::new();
                        }
                    }
                }
            }
        }
    }

    // Add remaining hunk
    if !current_hunk.is_empty()
        && current_hunk
            .iter()
            .any(|v| v.get("type").and_then(|t| t.as_str()) != Some("context"))
    {
        hunks.push(json!({
            "old_start": hunk_start_old + 1,
            "new_start": hunk_start_new + 1,
            "changes": current_hunk
        }));
    }

    // Generate unified diff string
    let unified = diff
        .unified_diff()
        .context_radius(context_lines)
        .header(&path1.to_string_lossy(), &path2.to_string_lossy())
        .to_string();

    Ok(json!({
        "file1": path1.to_string_lossy(),
        "file2": path2.to_string_lossy(),
        "identical": additions == 0 && deletions == 0,
        "additions": additions,
        "deletions": deletions,
        "hunks": hunks,
        "unified_diff": unified
    }))
}

/// Create file or update its timestamp (like touch command)
pub fn file_touch(path: &Path, create_parents: bool) -> Result<Value> {
    // Create parent directories if requested
    if create_parents && let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("Failed to create parent directories")?;
    }

    let created = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(_) => true,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            touch_existing_file(path)?;
            false
        }
        Err(e) => return Err(e).context("Failed to create file"),
    };

    let metadata = fs::metadata(path).context("Failed to get metadata")?;

    Ok(json!({
        "path": path.to_string_lossy(),
        "created": created,
        "updated": !created,
        "size": metadata.len(),
        "modified": metadata.modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
    }))
}

fn touch_existing_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let now = SystemTime::now();
        std::fs::File::open(path)
            .and_then(|f| {
                f.set_times(
                    std::fs::FileTimes::new()
                        .set_accessed(now)
                        .set_modified(now),
                )
            })
            .context("Failed to update timestamp")?;
    }
    #[cfg(not(unix))]
    {
        // On Windows (NTFS) opening in append mode without actually writing any
        // bytes does NOT advance mtime, so a plain open was a silent no-op and
        // build tools like cargo never saw the "touch". Set the timestamp
        // explicitly, mirroring the Unix branch. `set_times` needs the file
        // opened with write access on Windows.
        let now = SystemTime::now();
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|f| {
                f.set_times(
                    std::fs::FileTimes::new()
                        .set_accessed(now)
                        .set_modified(now),
                )
            })
            .context("Failed to update timestamp")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_file_touch_advances_mtime() {
        use std::time::Duration;
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("stale.txt");
        fs::write(&file, b"x").unwrap();

        // Backdate the file so the assertion can't be fooled by coarse
        // filesystem timestamp resolution.
        let past = SystemTime::now() - Duration::from_secs(3600);
        let f = fs::OpenOptions::new().write(true).open(&file).unwrap();
        f.set_times(std::fs::FileTimes::new().set_modified(past))
            .unwrap();
        drop(f);
        let before = fs::metadata(&file).unwrap().modified().unwrap();

        file_touch(&file, false).unwrap();

        let after = fs::metadata(&file).unwrap().modified().unwrap();
        assert!(
            after > before,
            "file_touch must advance mtime: before={before:?} after={after:?}"
        );
    }

    #[test]
    fn test_file_diff_identical() {
        let dir = TempDir::new().unwrap();
        let file1 = dir.path().join("a.txt");
        let file2 = dir.path().join("b.txt");

        fs::write(&file1, "hello\nworld\n").unwrap();
        fs::write(&file2, "hello\nworld\n").unwrap();

        let result = file_diff(&file1, &file2, 3).unwrap();
        assert_eq!(result["identical"], true);
        assert_eq!(result["additions"], 0);
        assert_eq!(result["deletions"], 0);
    }

    #[test]
    fn test_file_diff_changes() {
        let dir = TempDir::new().unwrap();
        let file1 = dir.path().join("a.txt");
        let file2 = dir.path().join("b.txt");

        fs::write(&file1, "line1\nline2\nline3\n").unwrap();
        fs::write(&file2, "line1\nmodified\nline3\nnew line\n").unwrap();

        let result = file_diff(&file1, &file2, 3).unwrap();
        assert_eq!(result["identical"], false);
        assert!(result["additions"].as_u64().unwrap() > 0);
        assert!(result["deletions"].as_u64().unwrap() > 0);
        assert!(result["unified_diff"].as_str().unwrap().contains("---"));
        assert!(result["unified_diff"].as_str().unwrap().contains("+++"));
    }

    #[test]
    fn test_file_diff_unicode() {
        let dir = TempDir::new().unwrap();
        let file1 = dir.path().join("a.txt");
        let file2 = dir.path().join("b.txt");

        fs::write(&file1, "Привет\n世界\n").unwrap();
        fs::write(&file2, "Привет\n世界\n🦀\n").unwrap();

        let result = file_diff(&file1, &file2, 3).unwrap();
        assert_eq!(result["additions"], 1);
        assert!(result["unified_diff"].as_str().unwrap().contains("🦀"));
    }

    #[test]
    fn test_file_touch_create() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("new_file.txt");

        assert!(!file.exists());
        let result = file_touch(&file, false).unwrap();
        assert!(file.exists());
        assert_eq!(result["created"], true);
        assert_eq!(result["updated"], false);
    }

    #[test]
    fn test_file_touch_update() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("existing.txt");
        fs::write(&file, "content").unwrap();

        let result = file_touch(&file, false).unwrap();
        assert_eq!(result["created"], false);
        assert_eq!(result["updated"], true);
    }

    #[test]
    fn test_file_touch_create_parents() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("deep").join("nested").join("file.txt");

        let result = file_touch(&file, true).unwrap();
        assert!(file.exists());
        assert_eq!(result["created"], true);
    }

    #[test]
    fn test_file_touch_unicode_path() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("файл_🦀.txt");

        let result = file_touch(&file, false).unwrap();
        assert!(file.exists());
        assert!(result["path"].as_str().unwrap().contains("🦀"));
    }
}
