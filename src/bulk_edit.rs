use std::path::PathBuf;

use anyhow::{Result, Context};
use tokio::fs;

use crate::allowed::AllowedDirs;
use crate::edit::{FileEdit, apply_edits};
use crate::fs_ops::read_text;
use crate::search::search_paths;

/// Result of editing a single file
#[derive(Debug, Clone)]
pub struct BulkEditResult {
    /// Path to edited file
    pub path: PathBuf,
    /// Whether file was modified
    pub modified: bool,
    /// Unified diff (if modified)
    pub diff: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Apply same edits to multiple files matching pattern
pub async fn bulk_edit_files(
    root: &str,
    pattern: &str,
    exclude_patterns: &[String],
    edits: &[FileEdit],
    dry_run: bool,
    allowed: &AllowedDirs,
    allow_symlink_escape: bool,
) -> Result<Vec<BulkEditResult>> {
    // Find matching files
    let paths = search_paths(root, pattern, exclude_patterns, allowed, allow_symlink_escape)
        .await
        .context("Failed to search for files")?;

    let mut results = Vec::new();

    for path in paths {
        // Skip directories
        if path.is_dir() {
            continue;
        }

        // Try to read as text
        let content = match read_text(&path).await {
            Ok(c) => c,
            Err(e) => {
                results.push(BulkEditResult {
                    path,
                    modified: false,
                    diff: None,
                    error: Some(format!("Failed to read file: {}", e)),
                });
                continue;
            }
        };

        // Apply edits
        match apply_edits(&content, edits) {
            Ok((modified, diff)) => {
                let changed = content != modified;

                // Write if modified and not dry run
                if changed && !dry_run && let Err(e) = fs::write(&path, &modified).await {
                    results.push(BulkEditResult {
                        path,
                        modified: false,
                        diff: None,
                        error: Some(format!("Failed to write file: {}", e)),
                    });
                    continue;
                }

                results.push(BulkEditResult {
                    path,
                    modified: changed,
                    diff: if changed { Some(diff) } else { None },
                    error: None,
                });
            }
            Err(e) => {
                results.push(BulkEditResult {
                    path,
                    modified: false,
                    diff: None,
                    error: Some(format!("Edit failed: {}", e)),
                });
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowed::AllowedDirs;
    use tempfile::TempDir;
    use tokio::fs;

    #[tokio::test]
    async fn test_bulk_edit_multiple_files() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create test files
        fs::write(root.join("file1.txt"), "hello world\ntest line\n")
            .await
            .unwrap();
        fs::write(root.join("file2.txt"), "hello world\nanother test\n")
            .await
            .unwrap();

        let allowed_dirs = AllowedDirs::new(vec![root.to_path_buf()]);

        let edits = vec![FileEdit {
            old_text: "hello".to_string(),
            new_text: "goodbye".to_string(),
            is_regex: false,
            replace_all: false,
        }];

        let results = bulk_edit_files(
            root.to_str().unwrap(),
            "*.txt",
            &[],
            &edits,
            false,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.modified));
        assert!(results.iter().all(|r| r.error.is_none()));

        // Verify changes were applied
        let content1 = fs::read_to_string(root.join("file1.txt"))
            .await
            .unwrap();
        assert!(content1.contains("goodbye world"));

        let content2 = fs::read_to_string(root.join("file2.txt"))
            .await
            .unwrap();
        assert!(content2.contains("goodbye world"));
    }

    #[tokio::test]
    async fn test_bulk_edit_dry_run() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("file.txt"), "original content\n")
            .await
            .unwrap();

        let allowed_dirs = AllowedDirs::new(vec![root.to_path_buf()]);

        let edits = vec![FileEdit {
            old_text: "original".to_string(),
            new_text: "modified".to_string(),
            is_regex: false,
            replace_all: false,
        }];

        let results = bulk_edit_files(
            root.to_str().unwrap(),
            "*.txt",
            &[],
            &edits,
            true, // dry_run = true
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].modified);
        assert!(results[0].diff.is_some());

        // Verify file was NOT changed
        let content = fs::read_to_string(root.join("file.txt"))
            .await
            .unwrap();
        assert_eq!(content, "original content\n");
    }

    #[tokio::test]
    async fn test_bulk_edit_with_exclude() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("file1.txt"), "hello\n").await.unwrap();
        fs::write(root.join("file2.txt"), "hello\n").await.unwrap();
        fs::write(root.join("skip.txt"), "hello\n").await.unwrap();

        let allowed_dirs = AllowedDirs::new(vec![root.to_path_buf()]);

        let edits = vec![FileEdit {
            old_text: "hello".to_string(),
            new_text: "bye".to_string(),
            is_regex: false,
            replace_all: false,
        }];

        let results = bulk_edit_files(
            root.to_str().unwrap(),
            "*.txt",
            &["skip.txt".to_string()],
            &edits,
            false,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        // Only 2 files should be processed (skip.txt excluded)
        assert_eq!(results.len(), 2);

        // Verify skip.txt was not modified
        let skip_content = fs::read_to_string(root.join("skip.txt"))
            .await
            .unwrap();
        assert_eq!(skip_content, "hello\n");
    }

    #[tokio::test]
    async fn test_bulk_edit_no_matches() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("file.txt"), "content\n").await.unwrap();

        let allowed_dirs = AllowedDirs::new(vec![root.to_path_buf()]);

        let edits = vec![FileEdit {
            old_text: "notfound".to_string(),
            new_text: "replacement".to_string(),
            is_regex: false,
            replace_all: false,
        }];

        let results = bulk_edit_files(
            root.to_str().unwrap(),
            "*.txt",
            &[],
            &edits,
            false,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(!results[0].modified);
        assert!(results[0].diff.is_none());
    }

    #[tokio::test]
    async fn test_bulk_edit_replace_all() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // File with multiple occurrences
        fs::write(root.join("file.txt"), "foo bar foo baz foo\n")
            .await
            .unwrap();

        let allowed_dirs = AllowedDirs::new(vec![root.to_path_buf()]);

        let edits = vec![FileEdit {
            old_text: "foo".to_string(),
            new_text: "qux".to_string(),
            is_regex: false,
            replace_all: true,
        }];

        let results = bulk_edit_files(
            root.to_str().unwrap(),
            "*.txt",
            &[],
            &edits,
            false,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].modified);

        let content = fs::read_to_string(root.join("file.txt"))
            .await
            .unwrap();
        assert_eq!(content, "qux bar qux baz qux\n");
    }

    #[tokio::test]
    async fn test_bulk_edit_regex_with_capture_groups() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(
            root.join("imports.rs"),
            "use crate::cache_man;\nuse crate::event_bus;\nuse crate::workers;\n",
        )
        .await
        .unwrap();

        let allowed_dirs = AllowedDirs::new(vec![root.to_path_buf()]);

        let edits = vec![FileEdit {
            old_text: r"use crate::(cache_man|event_bus|workers)".to_string(),
            new_text: "use crate::core::$1".to_string(),
            is_regex: true,
            replace_all: true,
        }];

        let results = bulk_edit_files(
            root.to_str().unwrap(),
            "*.rs",
            &[],
            &edits,
            false,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].modified);

        let content = fs::read_to_string(root.join("imports.rs"))
            .await
            .unwrap();
        assert!(content.contains("use crate::core::cache_man"));
        assert!(content.contains("use crate::core::event_bus"));
        assert!(content.contains("use crate::core::workers"));
    }

    #[tokio::test]
    async fn test_bulk_edit_regex_first_only() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("file.txt"), "aaa bbb aaa ccc aaa\n")
            .await
            .unwrap();

        let allowed_dirs = AllowedDirs::new(vec![root.to_path_buf()]);

        let edits = vec![FileEdit {
            old_text: "aaa".to_string(),
            new_text: "XXX".to_string(),
            is_regex: true,
            replace_all: false, // Only first match
        }];

        let results = bulk_edit_files(
            root.to_str().unwrap(),
            "*.txt",
            &[],
            &edits,
            false,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        assert!(results[0].modified);

        let content = fs::read_to_string(root.join("file.txt"))
            .await
            .unwrap();
        // Only first aaa replaced
        assert_eq!(content, "XXX bbb aaa ccc aaa\n");
    }

    #[tokio::test]
    async fn test_bulk_edit_regex_multiple_files() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create subdirectory structure in temp
        let project = root.join("project");
        fs::create_dir(&project).await.unwrap();

        // Multiple files with imports to refactor
        fs::write(
            project.join("main.rs"),
            "use crate::cache_man;\nuse crate::event_bus;\nfn main() {}\n",
        )
        .await
        .unwrap();

        fs::write(
            project.join("lib.rs"),
            "use crate::workers;\nuse crate::cache_man;\npub mod core;\n",
        )
        .await
        .unwrap();

        fs::write(
            project.join("utils.rs"),
            "use crate::event_bus;\nuse std::io;\n",
        )
        .await
        .unwrap();

        // File without matching imports (should not be modified)
        fs::write(
            project.join("other.rs"),
            "use std::collections::HashMap;\nfn foo() {}\n",
        )
        .await
        .unwrap();

        let allowed_dirs = AllowedDirs::new(vec![root.to_path_buf()]);

        let edits = vec![FileEdit {
            old_text: r"use crate::(cache_man|event_bus|workers)".to_string(),
            new_text: "use crate::core::$1".to_string(),
            is_regex: true,
            replace_all: true,
        }];

        let results = bulk_edit_files(
            project.to_str().unwrap(),
            "**/*.rs",
            &[],
            &edits,
            false,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        // 4 files processed
        assert_eq!(results.len(), 4);

        // 3 files modified (main.rs, lib.rs, utils.rs)
        let modified_count = results.iter().filter(|r| r.modified).count();
        assert_eq!(modified_count, 3);

        // Verify main.rs
        let main_content = fs::read_to_string(project.join("main.rs")).await.unwrap();
        assert!(main_content.contains("use crate::core::cache_man"));
        assert!(main_content.contains("use crate::core::event_bus"));

        // Verify lib.rs
        let lib_content = fs::read_to_string(project.join("lib.rs")).await.unwrap();
        assert!(lib_content.contains("use crate::core::workers"));
        assert!(lib_content.contains("use crate::core::cache_man"));

        // Verify utils.rs
        let utils_content = fs::read_to_string(project.join("utils.rs")).await.unwrap();
        assert!(utils_content.contains("use crate::core::event_bus"));
        assert!(utils_content.contains("use std::io")); // unchanged

        // Verify other.rs not modified
        let other_content = fs::read_to_string(project.join("other.rs")).await.unwrap();
        assert_eq!(other_content, "use std::collections::HashMap;\nfn foo() {}\n");
    }
}
