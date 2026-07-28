use std::path::PathBuf;

use anyhow::{Context, Result};
use tokio::fs;

use crate::core::allowed::AllowedDirs;
use crate::tools::edit::{EditEngine, FileEdit, apply_edits_with_mode};
use crate::tools::fs_ops::read_text_meta;
use crate::tools::search::search_paths;

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
    /// Match count per edit on this file (index-aligned with input edits).
    pub matches_per_edit: Vec<usize>,
    /// How many of each edit's matches were actually applied (post overlap-resolution).
    pub applied_per_edit: Vec<usize>,
}

#[allow(clippy::too_many_arguments)]
pub async fn bulk_edit_files(
    root: &str,
    pattern: &str,
    exclude_patterns: &[String],
    edits: &[FileEdit],
    dry_run: bool,
    fail_on_no_match: bool,
    engine: EditEngine,
    allowed: &AllowedDirs,
    allow_symlink_escape: bool,
) -> Result<Vec<BulkEditResult>> {
    let paths = search_paths(
        root,
        pattern,
        exclude_patterns,
        allowed,
        allow_symlink_escape,
    )
    .await
    .context("Failed to search for files")?;

    let edit_count = edits.len();
    let mut results = Vec::new();

    for path in paths {
        if path.is_dir() {
            continue;
        }

        // Read with round-trip metadata so writes preserve the file's original
        // encoding, BOM, and newline style rather than forcing UTF-8/LF.
        let tf = match read_text_meta(&path).await {
            Ok(t) => t,
            Err(e) => {
                results.push(BulkEditResult {
                    path,
                    modified: false,
                    diff: None,
                    error: Some(format!("Failed to read file: {}", e)),
                    matches_per_edit: vec![0; edit_count],
                    applied_per_edit: vec![0; edit_count],
                });
                continue;
            }
        };
        // A file that did not decode losslessly cannot be written back without
        // corrupting its undecodable bytes: skip it with an explicit note.
        if tf.had_errors {
            results.push(BulkEditResult {
                path,
                modified: false,
                diff: None,
                error: Some("Skipped: not valid text (writing back would corrupt it)".to_string()),
                matches_per_edit: vec![0; edit_count],
                applied_per_edit: vec![0; edit_count],
            });
            continue;
        }
        let content = &tf.text;

        match apply_edits_with_mode(content, edits, fail_on_no_match, engine) {
            Ok(outcome) => {
                let changed = *content != outcome.modified;

                if changed && !dry_run {
                    let write_res = match tf.encode(&outcome.modified) {
                        Ok(bytes) => fs::write(&path, &bytes).await.map_err(anyhow::Error::from),
                        Err(e) => Err(e),
                    };
                    if let Err(e) = write_res {
                        results.push(BulkEditResult {
                            path,
                            modified: false,
                            diff: None,
                            error: Some(format!("Failed to write file: {}", e)),
                            matches_per_edit: outcome.matches_per_edit,
                            applied_per_edit: outcome.applied_per_edit,
                        });
                        continue;
                    }
                }

                results.push(BulkEditResult {
                    path,
                    modified: changed,
                    diff: if changed { Some(outcome.diff) } else { None },
                    error: None,
                    matches_per_edit: outcome.matches_per_edit,
                    applied_per_edit: outcome.applied_per_edit,
                });
            }
            Err(e) => {
                results.push(BulkEditResult {
                    path,
                    modified: false,
                    diff: None,
                    error: Some(format!("Edit failed: {}", e)),
                    matches_per_edit: vec![0; edit_count],
                    applied_per_edit: vec![0; edit_count],
                });
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::allowed::AllowedDirs;
    use tempfile::TempDir;
    use tokio::fs;

    #[tokio::test]
    async fn test_bulk_edit_multiple_files() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
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
            false,
            EditEngine::Regex,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.modified));
        assert!(results.iter().all(|r| r.error.is_none()));

        let content1 = fs::read_to_string(root.join("file1.txt")).await.unwrap();
        assert!(content1.contains("goodbye world"));

        let content2 = fs::read_to_string(root.join("file2.txt")).await.unwrap();
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
            true,
            false,
            EditEngine::Regex,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].modified);
        assert!(results[0].diff.is_some());

        let content = fs::read_to_string(root.join("file.txt")).await.unwrap();
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
            false,
            EditEngine::Regex,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 2);

        let skip_content = fs::read_to_string(root.join("skip.txt")).await.unwrap();
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
            false,
            EditEngine::Regex,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(!results[0].modified);
        assert!(results[0].diff.is_none());
        assert_eq!(results[0].matches_per_edit, vec![0]);
    }

    #[tokio::test]
    async fn test_bulk_edit_replace_all() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

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
            false,
            EditEngine::Regex,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].modified);
        assert_eq!(results[0].applied_per_edit, vec![3]);

        let content = fs::read_to_string(root.join("file.txt")).await.unwrap();
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
            false,
            EditEngine::Regex,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].modified);
        assert_eq!(results[0].applied_per_edit, vec![3]);

        let content = fs::read_to_string(root.join("imports.rs")).await.unwrap();
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
            replace_all: false,
        }];

        let results = bulk_edit_files(
            root.to_str().unwrap(),
            "*.txt",
            &[],
            &edits,
            false,
            false,
            EditEngine::Regex,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        assert!(results[0].modified);

        let content = fs::read_to_string(root.join("file.txt")).await.unwrap();
        assert_eq!(content, "XXX bbb aaa ccc aaa\n");
    }

    #[tokio::test]
    async fn test_bulk_edit_regex_multiple_files() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        let project = root.join("project");
        fs::create_dir(&project).await.unwrap();

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
            false,
            EditEngine::Regex,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        assert_eq!(results.len(), 4);

        let modified_count = results.iter().filter(|r| r.modified).count();
        assert_eq!(modified_count, 3);

        let main_content = fs::read_to_string(project.join("main.rs")).await.unwrap();
        assert!(main_content.contains("use crate::core::cache_man"));
        assert!(main_content.contains("use crate::core::event_bus"));

        let lib_content = fs::read_to_string(project.join("lib.rs")).await.unwrap();
        assert!(lib_content.contains("use crate::core::workers"));
        assert!(lib_content.contains("use crate::core::cache_man"));

        let utils_content = fs::read_to_string(project.join("utils.rs")).await.unwrap();
        assert!(utils_content.contains("use crate::core::event_bus"));
        assert!(utils_content.contains("use std::io"));

        let other_content = fs::read_to_string(project.join("other.rs")).await.unwrap();
        assert_eq!(
            other_content,
            "use std::collections::HashMap;\nfn foo() {}\n"
        );
    }

    #[tokio::test]
    async fn test_bulk_edit_fancy_engine_lookahead() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(
            root.join("a.rs"),
            "let active = foo;\nlet inactive = bar; // disabled\nlet active2 = baz;\n",
        )
        .await
        .unwrap();

        let allowed_dirs = AllowedDirs::new(vec![root.to_path_buf()]);

        let edits = vec![FileEdit {
            // Match `let X = Y;` only when NOT followed by `// disabled`.
            old_text: r"let \w+ = \w+;(?!\s*//\s*disabled)".to_string(),
            new_text: "// ACTIVE".to_string(),
            is_regex: true,
            replace_all: true,
        }];

        let _ = bulk_edit_files(
            root.to_str().unwrap(),
            "*.rs",
            &[],
            &edits,
            false,
            false,
            EditEngine::Fancy,
            &allowed_dirs,
            false,
        )
        .await
        .unwrap();

        let content = fs::read_to_string(root.join("a.rs")).await.unwrap();
        assert!(content.contains("// ACTIVE"));
        assert!(content.contains("// disabled"));
        // Two `let active...` lines replaced, the disabled one survived.
        assert_eq!(content.matches("// ACTIVE").count(), 2);
    }
}
