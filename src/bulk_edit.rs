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
                if changed && !dry_run {
                    if let Err(e) = fs::write(&path, &modified).await {
                        results.push(BulkEditResult {
                            path,
                            modified: false,
                            diff: None,
                            error: Some(format!("Failed to write file: {}", e)),
                        });
                        continue;
                    }
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
