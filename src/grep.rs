use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::{Regex, RegexBuilder};
use tokio::fs;

use crate::allowed::AllowedDirs;
use crate::fs_ops::read_text;
use crate::path::resolve_validated_path;

/// Result of a grep match in a file
#[derive(Debug, Clone)]
pub struct GrepMatch {
    /// Path to file containing match
    pub path: PathBuf,
    /// Line number (1-indexed)
    pub line_number: usize,
    /// Matched line content
    pub line: String,
    /// Context lines before match (if requested)
    pub before_context: Vec<String>,
    /// Context lines after match (if requested)
    pub after_context: Vec<String>,
}

/// Grep search parameters
pub struct GrepParams {
    /// Root directory to search
    pub root: String,
    /// Regex pattern to search for
    pub pattern: String,
    /// Glob pattern for files to include (e.g., "*.rs", "**/*.txt")
    pub file_pattern: Option<String>,
    /// Case-insensitive search
    pub case_insensitive: bool,
    /// Number of context lines before match
    pub context_before: usize,
    /// Number of context lines after match
    pub context_after: usize,
    /// Maximum number of matches to return (0 = unlimited)
    pub max_matches: usize,
}

/// Search for pattern in files
pub async fn grep_files(
    params: GrepParams,
    allowed: &AllowedDirs,
    allow_symlink_escape: bool,
) -> Result<Vec<GrepMatch>> {
    let root_path = resolve_validated_path(&params.root, allowed, allow_symlink_escape)
        .await
        .context("Invalid root path")?;

    // Build regex pattern
    let regex = RegexBuilder::new(&params.pattern)
        .case_insensitive(params.case_insensitive)
        .build()
        .context("Invalid regex pattern")?;

    // Build file matcher
    let file_matcher = if let Some(pattern) = &params.file_pattern {
        Some(build_glob(pattern)?)
    } else {
        None
    };

    let mut matches = Vec::new();
    let mut total_matches = 0;

    // Walk directory tree
    let mut stack = vec![root_path.clone()];
    while let Some(current) = stack.pop() {
        if params.max_matches > 0 && total_matches >= params.max_matches {
            break;
        }

        let mut dir = match fs::read_dir(&current).await {
            Ok(d) => d,
            Err(_) => continue, // Skip unreadable dirs
        };

        while let Some(entry) = dir.next_entry().await? {
            if params.max_matches > 0 && total_matches >= params.max_matches {
                break;
            }

            let path = entry.path();

            // Validate path (symlink-safe)
            if resolve_validated_path(
                path.to_string_lossy().as_ref(),
                allowed,
                allow_symlink_escape,
            )
            .await
            .is_err()
            {
                continue;
            }

            let file_type = match entry.file_type().await {
                Ok(ft) => ft,
                Err(_) => continue,
            };

            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                // Check file pattern match
                if let Some(matcher) = &file_matcher {
                    let rel = path.strip_prefix(&root_path).unwrap_or(&path);
                    if !matcher.is_match(rel.to_string_lossy().as_ref()) {
                        continue;
                    }
                }

                // Search file content
                // Use saturating_sub to prevent underflow when total_matches >= max_matches
                let remaining = params.max_matches.saturating_sub(total_matches);
                if remaining == 0 && params.max_matches > 0 {
                    break; // Already at limit
                }

                if let Ok(file_matches) = search_file(
                    &path,
                    &regex,
                    params.context_before,
                    params.context_after,
                    remaining,
                )
                .await
                {
                    total_matches += file_matches.len();
                    matches.extend(file_matches);
                }
            }
        }
    }

    Ok(matches)
}

/// Search for pattern in a single file
async fn search_file(
    path: &Path,
    regex: &Regex,
    context_before: usize,
    context_after: usize,
    max_matches: usize,
) -> Result<Vec<GrepMatch>> {
    // Try to read as text
    let content = match read_text(path).await {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()), // Skip binary/unreadable files
    };

    let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    let mut matches = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        if max_matches > 0 && matches.len() >= max_matches {
            break;
        }

        if regex.is_match(&lines[i]) {
            let before_start = i.saturating_sub(context_before);
            let after_end = (i + 1 + context_after).min(lines.len());

            let before_context = if context_before > 0 {
                lines[before_start..i].to_vec()
            } else {
                Vec::new()
            };

            let after_context = if context_after > 0 {
                lines[(i + 1)..after_end].to_vec()
            } else {
                Vec::new()
            };

            matches.push(GrepMatch {
                path: path.to_path_buf(),
                line_number: i + 1, // 1-indexed
                line: lines[i].clone(),
                before_context,
                after_context,
            });
        }

        i += 1;
    }

    Ok(matches)
}

fn build_glob(pattern: &str) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    builder.add(Glob::new(pattern)?);
    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::fs;

    // Regression test: max_matches underflow prevention (fixed with saturating_sub)

    #[tokio::test]
    async fn test_max_matches_no_underflow() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create files with many matches
        fs::write(root.join("file1.txt"), "match\nmatch\nmatch\nmatch\nmatch\n")
            .await
            .unwrap();
        fs::write(root.join("file2.txt"), "match\nmatch\nmatch\nmatch\nmatch\n")
            .await
            .unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let params = GrepParams {
            root: root.to_string_lossy().to_string(),
            pattern: "match".to_string(),
            file_pattern: Some("*.txt".to_string()),
            case_insensitive: false,
            context_before: 0,
            context_after: 0,
            max_matches: 3, // Limit to 3, but there are 10 matches
        };

        // BUG: If first file returns 5 matches, then max_matches - total_matches
        // becomes 3 - 5 = underflow (huge number in usize)
        // This could cause search_file to return way more than expected
        let result = grep_files(params, &allowed, false).await;

        assert!(result.is_ok(), "Should not panic on underflow");
        let matches = result.unwrap();

        // Should have at most max_matches results
        assert!(
            matches.len() <= 3,
            "Should respect max_matches limit. Got {} matches",
            matches.len()
        );
    }

    #[tokio::test]
    async fn test_max_matches_exact_limit() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Create file with exactly max_matches
        fs::write(root.join("file.txt"), "a\nb\nc\n")
            .await
            .unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let params = GrepParams {
            root: root.to_string_lossy().to_string(),
            pattern: "[abc]".to_string(),
            file_pattern: None,
            case_insensitive: false,
            context_before: 0,
            context_after: 0,
            max_matches: 3,
        };

        let result = grep_files(params, &allowed, false).await.unwrap();
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_grep_empty_file() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("empty.txt"), "").await.unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let params = GrepParams {
            root: root.to_string_lossy().to_string(),
            pattern: "anything".to_string(),
            file_pattern: None,
            case_insensitive: false,
            context_before: 0,
            context_after: 0,
            max_matches: 100,
        };

        let result = grep_files(params, &allowed, false).await.unwrap();
        assert_eq!(result.len(), 0, "Empty file should have no matches");
    }
}
