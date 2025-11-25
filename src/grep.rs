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
                if let Ok(file_matches) = search_file(
                    &path,
                    &regex,
                    params.context_before,
                    params.context_after,
                    params.max_matches - total_matches,
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
