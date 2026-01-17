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

/// Grep output mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GrepOutputMode {
    /// Default: return matching lines with content
    #[default]
    Content,
    /// Only count matches per file
    CountOnly,
    /// Return files that have matches (like grep -l)
    FilesWithMatches,
    /// Return files WITHOUT matches (like grep -L)
    FilesWithoutMatch,
}

/// Count result per file
#[derive(Debug, Clone)]
pub struct GrepCount {
    pub path: PathBuf,
    pub count: usize,
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
    /// Invert match: show lines NOT matching pattern
    pub invert_match: bool,
    /// Output mode
    pub output_mode: GrepOutputMode,
}

/// Enhanced grep result supporting different output modes
#[derive(Debug, Clone)]
pub enum GrepResult {
    /// Content mode: return matching lines
    Matches(Vec<GrepMatch>),
    /// Count mode: return match counts per file
    Counts(Vec<GrepCount>),
    /// Files mode: return file paths only
    Files(Vec<PathBuf>),
}

impl GrepResult {
    /// Get matches if in content mode
    pub fn matches(&self) -> Option<&Vec<GrepMatch>> {
        match self {
            GrepResult::Matches(m) => Some(m),
            _ => None,
        }
    }
    
    /// Get counts if in count mode
    pub fn counts(&self) -> Option<&Vec<GrepCount>> {
        match self {
            GrepResult::Counts(c) => Some(c),
            _ => None,
        }
    }
    
    /// Get file list if in files mode
    pub fn files(&self) -> Option<&Vec<PathBuf>> {
        match self {
            GrepResult::Files(f) => Some(f),
            _ => None,
        }
    }
    
    /// Total count of results
    pub fn len(&self) -> usize {
        match self {
            GrepResult::Matches(m) => m.len(),
            GrepResult::Counts(c) => c.len(),
            GrepResult::Files(f) => f.len(),
        }
    }
    
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Search for pattern in files
pub async fn grep_files(
    params: GrepParams,
    allowed: &AllowedDirs,
    allow_symlink_escape: bool,
) -> Result<GrepResult> {
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
    let mut counts = Vec::new();
    let mut files = Vec::new();
    let mut total_matches = 0;

    // Check if root_path is a file (not a directory)
    let metadata = fs::metadata(&root_path).await?;
    if metadata.is_file() {
        // Search single file directly
        if let Some(matcher) = &file_matcher {
            let filename = root_path.file_name().unwrap_or_default().to_string_lossy();
            if !matcher.is_match(filename.as_ref()) {
                return Ok(result_for_mode(&params.output_mode, matches, counts, files));
            }
        }
        if let Ok(file_matches) = search_file(
            &root_path,
            &regex,
            params.context_before,
            params.context_after,
            params.max_matches,
            params.invert_match,
        )
        .await
        {
            handle_file_result(
                &root_path,
                file_matches,
                &params.output_mode,
                &mut matches,
                &mut counts,
                &mut files,
            );
        }
        return Ok(result_for_mode(&params.output_mode, matches, counts, files));
    }

    // Walk directory tree
    let mut stack = vec![root_path.clone()];
    while let Some(current) = stack.pop() {
        if params.max_matches > 0 && total_matches >= params.max_matches 
           && params.output_mode == GrepOutputMode::Content {
            break;
        }

        let mut dir = match fs::read_dir(&current).await {
            Ok(d) => d,
            Err(_) => continue, // Skip unreadable dirs
        };

        while let Some(entry) = dir.next_entry().await? {
            if params.max_matches > 0 && total_matches >= params.max_matches
               && params.output_mode == GrepOutputMode::Content {
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
                let remaining = if params.output_mode == GrepOutputMode::Content {
                    params.max_matches.saturating_sub(total_matches)
                } else {
                    0 // unlimited for other modes
                };
                
                if remaining == 0 && params.max_matches > 0 
                   && params.output_mode == GrepOutputMode::Content {
                    break; // Already at limit
                }

                if let Ok(file_matches) = search_file(
                    &path,
                    &regex,
                    params.context_before,
                    params.context_after,
                    remaining,
                    params.invert_match,
                )
                .await
                {
                    total_matches += file_matches.len();
                    handle_file_result(
                        &path,
                        file_matches,
                        &params.output_mode,
                        &mut matches,
                        &mut counts,
                        &mut files,
                    );
                }
            }
        }
    }

    Ok(result_for_mode(&params.output_mode, matches, counts, files))
}

/// Handle search results based on output mode
fn handle_file_result(
    path: &Path,
    file_matches: Vec<GrepMatch>,
    output_mode: &GrepOutputMode,
    matches: &mut Vec<GrepMatch>,
    counts: &mut Vec<GrepCount>,
    files: &mut Vec<PathBuf>,
) {
    match output_mode {
        GrepOutputMode::Content => {
            matches.extend(file_matches);
        }
        GrepOutputMode::CountOnly => {
            if !file_matches.is_empty() {
                counts.push(GrepCount {
                    path: path.to_path_buf(),
                    count: file_matches.len(),
                });
            }
        }
        GrepOutputMode::FilesWithMatches => {
            if !file_matches.is_empty() {
                files.push(path.to_path_buf());
            }
        }
        GrepOutputMode::FilesWithoutMatch => {
            if file_matches.is_empty() {
                files.push(path.to_path_buf());
            }
        }
    }
}

/// Build result based on output mode
fn result_for_mode(
    mode: &GrepOutputMode,
    matches: Vec<GrepMatch>,
    counts: Vec<GrepCount>,
    files: Vec<PathBuf>,
) -> GrepResult {
    match mode {
        GrepOutputMode::Content => GrepResult::Matches(matches),
        GrepOutputMode::CountOnly => GrepResult::Counts(counts),
        GrepOutputMode::FilesWithMatches | GrepOutputMode::FilesWithoutMatch => {
            GrepResult::Files(files)
        }
    }
}

/// Search for pattern in a single file
async fn search_file(
    path: &Path,
    regex: &Regex,
    context_before: usize,
    context_after: usize,
    max_matches: usize,
    invert_match: bool,
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

        // Match or inverse match based on flag
        let line_matches = regex.is_match(&lines[i]);
        let should_include = if invert_match { !line_matches } else { line_matches };
        
        if should_include {
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

    fn default_params(root: &str, pattern: &str) -> GrepParams {
        GrepParams {
            root: root.to_string(),
            pattern: pattern.to_string(),
            file_pattern: None,
            case_insensitive: false,
            context_before: 0,
            context_after: 0,
            max_matches: 0,
            invert_match: false,
            output_mode: GrepOutputMode::Content,
        }
    }

    #[tokio::test]
    async fn test_max_matches_no_underflow() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("file1.txt"), "match\nmatch\nmatch\nmatch\nmatch\n")
            .await
            .unwrap();
        fs::write(root.join("file2.txt"), "match\nmatch\nmatch\nmatch\nmatch\n")
            .await
            .unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let mut params = default_params(&root.to_string_lossy(), "match");
        params.file_pattern = Some("*.txt".to_string());
        params.max_matches = 3;

        let result = grep_files(params, &allowed, false).await;
        assert!(result.is_ok(), "Should not panic on underflow");
        assert!(result.unwrap().len() <= 3);
    }

    #[tokio::test]
    async fn test_max_matches_exact_limit() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("file.txt"), "a\nb\nc\n").await.unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let mut params = default_params(&root.to_string_lossy(), "[abc]");
        params.max_matches = 3;

        let result = grep_files(params, &allowed, false).await.unwrap();
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_grep_empty_file() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("empty.txt"), "").await.unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);
        let params = default_params(&root.to_string_lossy(), "anything");

        let result = grep_files(params, &allowed, false).await.unwrap();
        assert_eq!(result.len(), 0);
    }

    #[tokio::test]
    async fn test_grep_single_file_path() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        let file_path = root.join("target.txt");
        fs::write(&file_path, "hello world\nfoo bar\nhello again\n")
            .await
            .unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);
        let params = default_params(&file_path.to_string_lossy(), "hello");

        let result = grep_files(params, &allowed, false).await.unwrap();
        let matches = result.matches().unwrap();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].line, "hello world");
        assert_eq!(matches[1].line, "hello again");
    }

    #[tokio::test]
    async fn test_invert_match() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("file.txt"), "match\nno\nmatch\nyes\n")
            .await
            .unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let mut params = default_params(&root.to_string_lossy(), "match");
        params.invert_match = true;

        let result = grep_files(params, &allowed, false).await.unwrap();
        let matches = result.matches().unwrap();
        
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].line, "no");
        assert_eq!(matches[1].line, "yes");
    }

    #[tokio::test]
    async fn test_count_only_mode() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("file1.txt"), "a\na\na\n").await.unwrap();
        fs::write(root.join("file2.txt"), "a\na\n").await.unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let mut params = default_params(&root.to_string_lossy(), "a");
        params.output_mode = GrepOutputMode::CountOnly;

        let result = grep_files(params, &allowed, false).await.unwrap();
        let counts = result.counts().unwrap();
        
        assert_eq!(counts.len(), 2);
        let total: usize = counts.iter().map(|c| c.count).sum();
        assert_eq!(total, 5); // 3 + 2
    }

    #[tokio::test]
    async fn test_files_with_matches_mode() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("has_match.txt"), "findme\n").await.unwrap();
        fs::write(root.join("no_match.txt"), "nothing\n").await.unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let mut params = default_params(&root.to_string_lossy(), "findme");
        params.output_mode = GrepOutputMode::FilesWithMatches;

        let result = grep_files(params, &allowed, false).await.unwrap();
        let files = result.files().unwrap();
        
        assert_eq!(files.len(), 1);
        assert!(files[0].to_string_lossy().contains("has_match"));
    }

    #[tokio::test]
    async fn test_files_without_match_mode() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("has_match.txt"), "findme\n").await.unwrap();
        fs::write(root.join("no_match.txt"), "nothing\n").await.unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let mut params = default_params(&root.to_string_lossy(), "findme");
        params.output_mode = GrepOutputMode::FilesWithoutMatch;

        let result = grep_files(params, &allowed, false).await.unwrap();
        let files = result.files().unwrap();
        
        assert_eq!(files.len(), 1);
        assert!(files[0].to_string_lossy().contains("no_match"));
    }
}
