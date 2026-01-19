use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::Result;
use globset::{Glob, GlobSet, GlobSetBuilder};
use tokio::fs;

use crate::core::allowed::AllowedDirs;
use crate::core::path::resolve_validated_path;

/// File type filter for search
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileTypeFilter {
    /// Match any type
    #[default]
    Any,
    /// Match only files
    File,
    /// Match only directories
    Dir,
    /// Match only symlinks
    Symlink,
}

impl FileTypeFilter {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "any" | "all" => Some(Self::Any),
            "file" | "f" => Some(Self::File),
            "dir" | "directory" | "d" => Some(Self::Dir),
            "symlink" | "link" | "l" => Some(Self::Symlink),
            _ => None,
        }
    }
}

/// Search parameters with extended filtering
#[derive(Debug, Clone, Default)]
pub struct SearchParams {
    /// Root directory to search
    pub root: String,
    /// Glob pattern to match
    pub pattern: String,
    /// Patterns to exclude
    pub exclude_patterns: Vec<String>,
    /// Filter by file type
    pub file_type: FileTypeFilter,
    /// Minimum file size in bytes
    pub min_size: Option<u64>,
    /// Maximum file size in bytes
    pub max_size: Option<u64>,
    /// Modified after this time
    pub modified_after: Option<SystemTime>,
    /// Modified before this time
    pub modified_before: Option<SystemTime>,
}

/// Search result with metadata
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub path: PathBuf,
    pub is_file: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: Option<u64>,
    pub modified: Option<SystemTime>,
}

/// Search with extended filters
pub async fn search_files_extended(
    params: &SearchParams,
    allowed: &AllowedDirs,
    allow_symlink_escape: bool,
) -> Result<Vec<SearchResult>> {
    let root_path = resolve_validated_path(&params.root, allowed, allow_symlink_escape).await?;
    let matcher = build_glob(&params.pattern)?;
    let exclude = build_glob_set(&params.exclude_patterns)?;

    let mut stack = vec![root_path.clone()];
    let mut results = Vec::new();

    while let Some(current) = stack.pop() {
        let mut dir = match fs::read_dir(&current).await {
            Ok(d) => d,
            Err(_) => continue,
        };
        
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            let rel = path.strip_prefix(&root_path).unwrap_or(&path);
            let rel_str = rel.to_string_lossy();

            if exclude.is_match(rel_str.as_ref()) {
                continue;
            }

            // Validate each path (symlink-safe)
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

            let metadata = entry.metadata().await.ok();
            
            // Apply type filter
            let type_matches = match params.file_type {
                FileTypeFilter::Any => true,
                FileTypeFilter::File => file_type.is_file(),
                FileTypeFilter::Dir => file_type.is_dir(),
                FileTypeFilter::Symlink => file_type.is_symlink(),
            };
            
            if !type_matches && !file_type.is_dir() {
                // Skip non-matching files, but still traverse directories
                continue;
            }

            // Check if pattern matches
            let pattern_matches = matcher.is_match(rel_str.as_ref());
            
            if pattern_matches && type_matches {
                // Apply size filters (only for files)
                if file_type.is_file() {
                    if let Some(meta) = &metadata {
                        let size = meta.len();
                        
                        if let Some(min) = params.min_size {
                            if size < min {
                                continue;
                            }
                        }
                        
                        if let Some(max) = params.max_size {
                            if size > max {
                                continue;
                            }
                        }
                    }
                }
                
                // Apply time filters
                if let Some(meta) = &metadata {
                    if let Ok(modified) = meta.modified() {
                        if let Some(after) = params.modified_after {
                            if modified < after {
                                continue;
                            }
                        }
                        
                        if let Some(before) = params.modified_before {
                            if modified > before {
                                continue;
                            }
                        }
                    }
                }
                
                results.push(SearchResult {
                    path: path.clone(),
                    is_file: file_type.is_file(),
                    is_dir: file_type.is_dir(),
                    is_symlink: file_type.is_symlink(),
                    size: metadata.as_ref().map(|m| m.len()),
                    modified: metadata.as_ref().and_then(|m| m.modified().ok()),
                });
            }

            // Recurse into directories
            if file_type.is_dir() {
                stack.push(path);
            }
        }
    }

    Ok(results)
}

/// Legacy search function (for backward compatibility)
pub async fn search_paths(
    root: &str,
    pattern: &str,
    exclude_patterns: &[String],
    allowed: &AllowedDirs,
    allow_symlink_escape: bool,
) -> Result<Vec<PathBuf>> {
    let params = SearchParams {
        root: root.to_string(),
        pattern: pattern.to_string(),
        exclude_patterns: exclude_patterns.to_vec(),
        ..Default::default()
    };
    
    let results = search_files_extended(&params, allowed, allow_symlink_escape).await?;
    Ok(results.into_iter().map(|r| r.path).collect())
}

fn build_glob(pattern: &str) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    builder.add(Glob::new(pattern)?);
    Ok(builder.build()?)
}

fn build_glob_set(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pat in patterns {
        builder.add(Glob::new(pat)?);
    }
    Ok(builder.build()?)
}

pub fn build_exclude_set(patterns: &[String]) -> Result<GlobSet> {
    build_glob_set(patterns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;
    use std::time::Duration;

    #[tokio::test]
    async fn test_search_files_only() {
        let dir = tempdir().unwrap();
        
        fs::write(dir.path().join("file.txt"), "content").unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        
        let allowed = AllowedDirs::new(vec![dir.path().to_path_buf()]);
        
        let params = SearchParams {
            root: dir.path().to_string_lossy().to_string(),
            pattern: "**/*".to_string(),
            file_type: FileTypeFilter::File,
            ..Default::default()
        };
        
        let results = search_files_extended(&params, &allowed, false).await.unwrap();
        
        assert_eq!(results.len(), 1);
        assert!(results[0].is_file);
    }

    #[tokio::test]
    async fn test_search_dirs_only() {
        let dir = tempdir().unwrap();
        
        fs::write(dir.path().join("file.txt"), "content").unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        
        let allowed = AllowedDirs::new(vec![dir.path().to_path_buf()]);
        
        let params = SearchParams {
            root: dir.path().to_string_lossy().to_string(),
            pattern: "**/*".to_string(),
            file_type: FileTypeFilter::Dir,
            ..Default::default()
        };
        
        let results = search_files_extended(&params, &allowed, false).await.unwrap();
        
        assert_eq!(results.len(), 1);
        assert!(results[0].is_dir);
    }

    #[tokio::test]
    async fn test_search_by_size() {
        let dir = tempdir().unwrap();
        
        fs::write(dir.path().join("small.txt"), "ab").unwrap();
        fs::write(dir.path().join("large.txt"), "x".repeat(1000)).unwrap();
        
        let allowed = AllowedDirs::new(vec![dir.path().to_path_buf()]);
        
        // Find files >= 100 bytes
        let params = SearchParams {
            root: dir.path().to_string_lossy().to_string(),
            pattern: "**/*.txt".to_string(),
            min_size: Some(100),
            ..Default::default()
        };
        
        let results = search_files_extended(&params, &allowed, false).await.unwrap();
        
        assert_eq!(results.len(), 1);
        assert!(results[0].path.to_string_lossy().contains("large"));
    }

    #[tokio::test]
    async fn test_search_by_max_size() {
        let dir = tempdir().unwrap();
        
        fs::write(dir.path().join("small.txt"), "ab").unwrap();
        fs::write(dir.path().join("large.txt"), "x".repeat(1000)).unwrap();
        
        let allowed = AllowedDirs::new(vec![dir.path().to_path_buf()]);
        
        // Find files <= 100 bytes
        let params = SearchParams {
            root: dir.path().to_string_lossy().to_string(),
            pattern: "**/*.txt".to_string(),
            max_size: Some(100),
            ..Default::default()
        };
        
        let results = search_files_extended(&params, &allowed, false).await.unwrap();
        
        assert_eq!(results.len(), 1);
        assert!(results[0].path.to_string_lossy().contains("small"));
    }

    #[tokio::test]
    async fn test_search_by_modified_time() {
        let dir = tempdir().unwrap();
        
        let file_path = dir.path().join("recent.txt");
        fs::write(&file_path, "content").unwrap();
        
        let allowed = AllowedDirs::new(vec![dir.path().to_path_buf()]);
        
        // Find files modified after 1 hour ago
        let params = SearchParams {
            root: dir.path().to_string_lossy().to_string(),
            pattern: "**/*.txt".to_string(),
            modified_after: Some(SystemTime::now() - Duration::from_secs(3600)),
            ..Default::default()
        };
        
        let results = search_files_extended(&params, &allowed, false).await.unwrap();
        
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_file_type_filter_from_str() {
        assert_eq!(FileTypeFilter::from_str("file"), Some(FileTypeFilter::File));
        assert_eq!(FileTypeFilter::from_str("f"), Some(FileTypeFilter::File));
        assert_eq!(FileTypeFilter::from_str("dir"), Some(FileTypeFilter::Dir));
        assert_eq!(FileTypeFilter::from_str("directory"), Some(FileTypeFilter::Dir));
        assert_eq!(FileTypeFilter::from_str("symlink"), Some(FileTypeFilter::Symlink));
        assert_eq!(FileTypeFilter::from_str("any"), Some(FileTypeFilter::Any));
        assert_eq!(FileTypeFilter::from_str("invalid"), None);
    }

    #[tokio::test]
    async fn test_legacy_search_paths() {
        let dir = tempdir().unwrap();
        
        fs::write(dir.path().join("file.txt"), "content").unwrap();
        
        let allowed = AllowedDirs::new(vec![dir.path().to_path_buf()]);
        
        let results = search_paths(
            &dir.path().to_string_lossy(),
            "**/*.txt",
            &[],
            &allowed,
            false,
        ).await.unwrap();
        
        assert_eq!(results.len(), 1);
    }
}
