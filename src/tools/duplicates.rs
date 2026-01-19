use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, Context};

use crate::tools::hash::{hash_file, HashAlgorithm};

/// A group of duplicate files
#[derive(Debug, Clone)]
pub struct DuplicateGroup {
    /// Hash of the files
    pub hash: String,
    /// Size of each file
    pub size: u64,
    /// Paths to all duplicate files
    pub files: Vec<String>,
}

/// Result of duplicate search
#[derive(Debug, Clone)]
pub struct DuplicateResult {
    /// Groups of duplicates (each group has 2+ files with same content)
    pub duplicate_groups: Vec<DuplicateGroup>,
    /// Total wasted space (sum of duplicate sizes minus one copy per group)
    pub total_wasted_space: u64,
    /// Human-readable wasted space
    pub wasted_space_human: String,
    /// Total files scanned
    pub files_scanned: usize,
    /// Number of duplicate files
    pub duplicate_files: usize,
}

/// Find duplicate files in a directory
pub async fn find_duplicates(
    path: &Path,
    min_size: Option<u64>,
    by_content: bool,
) -> Result<DuplicateResult> {
    let min_size = min_size.unwrap_or(1); // Skip empty files by default
    
    // Step 1: Collect all files grouped by size (sync operation for directory traversal)
    let path_buf = path.to_path_buf();
    let by_size: HashMap<u64, Vec<PathBuf>> = tokio::task::spawn_blocking(move || {
        let mut by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();
        collect_files(&path_buf, &mut by_size)?;
        Ok::<_, anyhow::Error>(by_size)
    }).await.with_context(|| "Failed to spawn blocking task")??;
    
    let files_scanned = by_size.values().map(|v| v.len()).sum();
    
    // Step 2: Filter to only sizes with 2+ files and above min_size
    let candidates: HashMap<u64, Vec<PathBuf>> = by_size
        .into_iter()
        .filter(|(size, files)| *size >= min_size && files.len() >= 2)
        .collect();
    
    // Step 3: Find duplicates
    let mut duplicate_groups = Vec::new();
    
    if by_content {
        // Hash-based comparison
        for (size, files) in candidates {
            let mut by_hash: HashMap<String, Vec<PathBuf>> = HashMap::new();
            
            for file_path in files {
                match hash_file(&file_path, HashAlgorithm::Sha256).await {
                    Ok(result) => {
                        by_hash.entry(result.hash).or_default().push(file_path);
                    }
                    Err(_) => continue, // Skip unreadable files
                }
            }
            
            // Collect groups with 2+ files
            for (hash, paths) in by_hash {
                if paths.len() >= 2 {
                    duplicate_groups.push(DuplicateGroup {
                        hash,
                        size,
                        files: paths.into_iter().map(|p| p.display().to_string()).collect(),
                    });
                }
            }
        }
    } else {
        // Size-only comparison (less accurate but faster)
        for (size, files) in candidates {
            // Use size as "hash" for size-only mode
            duplicate_groups.push(DuplicateGroup {
                hash: format!("size:{}", size),
                size,
                files: files.into_iter().map(|p| p.display().to_string()).collect(),
            });
        }
    }
    
    // Sort groups by wasted space (descending)
    duplicate_groups.sort_by(|a, b| {
        let wasted_a = a.size * (a.files.len() as u64 - 1);
        let wasted_b = b.size * (b.files.len() as u64 - 1);
        wasted_b.cmp(&wasted_a)
    });
    
    // Calculate totals
    let duplicate_files: usize = duplicate_groups.iter().map(|g| g.files.len()).sum();
    let total_wasted_space: u64 = duplicate_groups
        .iter()
        .map(|g| g.size * (g.files.len() as u64 - 1))
        .sum();
    
    Ok(DuplicateResult {
        duplicate_groups,
        total_wasted_space,
        wasted_space_human: human_size(total_wasted_space),
        files_scanned,
        duplicate_files,
    })
}

fn collect_files(path: &Path, by_size: &mut HashMap<u64, Vec<PathBuf>>) -> Result<()> {
    if path.is_file() {
        if let Ok(meta) = std::fs::metadata(path) {
            by_size.entry(meta.len()).or_default().push(path.to_path_buf());
        }
        return Ok(());
    }
    
    if !path.is_dir() {
        anyhow::bail!("Path does not exist: {}", path.display());
    }
    
    let entries = std::fs::read_dir(path)
        .with_context(|| format!("Cannot read directory: {}", path.display()))?;
    
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        
        let entry_path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        
        if meta.is_file() {
            by_size.entry(meta.len()).or_default().push(entry_path);
        } else if meta.is_dir() {
            // Recursively collect from subdirectories
            let _ = collect_files(&entry_path, by_size);
        }
    }
    
    Ok(())
}

fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;
    
    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;

    #[tokio::test]
    async fn test_no_duplicates() {
        let dir = tempdir().unwrap();
        
        fs::write(dir.path().join("file1.txt"), "unique1").unwrap();
        fs::write(dir.path().join("file2.txt"), "unique22").unwrap();
        fs::write(dir.path().join("file3.txt"), "unique333").unwrap();
        
        let result = find_duplicates(dir.path(), None, true).await.unwrap();
        
        assert!(result.duplicate_groups.is_empty());
        assert_eq!(result.total_wasted_space, 0);
        assert_eq!(result.files_scanned, 3);
    }

    #[tokio::test]
    async fn test_find_duplicates_by_content() {
        let dir = tempdir().unwrap();
        
        // Create 3 copies of same content
        let content = "duplicate content here";
        fs::write(dir.path().join("file1.txt"), content).unwrap();
        fs::write(dir.path().join("file2.txt"), content).unwrap();
        fs::write(dir.path().join("file3.txt"), content).unwrap();
        
        // Create unique file
        fs::write(dir.path().join("unique.txt"), "unique").unwrap();
        
        let result = find_duplicates(dir.path(), None, true).await.unwrap();
        
        assert_eq!(result.duplicate_groups.len(), 1);
        assert_eq!(result.duplicate_groups[0].files.len(), 3);
        assert_eq!(result.duplicate_files, 3);
        // Wasted = size * (3 - 1) = 22 * 2 = 44
        assert_eq!(result.total_wasted_space, 44);
    }

    #[tokio::test]
    async fn test_find_duplicates_in_subdirs() {
        let dir = tempdir().unwrap();
        
        let content = "same content";
        fs::write(dir.path().join("root.txt"), content).unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        fs::write(dir.path().join("subdir/nested.txt"), content).unwrap();
        
        let result = find_duplicates(dir.path(), None, true).await.unwrap();
        
        assert_eq!(result.duplicate_groups.len(), 1);
        assert_eq!(result.duplicate_groups[0].files.len(), 2);
    }

    #[tokio::test]
    async fn test_find_duplicates_by_size_only() {
        let dir = tempdir().unwrap();
        
        // Same size but different content
        fs::write(dir.path().join("file1.txt"), "aaaa").unwrap();
        fs::write(dir.path().join("file2.txt"), "bbbb").unwrap();
        
        let result = find_duplicates(dir.path(), None, false).await.unwrap();
        
        // By size they look like duplicates
        assert_eq!(result.duplicate_groups.len(), 1);
        assert!(result.duplicate_groups[0].hash.starts_with("size:"));
    }

    #[tokio::test]
    async fn test_min_size_filter() {
        let dir = tempdir().unwrap();
        
        // Small duplicates (should be filtered)
        fs::write(dir.path().join("small1.txt"), "ab").unwrap();
        fs::write(dir.path().join("small2.txt"), "ab").unwrap();
        
        // Large duplicates (should be found)
        let large = "x".repeat(1000);
        fs::write(dir.path().join("large1.txt"), &large).unwrap();
        fs::write(dir.path().join("large2.txt"), &large).unwrap();
        
        let result = find_duplicates(dir.path(), Some(100), true).await.unwrap();
        
        // Only large duplicates should be found
        assert_eq!(result.duplicate_groups.len(), 1);
        assert_eq!(result.duplicate_groups[0].size, 1000);
    }

    #[tokio::test]
    async fn test_multiple_duplicate_groups() {
        let dir = tempdir().unwrap();
        
        // Group 1
        fs::write(dir.path().join("group1_a.txt"), "content_group_1").unwrap();
        fs::write(dir.path().join("group1_b.txt"), "content_group_1").unwrap();
        
        // Group 2
        fs::write(dir.path().join("group2_a.txt"), "different_content").unwrap();
        fs::write(dir.path().join("group2_b.txt"), "different_content").unwrap();
        
        let result = find_duplicates(dir.path(), None, true).await.unwrap();
        
        assert_eq!(result.duplicate_groups.len(), 2);
        assert_eq!(result.duplicate_files, 4);
    }

    #[tokio::test]
    async fn test_skip_empty_files() {
        let dir = tempdir().unwrap();
        
        // Empty files (should be skipped with default min_size=1)
        fs::write(dir.path().join("empty1.txt"), "").unwrap();
        fs::write(dir.path().join("empty2.txt"), "").unwrap();
        
        let result = find_duplicates(dir.path(), None, true).await.unwrap();
        
        assert!(result.duplicate_groups.is_empty());
    }

    #[tokio::test]
    async fn test_nonexistent_path() {
        let result = find_duplicates(Path::new("/nonexistent/path"), None, true).await;
        assert!(result.is_err());
    }
}
