use std::collections::HashMap;
use std::path::Path;

use anyhow::{Result, Context};

/// Statistics about a file or directory
#[derive(Debug, Clone)]
pub struct FileStats {
    /// Total number of files
    pub total_files: usize,
    /// Total number of directories
    pub total_dirs: usize,
    /// Total size in bytes
    pub total_size: u64,
    /// Human-readable size
    pub total_size_human: String,
    /// Breakdown by extension
    pub by_extension: HashMap<String, ExtensionStats>,
    /// Largest files (sorted by size desc)
    pub largest_files: Vec<FileInfo>,
}

/// Stats per extension
#[derive(Debug, Clone, Default)]
pub struct ExtensionStats {
    pub count: usize,
    pub size: u64,
}

/// Info about a single file
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
}

/// Get statistics for a file or directory
pub async fn file_stats(
    path: &Path,
    recursive: bool,
    largest_count: usize,
) -> Result<FileStats> {
    let path = path.to_path_buf();
    
    tokio::task::spawn_blocking(move || {
        file_stats_sync(&path, recursive, largest_count)
    }).await?
}

fn file_stats_sync(path: &Path, recursive: bool, largest_count: usize) -> Result<FileStats> {
    let mut total_files = 0usize;
    let mut total_dirs = 0usize;
    let mut total_size = 0u64;
    let mut by_extension: HashMap<String, ExtensionStats> = HashMap::new();
    let mut all_files: Vec<FileInfo> = Vec::new();
    
    if path.is_file() {
        // Single file stats
        let meta = std::fs::metadata(path)
            .with_context(|| format!("Cannot read metadata: {}", path.display()))?;
        
        let size = meta.len();
        total_files = 1;
        total_size = size;
        
        let ext = get_extension(path);
        by_extension.entry(ext).or_default().count += 1;
        by_extension.get_mut(&get_extension(path)).unwrap().size += size;
        
        all_files.push(FileInfo {
            path: path.display().to_string(),
            size,
        });
    } else if path.is_dir() {
        // Directory stats
        collect_dir_stats(
            path,
            path,
            recursive,
            &mut total_files,
            &mut total_dirs,
            &mut total_size,
            &mut by_extension,
            &mut all_files,
        )?;
    } else {
        anyhow::bail!("Path does not exist: {}", path.display());
    }
    
    // Sort files by size (descending) and take top N
    all_files.sort_by(|a, b| b.size.cmp(&a.size));
    let largest_files: Vec<FileInfo> = all_files.into_iter().take(largest_count).collect();
    
    Ok(FileStats {
        total_files,
        total_dirs,
        total_size,
        total_size_human: human_size(total_size),
        by_extension,
        largest_files,
    })
}

fn collect_dir_stats(
    base: &Path,
    current: &Path,
    recursive: bool,
    total_files: &mut usize,
    total_dirs: &mut usize,
    total_size: &mut u64,
    by_extension: &mut HashMap<String, ExtensionStats>,
    all_files: &mut Vec<FileInfo>,
) -> Result<()> {
    let entries = std::fs::read_dir(current)
        .with_context(|| format!("Cannot read directory: {}", current.display()))?;
    
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue, // Skip inaccessible entries
        };
        
        if meta.is_file() {
            let size = meta.len();
            *total_files += 1;
            *total_size += size;
            
            let ext = get_extension(&path);
            let stats = by_extension.entry(ext).or_default();
            stats.count += 1;
            stats.size += size;
            
            // Store relative path for clarity
            let rel_path = path.strip_prefix(base)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| path.display().to_string());
            
            all_files.push(FileInfo {
                path: rel_path,
                size,
            });
        } else if meta.is_dir() {
            *total_dirs += 1;
            
            if recursive {
                collect_dir_stats(
                    base,
                    &path,
                    recursive,
                    total_files,
                    total_dirs,
                    total_size,
                    by_extension,
                    all_files,
                )?;
            }
        }
    }
    
    Ok(())
}

fn get_extension(path: &Path) -> String {
    path.extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_else(|| "(no extension)".to_string())
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
    async fn test_single_file_stats() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("test.txt");
        fs::write(&file, "hello world").unwrap();
        
        let stats = file_stats(&file, true, 10).await.unwrap();
        
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_dirs, 0);
        assert_eq!(stats.total_size, 11); // "hello world" = 11 bytes
        assert_eq!(stats.by_extension.get(".txt").unwrap().count, 1);
        assert_eq!(stats.largest_files.len(), 1);
    }

    #[tokio::test]
    async fn test_directory_stats_recursive() {
        let dir = tempdir().unwrap();
        
        // Create structure:
        // /
        //   file1.txt (10 bytes)
        //   subdir/
        //     file2.rs (20 bytes)
        //     file3.rs (30 bytes)
        
        fs::write(dir.path().join("file1.txt"), "0123456789").unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        fs::write(dir.path().join("subdir/file2.rs"), "01234567890123456789").unwrap();
        fs::write(dir.path().join("subdir/file3.rs"), "012345678901234567890123456789").unwrap();
        
        let stats = file_stats(dir.path(), true, 10).await.unwrap();
        
        assert_eq!(stats.total_files, 3);
        assert_eq!(stats.total_dirs, 1);
        assert_eq!(stats.total_size, 60);
        
        assert_eq!(stats.by_extension.get(".txt").unwrap().count, 1);
        assert_eq!(stats.by_extension.get(".rs").unwrap().count, 2);
        
        // Largest file should be first
        assert!(stats.largest_files[0].path.contains("file3.rs"));
        assert_eq!(stats.largest_files[0].size, 30);
    }

    #[tokio::test]
    async fn test_directory_stats_non_recursive() {
        let dir = tempdir().unwrap();
        
        fs::write(dir.path().join("file1.txt"), "test").unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        fs::write(dir.path().join("subdir/file2.txt"), "nested").unwrap();
        
        let stats = file_stats(dir.path(), false, 10).await.unwrap();
        
        // Should only count top-level file
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_dirs, 1);
        assert_eq!(stats.total_size, 4);
    }

    #[tokio::test]
    async fn test_largest_files_limit() {
        let dir = tempdir().unwrap();
        
        // Create 5 files
        for i in 1..=5 {
            let content = "x".repeat(i * 10);
            fs::write(dir.path().join(format!("file{}.txt", i)), content).unwrap();
        }
        
        let stats = file_stats(dir.path(), true, 3).await.unwrap();
        
        // Should only return top 3
        assert_eq!(stats.largest_files.len(), 3);
        assert_eq!(stats.largest_files[0].size, 50);
        assert_eq!(stats.largest_files[1].size, 40);
        assert_eq!(stats.largest_files[2].size, 30);
    }

    #[test]
    fn test_human_size() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.00 KB");
        assert_eq!(human_size(1536), "1.50 KB");
        assert_eq!(human_size(1048576), "1.00 MB");
        assert_eq!(human_size(1073741824), "1.00 GB");
        assert_eq!(human_size(1099511627776), "1.00 TB");
    }

    #[tokio::test]
    async fn test_nonexistent_path() {
        let result = file_stats(Path::new("/nonexistent/path"), true, 10).await;
        assert!(result.is_err());
    }
}
