use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Result, Context};
use globset::{Glob, GlobSet, GlobSetBuilder};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::tools::hash::{hash_file_range, HashAlgorithm};

/// Single diff region sample
#[derive(Debug, Clone)]
pub struct DiffSample {
    pub offset: u64,
    pub length: usize,
    pub bytes1_hex: String,
    pub bytes2_hex: String,
}

/// Result of comparing two files
#[derive(Debug, Clone)]
pub struct CompareResult {
    pub identical: bool,
    pub size1: u64,
    pub size2: u64,
    pub size_diff: i64,
    pub hash1: String,
    pub hash2: String,
    pub first_diff_offset: Option<u64>,
    pub total_diff_regions: usize,
    pub total_diff_bytes: u64,
    pub match_percentage: f64,
    pub diff_samples: Vec<DiffSample>,
    /// Set when one file's range is empty (offset beyond EOF)
    pub file1_empty: bool,
    pub file2_empty: bool,
}

/// Parameters for file comparison
pub struct CompareParams {
    /// Offset in file1 (default: 0)
    pub offset1: u64,
    /// Offset in file2 (default: 0)
    pub offset2: u64,
    /// Length to compare (None = until EOF of shorter range)
    pub length: Option<u64>,
    /// Max diff samples to return
    pub max_diffs: usize,
    /// Context bytes around each diff
    pub context_bytes: usize,
}

impl Default for CompareParams {
    fn default() -> Self {
        Self {
            offset1: 0,
            offset2: 0,
            length: None,
            max_diffs: 20,
            context_bytes: 8,
        }
    }
}

/// Compare two files byte-by-byte
/// 
/// Edge cases handled:
/// - Different file sizes
/// - offset1/offset2 beyond respective file sizes
/// - length exceeding available bytes
/// - One file exists, other doesn't (error from caller)
pub async fn compare_files(
    path1: &Path,
    path2: &Path,
    params: CompareParams,
) -> Result<CompareResult> {
    let mut file1 = File::open(path1).await
        .with_context(|| format!("Cannot open file1: {}", path1.display()))?;
    let mut file2 = File::open(path2).await
        .with_context(|| format!("Cannot open file2: {}", path2.display()))?;
    
    let meta1 = file1.metadata().await?;
    let meta2 = file2.metadata().await?;
    let file_size1 = meta1.len();
    let file_size2 = meta2.len();
    
    // Calculate effective ranges
    let eff_start1 = params.offset1.min(file_size1);
    let eff_start2 = params.offset2.min(file_size2);
    let avail1 = file_size1.saturating_sub(eff_start1);
    let avail2 = file_size2.saturating_sub(eff_start2);
    
    // Check if offsets are beyond file bounds
    let file1_empty = params.offset1 >= file_size1;
    let file2_empty = params.offset2 >= file_size2;
    
    // Effective length to compare
    let compare_len = match params.length {
        Some(len) => len.min(avail1).min(avail2),
        None => avail1.min(avail2),
    };
    
    // Actual sizes in the compared range
    let range_size1 = match params.length {
        Some(len) => len.min(avail1),
        None => avail1,
    };
    let range_size2 = match params.length {
        Some(len) => len.min(avail2),
        None => avail2,
    };
    
    // Compute hashes for the ranges
    let hash1 = hash_file_range(path1, HashAlgorithm::Sha256, Some(params.offset1), params.length).await?;
    let hash2 = hash_file_range(path2, HashAlgorithm::Sha256, Some(params.offset2), params.length).await?;
    
    // Quick check: if hashes match, files are identical in range
    if hash1.hash == hash2.hash {
        return Ok(CompareResult {
            identical: true,
            size1: range_size1,
            size2: range_size2,
            size_diff: range_size1 as i64 - range_size2 as i64,
            hash1: hash1.hash,
            hash2: hash2.hash,
            first_diff_offset: None,
            total_diff_regions: 0,
            total_diff_bytes: 0,
            match_percentage: 100.0,
            diff_samples: Vec::new(),
            file1_empty,
            file2_empty,
        });
    }
    
    // Seek to start positions
    if eff_start1 > 0 {
        file1.seek(std::io::SeekFrom::Start(eff_start1)).await?;
    }
    if eff_start2 > 0 {
        file2.seek(std::io::SeekFrom::Start(eff_start2)).await?;
    }
    
    // Compare byte-by-byte in chunks
    const CHUNK_SIZE: usize = 64 * 1024;
    let mut buf1 = vec![0u8; CHUNK_SIZE];
    let mut buf2 = vec![0u8; CHUNK_SIZE];
    
    let mut bytes_compared = 0u64;
    let mut diff_bytes = 0u64;
    let mut diff_regions = 0usize;
    let mut first_diff: Option<u64> = None;
    let mut samples: Vec<DiffSample> = Vec::new();
    
    // Track current diff region
    let mut in_diff = false;
    let mut diff_start = 0u64;
    let mut diff_len = 0usize;
    let mut diff_bytes1: Vec<u8> = Vec::new();
    let mut diff_bytes2: Vec<u8> = Vec::new();
    
    while bytes_compared < compare_len {
        let to_read = ((compare_len - bytes_compared) as usize).min(CHUNK_SIZE);
        
        let n1 = file1.read(&mut buf1[..to_read]).await?;
        let n2 = file2.read(&mut buf2[..to_read]).await?;
        
        if n1 == 0 && n2 == 0 {
            break;
        }
        
        let n = n1.min(n2);
        
        for i in 0..n {
            let pos = bytes_compared + i as u64;
            
            if buf1[i] != buf2[i] {
                diff_bytes += 1;
                
                if first_diff.is_none() {
                    first_diff = Some(pos);
                }
                
                if !in_diff {
                    // Start new diff region
                    in_diff = true;
                    diff_start = pos;
                    diff_len = 1;
                    diff_bytes1.clear();
                    diff_bytes2.clear();
                    diff_bytes1.push(buf1[i]);
                    diff_bytes2.push(buf2[i]);
                } else {
                    // Continue diff region
                    diff_len += 1;
                    if diff_bytes1.len() < params.context_bytes * 2 {
                        diff_bytes1.push(buf1[i]);
                        diff_bytes2.push(buf2[i]);
                    }
                }
            } else if in_diff {
                // End of diff region
                diff_regions += 1;
                
                if samples.len() < params.max_diffs {
                    samples.push(DiffSample {
                        offset: diff_start,
                        length: diff_len,
                        bytes1_hex: bytes_to_hex(&diff_bytes1),
                        bytes2_hex: bytes_to_hex(&diff_bytes2),
                    });
                }
                
                in_diff = false;
            }
        }
        
        bytes_compared += n as u64;
        
        // Handle size difference at end
        if n1 != n2 {
            let extra = (n1.max(n2) - n) as u64;
            diff_bytes += extra;
            if !in_diff && first_diff.is_none() {
                first_diff = Some(bytes_compared);
            }
        }
    }
    
    // Close any open diff region
    if in_diff {
        diff_regions += 1;
        if samples.len() < params.max_diffs {
            samples.push(DiffSample {
                offset: diff_start,
                length: diff_len,
                bytes1_hex: bytes_to_hex(&diff_bytes1),
                bytes2_hex: bytes_to_hex(&diff_bytes2),
            });
        }
    }
    
    // Handle tail difference if sizes differ
    let max_range = range_size1.max(range_size2);
    let tail_diff = max_range.saturating_sub(compare_len);
    if tail_diff > 0 {
        diff_bytes += tail_diff;
        if diff_regions == 0 || !in_diff {
            diff_regions += 1;
        }
        if first_diff.is_none() {
            first_diff = Some(compare_len);
        }
    }
    
    // Calculate match percentage
    let total_bytes = max_range.max(1);
    let matching_bytes = total_bytes.saturating_sub(diff_bytes);
    let match_pct = (matching_bytes as f64 / total_bytes as f64) * 100.0;
    
    Ok(CompareResult {
        identical: false,
        size1: range_size1,
        size2: range_size2,
        size_diff: range_size1 as i64 - range_size2 as i64,
        hash1: hash1.hash,
        hash2: hash2.hash,
        first_diff_offset: first_diff,
        total_diff_regions: diff_regions,
        total_diff_bytes: diff_bytes,
        match_percentage: (match_pct * 100.0).round() / 100.0,
        diff_samples: samples,
        file1_empty,
        file2_empty,
    })
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

// ============================================================================
// Directory comparison
// ============================================================================

/// File that differs between directories
#[derive(Debug, Clone)]
pub struct DirDiffFile {
    pub path: String,
    pub size1: u64,
    pub size2: u64,
    pub hash1: Option<String>,
    pub hash2: Option<String>,
}

/// Result of comparing two directories
#[derive(Debug, Clone)]
pub struct DirCompareResult {
    pub identical: bool,
    pub only_in_first: Vec<String>,
    pub only_in_second: Vec<String>,
    pub different: Vec<DirDiffFile>,
    pub same_count: usize,
    pub diff_count: usize,
    pub errors: Vec<String>,
}

/// Parameters for directory comparison
pub struct DirCompareParams {
    pub recursive: bool,
    pub compare_content: bool,
    pub ignore_patterns: Vec<String>,
}

impl Default for DirCompareParams {
    fn default() -> Self {
        Self {
            recursive: true,
            compare_content: false,
            ignore_patterns: Vec::new(),
        }
    }
}

/// Compare two directories
pub async fn compare_directories(
    path1: &Path,
    path2: &Path,
    params: DirCompareParams,
) -> Result<DirCompareResult> {
    // Build ignore matcher
    let ignore = build_ignore_set(&params.ignore_patterns)?;
    
    // Collect files from both directories
    let files1 = collect_files(path1, path1, params.recursive, &ignore).await?;
    let files2 = collect_files(path2, path2, params.recursive, &ignore).await?;
    
    let set1: HashSet<_> = files1.keys().collect();
    let set2: HashSet<_> = files2.keys().collect();
    
    // Files only in first directory
    let only_in_first: Vec<String> = set1.difference(&set2)
        .map(|s| (*s).clone())
        .collect();
    
    // Files only in second directory
    let only_in_second: Vec<String> = set2.difference(&set1)
        .map(|s| (*s).clone())
        .collect();
    
    // Files in both - check if different
    let common: Vec<_> = set1.intersection(&set2).collect();
    let mut different = Vec::new();
    let mut same_count = 0;
    let mut errors = Vec::new();
    
    for rel_path in common {
        let info1 = &files1[*rel_path];
        let info2 = &files2[*rel_path];
        
        // Quick check by size
        if info1.size != info2.size {
            different.push(DirDiffFile {
                path: (*rel_path).clone(),
                size1: info1.size,
                size2: info2.size,
                hash1: None,
                hash2: None,
            });
            continue;
        }
        
        // Compare content if requested
        if params.compare_content {
            match (hash_file(&info1.full_path).await, hash_file(&info2.full_path).await) {
                (Ok(h1), Ok(h2)) => {
                    if h1 != h2 {
                        different.push(DirDiffFile {
                            path: (*rel_path).clone(),
                            size1: info1.size,
                            size2: info2.size,
                            hash1: Some(h1),
                            hash2: Some(h2),
                        });
                    } else {
                        same_count += 1;
                    }
                }
                (Err(e), _) | (_, Err(e)) => {
                    errors.push(format!("{}: {}", rel_path, e));
                }
            }
        } else {
            // Size matches, assume same
            same_count += 1;
        }
    }
    
    let identical = only_in_first.is_empty() 
        && only_in_second.is_empty() 
        && different.is_empty()
        && errors.is_empty();
    
    Ok(DirCompareResult {
        identical,
        only_in_first,
        only_in_second,
        diff_count: different.len(),
        different,
        same_count,
        errors,
    })
}

/// File info during directory scan
struct FileInfo {
    full_path: PathBuf,
    size: u64,
}

/// Collect all files in directory with relative paths
async fn collect_files(
    root: &Path,
    current: &Path,
    recursive: bool,
    ignore: &GlobSet,
) -> Result<HashMap<String, FileInfo>> {
    let mut result = HashMap::new();
    
    let mut entries = fs::read_dir(current).await
        .with_context(|| format!("Cannot read directory: {}", current.display()))?;
    
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let rel_path = path.strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/"); // Normalize path separators
        
        // Check ignore patterns
        if ignore.is_match(&rel_path) {
            continue;
        }
        
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue, // Skip unreadable entries
        };
        
        if meta.is_file() {
            result.insert(rel_path, FileInfo {
                full_path: path,
                size: meta.len(),
            });
        } else if meta.is_dir() && recursive {
            let sub = Box::pin(collect_files(root, &path, recursive, ignore)).await?;
            result.extend(sub);
        }
    }
    
    Ok(result)
}

/// Hash file for comparison
async fn hash_file(path: &Path) -> Result<String> {
    let result = hash_file_range(path, HashAlgorithm::Sha256, None, None).await?;
    Ok(result.hash)
}

/// Build glob set for ignore patterns
fn build_ignore_set(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pat in patterns {
        builder.add(Glob::new(pat).with_context(|| format!("Invalid glob: {}", pat))?);
    }
    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs;

    #[tokio::test]
    async fn test_compare_identical_files() {
        let dir = tempdir().unwrap();
        let path1 = dir.path().join("file1.bin");
        let path2 = dir.path().join("file2.bin");
        fs::write(&path1, b"identical content").await.unwrap();
        fs::write(&path2, b"identical content").await.unwrap();
        
        let result = compare_files(&path1, &path2, CompareParams::default()).await.unwrap();
        
        assert!(result.identical);
        assert_eq!(result.total_diff_bytes, 0);
        assert_eq!(result.match_percentage, 100.0);
    }

    #[tokio::test]
    async fn test_compare_different_files() {
        let dir = tempdir().unwrap();
        let path1 = dir.path().join("file1.bin");
        let path2 = dir.path().join("file2.bin");
        fs::write(&path1, b"hello world").await.unwrap();
        fs::write(&path2, b"hello earth").await.unwrap();
        
        let result = compare_files(&path1, &path2, CompareParams::default()).await.unwrap();
        
        assert!(!result.identical);
        assert!(result.total_diff_bytes > 0);
        assert!(result.first_diff_offset.is_some());
    }

    #[tokio::test]
    async fn test_compare_different_sizes() {
        let dir = tempdir().unwrap();
        let path1 = dir.path().join("file1.bin");
        let path2 = dir.path().join("file2.bin");
        fs::write(&path1, b"short").await.unwrap();
        fs::write(&path2, b"much longer content").await.unwrap();
        
        let result = compare_files(&path1, &path2, CompareParams::default()).await.unwrap();
        
        assert!(!result.identical);
        assert_eq!(result.size1, 5);
        assert_eq!(result.size2, 19);
        assert_eq!(result.size_diff, -14);
    }

    #[tokio::test]
    async fn test_compare_with_offset() {
        let dir = tempdir().unwrap();
        let path1 = dir.path().join("file1.bin");
        let path2 = dir.path().join("file2.bin");
        fs::write(&path1, b"prefix_same_content").await.unwrap();
        fs::write(&path2, b"different_same_content").await.unwrap();
        
        // Compare from offset where content matches
        let params = CompareParams {
            offset1: 7,  // "same_content"
            offset2: 10, // "same_content"
            ..Default::default()
        };
        
        let result = compare_files(&path1, &path2, params).await.unwrap();
        
        assert!(result.identical);
    }

    #[tokio::test]
    async fn test_compare_with_length() {
        let dir = tempdir().unwrap();
        let path1 = dir.path().join("file1.bin");
        let path2 = dir.path().join("file2.bin");
        fs::write(&path1, b"same_different").await.unwrap();
        fs::write(&path2, b"same_other____").await.unwrap();
        
        // Compare only first 4 bytes
        let params = CompareParams {
            length: Some(4),
            ..Default::default()
        };
        
        let result = compare_files(&path1, &path2, params).await.unwrap();
        
        assert!(result.identical);
        assert_eq!(result.size1, 4);
        assert_eq!(result.size2, 4);
    }

    #[tokio::test]
    async fn test_compare_offset_beyond_file1() {
        let dir = tempdir().unwrap();
        let path1 = dir.path().join("file1.bin");
        let path2 = dir.path().join("file2.bin");
        fs::write(&path1, b"short").await.unwrap();
        fs::write(&path2, b"content").await.unwrap();
        
        let params = CompareParams {
            offset1: 100, // Beyond file1
            offset2: 0,
            ..Default::default()
        };
        
        let result = compare_files(&path1, &path2, params).await.unwrap();
        
        assert!(result.file1_empty);
        assert!(!result.file2_empty);
        assert!(!result.identical);
    }

    #[tokio::test]
    async fn test_compare_offset_beyond_both() {
        let dir = tempdir().unwrap();
        let path1 = dir.path().join("file1.bin");
        let path2 = dir.path().join("file2.bin");
        fs::write(&path1, b"short").await.unwrap();
        fs::write(&path2, b"small").await.unwrap();
        
        let params = CompareParams {
            offset1: 100,
            offset2: 100,
            ..Default::default()
        };
        
        let result = compare_files(&path1, &path2, params).await.unwrap();
        
        assert!(result.file1_empty);
        assert!(result.file2_empty);
        assert!(result.identical); // Both empty ranges
    }

    #[tokio::test]
    async fn test_compare_empty_files() {
        let dir = tempdir().unwrap();
        let path1 = dir.path().join("file1.bin");
        let path2 = dir.path().join("file2.bin");
        fs::write(&path1, b"").await.unwrap();
        fs::write(&path2, b"").await.unwrap();
        
        let result = compare_files(&path1, &path2, CompareParams::default()).await.unwrap();
        
        assert!(result.identical);
        assert_eq!(result.size1, 0);
        assert_eq!(result.size2, 0);
    }

    #[tokio::test]
    async fn test_compare_diff_samples() {
        let dir = tempdir().unwrap();
        let path1 = dir.path().join("file1.bin");
        let path2 = dir.path().join("file2.bin");
        fs::write(&path1, b"aXbYc").await.unwrap();
        fs::write(&path2, b"a1b2c").await.unwrap();
        
        let result = compare_files(&path1, &path2, CompareParams::default()).await.unwrap();
        
        assert!(!result.identical);
        assert!(!result.diff_samples.is_empty());
        
        // Check first sample
        let sample = &result.diff_samples[0];
        assert!(sample.offset > 0); // First diff is at 'X' vs '1'
    }

    #[tokio::test]
    async fn test_compare_length_exceeds_file() {
        let dir = tempdir().unwrap();
        let path1 = dir.path().join("file1.bin");
        let path2 = dir.path().join("file2.bin");
        fs::write(&path1, b"short").await.unwrap();
        fs::write(&path2, b"short").await.unwrap();
        
        let params = CompareParams {
            length: Some(1000), // Way more than file size
            ..Default::default()
        };
        
        let result = compare_files(&path1, &path2, params).await.unwrap();
        
        assert!(result.identical);
        assert_eq!(result.size1, 5);
        assert_eq!(result.size2, 5);
    }

    // ========================================================================
    // Directory comparison tests
    // ========================================================================

    #[tokio::test]
    async fn test_compare_dirs_identical() {
        let dir = tempdir().unwrap();
        let dir1 = dir.path().join("dir1");
        let dir2 = dir.path().join("dir2");
        fs::create_dir_all(&dir1).await.unwrap();
        fs::create_dir_all(&dir2).await.unwrap();
        
        fs::write(dir1.join("file.txt"), b"content").await.unwrap();
        fs::write(dir2.join("file.txt"), b"content").await.unwrap();
        
        let result = compare_directories(&dir1, &dir2, DirCompareParams::default()).await.unwrap();
        
        assert!(result.identical);
        assert!(result.only_in_first.is_empty());
        assert!(result.only_in_second.is_empty());
        assert!(result.different.is_empty());
    }

    #[tokio::test]
    async fn test_compare_dirs_only_in_first() {
        let dir = tempdir().unwrap();
        let dir1 = dir.path().join("dir1");
        let dir2 = dir.path().join("dir2");
        fs::create_dir_all(&dir1).await.unwrap();
        fs::create_dir_all(&dir2).await.unwrap();
        
        fs::write(dir1.join("common.txt"), b"c").await.unwrap();
        fs::write(dir1.join("only1.txt"), b"x").await.unwrap();
        fs::write(dir2.join("common.txt"), b"c").await.unwrap();
        
        let result = compare_directories(&dir1, &dir2, DirCompareParams::default()).await.unwrap();
        
        assert!(!result.identical);
        assert_eq!(result.only_in_first.len(), 1);
        assert!(result.only_in_first.contains(&"only1.txt".to_string()));
    }

    #[tokio::test]
    async fn test_compare_dirs_only_in_second() {
        let dir = tempdir().unwrap();
        let dir1 = dir.path().join("dir1");
        let dir2 = dir.path().join("dir2");
        fs::create_dir_all(&dir1).await.unwrap();
        fs::create_dir_all(&dir2).await.unwrap();
        
        fs::write(dir1.join("common.txt"), b"c").await.unwrap();
        fs::write(dir2.join("common.txt"), b"c").await.unwrap();
        fs::write(dir2.join("only2.txt"), b"y").await.unwrap();
        
        let result = compare_directories(&dir1, &dir2, DirCompareParams::default()).await.unwrap();
        
        assert!(!result.identical);
        assert_eq!(result.only_in_second.len(), 1);
        assert!(result.only_in_second.contains(&"only2.txt".to_string()));
    }

    #[tokio::test]
    async fn test_compare_dirs_different_content() {
        let dir = tempdir().unwrap();
        let dir1 = dir.path().join("dir1");
        let dir2 = dir.path().join("dir2");
        fs::create_dir_all(&dir1).await.unwrap();
        fs::create_dir_all(&dir2).await.unwrap();
        
        fs::write(dir1.join("file.txt"), b"content1").await.unwrap();
        fs::write(dir2.join("file.txt"), b"content2").await.unwrap();
        
        // With content comparison
        let params = DirCompareParams {
            compare_content: true,
            ..Default::default()
        };
        
        let result = compare_directories(&dir1, &dir2, params).await.unwrap();
        
        assert!(!result.identical);
        assert_eq!(result.different.len(), 1);
        assert!(result.different[0].hash1.is_some());
    }

    #[tokio::test]
    async fn test_compare_dirs_different_size() {
        let dir = tempdir().unwrap();
        let dir1 = dir.path().join("dir1");
        let dir2 = dir.path().join("dir2");
        fs::create_dir_all(&dir1).await.unwrap();
        fs::create_dir_all(&dir2).await.unwrap();
        
        fs::write(dir1.join("file.txt"), b"short").await.unwrap();
        fs::write(dir2.join("file.txt"), b"much longer").await.unwrap();
        
        let result = compare_directories(&dir1, &dir2, DirCompareParams::default()).await.unwrap();
        
        assert!(!result.identical);
        assert_eq!(result.different.len(), 1);
        assert_eq!(result.different[0].size1, 5);
        assert_eq!(result.different[0].size2, 11);
    }

    #[tokio::test]
    async fn test_compare_dirs_recursive() {
        let dir = tempdir().unwrap();
        let dir1 = dir.path().join("dir1");
        let dir2 = dir.path().join("dir2");
        fs::create_dir_all(dir1.join("sub")).await.unwrap();
        fs::create_dir_all(dir2.join("sub")).await.unwrap();
        
        fs::write(dir1.join("sub/file.txt"), b"x").await.unwrap();
        fs::write(dir2.join("sub/file.txt"), b"x").await.unwrap();
        
        let result = compare_directories(&dir1, &dir2, DirCompareParams::default()).await.unwrap();
        
        assert!(result.identical);
        assert_eq!(result.same_count, 1);
    }

    #[tokio::test]
    async fn test_compare_dirs_ignore_pattern() {
        let dir = tempdir().unwrap();
        let dir1 = dir.path().join("dir1");
        let dir2 = dir.path().join("dir2");
        fs::create_dir_all(&dir1).await.unwrap();
        fs::create_dir_all(&dir2).await.unwrap();
        
        fs::write(dir1.join("file.txt"), b"same").await.unwrap();
        fs::write(dir1.join("ignore.log"), b"different1").await.unwrap();
        fs::write(dir2.join("file.txt"), b"same").await.unwrap();
        fs::write(dir2.join("ignore.log"), b"different2").await.unwrap();
        
        let params = DirCompareParams {
            ignore_patterns: vec!["*.log".to_string()],
            ..Default::default()
        };
        
        let result = compare_directories(&dir1, &dir2, params).await.unwrap();
        
        assert!(result.identical);
    }

    #[tokio::test]
    async fn test_compare_dirs_empty() {
        let dir = tempdir().unwrap();
        let dir1 = dir.path().join("dir1");
        let dir2 = dir.path().join("dir2");
        fs::create_dir_all(&dir1).await.unwrap();
        fs::create_dir_all(&dir2).await.unwrap();
        
        let result = compare_directories(&dir1, &dir2, DirCompareParams::default()).await.unwrap();
        
        assert!(result.identical);
        assert_eq!(result.same_count, 0);
    }
}
