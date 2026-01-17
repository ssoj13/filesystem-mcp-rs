use std::path::Path;

use anyhow::{Result, Context, bail};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha512, Digest};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use xxhash_rust::xxh64::Xxh64;

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, Default)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    #[default]
    Sha256,
    Sha512,
    Xxh64,
}

impl HashAlgorithm {
    /// Parse from string (case-insensitive)
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "md5" => Ok(Self::Md5),
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            "xxh64" | "xxhash64" | "xxhash" => Ok(Self::Xxh64),
            _ => bail!("Unknown algorithm '{}'. Supported: md5, sha1, sha256, sha512, xxh64", s),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
            Self::Xxh64 => "xxh64",
        }
    }
}

/// Result of hashing a file
#[derive(Debug, Clone)]
pub struct HashResult {
    pub hash: String,
    pub size: u64,
    pub algorithm: String,
}

/// Result of hashing multiple files
#[derive(Debug, Clone)]
pub struct MultiHashResult {
    pub results: Vec<FileHashResult>,
    pub all_match: bool,
}

#[derive(Debug, Clone)]
pub struct FileHashResult {
    pub path: String,
    pub hash: String,
    pub size: u64,
    pub error: Option<String>,
}

/// Hash entire file
pub async fn hash_file(path: &Path, algorithm: HashAlgorithm) -> Result<HashResult> {
    hash_file_range(path, algorithm, None, None).await
}

/// Hash file with optional offset and length
/// 
/// Edge cases handled:
/// - offset beyond file size: returns hash of empty data
/// - length exceeds remaining bytes: hashes until EOF
/// - offset + length overflow: clamped to file size
pub async fn hash_file_range(
    path: &Path,
    algorithm: HashAlgorithm,
    offset: Option<u64>,
    length: Option<u64>,
) -> Result<HashResult> {
    let mut file = File::open(path).await
        .with_context(|| format!("Cannot open file: {}", path.display()))?;
    
    let file_size = file.metadata().await?.len();
    let start = offset.unwrap_or(0);
    
    // Handle offset beyond file
    if start >= file_size {
        return Ok(HashResult {
            hash: compute_hash(&[], algorithm),
            size: 0,
            algorithm: algorithm.name().to_string(),
        });
    }
    
    // Seek to offset
    if start > 0 {
        file.seek(std::io::SeekFrom::Start(start)).await?;
    }
    
    // Calculate actual bytes to read
    let remaining = file_size - start;
    let to_read = match length {
        Some(len) => len.min(remaining),
        None => remaining,
    };
    
    // Read and hash in chunks (64KB)
    const CHUNK_SIZE: usize = 64 * 1024;
    let mut bytes_read = 0u64;
    let mut buf = vec![0u8; CHUNK_SIZE];
    
    let hash = match algorithm {
        HashAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            while bytes_read < to_read {
                let to_read_now = ((to_read - bytes_read) as usize).min(CHUNK_SIZE);
                let n = file.read(&mut buf[..to_read_now]).await?;
                if n == 0 { break; }
                hasher.update(&buf[..n]);
                bytes_read += n as u64;
            }
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Sha1 => {
            let mut hasher = Sha1::new();
            while bytes_read < to_read {
                let to_read_now = ((to_read - bytes_read) as usize).min(CHUNK_SIZE);
                let n = file.read(&mut buf[..to_read_now]).await?;
                if n == 0 { break; }
                hasher.update(&buf[..n]);
                bytes_read += n as u64;
            }
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            while bytes_read < to_read {
                let to_read_now = ((to_read - bytes_read) as usize).min(CHUNK_SIZE);
                let n = file.read(&mut buf[..to_read_now]).await?;
                if n == 0 { break; }
                hasher.update(&buf[..n]);
                bytes_read += n as u64;
            }
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            while bytes_read < to_read {
                let to_read_now = ((to_read - bytes_read) as usize).min(CHUNK_SIZE);
                let n = file.read(&mut buf[..to_read_now]).await?;
                if n == 0 { break; }
                hasher.update(&buf[..n]);
                bytes_read += n as u64;
            }
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Xxh64 => {
            let mut hasher = Xxh64::new(0);
            while bytes_read < to_read {
                let to_read_now = ((to_read - bytes_read) as usize).min(CHUNK_SIZE);
                let n = file.read(&mut buf[..to_read_now]).await?;
                if n == 0 { break; }
                hasher.update(&buf[..n]);
                bytes_read += n as u64;
            }
            format!("{:016x}", hasher.digest())
        }
    };
    
    Ok(HashResult {
        hash,
        size: bytes_read,
        algorithm: algorithm.name().to_string(),
    })
}

/// Compute hash of byte slice (for empty data case)
fn compute_hash(data: &[u8], algorithm: HashAlgorithm) -> String {
    match algorithm {
        HashAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Xxh64 => {
            let mut hasher = Xxh64::new(0);
            hasher.update(data);
            format!("{:016x}", hasher.digest())
        }
    }
}

/// Hash multiple files and check if all match
pub async fn hash_files_multiple(
    paths: &[&Path],
    algorithm: HashAlgorithm,
) -> MultiHashResult {
    let mut results = Vec::with_capacity(paths.len());
    let mut first_hash: Option<String> = None;
    let mut all_match = true;
    
    for path in paths {
        match hash_file(path, algorithm).await {
            Ok(result) => {
                // Check if matches first hash
                if let Some(ref first) = first_hash {
                    if &result.hash != first {
                        all_match = false;
                    }
                } else {
                    first_hash = Some(result.hash.clone());
                }
                
                results.push(FileHashResult {
                    path: path.display().to_string(),
                    hash: result.hash,
                    size: result.size,
                    error: None,
                });
            }
            Err(e) => {
                all_match = false;
                results.push(FileHashResult {
                    path: path.display().to_string(),
                    hash: String::new(),
                    size: 0,
                    error: Some(e.to_string()),
                });
            }
        }
    }
    
    MultiHashResult { results, all_match }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs;

    #[tokio::test]
    async fn test_hash_file_sha256() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");
        fs::write(&path, "hello world").await.unwrap();
        
        let result = hash_file(&path, HashAlgorithm::Sha256).await.unwrap();
        
        // Known SHA256 of "hello world"
        assert_eq!(result.hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        assert_eq!(result.size, 11);
        assert_eq!(result.algorithm, "sha256");
    }

    #[tokio::test]
    async fn test_hash_file_md5() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");
        fs::write(&path, "hello world").await.unwrap();
        
        let result = hash_file(&path, HashAlgorithm::Md5).await.unwrap();
        
        // Known MD5 of "hello world"
        assert_eq!(result.hash, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }

    #[tokio::test]
    async fn test_hash_file_sha1() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");
        fs::write(&path, "hello world").await.unwrap();
        
        let result = hash_file(&path, HashAlgorithm::Sha1).await.unwrap();
        
        // Known SHA1 of "hello world"
        assert_eq!(result.hash, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
    }

    #[tokio::test]
    async fn test_hash_file_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        fs::write(&path, "").await.unwrap();
        
        let result = hash_file(&path, HashAlgorithm::Sha256).await.unwrap();
        
        // SHA256 of empty string
        assert_eq!(result.hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(result.size, 0);
    }

    #[tokio::test]
    async fn test_hash_file_range_offset() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");
        fs::write(&path, "hello world").await.unwrap();
        
        // Hash "world" (offset 6)
        let result = hash_file_range(&path, HashAlgorithm::Sha256, Some(6), None).await.unwrap();
        
        // SHA256 of "world"
        assert_eq!(result.hash, "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7");
        assert_eq!(result.size, 5);
    }

    #[tokio::test]
    async fn test_hash_file_range_offset_and_length() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");
        fs::write(&path, "hello world").await.unwrap();
        
        // Hash "llo" (offset 2, length 3)
        let result = hash_file_range(&path, HashAlgorithm::Sha256, Some(2), Some(3)).await.unwrap();
        
        // SHA256 of "llo"
        assert_eq!(result.hash, "13d896353557f29e6c8aac4bde65c743f4206df820ff8328ae567f924189d339");
        assert_eq!(result.size, 3);
    }

    #[tokio::test]
    async fn test_hash_file_range_offset_beyond_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");
        fs::write(&path, "hello").await.unwrap();
        
        // Offset beyond file size
        let result = hash_file_range(&path, HashAlgorithm::Sha256, Some(100), None).await.unwrap();
        
        // Should return hash of empty data
        assert_eq!(result.hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(result.size, 0);
    }

    #[tokio::test]
    async fn test_hash_file_range_length_exceeds_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");
        fs::write(&path, "hello").await.unwrap();
        
        // Length exceeds remaining bytes
        let result = hash_file_range(&path, HashAlgorithm::Sha256, Some(2), Some(100)).await.unwrap();
        
        // Should hash "llo" (remaining 3 bytes)
        assert_eq!(result.size, 3);
    }

    #[tokio::test]
    async fn test_hash_files_multiple_identical() {
        let dir = tempdir().unwrap();
        let path1 = dir.path().join("file1.txt");
        let path2 = dir.path().join("file2.txt");
        fs::write(&path1, "same content").await.unwrap();
        fs::write(&path2, "same content").await.unwrap();
        
        let result = hash_files_multiple(
            &[path1.as_path(), path2.as_path()],
            HashAlgorithm::Sha256
        ).await;
        
        assert!(result.all_match);
        assert_eq!(result.results.len(), 2);
        assert_eq!(result.results[0].hash, result.results[1].hash);
    }

    #[tokio::test]
    async fn test_hash_files_multiple_different() {
        let dir = tempdir().unwrap();
        let path1 = dir.path().join("file1.txt");
        let path2 = dir.path().join("file2.txt");
        fs::write(&path1, "content one").await.unwrap();
        fs::write(&path2, "content two").await.unwrap();
        
        let result = hash_files_multiple(
            &[path1.as_path(), path2.as_path()],
            HashAlgorithm::Sha256
        ).await;
        
        assert!(!result.all_match);
        assert_ne!(result.results[0].hash, result.results[1].hash);
    }

    #[tokio::test]
    async fn test_hash_files_multiple_with_error() {
        let dir = tempdir().unwrap();
        let path1 = dir.path().join("exists.txt");
        let path2 = dir.path().join("nonexistent.txt");
        fs::write(&path1, "content").await.unwrap();
        
        let result = hash_files_multiple(
            &[path1.as_path(), path2.as_path()],
            HashAlgorithm::Sha256
        ).await;
        
        assert!(!result.all_match);
        assert!(result.results[0].error.is_none());
        assert!(result.results[1].error.is_some());
    }

    #[tokio::test]
    async fn test_algorithm_from_str() {
        assert!(matches!(HashAlgorithm::from_str("md5").unwrap(), HashAlgorithm::Md5));
        assert!(matches!(HashAlgorithm::from_str("SHA256").unwrap(), HashAlgorithm::Sha256));
        assert!(matches!(HashAlgorithm::from_str("xxhash64").unwrap(), HashAlgorithm::Xxh64));
        assert!(HashAlgorithm::from_str("invalid").is_err());
    }
}
