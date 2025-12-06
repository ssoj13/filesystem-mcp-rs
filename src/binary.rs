use anyhow::{Result, bail, Context};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use std::path::Path;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// Read bytes from file at offset
pub async fn read_bytes(path: &Path, offset: u64, length: usize) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path).await
        .context("Failed to open file")?;
    
    let file_len = file.metadata().await?.len();
    
    // Clamp to file boundaries - return what's available
    if offset >= file_len {
        return Ok(Vec::new());
    }
    
    let actual_len = length.min((file_len - offset) as usize);
    
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut buf = vec![0u8; actual_len];
    file.read_exact(&mut buf).await?;
    
    Ok(buf)
}

/// Write bytes to file at offset
/// mode: "replace" overwrites existing bytes, "insert" shifts remaining content
pub async fn write_bytes(path: &Path, offset: u64, data: &[u8], insert: bool) -> Result<()> {
    let exists = path.exists();
    
    if insert {
        // Insert mode: read all, splice, write back
        let mut content = if exists {
            fs::read(path).await.context("Failed to read file")?
        } else {
            Vec::new()
        };
        
        let insert_pos = (offset as usize).min(content.len());
        content.splice(insert_pos..insert_pos, data.iter().cloned());
        
        fs::write(path, &content).await.context("Failed to write file")?;
    } else {
        // Replace mode: overwrite bytes at offset
        if !exists {
            // Create new file with padding if needed
            let mut content = vec![0u8; offset as usize];
            content.extend_from_slice(data);
            fs::write(path, &content).await.context("Failed to write file")?;
        } else {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .open(path)
                .await
                .context("Failed to open file for writing")?;
            
            let file_len = file.metadata().await?.len();
            
            // Extend file if needed
            if offset > file_len {
                file.set_len(offset).await?;
            }
            
            file.seek(std::io::SeekFrom::Start(offset)).await?;
            file.write_all(data).await?;
        }
    }
    
    Ok(())
}

/// Extract (cut) bytes from file - returns extracted data and removes it from file
pub async fn extract_bytes(path: &Path, offset: u64, length: usize) -> Result<Vec<u8>> {
    let mut content = fs::read(path).await.context("Failed to read file")?;
    
    let start = (offset as usize).min(content.len());
    let end = (start + length).min(content.len());
    
    // Drain the range and return it
    let extracted: Vec<u8> = content.drain(start..end).collect();
    
    fs::write(path, &content).await.context("Failed to write file")?;
    
    Ok(extracted)
}

/// Find and replace binary pattern in file
/// Returns number of replacements made
pub async fn patch_bytes(
    path: &Path, 
    find: &[u8], 
    replace: &[u8], 
    replace_all: bool
) -> Result<usize> {
    if find.is_empty() {
        bail!("Find pattern cannot be empty");
    }
    
    let content = fs::read(path).await.context("Failed to read file")?;
    let mut result = Vec::with_capacity(content.len());
    let mut count = 0;
    let mut i = 0;
    
    while i < content.len() {
        if i + find.len() <= content.len() && &content[i..i + find.len()] == find {
            result.extend_from_slice(replace);
            count += 1;
            i += find.len();
            
            if !replace_all {
                // Copy rest and break
                result.extend_from_slice(&content[i..]);
                break;
            }
        } else {
            result.push(content[i]);
            i += 1;
        }
    }
    
    if count > 0 {
        fs::write(path, &result).await.context("Failed to write file")?;
    }
    
    Ok(count)
}

/// Encode bytes to base64
pub fn to_base64(data: &[u8]) -> String {
    BASE64.encode(data)
}

/// Decode base64 to bytes
pub fn from_base64(s: &str) -> Result<Vec<u8>> {
    BASE64.decode(s).context("Invalid base64 data")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_read_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bin");
        fs::write(&path, b"Hello, World!").await.unwrap();
        
        let data = read_bytes(&path, 7, 5).await.unwrap();
        assert_eq!(data, b"World");
    }
    
    #[tokio::test]
    async fn test_read_bytes_past_end() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bin");
        fs::write(&path, b"Short").await.unwrap();
        
        // Request more than available
        let data = read_bytes(&path, 2, 100).await.unwrap();
        assert_eq!(data, b"ort");
    }
    
    #[tokio::test]
    async fn test_write_bytes_replace() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bin");
        fs::write(&path, b"Hello, World!").await.unwrap();
        
        write_bytes(&path, 7, b"Rust!", false).await.unwrap();
        
        let content = fs::read(&path).await.unwrap();
        assert_eq!(content, b"Hello, Rust!!");
    }
    
    #[tokio::test]
    async fn test_write_bytes_insert() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bin");
        fs::write(&path, b"Hello World!").await.unwrap();
        
        write_bytes(&path, 5, b",", true).await.unwrap();
        
        let content = fs::read(&path).await.unwrap();
        assert_eq!(content, b"Hello, World!");
    }
    
    #[tokio::test]
    async fn test_extract_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bin");
        fs::write(&path, b"Hello, World!").await.unwrap();
        
        let extracted = extract_bytes(&path, 5, 2).await.unwrap();
        assert_eq!(extracted, b", ");
        
        let content = fs::read(&path).await.unwrap();
        assert_eq!(content, b"HelloWorld!");
    }
    
    #[tokio::test]
    async fn test_patch_bytes_single() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bin");
        fs::write(&path, b"foo bar foo baz").await.unwrap();
        
        let count = patch_bytes(&path, b"foo", b"qux", false).await.unwrap();
        assert_eq!(count, 1);
        
        let content = fs::read(&path).await.unwrap();
        assert_eq!(content, b"qux bar foo baz");
    }
    
    #[tokio::test]
    async fn test_patch_bytes_all() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.bin");
        fs::write(&path, b"foo bar foo baz foo").await.unwrap();

        let count = patch_bytes(&path, b"foo", b"X", true).await.unwrap();
        assert_eq!(count, 3);

        let content = fs::read(&path).await.unwrap();
        assert_eq!(content, b"X bar X baz X");
    }

    // ==========================================================================
    // Edge case tests for empty files and boundary conditions
    // ==========================================================================

    #[tokio::test]
    async fn test_read_bytes_empty_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        fs::write(&path, b"").await.unwrap();

        let data = read_bytes(&path, 0, 100).await.unwrap();
        assert!(data.is_empty(), "Empty file should return empty vec");
    }

    #[tokio::test]
    async fn test_read_bytes_offset_beyond_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("small.bin");
        fs::write(&path, b"abc").await.unwrap();

        let data = read_bytes(&path, 100, 50).await.unwrap();
        assert!(data.is_empty(), "Offset beyond file should return empty vec");
    }

    #[tokio::test]
    async fn test_write_bytes_to_empty_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("new.bin");
        // File doesn't exist yet

        write_bytes(&path, 0, b"hello", false).await.unwrap();

        let content = fs::read(&path).await.unwrap();
        assert_eq!(content, b"hello");
    }

    #[tokio::test]
    async fn test_write_bytes_with_gap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("gap.bin");
        // File doesn't exist, write at offset 5 should create padding

        write_bytes(&path, 5, b"X", false).await.unwrap();

        let content = fs::read(&path).await.unwrap();
        assert_eq!(content.len(), 6);
        assert_eq!(&content[0..5], &[0, 0, 0, 0, 0]); // Padding
        assert_eq!(content[5], b'X');
    }

    #[tokio::test]
    async fn test_extract_bytes_empty_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        fs::write(&path, b"").await.unwrap();

        let extracted = extract_bytes(&path, 0, 100).await.unwrap();
        assert!(extracted.is_empty());

        // File should still exist and be empty
        let content = fs::read(&path).await.unwrap();
        assert!(content.is_empty());
    }

    #[tokio::test]
    async fn test_patch_bytes_empty_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        fs::write(&path, b"").await.unwrap();

        let count = patch_bytes(&path, b"x", b"y", true).await.unwrap();
        assert_eq!(count, 0, "Empty file should have no matches");
    }
}
