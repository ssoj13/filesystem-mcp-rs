use std::path::Path;

use anyhow::Result;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt};

/// Read full file as UTF-8 text.
pub async fn read_text(path: &Path) -> Result<String> {
    let content = fs::read_to_string(path).await?;
    Ok(content)
}

/// Return first N lines.
pub async fn head(path: &Path, lines: usize) -> Result<String> {
    let mut file = fs::File::open(path).await?;
    let mut reader = tokio::io::BufReader::new(&mut file);
    let mut buf = String::new();
    let mut out = Vec::new();

    while out.len() < lines {
        buf.clear();
        let n = reader.read_line(&mut buf).await?;
        if n == 0 {
            break;
        }
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        out.push(buf.clone());
    }

    Ok(out.join("\n"))
}

/// Return last N lines; reads from end in chunks.
pub async fn tail(path: &Path, lines: usize) -> Result<String> {
    const CHUNK: usize = 4096;
    let mut file = fs::File::open(path).await?;
    let metadata = file.metadata().await?;
    let size = metadata.len();
    if size == 0 || lines == 0 {
        return Ok(String::new());
    }

    let mut pos: i64 = size as i64;
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut newline_count = 0usize;

    while pos > 0 && newline_count <= lines {
        let read_size = CHUNK.min(pos as usize);
        pos -= read_size as i64;
        let mut chunk = vec![0u8; read_size];
        file.seek(std::io::SeekFrom::Start(pos as u64)).await?;
        let n = file.read(&mut chunk).await?;
        chunk.truncate(n);
        newline_count += chunk.iter().filter(|b| **b == b'\n').count();
        chunks.push(chunk);
        if newline_count > lines {
            break;
        }
    }

    let mut combined = Vec::new();
    for chunk in chunks.iter().rev() {
        combined.extend_from_slice(chunk);
    }

    // Find valid UTF-8 boundary (skip partial multi-byte char at start)
    let text = find_valid_utf8_start(&combined);
    let lines_vec: Vec<&str> = text.lines().collect();
    let start = lines_vec.len().saturating_sub(lines);
    Ok(lines_vec[start..].join("\n"))
}

/// Find first valid UTF-8 boundary and decode from there.
/// This handles the case where chunk boundary splits a multi-byte UTF-8 char.
fn find_valid_utf8_start(bytes: &[u8]) -> String {
    // Try full slice first (common case)
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }

    // Skip continuation bytes (10xxxxxx = 0x80-0xBF) at the start
    // to find a valid UTF-8 sequence boundary
    for skip in 1..=4.min(bytes.len()) {
        if let Ok(s) = std::str::from_utf8(&bytes[skip..]) {
            return s.to_string();
        }
    }

    // Fallback: lossy conversion (shouldn't happen with valid UTF-8 files)
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs as async_fs;

    #[tokio::test]
    async fn test_read_text_normal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");
        async_fs::write(&path, "hello\nworld").await.unwrap();

        let content = read_text(&path).await.unwrap();
        assert_eq!(content, "hello\nworld");
    }

    #[tokio::test]
    async fn test_read_text_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        async_fs::write(&path, "").await.unwrap();

        let content = read_text(&path).await.unwrap();
        assert_eq!(content, "");
    }

    #[tokio::test]
    async fn test_head_normal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");
        async_fs::write(&path, "line1\nline2\nline3\nline4\n").await.unwrap();

        let result = head(&path, 2).await.unwrap();
        assert_eq!(result, "line1\nline2");
    }

    #[tokio::test]
    async fn test_head_empty_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        async_fs::write(&path, "").await.unwrap();

        let result = head(&path, 5).await.unwrap();
        assert_eq!(result, "");
    }

    #[tokio::test]
    async fn test_head_zero_lines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");
        async_fs::write(&path, "line1\nline2\n").await.unwrap();

        let result = head(&path, 0).await.unwrap();
        assert_eq!(result, "");
    }

    #[tokio::test]
    async fn test_head_more_than_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");
        async_fs::write(&path, "line1\nline2").await.unwrap();

        let result = head(&path, 100).await.unwrap();
        assert_eq!(result, "line1\nline2");
    }

    #[tokio::test]
    async fn test_tail_normal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");
        async_fs::write(&path, "line1\nline2\nline3\nline4\n").await.unwrap();

        let result = tail(&path, 2).await.unwrap();
        assert_eq!(result, "line3\nline4");
    }

    #[tokio::test]
    async fn test_tail_empty_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        async_fs::write(&path, "").await.unwrap();

        let result = tail(&path, 5).await.unwrap();
        assert_eq!(result, "");
    }

    #[tokio::test]
    async fn test_tail_zero_lines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");
        async_fs::write(&path, "line1\nline2\n").await.unwrap();

        let result = tail(&path, 0).await.unwrap();
        assert_eq!(result, "");
    }

    #[tokio::test]
    async fn test_tail_more_than_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");
        async_fs::write(&path, "line1\nline2").await.unwrap();

        let result = tail(&path, 100).await.unwrap();
        assert_eq!(result, "line1\nline2");
    }

    #[tokio::test]
    async fn test_head_strips_crlf() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("crlf.txt");
        async_fs::write(&path, "line1\r\nline2\r\n").await.unwrap();

        let result = head(&path, 2).await.unwrap();
        assert_eq!(result, "line1\nline2");
    }

    // UTF-8 safety tests

    #[tokio::test]
    async fn test_tail_utf8_multibyte() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("utf8.txt");
        // Content with multi-byte UTF-8: German umlauts (2 bytes each)
        async_fs::write(&path, "Zeile eins\nZeile zwei mit ooo\nDritte Zeile\n")
            .await
            .unwrap();

        let result = tail(&path, 2).await.unwrap();
        assert_eq!(result, "Zeile zwei mit ooo\nDritte Zeile");
    }

    #[tokio::test]
    async fn test_tail_utf8_emoji() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("emoji.txt");
        // Emoji are 4-byte UTF-8 sequences
        async_fs::write(&path, "line1\nline2\nline3\n").await.unwrap();

        let result = tail(&path, 2).await.unwrap();
        assert_eq!(result, "line2\nline3");
    }

    #[tokio::test]
    async fn test_head_utf8_multibyte() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("utf8.txt");
        async_fs::write(&path, "Erste Zeile\nZweite Zeile\nDritte\n")
            .await
            .unwrap();

        let result = head(&path, 2).await.unwrap();
        assert_eq!(result, "Erste Zeile\nZweite Zeile");
    }

    #[test]
    fn test_find_valid_utf8_start_clean() {
        // Valid UTF-8 - no skip needed
        let bytes = "hello world".as_bytes();
        assert_eq!(find_valid_utf8_start(bytes), "hello world");
    }

    #[test]
    fn test_find_valid_utf8_start_partial_2byte() {
        // Simulates partial 2-byte char at start (o = C3 B6)
        // If we only have the continuation byte B6, skip it
        let mut bytes = vec![0xB6]; // continuation byte only
        bytes.extend_from_slice("hello".as_bytes());
        let result = find_valid_utf8_start(&bytes);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_find_valid_utf8_start_partial_4byte() {
        // Simulates partial 4-byte emoji at start
        // 4-byte: F0 9F 98 80 - if we have only last 2 continuation bytes
        let mut bytes = vec![0x98, 0x80]; // last 2 continuation bytes
        bytes.extend_from_slice("test".as_bytes());
        let result = find_valid_utf8_start(&bytes);
        assert_eq!(result, "test");
    }
}
