use std::path::Path;

use anyhow::Result;
use chardetng::EncodingDetector;
use tokio::fs;

/// Decode bytes to string with auto-detected encoding.
/// Tries UTF-8 first (fast path), then uses chardetng for detection.
pub fn decode_bytes(bytes: &[u8]) -> String {
    // Fast path: valid UTF-8
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }

    // Detect encoding
    let mut detector = EncodingDetector::new();
    detector.feed(bytes, true);
    let encoding = detector.guess(None, true);

    // Decode with detected encoding
    let (decoded, _, _) = encoding.decode(bytes);
    decoded.into_owned()
}

/// Read full file with auto-detected encoding.
pub async fn read_text(path: &Path) -> Result<String> {
    let bytes = fs::read(path).await?;
    Ok(decode_bytes(&bytes))
}

/// Return first N lines (encoding-safe).
pub async fn head(path: &Path, lines: usize) -> Result<String> {
    if lines == 0 {
        return Ok(String::new());
    }
    // Read full file as bytes, decode, then take first N lines
    let bytes = fs::read(path).await?;
    let content = decode_bytes(&bytes);
    let result: Vec<&str> = content.lines().take(lines).collect();
    Ok(result.join("\n"))
}

/// Return last N lines (encoding-safe).
pub async fn tail(path: &Path, lines: usize) -> Result<String> {
    if lines == 0 {
        return Ok(String::new());
    }
    // Read full file as bytes, decode, then take last N lines
    let bytes = fs::read(path).await?;
    let content = decode_bytes(&bytes);
    let all_lines: Vec<&str> = content.lines().collect();
    let start = all_lines.len().saturating_sub(lines);
    Ok(all_lines[start..].join("\n"))
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

    // Encoding detection tests

    #[test]
    fn test_decode_bytes_utf8() {
        let bytes = "hello world".as_bytes();
        assert_eq!(decode_bytes(bytes), "hello world");
    }

    #[test]
    fn test_decode_bytes_utf8_with_bom() {
        // UTF-8 with BOM
        let mut bytes = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM
        bytes.extend_from_slice("hello".as_bytes());
        let result = decode_bytes(&bytes);
        // chardetng should handle BOM correctly
        assert!(result.contains("hello"));
    }

    #[test]
    fn test_decode_bytes_latin1() {
        // Latin-1 encoded: "cafe" with e-acute (0xE9 in Latin-1)
        let bytes: &[u8] = &[0x63, 0x61, 0x66, 0xE9]; // "cafe" with Latin-1 e-acute
        let result = decode_bytes(bytes);
        // Should decode without panicking, content may vary based on detection
        assert!(!result.is_empty());
    }

    #[test]
    fn test_decode_bytes_windows1252() {
        // Windows-1252: smart quotes and other special chars
        let bytes: &[u8] = &[0x93, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x94]; // "hello" in smart quotes
        let result = decode_bytes(bytes);
        assert!(!result.is_empty());
        assert!(result.contains("hello"));
    }

    #[tokio::test]
    async fn test_read_text_non_utf8_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("latin1.txt");
        // Write Latin-1 encoded content directly as bytes
        let content: &[u8] = b"Caf\xe9 au lait\nR\xe9sum\xe9";
        async_fs::write(&path, content).await.unwrap();

        // Should not panic and should return decoded content
        let result = read_text(&path).await.unwrap();
        assert!(!result.is_empty());
        // Content should be readable (may be decoded as Latin-1 or similar)
        assert!(result.lines().count() >= 1);
    }

    #[tokio::test]
    async fn test_head_non_utf8_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("latin1.txt");
        let content: &[u8] = b"Line1 with \xe9\nLine2\nLine3";
        async_fs::write(&path, content).await.unwrap();

        let result = head(&path, 2).await.unwrap();
        assert!(result.lines().count() == 2);
    }

    #[tokio::test]
    async fn test_tail_non_utf8_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("latin1.txt");
        let content: &[u8] = b"Line1\nLine2 with \xe9\nLine3";
        async_fs::write(&path, content).await.unwrap();

        let result = tail(&path, 2).await.unwrap();
        assert!(result.lines().count() == 2);
    }
}
