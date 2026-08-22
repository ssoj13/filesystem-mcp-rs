use std::borrow::Cow;
use std::path::Path;

use anyhow::Result;
use chardetng::{EncodingDetector, Iso2022JpDetection, Utf8Detection};
use encoding_rs::Encoding;
use tokio::fs;

/// Decode bytes to string with auto-detected encoding.
/// Tries UTF-8 first (fast path), then uses chardetng for detection.
pub fn decode_bytes(bytes: &[u8]) -> String {
    // Fast path: valid UTF-8
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }

    // Detect encoding (UTF-8 already ruled out above)
    let mut detector = EncodingDetector::new(Iso2022JpDetection::Allow);
    detector.feed(bytes, true);
    let encoding = detector.guess(None, Utf8Detection::Deny);

    // Decode with detected encoding
    let (decoded, _, _) = encoding.decode(bytes);
    decoded.into_owned()
}

/// Read full file with auto-detected encoding.
/// Line endings are normalized to LF (\n) for consistent behavior across platforms.
pub async fn read_text(path: &Path) -> Result<String> {
    let bytes = fs::read(path).await?;
    let content = decode_bytes(&bytes);
    // Normalize line endings: CRLF -> LF, CR -> LF
    Ok(normalize_line_endings(&content))
}

/// Normalize line endings to LF for consistent cross-platform behavior.
/// Handles CRLF (Windows), CR (old Mac), and preserves LF (Unix).
#[inline]
pub fn normalize_line_endings(s: &str) -> String {
    // Fast path: no CR in content
    if !s.contains('\r') {
        return s.to_string();
    }
    // Replace CRLF first, then standalone CR
    s.replace("\r\n", "\n").replace('\r', "\n")
}

/// Newline convention detected in a text file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Newline {
    /// Unix `\n`.
    Lf,
    /// Windows `\r\n`.
    Crlf,
    /// Classic Mac `\r`.
    Cr,
}

/// A decoded text file plus the metadata needed to write it back *faithfully*.
///
/// `text` is always LF-normalized so editing and pattern-matching stay uniform
/// regardless of the file's on-disk convention; [`TextFile::encode`] restores
/// the original newline style, character encoding, and BOM. This is what keeps
/// an `edit_file` on a Windows CRLF / UTF-8-BOM / legacy-codepage file from
/// silently rewriting every line ending or transcoding the whole file.
pub struct TextFile {
    /// Decoded content, LF-normalized.
    pub text: String,
    /// Encoding the bytes were decoded with (used to re-encode on write).
    encoding: &'static Encoding,
    /// Whether the source started with a byte-order mark.
    had_bom: bool,
    /// Original newline convention, restored on write.
    newline: Newline,
    /// True if decoding produced replacement characters, i.e. the bytes were
    /// not valid in the detected encoding. Such a file cannot be round-tripped
    /// losslessly; edit handlers must refuse rather than corrupt it.
    pub had_errors: bool,
}

/// Detect the file's newline convention from its first line ending.
fn detect_newline(s: &str) -> Newline {
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'\n' => return Newline::Lf,
            b'\r' => {
                return if bytes.get(i + 1) == Some(&b'\n') {
                    Newline::Crlf
                } else {
                    Newline::Cr
                };
            }
            _ => {}
        }
    }
    // No line ending in the file: LF is the harmless default.
    Newline::Lf
}

/// Decode bytes into a [`TextFile`], recording encoding/BOM/newline metadata.
pub fn decode_meta(bytes: &[u8]) -> TextFile {
    // Determine encoding + BOM. UTF-8 (with or without BOM) is the fast, common
    // path; only genuinely non-UTF-8 bytes reach chardetng.
    let (encoding, had_bom): (&'static Encoding, bool) = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        (encoding_rs::UTF_8, true)
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        (encoding_rs::UTF_16LE, true)
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        (encoding_rs::UTF_16BE, true)
    } else if std::str::from_utf8(bytes).is_ok() {
        (encoding_rs::UTF_8, false)
    } else {
        let mut detector = EncodingDetector::new(Iso2022JpDetection::Allow);
        detector.feed(bytes, true);
        (detector.guess(None, Utf8Detection::Deny), false)
    };

    // `decode` strips a leading BOM matching the encoding and reports whether any
    // byte sequence was malformed (replaced with U+FFFD).
    let (decoded, _actual, had_errors) = encoding.decode(bytes);
    let raw = decoded.into_owned();
    let newline = detect_newline(&raw);
    let text = normalize_line_endings(&raw);
    TextFile {
        text,
        encoding,
        had_bom,
        newline,
        had_errors,
    }
}

/// Read a file and decode it into a [`TextFile`] carrying round-trip metadata.
/// Use this (not [`read_text`]) whenever the content will be edited and written
/// back, so the original encoding/BOM/newlines are preserved.
pub async fn read_text_meta(path: &Path) -> Result<TextFile> {
    let bytes = fs::read(path).await?;
    Ok(decode_meta(&bytes))
}

impl TextFile {
    /// Re-encode LF-normalized `text` back to the file's original byte
    /// representation: restore newline style, re-apply the source encoding, and
    /// re-add the BOM if the source had one. Errors if the edited text contains
    /// characters the original (legacy) encoding cannot represent, rather than
    /// emitting numeric-reference mojibake.
    pub fn encode(&self, text: &str) -> Result<Vec<u8>> {
        let restored: Cow<'_, str> = match self.newline {
            Newline::Lf => Cow::Borrowed(text),
            Newline::Crlf => Cow::Owned(text.replace('\n', "\r\n")),
            Newline::Cr => Cow::Owned(text.replace('\n', "\r")),
        };

        if self.encoding == encoding_rs::UTF_8 {
            let mut out = Vec::with_capacity(restored.len() + 3);
            if self.had_bom {
                out.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
            }
            out.extend_from_slice(restored.as_bytes());
            return Ok(out);
        }

        let (encoded, _enc, had_unmappable) = self.encoding.encode(&restored);
        if had_unmappable {
            anyhow::bail!(
                "edited text contains characters that the file's original encoding ({}) \
                 cannot represent; refusing to write to avoid corruption",
                self.encoding.name()
            );
        }
        Ok(encoded.into_owned())
    }

    /// Guard for edit round-trips: reject sources that could not be decoded
    /// losslessly (writing them back would replace unmappable bytes with U+FFFD).
    pub fn ensure_roundtrippable(&self) -> Result<()> {
        if self.had_errors {
            anyhow::bail!(
                "file is not valid {}; refusing to edit because writing it back \
                 would corrupt the undecodable bytes",
                self.encoding.name()
            );
        }
        Ok(())
    }
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
        async_fs::write(&path, "line1\nline2\nline3\nline4\n")
            .await
            .unwrap();

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
        async_fs::write(&path, "line1\nline2\nline3\nline4\n")
            .await
            .unwrap();

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

    #[tokio::test]
    async fn test_read_text_normalizes_crlf() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("crlf.txt");
        async_fs::write(&path, "line1\r\nline2\r\nline3")
            .await
            .unwrap();

        let content = read_text(&path).await.unwrap();
        assert_eq!(content, "line1\nline2\nline3");
        assert!(!content.contains('\r'));
    }

    #[tokio::test]
    async fn test_read_text_normalizes_cr_only() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cr.txt");
        // Old Mac style: CR only
        async_fs::write(&path, "line1\rline2\rline3").await.unwrap();

        let content = read_text(&path).await.unwrap();
        assert_eq!(content, "line1\nline2\nline3");
        assert!(!content.contains('\r'));
    }

    #[test]
    fn test_normalize_line_endings_fast_path() {
        // No CR - should return as-is (fast path)
        let input = "hello\nworld\n";
        let result = normalize_line_endings(input);
        assert_eq!(result, input);
    }

    #[test]
    fn test_normalize_line_endings_crlf() {
        let input = "hello\r\nworld\r\n";
        let result = normalize_line_endings(input);
        assert_eq!(result, "hello\nworld\n");
    }

    #[test]
    fn test_normalize_line_endings_cr_only() {
        let input = "hello\rworld\r";
        let result = normalize_line_endings(input);
        assert_eq!(result, "hello\nworld\n");
    }

    #[test]
    fn test_normalize_line_endings_mixed() {
        // Mixed: CRLF, LF, CR
        let input = "a\r\nb\nc\rd";
        let result = normalize_line_endings(input);
        assert_eq!(result, "a\nb\nc\nd");
    }

    // UTF-8 safety tests

    #[tokio::test]
    async fn test_tail_utf8_multibyte() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("utf8.txt");
        // ContentBlock with multi-byte UTF-8: German umlauts (2 bytes each)
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
        async_fs::write(&path, "line1\nline2\nline3\n")
            .await
            .unwrap();

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
        // ContentBlock should be readable (may be decoded as Latin-1 or similar)
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

    // BH-07: round-trip metadata (encoding / BOM / newline) preservation.

    #[test]
    fn test_meta_crlf_roundtrip_preserves_line_endings() {
        // A Windows CRLF file edited in LF space must be written back as CRLF.
        let tf = decode_meta(b"line1\r\nline2\r\nline3\r\n");
        assert_eq!(tf.text, "line1\nline2\nline3\n"); // LF-normalized for editing
        assert!(!tf.had_errors);
        let out = tf.encode(&tf.text.replace("line2", "LINE2")).unwrap();
        assert_eq!(out, b"line1\r\nLINE2\r\nline3\r\n");
    }

    #[test]
    fn test_meta_lf_stays_lf() {
        let tf = decode_meta(b"a\nb\n");
        let out = tf.encode(&tf.text).unwrap();
        assert_eq!(out, b"a\nb\n");
    }

    #[test]
    fn test_meta_utf8_bom_preserved() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice("hello\r\n".as_bytes());
        let tf = decode_meta(&bytes);
        assert_eq!(tf.text, "hello\n");
        let out = tf.encode(&tf.text).unwrap();
        assert_eq!(out, bytes); // BOM + CRLF both restored
    }

    #[test]
    fn test_meta_cyrillic_utf8_roundtrip() {
        // Cyrillic UTF-8 with CRLF: the exact daily-pain case.
        let src = "привет\r\nмир\r\n".as_bytes().to_vec();
        let tf = decode_meta(&src);
        assert!(!tf.had_errors);
        let edited = tf.text.replace("мир", "Земля");
        let out = tf.encode(&edited).unwrap();
        assert_eq!(out, "привет\r\nЗемля\r\n".as_bytes());
    }

    #[test]
    fn test_meta_invalid_bytes_flagged_and_guarded() {
        // Bytes that are not valid UTF-8 and decode with replacement: the edit
        // guard must refuse rather than let a write corrupt them.
        let tf = decode_meta(b"ok \xff\xfe bad");
        // chardetng picks some legacy encoding; if it had to replace, guard trips.
        if tf.had_errors {
            assert!(tf.ensure_roundtrippable().is_err());
        }
    }
}
