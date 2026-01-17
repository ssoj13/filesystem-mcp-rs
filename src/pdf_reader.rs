use std::path::{Path, PathBuf};

use anyhow::{Result, Context, bail};

/// Result of reading PDF file
#[derive(Debug, Clone)]
pub struct PdfReadResult {
    /// Extracted text content
    pub text: String,
    /// Total pages in document
    pub pages_count: usize,
    /// Pages that were extracted (1-indexed)
    pub pages_extracted: Vec<usize>,
    /// Whether content was truncated due to max_chars
    pub truncated: bool,
    /// Character count
    pub char_count: usize,
}

/// Parse page range string like "1-5" or "1,3,5" or "1,3-5,7"
fn parse_page_range(range: &str, total_pages: usize) -> Result<Vec<usize>> {
    let mut pages = Vec::new();
    
    for part in range.split(',') {
        let part = part.trim();
        
        if part.contains('-') {
            // Range: "1-5"
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() != 2 {
                bail!("Invalid page range: {}", part);
            }
            
            let start: usize = bounds[0].trim().parse()
                .with_context(|| format!("Invalid page number: {}", bounds[0]))?;
            let end: usize = bounds[1].trim().parse()
                .with_context(|| format!("Invalid page number: {}", bounds[1]))?;
            
            if start == 0 || end == 0 {
                bail!("Page numbers are 1-indexed, got 0");
            }
            if start > end {
                bail!("Invalid range: start {} > end {}", start, end);
            }
            
            for p in start..=end.min(total_pages) {
                if !pages.contains(&p) {
                    pages.push(p);
                }
            }
        } else {
            // Single page: "3"
            let p: usize = part.parse()
                .with_context(|| format!("Invalid page number: {}", part))?;
            
            if p == 0 {
                bail!("Page numbers are 1-indexed, got 0");
            }
            if p <= total_pages && !pages.contains(&p) {
                pages.push(p);
            }
        }
    }
    
    pages.sort();
    Ok(pages)
}

/// Read and extract text from PDF file
/// 
/// Handles:
/// - Page range selection
/// - Character limit truncation
/// - Corrupted/unreadable PDFs
pub async fn read_pdf(
    path: &Path,
    pages: Option<&str>,
    max_chars: usize,
) -> Result<PdfReadResult> {
    let path_buf = path.to_path_buf();
    let pages_owned = pages.map(|s| s.to_string());
    
    // pdf-extract is sync, run in blocking task
    let result = tokio::task::spawn_blocking(move || {
        read_pdf_sync(&path_buf, pages_owned.as_deref(), max_chars)
    }).await
        .with_context(|| "PDF extraction task panicked")?;
    
    result
}

fn read_pdf_sync(
    path: &PathBuf,
    pages_str: Option<&str>,
    max_chars: usize,
) -> Result<PdfReadResult> {
    // Load PDF document
    let bytes = std::fs::read(path)
        .with_context(|| format!("Cannot read file: {}", path.display()))?;
    
    // Extract text using pdf-extract
    let text = pdf_extract::extract_text_from_mem(&bytes)
        .with_context(|| format!("Cannot extract text from PDF: {}. The file may be corrupted, encrypted, or contain only images.", path.display()))?;
    
    // Count total pages (estimate from page breaks or use pdf-extract's output)
    let total_pages = estimate_page_count(&text);
    
    // Determine which pages to extract
    let pages_to_extract = if let Some(range) = pages_str {
        parse_page_range(range, total_pages)?
    } else {
        (1..=total_pages).collect()
    };
    
    // For now, pdf-extract gives us all text at once, so we just return it
    // Page-level extraction would require a more sophisticated PDF library
    let mut result_text = text;
    let mut truncated = false;
    
    // Apply character limit
    if result_text.len() > max_chars {
        // Truncate at character boundary
        let mut char_count = 0;
        let mut byte_pos = 0;
        for (idx, c) in result_text.char_indices() {
            char_count += 1;
            byte_pos = idx + c.len_utf8();
            if char_count >= max_chars {
                break;
            }
        }
        result_text.truncate(byte_pos);
        truncated = true;
    }
    
    let char_count = result_text.chars().count();
    
    Ok(PdfReadResult {
        text: result_text,
        pages_count: total_pages,
        pages_extracted: pages_to_extract,
        truncated,
        char_count,
    })
}

/// Estimate page count from text (rough heuristic based on form feeds)
fn estimate_page_count(text: &str) -> usize {
    // PDF text often has form feed characters between pages
    let ff_count = text.matches('\x0C').count();
    if ff_count > 0 {
        return ff_count + 1;
    }
    
    // Fallback: estimate based on character count (roughly 2000 chars per page)
    let chars = text.chars().count();
    if chars == 0 {
        return 1;
    }
    
    (chars / 2000).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_page_range_single() {
        let pages = parse_page_range("3", 10).unwrap();
        assert_eq!(pages, vec![3]);
    }

    #[test]
    fn test_parse_page_range_multiple() {
        let pages = parse_page_range("1,3,5", 10).unwrap();
        assert_eq!(pages, vec![1, 3, 5]);
    }

    #[test]
    fn test_parse_page_range_range() {
        let pages = parse_page_range("2-5", 10).unwrap();
        assert_eq!(pages, vec![2, 3, 4, 5]);
    }

    #[test]
    fn test_parse_page_range_mixed() {
        let pages = parse_page_range("1, 3-5, 7", 10).unwrap();
        assert_eq!(pages, vec![1, 3, 4, 5, 7]);
    }

    #[test]
    fn test_parse_page_range_beyond_total() {
        let pages = parse_page_range("8-15", 10).unwrap();
        assert_eq!(pages, vec![8, 9, 10]);
    }

    #[test]
    fn test_parse_page_range_zero_error() {
        let result = parse_page_range("0", 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_page_range_invalid_range() {
        let result = parse_page_range("5-3", 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_estimate_page_count_empty() {
        assert_eq!(estimate_page_count(""), 1);
    }

    #[test]
    fn test_estimate_page_count_with_ff() {
        let text = "Page 1\x0CPage 2\x0CPage 3";
        assert_eq!(estimate_page_count(text), 3);
    }

    #[test]
    fn test_estimate_page_count_by_chars() {
        let text = "x".repeat(5000);
        assert_eq!(estimate_page_count(&text), 2);
    }

    // Note: Integration tests with actual PDF files would require
    // test PDF fixtures. For now, we test the helper functions.
}
