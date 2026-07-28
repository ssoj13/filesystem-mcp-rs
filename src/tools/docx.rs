//! DOCX file reading tools.

use anyhow::{Context, Result};
use docx_lite::{extract_text, parse_document_from_path};
use serde_json::{Value, json};
use std::path::Path;

/// Extract text from DOCX file
pub fn docx_read(path: &Path, include_structure: bool) -> Result<Value> {
    if include_structure {
        // Parse with structure (paragraphs, tables)
        let doc = parse_document_from_path(path).context("Failed to parse DOCX document")?;

        let paragraphs: Vec<Value> = doc
            .paragraphs
            .iter()
            .map(|p| {
                json!({
                    "text": p.to_text(),
                })
            })
            .collect();

        let tables: Vec<Value> = doc
            .tables
            .iter()
            .map(|t| {
                let rows: Vec<Vec<String>> = t
                    .rows
                    .iter()
                    .map(|row| {
                        row.cells
                            .iter()
                            .map(|cell| {
                                cell.paragraphs
                                    .iter()
                                    .map(|p| p.to_text())
                                    .collect::<Vec<_>>()
                                    .join("\n")
                            })
                            .collect()
                    })
                    .collect();
                json!({ "rows": rows })
            })
            .collect();

        Ok(json!({
            "path": path.display().to_string(),
            "paragraphs": paragraphs,
            "tables": tables,
            "paragraph_count": paragraphs.len(),
            "table_count": tables.len()
        }))
    } else {
        // Simple text extraction
        let text = extract_text(path).context("Failed to extract text from DOCX")?;

        Ok(json!({
            "path": path.display().to_string(),
            "text": text,
            "length": text.len()
        }))
    }
}

/// Get DOCX document info (paragraph/table counts)
pub fn docx_info(path: &Path) -> Result<Value> {
    let doc = parse_document_from_path(path).context("Failed to parse DOCX document")?;

    let total_chars: usize = doc.paragraphs.iter().map(|p| p.to_text().len()).sum();

    Ok(json!({
        "path": path.display().to_string(),
        "paragraph_count": doc.paragraphs.len(),
        "table_count": doc.tables.len(),
        "total_characters": total_chars
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_docx_read_not_found() {
        let path = PathBuf::from("nonexistent.docx");
        let result = docx_read(&path, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_docx_info_not_found() {
        let path = PathBuf::from("nonexistent.docx");
        let result = docx_info(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_docx_read_invalid_file() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a non-docx file
        let mut temp = NamedTempFile::with_suffix(".docx").unwrap();
        temp.write_all(b"not a docx file").unwrap();

        let result = docx_read(temp.path(), false);
        assert!(result.is_err());
    }
}
