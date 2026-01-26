//! DOCX file reading tools.

use docx_lite::{extract_text, parse_document_from_path};
use serde_json::{json, Value};
use std::path::Path;

/// Extract text from DOCX file
pub fn docx_read(path: &Path, include_structure: bool) -> Result<Value, String> {
    if include_structure {
        // Parse with structure (paragraphs, tables)
        let doc = parse_document_from_path(path).map_err(|e| e.to_string())?;
        
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
        let text = extract_text(path).map_err(|e| e.to_string())?;
        
        Ok(json!({
            "path": path.display().to_string(),
            "text": text,
            "length": text.len()
        }))
    }
}

/// Get DOCX document info (paragraph/table counts)
pub fn docx_info(path: &Path) -> Result<Value, String> {
    let doc = parse_document_from_path(path).map_err(|e| e.to_string())?;
    
    let total_chars: usize = doc.paragraphs.iter().map(|p| p.to_text().len()).sum();
    
    Ok(json!({
        "path": path.display().to_string(),
        "paragraph_count": doc.paragraphs.len(),
        "table_count": doc.tables.len(),
        "total_characters": total_chars
    }))
}
