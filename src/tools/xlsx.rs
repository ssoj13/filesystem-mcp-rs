//! XLSX file reading tools.

use calamine::{open_workbook_auto, Data, DataType, Reader};
use serde_json::{json, Value};
use std::path::Path;

/// Get workbook metadata (sheets, dimensions)
pub fn xlsx_info(path: &Path) -> Result<Value, String> {
    let mut workbook = open_workbook_auto(path).map_err(|e| e.to_string())?;
    
    let sheet_names = workbook.sheet_names().to_vec();
    let sheets: Vec<Value> = sheet_names
        .iter()
        .map(|name| {
            let dims = workbook
                .worksheet_range(name)
                .map(|r| {
                    let (rows, cols) = r.get_size();
                    json!({"rows": rows, "cols": cols})
                })
                .unwrap_or(json!({"rows": 0, "cols": 0}));
            json!({"name": name, "dimensions": dims})
        })
        .collect();

    Ok(json!({
        "path": path.display().to_string(),
        "sheets": sheets,
        "sheet_count": sheets.len()
    }))
}

/// List sheet names
pub fn xlsx_sheets(path: &Path) -> Result<Vec<String>, String> {
    let workbook = open_workbook_auto(path).map_err(|e| e.to_string())?;
    Ok(workbook.sheet_names().to_vec())
}

/// Read sheet data as JSON
pub fn xlsx_read(
    path: &Path,
    sheet: Option<&str>,
    headers: bool,
    max_rows: Option<u32>,
    offset: Option<u32>,
) -> Result<Value, String> {
    let mut workbook = open_workbook_auto(path).map_err(|e| e.to_string())?;
    
    // Get sheet name (first sheet if not specified)
    let sheet_name = match sheet {
        Some(s) => s.to_string(),
        None => workbook
            .sheet_names()
            .first()
            .cloned()
            .ok_or("No sheets in workbook")?,
    };

    // Get worksheet range
    let range = workbook
        .worksheet_range(&sheet_name)
        .map_err(|e| e.to_string())?;

    let (total_rows, cols) = range.get_size();
    let skip = offset.unwrap_or(0) as usize;
    let limit = max_rows.map(|m| m as usize).unwrap_or(total_rows);

    if headers && total_rows > 0 {
        // First row as headers (not affected by offset)
        let header_row: Vec<String> = (0..cols)
            .map(|c| cell_to_string(range.get((0, c))))
            .collect();

        // Data starts from row 1, apply offset/limit
        let data_start = 1 + skip;
        let data_end = (data_start + limit).min(total_rows);

        let data: Vec<Value> = (data_start..data_end)
            .map(|r| {
                let obj: serde_json::Map<String, Value> = header_row
                    .iter()
                    .enumerate()
                    .map(|(c, h)| {
                        let key = if h.is_empty() {
                            format!("col_{}", c)
                        } else {
                            h.clone()
                        };
                        (key, cell_to_value(range.get((r, c))))
                    })
                    .collect();
                Value::Object(obj)
            })
            .collect();

        Ok(json!({
            "sheet": sheet_name,
            "headers": header_row,
            "data": data,
            "total_rows": total_rows - 1,
            "returned": data.len(),
            "offset": skip
        }))
    } else {
        // Raw array of arrays
        let data_start = skip;
        let data_end = (data_start + limit).min(total_rows);

        let data: Vec<Vec<Value>> = (data_start..data_end)
            .map(|r| {
                (0..cols)
                    .map(|c| cell_to_value(range.get((r, c))))
                    .collect()
            })
            .collect();

        Ok(json!({
            "sheet": sheet_name,
            "data": data,
            "total_rows": total_rows,
            "returned": data.len(),
            "cols": cols,
            "offset": skip
        }))
    }
}

fn cell_to_string(cell: Option<&Data>) -> String {
    match cell {
        Some(c) => c.as_string().unwrap_or_default(),
        None => String::new(),
    }
}

fn cell_to_value(cell: Option<&Data>) -> Value {
    match cell {
        Some(Data::Int(i)) => json!(i),
        Some(Data::Float(f)) => json!(f),
        Some(Data::String(s)) => Value::String(s.clone()),
        Some(Data::Bool(b)) => Value::Bool(*b),
        Some(Data::DateTime(dt)) => json!(dt.as_f64()),
        Some(Data::DateTimeIso(s)) => Value::String(s.clone()),
        Some(Data::DurationIso(s)) => Value::String(s.clone()),
        Some(Data::Error(e)) => Value::String(format!("#ERR:{:?}", e)),
        Some(Data::Empty) | None => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_test_xlsx() -> NamedTempFile {
        use rust_xlsxwriter::Workbook;
        
        let temp = NamedTempFile::with_suffix(".xlsx").unwrap();
        let mut workbook = Workbook::new();
        let sheet = workbook.add_worksheet();
        
        // Headers
        sheet.write_string(0, 0, "Name").unwrap();
        sheet.write_string(0, 1, "Value").unwrap();
        sheet.write_string(0, 2, "Описание").unwrap(); // Unicode header
        
        // Data
        sheet.write_string(1, 0, "Alpha").unwrap();
        sheet.write_number(1, 1, 42.0).unwrap();
        sheet.write_string(1, 2, "Привет 🦀").unwrap();
        
        sheet.write_string(2, 0, "Beta").unwrap();
        sheet.write_number(2, 1, 3.14).unwrap();
        sheet.write_string(2, 2, "世界").unwrap();
        
        workbook.save(temp.path()).unwrap();
        temp
    }

    #[test]
    fn test_xlsx_info() {
        let temp = create_test_xlsx();
        let result = xlsx_info(temp.path());
        assert!(result.is_ok());
        let json = result.unwrap();
        assert_eq!(json["sheet_count"], 1);
        assert!(json["sheets"].as_array().unwrap().len() > 0);
    }

    #[test]
    fn test_xlsx_sheets() {
        let temp = create_test_xlsx();
        let result = xlsx_sheets(temp.path());
        assert!(result.is_ok());
        let sheets = result.unwrap();
        assert!(!sheets.is_empty());
    }

    #[test]
    fn test_xlsx_read_with_headers() {
        let temp = create_test_xlsx();
        let result = xlsx_read(temp.path(), None, true, None, None);
        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.get("headers").is_some());
        assert!(json.get("data").is_some());
        
        // Check Unicode header
        let headers = json["headers"].as_array().unwrap();
        assert!(headers.iter().any(|h| h.as_str().unwrap().contains("Описание")));
    }

    #[test]
    fn test_xlsx_read_unicode_data() {
        let temp = create_test_xlsx();
        let result = xlsx_read(temp.path(), None, true, None, None);
        assert!(result.is_ok());
        let json = result.unwrap();
        
        // Check Unicode data is preserved
        let data = json["data"].as_array().unwrap();
        let first_row = &data[0];
        assert!(first_row["Описание"].as_str().unwrap().contains("🦀"));
    }

    #[test]
    fn test_xlsx_read_pagination() {
        let temp = create_test_xlsx();
        let result = xlsx_read(temp.path(), None, true, Some(1), Some(0));
        assert!(result.is_ok());
        let json = result.unwrap();
        assert_eq!(json["returned"], 1);
    }

    #[test]
    fn test_xlsx_read_no_headers() {
        let temp = create_test_xlsx();
        let result = xlsx_read(temp.path(), None, false, None, None);
        assert!(result.is_ok());
        let json = result.unwrap();
        // Data should be array of arrays
        let data = json["data"].as_array().unwrap();
        assert!(data[0].is_array());
    }
}
