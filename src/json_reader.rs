use std::path::Path;

use anyhow::{Result, Context, bail};
use serde_json::Value;
use serde_json_path::JsonPath;
use tokio::fs;

use crate::fs_ops::decode_bytes;

/// Result of reading JSON file
#[derive(Debug, Clone)]
pub struct JsonReadResult {
    /// Parsed/queried result
    pub result: Value,
    /// Whether query matched anything
    pub query_matched: bool,
    /// Total number of keys at root level (for objects)
    pub total_keys: Option<usize>,
    /// Total array length (for arrays)
    pub array_length: Option<usize>,
    /// Pretty-printed result
    pub pretty: String,
    /// Parse error if file was invalid JSON
    pub parse_error: Option<JsonParseError>,
}

/// Detailed parse error info
#[derive(Debug, Clone)]
pub struct JsonParseError {
    pub message: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
    /// Context around the error (few lines)
    pub context: Option<String>,
}

/// Read and parse JSON file with optional JSONPath query
/// 
/// Handles:
/// - Valid JSON -> parse and optionally query
/// - Invalid JSON -> detailed error with location and context
/// - Empty file -> error
/// - Non-UTF8 -> try to decode with charset detection
pub async fn read_json(
    path: &Path,
    query: Option<&str>,
    pretty: bool,
) -> Result<JsonReadResult> {
    // Read file content
    let bytes = fs::read(path).await
        .with_context(|| format!("Cannot read file: {}", path.display()))?;
    
    if bytes.is_empty() {
        bail!("File is empty: {}", path.display());
    }
    
    // Decode bytes (handles non-UTF8)
    let content = decode_bytes(&bytes);
    
    // Try to parse JSON
    let parsed: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            // Build detailed error info
            let line = e.line();
            let column = e.column();
            let context = extract_error_context(&content, line, column);
            
            let parse_error = JsonParseError {
                message: format!("Invalid JSON: {}", e),
                line: Some(line),
                column: Some(column),
                context,
            };
            
            // Return partial result with error
            return Ok(JsonReadResult {
                result: Value::Null,
                query_matched: false,
                total_keys: None,
                array_length: None,
                pretty: String::new(),
                parse_error: Some(parse_error),
            });
        }
    };
    
    // Get root stats
    let total_keys = if let Value::Object(obj) = &parsed {
        Some(obj.len())
    } else {
        None
    };
    
    let array_length = if let Value::Array(arr) = &parsed {
        Some(arr.len())
    } else {
        None
    };
    
    // Apply query if provided
    let (result, query_matched) = if let Some(query_str) = query {
        apply_query(&parsed, query_str)?
    } else {
        (parsed.clone(), true)
    };
    
    // Format result
    let pretty_result = if pretty {
        serde_json::to_string_pretty(&result).unwrap_or_default()
    } else {
        serde_json::to_string(&result).unwrap_or_default()
    };
    
    Ok(JsonReadResult {
        result,
        query_matched,
        total_keys,
        array_length,
        pretty: pretty_result,
        parse_error: None,
    })
}

/// Apply JSONPath query to parsed JSON
fn apply_query(json: &Value, query: &str) -> Result<(Value, bool)> {
    // Try JSONPath first
    if query.starts_with('$') {
        let path = JsonPath::parse(query)
            .map_err(|e| anyhow::anyhow!("Invalid JSONPath '{}': {}", query, e))?;
        
        let nodes = path.query(json);
        let results: Vec<&Value> = nodes.all();
        
        if results.is_empty() {
            return Ok((Value::Null, false));
        }
        
        // Return single value or array of values
        if results.len() == 1 {
            return Ok((results[0].clone(), true));
        }
        
        let arr: Vec<Value> = results.into_iter().cloned().collect();
        return Ok((Value::Array(arr), true));
    }
    
    // Simple dot notation: "foo.bar.baz"
    let parts: Vec<&str> = query.split('.').collect();
    let mut current = json;
    
    for part in parts {
        // Handle array index: "items[0]"
        if let Some(idx_start) = part.find('[') {
            let key = &part[..idx_start];
            let idx_str = &part[idx_start + 1..part.len() - 1];
            
            if !key.is_empty() {
                current = current.get(key).unwrap_or(&Value::Null);
            }
            
            if let Ok(idx) = idx_str.parse::<usize>() {
                current = current.get(idx).unwrap_or(&Value::Null);
            } else {
                return Ok((Value::Null, false));
            }
        } else {
            current = current.get(part).unwrap_or(&Value::Null);
        }
        
        if current.is_null() {
            return Ok((Value::Null, false));
        }
    }
    
    Ok((current.clone(), true))
}

/// Extract context around parse error
fn extract_error_context(content: &str, line: usize, column: usize) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    
    if line == 0 || line > lines.len() {
        return None;
    }
    
    let line_idx = line - 1;
    let mut context = Vec::new();
    
    // Show 2 lines before
    for i in line_idx.saturating_sub(2)..line_idx {
        context.push(format!("{:4} | {}", i + 1, lines[i]));
    }
    
    // Show error line with pointer
    if line_idx < lines.len() {
        context.push(format!("{:4} | {}", line, lines[line_idx]));
        
        // Add pointer to error column
        let pointer = format!("     | {}^", " ".repeat(column.saturating_sub(1)));
        context.push(pointer);
    }
    
    // Show 1 line after
    if line_idx + 1 < lines.len() {
        context.push(format!("{:4} | {}", line + 1, lines[line_idx + 1]));
    }
    
    Some(context.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs;

    #[tokio::test]
    async fn test_read_valid_json_object() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.json");
        fs::write(&path, r#"{"name": "test", "value": 42}"#).await.unwrap();
        
        let result = read_json(&path, None, true).await.unwrap();
        
        assert!(result.parse_error.is_none());
        assert!(result.query_matched);
        assert_eq!(result.total_keys, Some(2));
        assert!(result.pretty.contains("name"));
    }

    #[tokio::test]
    async fn test_read_valid_json_array() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.json");
        fs::write(&path, r#"[1, 2, 3, 4, 5]"#).await.unwrap();
        
        let result = read_json(&path, None, true).await.unwrap();
        
        assert!(result.parse_error.is_none());
        assert_eq!(result.array_length, Some(5));
    }

    #[tokio::test]
    async fn test_read_invalid_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.json");
        fs::write(&path, r#"{"name": "test", invalid}"#).await.unwrap();
        
        let result = read_json(&path, None, true).await.unwrap();
        
        assert!(result.parse_error.is_some());
        let err = result.parse_error.unwrap();
        assert!(err.message.contains("Invalid JSON"));
        assert!(err.line.is_some());
        assert!(err.context.is_some());
    }

    #[tokio::test]
    async fn test_read_empty_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.json");
        fs::write(&path, "").await.unwrap();
        
        let result = read_json(&path, None, true).await;
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[tokio::test]
    async fn test_query_dot_notation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.json");
        fs::write(&path, r#"{"user": {"name": "Alice", "age": 30}}"#).await.unwrap();
        
        let result = read_json(&path, Some("user.name"), true).await.unwrap();
        
        assert!(result.query_matched);
        assert_eq!(result.result, Value::String("Alice".to_string()));
    }

    #[tokio::test]
    async fn test_query_array_index() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.json");
        fs::write(&path, r#"{"items": ["a", "b", "c"]}"#).await.unwrap();
        
        let result = read_json(&path, Some("items[1]"), true).await.unwrap();
        
        assert!(result.query_matched);
        assert_eq!(result.result, Value::String("b".to_string()));
    }

    #[tokio::test]
    async fn test_query_jsonpath() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.json");
        fs::write(&path, r#"{"users": [{"name": "Alice"}, {"name": "Bob"}]}"#).await.unwrap();
        
        let result = read_json(&path, Some("$.users[*].name"), true).await.unwrap();
        
        assert!(result.query_matched);
        if let Value::Array(arr) = &result.result {
            assert_eq!(arr.len(), 2);
        } else {
            panic!("Expected array result");
        }
    }

    #[tokio::test]
    async fn test_query_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.json");
        fs::write(&path, r#"{"name": "test"}"#).await.unwrap();
        
        let result = read_json(&path, Some("nonexistent"), true).await.unwrap();
        
        assert!(!result.query_matched);
        assert!(result.result.is_null());
    }

    #[tokio::test]
    async fn test_invalid_json_with_context() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.json");
        let content = r#"{
    "name": "test",
    "value": ,
    "other": 1
}"#;
        fs::write(&path, content).await.unwrap();
        
        let result = read_json(&path, None, true).await.unwrap();
        
        assert!(result.parse_error.is_some());
        let err = result.parse_error.unwrap();
        assert!(err.context.is_some());
        let ctx = err.context.unwrap();
        assert!(ctx.contains("value"));
    }

    #[tokio::test]
    async fn test_nested_query() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.json");
        fs::write(&path, r#"{"a": {"b": {"c": {"d": 42}}}}"#).await.unwrap();
        
        let result = read_json(&path, Some("a.b.c.d"), true).await.unwrap();
        
        assert!(result.query_matched);
        assert_eq!(result.result, Value::Number(42.into()));
    }
}
