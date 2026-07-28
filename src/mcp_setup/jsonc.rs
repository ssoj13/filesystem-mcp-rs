//! Reading and writing the agents' JSON configs — which are frequently **JSONC**.
//!
//! Zed, VS Code and friends ship settings files full of comments and trailing commas. Parsing them
//! with strict `serde_json` fails outright, and rewriting them from a `serde_json::Value` would
//! silently delete the user's comments and formatting. So:
//!
//! - **reads** go through a JSONC-tolerant parser (comments are fine),
//! - **writes** go through the CST, which edits the text in place and leaves everything we did not
//!   touch — comments, key order, indentation — exactly as the user wrote it.

use std::path::Path;

use jsonc_parser::ParseOptions;
use jsonc_parser::cst::{CstInputValue, CstObject, CstRootNode};
use serde_json::{Map, Value};

use crate::mcp_setup::error::{Result, SetupError};

/// Parse a config file into a plain JSON object; a missing or empty file is an empty object.
/// Comments and trailing commas are accepted — these are settings files, not wire JSON.
pub fn read_root_object(path: &Path) -> Result<Map<String, Value>> {
    let Some(raw) = read_if_present(path)? else {
        return Ok(Map::new());
    };
    if raw.trim().is_empty() {
        return Ok(Map::new());
    }
    let value = jsonc_parser::parse_to_serde_value(&raw, &Default::default())
        .map_err(|e| jsonc_error(path, &e.to_string()))?;
    match value {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(map)) => Ok(map),
        Some(_) => Err(SetupError::ExpectedJsonObject {
            path: path.to_path_buf(),
        }),
    }
}

fn read_if_present(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    std::fs::read_to_string(path)
        .map(Some)
        .map_err(|e| SetupError::io(path.to_path_buf(), e))
}

fn jsonc_error(path: &Path, msg: &str) -> SetupError {
    SetupError::InvalidBundle(format!("{} is not valid JSON/JSONC: {msg}", path.display()))
}

fn root_of(path: &Path, raw: &str) -> Result<CstRootNode> {
    let text = if raw.trim().is_empty() { "{}" } else { raw };
    CstRootNode::parse(text, &ParseOptions::default())
        .map_err(|e| jsonc_error(path, &e.to_string()))
}

/// Walk (creating as needed) to the object holding the servers, e.g. `mcp` → `servers`.
fn servers_object(root: &CstRootNode, parent_path: &[&str]) -> CstObject {
    let mut obj = root.object_value_or_set();
    for key in parent_path {
        obj = obj.object_value_or_set(key);
    }
    obj
}

/// Insert or replace `parent_path.<key>`, preserving everything else in the file verbatim.
pub fn upsert_in_file(
    path: &Path,
    parent_path: &[&str],
    key: &str,
    entry: &Value,
) -> Result<()> {
    let raw = read_if_present(path)?.unwrap_or_default();
    let root = root_of(path, &raw)?;
    let servers = servers_object(&root, parent_path);

    let input = to_cst(entry);
    match servers.get(key) {
        Some(prop) => prop.set_value(input),
        None => {
            servers.append(key, input);
        }
    }
    write(path, &root.to_string())
}

/// Remove `parent_path.<key>` if present, preserving the rest of the file. Returns true if the key
/// was there.
pub fn remove_in_file(path: &Path, parent_path: &[&str], key: &str) -> Result<bool> {
    let Some(raw) = read_if_present(path)? else {
        return Ok(false);
    };
    let root = root_of(path, &raw)?;
    let mut obj = root.object_value_or_set();
    for k in parent_path {
        let Some(next) = obj.get(k).and_then(|prop| prop.value().and_then(|v| v.as_object())) else {
            return Ok(false);
        };
        obj = next;
    }
    let Some(prop) = obj.get(key) else {
        return Ok(false);
    };
    prop.remove();
    write(path, &root.to_string())?;
    Ok(true)
}

fn write(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SetupError::io(parent.to_path_buf(), e))?;
    }
    std::fs::write(path, text).map_err(|e| SetupError::io(path.to_path_buf(), e))
}

/// `serde_json::Value` → the CST's input type. Numbers keep their original text so `1.0` does not
/// silently become `1`.
fn to_cst(value: &Value) -> CstInputValue {
    match value {
        Value::Null => CstInputValue::Null,
        Value::Bool(b) => CstInputValue::Bool(*b),
        Value::Number(n) => CstInputValue::Number(n.to_string()),
        Value::String(s) => CstInputValue::String(s.clone()),
        Value::Array(items) => CstInputValue::Array(items.iter().map(to_cst).collect()),
        Value::Object(map) => CstInputValue::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), to_cst(v)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_formatting_survive_an_upsert() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("settings.json");
        std::fs::write(
            &path,
            "{\n  // my notes\n  \"theme\": \"dark\",\n  \"context_servers\": {}\n}\n",
        )
        .unwrap();

        upsert_in_file(
            &path,
            &["context_servers"],
            "demo",
            &serde_json::json!({"source": "custom", "command": "demo"}),
        )
        .unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("// my notes"), "comment was eaten: {after}");
        assert!(after.contains("\"theme\": \"dark\""));
        assert!(after.contains("\"demo\""));

        // …and removing it again leaves the user's file as it was.
        assert!(remove_in_file(&path, &["context_servers"], "demo").unwrap());
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("// my notes"));
        assert!(!after.contains("demo"));
    }

    #[test]
    fn jsonc_with_comments_reads_as_a_plain_object() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("settings.json");
        std::fs::write(&path, "{\n  // hi\n  \"a\": 1,\n}\n").unwrap();
        let map = read_root_object(&path).unwrap();
        assert_eq!(map.get("a").unwrap(), &serde_json::json!(1));
    }

    #[test]
    fn missing_file_is_created_with_the_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested").join("mcp.json");
        upsert_in_file(&path, &["servers"], "demo", &serde_json::json!({"command": "x"})).unwrap();
        let map = read_root_object(&path).unwrap();
        assert!(map["servers"]["demo"]["command"] == serde_json::json!("x"));
    }
}
