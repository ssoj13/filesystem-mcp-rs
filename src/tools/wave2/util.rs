//! Utility functions - clipboard, env, which.

use serde_json::{json, Value};
use std::env;
use std::path::PathBuf;

/// Read text from system clipboard
#[cfg(feature = "screenshot-tools")]
pub fn clipboard_read() -> Result<String, String> {
    use arboard::Clipboard;
    let mut clipboard = Clipboard::new()
        .map_err(|e| format!("Failed to access clipboard: {}", e))?;
    clipboard.get_text()
        .map_err(|e| format!("Failed to read clipboard: {}", e))
}

#[cfg(not(feature = "screenshot-tools"))]
pub fn clipboard_read() -> Result<String, String> {
    Err("Clipboard support requires screenshot-tools feature".to_string())
}

/// Write text to system clipboard
#[cfg(feature = "screenshot-tools")]
pub fn clipboard_write(text: &str) -> Result<(), String> {
    use arboard::Clipboard;
    let mut clipboard = Clipboard::new()
        .map_err(|e| format!("Failed to access clipboard: {}", e))?;
    clipboard.set_text(text.to_string())
        .map_err(|e| format!("Failed to write to clipboard: {}", e))
}

#[cfg(not(feature = "screenshot-tools"))]
pub fn clipboard_write(_text: &str) -> Result<(), String> {
    Err("Clipboard support requires screenshot-tools feature".to_string())
}

/// Get environment variable
pub fn env_get(name: &str) -> Option<String> {
    env::var(name).ok()
}

/// Set environment variable (for current process only)
/// # Safety
/// Modifying env vars is inherently unsafe in multi-threaded contexts
pub fn env_set(name: &str, value: &str) {
    // SAFETY: We accept the risk for current process modification
    unsafe { env::set_var(name, value) };
}

/// Remove environment variable (for current process only)
/// # Safety
/// Modifying env vars is inherently unsafe in multi-threaded contexts
pub fn env_remove(name: &str) {
    // SAFETY: We accept the risk for current process modification
    unsafe { env::remove_var(name) };
}

/// List all environment variables
pub fn env_list() -> Value {
    let vars: Vec<Value> = env::vars()
        .map(|(k, v)| json!({"name": k, "value": v}))
        .collect();
    json!({
        "count": vars.len(),
        "variables": vars
    })
}

/// Find executable in PATH (like 'which' command)
pub fn which(command: &str) -> Result<Value, String> {
    let path_var = env::var("PATH").unwrap_or_default();
    
    #[cfg(target_os = "windows")]
    let path_sep = ';';
    #[cfg(not(target_os = "windows"))]
    let path_sep = ':';
    
    #[cfg(target_os = "windows")]
    let pathext = env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC".to_string());
    #[cfg(target_os = "windows")]
    let mut extensions: Vec<&str> = pathext
        .split(';')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    #[cfg(target_os = "windows")]
    extensions.push(""); // Also try without extension
    
    #[cfg(not(target_os = "windows"))]
    let extensions = vec![""];
    
    let mut found = Vec::new();
    
    for dir in path_var.split(path_sep) {
        let dir_path = PathBuf::from(dir);
        
        for ext in &extensions {
            let mut candidate = dir_path.join(command);
            if !ext.is_empty() {
                let name = format!("{}{}", command, ext);
                candidate = dir_path.join(&name);
            }
            
            if candidate.is_file() {
                // Check if executable
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(metadata) = candidate.metadata() {
                        let mode = metadata.permissions().mode();
                        if mode & 0o111 != 0 {
                            found.push(candidate.to_string_lossy().to_string());
                        }
                    }
                }
                #[cfg(not(unix))]
                {
                    found.push(candidate.to_string_lossy().to_string());
                }
            }
        }
    }
    
    // Also check if command is an absolute path
    let abs_path = PathBuf::from(command);
    if abs_path.is_absolute() && abs_path.is_file() {
        if !found.contains(&abs_path.to_string_lossy().to_string()) {
            found.insert(0, abs_path.to_string_lossy().to_string());
        }
    }
    
    if found.is_empty() {
        Err(format!("Command '{}' not found in PATH", command))
    } else {
        Ok(json!({
            "command": command,
            "found": true,
            "path": found.first(),
            "all_matches": found
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_get_set_remove() {
        let key = "TEST_WAVE2_ENV_VAR";
        let value = "test_value_123";
        
        // Initially not set
        assert!(env_get(key).is_none());
        
        // Set and get
        env_set(key, value);
        assert_eq!(env_get(key), Some(value.to_string()));
        
        // Remove
        env_remove(key);
        assert!(env_get(key).is_none());
    }

    #[test]
    fn test_env_unicode() {
        let key = "TEST_WAVE2_UNICODE";
        let value = "Привет мир 你好世界 🦀";
        
        env_set(key, value);
        assert_eq!(env_get(key), Some(value.to_string()));
        env_remove(key);
    }

    #[test]
    fn test_env_list() {
        let result = env_list();
        assert!(result.get("count").is_some());
        assert!(result.get("variables").is_some());
        let count = result["count"].as_u64().unwrap();
        assert!(count > 0);
    }

    #[test]
    fn test_which_cargo() {
        // cargo should be in PATH for Rust projects
        let result = which("cargo");
        assert!(result.is_ok());
        let json = result.unwrap();
        assert_eq!(json["command"], "cargo");
        assert_eq!(json["found"], true);
        assert!(json["path"].as_str().is_some());
    }

    #[test]
    fn test_which_not_found() {
        let result = which("nonexistent_command_12345");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    #[cfg(feature = "screenshot-tools")]
    fn test_clipboard_roundtrip() {
        let text = "Test clipboard text 🦀 Привет";
        // This test may fail in CI without display
        if clipboard_write(text).is_ok() {
            if let Ok(read) = clipboard_read() {
                assert_eq!(read, text);
            }
        }
    }
}
