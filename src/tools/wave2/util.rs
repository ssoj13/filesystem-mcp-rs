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
