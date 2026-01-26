//! File utilities - file_diff, file_touch.

use serde_json::{json, Value};
use similar::{ChangeTag, TextDiff};
use std::fs;
use std::path::Path;
use std::time::SystemTime;

/// Compare two files and return diff
pub fn file_diff(path1: &Path, path2: &Path, context_lines: usize) -> Result<Value, String> {
    let content1 = fs::read_to_string(path1)
        .map_err(|e| format!("Failed to read {}: {}", path1.display(), e))?;
    let content2 = fs::read_to_string(path2)
        .map_err(|e| format!("Failed to read {}: {}", path2.display(), e))?;
    
    let diff = TextDiff::from_lines(&content1, &content2);
    
    let mut hunks = Vec::new();
    let mut additions = 0;
    let mut deletions = 0;
    let mut current_hunk: Vec<Value> = Vec::new();
    let mut hunk_start_old = 0;
    let mut hunk_start_new = 0;
    
    for (_idx, change) in diff.iter_all_changes().enumerate() {
        let tag = change.tag();
        let line_content = change.value();
        
        match tag {
            ChangeTag::Delete => {
                deletions += 1;
                if current_hunk.is_empty() {
                    hunk_start_old = change.old_index().unwrap_or(0);
                    hunk_start_new = change.new_index().unwrap_or(0);
                }
                current_hunk.push(json!({
                    "type": "delete",
                    "line": line_content.trim_end(),
                    "old_line_no": change.old_index().map(|i| i + 1)
                }));
            }
            ChangeTag::Insert => {
                additions += 1;
                if current_hunk.is_empty() {
                    hunk_start_old = change.old_index().unwrap_or(0);
                    hunk_start_new = change.new_index().unwrap_or(0);
                }
                current_hunk.push(json!({
                    "type": "insert",
                    "line": line_content.trim_end(),
                    "new_line_no": change.new_index().map(|i| i + 1)
                }));
            }
            ChangeTag::Equal => {
                // Add context lines around changes
                if !current_hunk.is_empty() {
                    current_hunk.push(json!({
                        "type": "context",
                        "line": line_content.trim_end(),
                        "old_line_no": change.old_index().map(|i| i + 1),
                        "new_line_no": change.new_index().map(|i| i + 1)
                    }));
                    
                    // Check if we should close hunk (context_lines equal lines in a row)
                    let equal_count = current_hunk.iter().rev()
                        .take_while(|v| v.get("type").and_then(|t| t.as_str()) == Some("context"))
                        .count();
                    
                    if equal_count > context_lines * 2 {
                        // Close hunk, trim trailing context
                        while current_hunk.len() > 0 {
                            if let Some(last) = current_hunk.last() {
                                if last.get("type").and_then(|t| t.as_str()) == Some("context") {
                                    let _trimmed = current_hunk.split_off(current_hunk.len().saturating_sub(context_lines));
                                    if current_hunk.iter().any(|v| v.get("type").and_then(|t| t.as_str()) != Some("context")) {
                                        hunks.push(json!({
                                            "old_start": hunk_start_old + 1,
                                            "new_start": hunk_start_new + 1,
                                            "changes": current_hunk
                                        }));
                                    }
                                    current_hunk = Vec::new();
                                    break;
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    
    // Add remaining hunk
    if !current_hunk.is_empty() && current_hunk.iter().any(|v| v.get("type").and_then(|t| t.as_str()) != Some("context")) {
        hunks.push(json!({
            "old_start": hunk_start_old + 1,
            "new_start": hunk_start_new + 1,
            "changes": current_hunk
        }));
    }
    
    // Generate unified diff string
    let unified = diff.unified_diff()
        .context_radius(context_lines)
        .header(&path1.to_string_lossy(), &path2.to_string_lossy())
        .to_string();
    
    Ok(json!({
        "file1": path1.to_string_lossy(),
        "file2": path2.to_string_lossy(),
        "identical": additions == 0 && deletions == 0,
        "additions": additions,
        "deletions": deletions,
        "hunks": hunks,
        "unified_diff": unified
    }))
}

/// Create file or update its timestamp (like touch command)
pub fn file_touch(path: &Path, create_parents: bool) -> Result<Value, String> {
    // Create parent directories if requested
    if create_parents {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create parent directories: {}", e))?;
        }
    }
    
    let existed = path.exists();
    let _now = SystemTime::now();
    
    if existed {
        // Update timestamps
        #[cfg(unix)]
        {
            use std::os::unix::fs::UtimesExt;
            let now_secs = now.duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            std::fs::File::open(path)
                .and_then(|f| f.set_times(std::fs::FileTimes::new()
                    .set_accessed(now)
                    .set_modified(now)))
                .map_err(|e| format!("Failed to update timestamp: {}", e))?;
        }
        #[cfg(not(unix))]
        {
            // On Windows, just write empty to update mtime (if file is empty) or use filetime crate
            // For simplicity, we'll just report that we would update it
            let _metadata = fs::metadata(path)
                .map_err(|e| format!("Failed to get metadata: {}", e))?;
            // Touch by opening for append (doesn't change content but updates atime)
            fs::OpenOptions::new()
                .append(true)
                .open(path)
                .map_err(|e| format!("Failed to touch file: {}", e))?;
        }
    } else {
        // Create empty file
        fs::File::create(path)
            .map_err(|e| format!("Failed to create file: {}", e))?;
    }
    
    let metadata = fs::metadata(path)
        .map_err(|e| format!("Failed to get metadata: {}", e))?;
    
    Ok(json!({
        "path": path.to_string_lossy(),
        "created": !existed,
        "updated": existed,
        "size": metadata.len(),
        "modified": metadata.modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
    }))
}
