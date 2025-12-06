use anyhow::{Result, bail};
use regex::Regex;

use crate::diff::unified_diff;

#[derive(Clone)]
pub struct FileEdit {
    pub old_text: String,
    pub new_text: String,
    /// Use regex pattern instead of literal text
    pub is_regex: bool,
    /// Replace all occurrences instead of just first
    pub replace_all: bool,
}

pub fn apply_edits(content: &str, edits: &[FileEdit]) -> Result<(String, String)> {
    let mut modified = normalize_newlines(content);

    for edit in edits {
        let old = normalize_newlines(&edit.old_text);
        let new = normalize_newlines(&edit.new_text);

        // Regex mode: use pattern matching
        if edit.is_regex {
            let re = Regex::new(&old)
                .map_err(|e| anyhow::anyhow!("Invalid regex pattern '{}': {}", old, e))?;

            if !re.is_match(&modified) {
                // No match found - skip silently for bulk operations
                // (individual file edits will still show 0 modifications)
                continue;
            }

            if edit.replace_all {
                modified = re.replace_all(&modified, new.as_str()).to_string();
            } else {
                modified = re.replace(&modified, new.as_str()).to_string();
            }
            continue;
        }

        // Literal mode with replace_all
        if edit.replace_all {
            if modified.contains(&old) {
                modified = modified.replace(&old, &new);
                continue;
            }
            // Fall through to whitespace-tolerant match
        } else {
            // Original behavior: replace first occurrence
            if let Some(pos) = modified.find(&old) {
                modified.replace_range(pos..pos + old.len(), &new);
                continue;
            }
        }

        // Fallback: whitespace-tolerant line match (only for single replacement)
        if !edit.replace_all {
            let old_lines: Vec<_> = old.lines().collect();
            let mut lines: Vec<String> = modified.lines().map(|s| s.to_string()).collect();
            let mut matched = false;
            for i in 0..=lines.len().saturating_sub(old_lines.len()) {
                let window = &lines[i..i + old_lines.len()];
                let same = window
                    .iter()
                    .zip(&old_lines)
                    .all(|(a, b)| a.trim() == b.trim());
                if same {
                    lines.splice(i..i + old_lines.len(), new.lines().map(|s| s.to_string()));
                    modified = lines.join("\n");
                    matched = true;
                    break;
                }
            }
            if matched {
                continue;
            }
        }

        // No match found
        let preview = if edit.old_text.len() > 200 {
            format!("{}... ({} chars total)", &edit.old_text[..200], edit.old_text.len())
        } else {
            edit.old_text.clone()
        };

        bail!(
            "Text not found in file. The 'oldText' parameter does not match any content.\n\
            \n\
            Searched for:\n{}\n\
            \n\
            This usually means:\n\
            1. The file was modified by a previous edit in this operation\n\
            2. Whitespace/indentation doesn't match exactly\n\
            3. The text has been changed since you last read the file\n\
            \n\
            Solution: Re-read the file to get current content, then retry the edit with exact text.",
            preview
        );
    }

    let diff = unified_diff(&normalize_newlines(content), &modified, "file")?;
    Ok((modified, diff))
}

fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n")
}
