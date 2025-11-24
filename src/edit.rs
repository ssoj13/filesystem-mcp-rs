use anyhow::{Result, bail};

use crate::diff::unified_diff;

#[derive(Clone)]
pub struct FileEdit {
    pub old_text: String,
    pub new_text: String,
}

pub fn apply_edits(content: &str, edits: &[FileEdit]) -> Result<(String, String)> {
    let mut modified = normalize_newlines(content);

    for edit in edits {
        let old = normalize_newlines(&edit.old_text);
        let new = normalize_newlines(&edit.new_text);

        if let Some(pos) = modified.find(&old) {
            modified.replace_range(pos..pos + old.len(), &new);
            continue;
        }

        // Fallback: whitespace-tolerant line match
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

        if !matched {
            bail!("Could not find exact match for edit:\n{}", edit.old_text);
        }
    }

    let diff = unified_diff(&normalize_newlines(content), &modified, "file")?;
    Ok((modified, diff))
}

fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n")
}
