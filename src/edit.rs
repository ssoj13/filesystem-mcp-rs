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
                // No match found - error out like literal mode does
                let preview = if edit.old_text.len() > 200 {
                    format!("{}... ({} chars total)", &edit.old_text[..200], edit.old_text.len())
                } else {
                    edit.old_text.clone()
                };
                bail!(
                    "Regex pattern not found in file.\n\
                    \n\
                    Pattern: {}\n\
                    \n\
                    This usually means the pattern doesn't match any content in the file.",
                    preview
                );
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

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // BUG TEST: Regex mode silently skips non-matching patterns
    // Expected: Should return error when regex doesn't match (like literal mode)
    // Current: Silently continues, returns unchanged content with empty diff
    // ==========================================================================

    #[test]
    fn test_regex_no_match_should_error() {
        let content = "hello world";
        let edits = vec![FileEdit {
            old_text: "nonexistent_pattern".to_string(),
            new_text: "replacement".to_string(),
            is_regex: true,
            replace_all: false,
        }];

        // BUG: Currently this succeeds with no changes instead of erroring
        let result = apply_edits(content, &edits);

        // This test will FAIL until bug is fixed
        // Regex mode should error on no match, just like literal mode does
        assert!(result.is_err(), "Regex with no match should return error, not silently succeed");
    }

    #[test]
    fn test_regex_no_match_replace_all_should_error() {
        let content = "hello world";
        let edits = vec![FileEdit {
            old_text: r"\d+".to_string(), // No digits in content
            new_text: "NUMBER".to_string(),
            is_regex: true,
            replace_all: true,
        }];

        let result = apply_edits(content, &edits);

        // Should error, not silently skip
        assert!(result.is_err(), "Regex replace_all with no match should return error");
    }

    #[test]
    fn test_literal_no_match_errors() {
        // Verify literal mode DOES error (this should pass - it's the correct behavior)
        let content = "hello world";
        let edits = vec![FileEdit {
            old_text: "nonexistent".to_string(),
            new_text: "replacement".to_string(),
            is_regex: false,
            replace_all: false,
        }];

        let result = apply_edits(content, &edits);
        assert!(result.is_err(), "Literal mode with no match should error");
    }

    #[test]
    fn test_regex_match_succeeds() {
        // Verify regex works when it DOES match
        let content = "hello 123 world";
        let edits = vec![FileEdit {
            old_text: r"\d+".to_string(),
            new_text: "NUMBER".to_string(),
            is_regex: true,
            replace_all: false,
        }];

        let result = apply_edits(content, &edits);
        assert!(result.is_ok());
        let (modified, _) = result.unwrap();
        assert_eq!(modified, "hello NUMBER world");
    }
}
