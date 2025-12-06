use anyhow::{Result, bail, Context};

use crate::diff::unified_diff;

/// Line-based edit operation
#[derive(Debug, Clone)]
pub enum LineOperation {
    /// Replace line(s) with new text
    Replace,
    /// Insert text before line
    InsertBefore,
    /// Insert text after line
    InsertAfter,
    /// Delete line(s)
    Delete,
}

/// Single line edit instruction
#[derive(Debug, Clone)]
pub struct LineEdit {
    /// Start line number (1-indexed)
    pub start_line: usize,
    /// End line number (1-indexed, inclusive). If None, operates on single line
    pub end_line: Option<usize>,
    /// Operation to perform
    pub operation: LineOperation,
    /// New text content (for replace/insert operations)
    pub text: Option<String>,
}

/// Apply line-based edits to file content
pub fn apply_line_edits(content: &str, edits: &[LineEdit]) -> Result<(String, String)> {
    let original = normalize_newlines(content);

    // Track if original content ends with newline
    let had_trailing_newline = original.ends_with('\n');

    let mut lines: Vec<String> = original.lines().map(|s| s.to_string()).collect();
    let original_lines = lines.clone();

    // Sort edits by line number (descending) to avoid line number shifts
    let mut sorted_edits = edits.to_vec();
    sorted_edits.sort_by(|a, b| b.start_line.cmp(&a.start_line));

    for edit in sorted_edits {
        // Note: caller must validate that start_line >= 1 before calling
        let start_idx = edit.start_line - 1; // Convert to 0-indexed
        let end_idx = edit.end_line.map(|e| e - 1).unwrap_or(start_idx);

        // Validate line numbers
        if start_idx >= lines.len() {
            bail!(
                "Line {} is out of range (file has {} lines)",
                edit.start_line,
                lines.len()
            );
        }
        if end_idx >= lines.len() {
            bail!(
                "Line {} is out of range (file has {} lines)",
                end_idx + 1,
                lines.len()
            );
        }
        if start_idx > end_idx {
            bail!(
                "Invalid range: start line {} is after end line {}",
                edit.start_line,
                end_idx + 1
            );
        }

        match edit.operation {
            LineOperation::Replace => {
                let text = edit.text.as_ref()
                    .context("Replace operation requires text")?;
                let new_lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
                lines.splice(start_idx..=end_idx, new_lines);
            }
            LineOperation::InsertBefore => {
                let text = edit.text.as_ref()
                    .context("InsertBefore operation requires text")?;
                let new_lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
                lines.splice(start_idx..start_idx, new_lines);
            }
            LineOperation::InsertAfter => {
                let text = edit.text.as_ref()
                    .context("InsertAfter operation requires text")?;
                let new_lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
                lines.splice(end_idx + 1..end_idx + 1, new_lines);
            }
            LineOperation::Delete => {
                lines.splice(start_idx..=end_idx, std::iter::empty());
            }
        }
    }

    let mut modified = lines.join("\n");

    // Preserve trailing newline if original had one
    if had_trailing_newline && !modified.is_empty() {
        modified.push('\n');
    }

    let mut original_text = original_lines.join("\n");
    if had_trailing_newline && !original_text.is_empty() {
        original_text.push('\n');
    }

    let diff = unified_diff(&original_text, &modified, "file")?;

    Ok((modified, diff))
}

fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_single_line() {
        // Input has trailing newline, output should preserve it
        let content = "line 1\nline 2\nline 3\n";
        let edits = vec![LineEdit {
            start_line: 2,
            end_line: None,
            operation: LineOperation::Replace,
            text: Some("NEW LINE 2".to_string()),
        }];
        let (result, _) = apply_line_edits(content, &edits).unwrap();
        assert_eq!(result, "line 1\nNEW LINE 2\nline 3\n");
    }

    #[test]
    fn test_delete_range() {
        // Input has trailing newline, output should preserve it
        let content = "line 1\nline 2\nline 3\nline 4\n";
        let edits = vec![LineEdit {
            start_line: 2,
            end_line: Some(3),
            operation: LineOperation::Delete,
            text: None,
        }];
        let (result, _) = apply_line_edits(content, &edits).unwrap();
        assert_eq!(result, "line 1\nline 4\n");
    }

    #[test]
    fn test_insert_before() {
        // Input has trailing newline, output should preserve it
        let content = "line 1\nline 2\n";
        let edits = vec![LineEdit {
            start_line: 2,
            end_line: None,
            operation: LineOperation::InsertBefore,
            text: Some("inserted".to_string()),
        }];
        let (result, _) = apply_line_edits(content, &edits).unwrap();
        assert_eq!(result, "line 1\ninserted\nline 2\n");
    }

    #[test]
    fn test_insert_after() {
        // Input has trailing newline, output should preserve it
        let content = "line 1\nline 2\n";
        let edits = vec![LineEdit {
            start_line: 1,
            end_line: None,
            operation: LineOperation::InsertAfter,
            text: Some("inserted".to_string()),
        }];
        let (result, _) = apply_line_edits(content, &edits).unwrap();
        assert_eq!(result, "line 1\ninserted\nline 2\n");
    }

    #[test]
    fn test_multiple_edits() {
        // Input has trailing newline, output should preserve it
        let content = "line 1\nline 2\nline 3\nline 4\n";
        let edits = vec![
            LineEdit {
                start_line: 2,
                end_line: None,
                operation: LineOperation::Replace,
                text: Some("REPLACED 2".to_string()),
            },
            LineEdit {
                start_line: 4,
                end_line: None,
                operation: LineOperation::Delete,
                text: None,
            },
        ];
        let (result, _) = apply_line_edits(content, &edits).unwrap();
        assert_eq!(result, "line 1\nREPLACED 2\nline 3\n");
    }

    // Regression tests: trailing newline must be preserved (fixed in previous session)

    #[test]
    fn test_trailing_newline_preserved_on_replace() {
        // File with trailing newline
        let content = "line 1\nline 2\nline 3\n";
        let edits = vec![LineEdit {
            start_line: 2,
            end_line: None,
            operation: LineOperation::Replace,
            text: Some("NEW LINE 2".to_string()),
        }];

        let (result, _) = apply_line_edits(content, &edits).unwrap();

        // BUG: Currently returns "line 1\nNEW LINE 2\nline 3" (no trailing \n)
        assert!(
            result.ends_with('\n'),
            "Trailing newline should be preserved. Got: {:?}",
            result
        );
        assert_eq!(result, "line 1\nNEW LINE 2\nline 3\n");
    }

    #[test]
    fn test_no_trailing_newline_stays_without() {
        // File WITHOUT trailing newline should stay that way
        let content = "line 1\nline 2\nline 3";
        let edits = vec![LineEdit {
            start_line: 2,
            end_line: None,
            operation: LineOperation::Replace,
            text: Some("NEW LINE 2".to_string()),
        }];

        let (result, _) = apply_line_edits(content, &edits).unwrap();

        assert!(
            !result.ends_with('\n'),
            "No trailing newline should remain absent. Got: {:?}",
            result
        );
        assert_eq!(result, "line 1\nNEW LINE 2\nline 3");
    }

    #[test]
    fn test_trailing_newline_preserved_on_delete() {
        let content = "line 1\nline 2\nline 3\n";
        let edits = vec![LineEdit {
            start_line: 2,
            end_line: None,
            operation: LineOperation::Delete,
            text: None,
        }];

        let (result, _) = apply_line_edits(content, &edits).unwrap();

        assert!(
            result.ends_with('\n'),
            "Trailing newline should be preserved after delete"
        );
        assert_eq!(result, "line 1\nline 3\n");
    }

    #[test]
    fn test_trailing_newline_preserved_on_insert() {
        let content = "line 1\nline 2\n";
        let edits = vec![LineEdit {
            start_line: 1,
            end_line: None,
            operation: LineOperation::InsertAfter,
            text: Some("inserted".to_string()),
        }];

        let (result, _) = apply_line_edits(content, &edits).unwrap();

        assert!(
            result.ends_with('\n'),
            "Trailing newline should be preserved after insert"
        );
        assert_eq!(result, "line 1\ninserted\nline 2\n");
    }
}
