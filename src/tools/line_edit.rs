use anyhow::{Context, Result, bail};

use crate::tools::diff::unified_diff;
use crate::tools::fs_ops::normalize_line_endings;

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

/// Inclusive 1-indexed line span an edit claims in *original* file coordinates.
fn edit_span(edit: &LineEdit) -> (usize, usize) {
    let start = edit.start_line;
    let end = match edit.operation {
        // Inserts touch a single anchor line in original coordinates.
        LineOperation::InsertBefore => start,
        LineOperation::InsertAfter => edit.end_line.unwrap_or(start),
        LineOperation::Replace | LineOperation::Delete => edit.end_line.unwrap_or(start),
    };
    (start, end)
}

fn spans_overlap(a: (usize, usize), b: (usize, usize)) -> bool {
    a.0 <= b.1 && b.0 <= a.1
}

/// Reject overlapping edits up front. Without this, descending application can
/// shrink the file and surface a confusing "out of range" on the lower edit.
fn reject_overlapping_edits(edits: &[LineEdit]) -> Result<()> {
    for i in 0..edits.len() {
        let a = edit_span(&edits[i]);
        if a.0 == 0 || a.1 == 0 {
            // start/end == 0 is validated later with a clearer message
            continue;
        }
        if a.0 > a.1 {
            bail!(
                "Invalid range: start line {} is after end line {}",
                a.0,
                a.1
            );
        }
        for other in &edits[i + 1..] {
            let b = edit_span(other);
            if b.0 == 0 || b.1 == 0 {
                continue;
            }
            if spans_overlap(a, b) {
                bail!(
                    "Overlapping edits: edit A lines {}-{} overlaps edit B lines {}-{}. \
                     Use non-overlapping ranges (original line numbers); apply sequential \
                     calls if you need dependent edits.",
                    a.0,
                    a.1,
                    b.0,
                    b.1
                );
            }
        }
    }
    Ok(())
}

/// Apply line-based edits to file content
pub fn apply_line_edits(content: &str, edits: &[LineEdit]) -> Result<(String, String)> {
    let original = normalize_line_endings(content);

    // Track if original content ends with newline
    let had_trailing_newline = original.ends_with('\n');

    let mut lines: Vec<String> = original.lines().map(|s| s.to_string()).collect();
    let original_lines = lines.clone();

    reject_overlapping_edits(edits)?;

    // Sort edits by line number (descending) to avoid line number shifts
    let mut sorted_edits = edits.to_vec();
    sorted_edits.sort_by_key(|e| std::cmp::Reverse(e.start_line));

    for edit in sorted_edits {
        if edit.start_line == 0 {
            bail!("Line number must be >= 1 (got 0)");
        }
        if edit.end_line == Some(0) {
            bail!("End line number must be >= 1 (got 0)");
        }
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
                let text = edit
                    .text
                    .as_ref()
                    .context("Replace operation requires text")?;
                let new_lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
                lines.splice(start_idx..=end_idx, new_lines);
            }
            LineOperation::InsertBefore => {
                let text = edit
                    .text
                    .as_ref()
                    .context("InsertBefore operation requires text")?;
                let new_lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
                lines.splice(start_idx..start_idx, new_lines);
            }
            LineOperation::InsertAfter => {
                let text = edit
                    .text
                    .as_ref()
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

    /// Documented expand behavior: replace without end_line splices onto ONE line
    /// and leaves the following original lines in place. Valid when expanding a
    /// single line; mangled when the caller *meant* a range but dropped end_line
    /// (fixed at the serde layer via `alias = "end_line"`).
    #[test]
    fn replace_multiline_without_end_line_expands_single_line() {
        let content = concat!(
            "def alpha():
",
            "    pass
",
            "
",
            "def beta():
",
            "    old1
",
            "    old2
",
            "    old3
",
        );
        // Agent meant to replace beta() body (lines 4-7) but end_line was dropped.
        let edits = vec![LineEdit {
            start_line: 4,
            end_line: None,
            operation: LineOperation::Replace,
            text: Some(
                "def beta():
    new1
    new2
    new3"
                    .to_string(),
            ),
        }];
        let (result, _) = apply_line_edits(content, &edits).unwrap();
        assert_eq!(
            result,
            concat!(
                "def alpha():
",
                "    pass
",
                "
",
                "def beta():
",
                "    new1
",
                "    new2
",
                "    new3
",
                "    old1
",
                "    old2
",
                "    old3
",
            ),
            "single-line replace + multi-line text must leave old tail",
        );
    }

    /// Correct end_line removes the whole range.
    #[test]
    fn replace_range_with_end_line() {
        let content = concat!(
            "def alpha():
",
            "    pass
",
            "
",
            "def beta():
",
            "    old1
",
            "    old2
",
            "    old3
",
        );
        let edits = vec![LineEdit {
            start_line: 4,
            end_line: Some(7),
            operation: LineOperation::Replace,
            text: Some(
                "def beta():
    new1
    new2
    new3"
                    .to_string(),
            ),
        }];
        let (result, _) = apply_line_edits(content, &edits).unwrap();
        assert_eq!(
            result,
            concat!(
                "def alpha():
",
                "    pass
",
                "
",
                "def beta():
",
                "    new1
",
                "    new2
",
                "    new3
",
            ),
        );
    }

    /// Two non-overlapping edits use original line numbers when sorted descending.
    #[test]
    fn multi_edit_original_line_numbers() {
        let content = "L1
L2
L3
L4
L5
";
        let edits = vec![
            LineEdit {
                start_line: 2,
                end_line: Some(2),
                operation: LineOperation::Replace,
                text: Some(
                    "A
B
C"
                    .to_string(),
                ), // expands 1 line -> 3
            },
            LineEdit {
                start_line: 4,
                end_line: Some(5),
                operation: LineOperation::Replace,
                text: Some("X".to_string()),
            },
        ];
        let (result, _) = apply_line_edits(content, &edits).unwrap();
        // Apply high range first: L4-L5 -> X, then L2 -> A/B/C
        assert_eq!(
            result,
            "L1
A
B
C
L3
X
"
        );
    }

    /// Overlapping ranges are rejected up front (not after a confusing shrink).
    #[test]
    fn overlapping_ranges_rejected_upfront() {
        let content = "L1
L2
L3
L4
";
        let edits = vec![
            LineEdit {
                start_line: 1,
                end_line: Some(3),
                operation: LineOperation::Replace,
                text: Some("AAA".to_string()),
            },
            LineEdit {
                start_line: 2,
                end_line: Some(4),
                operation: LineOperation::Replace,
                text: Some("BBB".to_string()),
            },
        ];
        let err = apply_line_edits(content, &edits).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("Overlapping edits"),
            "expected upfront overlap rejection, got: {msg}"
        );
    }
}
