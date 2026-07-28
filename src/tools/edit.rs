use anyhow::{Result, bail};
use regex::Regex;

use crate::tools::diff::unified_diff;
use crate::tools::fs_ops::normalize_line_endings;

/// Truncate string to max chars safely (Unicode-aware, no panic on multi-byte)
fn truncate_preview(s: &str, max_chars: usize) -> String {
    let char_count = s.chars().count();
    if char_count > max_chars {
        let truncated: String = s.chars().take(max_chars).collect();
        format!("{}... ({} chars total)", truncated, char_count)
    } else {
        s.to_string()
    }
}

#[derive(Clone)]
pub struct FileEdit {
    pub old_text: String,
    pub new_text: String,
    /// Use regex pattern instead of literal text
    pub is_regex: bool,
    /// Replace all occurrences instead of just first
    pub replace_all: bool,
}

/// Which regex engine to use for `is_regex` edits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EditEngine {
    /// Default. Linear-time `regex` crate. No look-around or backrefs.
    #[default]
    Regex,
    /// Backtracking `fancy_regex`. Supports look-around, backrefs.
    /// Catastrophic worst-case on patho. patterns — opt-in only.
    Fancy,
}

/// Aggregate outcome of applying a batch of edits to a single file.
#[derive(Debug, Clone)]
pub struct EditOutcome {
    pub modified: String,
    pub diff: String,
    /// Match count per edit (index-aligned with input `edits`). For literal /
    /// `replace_all=false`, max is 1.
    pub matches_per_edit: Vec<usize>,
    /// How many of each edit's matches survived overlap resolution.
    pub applied_per_edit: Vec<usize>,
}

/// Resolved replacement on the *original* content. Used by snapshot semantics
/// so cascading bulk edits with overlapping patterns (BUG #1) cannot duplicate
/// inserted text.
struct Replacement {
    start: usize,
    end: usize,
    new_text: String,
    edit_index: usize,
}

pub fn apply_edits(content: &str, edits: &[FileEdit]) -> Result<EditOutcome> {
    apply_edits_with_mode(content, edits, true, EditEngine::Regex)
}

/// Apply all edits to a frozen snapshot of `content`.
///
/// Each edit's matches are collected against the ORIGINAL content; overlapping
/// matches are resolved by: (1) longest span wins, (2) earlier-declared edit
/// wins on ties. This prevents cascading duplicates when a shorter `old_text`
/// is a substring of a longer `old_text` (the wgpu migration case).
pub fn apply_edits_with_mode(
    content: &str,
    edits: &[FileEdit],
    fail_on_no_match: bool,
    engine: EditEngine,
) -> Result<EditOutcome> {
    let original = normalize_line_endings(content);

    let mut replacements: Vec<Replacement> = Vec::new();
    let mut matches_per_edit = vec![0usize; edits.len()];

    for (idx, edit) in edits.iter().enumerate() {
        let old = normalize_line_endings(&edit.old_text);
        let new = normalize_line_endings(&edit.new_text);

        if edit.is_regex {
            let found = match engine {
                EditEngine::Regex => collect_regex_matches(idx, &old, &new, &original, edit.replace_all),
                EditEngine::Fancy => collect_fancy_matches(idx, &old, &new, &original, edit.replace_all),
            }?;
            matches_per_edit[idx] = found.len();
            replacements.extend(found);
            continue;
        }

        // Literal mode.
        if old.is_empty() {
            // Treat empty oldText as no-match (avoids infinite loops / spurious inserts).
            continue;
        }

        if edit.replace_all {
            let mut cursor = 0;
            while let Some(rel) = original[cursor..].find(&old) {
                let abs = cursor + rel;
                replacements.push(Replacement {
                    start: abs,
                    end: abs + old.len(),
                    new_text: new.clone(),
                    edit_index: idx,
                });
                matches_per_edit[idx] += 1;
                cursor = abs + old.len();
            }
        } else if let Some(pos) = original.find(&old) {
            replacements.push(Replacement {
                start: pos,
                end: pos + old.len(),
                new_text: new,
                edit_index: idx,
            });
            matches_per_edit[idx] = 1;
        } else if let Some(span) = whitespace_tolerant_match(&original, &old) {
            // Whitespace-tolerant fallback for single literal edits only.
            replacements.push(Replacement {
                start: span.0,
                end: span.1,
                new_text: new,
                edit_index: idx,
            });
            matches_per_edit[idx] = 1;
        }
    }

    // Aggregate fail_on_no_match: list ALL edits that produced zero matches.
    let unmatched: Vec<usize> = matches_per_edit
        .iter()
        .enumerate()
        .filter_map(|(i, &n)| if n == 0 { Some(i) } else { None })
        .collect();

    if !unmatched.is_empty() && fail_on_no_match {
        let mut lines = Vec::new();
        lines.push(format!(
            "{} of {} edits produced zero matches:",
            unmatched.len(),
            edits.len()
        ));
        for &i in &unmatched {
            let preview = truncate_preview(&edits[i].old_text, 120);
            let kind = if edits[i].is_regex { "regex" } else { "literal" };
            lines.push(format!("  edit #{} ({kind}): {}", i + 1, preview));
        }
        lines.push(String::new());
        lines.push(
            "Hints: re-read the file to verify current content; check for indentation drift; \
             or set failOnNoMatch=false to tolerate misses."
                .to_string(),
        );
        bail!(lines.join("\n"));
    }

    // Sort by (start ASC, length DESC) so earlier + longer wins on overlap.
    replacements.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
            .then_with(|| a.edit_index.cmp(&b.edit_index))
    });

    // Greedy non-overlap selection.
    let mut applied_per_edit = vec![0usize; edits.len()];
    let mut accepted: Vec<Replacement> = Vec::with_capacity(replacements.len());
    let mut last_end = 0usize;
    for r in replacements {
        if r.start < last_end {
            continue;
        }
        last_end = r.end;
        applied_per_edit[r.edit_index] += 1;
        accepted.push(r);
    }

    // Apply accepted replacements left-to-right.
    let mut modified = String::with_capacity(original.len());
    let mut cursor = 0usize;
    for r in &accepted {
        modified.push_str(&original[cursor..r.start]);
        modified.push_str(&r.new_text);
        cursor = r.end;
    }
    modified.push_str(&original[cursor..]);

    let diff = unified_diff(&original, &modified, "file")?;
    Ok(EditOutcome {
        modified,
        diff,
        matches_per_edit,
        applied_per_edit,
    })
}

fn collect_regex_matches(
    edit_index: usize,
    pattern: &str,
    replacement: &str,
    original: &str,
    replace_all: bool,
) -> Result<Vec<Replacement>> {
    let re = Regex::new(pattern)
        .map_err(|e| anyhow::anyhow!("Invalid regex pattern '{}': {}", pattern, e))?;
    let mut out = Vec::new();
    if replace_all {
        for caps in re.captures_iter(original) {
            let m = caps.get(0).unwrap();
            let mut expanded = String::new();
            caps.expand(replacement, &mut expanded);
            out.push(Replacement {
                start: m.start(),
                end: m.end(),
                new_text: expanded,
                edit_index,
            });
        }
    } else if let Some(caps) = re.captures(original) {
        let m = caps.get(0).unwrap();
        let mut expanded = String::new();
        caps.expand(replacement, &mut expanded);
        out.push(Replacement {
            start: m.start(),
            end: m.end(),
            new_text: expanded,
            edit_index,
        });
    }
    Ok(out)
}

fn collect_fancy_matches(
    edit_index: usize,
    pattern: &str,
    replacement: &str,
    original: &str,
    replace_all: bool,
) -> Result<Vec<Replacement>> {
    let re = fancy_regex::Regex::new(pattern)
        .map_err(|e| anyhow::anyhow!("Invalid fancy-regex pattern '{}': {}", pattern, e))?;
    let mut out = Vec::new();
    if replace_all {
        let mut cursor = 0usize;
        loop {
            match re.captures_from_pos(original, cursor) {
                Ok(Some(caps)) => {
                    let m = caps.get(0).unwrap();
                    let expanded = expand_fancy(&caps, replacement);
                    let (start, end) = (m.start(), m.end());
                    out.push(Replacement {
                        start,
                        end,
                        new_text: expanded,
                        edit_index,
                    });
                    // Zero-width match: advance past exactly one full character
                    // (never a raw `+1`, which can land mid-codepoint and split UTF-8).
                    if end == start {
                        match original[end..].chars().next() {
                            Some(ch) => cursor = end + ch.len_utf8(),
                            None => break, // at end of input
                        }
                    } else {
                        cursor = end;
                    }
                    if cursor > original.len() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => bail!("fancy-regex error: {e}"),
            }
        }
    } else {
        match re.captures(original) {
            Ok(Some(caps)) => {
                let m = caps.get(0).unwrap();
                let expanded = expand_fancy(&caps, replacement);
                out.push(Replacement {
                    start: m.start(),
                    end: m.end(),
                    new_text: expanded,
                    edit_index,
                });
            }
            Ok(None) => {}
            Err(e) => bail!("fancy-regex error: {e}"),
        }
    }
    Ok(out)
}

/// Hand-rolled `$N` / `${name}` expansion for fancy_regex (its `Captures::expand`
/// signature differs across versions; this avoids the version pin).
///
/// Iterates over `char`s, not bytes: every `$`-escape token is pure ASCII, while
/// literal text between tokens may be any UTF-8 (Cyrillic, emoji, ...). A previous
/// byte-wise version pushed `byte as char`, i.e. Latin-1, which mangled every
/// non-ASCII replacement into mojibake.
fn expand_fancy(caps: &fancy_regex::Captures<'_>, template: &str) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            // Trailing `$` at end of template -> literal `$`.
            None => out.push('$'),
            // `$$` -> literal `$`.
            Some('$') => {
                chars.next();
                out.push('$');
            }
            // Named: `${name}`.
            Some('{') => {
                chars.next(); // consume `{`
                let mut name = String::new();
                let mut closed = false;
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc == '}' {
                        closed = true;
                        break;
                    }
                    name.push(nc);
                }
                if closed {
                    if let Some(m) = caps.name(&name) {
                        out.push_str(m.as_str());
                    }
                } else {
                    // Unterminated `${...` -> emit verbatim.
                    out.push('$');
                    out.push('{');
                    out.push_str(&name);
                }
            }
            // Numeric: `$1`, `$12`, ...
            Some(d) if d.is_ascii_digit() => {
                let mut num = 0usize;
                while let Some(&nc) = chars.peek() {
                    match nc.to_digit(10) {
                        Some(dig) => {
                            num = num.saturating_mul(10).saturating_add(dig as usize);
                            chars.next();
                        }
                        None => break,
                    }
                }
                if let Some(m) = caps.get(num) {
                    out.push_str(m.as_str());
                }
            }
            // `$` followed by anything else -> literal `$`, the char is handled next.
            Some(_) => out.push('$'),
        }
    }
    out
}

/// Find a window of consecutive lines where `target.lines().count()` lines
/// match `target.lines()` ignoring leading/trailing whitespace per line.
/// Returns byte span in the original content.
fn whitespace_tolerant_match(original: &str, target: &str) -> Option<(usize, usize)> {
    let target_lines: Vec<&str> = target.lines().collect();
    if target_lines.is_empty() {
        return None;
    }

    let mut line_starts: Vec<usize> = vec![0];
    for (i, b) in original.bytes().enumerate() {
        if b == b'\n' {
            line_starts.push(i + 1);
        }
    }
    let original_lines: Vec<&str> = original.lines().collect();

    if original_lines.len() < target_lines.len() {
        return None;
    }

    for i in 0..=original_lines.len() - target_lines.len() {
        let window = &original_lines[i..i + target_lines.len()];
        let same = window
            .iter()
            .zip(target_lines.iter())
            .all(|(a, b)| a.trim() == b.trim());
        if same {
            let start = line_starts[i];
            let last_line_idx = i + target_lines.len() - 1;
            let end = if last_line_idx + 1 < line_starts.len() {
                line_starts[last_line_idx + 1]
            } else {
                let raw_end = line_starts[last_line_idx] + original_lines[last_line_idx].len();
                if raw_end < original.len() && original.as_bytes()[raw_end] == b'\n' {
                    raw_end + 1
                } else {
                    raw_end
                }
            };
            return Some((start, end));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(content: &str, edits: Vec<FileEdit>) -> Result<EditOutcome> {
        apply_edits(content, &edits)
    }

    #[test]
    fn test_regex_no_match_should_error() {
        let result = run(
            "hello world",
            vec![FileEdit {
                old_text: "nonexistent_pattern".to_string(),
                new_text: "replacement".to_string(),
                is_regex: true,
                replace_all: false,
            }],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_regex_no_match_replace_all_should_error() {
        let result = run(
            "hello world",
            vec![FileEdit {
                old_text: r"\d+".to_string(),
                new_text: "NUMBER".to_string(),
                is_regex: true,
                replace_all: true,
            }],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_literal_no_match_errors() {
        let result = run(
            "hello world",
            vec![FileEdit {
                old_text: "nonexistent".to_string(),
                new_text: "replacement".to_string(),
                is_regex: false,
                replace_all: false,
            }],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_relaxed_no_match_is_ok() {
        let outcome = apply_edits_with_mode(
            "hello world",
            &[FileEdit {
                old_text: "missing".to_string(),
                new_text: "replacement".to_string(),
                is_regex: false,
                replace_all: false,
            }],
            false,
            EditEngine::Regex,
        )
        .unwrap();
        assert_eq!(outcome.modified, "hello world");
        assert_eq!(outcome.matches_per_edit, vec![0]);
    }

    #[test]
    fn test_regex_match_succeeds() {
        let outcome = run(
            "hello 123 world",
            vec![FileEdit {
                old_text: r"\d+".to_string(),
                new_text: "NUMBER".to_string(),
                is_regex: true,
                replace_all: false,
            }],
        )
        .unwrap();
        assert_eq!(outcome.modified, "hello NUMBER world");
    }

    #[test]
    fn test_regex_capture_groups() {
        let outcome = run(
            "use crate::cache_man;\nuse crate::event_bus;\n",
            vec![FileEdit {
                old_text: r"use crate::(cache_man|event_bus)".to_string(),
                new_text: "use crate::core::$1".to_string(),
                is_regex: true,
                replace_all: true,
            }],
        )
        .unwrap();
        assert!(outcome.modified.contains("use crate::core::cache_man"));
        assert!(outcome.modified.contains("use crate::core::event_bus"));
        assert_eq!(outcome.matches_per_edit, vec![2]);
        assert_eq!(outcome.applied_per_edit, vec![2]);
    }

    /// Regression for BUG #1: shorter literal `oldText` that is a substring of
    /// a longer `oldText` must NOT cascade-duplicate the inserted text.
    #[test]
    fn test_overlapping_literal_replace_all_no_cascade() {
        let content = "        occlusion_query_set: None,\n            occlusion_query_set: None,\n                occlusion_query_set: None,\n";

        let edits = vec![
            FileEdit {
                old_text: "        occlusion_query_set: None,\n".into(),
                new_text: "        occlusion_query_set: None,\n        multiview_mask: None,\n"
                    .into(),
                is_regex: false,
                replace_all: true,
            },
            FileEdit {
                old_text: "            occlusion_query_set: None,\n".into(),
                new_text:
                    "            occlusion_query_set: None,\n            multiview_mask: None,\n"
                        .into(),
                is_regex: false,
                replace_all: true,
            },
            FileEdit {
                old_text: "                occlusion_query_set: None,\n".into(),
                new_text: "                occlusion_query_set: None,\n                multiview_mask: None,\n"
                    .into(),
                is_regex: false,
                replace_all: true,
            },
        ];

        let outcome = run(content, edits).unwrap();
        let count_mv = outcome.modified.matches("multiview_mask: None,").count();
        assert_eq!(count_mv, 3, "expected exactly 3 inserts, got\n{}", outcome.modified);
        // Each edit applied at exactly one site.
        assert_eq!(outcome.applied_per_edit, vec![1, 1, 1]);
    }

    #[test]
    fn test_overlapping_regex_longest_wins() {
        let outcome = run(
            "foo bar baz",
            vec![
                FileEdit {
                    old_text: "foo bar".into(),
                    new_text: "A".into(),
                    is_regex: false,
                    replace_all: false,
                },
                FileEdit {
                    old_text: "foo bar baz".into(),
                    new_text: "B".into(),
                    is_regex: false,
                    replace_all: false,
                },
            ],
        )
        .unwrap();
        assert_eq!(outcome.modified, "B");
        assert_eq!(outcome.applied_per_edit, vec![0, 1]);
    }

    #[test]
    fn test_independent_edits_apply_independently() {
        let outcome = run(
            "alpha beta gamma",
            vec![
                FileEdit {
                    old_text: "alpha".into(),
                    new_text: "A".into(),
                    is_regex: false,
                    replace_all: false,
                },
                FileEdit {
                    old_text: "gamma".into(),
                    new_text: "G".into(),
                    is_regex: false,
                    replace_all: false,
                },
            ],
        )
        .unwrap();
        assert_eq!(outcome.modified, "A beta G");
    }

    #[test]
    fn test_whitespace_tolerant_single_edit() {
        let outcome = run(
            "  hello world  \n  goodbye  \n",
            vec![FileEdit {
                old_text: "hello world".into(),
                new_text: "HI".into(),
                is_regex: false,
                replace_all: false,
            }],
        )
        .unwrap();
        assert!(outcome.modified.contains("HI"));
    }

    /// fancy-regex: look-ahead support.
    #[test]
    fn test_fancy_lookahead() {
        let outcome = apply_edits_with_mode(
            "use crate::foo;\nuse crate::bar; // skip\nuse crate::baz;\n",
            &[FileEdit {
                old_text: r"use crate::\w+;(?!\s*//)".to_string(),
                new_text: "use crate::core::REPL;".to_string(),
                is_regex: true,
                replace_all: true,
            }],
            true,
            EditEngine::Fancy,
        )
        .unwrap();
        // foo and baz are replaced, bar (followed by `//`) is NOT.
        assert!(outcome.modified.contains("use crate::core::REPL;"));
        assert!(outcome.modified.contains("use crate::bar;"));
        let replaced_count = outcome.modified.matches("use crate::core::REPL;").count();
        assert_eq!(replaced_count, 2);
    }

    #[test]
    fn test_fancy_cyrillic_replacement_not_mangled() {
        // BH-18a: non-ASCII replacement text under the fancy engine must survive
        // byte-for-byte, not be widened byte-as-Latin-1 into mojibake.
        let outcome = apply_edits_with_mode(
            "greeting = TODO;\n",
            &[FileEdit {
                old_text: "TODO".to_string(),
                new_text: "Привет".to_string(),
                is_regex: true,
                replace_all: true,
            }],
            true,
            EditEngine::Fancy,
        )
        .unwrap();
        assert_eq!(outcome.modified, "greeting = Привет;\n");
    }

    #[test]
    fn test_fancy_capture_group_preserves_unicode() {
        // `$1` expansion must copy the matched Unicode span intact.
        let outcome = apply_edits_with_mode(
            "имя: Алекс\n",
            &[FileEdit {
                old_text: r"имя: (\w+)".to_string(),
                new_text: "name=$1".to_string(),
                is_regex: true,
                replace_all: false,
            }],
            true,
            EditEngine::Fancy,
        )
        .unwrap();
        assert_eq!(outcome.modified, "name=Алекс\n");
    }

    #[test]
    fn test_fancy_zero_width_over_unicode_no_panic() {
        // BH-18b: a zero-width match (lookahead) that advances the cursor over
        // multibyte text must not split a codepoint (would panic on the slice)
        // and must not skip characters.
        let outcome = apply_edits_with_mode(
            "абв\n",
            &[FileEdit {
                // Insert a marker before every char via zero-width lookahead.
                old_text: r"(?=.)".to_string(),
                new_text: "|".to_string(),
                is_regex: true,
                replace_all: true,
            }],
            true,
            EditEngine::Fancy,
        )
        .unwrap();
        // A marker before each of а, б, в (`.` does not match the trailing \n).
        assert_eq!(outcome.modified, "|а|б|в\n");
    }

    #[test]
    fn test_aggregated_no_match_error_lists_all() {
        let result = run(
            "hello world",
            vec![
                FileEdit {
                    old_text: "missing_a".into(),
                    new_text: "x".into(),
                    is_regex: false,
                    replace_all: false,
                },
                FileEdit {
                    old_text: "hello".into(),
                    new_text: "HI".into(),
                    is_regex: false,
                    replace_all: false,
                },
                FileEdit {
                    old_text: "missing_b".into(),
                    new_text: "x".into(),
                    is_regex: false,
                    replace_all: false,
                },
            ],
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("edit #1"), "{err}");
        assert!(err.contains("edit #3"), "{err}");
        assert!(!err.contains("edit #2"), "{err}");
    }
}
