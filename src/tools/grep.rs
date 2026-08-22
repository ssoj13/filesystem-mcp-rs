use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder};
use tokio::fs;

use crate::core::allowed::AllowedDirs;
use crate::core::glob::{build_glob, build_glob_set};
use crate::core::path::resolve_validated_path;
use crate::tools::fs_ops::read_text;

/// Result of a grep match in a file
#[derive(Debug, Clone)]
pub struct GrepMatch {
    /// Path to file containing match
    pub path: PathBuf,
    /// Line number (1-indexed)
    pub line_number: usize,
    /// Matched line content
    pub line: String,
    /// Context lines before match (if requested)
    pub before_context: Vec<String>,
    /// Context lines after match (if requested)
    pub after_context: Vec<String>,
}

/// Grep output mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GrepOutputMode {
    /// Default: return matching lines with content
    #[default]
    ContentBlock,
    /// Only count matches per file
    CountOnly,
    /// Return files that have matches (like grep -l)
    FilesWithMatches,
    /// Return files WITHOUT matches (like grep -L)
    FilesWithoutMatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NearbyDirection {
    Before,
    After,
    #[default]
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NearbyMatchMode {
    #[default]
    Any,
    All,
}

/// Count result per file
#[derive(Debug, Clone)]
pub struct GrepCount {
    pub path: PathBuf,
    pub count: usize,
}

/// Grep search parameters
pub struct GrepParams {
    /// Root directory to search
    pub root: String,
    /// Regex pattern to search for
    pub pattern: String,
    /// Glob pattern for files to include (e.g., "*.rs", "**/*.txt")
    pub file_pattern: Option<String>,
    /// Glob patterns to exclude (e.g., "target/**", "**/*.min.js")
    pub exclude_patterns: Vec<String>,
    /// Case-insensitive search
    pub case_insensitive: bool,
    /// Number of context lines before match
    pub context_before: usize,
    /// Number of context lines after match
    pub context_after: usize,
    /// Maximum number of matches to return (0 = unlimited)
    pub max_matches: usize,
    /// Invert match: show lines NOT matching pattern
    pub invert_match: bool,
    /// Output mode
    pub output_mode: GrepOutputMode,
    /// Allow patterns to span newlines (`\n` in regex). When true, the
    /// searcher reads files whole-buffer instead of line-by-line.
    pub multiline: bool,
    /// Treat `pattern` as a fixed string (no regex parsing). Like `rg -F`.
    pub fixed_strings: bool,
    /// Constrain matches to word boundaries (`\b...\b`). Like `rg -w`.
    pub whole_word: bool,
    /// Maximum recursion depth (0 = unlimited).
    /// (CRLF handling is always enabled — it's safe on all platforms.)
    pub max_depth: usize,
    /// Skip files larger than this size in bytes (0 = no limit).
    pub max_filesize: u64,
    /// Force text encoding for files (e.g. "utf-8", "utf-16", "windows-1251").
    /// `None` = auto-detect via grep-searcher (binary detection still applies).
    pub encoding: Option<String>,
    /// Heap limit in MB for the searcher (0 = no limit). Protects against
    /// huge single-line files in multiline mode.
    pub heap_limit_mb: usize,
    /// Regex engine for the pattern. `Regex` is linear-time; `Fancy` enables
    /// look-around and backreferences at the cost of backtracking.
    pub engine: GrepEngine,
}

/// Regex engine selection for grep tools.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GrepEngine {
    /// Default. `grep-regex` (ripgrep's regex). Linear time, no look-around.
    #[default]
    Regex,
    /// `fancy_regex`. Supports look-around / backreferences.
    Fancy,
}

pub struct GrepContextParams {
    /// Root directory to search
    pub root: String,
    /// Regex pattern to search for
    pub pattern: String,
    /// Glob pattern for files to include (e.g., "*.rs", "**/*.txt")
    pub file_pattern: Option<String>,
    /// Glob patterns to exclude (e.g., "target/**", "**/*.min.js")
    pub exclude_patterns: Vec<String>,
    /// Case-insensitive search
    pub case_insensitive: bool,
    /// Number of context lines before match
    pub context_before: usize,
    /// Number of context lines after match
    pub context_after: usize,
    /// Maximum number of matches to return (0 = unlimited)
    pub max_matches: usize,
    /// Output mode
    pub output_mode: GrepOutputMode,
    /// Nearby patterns that must appear within the window
    pub nearby_patterns: Vec<String>,
    /// Treat nearby patterns as regex (false = literal)
    pub nearby_is_regex: bool,
    /// Case-insensitive matching for nearby patterns
    pub nearby_case_insensitive: bool,
    /// Direction to search for nearby patterns
    pub nearby_direction: NearbyDirection,
    /// Window size in words (optional)
    pub nearby_window_words: Option<usize>,
    /// Window size in characters (optional)
    pub nearby_window_chars: Option<usize>,
    /// How to match multiple nearby patterns
    pub nearby_match_mode: NearbyMatchMode,
    /// Treat `pattern` as a literal string.
    pub fixed_strings: bool,
    /// Constrain matches to word boundaries.
    pub whole_word: bool,
    /// Maximum recursion depth (0 = unlimited).
    pub max_depth: usize,
    /// Skip files larger than this size in bytes (0 = no limit).
    pub max_filesize: u64,
    /// Regex engine for `pattern`.
    pub engine: GrepEngine,
}

/// Enhanced grep result supporting different output modes
#[derive(Debug, Clone)]
pub enum GrepResult {
    /// ContentBlock mode: return matching lines
    Matches(Vec<GrepMatch>),
    /// Count mode: return match counts per file
    Counts(Vec<GrepCount>),
    /// Files mode: return file paths only
    Files(Vec<PathBuf>),
}

/// Dual-engine matcher for grep_context: regex (fast, no look-around) or
/// fancy-regex (look-around / backreferences). Both produce (start, end) byte
/// spans on a haystack &str.
enum AnyMatcher {
    Regex(Regex),
    Fancy(fancy_regex::Regex),
}

impl AnyMatcher {
    fn find_spans(&self, hay: &str) -> Vec<(usize, usize)> {
        match self {
            AnyMatcher::Regex(re) => re.find_iter(hay).map(|m| (m.start(), m.end())).collect(),
            AnyMatcher::Fancy(re) => {
                let mut out = Vec::new();
                let mut cursor = 0usize;
                while cursor <= hay.len() {
                    match re.find_from_pos(hay, cursor) {
                        Ok(Some(m)) => {
                            out.push((m.start(), m.end()));
                            cursor = if m.end() == m.start() {
                                m.end() + 1
                            } else {
                                m.end()
                            };
                        }
                        _ => break,
                    }
                }
                out
            }
        }
    }
}

fn build_any_matcher(
    pattern: &str,
    case_insensitive: bool,
    fixed_strings: bool,
    whole_word: bool,
    engine: GrepEngine,
) -> Result<AnyMatcher> {
    let mut p = pattern.to_string();
    if fixed_strings {
        p = regex::escape(&p);
    }
    if whole_word {
        p = format!(r"\b(?:{p})\b");
    }
    if case_insensitive {
        p = format!("(?i){p}");
    }
    match engine {
        GrepEngine::Regex => Ok(AnyMatcher::Regex(
            RegexBuilder::new(&p)
                .build()
                .context("Invalid regex pattern")?,
        )),
        GrepEngine::Fancy => Ok(AnyMatcher::Fancy(
            fancy_regex::Regex::new(&p).context("Invalid fancy-regex pattern")?,
        )),
    }
}

pub async fn grep_context_files(
    params: GrepContextParams,
    allowed: &AllowedDirs,
    allow_symlink_escape: bool,
) -> Result<GrepResult> {
    let root_path = resolve_validated_path(&params.root, allowed, allow_symlink_escape)
        .await
        .context("Invalid root path")?;

    let matcher = build_any_matcher(
        &params.pattern,
        params.case_insensitive,
        params.fixed_strings,
        params.whole_word,
        params.engine,
    )?;

    let nearby_regexes = build_nearby_regexes(
        &params.nearby_patterns,
        params.nearby_is_regex,
        params.nearby_case_insensitive,
    )?;

    let file_matcher = if let Some(pattern) = &params.file_pattern {
        Some(build_glob(pattern)?)
    } else {
        None
    };
    let exclude_matcher = if params.exclude_patterns.is_empty() {
        None
    } else {
        Some(build_glob_set(&params.exclude_patterns)?)
    };

    let mut matches = Vec::new();
    let mut counts = Vec::new();
    let mut files = Vec::new();
    let mut total_matches = 0;

    let metadata = fs::metadata(&root_path).await?;
    if metadata.is_file() {
        if let Some(matcher) = &exclude_matcher {
            let filename = root_path.file_name().unwrap_or_default().to_string_lossy();
            if matcher.is_match(&*filename) {
                return Ok(result_for_mode(&params.output_mode, matches, counts, files));
            }
        }
        if let Some(matcher) = &file_matcher {
            let filename = root_path.file_name().unwrap_or_default().to_string_lossy();
            if !matcher.is_match(&*filename) {
                return Ok(result_for_mode(&params.output_mode, matches, counts, files));
            }
        }
        if let Ok(file_matches) = search_file_with_context(
            &root_path,
            &matcher,
            &nearby_regexes,
            params.context_before,
            params.context_after,
            params.max_matches,
            params.nearby_direction,
            params.nearby_window_words,
            params.nearby_window_chars,
            params.nearby_match_mode,
            params.max_filesize,
        )
        .await
        {
            handle_file_result(
                &root_path,
                file_matches,
                &params.output_mode,
                &mut matches,
                &mut counts,
                &mut files,
            );
        }
        return Ok(result_for_mode(&params.output_mode, matches, counts, files));
    }

    // Stack stores (path, depth). depth=0 means `root_path` itself.
    let mut stack: Vec<(PathBuf, usize)> = vec![(root_path.clone(), 0)];
    while let Some((current, depth)) = stack.pop() {
        if params.max_matches > 0
            && total_matches >= params.max_matches
            && params.output_mode == GrepOutputMode::ContentBlock
        {
            break;
        }

        let mut dir = match fs::read_dir(&current).await {
            Ok(d) => d,
            Err(_) => continue,
        };

        while let Some(entry) = dir.next_entry().await? {
            if params.max_matches > 0
                && total_matches >= params.max_matches
                && params.output_mode == GrepOutputMode::ContentBlock
            {
                break;
            }

            let path = entry.path();

            if resolve_validated_path(
                path.to_string_lossy().as_ref(),
                allowed,
                allow_symlink_escape,
            )
            .await
            .is_err()
            {
                continue;
            }

            let file_type = match entry.file_type().await {
                Ok(ft) => ft,
                Err(_) => continue,
            };

            if let Some(matcher) = &exclude_matcher {
                let rel = path.strip_prefix(&root_path).unwrap_or(&path);
                if matcher.is_match(&*rel.to_string_lossy()) {
                    continue;
                }
            }

            if file_type.is_dir() {
                if params.max_depth == 0 || depth < params.max_depth {
                    stack.push((path, depth + 1));
                }
            } else if file_type.is_file() {
                if let Some(matcher) = &file_matcher {
                    let rel = path.strip_prefix(&root_path).unwrap_or(&path);
                    if !matcher.is_match(&*rel.to_string_lossy()) {
                        continue;
                    }
                }

                let remaining = if params.output_mode == GrepOutputMode::ContentBlock {
                    params.max_matches.saturating_sub(total_matches)
                } else {
                    0
                };

                if remaining == 0
                    && params.max_matches > 0
                    && params.output_mode == GrepOutputMode::ContentBlock
                {
                    break;
                }

                if let Ok(file_matches) = search_file_with_context(
                    &path,
                    &matcher,
                    &nearby_regexes,
                    params.context_before,
                    params.context_after,
                    remaining,
                    params.nearby_direction,
                    params.nearby_window_words,
                    params.nearby_window_chars,
                    params.nearby_match_mode,
                    params.max_filesize,
                )
                .await
                {
                    total_matches += file_matches.len();
                    handle_file_result(
                        &path,
                        file_matches,
                        &params.output_mode,
                        &mut matches,
                        &mut counts,
                        &mut files,
                    );
                }
            }
        }
    }

    Ok(result_for_mode(&params.output_mode, matches, counts, files))
}

/// Handle search results based on output mode
fn handle_file_result(
    path: &Path,
    file_matches: Vec<GrepMatch>,
    output_mode: &GrepOutputMode,
    matches: &mut Vec<GrepMatch>,
    counts: &mut Vec<GrepCount>,
    files: &mut Vec<PathBuf>,
) {
    match output_mode {
        GrepOutputMode::ContentBlock => {
            matches.extend(file_matches);
        }
        GrepOutputMode::CountOnly => {
            if !file_matches.is_empty() {
                counts.push(GrepCount {
                    path: path.to_path_buf(),
                    count: file_matches.len(),
                });
            }
        }
        GrepOutputMode::FilesWithMatches => {
            if !file_matches.is_empty() {
                files.push(path.to_path_buf());
            }
        }
        GrepOutputMode::FilesWithoutMatch => {
            if file_matches.is_empty() {
                files.push(path.to_path_buf());
            }
        }
    }
}

/// Build result based on output mode
fn result_for_mode(
    mode: &GrepOutputMode,
    matches: Vec<GrepMatch>,
    counts: Vec<GrepCount>,
    files: Vec<PathBuf>,
) -> GrepResult {
    match mode {
        GrepOutputMode::ContentBlock => GrepResult::Matches(matches),
        GrepOutputMode::CountOnly => GrepResult::Counts(counts),
        GrepOutputMode::FilesWithMatches | GrepOutputMode::FilesWithoutMatch => {
            GrepResult::Files(files)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn search_file_with_context(
    path: &Path,
    matcher: &AnyMatcher,
    nearby_regexes: &[Regex],
    context_before: usize,
    context_after: usize,
    max_matches: usize,
    nearby_direction: NearbyDirection,
    nearby_window_words: Option<usize>,
    nearby_window_chars: Option<usize>,
    nearby_match_mode: NearbyMatchMode,
    max_filesize: u64,
) -> Result<Vec<GrepMatch>> {
    if max_filesize > 0
        && let Ok(meta) = fs::metadata(path).await
        && meta.len() > max_filesize
    {
        return Ok(Vec::new());
    }

    let content = match read_text(path).await {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };

    let lines: Vec<&str> = content.lines().collect();
    let line_starts = build_line_starts(&content);
    let word_spans = build_word_spans(&content);
    let mut matches = Vec::new();

    for (m_start, m_end) in matcher.find_spans(&content) {
        if max_matches > 0 && matches.len() >= max_matches {
            break;
        }

        if !nearby_patterns_match(
            &content,
            m_start,
            m_end,
            nearby_regexes,
            &word_spans,
            nearby_direction,
            nearby_window_words,
            nearby_window_chars,
            nearby_match_mode,
        ) {
            continue;
        }

        let line_index = line_index_for_offset(&line_starts, m_start);
        if line_index >= lines.len() {
            continue;
        }

        let before_start = line_index.saturating_sub(context_before);
        let after_end = (line_index + 1 + context_after).min(lines.len());

        let before_context = if context_before > 0 {
            lines[before_start..line_index]
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            Vec::new()
        };

        let after_context = if context_after > 0 {
            lines[(line_index + 1)..after_end]
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            Vec::new()
        };

        matches.push(GrepMatch {
            path: path.to_path_buf(),
            line_number: line_index + 1,
            line: lines[line_index].to_string(),
            before_context,
            after_context,
        });
    }

    Ok(matches)
}

fn build_nearby_regexes(
    patterns: &[String],
    is_regex: bool,
    case_insensitive: bool,
) -> Result<Vec<Regex>> {
    let mut compiled = Vec::new();
    for pattern in patterns {
        let pat = if is_regex {
            pattern.clone()
        } else {
            regex::escape(pattern)
        };
        let re = RegexBuilder::new(&pat)
            .case_insensitive(case_insensitive)
            .build()
            .context("Invalid nearby pattern regex")?;
        compiled.push(re);
    }
    Ok(compiled)
}

fn build_line_starts(content: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (idx, ch) in content.char_indices() {
        if ch == '\n' {
            starts.push(idx + 1);
        }
    }
    starts
}

fn line_index_for_offset(starts: &[usize], offset: usize) -> usize {
    let mut low = 0;
    let mut high = starts.len();
    while low < high {
        let mid = (low + high) / 2;
        if starts[mid] <= offset {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    low.saturating_sub(1)
}

fn build_word_spans(content: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let word_re = Regex::new(r"\b\w+\b").unwrap();
    for m in word_re.find_iter(content) {
        spans.push((m.start(), m.end()));
    }
    spans
}

#[allow(clippy::too_many_arguments)]
fn nearby_patterns_match(
    content: &str,
    match_start: usize,
    match_end: usize,
    nearby_regexes: &[Regex],
    word_spans: &[(usize, usize)],
    direction: NearbyDirection,
    window_words: Option<usize>,
    window_chars: Option<usize>,
    match_mode: NearbyMatchMode,
) -> bool {
    if nearby_regexes.is_empty() {
        return false;
    }

    let windows = build_windows(
        content,
        match_start,
        match_end,
        word_spans,
        direction,
        window_words,
        window_chars,
    );
    if windows.is_empty() {
        return false;
    }

    let mut results = Vec::with_capacity(nearby_regexes.len());
    for re in nearby_regexes {
        let found = windows.iter().any(|w| re.is_match(w));
        results.push(found);
    }

    match match_mode {
        NearbyMatchMode::Any => results.into_iter().any(|v| v),
        NearbyMatchMode::All => results.into_iter().all(|v| v),
    }
}

fn build_windows<'a>(
    content: &'a str,
    match_start: usize,
    match_end: usize,
    word_spans: &[(usize, usize)],
    direction: NearbyDirection,
    window_words: Option<usize>,
    window_chars: Option<usize>,
) -> Vec<&'a str> {
    let mut windows = Vec::new();

    if let Some(chars) = window_chars.filter(|c| *c > 0)
        && let Some(window) = char_window(content, match_start, match_end, direction, chars)
    {
        windows.extend(window);
    }

    if let Some(words) = window_words.filter(|w| *w > 0)
        && let Some(window) = word_window(content, match_start, word_spans, direction, words)
    {
        windows.extend(window);
    }

    windows
}

fn char_window(
    content: &str,
    match_start: usize,
    match_end: usize,
    direction: NearbyDirection,
    window_chars: usize,
) -> Option<Vec<&str>> {
    let total_chars = content.chars().count();
    let start_chars = content[..match_start].chars().count();
    let end_chars = content[..match_end].chars().count();

    let mut windows = Vec::new();

    if matches!(direction, NearbyDirection::Before | NearbyDirection::Both) && start_chars > 0 {
        let before_start = start_chars.saturating_sub(window_chars);
        let start_byte = char_index_to_byte(content, before_start);
        let end_byte = char_index_to_byte(content, start_chars);
        if start_byte < end_byte {
            windows.push(&content[start_byte..end_byte]);
        }
    }

    if matches!(direction, NearbyDirection::After | NearbyDirection::Both)
        && end_chars < total_chars
    {
        let after_end = (end_chars + window_chars).min(total_chars);
        let start_byte = char_index_to_byte(content, end_chars);
        let end_byte = char_index_to_byte(content, after_end);
        if start_byte < end_byte {
            windows.push(&content[start_byte..end_byte]);
        }
    }

    if windows.is_empty() {
        None
    } else {
        Some(windows)
    }
}

fn word_window<'a>(
    content: &'a str,
    match_start: usize,
    word_spans: &[(usize, usize)],
    direction: NearbyDirection,
    window_words: usize,
) -> Option<Vec<&'a str>> {
    if word_spans.is_empty() {
        return None;
    }

    let mut match_index = None;
    for (idx, (start, end)) in word_spans.iter().enumerate() {
        if *start <= match_start && match_start < *end {
            match_index = Some(idx);
            break;
        }
    }
    if match_index.is_none() {
        for (idx, (start, _)) in word_spans.iter().enumerate() {
            if *start > match_start {
                match_index = Some(idx);
                break;
            }
        }
    }
    let idx = match_index?;

    let mut windows = Vec::new();

    if matches!(direction, NearbyDirection::Before | NearbyDirection::Both) && idx > 0 {
        let start_idx = idx.saturating_sub(window_words);
        let end_idx = idx.saturating_sub(1);
        let start_byte = word_spans[start_idx].0;
        let end_byte = word_spans[end_idx].1;
        if start_byte < end_byte {
            windows.push(&content[start_byte..end_byte]);
        }
    }

    if matches!(direction, NearbyDirection::After | NearbyDirection::Both)
        && idx + 1 < word_spans.len()
    {
        let start_idx = (idx + 1).min(word_spans.len() - 1);
        let end_idx = (idx + window_words).min(word_spans.len() - 1);
        let start_byte = word_spans[start_idx].0;
        let end_byte = word_spans[end_idx].1;
        if start_byte < end_byte {
            windows.push(&content[start_byte..end_byte]);
        }
    }

    if windows.is_empty() {
        None
    } else {
        Some(windows)
    }
}

fn char_index_to_byte(content: &str, char_index: usize) -> usize {
    content
        .char_indices()
        .nth(char_index)
        .map(|(idx, _)| idx)
        .unwrap_or_else(|| content.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::fast_grep::grep_files_fast;
    use tempfile::TempDir;
    use tokio::fs;

    // These behaviour tests exercise the SHIPPED grep path (`grep_files_fast`),
    // which is what the MCP `grep_files` tool actually calls. The old
    // single-threaded `grep_files` helper they used to cover was dead code and
    // has been removed (BH-25).
    fn default_params(root: &str, pattern: &str) -> GrepParams {
        GrepParams {
            root: root.to_string(),
            pattern: pattern.to_string(),
            file_pattern: None,
            exclude_patterns: Vec::new(),
            case_insensitive: false,
            context_before: 0,
            context_after: 0,
            max_matches: 0,
            invert_match: false,
            output_mode: GrepOutputMode::ContentBlock,
            multiline: false,
            fixed_strings: false,
            whole_word: false,
            max_depth: 0,
            max_filesize: 0,
            encoding: None,
            heap_limit_mb: 0,
            engine: GrepEngine::Regex,
        }
    }

    #[tokio::test]
    async fn test_max_matches_no_underflow() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(
            root.join("file1.txt"),
            "match\nmatch\nmatch\nmatch\nmatch\n",
        )
        .await
        .unwrap();
        fs::write(
            root.join("file2.txt"),
            "match\nmatch\nmatch\nmatch\nmatch\n",
        )
        .await
        .unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let mut params = default_params(&root.to_string_lossy(), "match");
        params.file_pattern = Some("*.txt".to_string());
        params.max_matches = 3;

        let result = grep_files_fast(params, &allowed, false, None).await;
        assert!(result.is_ok(), "Should not panic on underflow");
        let result = result.unwrap().result;
        if let GrepResult::Matches(m) = result {
            assert!(m.len() <= 3);
        }
    }

    #[tokio::test]
    async fn test_max_matches_exact_limit() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("file.txt"), "a\nb\nc\n").await.unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let mut params = default_params(&root.to_string_lossy(), "[abc]");
        params.max_matches = 3;

        let result = grep_files_fast(params, &allowed, false, None)
            .await
            .unwrap()
            .result;
        if let GrepResult::Matches(m) = result {
            assert_eq!(m.len(), 3);
        } else {
            panic!("Expected Matches variant");
        }
    }

    #[tokio::test]
    async fn test_grep_empty_file() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("empty.txt"), "").await.unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);
        let params = default_params(&root.to_string_lossy(), "anything");

        let result = grep_files_fast(params, &allowed, false, None)
            .await
            .unwrap()
            .result;
        if let GrepResult::Matches(m) = result {
            assert_eq!(m.len(), 0);
        } else {
            panic!("Expected Matches variant");
        }
    }

    #[tokio::test]
    async fn test_grep_single_file_path() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        let file_path = root.join("target.txt");
        fs::write(&file_path, "hello world\nfoo bar\nhello again\n")
            .await
            .unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);
        let params = default_params(&file_path.to_string_lossy(), "hello");

        let result = grep_files_fast(params, &allowed, false, None)
            .await
            .unwrap()
            .result;
        if let GrepResult::Matches(matches) = result {
            assert_eq!(matches.len(), 2);
            assert_eq!(matches[0].line, "hello world");
            assert_eq!(matches[1].line, "hello again");
        } else {
            panic!("Expected Matches variant");
        }
    }

    #[tokio::test]
    async fn test_invert_match() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("file.txt"), "match\nno\nmatch\nyes\n")
            .await
            .unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let mut params = default_params(&root.to_string_lossy(), "match");
        params.invert_match = true;

        let result = grep_files_fast(params, &allowed, false, None)
            .await
            .unwrap()
            .result;
        if let GrepResult::Matches(matches) = result {
            assert_eq!(matches.len(), 2);
            assert_eq!(matches[0].line, "no");
            assert_eq!(matches[1].line, "yes");
        } else {
            panic!("Expected Matches variant");
        }
    }

    #[tokio::test]
    async fn test_count_only_mode() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("file1.txt"), "a\na\na\n")
            .await
            .unwrap();
        fs::write(root.join("file2.txt"), "a\na\n").await.unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let mut params = default_params(&root.to_string_lossy(), "a");
        params.output_mode = GrepOutputMode::CountOnly;

        let result = grep_files_fast(params, &allowed, false, None)
            .await
            .unwrap()
            .result;
        if let GrepResult::Counts(counts) = result {
            assert_eq!(counts.len(), 2);
            let total: usize = counts.iter().map(|c| c.count).sum();
            assert_eq!(total, 5); // 3 + 2
        } else {
            panic!("Expected Counts variant");
        }
    }

    #[tokio::test]
    async fn test_files_with_matches_mode() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("has_match.txt"), "findme\n")
            .await
            .unwrap();
        fs::write(root.join("no_match.txt"), "nothing\n")
            .await
            .unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let mut params = default_params(&root.to_string_lossy(), "findme");
        params.output_mode = GrepOutputMode::FilesWithMatches;

        let result = grep_files_fast(params, &allowed, false, None)
            .await
            .unwrap()
            .result;
        if let GrepResult::Files(files) = result {
            assert_eq!(files.len(), 1);
            assert!(files[0].to_string_lossy().contains("has_match"));
        } else {
            panic!("Expected Files variant");
        }
    }

    #[tokio::test]
    async fn test_files_without_match_mode() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("has_match.txt"), "findme\n")
            .await
            .unwrap();
        fs::write(root.join("no_match.txt"), "nothing\n")
            .await
            .unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let mut params = default_params(&root.to_string_lossy(), "findme");
        params.output_mode = GrepOutputMode::FilesWithoutMatch;

        let result = grep_files_fast(params, &allowed, false, None)
            .await
            .unwrap()
            .result;
        if let GrepResult::Files(files) = result {
            assert_eq!(files.len(), 1);
            assert!(files[0].to_string_lossy().contains("no_match"));
        } else {
            panic!("Expected Files variant");
        }
    }

    #[tokio::test]
    async fn test_exclude_patterns() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        fs::write(root.join("keep.txt"), "match\n").await.unwrap();
        fs::write(root.join("skip.txt"), "match\n").await.unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        let mut params = default_params(&root.to_string_lossy(), "match");
        params.exclude_patterns = vec!["skip.txt".to_string()];

        let result = grep_files_fast(params, &allowed, false, None)
            .await
            .unwrap()
            .result;
        if let GrepResult::Matches(matches) = result {
            assert_eq!(matches.len(), 1);
            assert!(matches[0].path.to_string_lossy().contains("keep.txt"));
        } else {
            panic!("Expected Matches variant");
        }
    }
}
