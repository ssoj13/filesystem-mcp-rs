use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// Zero-width / invisible characters commonly injected by PDF extractors.
const INVISIBLE: &[char] = &[
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{FEFF}', // BOM / ZWNBSP
    '\u{00AD}', // SOFT HYPHEN
];

/// Private-use sentinel for inter-word separators detected via ZWSP runs.
const WORD_SEP: char = '\u{E000}';

/// Result of reading PDF file
#[derive(Debug, Clone)]
pub struct PdfReadResult {
    /// Extracted text content (normalized by default)
    pub text: String,
    /// Total pages in document
    pub pages_count: usize,
    /// Pages that were extracted (1-indexed)
    pub pages_extracted: Vec<usize>,
    /// Whether content was truncated due to max_chars
    pub truncated: bool,
    /// Character count of returned `text`
    pub char_count: usize,
    /// Whether normalization was applied to `text`
    pub normalized: bool,
    /// Quality assessment (always computed from raw extract)
    pub quality: PdfQuality,
    /// Unnormalized extract when `include_raw` was requested
    pub raw_text: Option<String>,
}

/// Extraction quality metrics and warnings for agents.
#[derive(Debug, Clone)]
pub struct PdfQuality {
    /// 0.0 (unusable) .. 1.0 (looks clean)
    pub score: f64,
    /// Machine-readable warning codes
    pub warnings: Vec<String>,
    /// Count of zero-width / invisible chars in the raw extract
    pub zero_width_chars: usize,
    /// Fraction of raw tokens that are single letters (letter-spacing symptom)
    pub single_letter_token_ratio: f64,
    /// Fraction of tokens that look like broken glyph/encoding maps
    pub suspicious_token_ratio: f64,
    /// Sample of suspicious tokens (deduped, capped)
    pub suspicious_tokens: Vec<String>,
}

/// Parse page range string like "1-5" or "1,3,5" or "1,3-5,7"
fn parse_page_range(range: &str, total_pages: usize) -> Result<Vec<usize>> {
    let mut pages = Vec::new();

    for part in range.split(',') {
        let part = part.trim();

        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() != 2 {
                bail!("Invalid page range: {}", part);
            }

            let start: usize = bounds[0]
                .trim()
                .parse()
                .with_context(|| format!("Invalid page number: {}", bounds[0]))?;
            let end: usize = bounds[1]
                .trim()
                .parse()
                .with_context(|| format!("Invalid page number: {}", bounds[1]))?;

            if start == 0 || end == 0 {
                bail!("Page numbers are 1-indexed, got 0");
            }
            if start > end {
                bail!("Invalid range: start {} > end {}", start, end);
            }

            for p in start..=end.min(total_pages) {
                if !pages.contains(&p) {
                    pages.push(p);
                }
            }
        } else {
            let p: usize = part
                .parse()
                .with_context(|| format!("Invalid page number: {}", part))?;

            if p == 0 {
                bail!("Page numbers are 1-indexed, got 0");
            }
            if p <= total_pages && !pages.contains(&p) {
                pages.push(p);
            }
        }
    }

    pages.sort();
    Ok(pages)
}

/// Options for [`read_pdf`].
#[derive(Debug, Clone, Copy)]
pub struct ReadPdfOptions {
    pub normalize: bool,
    pub include_raw: bool,
}

impl Default for ReadPdfOptions {
    fn default() -> Self {
        Self {
            normalize: true,
            include_raw: false,
        }
    }
}

/// Read and extract text from PDF file.
///
/// Handles page range selection, character limit truncation, ZWSP/spaced-glyph
/// normalization, and quality scoring so agents know when encoding maps failed.
pub async fn read_pdf(
    path: &Path,
    pages: Option<&str>,
    max_chars: usize,
    options: ReadPdfOptions,
) -> Result<PdfReadResult> {
    let path_buf = path.to_path_buf();
    let pages_owned = pages.map(|s| s.to_string());

    tokio::task::spawn_blocking(move || {
        read_pdf_sync(
            &path_buf,
            pages_owned.as_deref(),
            max_chars,
            options,
        )
    })
    .await
    .with_context(|| "PDF extraction task panicked")?
}

fn read_pdf_sync(
    path: &PathBuf,
    pages_str: Option<&str>,
    max_chars: usize,
    options: ReadPdfOptions,
) -> Result<PdfReadResult> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Cannot read file: {}", path.display()))?;

    let raw = pdf_extract::extract_text_from_mem(&bytes).with_context(|| {
        format!(
            "Cannot extract text from PDF: {}. The file may be corrupted, encrypted, or contain only images.",
            path.display()
        )
    })?;

    let total_pages = estimate_page_count(&raw);

    let (raw_selected, pages_extracted) = match pages_str {
        Some(range) => {
            let selected = parse_page_range(range, total_pages)?;
            let picked = select_page_text(&raw, &selected, total_pages)?;
            (picked, selected)
        }
        None => (raw, (1..=total_pages).collect::<Vec<_>>()),
    };

    let quality = assess_quality(&raw_selected);
    let normalized_full = normalize_pdf_text(&raw_selected);

    let mut result_text = if options.normalize {
        normalized_full
    } else {
        raw_selected.clone()
    };
    let mut truncated = false;

    if result_text.chars().count() > max_chars {
        let mut char_count = 0;
        let mut byte_pos = 0;
        for (idx, c) in result_text.char_indices() {
            char_count += 1;
            byte_pos = idx + c.len_utf8();
            if char_count >= max_chars {
                break;
            }
        }
        result_text.truncate(byte_pos);
        truncated = true;
    }

    let char_count = result_text.chars().count();
    let raw_text = if options.include_raw {
        Some(raw_selected)
    } else {
        None
    };

    Ok(PdfReadResult {
        text: result_text,
        pages_count: total_pages,
        pages_extracted,
        truncated,
        char_count,
        normalized: options.normalize,
        quality,
        raw_text,
    })
}

/// Normalize PDF extractor artifacts.
///
/// Many extractors emit U+200B between *words* and ordinary spaces between
/// *glyph clusters* of the same word (`Ta ble\u{200B} \u{200B}o f`). We treat
/// any whitespace run that contains a zero-width char as an inter-word
/// separator, then delete spaces that sit between alphanumeric characters
/// inside each word group.
pub fn normalize_pdf_text(text: &str) -> String {
    let mut out_lines = Vec::new();
    for line in text.split('\n') {
        out_lines.push(normalize_pdf_line(line));
    }
    let mut joined = out_lines.join("\n");
    while joined.contains("\n\n\n") {
        joined = joined.replace("\n\n\n", "\n\n");
    }
    joined
}

fn normalize_pdf_line(line: &str) -> String {
    let mut marked = String::with_capacity(line.len());
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if is_invisible(c) || c.is_whitespace() {
            let start = i;
            let mut saw_invisible = is_invisible(c);
            i += 1;
            while i < chars.len() && (chars[i].is_whitespace() || is_invisible(chars[i])) {
                if is_invisible(chars[i]) {
                    saw_invisible = true;
                }
                i += 1;
            }
            if saw_invisible {
                marked.push(WORD_SEP);
            } else {
                // Preserve ordinary whitespace runs (may still be intra-word).
                for ch in &chars[start..i] {
                    marked.push(*ch);
                }
            }
        } else {
            marked.push(c);
            i += 1;
        }
    }

    let mut parts = Vec::new();
    for part in marked.split(WORD_SEP) {
        let collapsed = collapse_intra_word_spaces(part);
        let trimmed = collapsed.trim();
        if !trimmed.is_empty() {
            parts.push(trimmed.to_string());
        }
    }
    parts.join(" ")
}

fn is_invisible(c: char) -> bool {
    INVISIBLE.contains(&c)
}

/// Inside a ZWSP-delimited word group, join short alphabetic fragments
/// (`Ta`+`ble`, `C`+`o`+`n`+`ten`+`ts`) but keep real spaces between longer words
/// (`Layer naming`, `Hello world`).
fn collapse_intra_word_spaces(s: &str) -> String {
    let tokens: Vec<&str> = s.split_whitespace().collect();
    if tokens.is_empty() {
        return String::new();
    }

    let mut out: Vec<String> = Vec::new();
    let mut buf: Vec<&str> = Vec::new();

    let flush = |buf: &mut Vec<&str>, out: &mut Vec<String>| {
        if buf.is_empty() {
            return;
        }
        if buf.len() == 1 {
            out.push(buf[0].to_string());
        } else {
            out.push(buf.concat());
        }
        buf.clear();
    };

    for t in tokens {
        if is_glyph_fragment(t) {
            buf.push(t);
        } else {
            flush(&mut buf, &mut out);
            out.push(t.to_string());
        }
    }
    flush(&mut buf, &mut out);
    out.join(" ")
}

fn is_glyph_fragment(token: &str) -> bool {
    let alnum: String = token
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if alnum.is_empty() || alnum.len() > 3 {
        return false;
    }
    // Allow only edge punctuation around an alphanumeric core.
    let trimmed = token.trim_matches(|c: char| c.is_ascii_punctuation());
    !trimmed.is_empty()
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric())
}

fn assess_quality(raw: &str) -> PdfQuality {
    let zero_width_chars = raw.chars().filter(|c| is_invisible(*c)).count();

    let tokens: Vec<&str> = raw.split_whitespace().collect();
    let token_count = tokens.len().max(1);
    let single_letter = tokens
        .iter()
        .filter(|t| {
            let letters: String = t.chars().filter(|c| c.is_ascii_alphabetic()).collect();
            letters.len() == 1 && t.chars().all(|c| c.is_ascii_alphabetic() || is_invisible(c))
        })
        .count();
    let single_letter_token_ratio = single_letter as f64 / token_count as f64;

    let mut suspicious_tokens = Vec::new();
    let mut suspicious_count = 0usize;
    for t in &tokens {
        if is_suspicious_token(t) {
            suspicious_count += 1;
            if suspicious_tokens.len() < 12 && !suspicious_tokens.iter().any(|s| s == t) {
                suspicious_tokens.push((*t).to_string());
            }
        }
    }
    let suspicious_token_ratio = suspicious_count as f64 / token_count as f64;

    let zw_density = zero_width_chars as f64 / (raw.chars().count().max(1) as f64);

    let mut score = 1.0;
    score -= (zw_density * 4.0).min(0.35);
    score -= (single_letter_token_ratio * 1.5).min(0.35);
    score -= (suspicious_token_ratio * 3.0).min(0.45);
    if score < 0.0 {
        score = 0.0;
    }

    let mut warnings = Vec::new();
    if zero_width_chars > 0 {
        warnings.push("zero_width_chars_present".into());
    }
    if single_letter_token_ratio >= 0.08 {
        warnings.push("spaced_glyphs_detected".into());
    }
    if suspicious_token_ratio >= 0.01 || !suspicious_tokens.is_empty() {
        warnings.push("suspicious_encoding_tokens".into());
    }
    if score < 0.75 {
        warnings.push("extraction_quality_degraded".into());
    }
    if score < 0.45 {
        warnings.push("do_not_treat_as_source_of_truth".into());
    }

    PdfQuality {
        score: (score * 1000.0).round() / 1000.0,
        warnings,
        zero_width_chars,
        single_letter_token_ratio: (single_letter_token_ratio * 1000.0).round() / 1000.0,
        suspicious_token_ratio: (suspicious_token_ratio * 1000.0).round() / 1000.0,
        suspicious_tokens,
    }
}

fn is_suspicious_token(token: &str) -> bool {
    let t = token.trim_matches(|c: char| c.is_ascii_punctuation() && c != ']' && c != '[');
    if t.len() < 4 {
        return false;
    }
    let alpha = t.chars().filter(|c| c.is_ascii_alphabetic()).count();
    if alpha < 3 {
        return false;
    }
    // Broken ToUnicode maps often yield letter soup mixed with ] [ } {
    let weird = t.chars().any(|c| matches!(c, ']' | '[' | '{' | '}' | '|' | '<' | '>'));
    if weird && alpha as f64 / t.len() as f64 >= 0.5 {
        return true;
    }
    false
}

/// Extract the text of the `selected` (1-indexed) pages from pdf-extract output.
///
/// pdf-extract separates pages with a form-feed (`\x0C`); when the number of
/// form-feed-delimited chunks matches `total_pages` we can isolate pages
/// exactly. If the page count was only estimated (no separators present), page
/// selection is impossible and we return an error rather than silently handing
/// back the whole document under a page-range request.
fn select_page_text(text: &str, selected: &[usize], total_pages: usize) -> Result<String> {
    let page_chunks: Vec<&str> = text.split('\u{0C}').collect();
    if page_chunks.len() != total_pages {
        anyhow::bail!(
            "This PDF has no detectable page separators; page selection is not \
             supported for it. Omit `pages` to read the whole document."
        );
    }
    let picked: Vec<&str> = selected
        .iter()
        .filter_map(|&p| page_chunks.get(p.checked_sub(1)?).copied())
        .collect();
    Ok(picked.join("\u{0C}"))
}

/// Estimate page count from text (rough heuristic based on form feeds)
fn estimate_page_count(text: &str) -> usize {
    let ff_count = text.matches('\x0C').count();
    if ff_count > 0 {
        return ff_count + 1;
    }

    let chars = text.chars().count();
    if chars == 0 {
        return 1;
    }

    (chars / 2000).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_page_range_single() {
        let pages = parse_page_range("3", 10).unwrap();
        assert_eq!(pages, vec![3]);
    }

    #[test]
    fn test_parse_page_range_multiple() {
        let pages = parse_page_range("1,3,5", 10).unwrap();
        assert_eq!(pages, vec![1, 3, 5]);
    }

    #[test]
    fn test_parse_page_range_range() {
        let pages = parse_page_range("2-5", 10).unwrap();
        assert_eq!(pages, vec![2, 3, 4, 5]);
    }

    #[test]
    fn test_parse_page_range_mixed() {
        let pages = parse_page_range("1, 3-5, 7", 10).unwrap();
        assert_eq!(pages, vec![1, 3, 4, 5, 7]);
    }

    #[test]
    fn test_parse_page_range_beyond_total() {
        let pages = parse_page_range("8-15", 10).unwrap();
        assert_eq!(pages, vec![8, 9, 10]);
    }

    #[test]
    fn test_parse_page_range_zero_error() {
        let result = parse_page_range("0", 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_page_range_invalid_range() {
        let result = parse_page_range("5-3", 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_estimate_page_count_empty() {
        assert_eq!(estimate_page_count(""), 1);
    }

    #[test]
    fn test_estimate_page_count_with_ff() {
        let text = "Page 1\x0CPage 2\x0CPage 3";
        assert_eq!(estimate_page_count(text), 3);
    }

    #[test]
    fn test_estimate_page_count_by_chars() {
        let text = "x".repeat(5000);
        assert_eq!(estimate_page_count(&text), 2);
    }

    #[test]
    fn test_select_page_text_picks_requested_pages() {
        let text = "PAGE1\u{0C}PAGE2\u{0C}PAGE3";
        let out = select_page_text(text, &[2], 3).unwrap();
        assert_eq!(out, "PAGE2");
        let out2 = select_page_text(text, &[1, 3], 3).unwrap();
        assert_eq!(out2, "PAGE1\u{0C}PAGE3");
    }

    #[test]
    fn test_select_page_text_errors_without_separators() {
        let text = "one big blob of text";
        let result = select_page_text(text, &[2], 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_select_page_text_single_page_whole_doc() {
        let text = "only page";
        let out = select_page_text(text, &[1], 1).unwrap();
        assert_eq!(out, "only page");
    }

    #[test]
    fn normalize_zwsp_word_separators_and_spaced_glyphs() {
        // Mirrors Cryptomatte TOC artifact pattern from pdf-extract.
        let raw = "Ta ble\u{200B} \u{200B}o f\u{200B} \u{200B}C o n ten ts:";
        let n = normalize_pdf_text(raw);
        assert_eq!(n, "Table of Contents:");
        assert!(!n.contains('\u{200B}'));
        assert!(!n.contains("Ta ble"));
    }

    #[test]
    fn normalize_preserves_normal_words() {
        let raw = "Layer\u{200B} \u{200B}naming";
        assert_eq!(normalize_pdf_text(raw), "Layer naming");
        assert_eq!(normalize_pdf_text("Hello world"), "Hello world");
        assert_eq!(normalize_pdf_text("EXR\u{200B} \u{200B}File"), "EXR File");
    }

    #[test]
    fn quality_flags_suspicious_encoding_tokens() {
        let raw = "CryptoObject ok\nlqh]fe] lqh]fe] junk\n";
        let q = assess_quality(raw);
        assert!(q.warnings.iter().any(|w| w == "suspicious_encoding_tokens"));
        assert!(q.suspicious_tokens.iter().any(|t| t.contains("lqh]fe]")));
        assert!(q.score < 1.0);
    }

    #[test]
    fn quality_flags_zwsp_and_spaced_glyphs() {
        let raw = "Ta ble\u{200B} \u{200B}o f\u{200B} \u{200B}C o n ten ts:";
        let q = assess_quality(raw);
        assert!(q.zero_width_chars > 0);
        assert!(q.warnings.iter().any(|w| w == "zero_width_chars_present"));
        assert!(q.warnings.iter().any(|w| w == "spaced_glyphs_detected"));
        assert!(q.warnings.iter().any(|w| w == "extraction_quality_degraded"));
    }

    #[tokio::test]
    async fn cryptomatte_fixture_normalizes_toc_and_warns() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cryptomatte_specification.pdf");
        if !path.is_file() {
            eprintln!("skip: fixture missing at {}", path.display());
            return;
        }
        let result = read_pdf(
            &path,
            None,
            80_000,
            ReadPdfOptions {
                normalize: true,
                include_raw: true,
            },
        )
        .await
        .expect("read_pdf");

        assert!(
            result.text.contains("Table of Contents"),
            "normalized text should repair TOC spacing; got snippet: {:?}",
            result.text.chars().take(200).collect::<String>()
        );
        assert!(!result.text.contains("Ta ble"));
        assert!(result.normalized);
        assert!(result.quality.score < 0.85);
        assert!(
            result
                .quality
                .warnings
                .iter()
                .any(|w| w == "extraction_quality_degraded"
                    || w == "suspicious_encoding_tokens")
        );
        let raw = result.raw_text.as_deref().unwrap_or("");
        assert!(raw.contains('\u{200B}') || raw.contains("Ta ble") || raw.contains("lqh]fe]"));
    }
}
