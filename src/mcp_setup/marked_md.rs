//! Marked-section patching for agent context files (`QWEN.md`, `GEMINI.md`, `CLAUDE.md`, …):
//! outer HTML markers define our region; **managed** inner markers hold mcp-setup-owned Markdown.
//! User notes stay outside the managed section (still inside the outer block) and survive re-`apply`.
//! Removing the install deletes the whole outer region.
//!
//! Optional **snippet source** (see `crate::mcp_setup::types::HintsConfig::snippet_source`) can supply
//! preamble text merged on each `apply`.

use std::path::Path;

use crate::mcp_setup::error::{Result, SetupError};

/// Outer delimiters: the whole install-owned region (deleted on `remove`).
pub fn marker_delimiters(marker_token: &str) -> (String, String) {
    (
        format!("<!-- mcp-setup:{marker_token}:begin -->"),
        format!("<!-- mcp-setup:{marker_token}:end -->"),
    )
}

/// Inner delimiters: only this part is replaced on `apply`.
pub fn managed_delimiters(marker_token: &str) -> (String, String) {
    (
        format!("<!-- mcp-setup:{marker_token}:managed:begin -->"),
        format!("<!-- mcp-setup:{marker_token}:managed:end -->"),
    )
}

/// Managed lines only (no trailing newline after `managed:end`).
fn managed_chunk(mb: &str, body: &str, me: &str) -> String {
    format!("{mb}\n{body}\n{me}")
}

/// `preamble` / `appendix` are user-owned slices inside the outer block (outside managed).
fn compose_outer_inner(
    mb: &str,
    me: &str,
    managed_body: &str,
    preamble: &str,
    appendix: &str,
) -> String {
    let m = managed_chunk(mb, managed_body, me);
    let pre = preamble.trim();
    let app = appendix.trim();
    match (pre.is_empty(), app.is_empty()) {
        (true, true) => m,
        (false, true) => format!("{pre}\n\n{m}"),
        (true, false) => format!("{m}\n\n{app}\n"),
        (false, false) => format!("{pre}\n\n{m}\n\n{app}\n"),
    }
}

pub fn marker_token_from(install_id: &str, mcp_server_key: &str) -> String {
    let s = format!("{mcp_server_key}__{install_id}");
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Same as [`upsert_marked_section_with_preamble`] with no user snippet file.
///
/// Public helper on the `qwen_md` module; the in-crate Qwen client uses `_with_preamble` only.
#[allow(dead_code)]
pub fn upsert_marked_section(
    existing_content: &str,
    marker_token: &str,
    body_markdown: &str,
) -> (String, bool) {
    upsert_marked_section_with_preamble(existing_content, marker_token, body_markdown, None)
}

/// Returns `(new_content, changed)`.
///
/// When `user_snippet_preamble` is `Some(text)`, it replaces the in-file preamble (the slice before
/// `managed:begin` inside the outer block). Use this to integrate a user-maintained `QWEN.md` (or
/// fragment file) into the real Qwen `QWEN.md` output on each `apply`. `None` keeps the preamble
/// already stored in `existing_content`.
pub fn upsert_marked_section_with_preamble(
    existing_content: &str,
    marker_token: &str,
    body_markdown: &str,
    user_snippet_preamble: Option<&str>,
) -> (String, bool) {
    let (ob, oe) = marker_delimiters(marker_token);
    let (mb, me) = managed_delimiters(marker_token);
    let managed_body = body_markdown.trim_end();

    if let Some((i0, i1)) = find_block(existing_content, &ob, &oe) {
        let before = &existing_content[..i0];
        let after = &existing_content[i1..];
        let block = &existing_content[i0..i1];
        let Some(inner) = outer_block_inner(block, &ob, &oe) else {
            return append_new_outer(
                existing_content,
                &ob,
                &oe,
                &mb,
                &me,
                managed_body,
                user_snippet_preamble,
            );
        };

        let new_inner = if let Some((mj0, mj1)) = find_block(inner, &mb, &me) {
            let preamble = if let Some(p) = user_snippet_preamble {
                p
            } else {
                &inner[..mj0]
            };
            let appendix = &inner[mj1..];
            compose_outer_inner(&mb, &me, managed_body, preamble, appendix)
        } else {
            let legacy = inner.trim();
            if let Some(p) = user_snippet_preamble {
                compose_outer_inner(&mb, &me, managed_body, p, legacy)
            } else {
                compose_outer_inner(&mb, &me, managed_body, "", legacy)
            }
        };

        let full_block = format!("{ob}\n{new_inner}\n{oe}\n");
        let mut out = String::with_capacity(existing_content.len() + full_block.len());
        out.push_str(before);
        out.push_str(&full_block);
        out.push_str(after);
        let changed = normalized_tail(&out) != normalized_tail(existing_content);
        let out = if changed {
            out
        } else {
            existing_content.to_string()
        };
        return (out, changed);
    }

    append_new_outer(
        existing_content,
        &ob,
        &oe,
        &mb,
        &me,
        managed_body,
        user_snippet_preamble,
    )
}

fn append_new_outer(
    existing_content: &str,
    ob: &str,
    oe: &str,
    mb: &str,
    me: &str,
    managed_body: &str,
    user_snippet_preamble: Option<&str>,
) -> (String, bool) {
    let pre = user_snippet_preamble.unwrap_or("").trim();
    let new_inner = compose_outer_inner(mb, me, managed_body, pre, "");
    let block = format!("{ob}\n{new_inner}\n{oe}\n");
    let mut out = existing_content.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(&block);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    (out, true)
}

/// Slice inside `block` (full `outer_begin..outer_end` span) between outer markers, excluding the marker lines.
fn outer_block_inner<'a>(block: &'a str, ob: &str, oe: &str) -> Option<&'a str> {
    let rest = block.strip_prefix(ob)?;
    let rel_end = rest.find(oe)?;
    Some(&rest[..rel_end])
}

/// Returns `(new_content, changed)` where `changed` is true if anything was removed.
pub fn remove_marked_section(existing_content: &str, marker_token: &str) -> (String, bool) {
    let (begin, end) = marker_delimiters(marker_token);
    let Some((i0, i1)) = find_block(existing_content, &begin, &end) else {
        return (existing_content.to_string(), false);
    };
    let mut out = String::with_capacity(existing_content.len());
    out.push_str(&existing_content[..i0]);
    out.push_str(&existing_content[i1..]);
    let out = trim_reasonable_blank_edges(&out);
    (out, true)
}

fn find_block(s: &str, begin: &str, end: &str) -> Option<(usize, usize)> {
    let i0 = s.find(begin)?;
    let rest = &s[i0 + begin.len()..];
    let rel_end = rest.find(end)?;
    Some((i0, i0 + begin.len() + rel_end + end.len()))
}

fn trim_reasonable_blank_edges(s: &str) -> String {
    s.trim_matches(|c| c == ' ' || c == '\t' || c == '\n' || c == '\r')
        .to_string()
}

#[inline]
fn normalized_tail(s: &str) -> String {
    format!("{}\n", s.trim_end_matches(['\r', '\n', ' ', '\t']))
}

/// Read file as UTF-8 string, or empty if missing.
pub fn read_or_empty(path: &Path) -> Result<String> {
    if !path.exists() {
        return Ok(String::new());
    }
    std::fs::read_to_string(path).map_err(|e| SetupError::io(path.to_path_buf(), e))
}

/// Writes UTF-8. Deletes the file when content is empty/whitespace-only after trim.
pub fn write_or_delete_if_empty(path: &Path, content: &str) -> Result<()> {
    let t = content.trim();
    if t.is_empty() {
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| SetupError::io(path.to_path_buf(), e))?;
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SetupError::io(parent.to_path_buf(), e))?;
    }
    let mut out = content.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    std::fs::write(path, out).map_err(|e| SetupError::io(path.to_path_buf(), e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_then_remove_roundtrip() {
        let tok = "filesystem-mcp-rs__v1";
        let body = "hello\nworld";
        let (a, c1) = upsert_marked_section("", tok, body);
        assert!(c1);
        assert!(a.contains("hello"));
        assert!(a.contains("managed:begin"));
        let (b, c2) = remove_marked_section(&a, tok);
        assert!(c2);
        assert!(!b.contains("hello"));
    }

    #[test]
    fn upsert_updates_managed_keeps_user_suffix() {
        let tok = "x";
        let (mb, me) = managed_delimiters(tok);
        let (bgn, e) = marker_delimiters(tok);

        let old = format!("pre\n{bgn}\n{mb}\nOLD_MANAGED\n{me}\n\nMy notes stay.\n{e}\npost");
        let (new, ch) = upsert_marked_section(&old, tok, "NEW_MANAGED");
        assert!(ch);
        assert!(new.contains("NEW_MANAGED"));
        assert!(!new.contains("OLD_MANAGED"));
        assert!(new.contains("My notes stay."));
        assert!(new.contains("pre"));
        assert!(new.contains("post"));
    }

    #[test]
    fn upsert_migrates_legacy_flat_body_to_user_tail() {
        let tok = "k";
        let (bgn, e) = marker_delimiters(tok);
        let old = format!("pre\n{bgn}\nLEGACY_LINE\n{e}\npost");
        let (new, ch) = upsert_marked_section(&old, tok, "FRESH");
        assert!(ch);
        assert!(new.contains("FRESH"));
        assert!(new.contains("LEGACY_LINE"));
        assert!(new.contains("managed:end"));
        assert!(new.contains("pre"));
    }

    #[test]
    fn upsert_preserves_user_preamble_before_managed() {
        let tok = "t";
        let (mb, me) = managed_delimiters(tok);
        let (bgn, e) = marker_delimiters(tok);
        let old = format!("{bgn}\nIntro from user.\n{mb}\nM1\n{me}\n{e}\n");
        let (new, ch) = upsert_marked_section(&old, tok, "M2");
        assert!(ch);
        assert!(new.contains("Intro from user."));
        assert!(new.contains("M2"));
        assert!(!new.contains("M1"));
    }

    #[test]
    fn second_apply_is_noop_when_nothing_user_edited() {
        let tok = "idempotent_tok";
        let body = "same body";
        let (a, _) = upsert_marked_section("", tok, body);
        let (b, ch) = upsert_marked_section(&a, tok, body);
        assert!(!ch);
        assert_eq!(a, b);
    }

    #[test]
    fn snippet_file_replaces_preamble_on_apply() {
        let tok = "snippet_tok";
        let (bgn, e) = marker_delimiters(tok);
        let (mb, me) = managed_delimiters(tok);
        let old = format!("{bgn}\nOld preamble text.\n{mb}\nM1\n{me}\n{e}\n");
        let (new, ch) =
            upsert_marked_section_with_preamble(&old, tok, "M2", Some("From snippet file."));
        assert!(ch);
        assert!(new.contains("From snippet file."));
        assert!(!new.contains("Old preamble text"));
        assert!(new.contains("M2"));
    }

    #[test]
    fn snippet_with_legacy_inner_migrates() {
        let tok = "leg";
        let (bgn, e) = marker_delimiters(tok);
        let old = format!("{bgn}\nLEGACY_ONLY\n{e}\n");
        let (new, ch) =
            upsert_marked_section_with_preamble(&old, tok, "MANAGED", Some("PREAMBLE_SNIP"));
        assert!(ch);
        assert!(new.contains("PREAMBLE_SNIP"));
        assert!(new.contains("LEGACY_ONLY"));
        assert!(new.contains("MANAGED"));
        assert!(new.contains("managed:begin"));
    }
}
