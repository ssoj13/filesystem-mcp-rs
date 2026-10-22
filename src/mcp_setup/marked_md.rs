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

    if let Some((i0, i1, existing_tok)) = find_server_block(existing_content, marker_token) {
        let (old_ob, old_oe) = marker_delimiters(&existing_tok);
        let (old_mb, old_me) = managed_delimiters(&existing_tok);
        let before = &existing_content[..i0];
        let after_cleaned = strip_all_server_blocks(&existing_content[i1..], marker_token);
        let after = after_cleaned.as_str();
        let block = &existing_content[i0..i1];
        let Some(inner) = outer_block_inner(block, &old_ob, &old_oe) else {
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

        let new_inner = if let Some((mj0, mj1)) = find_block(inner, &old_mb, &old_me) {
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
        if !after.is_empty() {
            if !after.starts_with('\n') && !after.starts_with('\r') {
                out.push('\n');
            }
            out.push_str(after.trim_start_matches(['\r', '\n']));
            if !out.ends_with('\n') {
                out.push('\n');
            }
        }
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
///
/// Removes the exact `marker_token` block as well as any legacy versioned blocks sharing the same
/// `<server_key>__` prefix so version upgrades never leave unremovable orphan blocks behind.
pub fn remove_marked_section(existing_content: &str, marker_token: &str) -> (String, bool) {
    let cleaned = strip_all_server_blocks(existing_content, marker_token);
    if cleaned == existing_content {
        return (existing_content.to_string(), false);
    }
    let out = trim_reasonable_blank_edges(&cleaned);
    (out, true)
}

fn find_block(s: &str, begin: &str, end: &str) -> Option<(usize, usize)> {
    let i0 = s.find(begin)?;
    let rest = &s[i0 + begin.len()..];
    let rel_end = rest.find(end)?;
    Some((i0, i0 + begin.len() + rel_end + end.len()))
}

/// Prefix `<server_key>__` when `marker_token` was produced by [`marker_token_from`].
fn server_key_prefix(marker_token: &str) -> Option<&str> {
    let (key, _) = marker_token.split_once("__")?;
    (!key.is_empty()).then_some(key)
}

/// Find a block matching `marker_token` exactly, or the first block matching the same
/// `<server_key>__*` prefix (e.g. from an earlier version of the same server).
fn find_server_block(s: &str, marker_token: &str) -> Option<(usize, usize, String)> {
    if let Some(key) = server_key_prefix(marker_token) {
        let prefix = format!("<!-- mcp-setup:{key}__");
        let suffix = ":begin -->";
        let mut search_from = 0;
        while let Some(rel) = s[search_from..].find(&prefix) {
            let start = search_from + rel;
            let after_prefix = start + "<!-- mcp-setup:".len();
            if let Some(end_rel) = s[after_prefix..].find(suffix) {
                let candidate_tok = &s[after_prefix..after_prefix + end_rel];
                if !candidate_tok.contains('\n') && !candidate_tok.contains(':') {
                    let (ob, oe) = marker_delimiters(candidate_tok);
                    if let Some((b0, b1)) = find_block(&s[start..], &ob, &oe) {
                        return Some((start + b0, start + b1, candidate_tok.to_string()));
                    }
                }
            }
            search_from = after_prefix;
        }
    }
    let (ob, oe) = marker_delimiters(marker_token);
    find_block(s, &ob, &oe).map(|(i0, i1)| (i0, i1, marker_token.to_string()))
}

/// Strip every block matching `marker_token` or its `<server_key>__*` prefix.
fn strip_all_server_blocks(s: &str, marker_token: &str) -> String {
    let mut current = s.to_string();
    while let Some((i0, i1, _)) = find_server_block(&current, marker_token) {
        let mut next = String::with_capacity(current.len());
        next.push_str(&current[..i0]);
        next.push_str(&current[i1..]);
        current = next;
    }
    current
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

    #[test]
    fn upsert_replaces_earlier_version_block_and_deduplicates() {
        let tok_v1 = marker_token_from("filesystem-mcp-rs:0.2.0", "filesystem-mcp-rs");
        let tok_v2 = marker_token_from("filesystem-mcp-rs:0.2.1", "filesystem-mcp-rs");
        let (s1, _) = upsert_marked_section("# Header\n", &tok_v1, "OLD_V1");
        let (s2, ch) = upsert_marked_section(&s1, &tok_v2, "NEW_V2");
        assert!(ch);
        assert!(!s2.contains("OLD_V1"));
        assert!(!s2.contains(&tok_v1));
        assert!(s2.contains("NEW_V2"));
        assert!(s2.contains(&tok_v2));

        let (removed, rch) = remove_marked_section(&s2, &tok_v1);
        assert!(rch);
        assert!(!removed.contains("NEW_V2"));
    }
}
