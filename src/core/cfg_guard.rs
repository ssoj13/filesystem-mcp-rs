//! Test-only guard: an item gated on a feature must not re-test that same feature inside itself.
//!
//! **The rule.** If an item carries a plain `#[cfg(feature = "X")]`, then inside that item there
//! must be no further test of the same `X` - neither the attribute again, nor its negation, nor a
//! `cfg!` expression. The inner condition is either always true (the item does not exist
//! otherwise) or always false, so it decides nothing, and the branch it guards is unreachable code
//! that reads as deliberate.
//!
//! **Why a guard and not a review note.** This shape cost a real defect. `Backend::screen` had its
//! attribute widened from one feature to a wider one while the body kept testing the narrow one.
//! The two spellings drifted apart, an OCR-only build compiled with no error and no warning,
//! reported that capture was available, and then refused every monitor capture and pixel read at
//! runtime. Four more instances were found afterwards in two further spellings: a `cfg!`
//! expression, which no search for an attribute finds, and a dead negated arm carrying its own
//! error message - which is exactly what makes the form look considered and survive edits.
//!
//! **What is allowed.** An inner condition on a *different* axis (a platform, another feature,
//! `test`), or one strictly narrower that really does choose between two live behaviours. Only the
//! same-feature case is refused, and only under a plain `feature = "X"` gate: `any(...)` and
//! `all(...)` are different conditions and this guard does not judge them.
//!
//! The scan is textual, like [`super::paths_guard`]: it reads every `.rs` file under `src/`
//! whatever this build compiles, which is the point - a defect gated out of the current build is
//! still a defect. It works in bytes throughout, because slicing a `&str` at an index that lands
//! inside a multi-byte character panics, and this crate's prose is full of em dashes - a guard
//! that crashes on the tree it scans is worse than no guard.

/// One violation: an item gated on `feature`, and the inner test of that same feature.
#[derive(Debug, PartialEq, Eq)]
pub struct Nested {
    pub file: String,
    /// 1-indexed line of the item's own `#[cfg]`.
    pub outer_line: usize,
    /// 1-indexed line of the redundant inner test.
    pub inner_line: usize,
    pub feature: String,
}

/// `needle` at or after `from`, by bytes.
fn find_bytes(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() || needle.len() > hay.len() - from {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|k| from + k)
}

/// For each byte of `text`, whether it is code rather than a comment or a string literal.
///
/// A map rather than a blanked-out copy, which is where a first attempt went wrong: an attribute
/// like `#[cfg(feature = "x")]` *contains* a string literal, so blanking literals erases the very
/// thing this guard searches for. Marking instead lets the search run over the real text and
/// simply ignore a hit that begins inside a comment or a literal - which is what keeps the guard
/// from reporting its own documentation and its own test fixtures.
fn code_map(text: &str) -> Vec<bool> {
    let b = text.as_bytes();
    let mut code = vec![true; b.len()];
    let mut i = 0usize;
    while i < b.len() {
        if b[i..].starts_with(b"//") {
            let stop = find_bytes(b, b"\n", i).unwrap_or(b.len());
            code[i..stop].fill(false);
            i = stop;
        } else if b[i..].starts_with(b"/*") {
            let stop = find_bytes(b, b"*/", i).map_or(b.len(), |k| k + 2);
            code[i..stop].fill(false);
            i = stop;
        } else if b[i] == b'"' {
            // A raw string is introduced by `r` and some `#`s, both already behind us.
            let mut hashes = 0usize;
            let mut j = i;
            while j > 0 && b[j - 1] == b'#' {
                hashes += 1;
                j -= 1;
            }
            let open = i;
            i += 1;
            if hashes > 0 && j > 0 && b[j - 1] == b'r' {
                let mut close = vec![b'"'];
                close.extend(std::iter::repeat_n(b'#', hashes));
                i = find_bytes(b, &close, i).map_or(b.len(), |k| k + close.len());
            } else {
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i = (i + 1).min(b.len());
            }
            // The quotes themselves stay code, so the attribute around them stays findable.
            let inner_end = i.saturating_sub(1).max(open + 1).min(b.len());
            code[(open + 1).min(b.len())..inner_end].fill(false);
        } else if b[i] == b'\'' {
            // A char literal, or a lifetime - which has no closing quote, and for which stepping
            // a single byte is right.
            i += if b[i..].starts_with(b"'\\") {
                find_bytes(b, b"'", i + 2).map_or(1, |k| k - i + 1)
            } else if b.len() - i > 2 && b[i + 2] == b'\'' {
                3
            } else {
                1
            };
        } else {
            i += 1;
        }
    }
    code
}

/// The next occurrence of `needle` at or after `from` that begins in code, if any.
fn find_in_code(text: &str, code: &[bool], from: usize, needle: &str) -> Option<usize> {
    let b = text.as_bytes();
    let n = needle.as_bytes();
    let mut at = from;
    while let Some(hit) = find_bytes(b, n, at) {
        if code.get(hit).copied().unwrap_or(false) {
            return Some(hit);
        }
        at = hit + 1;
    }
    None
}

/// Index just past the `{...}` block belonging to the item that starts at `i`.
///
/// `None` when the item has no block of its own: a `use`, a struct field, an enum variant, a trait
/// method declaration. That case matters. A `#[cfg]` on an enum variant is eventually followed by
/// some *other* item's `{`, and mistaking that for the variant's body would report every sibling
/// gate in the enclosing block. A `,` or `;` before any `{` is what says the item ended.
///
/// Braces inside comments and literals are skipped via `code`.
fn block_end(text: &str, code: &[bool], i: usize) -> Option<usize> {
    let b = text.as_bytes();
    let mut i = i;
    let is_code = |i: usize| code.get(i).copied().unwrap_or(false);
    while i < b.len() && !(b[i] == b'{' && is_code(i)) {
        if is_code(i) && (b[i] == b';' || b[i] == b',') {
            return None;
        }
        i += 1;
    }
    if i >= b.len() {
        return None;
    }
    let mut depth = 0usize;
    while i < b.len() {
        if is_code(i) {
            match b[i] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Every same-feature nesting under `dir`.
pub fn scan(dir: &std::path::Path) -> Vec<Nested> {
    let mut out = Vec::new();
    let mut files = Vec::new();
    walk(dir, &mut files);
    files.sort();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        scan_text(&path.to_string_lossy(), &text, &mut out);
    }
    out
}

fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The scan over one file's text. Separate from [`scan`] so the tests can feed it a string.
pub fn scan_text(file: &str, text: &str, out: &mut Vec<Nested>) {
    const OPEN: &str = "#[cfg(feature = \"";
    const CLOSE: &str = "\")]";

    let b = text.as_bytes();
    let code = code_map(text);
    let line_of = |byte: usize| {
        b[..byte.min(b.len())]
            .iter()
            .filter(|c| **c == b'\n')
            .count()
            + 1
    };

    let mut at = 0usize;
    while let Some(start) = find_in_code(text, &code, at, OPEN) {
        let open = start + OPEN.len();
        let Some(close) = find_bytes(b, CLOSE.as_bytes(), open) else {
            break;
        };
        at = close;

        // A feature name has no quotes, parens or commas in it; anything else means the gate is an
        // `any(...)`/`all(...)`, which this guard does not judge. `get` rather than a slice: the
        // bytes between are ASCII in every real gate, and a malformed one is skipped, not fatal.
        let Some(feature) = text.get(open..close) else {
            continue;
        };
        if feature.contains(['"', '(', ')', ',']) {
            continue;
        }
        let after = close + CLOSE.len();
        let Some(end) = block_end(text, &code, after) else {
            continue;
        };

        for needle in [
            format!("#[cfg(feature = \"{feature}\")]"),
            format!("#[cfg(not(feature = \"{feature}\"))]"),
            format!("cfg!(feature = \"{feature}\")"),
        ] {
            if let Some(hit) = find_in_code(text, &code, after, &needle)
                && hit < end
            {
                out.push(Nested {
                    file: file.to_owned(),
                    outer_line: line_of(start),
                    inner_line: line_of(hit),
                    feature: feature.to_owned(),
                });
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No item in this crate re-tests its own gate.
    ///
    /// The whole tree, not just the module the defect was found in: the shape is a habit rather
    /// than a property of one file, and it turned up in three of them.
    #[test]
    fn no_item_re_tests_its_own_feature_gate() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let found = scan(&src);
        assert!(
            found.is_empty(),
            "an item gated on a feature tests that same feature inside itself, so the inner \
             branch is unreachable and the two conditions can drift apart - which is how an \
             OCR-only build came to compile and then refuse every screen query: {found:#?}"
        );
    }

    /// All three spellings are caught, including the one no attribute search would find.
    #[test]
    fn all_three_spellings_are_caught() {
        for body in [
            "#[cfg(feature = \"x\")]\nfn f() {\n    #[cfg(feature = \"x\")]\n    { 1 }\n}\n",
            "#[cfg(feature = \"x\")]\nfn f() {\n    #[cfg(not(feature = \"x\"))]\n    { 1 }\n}\n",
            "#[cfg(feature = \"x\")]\nfn f() -> bool {\n    cfg!(feature = \"x\")\n}\n",
        ] {
            let mut out = Vec::new();
            scan_text("probe.rs", body, &mut out);
            assert_eq!(out.len(), 1, "missed a spelling: {body}");
            assert_eq!(out[0].feature, "x");
        }
    }

    /// The cases that must NOT be reported, each of which the crate really contains.
    ///
    /// Without these the guard would be noise: a platform gate inside a feature gate is how this
    /// crate separates OS code and cannot drift with the outer one; a `#[cfg]` on an enum variant
    /// is followed by some other item's braces; and the guard reads its own source, where these
    /// very fixtures live inside string literals.
    #[test]
    fn conditions_on_another_axis_and_items_without_a_body_are_not_violations() {
        for body in [
            "#[cfg(feature = \"x\")]\nfn f() {\n    #[cfg(windows)]\n    { 1 }\n}\n",
            "#[cfg(feature = \"x\")]\nfn f() {\n    #[cfg(feature = \"y\")]\n    { 1 }\n}\n",
            "#[cfg(any(feature = \"x\", feature = \"y\"))]\nfn f() {\n    #[cfg(feature = \"x\")]\n    { 1 }\n}\n",
            "enum E {\n    #[cfg(feature = \"x\")]\n    A,\n    #[cfg(feature = \"x\")]\n    B,\n}\n",
            "#[cfg(feature = \"x\")]\nfn f(&self) -> bool;\n",
            "// #[cfg(feature = \"x\")] fn f() { #[cfg(feature = \"x\")] {} }\n",
            "#[cfg(feature = \"x\")]\nfn f() {\n    let s = \"#[cfg(feature = \\\"x\\\")]\";\n}\n",
        ] {
            let mut out = Vec::new();
            scan_text("probe.rs", body, &mut out);
            assert!(out.is_empty(), "false positive on: {body}");
        }
    }

    /// Non-ASCII prose must not crash the scan.
    ///
    /// The first byte-unsafe version panicked on this crate's own comments: slicing a `&str` at an
    /// index inside a multi-byte character is a panic, and an em dash is three bytes.
    #[test]
    fn multibyte_prose_is_scanned_not_panicked_on() {
        let body = "// зачем — вот зачем\n#[cfg(feature = \"x\")]\nfn f() {\n    // ещё — раз\n    #[cfg(feature = \"x\")]\n    { 1 }\n}\n";
        let mut out = Vec::new();
        scan_text("probe.rs", body, &mut out);
        assert_eq!(out.len(), 1);
    }
}
