//! Detect NAME tokens that MCP hosts may delete from tool arguments.
//!
//! The host substitution happens *before* JSON-RPC reaches this server. If a
//! token is still present we refuse the call instead of running a silently
//! emptied command. If the host already stripped it, we cannot see it.

/// First ident / brace-form in `command` then `args`, if any.
pub fn first_in_command_and_args(command: &str, args: &[String]) -> Option<String> {
    if let Some(tok) = first_dollar_token(command) {
        return Some(tok);
    }
    for a in args {
        if let Some(tok) = first_dollar_token(a) {
            return Some(tok);
        }
    }
    None
}

/// DOLLAR followed by `{`, `_`, or an ASCII letter — the forms hosts interpolate.
pub fn first_dollar_token(s: &str) -> Option<String> {
    let dollar = '\u{24}';
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == dollar as u8 && i + 1 < bytes.len() {
            let n = bytes[i + 1];
            if n == b'{' || n == b'_' || n.is_ascii_alphabetic() {
                return Some(take_token(&s[i..]));
            }
        }
        i += 1;
    }
    None
}

fn take_token(from_dollar: &str) -> String {
    let mut chars = from_dollar.chars();
    let mut out = String::new();
    out.push(chars.next().expect("token starts with dollar"));
    match chars.next() {
        Some('{') => {
            out.push('{');
            for c in chars {
                out.push(c);
                if c == '}' {
                    break;
                }
            }
        }
        Some(c) => {
            out.push(c);
            for c in chars {
                if c.is_ascii_alphanumeric() || c == '_' {
                    out.push(c);
                } else {
                    break;
                }
            }
        }
        None => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d() -> char {
        '\u{24}'
    }

    #[test]
    fn finds_simple_ident() {
        let s = format!("& {}git clone", d());
        assert_eq!(first_dollar_token(&s).as_deref(), Some(&format!("{}git", d())[..]));
    }

    #[test]
    fn finds_env_style() {
        let s = format!("Write-Output {}env:PATH", d());
        assert_eq!(
            first_dollar_token(&s).as_deref(),
            Some(&format!("{}env", d())[..])
        );
    }

    #[test]
    fn finds_brace() {
        let s = format!("echo {}{{HOME}}", d());
        assert_eq!(
            first_dollar_token(&s).as_deref(),
            Some(&format!("{}{{HOME}}", d())[..])
        );
    }

    #[test]
    fn ignores_regex_end_anchor() {
        assert_eq!(first_dollar_token("grep 'foo$' file"), None);
    }

    #[test]
    fn scans_args_too() {
        let tok = format!("{}HOME", d());
        let args = vec![tok.clone()];
        assert_eq!(first_in_command_and_args("echo", &args), Some(tok));
    }

    #[test]
    fn clean_command_is_ok() {
        assert_eq!(first_in_command_and_args("git", &["status".into()]), None);
    }
}
