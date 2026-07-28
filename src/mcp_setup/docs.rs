//! Host-supplied Markdown for agent context files.
//!
//! The crate knows *where* each agent reads its rules from; it does not know what your server
//! is for. So the host passes [`HintDocs`] — ordered Markdown sections — and the crate renders
//! them into the managed block, appending a per-client footer that names the registry key.
//!
//! Placeholders substituted at render time:
//! - `{{MCP_SERVER_KEY}}` — the registry key (e.g. `filesystem-mcp-rs`)
//! - `{{CLIENT_LABEL}}` — human client name (e.g. `Claude Code`)
//! - `{{CLIENT_CONFIG}}` — where this client stores MCP servers

/// Generic engineering rules (no server-specific content) that hosts may prepend to their docs.
pub const KARPATHY_RULES: &str = include_str!("docs/karpathy_rules.md");

/// Ordered Markdown sections rendered inside the managed block. Empty => no context file is
/// touched at all, even when hints are enabled.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HintDocs {
    pub sections: Vec<String>,
}

impl HintDocs {
    pub fn new<I, S>(sections: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            sections: sections.into_iter().map(Into::into).collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.sections.iter().all(|s| s.trim().is_empty())
    }

    /// Render the managed body for one client. Returns an empty string when there is nothing
    /// to say — callers treat that as "leave the context file alone".
    pub fn render(&self, server_key: &str, client_label: &str, client_config: &str) -> String {
        if self.is_empty() {
            return String::new();
        }
        let mut out = String::new();
        for section in self.sections.iter().filter(|s| !s.trim().is_empty()) {
            if !out.is_empty() {
                out.push_str("\n\n---\n\n");
            }
            out.push_str(section.trim());
        }
        out.push_str(&format!(
            "\n\n---\n\nManaged MCP server key: `{server_key}` ({client_config})."
        ));
        subst(&out, server_key, client_label, client_config)
    }
}

fn subst(text: &str, server_key: &str, client_label: &str, client_config: &str) -> String {
    text.replace("{{MCP_SERVER_KEY}}", server_key)
        .replace("{{CLIENT_LABEL}}", client_label)
        .replace("{{CLIENT_CONFIG}}", client_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_docs_render_to_nothing() {
        assert!(HintDocs::default().render("k", "l", "c").is_empty());
        assert!(HintDocs::new(["  \n "]).render("k", "l", "c").is_empty());
    }

    #[test]
    fn sections_are_joined_and_placeholders_substituted() {
        let docs = HintDocs::new(["A: {{MCP_SERVER_KEY}}", "B: {{CLIENT_LABEL}}"]);
        let out = docs.render("srv", "Claude Code", "`mcpServers` in `~/.claude.json`");
        assert!(out.contains("A: srv"));
        assert!(out.contains("B: Claude Code"));
        assert!(out.contains("---"));
        assert!(out.contains("Managed MCP server key: `srv`"));
    }
}
