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
        // The footer names the server, not the client, and that is deliberate.
        //
        // Several agents share one context file - `AGENTS.md` serves Codex,
        // Grok, Cursor, OpenCode, Amp, Kiro and Roo - while the managed block
        // is keyed by (server, install id) alone. A footer that named the
        // client therefore made every one of them rewrite the block the
        // previous one had just written: an install touching three such
        // agents left three backups behind and reported "changed" forever,
        // with the footer naming whichever client ran last.
        //
        // Where the server is configured is a question `status` answers
        // exactly, per client. A host that still wants client-specific text
        // can put {{CLIENT_LABEL}} or {{CLIENT_CONFIG}} in its own sections,
        // and is then opting into that churn knowingly.
        out.push_str(&format!(
            "\n\n---\n\nManaged MCP server key: `{server_key}`."
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

    /// Two clients sharing a context file must render the same bytes, or they
    /// overwrite each other's block on every install.
    #[test]
    fn the_body_does_not_depend_on_which_client_is_installing() {
        let docs = HintDocs::new(["Use `note_append` to record something durable."]);
        let codex = docs.render("srv", "Codex", "`mcp_servers` in `~/.codex/config.toml`");
        let zed = docs.render("srv", "Zed", "`context_servers` in Zed's `settings.json`");
        assert_eq!(codex, zed);
    }

    /// Unless the host asks for it, which is a deliberate opt-in.
    #[test]
    fn a_host_can_still_ask_for_client_specific_text() {
        let docs = HintDocs::new(["Configured in {{CLIENT_CONFIG}} for {{CLIENT_LABEL}}."]);
        let out = docs.render("srv", "Zed", "`context_servers`");
        assert!(out.contains("for Zed"));
        assert!(out.contains("`context_servers`"));
    }
}
