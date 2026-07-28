//! The client abstraction: one trait, one scope type, one context-file descriptor.
//!
//! Adding an agent means adding *data* (a [`crate::mcp_setup::json_client::JsonClient`] const) or, when the
//! config is not JSON, one `impl McpClient`. Nothing else in the crate changes.

use std::path::{Path, PathBuf};

use crate::mcp_setup::error::Result;
use crate::mcp_setup::types::{ApplyReport, InstallPlan, RemoveReport, Scope, SetupContext, StatusReport};

/// Where an agent auto-loads its Markdown rules from (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, …).
/// `None` for a scope means that agent has no context file there, so hints are skipped.
#[derive(Debug, Clone, Copy)]
pub struct ContextFile {
    pub user: Option<fn(&Path) -> PathBuf>,
    pub project: Option<fn(&Path) -> PathBuf>,
}

impl ContextFile {
    pub const NONE: Self = Self {
        user: None,
        project: None,
    };

    /// Resolve the context file for `scope`, given the user's home directory.
    pub fn path(&self, scope: &Scope, home: &Path) -> Option<PathBuf> {
        match scope {
            Scope::User => self.user.map(|f| f(home)),
            Scope::Project(root) => self.project.map(|f| f(root)),
        }
    }

    /// Base directory a relative snippet path resolves against.
    pub fn snippet_base(scope: &Scope, home: &Path) -> PathBuf {
        match scope {
            Scope::User => home.to_path_buf(),
            Scope::Project(root) => root.clone(),
        }
    }
}

/// One agent integration. Implementations must be side-effect free until `apply`/`remove`.
pub trait McpClient: Sync {
    /// Stable id used on the CLI (`--client claude`) and in manifest file names.
    fn id(&self) -> &'static str;
    /// Human label for reports.
    fn label(&self) -> &'static str;
    /// Short phrase naming where this client keeps MCP servers; rendered into the hint footer.
    fn config_hint(&self) -> &'static str;
    /// False when the agent has no per-project config (install falls back to user scope only).
    fn supports_project(&self) -> bool {
        true
    }

    /// The directory whose existence means "this agent is installed for this user". We never
    /// create it: an agent the user does not have is skipped, not conjured.
    fn user_marker_dir(&self, home: &Path) -> PathBuf;

    fn apply(&self, ctx: &SetupContext, scope: &Scope, plan: &InstallPlan) -> Result<ApplyReport>;
    fn remove(&self, ctx: &SetupContext, scope: &Scope, plan: &InstallPlan)
    -> Result<RemoveReport>;
    fn status(&self, ctx: &SetupContext, scope: &Scope, plan: &InstallPlan)
    -> Result<StatusReport>;
}
