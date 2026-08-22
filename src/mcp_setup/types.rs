//! Shared vocabulary: scope, context, the install plan, and the three report shapes.

use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::mcp_setup::docs::HintDocs;
use crate::mcp_setup::error::{Result, SetupError};

/// Env key written into every managed MCP entry. It is what makes `uninstall` precise:
/// we only ever delete entries carrying *our* install id, never a hand-written one.
pub const INSTALL_ID_ENV_KEY: &str = "MCP_SETUP_INSTALL_ID";

/// Manifest scope slug for the user-global installation.
pub const SCOPE_USER: &str = "user";

/// Where an install lands: the user's global agent config, or one project tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    User,
    Project(PathBuf),
}

impl Scope {
    pub fn name(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project(_) => "project",
        }
    }

    pub fn project_root(&self) -> Option<&Path> {
        match self {
            Self::User => None,
            Self::Project(root) => Some(root),
        }
    }

    /// Stable per-scope id used in manifest file names. Hashing the canonical project path
    /// keeps the name short and filesystem-safe while staying stable across runs.
    pub fn slug(&self) -> Result<String> {
        match self {
            Self::User => Ok(SCOPE_USER.to_string()),
            Self::Project(root) => {
                ensure_project_root(root)?;
                let canon = std::fs::canonicalize(root).unwrap_or_else(|_| root.clone());
                let mut h = DefaultHasher::new();
                canon.to_string_lossy().hash(&mut h);
                Ok(format!("project_{:x}", h.finish()))
            }
        }
    }
}

pub fn ensure_project_root(root: &Path) -> Result<()> {
    if !root.exists() {
        return Err(SetupError::InvalidProjectRoot {
            path: root.to_path_buf(),
            reason: "path does not exist".to_string(),
        });
    }
    if !root.is_dir() {
        return Err(SetupError::InvalidProjectRoot {
            path: root.to_path_buf(),
            reason: "not a directory".to_string(),
        });
    }
    Ok(())
}

/// Per-run context. Home is injectable so the whole crate is testable against a temp dir.
#[derive(Debug, Clone)]
pub struct SetupContext {
    home_dir: PathBuf,
}

impl SetupContext {
    pub fn from_home(home_dir: PathBuf) -> Result<Self> {
        if home_dir.as_os_str().is_empty() {
            return Err(SetupError::InvalidHome);
        }
        Ok(Self { home_dir })
    }

    /// Uses [`dirs::home_dir`] (respects `HOME` / Windows profile).
    pub fn from_user_dirs() -> Result<Self> {
        let Some(h) = dirs::home_dir() else {
            return Err(SetupError::InvalidHome);
        };
        Self::from_home(h)
    }

    pub fn home_dir(&self) -> &Path {
        &self.home_dir
    }
}

/// A stdio MCP server: the binary, its argv tail, and its environment.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StdioMcpEntry {
    pub command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

/// Controls the "second level" of an install: a managed Markdown block inside the agent's
/// context file (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, …), so the agent learns *how* to use
/// the server, not just that it exists.
#[derive(Debug, Clone)]
pub struct HintsConfig {
    /// Off => only the MCP JSON/TOML entry is touched, no Markdown is written.
    pub enabled: bool,
    /// Replaces the rendered [`HintDocs`] body wholesale.
    pub body_override: Option<String>,
    /// A user-owned Markdown file merged as a preamble inside our managed block on every apply.
    /// Relative paths resolve against home (user scope) or the project root (project scope).
    pub snippet_source: Option<PathBuf>,
}

impl Default for HintsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            body_override: None,
            snippet_source: None,
        }
    }
}

/// Everything one client needs to install, remove, or inspect a registration.
#[derive(Debug, Clone)]
pub struct InstallPlan {
    /// Stable id written to [`INSTALL_ID_ENV_KEY`]; ownership marker for uninstall.
    pub install_id: String,
    /// Registry key: `mcpServers.<key>`, `mcp.<key>`, `mcp_servers.<key>`, … per client.
    pub mcp_server_key: String,
    pub stdio: StdioMcpEntry,
    pub hints: HintsConfig,
    /// Markdown the host wants injected into agent context files.
    pub docs: HintDocs,
    /// Overwrite an entry at [`mcp_server_key`](Self::mcp_server_key) that we do not own.
    ///
    /// Off by default: `install` refuses to touch a hand-written entry, because silently
    /// replacing someone's own configuration is worse than failing loudly. Turning it on is a
    /// deliberate "this key is mine now" — the previous content still goes to a timestamped
    /// backup first, and the apply report says an unmanaged entry was overwritten.
    pub force: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ApplyReport {
    pub client: &'static str,
    pub settings_path: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub manifest_path: PathBuf,
    pub changed: bool,
    /// Context file that received the managed block, when hints are enabled.
    pub hints_path: Option<PathBuf>,
    pub hints_changed: bool,
    pub hints_backup: Option<PathBuf>,
    /// Extra context for UIs (e.g. Codex fell back to TOML because `codex mcp add` failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RemoveReport {
    pub client: &'static str,
    pub settings_path: PathBuf,
    pub manifest_path: PathBuf,
    pub backup_path: Option<PathBuf>,
    pub removed: bool,
    pub hints_changed: bool,
    pub hints_backup: Option<PathBuf>,
}

/// Read-only view of one client/scope registration.
#[derive(Debug, Clone, Default, Serialize)]
pub struct StatusReport {
    pub client: &'static str,
    pub scope: String,
    pub settings_path: PathBuf,
    pub manifest_path: PathBuf,
    /// The agent itself appears to be installed (its config dir exists).
    pub host_detected: bool,
    /// Our key exists in the config (regardless of who wrote it).
    pub config_entry: bool,
    /// Our sidecar manifest exists.
    pub manifest: bool,
    /// Our key exists *and* carries our install id.
    pub installed: bool,
    /// The same binary is registered under a key we do not manage (hand-written entry).
    pub custom_installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found_install_id: Option<String>,
    /// The `command` string as it is actually written in the config, before any resolution.
    /// `None` when there is no entry to read one from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_command: Option<String>,
    /// Whether [`stored_command`](Self::stored_command) can actually be launched — the file
    /// exists, or a bare name is found on `PATH`. `None` when there is no entry.
    ///
    /// `Some(false)` alongside `installed` is the *broken* case: we own the entry, but it points
    /// at a binary that is gone (a build-tree path after `cargo clean`, a moved repo, an
    /// uninstalled server). Without this, such an entry is indistinguishable from a healthy one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_resolves: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}
