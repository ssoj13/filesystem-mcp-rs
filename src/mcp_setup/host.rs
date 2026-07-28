//! What the *hosting* MCP server tells us about itself, plus the three top-level operations.
//!
//! A host builds one [`HostSpec`] and hands it to [`install`] / [`uninstall`] / [`status`] for
//! each client it wants to touch. Everything client-specific lives in `clients/`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::mcp_setup::client::McpClient;
use crate::mcp_setup::docs::HintDocs;
use crate::mcp_setup::error::{Result, SetupError};
use crate::mcp_setup::types::{
    ApplyReport, HintsConfig, InstallPlan, RemoveReport, Scope, SetupContext, StatusReport,
    StdioMcpEntry,
};

/// Identity and launch recipe of the MCP server being installed.
#[derive(Debug, Clone)]
pub struct HostSpec {
    /// Registry key, e.g. `shotgrid-mcp-rs`. One per server, stable across versions.
    pub server_key: String,
    /// Ownership marker, e.g. `shotgrid-mcp-rs:0.9.6`. Changing it makes the next `uninstall`
    /// refuse to touch the old entry, so keep it stable unless you mean to fork the install.
    pub install_id: String,
    /// Absolute path to the server binary.
    pub command: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub hints: HintsConfig,
    pub docs: HintDocs,
}

impl HostSpec {
    /// `command` defaults to the current executable — the common case for a server installing
    /// itself. Resolved through `canonicalize` so the config records a stable absolute path.
    pub fn from_current_exe(server_key: impl Into<String>, install_id: impl Into<String>) -> Result<Self> {
        let exe = std::env::current_exe().map_err(|e| SetupError::io(PathBuf::new(), e))?;
        Ok(Self::new(server_key, install_id, normalize_path(&exe)))
    }

    pub fn new(
        server_key: impl Into<String>,
        install_id: impl Into<String>,
        command: impl Into<String>,
    ) -> Self {
        Self {
            server_key: server_key.into(),
            install_id: install_id.into(),
            command: command.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            hints: HintsConfig::default(),
            docs: HintDocs::default(),
        }
    }

    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_env<I, K, V>(mut self, env: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.env = env
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self
    }

    pub fn with_docs(mut self, docs: HintDocs) -> Self {
        self.docs = docs;
        self
    }

    pub fn plan(&self) -> Result<InstallPlan> {
        if self.command.trim().is_empty() {
            return Err(SetupError::InvalidBundle(
                "command (path to the MCP server binary) is empty".to_string(),
            ));
        }
        if self.server_key.trim().is_empty() {
            return Err(SetupError::InvalidBundle("server_key is empty".to_string()));
        }
        Ok(InstallPlan {
            install_id: self.install_id.clone(),
            mcp_server_key: self.server_key.clone(),
            stdio: StdioMcpEntry {
                command: self.command.clone(),
                args: self.args.clone(),
                env: self.env.clone(),
            },
            hints: self.hints.clone(),
            docs: self.docs.clone(),
        })
    }
}

/// Absolute path with symlinks resolved; falls back to the input when the path cannot be
/// canonicalized (e.g. it does not exist yet).
pub fn normalize_path(p: &Path) -> String {
    std::fs::canonicalize(p)
        .unwrap_or_else(|_| p.to_path_buf())
        .to_string_lossy()
        .to_string()
}

fn check_scope(client: &dyn McpClient, scope: &Scope) -> Result<()> {
    if matches!(scope, Scope::Project(_)) && !client.supports_project() {
        return Err(SetupError::UnsupportedScope {
            client: client.label(),
            scope: "project",
        });
    }
    Ok(())
}

pub fn install(
    ctx: &SetupContext,
    client: &dyn McpClient,
    scope: &Scope,
    spec: &HostSpec,
) -> Result<ApplyReport> {
    check_scope(client, scope)?;
    client.apply(ctx, scope, &spec.plan()?)
}

pub fn uninstall(
    ctx: &SetupContext,
    client: &dyn McpClient,
    scope: &Scope,
    spec: &HostSpec,
) -> Result<RemoveReport> {
    check_scope(client, scope)?;
    client.remove(ctx, scope, &spec.plan()?)
}

pub fn status(
    ctx: &SetupContext,
    client: &dyn McpClient,
    scope: &Scope,
    spec: &HostSpec,
) -> Result<StatusReport> {
    check_scope(client, scope)?;
    client.status(ctx, scope, &spec.plan()?)
}
