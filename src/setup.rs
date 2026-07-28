//! Registration of this binary as an MCP server in AI coding agents.
//!
//! The client matrix (config locations, ownership markers, backups, uninstall safety) lives in the
//! vendored `crate::mcp_setup` module. This module only declares what is specific to the filesystem
//! server: the registry key, the allowlist environment, and the Markdown the agent should read.

use std::collections::BTreeMap;

use crate::mcp_setup::Result;
use crate::mcp_setup::docs::{HintDocs, KARPATHY_RULES};
use crate::mcp_setup::host::HostSpec;

/// Registry key: `mcpServers.filesystem-mcp-rs` (and the equivalent in every other client).
pub const SERVER_KEY: &str = "filesystem-mcp-rs";

/// Session policy: this server is mandatory once connected. Written into the agent's context file.
const MCP_POLICY: &str = include_str!("docs/mcp_policy.md");
/// Concrete tool workflows (search_files / grep_files / run_command …).
const MCP_WORKFLOWS: &str = include_str!("docs/mcp_workflows.md");

/// Outbound HTTP allowlist written by `install` unless `--env FS_MCP_HTTP_ALLOW_LIST=...` overrides.
#[cfg(feature = "http-tools")]
const DEFAULT_HTTP_ALLOW_LIST: &str = "*";
/// S3 bucket allowlist written by `install` unless `--env FS_MCP_S3_ALLOW_LIST=...` overrides.
#[cfg(feature = "s3-tools")]
const DEFAULT_S3_ALLOW_LIST: &str = "*";

fn default_env() -> BTreeMap<String, String> {
    #[allow(unused_mut)]
    let mut env = BTreeMap::new();
    #[cfg(feature = "http-tools")]
    env.insert(
        "FS_MCP_HTTP_ALLOW_LIST".to_string(),
        DEFAULT_HTTP_ALLOW_LIST.to_string(),
    );
    #[cfg(feature = "s3-tools")]
    env.insert(
        "FS_MCP_S3_ALLOW_LIST".to_string(),
        DEFAULT_S3_ALLOW_LIST.to_string(),
    );
    env
}

/// Build the install spec: this executable, its allowlists, and its docs.
///
/// Allowed directories are not baked in here — they are the trailing arguments of
/// `filesystem-mcp-rs install <DIR>...`, which the CLI appends to the server command line.
pub fn host_spec() -> Result<HostSpec> {
    let install_id = format!("{SERVER_KEY}:{}", env!("CARGO_PKG_VERSION"));
    Ok(HostSpec::from_current_exe(SERVER_KEY, install_id)?
        .with_env(default_env())
        .with_docs(HintDocs::new([
            KARPATHY_RULES,
            MCP_POLICY,
            MCP_WORKFLOWS,
        ])))
}
