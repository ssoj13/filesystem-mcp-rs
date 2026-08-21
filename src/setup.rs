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
/// [`with_default_dirs`] fills those in with full-disk access when the user passed none.
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

/// Directories written into the server's command line when `install` is run with no trailing
/// `DIR` arguments: `/` on Unix, every mounted drive root on Windows.
///
/// Matches the "permissive by default, tighten later" posture already used for the HTTP/S3
/// allowlists in [`default_env`] — `install` with no extra flags should make the server
/// immediately useful rather than fail closed with "No allowed directories configured".
fn default_install_dirs() -> Vec<String> {
    #[cfg(unix)]
    {
        vec!["/".to_string()]
    }
    #[cfg(windows)]
    {
        ('A'..='Z')
            .map(|letter| format!("{letter}:\\"))
            .filter(|root| std::path::Path::new(root).exists())
            .collect()
    }
}

/// Fill in [`default_install_dirs`] as the `Install` subcommand's trailing directory arguments
/// when the user did not pass any. Leaves `Uninstall`/`Status` and an explicit directory list
/// untouched.
pub fn with_default_dirs(
    cmd: crate::mcp_setup::cli::SetupCommand,
) -> crate::mcp_setup::cli::SetupCommand {
    use crate::mcp_setup::cli::SetupCommand;
    match cmd {
        SetupCommand::Install(mut args) if args.server_args.is_empty() => {
            args.server_args = default_install_dirs();
            SetupCommand::Install(args)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_setup::cli::{InstallArgs, SetupCommand, TargetArgs};

    #[test]
    fn default_install_dirs_is_never_empty_on_a_real_machine() {
        assert!(!default_install_dirs().is_empty());
    }

    #[test]
    fn install_with_no_dirs_gets_the_default() {
        let cmd = SetupCommand::Install(InstallArgs::default());
        let SetupCommand::Install(args) = with_default_dirs(cmd) else {
            panic!("expected Install to stay Install");
        };
        assert_eq!(args.server_args, default_install_dirs());
    }

    #[test]
    fn install_with_explicit_dirs_is_left_alone() {
        let explicit = vec!["/only/this".to_string()];
        let cmd = SetupCommand::Install(InstallArgs {
            server_args: explicit.clone(),
            ..Default::default()
        });
        let SetupCommand::Install(args) = with_default_dirs(cmd) else {
            panic!("expected Install to stay Install");
        };
        assert_eq!(args.server_args, explicit);
    }

    #[test]
    fn status_and_uninstall_are_untouched() {
        let cmd = SetupCommand::Status(TargetArgs::default());
        assert!(matches!(with_default_dirs(cmd), SetupCommand::Status(_)));

        let cmd = SetupCommand::Uninstall(TargetArgs::default());
        assert!(matches!(with_default_dirs(cmd), SetupCommand::Uninstall(_)));
    }
}
