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

/// Arm-gate policy, appended only when this build can actually move the mouse.
#[cfg(any(feature = "ctl-input", feature = "ctl-uia"))]
const CTL_POLICY: &str = concat!(
    "== COMPUTER CONTROL POLICY ==\n",
    "This build can move the mouse and type into real windows. Input tools REQUIRE ",
    "`arm {ttl_ms}` first (TTL gate, ops-per-minute cap enforced).\n",
    "Read-only ctl tools (capture, monitors, win_list) work without arming.\n"
);

/// The context-file sections: policy, the arm gate when relevant, the env table, workflows.
///
/// The env table is rendered from [`crate::env_spec`] rather than written out here — the old
/// hand-maintained copy had already drifted from the code it documented.
fn hint_sections() -> Vec<String> {
    #[allow(unused_mut)]
    let mut policy = MCP_POLICY.to_string();
    #[cfg(any(feature = "ctl-input", feature = "ctl-uia"))]
    {
        policy.push('\n');
        policy.push_str(CTL_POLICY);
    }
    vec![
        KARPATHY_RULES.to_string(),
        policy,
        crate::env_spec::render_table(),
        MCP_WORKFLOWS.to_string(),
    ]
}
/// Concrete tool workflows (search_files / grep_files / run_command …).
const MCP_WORKFLOWS: &str = include_str!("docs/mcp_workflows.md");

/// Every knob this build supports, written into the client config with its default value.
///
/// JSON configs cannot hold comments, so the config *is* the documentation: a key present with
/// its default is the equivalent of a commented-out line, and changing behavior means editing a
/// value that is already in front of the user. Optional knobs (no meaningful default) are
/// written blank; `env_spec::get` reads blank as unset, so they stay no-ops until filled in.
fn default_env() -> BTreeMap<String, String> {
    crate::env_spec::vars()
        .into_iter()
        .map(|v| (v.key.to_string(), v.default.to_string()))
        .collect()
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
        .with_docs(HintDocs::new(hint_sections())))
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
