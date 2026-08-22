//! Ready-made `install` / `uninstall` / `status` subcommands.
//!
//! A host binary flattens [`SetupCommand`] into its clap enum and calls [`run`] with its
//! [`HostSpec`]. Host-specific configuration reaches the server through `--env KEY=VALUE` and
//! trailing server arguments, so this CLI never needs to know what the server does.

use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

use crate::mcp_setup::client::McpClient;
use crate::mcp_setup::clients;
use crate::mcp_setup::error::SetupError;
use crate::mcp_setup::host::{self, HostSpec};
use crate::mcp_setup::types::{ApplyReport, RemoveReport, Scope, SetupContext, StatusReport};

type CliResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Subcommand, Debug)]
pub enum SetupCommand {
    /// Register this server in the supported MCP clients.
    Install(InstallArgs),
    /// Remove a registration created by `install` (same scope / key / install id).
    Uninstall(TargetArgs),
    /// Show where this server is registered.
    Status(TargetArgs),
}

#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ScopeArg {
    /// The user's global agent configs.
    #[default]
    User,
    /// One project tree (defaults to the current directory).
    Project,
}

/// Flags shared by all three subcommands.
#[derive(Args, Debug, Clone, Default)]
pub struct TargetArgs {
    #[arg(long, value_enum, default_value_t = ScopeArg::User)]
    pub scope: ScopeArg,

    /// Client to act on; repeat for several. Defaults to every supported client.
    #[arg(long = "client", value_name = "CLIENT", action = clap::ArgAction::Append)]
    pub clients: Vec<String>,

    /// With `--scope project`: the project root (default: current directory).
    #[arg(long, value_name = "DIR")]
    pub project: Option<PathBuf>,

    /// Override the registry key (only if you installed under a non-default key).
    #[arg(long, value_name = "KEY")]
    pub server_key: Option<String>,

    /// Override the install id (only if you installed under a non-default id).
    #[arg(long, value_name = "ID")]
    pub install_id: Option<String>,
}

#[derive(Args, Debug, Clone, Default)]
pub struct InstallArgs {
    #[command(flatten)]
    pub target: TargetArgs,

    /// Extra environment for the server process, e.g. `--env SG_SERVER=https://...`.
    #[arg(long = "env", value_name = "KEY=VALUE", action = clap::ArgAction::Append)]
    pub env: Vec<String>,

    /// Do not touch agent context files (`CLAUDE.md`, `AGENTS.md`, …); only write MCP config.
    #[arg(long, default_value_t = false)]
    pub no_hints: bool,

    /// Markdown file merged as a user preamble inside the managed hints block. Relative paths
    /// resolve against home (user scope) or the project root (project scope).
    #[arg(long, value_name = "PATH")]
    pub hints_snippet: Option<PathBuf>,

    /// Arguments appended to the server's command line in the generated config.
    #[arg(value_name = "SERVER_ARG", trailing_var_arg = true)]
    pub server_args: Vec<String>,
}

fn parse_env(pairs: &[String]) -> CliResult<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for p in pairs {
        let Some((k, v)) = p.split_once('=') else {
            return Err(format!("--env must be KEY=VALUE, got {p:?}").into());
        };
        let k = k.trim();
        if k.is_empty() {
            return Err(format!("--env has an empty key in {p:?}").into());
        }
        out.insert(k.to_string(), v.to_string());
    }
    Ok(out)
}

fn resolve_scope(args: &TargetArgs) -> CliResult<Scope> {
    Ok(match args.scope {
        ScopeArg::User => Scope::User,
        ScopeArg::Project => Scope::Project(match &args.project {
            Some(p) => p.clone(),
            None => std::env::current_dir()?,
        }),
    })
}

fn resolve_clients(args: &TargetArgs) -> CliResult<Vec<&'static dyn McpClient>> {
    if args.clients.is_empty() {
        return Ok(clients::all());
    }
    let mut out: Vec<&'static dyn McpClient> = Vec::new();
    for name in &args.clients {
        let client = clients::by_id(name).ok_or_else(|| SetupError::UnknownClient(name.clone()))?;
        if !out.iter().any(|c| c.id() == client.id()) {
            out.push(client);
        }
    }
    Ok(out)
}

/// CLI overrides applied on top of what the host declared.
fn effective_spec(
    base: &HostSpec,
    target: &TargetArgs,
    install: Option<&InstallArgs>,
) -> CliResult<HostSpec> {
    let mut spec = base.clone();
    if let Some(key) = &target.server_key {
        spec.server_key = key.clone();
    }
    if let Some(id) = &target.install_id {
        spec.install_id = id.clone();
    }
    if let Some(args) = install {
        spec.env.extend(parse_env(&args.env)?);
        spec.args.extend(args.server_args.iter().cloned());
        spec.hints.enabled = !args.no_hints;
        spec.hints.snippet_source = args.hints_snippet.clone();
    }
    Ok(spec)
}

/// Run one subcommand against every selected client, print a table, and fail if any target did.
/// Whether a sweep finished cleanly.
///
/// Returned as a value rather than raised as an error: a client that is broken or unreachable is
/// a *result*, already spelled out in the table, not an internal failure. Raising it made hosts
/// wrap it in their error type and print an error chain — and, under `RUST_BACKTRACE=1`, a full
/// Rust backtrace — on top of a perfectly readable table. Genuine failures (an unknown client, a
/// malformed `--env`, no resolvable home) still come back as `Err`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Outcome {
    AllOk,
    SomeFailed,
}

impl Outcome {
    /// Process exit code for this outcome: 0 clean, 1 if any target failed.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::AllOk => 0,
            Self::SomeFailed => 1,
        }
    }

    pub fn all_ok(self) -> bool {
        matches!(self, Self::AllOk)
    }
}

pub fn run(cmd: &SetupCommand, base: &HostSpec) -> CliResult<Outcome> {
    let ctx = SetupContext::from_user_dirs()?;
    let (target, install) = match cmd {
        SetupCommand::Install(a) => (&a.target, Some(a)),
        SetupCommand::Uninstall(t) | SetupCommand::Status(t) => (t, None),
    };
    let spec = effective_spec(base, target, install)?;
    let scope = resolve_scope(target)?;

    let mut rows = Vec::new();
    for client in resolve_clients(target)? {
        rows.push(match cmd {
            SetupCommand::Install(_) => {
                apply_row(client.label(), host::install(&ctx, client, &scope, &spec))
            }
            SetupCommand::Uninstall(_) => {
                remove_row(client.label(), host::uninstall(&ctx, client, &scope, &spec))
            }
            SetupCommand::Status(_) => {
                status_row(client.label(), host::status(&ctx, client, &scope, &spec))
            }
        });
    }

    let failed = rows.iter().any(|r| !r.ok);
    print_table(&rows);
    Ok(if failed {
        Outcome::SomeFailed
    } else {
        Outcome::AllOk
    })
}

// --- table ---------------------------------------------------------------------------------

#[derive(Debug)]
struct Row {
    target: String,
    status: String,
    ok: bool,
    detail: String,
}

/// A client the user does not have installed — or one that has no config for this scope — is not
/// an error when we are sweeping every client: it is simply skipped.
fn skip_or_fail(label: &str, e: SetupError) -> Row {
    let skip_detail = match &e {
        SetupError::HostNotDetected { hint, .. } => Some(hint.clone()),
        SetupError::UnsupportedScope { scope, .. } => Some(format!("no {scope}-scope config")),
        _ => None,
    };
    match skip_detail {
        Some(detail) => Row {
            target: label.to_string(),
            status: "skipped".to_string(),
            ok: true,
            detail,
        },
        None => Row {
            target: label.to_string(),
            status: "failed".to_string(),
            ok: false,
            detail: e.to_string(),
        },
    }
}

fn apply_row(label: &str, res: crate::mcp_setup::error::Result<ApplyReport>) -> Row {
    match res {
        Ok(r) => Row {
            target: label.to_string(),
            status: if r.changed { "ok" } else { "unchanged" }.to_string(),
            ok: true,
            detail: format!(
                "config={}; hints={}; backup={}{}",
                r.settings_path.display(),
                r.hints_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "-".to_string()),
                r.backup_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "-".to_string()),
                r.note.map(|n| format!("; note={n}")).unwrap_or_default(),
            ),
        },
        Err(e) => skip_or_fail(label, e),
    }
}

fn remove_row(label: &str, res: crate::mcp_setup::error::Result<RemoveReport>) -> Row {
    match res {
        Ok(r) => Row {
            target: label.to_string(),
            status: if r.removed || r.hints_changed {
                "removed"
            } else {
                "not installed"
            }
            .to_string(),
            ok: true,
            detail: format!(
                "config={}; hints_changed={}; backup={}",
                r.settings_path.display(),
                r.hints_changed,
                r.backup_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
        },
        Err(e) => skip_or_fail(label, e),
    }
}

fn status_row(label: &str, res: crate::mcp_setup::error::Result<StatusReport>) -> Row {
    match res {
        Ok(r) => {
            // An entry we own whose command no longer resolves is *broken*, not installed:
            // the agent will fail to spawn it. Reported as not-ok so a sweep's exit code and a
            // CI check both notice, and `install` is named as the repair.
            let dangling = r.command_resolves == Some(false);
            let state = if !r.host_detected {
                "not detected"
            } else if r.installed && dangling {
                "broken"
            } else if r.installed {
                "installed"
            } else if r.custom_installed {
                "custom"
            } else if r.config_entry {
                "conflict"
            } else {
                "not installed"
            };
            let broken_detail = (r.host_detected && dangling).then(|| {
                format!(
                    "; command={:?} does not resolve — re-run `install` to repair",
                    r.stored_command.as_deref().unwrap_or_default()
                )
            });
            Row {
                target: label.to_string(),
                status: state.to_string(),
                ok: state != "broken",
                detail: format!(
                    "scope={}; config={}; manifest={}{}{}",
                    r.scope,
                    r.settings_path.display(),
                    r.manifest,
                    broken_detail.unwrap_or_default(),
                    r.note.map(|n| format!("; note={n}")).unwrap_or_default(),
                ),
            }
        }
        Err(e) => skip_or_fail(label, e),
    }
}

fn print_table(rows: &[Row]) {
    const W0: usize = 22;
    const W1: usize = 14;
    const W2: usize = 86;
    let line = |l: char, m: char, r: char| {
        println!(
            "{l}{}{m}{}{m}{}{r}",
            "─".repeat(W0 + 2),
            "─".repeat(W1 + 2),
            "─".repeat(W2 + 2)
        );
    };
    let row = |a: &str, b: &str, c: &str| {
        println!("│ {a:<W0$} │ {b:<W1$} │ {c:<W2$} │");
    };

    line('┌', '┬', '┐');
    row("Target", "Status", "Detail");
    line('├', '┼', '┤');
    for r in rows {
        let flat = r.detail.lines().collect::<Vec<_>>().join(" ");
        let detail = if flat.chars().count() > W2 {
            format!(
                "{}…",
                flat.chars().take(W2.saturating_sub(1)).collect::<String>()
            )
        } else {
            flat
        };
        row(&r.target, &r.status, &detail);
    }
    line('└', '┴', '┘');
}
