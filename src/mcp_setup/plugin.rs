//! The plugin channel: installing a whole plugin instead of one MCP entry.
//!
//! Some hosts have grown a plugin system, and where one exists it is the better
//! channel by a wide margin. An MCP entry registers a server and nothing else; a
//! plugin carries its skills, its hooks, its agents and its commands as well, in
//! one artifact the host knows how to update and remove. For a server that ships
//! inside a plugin anyway, writing a separate MCP entry is not just redundant -
//! it registers the same server twice, and the model then sees every tool twice.
//!
//! # Why this is not a field on the client structs
//!
//! [`crate::mcp_setup::json_client::JsonClient`] and [`crate::mcp_setup::toml_client::TomlClient`]
//! describe a *config file*: where it lives, what dialect it speaks, which key
//! holds the servers. Whether the host also ships a plugin manager is a property
//! of the host *program*, not of its config file, and only two of the eighteen
//! have one. A table here keyed by client id says that without adding a field
//! that sixteen clients would have to spell `None`.
//!
//! # Ownership
//!
//! Nothing here writes a config file, so there is no install-id marker to plant
//! and none to look for. The host's own plugin manager records the installation
//! and is asked about it - `status` runs `plugin list` rather than guessing from
//! a file. Removing is likewise the host's job.

use std::fs::File;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use crate::mcp_setup::agent_cli::agent_command;
use crate::mcp_setup::error::{Result, SetupError};
use crate::mcp_setup::types::Scope;

/// The plugin to install, and where the host should fetch it from.
#[derive(Debug, Clone)]
pub struct PluginSpec {
    /// Plugin name, as its manifest declares it.
    pub name: String,
    /// Marketplace id the host will file it under. For a single-plugin
    /// repository this is usually the same string as [`name`](Self::name).
    pub marketplace: String,
    /// What the host's `plugin marketplace add` is given: a Git URL (https or
    /// ssh), an `owner/repo` shorthand, or a local path.
    pub source: String,
}

/// How one host spells the three verbs. Everything else about the two known
/// plugin managers is identical, down to `plugin marketplace add <source>`.
#[derive(Debug, Clone, Copy)]
pub struct PluginCli {
    pub program: &'static str,
    /// `claude plugin **install**` but `codex plugin **add**`.
    pub install: &'static str,
    /// `claude plugin **uninstall**` but `codex plugin **remove**`.
    pub remove: &'static str,
}

/// Hosts with a plugin manager, by the client id used on `--client`.
///
/// Both read Claude Code plugin repositories, which is why one plugin can serve
/// them both without a second packaging step.
const CLIS: [(&str, PluginCli); 2] = [
    (
        "claude",
        PluginCli {
            program: "claude",
            install: "install",
            remove: "uninstall",
        },
    ),
    (
        "codex",
        PluginCli {
            program: "codex",
            install: "add",
            remove: "remove",
        },
    ),
];

/// The plugin manager for this client, if it has one.
pub fn cli_for(client_id: &str) -> Option<PluginCli> {
    CLIS.iter()
        .find(|(id, _)| *id == client_id)
        .map(|(_, cli)| *cli)
}

/// Whether the plugin channel applies at all.
///
/// Project scope is excluded deliberately: both plugin managers install for the
/// user, and pretending otherwise would report a project-scoped install that
/// does not exist. A project-scoped request falls through to the MCP entry,
/// which really is per project.
pub fn applies(client_id: &str, scope: &Scope, spec: Option<&PluginSpec>) -> Option<PluginCli> {
    if !matches!(scope, Scope::User) {
        return None;
    }
    spec?;
    cli_for(client_id)
}

/// `<plugin>@<marketplace>`, the selector both managers accept.
fn selector(spec: &PluginSpec) -> String {
    format!("{}@{}", spec.name, spec.marketplace)
}

fn failed(cli: &PluginCli, what: &str, detail: String) -> SetupError {
    SetupError::CodexConfigFailed {
        detail: format!("`{} plugin {what}` failed: {detail}", cli.program),
    }
}

/// How long a read-only query may take before it is abandoned.
///
/// Generous rather than tight: `codex plugin list` contacts a remote catalog and
/// takes about ten seconds on a good day. The point is not to be quick, it is to
/// be *bounded* - `status` is a diagnostic and must not be capable of blocking
/// forever on somebody else's network call.
const QUERY_LIMIT: Duration = Duration::from_secs(45);

/// How long a change may take. It clones a repository, so minutes are normal.
const CHANGE_LIMIT: Duration = Duration::from_secs(600);

/// What one invocation did.
enum Outcome {
    Succeeded(String),
    /// Ran to completion and reported failure; the payload is its stderr.
    Failed(String),
    /// Never finished within its limit, and was killed.
    TimedOut,
    /// Could not be started at all.
    Unavailable(String),
}

/// Run one `<program> plugin ...` invocation under a time limit.
///
/// Two deliberate choices, both learned the hard way:
///
/// **Output goes to temporary files, not pipes.** A CLI that leaves a
/// background process holding the write end keeps the pipe open after the
/// command itself has exited, and `Command::output()` then waits for an EOF that
/// never comes. A file has no such end to wait for.
///
/// **The wait is polled, not blocking.** `wait()` cannot be interrupted, so a
/// manager that stalls - prompting on a console it inherited, or waiting on a
/// network that is not answering - would take the caller with it.
fn run(cli: &PluginCli, args: &[&str], limit: Duration) -> Outcome {
    let stamp = std::process::id();
    let out_path = std::env::temp_dir().join(format!("mcp-setup-{stamp}-{}.out", cli.program));
    let err_path = out_path.with_extension("err");

    let (Ok(out_file), Ok(err_file)) = (File::create(&out_path), File::create(&err_path)) else {
        return Outcome::Unavailable("cannot create a temporary file for the output".to_string());
    };

    let mut command = agent_command(cli.program);
    command.arg("plugin");
    for arg in args {
        command.arg(arg);
    }
    // No stdin: a manager that decides to prompt fails instead of waiting for an
    // answer that is never coming.
    command.stdin(Stdio::null());
    command.stdout(Stdio::from(out_file));
    command.stderr(Stdio::from(err_file));

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            cleanup(&out_path, &err_path);
            return Outcome::Unavailable(format!("could not run `{}`: {error}", cli.program));
        }
    };

    let status = match wait_bounded(&mut child, limit) {
        Ok(status) => status,
        Err(error) => {
            cleanup(&out_path, &err_path);
            return Outcome::Unavailable(format!("could not wait for `{}`: {error}", cli.program));
        }
    };

    let stdout = std::fs::read_to_string(&out_path).unwrap_or_default();
    let stderr = std::fs::read_to_string(&err_path).unwrap_or_default();
    cleanup(&out_path, &err_path);

    match status {
        None => Outcome::TimedOut,
        Some(status) if status.success() => Outcome::Succeeded(stdout),
        Some(status) => {
            let stderr = stderr.trim().to_string();
            Outcome::Failed(if stderr.is_empty() {
                format!("exited with {status}")
            } else {
                stderr
            })
        }
    }
}

/// Wait for `child`, killing it once `limit` has passed.
///
/// `Ok(None)` means it had to be killed. Separated from [`run`] so the part that
/// can hang is the part a test can drive with a real slow process.
fn wait_bounded(
    child: &mut std::process::Child,
    limit: Duration,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    let started = Instant::now();
    loop {
        match child.try_wait()? {
            Some(status) => return Ok(Some(status)),
            None if started.elapsed() >= limit => {
                child.kill()?;
                child.wait()?;
                return Ok(None);
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn cleanup(out_path: &Path, err_path: &Path) {
    let _ = std::fs::remove_file(out_path);
    let _ = std::fs::remove_file(err_path);
}

/// Register the marketplace, then install the plugin from it.
///
/// Adding a marketplace that is already registered is not treated as a failure:
/// both managers refuse the duplicate, and on a second `install` that refusal is
/// the expected answer, not a problem. Only the install itself is required to
/// succeed - if the marketplace really is missing, that is what it will say.
pub fn apply(cli: &PluginCli, spec: &PluginSpec) -> Result<String> {
    let marketplace = run(cli, &["marketplace", "add", &spec.source], CHANGE_LIMIT);
    let selector = selector(spec);

    match run(cli, &[cli.install, &selector], CHANGE_LIMIT) {
        Outcome::Succeeded(_) => Ok(format!("plugin {selector} via `{} plugin`", cli.program)),
        Outcome::TimedOut => Err(failed(
            cli,
            cli.install,
            format!("still running after {}s; killed", CHANGE_LIMIT.as_secs()),
        )),
        Outcome::Failed(detail) | Outcome::Unavailable(detail) => {
            // Naming both halves matters: "plugin not found" reads very
            // differently once you know the marketplace was never added.
            let detail = match &marketplace {
                Outcome::Failed(first) | Outcome::Unavailable(first) => {
                    format!("{detail}; adding the marketplace also failed: {first}")
                }
                Outcome::TimedOut => format!("{detail}; adding the marketplace timed out"),
                Outcome::Succeeded(_) => detail,
            };
            Err(failed(cli, cli.install, detail))
        }
    }
}

/// Uninstall the plugin. The marketplace is left registered: the user may have
/// other plugins from it, and removing it would take those with it.
pub fn remove(cli: &PluginCli, spec: &PluginSpec) -> Result<bool> {
    match run(cli, &[cli.remove, &spec.name], CHANGE_LIMIT) {
        Outcome::Succeeded(_) => Ok(true),
        // Not installed is the same end state the caller asked for, and both
        // managers report it as a failure. Distinguishing it from a real error
        // by parsing prose would break on the next wording change, so this
        // reports "nothing was removed" instead of inventing a certainty.
        Outcome::Failed(_) | Outcome::Unavailable(_) => Ok(false),
        Outcome::TimedOut => Err(failed(
            cli,
            cli.remove,
            format!("still running after {}s; killed", CHANGE_LIMIT.as_secs()),
        )),
    }
}

/// Ask the host whether the plugin is installed.
///
/// `plugin list` prints the installed plugins; a `None` answer means the manager
/// itself could not be run, which is not the same as "not installed" and must
/// not be reported as one.
pub fn installed(cli: &PluginCli, spec: &PluginSpec) -> Option<bool> {
    match run(cli, &["list"], QUERY_LIMIT) {
        Outcome::Succeeded(listing) => {
            Some(listing.contains(&selector(spec)) || listing.contains(&spec.name))
        }
        // A manager that failed, could not start, or had to be killed has told
        // us nothing about whether the plugin is there. Saying "not installed"
        // here would turn a slow network into a confident lie.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_hosts_with_a_plugin_manager_have_one() {
        assert!(cli_for("claude").is_some());
        assert!(cli_for("codex").is_some());
        assert!(cli_for("cursor").is_none());
        assert!(cli_for("zed").is_none());
    }

    #[test]
    fn the_two_managers_spell_the_verbs_differently() {
        assert_eq!(cli_for("claude").expect("claude").install, "install");
        assert_eq!(cli_for("codex").expect("codex").install, "add");
    }

    #[test]
    fn the_channel_is_user_scope_only() {
        let spec = PluginSpec {
            name: "p".into(),
            marketplace: "m".into(),
            source: "o/r".into(),
        };
        assert!(applies("codex", &Scope::User, Some(&spec)).is_some());
        assert!(applies("codex", &Scope::Project("/tmp".into()), Some(&spec)).is_none());
        // No plugin in the spec: the MCP entry remains the only channel.
        assert!(applies("codex", &Scope::User, None).is_none());
    }

    /// A process that outlasts its limit is killed, and the wait returns.
    ///
    /// The regression this guards: `status` shells out to two plugin managers,
    /// one of which contacts a remote catalog. Before this, a manager that never
    /// answered took the whole diagnostic with it.
    #[test]
    fn a_process_that_overruns_is_killed() {
        let mut sleeper = if cfg!(windows) {
            // No `sleep` on Windows; a ping to loopback is the usual stand-in.
            let mut c = std::process::Command::new("cmd");
            c.args(["/C", "ping", "-n", "30", "127.0.0.1"]);
            c
        } else {
            let mut c = std::process::Command::new("sleep");
            c.arg("30");
            c
        };
        let mut child = sleeper
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the sleeper starts");

        let started = Instant::now();
        let status = wait_bounded(&mut child, Duration::from_millis(300)).expect("wait succeeds");

        assert!(
            status.is_none(),
            "an overrunning process must report as killed"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the wait returned after {:?}, so the limit did not hold",
            started.elapsed()
        );
    }

    /// A process that finishes in time reports its own status, not a timeout.
    #[test]
    fn a_process_that_finishes_reports_its_status() {
        let mut quick = if cfg!(windows) {
            let mut c = std::process::Command::new("cmd");
            c.args(["/C", "exit", "0"]);
            c
        } else {
            std::process::Command::new("true")
        };
        let mut child = quick
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the quick command starts");

        let status = wait_bounded(&mut child, Duration::from_secs(30))
            .expect("wait succeeds")
            .expect("it finished on its own");
        assert!(status.success());
    }

    #[test]
    fn the_selector_is_what_both_managers_accept() {
        let spec = PluginSpec {
            name: "oh-my-harness".into(),
            marketplace: "oh-my-harness".into(),
            source: "ssoj13/oh-my-harness".into(),
        };
        assert_eq!(selector(&spec), "oh-my-harness@oh-my-harness");
    }
}
