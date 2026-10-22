//! Running an agent's own command-line tool.
//!
//! Two very different features need this: registering an MCP server through
//! `codex mcp add` rather than by editing TOML, and installing a whole plugin
//! through `codex plugin add`. One spawn helper serves both, because the reason
//! it is not `Command::new(program)` is the same in either case.

use std::process::Command;

/// A command that will actually start the agent's CLI on this platform.
///
/// On Windows these agents ship as `.cmd` shims, which `CreateProcess` cannot
/// execute directly - so the shim is handed to `cmd /C`, which can.
pub(crate) fn agent_command(program: &str) -> Command {
    if cfg!(windows) {
        let mut command = Command::new("cmd");
        command.arg("/C").arg(program);
        command
    } else {
        Command::new(program)
    }
}
