//! Install a local **stdio MCP server** into AI coding agents — and remove it again, precisely.
//!
//! # Why this exists
//!
//! Every agent (Claude Code, Codex, Cursor, Gemini CLI, …) stores MCP servers in its own file,
//! under its own key, in its own dialect. Shipping an MCP server means either writing that matrix
//! by hand in every project, or telling users to hand-edit JSON. This crate is that matrix, once.
//!
//! # Two levels
//!
//! 1. **The MCP entry** — `mcpServers.<key>` (or `mcp_servers`, `mcp`, …) pointing at your binary.
//! 2. **The hints** — an optional managed Markdown block in the agent's context file
//!    (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `QWEN.md`), so the agent learns *how* to use your
//!    server. Supply the Markdown via [`docs::HintDocs`]; the crate knows where each agent reads it.
//!
//! # Ownership, not guessing
//!
//! Every managed entry carries `env.MCP_SETUP_INSTALL_ID`, and every install writes a manifest
//! under `~/.mcp-setup/manifests/`. Uninstall only removes entries that prove they are ours; a
//! hand-written entry under the same key is a conflict, never a silent overwrite. Config files are
//! backed up (timestamped, beside the original) before any modification.
//!
//! # Usage
//!
//! ```no_run
//! use mcp_setup::{clients, docs::HintDocs, host::{self, HostSpec}, types::{Scope, SetupContext}};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let spec = HostSpec::from_current_exe("my-mcp", concat!("my-mcp:", env!("CARGO_PKG_VERSION")))?
//!     .with_env([("MY_TOKEN", "abc")])
//!     .with_docs(HintDocs::new(["## my-mcp\n\nUse `my_tool` for X."]));
//!
//! let ctx = SetupContext::from_user_dirs()?;
//! for client in clients::all() {
//!     match host::install(&ctx, client, &Scope::User, &spec) {
//!         Ok(report) => println!("{}: {}", client.label(), report.settings_path.display()),
//!         Err(e) => eprintln!("{}: {e}", client.label()),
//!     }
//! }
//! # Ok(()) }
//! ```
//!
//! [`cli::SetupCommand`] gives this binary ready-made `install` / `uninstall` / `status`
//! subcommands with a results table.
//!
//! # Vendored copy — do not edit here
//!
//! This module is a verbatim copy of the private `mcp-setup-rs` crate (see `VENDOR.md` for the
//! pinned commit and the resync procedure). It is vendored rather than consumed as a git
//! dependency because crates.io rejects git dependencies: every dependency of a published crate
//! must itself exist on crates.io, and `mcp-setup-rs` is deliberately private. Fixes belong
//! upstream, in the private repo; re-vendor from there.
//!
//! The only edit applied to the upstream sources is mechanical: `crate::` → `crate::mcp_setup::`,
//! because the vendored files address what was their own crate root and is now this module. The
//! upstream `cli` cargo feature is dropped — this host always builds the CLI.

mod backup;
mod json_client;
mod toml_client;
mod json_merge;
mod jsonc;
mod manifest;

pub mod client;
pub mod clients;
pub mod docs;
pub mod error;
pub mod hints;
pub mod host;
pub mod marked_md;
pub mod types;

pub mod cli;

#[cfg(test)]
mod tests;

pub use client::{ContextFile, McpClient};
pub use docs::HintDocs;
pub use error::{Result, SetupError};
pub use host::{HostSpec, install, status, uninstall};
pub use json_client::JsonClient;
pub use toml_client::TomlClient;
pub use json_merge::EntryStyle;
pub use types::{
    ApplyReport, HintsConfig, INSTALL_ID_ENV_KEY, InstallPlan, RemoveReport, Scope, SetupContext,
    StatusReport, StdioMcpEntry,
};
