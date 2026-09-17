pub mod agent_policy;
pub mod allowed;
pub mod content_plane;
pub mod dollar_guard;
pub mod format;
pub mod glob;
pub mod housekeeping;
pub mod instance;
pub mod logging;
pub mod path;
pub mod paths;
/// Test-only guard: asserts nothing outside [`paths`] resolves a platform directory.
#[cfg(test)]
pub mod paths_guard;
pub mod run_command_args;
pub mod schema;
pub mod serde;
/// Test-only guard: asserts the tool list stays within the budgets in `docs/TOOL_STYLE.md`.
#[cfg(test)]
pub mod tool_surface_guard;
