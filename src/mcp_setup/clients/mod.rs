//! The client registry.
//!
//! Every agent here is **data**: a `JsonClient` (JSON config) or a `TomlClient` (Codex, Grok).
//! Supporting a new agent means adding one const and listing it in [`all`] — no new logic.
//!
//! Config locations are derived from the user's home directory rather than looked up through the
//! OS, so a temp HOME in tests exercises the exact same code paths as a real install.

use std::path::{Path, PathBuf};

use crate::mcp_setup::client::{ContextFile, McpClient};
use crate::mcp_setup::json_client::JsonClient;
use crate::mcp_setup::json_merge::EntryStyle;
use crate::mcp_setup::toml_client::TomlClient;

/// Every built-in client, in the order they are shown and installed.
pub fn all() -> Vec<&'static dyn McpClient> {
    vec![
        // Agent CLIs
        &CLAUDE_CODE,
        &CODEX,
        &GROK,
        &GEMINI,
        &QWEN,
        &OPENCODE,
        &AMP,
        &CRUSH,
        // Editors / IDEs
        &CURSOR,
        &VSCODE,
        &ZED,
        &WINDSURF,
        &KIRO,
        &JUNIE,
        // VS Code extensions
        &CLINE,
        &ROO,
        // Desktop / terminal
        &CLAUDE_DESKTOP,
        &WARP,
    ]
}

pub fn by_id(id: &str) -> Option<&'static dyn McpClient> {
    all().into_iter().find(|c| c.id().eq_ignore_ascii_case(id))
}

/// Ids accepted by `--client`, for help text and error messages.
pub fn ids() -> Vec<&'static str> {
    all().iter().map(|c| c.id()).collect()
}

// --- platform paths -------------------------------------------------------------------------

/// `%APPDATA%` on Windows, `~/Library/Application Support` on macOS, `~/.config` elsewhere.
/// This is where GUI apps (Claude Desktop, VS Code, Zed) keep per-user settings.
fn app_data(home: &Path) -> PathBuf {
    if cfg!(windows) {
        home.join("AppData").join("Roaming")
    } else if cfg!(target_os = "macos") {
        home.join("Library").join("Application Support")
    } else {
        home.join(".config")
    }
}

/// `%LOCALAPPDATA%` on Windows, `~/.config` elsewhere.
fn local_app_data(home: &Path) -> PathBuf {
    if cfg!(windows) {
        home.join("AppData").join("Local")
    } else {
        home.join(".config")
    }
}

/// VS Code's per-user directory (`.../Code/User`), shared by VS Code itself and its extensions.
fn vscode_user_dir(home: &Path) -> PathBuf {
    app_data(home).join("Code").join("User")
}

/// Where a VS Code extension keeps its own settings file.
fn vscode_ext_dir(home: &Path, ext_id: &str) -> PathBuf {
    vscode_user_dir(home)
        .join("globalStorage")
        .join(ext_id)
        .join("settings")
}

// --- Claude Code ----------------------------------------------------------------------------

fn claude_dir(home: &Path) -> PathBuf {
    home.join(".claude")
}

pub static CLAUDE_CODE: JsonClient = JsonClient {
    id: "claude",
    label: "Claude Code",
    config_hint: "`mcpServers` in `~/.claude.json`",
    parent_path: &["mcpServers"],
    user_config: Some(|home| home.join(".claude.json")),
    project_config: Some(|root| root.join(".mcp.json")),
    user_marker: claude_dir,
    user_missing_hint: "~/.claude missing",
    context: ContextFile {
        user: Some(|home| claude_dir(home).join("CLAUDE.md")),
        project: Some(|root| root.join("CLAUDE.md")),
    },
    entry: EntryStyle::Plain,
};

// --- Claude Desktop -------------------------------------------------------------------------

fn claude_desktop_dir(home: &Path) -> PathBuf {
    app_data(home).join("Claude")
}

/// Desktop app: user scope only, and no context file — it has no agent-rules mechanism.
pub static CLAUDE_DESKTOP: JsonClient = JsonClient {
    id: "claude-desktop",
    label: "Claude Desktop",
    config_hint: "`mcpServers` in `claude_desktop_config.json`",
    parent_path: &["mcpServers"],
    user_config: Some(|home| claude_desktop_dir(home).join("claude_desktop_config.json")),
    project_config: None,
    user_marker: claude_desktop_dir,
    user_missing_hint: "Claude Desktop config dir missing",
    context: ContextFile::NONE,
    entry: EntryStyle::Plain,
};

// --- Codex ----------------------------------------------------------------------------------

fn codex_dir(home: &Path) -> PathBuf {
    home.join(".codex")
}

pub static CODEX: TomlClient = TomlClient {
    id: "codex",
    label: "Codex",
    config_hint: "`mcp_servers` in `~/.codex/config.toml` / `codex mcp add`",
    parent_key: "mcp_servers",
    user_config: |home| codex_dir(home).join("config.toml"),
    project_config: |root| root.join(".codex").join("config.toml"),
    user_marker: codex_dir,
    user_missing_hint: "~/.codex missing",
    context: ContextFile {
        user: Some(|home| codex_dir(home).join("AGENTS.md")),
        project: Some(|root| root.join("AGENTS.md")),
    },
    cli: Some("codex"),
};

// --- Grok Build (xAI) -----------------------------------------------------------------------

fn grok_dir(home: &Path) -> PathBuf {
    home.join(".grok")
}

/// Same TOML shape as Codex, but no `mcp add` CLI — servers are managed in the TUI or the file.
pub static GROK: TomlClient = TomlClient {
    id: "grok",
    label: "Grok Build",
    config_hint: "`mcp_servers` in `~/.grok/config.toml`",
    parent_key: "mcp_servers",
    user_config: |home| grok_dir(home).join("config.toml"),
    project_config: |root| root.join(".grok").join("config.toml"),
    user_marker: grok_dir,
    user_missing_hint: "~/.grok missing",
    context: ContextFile {
        user: None,
        project: Some(|root| root.join("AGENTS.md")),
    },
    cli: None,
};

// --- Gemini CLI -----------------------------------------------------------------------------

fn gemini_dir(home: &Path) -> PathBuf {
    home.join(".gemini")
}

pub static GEMINI: JsonClient = JsonClient {
    id: "gemini",
    label: "Gemini CLI",
    config_hint: "`mcpServers` in `~/.gemini/settings.json`",
    parent_path: &["mcpServers"],
    user_config: Some(|home| gemini_dir(home).join("settings.json")),
    project_config: Some(|root| root.join(".gemini").join("settings.json")),
    user_marker: gemini_dir,
    user_missing_hint: "~/.gemini missing",
    context: ContextFile {
        user: Some(|home| gemini_dir(home).join("GEMINI.md")),
        project: Some(|root| root.join("GEMINI.md")),
    },
    entry: EntryStyle::Plain,
};

// --- Qwen Code ------------------------------------------------------------------------------

fn qwen_dir(home: &Path) -> PathBuf {
    home.join(".qwen")
}

pub static QWEN: JsonClient = JsonClient {
    id: "qwen",
    label: "Qwen Code",
    config_hint: "`mcpServers` in `~/.qwen/settings.json`",
    parent_path: &["mcpServers"],
    user_config: Some(|home| qwen_dir(home).join("settings.json")),
    project_config: Some(|root| root.join(".qwen").join("settings.json")),
    user_marker: qwen_dir,
    user_missing_hint: "~/.qwen missing",
    context: ContextFile {
        user: Some(|home| qwen_dir(home).join("QWEN.md")),
        project: Some(|root| root.join("QWEN.md")),
    },
    entry: EntryStyle::Plain,
};

// --- OpenCode -------------------------------------------------------------------------------

fn opencode_dir(home: &Path) -> PathBuf {
    home.join(".config").join("opencode")
}

pub static OPENCODE: JsonClient = JsonClient {
    id: "opencode",
    label: "OpenCode",
    config_hint: "`mcp.<key>` in `~/.config/opencode/opencode.json`",
    parent_path: &["mcp"],
    user_config: Some(|home| opencode_dir(home).join("opencode.json")),
    project_config: Some(|root| root.join("opencode.json")),
    user_marker: opencode_dir,
    user_missing_hint: "~/.config/opencode missing",
    context: ContextFile {
        user: Some(|home| opencode_dir(home).join("AGENTS.md")),
        project: Some(|root| root.join("AGENTS.md")),
    },
    entry: EntryStyle::LocalCommandArray,
};

// --- Amp (Sourcegraph) ----------------------------------------------------------------------

fn amp_dir(home: &Path) -> PathBuf {
    home.join(".config").join("amp")
}

/// Amp nests its servers under a single dotted key, `amp.mcpServers` — one key, not two levels.
pub static AMP: JsonClient = JsonClient {
    id: "amp",
    label: "Amp",
    config_hint: "`amp.mcpServers` in `~/.config/amp/settings.json`",
    parent_path: &["amp.mcpServers"],
    user_config: Some(|home| amp_dir(home).join("settings.json")),
    project_config: Some(|root| root.join(".amp").join("settings.json")),
    user_marker: amp_dir,
    user_missing_hint: "~/.config/amp missing",
    context: ContextFile {
        user: None,
        project: Some(|root| root.join("AGENTS.md")),
    },
    entry: EntryStyle::Plain,
};

// --- Crush (Charm) --------------------------------------------------------------------------

fn crush_dir(home: &Path) -> PathBuf {
    local_app_data(home).join("crush")
}

pub static CRUSH: JsonClient = JsonClient {
    id: "crush",
    label: "Crush",
    config_hint: "`mcp` in `crush.json`",
    parent_path: &["mcp"],
    user_config: Some(|home| crush_dir(home).join("crush.json")),
    project_config: Some(|root| root.join("crush.json")),
    user_marker: crush_dir,
    user_missing_hint: "Crush config dir missing",
    context: ContextFile {
        user: None,
        project: Some(|root| root.join("CRUSH.md")),
    },
    entry: EntryStyle::TypedStdio,
};

// --- Cursor ---------------------------------------------------------------------------------

fn cursor_dir(home: &Path) -> PathBuf {
    home.join(".cursor")
}

pub static CURSOR: JsonClient = JsonClient {
    id: "cursor",
    label: "Cursor",
    config_hint: "`mcpServers` in `~/.cursor/mcp.json`",
    parent_path: &["mcpServers"],
    user_config: Some(|home| cursor_dir(home).join("mcp.json")),
    project_config: Some(|root| root.join(".cursor").join("mcp.json")),
    user_marker: cursor_dir,
    user_missing_hint: "~/.cursor missing",
    context: ContextFile {
        user: Some(|home| cursor_dir(home).join("AGENTS.md")),
        project: Some(|root| root.join("AGENTS.md")),
    },
    entry: EntryStyle::Plain,
};

// --- VS Code (Copilot agent mode) -----------------------------------------------------------

/// VS Code is the odd one out: the map is `servers`, not `mcpServers`, and each entry must name
/// its transport explicitly (`"type": "stdio"`).
pub static VSCODE: JsonClient = JsonClient {
    id: "vscode",
    label: "VS Code",
    config_hint: "`servers` in VS Code's `mcp.json`",
    parent_path: &["servers"],
    user_config: Some(|home| vscode_user_dir(home).join("mcp.json")),
    project_config: Some(|root| root.join(".vscode").join("mcp.json")),
    user_marker: vscode_user_dir,
    user_missing_hint: "VS Code user dir missing",
    context: ContextFile::NONE,
    entry: EntryStyle::TypedStdio,
};

// --- Cline / Roo Code (VS Code extensions) --------------------------------------------------

fn cline_dir(home: &Path) -> PathBuf {
    vscode_ext_dir(home, "saoudrizwan.claude-dev")
}

pub static CLINE: JsonClient = JsonClient {
    id: "cline",
    label: "Cline",
    config_hint: "`mcpServers` in `cline_mcp_settings.json`",
    parent_path: &["mcpServers"],
    user_config: Some(|home| cline_dir(home).join("cline_mcp_settings.json")),
    project_config: None,
    user_marker: cline_dir,
    user_missing_hint: "Cline extension dir missing",
    context: ContextFile::NONE,
    entry: EntryStyle::Plain,
};

fn roo_dir(home: &Path) -> PathBuf {
    vscode_ext_dir(home, "rooveterinaryinc.roo-cline")
}

pub static ROO: JsonClient = JsonClient {
    id: "roo",
    label: "Roo Code",
    config_hint: "`mcpServers` in Roo's `mcp_settings.json`",
    parent_path: &["mcpServers"],
    user_config: Some(|home| roo_dir(home).join("mcp_settings.json")),
    project_config: Some(|root| root.join(".roo").join("mcp.json")),
    user_marker: roo_dir,
    user_missing_hint: "Roo Code extension dir missing",
    context: ContextFile {
        user: None,
        project: Some(|root| root.join("AGENTS.md")),
    },
    entry: EntryStyle::Plain,
};

// --- Zed ------------------------------------------------------------------------------------

fn zed_dir(home: &Path) -> PathBuf {
    if cfg!(windows) {
        app_data(home).join("Zed")
    } else {
        home.join(".config").join("zed")
    }
}

/// Zed keeps servers under `context_servers`, and a local one is marked `"source": "custom"`.
pub static ZED: JsonClient = JsonClient {
    id: "zed",
    label: "Zed",
    config_hint: "`context_servers` in Zed's `settings.json`",
    parent_path: &["context_servers"],
    user_config: Some(|home| zed_dir(home).join("settings.json")),
    project_config: Some(|root| root.join(".zed").join("settings.json")),
    user_marker: zed_dir,
    user_missing_hint: "Zed config dir missing",
    context: ContextFile {
        user: Some(|home| zed_dir(home).join("AGENTS.md")),
        project: Some(|root| root.join("AGENTS.md")),
    },
    entry: EntryStyle::ZedCustom,
};

// --- Windsurf -------------------------------------------------------------------------------

fn windsurf_dir(home: &Path) -> PathBuf {
    home.join(".codeium").join("windsurf")
}

pub static WINDSURF: JsonClient = JsonClient {
    id: "windsurf",
    label: "Windsurf",
    config_hint: "`mcpServers` in `~/.codeium/windsurf/mcp_config.json`",
    parent_path: &["mcpServers"],
    user_config: Some(|home| windsurf_dir(home).join("mcp_config.json")),
    project_config: None,
    user_marker: windsurf_dir,
    user_missing_hint: "~/.codeium/windsurf missing",
    context: ContextFile::NONE,
    entry: EntryStyle::Plain,
};

// --- Kiro (AWS) -----------------------------------------------------------------------------

fn kiro_dir(home: &Path) -> PathBuf {
    home.join(".kiro")
}

pub static KIRO: JsonClient = JsonClient {
    id: "kiro",
    label: "Kiro",
    config_hint: "`mcpServers` in `~/.kiro/settings/mcp.json`",
    parent_path: &["mcpServers"],
    user_config: Some(|home| kiro_dir(home).join("settings").join("mcp.json")),
    project_config: Some(|root| root.join(".kiro").join("settings").join("mcp.json")),
    user_marker: kiro_dir,
    user_missing_hint: "~/.kiro missing",
    context: ContextFile {
        user: None,
        project: Some(|root| root.join("AGENTS.md")),
    },
    entry: EntryStyle::Plain,
};

// --- JetBrains Junie ------------------------------------------------------------------------

fn junie_dir(home: &Path) -> PathBuf {
    home.join(".junie")
}

pub static JUNIE: JsonClient = JsonClient {
    id: "junie",
    label: "JetBrains Junie",
    config_hint: "`mcpServers` in `~/.junie/mcp/mcp.json`",
    parent_path: &["mcpServers"],
    user_config: Some(|home| junie_dir(home).join("mcp").join("mcp.json")),
    project_config: Some(|root| root.join(".junie").join("mcp").join("mcp.json")),
    user_marker: junie_dir,
    user_missing_hint: "~/.junie missing",
    context: ContextFile::NONE,
    entry: EntryStyle::Plain,
};

// --- Warp -----------------------------------------------------------------------------------

fn warp_dir(home: &Path) -> PathBuf {
    home.join(".warp")
}

pub static WARP: JsonClient = JsonClient {
    id: "warp",
    label: "Warp",
    config_hint: "`mcpServers` in `~/.warp/.mcp.json`",
    parent_path: &["mcpServers"],
    user_config: Some(|home| warp_dir(home).join(".mcp.json")),
    project_config: Some(|root| root.join(".warp").join(".mcp.json")),
    user_marker: warp_dir,
    user_missing_hint: "~/.warp missing",
    context: ContextFile {
        user: None,
        project: Some(|root| root.join("WARP.md")),
    },
    entry: EntryStyle::Plain,
};
