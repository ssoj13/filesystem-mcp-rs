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
    /// See [`InstallPlan::force`]. Off by default.
    pub force: bool,
}

impl HostSpec {
    /// `command` defaults to the *installed* copy of this server — not literally the running
    /// binary. That distinction matters: a server registering itself from `target/release` would
    /// otherwise bake a build-tree path into every agent config, and that path dies on the next
    /// `cargo clean`, branch switch or repo move, leaving a config pointing at nothing while
    /// `status` still reports "installed".
    ///
    /// Resolution order (see [`resolve_installed_exe`]):
    ///   1. `$CARGO_HOME/bin/<name>` (default `~/.cargo/bin`) — the stable install location,
    ///   2. the first `<name>` on `PATH`,
    ///   3. the running executable, as a last resort for a checkout with nothing installed.
    pub fn from_current_exe(
        server_key: impl Into<String>,
        install_id: impl Into<String>,
    ) -> Result<Self> {
        let exe = std::env::current_exe().map_err(|e| SetupError::io(PathBuf::new(), e))?;
        Ok(Self::new(
            server_key,
            install_id,
            resolve_installed_exe(&exe),
        ))
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
            force: false,
        }
    }

    /// Let `install` overwrite an entry under our key that carries no install-id marker of ours
    /// (a hand-written one). See [`InstallPlan::force`] for why this is opt-in.
    pub fn with_force(mut self, force: bool) -> Self {
        self.force = force;
        self
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
        self.env = env.into_iter().map(|(k, v)| (k.into(), v.into())).collect();
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
            force: self.force,
        })
    }
}

/// Absolute path with symlinks resolved; falls back to the input when the path cannot be
/// canonicalized (e.g. it does not exist yet).
pub fn normalize_path(p: &Path) -> String {
    let resolved = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    strip_verbatim(&resolved.to_string_lossy())
}

/// Drop Windows' `\\?\` verbatim prefix that `canonicalize` adds.
///
/// Agent configs are consumed by every kind of launcher (Node `child_process`, Python
/// `subprocess`, Go, shells). The extended-length form is legal for `CreateProcess` but not
/// universally understood by those wrappers, and it looks broken to anyone reading the config by
/// hand. `\\?\UNC\server\share` folds back to `\\server\share`.
fn strip_verbatim(s: &str) -> String {
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    s.strip_prefix(r"\\?\").unwrap_or(s).to_string()
}

/// Where the *installed* copy of `exe` lives, preferred over the running one.
///
/// Falls back to the running binary so a plain `cargo run` in a fresh checkout still produces a
/// usable entry, rather than failing or writing a bare name that may not be on the host's PATH.
pub fn resolve_installed_exe(exe: &Path) -> String {
    resolve_installed_exe_in(exe, cargo_bin_dir().as_deref())
}

/// [`resolve_installed_exe`] with the install directory injected.
///
/// Split out so the preference order is testable without mutating `CARGO_HOME`: that is a
/// process-global, and a test that writes it races every other test in the same binary.
pub fn resolve_installed_exe_in(exe: &Path, install_dir: Option<&Path>) -> String {
    let Some(name) = exe.file_name() else {
        return normalize_path(exe);
    };

    if let Some(bin) = install_dir {
        let candidate = bin.join(name);
        if candidate.is_file() {
            return normalize_path(&candidate);
        }
    }

    if let Some(found) = find_on_path(&name.to_string_lossy()) {
        return normalize_path(&found);
    }

    normalize_path(exe)
}

/// `$CARGO_HOME/bin`, else `~/.cargo/bin`. `None` when neither is knowable.
fn cargo_bin_dir() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("CARGO_HOME") {
        return Some(PathBuf::from(home).join("bin"));
    }
    dirs::home_dir().map(|h| h.join(".cargo").join("bin"))
}

/// First match for `name` on `PATH`.
///
/// Walks `PATH` directly instead of shelling out to `where` / `which`: no subprocess, no
/// locale-dependent output to parse, and it behaves identically on every platform. On Windows a
/// name without an extension is retried against each `PATHEXT` suffix.
pub fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let direct = dir.join(name);
        if direct.is_file() {
            return Some(direct);
        }
        for ext in path_exts() {
            let candidate = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Executable suffixes to try for a bare name. Empty everywhere but Windows.
fn path_exts() -> Vec<String> {
    if !cfg!(windows) {
        return Vec::new();
    }
    let raw = std::env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".to_string());
    raw.split(';')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(|e| {
            if e.starts_with('.') {
                e.to_string()
            } else {
                format!(".{e}")
            }
        })
        .collect()
}

/// Can the `command` recorded in an agent config actually be launched?
///
/// This is the check whose absence let a stale entry masquerade as a healthy one: the config
/// carried our key and our install id, so `status` said "installed", while the path it named had
/// not existed for weeks. A bare name is looked up on `PATH`; anything path-shaped is tested on
/// disk (with `PATHEXT` retries, so a config recording `foo` rather than `foo.exe` resolves too).
pub fn command_resolves(command: &str) -> bool {
    if command.is_empty() {
        return false;
    }
    let p = Path::new(command);
    let path_shaped = p.is_absolute()
        || command.contains('/')
        || command.contains('\\')
        || p.components().count() > 1;

    if !path_shaped {
        return find_on_path(command).is_some();
    }
    if p.is_file() {
        return true;
    }
    if p.extension().is_none() {
        return path_exts()
            .iter()
            .any(|ext| Path::new(&format!("{command}{ext}")).is_file());
    }
    false
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

#[cfg(test)]
mod resolve_tests {
    use super::*;

    /// The bug this whole check exists for: a config naming a path that is gone must not read as
    /// healthy. `status` used to have no way to tell this from a working entry.
    #[test]
    fn a_missing_path_does_not_resolve() {
        let missing = std::env::temp_dir().join("mcp-setup-rs-definitely-not-here.exe");
        assert!(!missing.exists(), "test fixture must not exist");
        assert!(!command_resolves(&missing.to_string_lossy()));
    }

    #[test]
    fn an_existing_file_resolves() {
        let f = tempfile::NamedTempFile::new().expect("temp file");
        assert!(command_resolves(&f.path().to_string_lossy()));
    }

    /// Bare names go through PATH, not the filesystem. Every platform ships something.
    #[test]
    fn a_bare_name_on_path_resolves() {
        let probe = if cfg!(windows) { "cmd" } else { "sh" };
        assert!(command_resolves(probe), "{probe} should be on PATH");
    }

    #[test]
    fn a_bare_name_not_on_path_does_not_resolve() {
        assert!(!command_resolves("mcp-setup-rs-no-such-binary-anywhere"));
    }

    #[test]
    fn an_empty_command_does_not_resolve() {
        assert!(!command_resolves(""));
    }

    /// Configs are read by launchers that do not all understand the extended-length form.
    #[test]
    fn verbatim_prefix_is_stripped() {
        assert_eq!(strip_verbatim(r"\\?\C:\bin\x.exe"), r"C:\bin\x.exe");
        assert_eq!(
            strip_verbatim(r"\\?\UNC\srv\share\x.exe"),
            r"\\srv\share\x.exe"
        );
        assert_eq!(strip_verbatim(r"C:\bin\x.exe"), r"C:\bin\x.exe");
        assert_eq!(strip_verbatim("/usr/bin/x"), "/usr/bin/x");
    }

    /// A build-tree binary must not be what lands in the config when an installed copy exists —
    /// that is exactly how a path dies on the next `cargo clean` or repo move.
    #[test]
    fn installed_copy_wins_over_the_running_one() {
        let install_dir = tempfile::tempdir().expect("tempdir");
        let build_tree = tempfile::tempdir().expect("tempdir");
        let name = if cfg!(windows) { "srv.exe" } else { "srv" };

        let installed = install_dir.path().join(name);
        std::fs::write(&installed, b"").expect("write installed");
        let running = build_tree.path().join(name);
        std::fs::write(&running, b"").expect("write running");

        let got = resolve_installed_exe_in(&running, Some(install_dir.path()));
        assert_eq!(got, normalize_path(&installed), "installed copy must win");
    }

    /// With nothing installed we still produce a usable entry rather than failing.
    #[test]
    fn falls_back_to_the_running_binary() {
        let empty = tempfile::tempdir().expect("tempdir");
        let build_tree = tempfile::tempdir().expect("tempdir");
        let running = build_tree.path().join("mcp-setup-rs-unique-fallback-probe");
        std::fs::write(&running, b"").expect("write running");

        let got = resolve_installed_exe_in(&running, Some(empty.path()));
        assert_eq!(got, normalize_path(&running));
    }
}
