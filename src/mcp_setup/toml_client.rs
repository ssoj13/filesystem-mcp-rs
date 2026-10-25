//! The engine behind TOML-config agents (Codex, Grok Build, Mistral Vibe).
//!
//! Codex and Grok keep servers in `[mcp_servers.<key>]` with `command` / `args` / `env`.
//! Mistral Vibe keeps servers in `[[mcp_servers]]` array of tables with `name` / `transport` /
//! `command` / `args` / `env`.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, Value as TomlVal};

use crate::mcp_setup::agent_cli::agent_command;
use crate::mcp_setup::backup::backup_file_if_exists;
use crate::mcp_setup::client::{ContextFile, McpClient};
use crate::mcp_setup::error::{Result, SetupError};
use crate::mcp_setup::hints::{self, ClientDoc};
use crate::mcp_setup::json_merge::is_ours;
use crate::mcp_setup::manifest::{InstallManifest, MANIFEST_SCHEMA};
use crate::mcp_setup::types::{
    ApplyReport, INSTALL_ID_ENV_KEY, InstallPlan, RemoveReport, Scope, SetupContext, StatusReport,
    StdioMcpEntry, ensure_project_root,
};

/// Set to skip an agent's own CLI and write its TOML directly (tests, and users who want the file
/// written deterministically).
pub const FORCE_TOML_ENV: &str = "MCP_SETUP_FORCE_TOML";

/// How a TOML client structures its MCP server entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TomlStyle {
    /// `[mcp_servers.<key>]` table map (Codex, Grok Build).
    #[default]
    TableMap,
    /// `[[mcp_servers]]` array of tables with `name = "<key>"` and `transport = "stdio"` (Mistral Vibe).
    ArrayOfTables,
}

/// A TOML-config agent, described declaratively.
pub struct TomlClient {
    pub id: &'static str,
    pub label: &'static str,
    pub config_hint: &'static str,
    /// Table or array-of-tables key holding the servers, e.g. `mcp_servers`.
    pub parent_key: &'static str,
    pub user_config: fn(&Path) -> PathBuf,
    pub project_config: fn(&Path) -> PathBuf,
    pub user_marker: fn(&Path) -> PathBuf,
    pub user_missing_hint: &'static str,
    pub context: ContextFile,
    /// The agent's own MCP CLI (`codex mcp add …`), preferred in user scope so the agent's
    /// internal registry stays in sync. `None` => always write the file ourselves.
    pub cli: Option<&'static str>,
    pub style: TomlStyle,
}

// --- the agent's own CLI --------------------------------------------------------------------

#[derive(Debug)]
enum CliOutcome {
    NoCli,
    SkippedForceToml,
    Succeeded,
    FailedOutput(std::process::Output),
    FailedSpawn(std::io::Error),
}

fn run_cli_add(program: Option<&str>, plan: &InstallPlan) -> CliOutcome {
    let Some(program) = program else {
        return CliOutcome::NoCli;
    };
    if std::env::var_os(FORCE_TOML_ENV).is_some() {
        return CliOutcome::SkippedForceToml;
    }
    let mut c = agent_command(program);
    c.arg("mcp")
        .arg("add")
        .arg(&plan.mcp_server_key)
        .arg("--")
        .arg(&plan.stdio.command);
    for a in &plan.stdio.args {
        c.arg(a);
    }
    c.stdin(Stdio::null());
    match c.output() {
        Ok(out) if out.status.success() => CliOutcome::Succeeded,
        Ok(out) => CliOutcome::FailedOutput(out),
        Err(e) => CliOutcome::FailedSpawn(e),
    }
}

fn run_cli_remove(program: Option<&str>, key: &str) {
    let Some(program) = program else { return };
    if std::env::var_os(FORCE_TOML_ENV).is_some() {
        return;
    }
    let _ = agent_command(program)
        .arg("mcp")
        .arg("remove")
        .arg(key)
        .stdin(Stdio::null())
        .output();
}

fn trim(s: &str, max: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= max {
        return t.to_string();
    }
    format!(
        "{}…",
        t.chars().take(max.saturating_sub(1)).collect::<String>()
    )
}

fn fallback_note(client: &TomlClient, outcome: &CliOutcome, path: &Path) -> Option<String> {
    let file = path.display();
    match outcome {
        CliOutcome::Succeeded => None,
        CliOutcome::NoCli => Some(format!("MCP via {file}")),
        CliOutcome::SkippedForceToml => Some(format!("MCP via {file} ({FORCE_TOML_ENV})")),
        CliOutcome::FailedOutput(out) => Some(format!(
            "MCP via {file} (`{} mcp add` exited with {})",
            client.cli.unwrap_or_default(),
            out.status
        )),
        CliOutcome::FailedSpawn(e) => Some(format!(
            "MCP via {file} (could not run `{}`: {e})",
            client.cli.unwrap_or_default()
        )),
    }
}

/// Both paths failed: surface the TOML error *and* why the CLI could not help, so the user is not
/// left guessing which half broke.
fn apply_error(client: &TomlClient, toml_err: SetupError, cli: &CliOutcome) -> SetupError {
    let mut detail = format!(
        "could not update {}'s config.toml: {toml_err}",
        client.label
    );
    match cli {
        CliOutcome::FailedOutput(out) => {
            let stderr = trim(&String::from_utf8_lossy(&out.stderr), 600);
            if stderr.is_empty() {
                detail.push_str(&format!("; `mcp add` exited {}", out.status));
            } else {
                detail.push_str("; `mcp add` stderr: ");
                detail.push_str(&stderr);
            }
        }
        CliOutcome::FailedSpawn(e) => detail.push_str(&format!("; spawn error: {e}")),
        CliOutcome::NoCli | CliOutcome::SkippedForceToml | CliOutcome::Succeeded => {}
    }
    SetupError::CodexConfigFailed { detail }
}

// --- TOML -----------------------------------------------------------------------------------

fn read_install_id(entry: &Table) -> Option<String> {
    entry
        .get("env")?
        .as_table()?
        .get(INSTALL_ID_ENV_KEY)?
        .as_str()
        .map(ToString::to_string)
}

fn parse_doc(client: &TomlClient, path: &Path, raw: &str) -> Result<DocumentMut> {
    raw.parse::<DocumentMut>().map_err(|e| {
        SetupError::InvalidBundle(format!(
            "{} config at {} is not valid TOML: {e}",
            client.label,
            path.display()
        ))
    })
}

fn find_entry<'a>(client: &TomlClient, doc: &'a DocumentMut, key: &str) -> Option<&'a Table> {
    match client.style {
        TomlStyle::TableMap => doc
            .get(client.parent_key)
            .and_then(Item::as_table)
            .and_then(|t| t.get(key))
            .and_then(Item::as_table),
        TomlStyle::ArrayOfTables => doc
            .get(client.parent_key)
            .and_then(Item::as_array_of_tables)
            .and_then(|aot| {
                aot.iter()
                    .find(|t| t.get("name").and_then(Item::as_str) == Some(key))
            }),
    }
}

fn ensure_key_available(
    client: &TomlClient,
    doc: &DocumentMut,
    plan: &InstallPlan,
    cli_succeeded: bool,
) -> Result<()> {
    let Some(entry) = find_entry(client, doc, &plan.mcp_server_key) else {
        return Ok(());
    };
    match read_install_id(entry) {
        Some(id) if is_ours(&id, &plan.mcp_server_key) => Ok(()),
        // If `codex mcp add` just created/updated this key, it stripped env/MCP_SETUP_INSTALL_ID,
        // so allow `upsert_toml` to enrich the entry with our `env` and `MCP_SETUP_INSTALL_ID`.
        None if cli_succeeded => Ok(()),
        _ if plan.force => Ok(()),
        found => Err(SetupError::McpKeyConflict {
            key: plan.mcp_server_key.clone(),
            expected: Some(plan.install_id.clone()),
            found,
        }),
    }
}

fn build_entry_table(client: &TomlClient, plan: &InstallPlan) -> Table {
    let mut entry = Table::new();
    if matches!(client.style, TomlStyle::ArrayOfTables) {
        entry.insert(
            "name",
            Item::Value(TomlVal::String(toml_edit::Formatted::new(
                plan.mcp_server_key.clone(),
            ))),
        );
        entry.insert(
            "transport",
            Item::Value(TomlVal::String(toml_edit::Formatted::new(
                "stdio".to_string(),
            ))),
        );
    }
    entry.insert(
        "command",
        Item::Value(TomlVal::String(toml_edit::Formatted::new(
            plan.stdio.command.clone(),
        ))),
    );
    let mut args = Array::new();
    for a in &plan.stdio.args {
        args.push(TomlVal::String(toml_edit::Formatted::new(a.clone())));
    }
    entry.insert("args", Item::Value(TomlVal::Array(args)));

    let mut env = Table::new();
    env.insert(
        INSTALL_ID_ENV_KEY,
        Item::Value(TomlVal::String(toml_edit::Formatted::new(
            plan.install_id.clone(),
        ))),
    );
    for (k, v) in &plan.stdio.env {
        env.insert(
            k.as_str(),
            Item::Value(TomlVal::String(toml_edit::Formatted::new(v.clone()))),
        );
    }
    entry.insert("env", Item::Table(env));
    entry
}

fn upsert_toml(
    client: &TomlClient,
    path: &Path,
    plan: &InstallPlan,
    cli_succeeded: bool,
    pre_cli_backup: Option<PathBuf>,
) -> Result<Written> {
    let raw = if path.exists() {
        std::fs::read_to_string(path).map_err(|e| SetupError::io(path.to_path_buf(), e))?
    } else {
        String::new()
    };
    let mut doc = if raw.trim().is_empty() {
        DocumentMut::new()
    } else {
        parse_doc(client, path, &raw)?
    };
    ensure_key_available(client, &doc, plan, cli_succeeded)?;

    let entry = build_entry_table(client, plan);

    match client.style {
        TomlStyle::TableMap => {
            let servers = doc
                .entry(client.parent_key)
                .or_insert(Item::Table(Table::new()))
                .as_table_mut()
                .ok_or_else(|| {
                    SetupError::InvalidBundle(format!(
                        "{}: `{}` is not a table",
                        client.label, client.parent_key
                    ))
                })?;
            servers.insert(&plan.mcp_server_key, Item::Table(entry));
        }
        TomlStyle::ArrayOfTables => {
            if doc
                .get(client.parent_key)
                .and_then(Item::as_array)
                .is_some_and(Array::is_empty)
            {
                doc.insert(client.parent_key, Item::ArrayOfTables(ArrayOfTables::new()));
            }
            let aot = doc
                .entry(client.parent_key)
                .or_insert(Item::ArrayOfTables(ArrayOfTables::new()))
                .as_array_of_tables_mut()
                .ok_or_else(|| {
                    SetupError::InvalidBundle(format!(
                        "{}: `{}` is not an array of tables",
                        client.label, client.parent_key
                    ))
                })?;
            if let Some(existing) = aot.iter_mut().find(|t| {
                t.get("name").and_then(Item::as_str) == Some(plan.mcp_server_key.as_str())
            }) {
                *existing = entry;
            } else {
                aot.push(entry);
            }
        }
    }

    let rendered = doc.to_string();
    if rendered == raw && !cli_succeeded {
        return Ok(Written::Unchanged);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SetupError::io(parent.to_path_buf(), e))?;
    }
    let backup = match pre_cli_backup {
        Some(b) => Some(b),
        None => backup_file_if_exists(path)?,
    };
    std::fs::write(path, rendered).map_err(|e| SetupError::io(path.to_path_buf(), e))?;
    Ok(Written::Changed(backup))
}

/// What `upsert_toml` did, and the backup it took if it wrote.
enum Written {
    Unchanged,
    Changed(Option<PathBuf>),
}

/// `trust_manifest` allows removing an entry written by the agent's own CLI (which strips our env
/// marker) — but only when our manifest proves we are the ones who put it there.
fn remove_toml(
    client: &TomlClient,
    path: &Path,
    plan: &InstallPlan,
    trust_manifest: bool,
) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let raw = std::fs::read_to_string(path).map_err(|e| SetupError::io(path.to_path_buf(), e))?;
    let mut doc = parse_doc(client, path, &raw)?;

    let Some(entry) = find_entry(client, &doc, &plan.mcp_server_key) else {
        return Ok(false);
    };

    match (read_install_id(entry), trust_manifest) {
        (Some(id), _) if is_ours(&id, &plan.mcp_server_key) => {}
        (None, true) => {}
        (Some(id), _) => {
            return Err(SetupError::ManifestConflict(format!(
                "refusing remove: {} key {:?} is owned by {id}, not by {}",
                client.label, plan.mcp_server_key, plan.install_id
            )));
        }
        (None, false) => {
            return Err(SetupError::NotOurInstall {
                key: plan.mcp_server_key.clone(),
                install_id_key: INSTALL_ID_ENV_KEY,
            });
        }
    }

    match client.style {
        TomlStyle::TableMap => {
            if let Some(servers) = doc.get_mut(client.parent_key).and_then(Item::as_table_mut) {
                servers.remove(&plan.mcp_server_key);
            }
        }
        TomlStyle::ArrayOfTables => {
            if let Some(aot) = doc
                .get_mut(client.parent_key)
                .and_then(Item::as_array_of_tables_mut)
            {
                let mut idx_to_remove = None;
                for (i, t) in aot.iter().enumerate() {
                    if t.get("name").and_then(Item::as_str) == Some(plan.mcp_server_key.as_str()) {
                        idx_to_remove = Some(i);
                        break;
                    }
                }
                if let Some(idx) = idx_to_remove {
                    aot.remove(idx);
                }
            }
        }
    }
    std::fs::write(path, doc.to_string()).map_err(|e| SetupError::io(path.to_path_buf(), e))?;
    Ok(true)
}

/// `(entry present, install id, command)` for `key`. The command comes back so `status` can
/// check that what the config names is still launchable.
fn read_toml_status(
    client: &TomlClient,
    path: &Path,
    key: &str,
) -> Result<(bool, Option<String>, Option<String>)> {
    if !path.exists() {
        return Ok((false, None, None));
    }
    let raw = std::fs::read_to_string(path).map_err(|e| SetupError::io(path.to_path_buf(), e))?;
    if raw.trim().is_empty() {
        return Ok((false, None, None));
    }
    let doc = parse_doc(client, path, &raw)?;
    let entry = find_entry(client, &doc, key);
    let command = entry
        .and_then(|t| t.get("command"))
        .and_then(Item::as_str)
        .map(ToString::to_string);
    Ok((entry.is_some(), entry.and_then(read_install_id), command))
}

// --- client ---------------------------------------------------------------------------------

impl TomlClient {
    fn doc(&self) -> ClientDoc {
        ClientDoc {
            label: self.label,
            config_hint: self.config_hint,
        }
    }

    fn config_path(&self, scope: &Scope, home: &Path) -> PathBuf {
        match scope {
            Scope::User => (self.user_config)(home),
            Scope::Project(root) => (self.project_config)(root),
        }
    }

    fn ensure_scope_ready(&self, scope: &Scope, home: &Path) -> Result<()> {
        match scope {
            Scope::User => {
                if !(self.user_marker)(home).exists() {
                    return Err(SetupError::HostNotDetected {
                        client: self.label,
                        hint: self.user_missing_hint.to_string(),
                    });
                }
                Ok(())
            }
            Scope::Project(root) => ensure_project_root(root),
        }
    }

    fn manifest_entry(&self, plan: &InstallPlan) -> StdioMcpEntry {
        let mut s = plan.stdio.clone();
        s.env
            .insert(INSTALL_ID_ENV_KEY.to_string(), plan.install_id.clone());
        s
    }
}

impl McpClient for TomlClient {
    fn id(&self) -> &'static str {
        self.id
    }

    fn label(&self) -> &'static str {
        self.label
    }

    fn config_hint(&self) -> &'static str {
        self.config_hint
    }

    fn user_marker_dir(&self, home: &Path) -> PathBuf {
        (self.user_marker)(home)
    }

    fn apply(&self, ctx: &SetupContext, scope: &Scope, plan: &InstallPlan) -> Result<ApplyReport> {
        let home = ctx.home_dir();
        self.ensure_scope_ready(scope, home)?;
        let settings_path = self.config_path(scope, home);
        let scope_slug = scope.slug()?;
        let manifest_path =
            InstallManifest::manifest_path_for(home, self.id, &scope_slug, &plan.mcp_server_key);

        // Pre-validate key availability before running `codex mcp add` so we never clobber a
        // foreign entry through the CLI when `--force` is false.
        if settings_path.exists() {
            let raw = std::fs::read_to_string(&settings_path)
                .map_err(|e| SetupError::io(settings_path.clone(), e))?;
            if !raw.trim().is_empty() {
                let doc = parse_doc(self, &settings_path, &raw)?;
                ensure_key_available(self, &doc, plan, false)?;
            }
        }

        let pre_cli_backup = if matches!(scope, Scope::User)
            && self.cli.is_some()
            && std::env::var_os(FORCE_TOML_ENV).is_none()
        {
            backup_file_if_exists(&settings_path)?
        } else {
            None
        };

        // The agent's own CLI only owns the user-scope registry; project configs we always write.
        let cli_outcome = match scope {
            Scope::User => run_cli_add(self.cli, plan),
            Scope::Project(_) => CliOutcome::NoCli,
        };
        let cli_succeeded = matches!(cli_outcome, CliOutcome::Succeeded);
        let note = fallback_note(self, &cli_outcome, &settings_path);
        // Always run `upsert_toml` even after `codex mcp add` succeeds so that `env` variables
        // and `MCP_SETUP_INSTALL_ID` are preserved in `config.toml`!
        let (changed, backup_path) =
            match upsert_toml(self, &settings_path, plan, cli_succeeded, pre_cli_backup) {
                Ok(Written::Unchanged) => (false, None),
                Ok(Written::Changed(backup)) => (true, backup),
                Err(e) => return Err(apply_error(self, e, &cli_outcome)),
            };

        let mut manifest = InstallManifest {
            schema: MANIFEST_SCHEMA,
            client: self.id.to_string(),
            scope: scope_slug,
            settings_path: settings_path.clone(),
            mcp_server_key: plan.mcp_server_key.clone(),
            install_id: plan.install_id.clone(),
            entry: self.manifest_entry(plan),
            project_root: scope.project_root().map(Path::to_path_buf),
            hints_file: None,
            hints_marker: None,
        };
        let mut report = ApplyReport {
            client: self.id,
            settings_path,
            backup_path,
            manifest_path: manifest_path.clone(),
            changed,
            note,
            ..ApplyReport::default()
        };

        hints::apply_to_manifest_and_report(
            plan,
            &mut manifest,
            &mut report,
            &self.context,
            self.doc(),
            scope,
            home,
        )?;
        manifest.save(&manifest_path)?;
        Ok(report)
    }

    fn remove(
        &self,
        ctx: &SetupContext,
        scope: &Scope,
        plan: &InstallPlan,
    ) -> Result<RemoveReport> {
        let home = ctx.home_dir();
        self.ensure_scope_ready(scope, home)?;
        let settings_path = self.config_path(scope, home);
        let scope_slug = scope.slug()?;
        let manifest_path =
            InstallManifest::manifest_path_for(home, self.id, &scope_slug, &plan.mcp_server_key);
        let manifest = InstallManifest::load_for(home, self.id, &scope_slug, &plan.mcp_server_key)?;
        if let Some(ref m) = manifest {
            m.ensure_matches(&settings_path, plan)?;
        }

        // Take the backup BEFORE `run_cli_remove` mutates `settings_path`.
        let backup_path = backup_file_if_exists(&settings_path)?;
        let had_entry_before_cli = read_toml_status(self, &settings_path, &plan.mcp_server_key)
            .map(|(present, _, _)| present)
            .unwrap_or(false);

        if matches!(scope, Scope::User) {
            run_cli_remove(self.cli, &plan.mcp_server_key);
        }

        let removed_by_toml = remove_toml(self, &settings_path, plan, manifest.is_some())?;
        let removed = removed_by_toml || had_entry_before_cli;

        let mut report = RemoveReport {
            client: self.id,
            settings_path,
            manifest_path,
            backup_path: if removed { backup_path } else { None },
            removed,
            ..RemoveReport::default()
        };
        hints::merge_remove_report(manifest.as_ref(), &mut report)?;
        InstallManifest::remove_for(home, self.id, &scope_slug, &plan.mcp_server_key)?;
        Ok(report)
    }

    fn status(
        &self,
        ctx: &SetupContext,
        scope: &Scope,
        plan: &InstallPlan,
    ) -> Result<StatusReport> {
        let home = ctx.home_dir();
        let settings_path = self.config_path(scope, home);
        let scope_slug = scope.slug()?;
        let manifest_path =
            InstallManifest::manifest_path_for(home, self.id, &scope_slug, &plan.mcp_server_key);
        let manifest =
            InstallManifest::load_for(home, self.id, &scope_slug, &plan.mcp_server_key)?.is_some();
        let host_detected = match scope {
            Scope::User => (self.user_marker)(home).exists(),
            Scope::Project(root) => root.is_dir(),
        };

        let mut report = StatusReport {
            client: self.label,
            scope: match scope {
                Scope::User => "user".to_string(),
                Scope::Project(root) => format!("project:{}", root.display()),
            },
            settings_path: settings_path.clone(),
            manifest_path,
            host_detected,
            manifest,
            ..StatusReport::default()
        };
        if !host_detected {
            report.note = Some(match scope {
                Scope::User => self.user_missing_hint.to_string(),
                Scope::Project(root) => format!("project root not found: {}", root.display()),
            });
            return Ok(report);
        }

        let (entry_present, found, stored_command) =
            read_toml_status(self, &settings_path, &plan.mcp_server_key)?;
        report.config_entry = entry_present;
        report.found_install_id = found.clone();
        if let Some(cmd) = stored_command {
            report.command_resolves = Some(crate::mcp_setup::host::command_resolves(&cmd));
            report.stored_command = Some(cmd);
        }
        // A manifest with no TOML entry means the agent's own CLI took it into its registry.
        report.installed = found
            .as_deref()
            .is_some_and(|id| is_ours(id, &plan.mcp_server_key))
            || (manifest && !entry_present && self.cli.is_some());
        report.note = match found {
            Some(id) if id == plan.install_id => {
                (!manifest).then(|| "config entry present, manifest missing".to_string())
            }
            Some(id) if is_ours(&id, &plan.mcp_server_key) => Some(format!(
                "installed by {id:?} (this build is {:?})",
                plan.install_id
            )),
            Some(id) => Some(format!(
                "key exists but is owned by {id:?}, not by {:?}",
                plan.install_id
            )),
            None if entry_present => Some(format!(
                "key exists but {INSTALL_ID_ENV_KEY} marker is missing"
            )),
            None if manifest => {
                Some("manifest present; the agent's own registry may hold the entry".to_string())
            }
            None => None,
        };
        Ok(report)
    }
}
