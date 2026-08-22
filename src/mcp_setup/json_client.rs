//! The engine behind every JSON-config agent. A client is pure data ([`JsonClient`]); this file
//! is the only place that knows how to merge, back up, and unmerge those files.

use std::path::{Path, PathBuf};

use crate::mcp_setup::backup::backup_file_if_exists;
use crate::mcp_setup::client::{ContextFile, McpClient};
use crate::mcp_setup::error::{Result, SetupError};
use crate::mcp_setup::hints::{self, ClientDoc};
use crate::mcp_setup::json_merge::{
    EntryStyle, ensure_key_available_for_apply, find_custom_mcp_server_key, foreign_entry_at,
    is_ours, mcp_command_from_value, mcp_install_id_from_value, servers_at,
};
use crate::mcp_setup::jsonc::{read_root_object, remove_in_file, upsert_in_file};
use crate::mcp_setup::manifest::{InstallManifest, MANIFEST_SCHEMA};
use crate::mcp_setup::types::{
    ApplyReport, INSTALL_ID_ENV_KEY, InstallPlan, RemoveReport, Scope, SetupContext, StatusReport,
    StdioMcpEntry, ensure_project_root,
};

/// A JSON-config agent, described declaratively. See `clients/` for the registry.
pub struct JsonClient {
    pub id: &'static str,
    pub label: &'static str,
    /// Where this client keeps MCP servers, in prose — rendered into the hint footer.
    pub config_hint: &'static str,
    /// Key path to the servers map, e.g. `["mcpServers"]` or `["mcp", "servers"]`.
    pub parent_path: &'static [&'static str],
    /// Config file in user scope; `None` when the agent has no global config.
    pub user_config: Option<fn(&Path) -> PathBuf>,
    /// Config file in project scope, given the project root; `None` when unsupported.
    pub project_config: Option<fn(&Path) -> PathBuf>,
    /// Directory whose existence means "this agent is installed for this user".
    pub user_marker: fn(&Path) -> PathBuf,
    pub user_missing_hint: &'static str,
    pub context: ContextFile,
    pub entry: EntryStyle,
}

impl JsonClient {
    fn doc(&self) -> ClientDoc {
        ClientDoc {
            label: self.label,
            config_hint: self.config_hint,
        }
    }

    fn config_path(&self, scope: &Scope, home: &Path) -> Result<PathBuf> {
        let path = match scope {
            Scope::User => self.user_config.map(|f| f(home)),
            Scope::Project(root) => self.project_config.map(|f| f(root)),
        };
        path.ok_or(SetupError::UnsupportedScope {
            client: self.label,
            scope: scope.name(),
        })
    }

    fn manifest_path(
        &self,
        ctx: &SetupContext,
        scope: &Scope,
        plan: &InstallPlan,
    ) -> Result<PathBuf> {
        Ok(InstallManifest::manifest_path_for(
            ctx.home_dir(),
            self.id,
            &scope.slug()?,
            &plan.mcp_server_key,
        ))
    }

    /// User scope requires the agent to actually be installed (we will not create `~/.foo` for an
    /// agent the user does not have). Project scope only requires the directory to exist.
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

    /// The entry as it will exist on disk (with the install-id marker), recorded in the manifest.
    fn manifest_entry(&self, plan: &InstallPlan) -> StdioMcpEntry {
        let mut s = plan.stdio.clone();
        s.env
            .insert(INSTALL_ID_ENV_KEY.to_string(), plan.install_id.clone());
        s
    }

    /// Nothing left in the config (already gone, or never written): still clean up our Markdown
    /// block and manifest so the uninstall is complete.
    fn no_entry_remove(
        &self,
        manifest: &Option<InstallManifest>,
        manifest_path: &Path,
        settings_path: PathBuf,
        home: &Path,
        scope_slug: &str,
        key: &str,
    ) -> Result<RemoveReport> {
        let mut report = RemoveReport {
            client: self.id,
            settings_path,
            manifest_path: manifest_path.to_path_buf(),
            ..RemoveReport::default()
        };
        hints::merge_remove_report(manifest.as_ref(), &mut report)?;
        InstallManifest::remove_for(home, self.id, scope_slug, key)?;
        Ok(report)
    }
}

impl McpClient for JsonClient {
    fn id(&self) -> &'static str {
        self.id
    }

    fn label(&self) -> &'static str {
        self.label
    }

    fn config_hint(&self) -> &'static str {
        self.config_hint
    }

    fn supports_project(&self) -> bool {
        self.project_config.is_some()
    }

    fn user_marker_dir(&self, home: &Path) -> PathBuf {
        (self.user_marker)(home)
    }

    fn apply(&self, ctx: &SetupContext, scope: &Scope, plan: &InstallPlan) -> Result<ApplyReport> {
        let home = ctx.home_dir();
        self.ensure_scope_ready(scope, home)?;

        let settings_path = self.config_path(scope, home)?;
        let manifest_path = self.manifest_path(ctx, scope, plan)?;
        let new_val = self.entry.build(&plan.stdio, &plan.install_id);

        let root = read_root_object(&settings_path)?;
        ensure_key_available_for_apply(
            &root,
            self.parent_path,
            &plan.mcp_server_key,
            &plan.mcp_server_key,
            &plan.install_id,
            plan.force,
        )?;
        // Only possible under `force` — without it the guard above would have refused. Recorded
        // so the apply report can say whose entry was replaced rather than overwriting quietly.
        let took_foreign_entry = foreign_entry_at(
            &root,
            self.parent_path,
            &plan.mcp_server_key,
            &plan.mcp_server_key,
        );

        // Re-running install with identical settings must not rewrite (or back up) the file.
        let changed = servers_at(&root, self.parent_path)
            .and_then(|servers| servers.get(&plan.mcp_server_key))
            .map(|existing| existing != &new_val)
            .unwrap_or(true);

        let backup_path = if changed {
            backup_file_if_exists(&settings_path)?
        } else {
            None
        };
        if changed {
            // Edits the file in place through the CST: the user's comments, key order and
            // indentation survive untouched.
            upsert_in_file(
                &settings_path,
                self.parent_path,
                &plan.mcp_server_key,
                &new_val,
            )?;
        }

        let mut manifest = InstallManifest {
            schema: MANIFEST_SCHEMA,
            client: self.id.to_string(),
            scope: scope.slug()?,
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
            note: took_foreign_entry.then(|| {
                "overwrote an unmanaged entry (--force); previous content is in the backup"
                    .to_string()
            }),
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

        let settings_path = self.config_path(scope, home)?;
        let manifest_path = self.manifest_path(ctx, scope, plan)?;
        let scope_slug = scope.slug()?;
        let manifest = InstallManifest::load_for(home, self.id, &scope_slug, &plan.mcp_server_key)?;

        if let Some(ref m) = manifest {
            m.ensure_matches(&settings_path, plan)?;
        }

        let root = read_root_object(&settings_path)?;
        let existing = servers_at(&root, self.parent_path)
            .and_then(|servers| servers.get(&plan.mcp_server_key))
            .cloned();
        let Some(existing) = existing else {
            return self.no_entry_remove(
                &manifest,
                &manifest_path,
                settings_path,
                home,
                &scope_slug,
                &plan.mcp_server_key,
            );
        };

        match mcp_install_id_from_value(&existing) {
            // Any version of *our* server is ours to remove — see `is_ours`.
            Some(id) if is_ours(&id, &plan.mcp_server_key) => {
                let backup_path = backup_file_if_exists(&settings_path)?;
                let removed =
                    remove_in_file(&settings_path, self.parent_path, &plan.mcp_server_key)?;
                debug_assert!(removed);
                let mut report = RemoveReport {
                    client: self.id,
                    settings_path,
                    manifest_path: manifest_path.clone(),
                    backup_path,
                    removed: true,
                    ..RemoveReport::default()
                };
                hints::merge_remove_report(manifest.as_ref(), &mut report)?;
                InstallManifest::remove_for(home, self.id, &scope_slug, &plan.mcp_server_key)?;
                Ok(report)
            }
            Some(id) => Err(SetupError::ManifestConflict(format!(
                "MCP key {:?} is owned by {id:?}, not by {:?} — refusing to delete",
                plan.mcp_server_key, plan.install_id
            ))),
            None => Err(SetupError::NotOurInstall {
                key: plan.mcp_server_key.clone(),
                install_id_key: INSTALL_ID_ENV_KEY,
            }),
        }
    }

    fn status(
        &self,
        ctx: &SetupContext,
        scope: &Scope,
        plan: &InstallPlan,
    ) -> Result<StatusReport> {
        let home = ctx.home_dir();
        let settings_path = self.config_path(scope, home)?;
        let manifest_path = self.manifest_path(ctx, scope, plan)?;
        let manifest =
            InstallManifest::load_for(home, self.id, &scope.slug()?, &plan.mcp_server_key)?
                .is_some();

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

        let root = read_root_object(&settings_path)?;
        let entry = servers_at(&root, self.parent_path)
            .and_then(|servers| servers.get(&plan.mcp_server_key));
        let found = entry.and_then(mcp_install_id_from_value);

        report.config_entry = entry.is_some();
        report.installed = found
            .as_deref()
            .is_some_and(|id| is_ours(id, &plan.mcp_server_key));
        report.found_install_id = found.clone();

        // Read back the command the config actually names and check it still launches. An entry
        // can carry our key and our install id yet point at a binary that no longer exists.
        if let Some(cmd) = entry.and_then(mcp_command_from_value) {
            report.stored_command = Some(cmd.to_string());
            report.command_resolves = Some(crate::mcp_setup::host::command_resolves(cmd));
        }

        if !report.config_entry
            && let Some(custom_key) = find_custom_mcp_server_key(
                &root,
                self.parent_path,
                &plan.mcp_server_key,
                &plan.stdio.command,
            )
        {
            report.custom_installed = true;
            report.note = Some(format!(
                "matching command found under unmanaged key {custom_key:?}"
            ));
            report.custom_key = Some(custom_key);
            return Ok(report);
        }

        report.note = match found {
            Some(id) if id == plan.install_id => {
                (!manifest).then(|| "config entry present, manifest missing".to_string())
            }
            // Ours, but written by another version of this server: install will upgrade it.
            Some(id) if is_ours(&id, &plan.mcp_server_key) => Some(format!(
                "installed by {id:?} (this build is {:?})",
                plan.install_id
            )),
            Some(id) => Some(format!(
                "key exists but is owned by {id:?}, not by {:?}",
                plan.install_id
            )),
            None if entry.is_some() => Some(format!(
                "key exists but {INSTALL_ID_ENV_KEY} marker is missing"
            )),
            None if manifest => Some("manifest present, config entry missing".to_string()),
            None => None,
        };
        Ok(report)
    }
}
