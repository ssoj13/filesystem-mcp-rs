//! Sidecar manifest under `~/.mcp-setup/manifests/`: records what we installed, so `uninstall`
//! stays precise months later even if the user's config has drifted.
//!
//! One manifest per `(client, scope, server key)` — which is exactly the uniqueness of a config
//! entry. The file name deliberately does **not** carry the version: an upgraded server must still
//! find (and be able to clean up) what its previous version installed.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::mcp_setup::error::{Result, SetupError};
use crate::mcp_setup::json_merge::is_ours;
use crate::mcp_setup::types::{InstallPlan, StdioMcpEntry};

pub const MANIFEST_SCHEMA: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallManifest {
    pub schema: u32,
    pub client: String,
    pub scope: String,
    pub settings_path: PathBuf,
    pub mcp_server_key: String,
    pub install_id: String,
    pub entry: StdioMcpEntry,
    /// Project root when `scope` starts with `project_`.
    #[serde(default)]
    pub project_root: Option<PathBuf>,
    /// Context file that received our managed Markdown block, if any.
    /// The alias keeps manifests written before the crate extraction readable.
    #[serde(default, alias = "second_level_qwen_md")]
    pub hints_file: Option<PathBuf>,
    /// Marker token of that block (derived from key + install id).
    #[serde(default, alias = "second_level_marker_token")]
    pub hints_marker: Option<String>,
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

impl InstallManifest {
    fn dir(home: &Path) -> PathBuf {
        home.join(".mcp-setup").join("manifests")
    }

    pub fn manifest_path_for(home: &Path, client: &str, scope: &str, mcp_server_key: &str) -> PathBuf {
        Self::dir(home).join(format!(
            "{}__{}__{}.json",
            sanitize(client),
            sanitize(scope),
            sanitize(mcp_server_key)
        ))
    }

    /// Manifests written before the file name dropped the install id: `<client>__<scope>__<key>__<id>.json`.
    /// Without this, upgrading the server would orphan the old manifest and `uninstall` would lose
    /// track of the Markdown block it has to remove.
    fn legacy_path(home: &Path, client: &str, scope: &str, mcp_server_key: &str) -> Option<PathBuf> {
        let prefix = format!(
            "{}__{}__{}__",
            sanitize(client),
            sanitize(scope),
            sanitize(mcp_server_key)
        );
        let mut found: Vec<PathBuf> = std::fs::read_dir(Self::dir(home))
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(".json"))
            })
            .collect();
        found.sort();
        found.pop()
    }

    /// Load the manifest for this (client, scope, key), falling back to a legacy file.
    pub fn load_for(
        home: &Path,
        client: &str,
        scope: &str,
        mcp_server_key: &str,
    ) -> Result<Option<Self>> {
        let path = Self::manifest_path_for(home, client, scope, mcp_server_key);
        if let Some(m) = Self::load(&path)? {
            return Ok(Some(m));
        }
        match Self::legacy_path(home, client, scope, mcp_server_key) {
            Some(legacy) => Self::load(&legacy),
            None => Ok(None),
        }
    }

    /// Delete the manifest for this (client, scope, key), including any legacy file.
    pub fn remove_for(home: &Path, client: &str, scope: &str, mcp_server_key: &str) -> Result<()> {
        Self::remove_file(&Self::manifest_path_for(home, client, scope, mcp_server_key))?;
        if let Some(legacy) = Self::legacy_path(home, client, scope, mcp_server_key) {
            Self::remove_file(&legacy)?;
        }
        Ok(())
    }

    /// A manifest pointing somewhere else than the plan means the caller is about to delete the
    /// wrong thing — refuse rather than guess. The install id only has to be *ours* (same server
    /// key), not identical: the entry may have been written by an earlier version.
    pub fn ensure_matches(&self, settings_path: &Path, plan: &InstallPlan) -> Result<()> {
        if self.settings_path != settings_path {
            return Err(SetupError::ManifestConflict(format!(
                "manifest targets {:?}, but current settings path is {settings_path:?}",
                self.settings_path
            )));
        }
        if self.mcp_server_key != plan.mcp_server_key {
            return Err(SetupError::ManifestConflict(format!(
                "manifest key {:?} differs from plan {:?}",
                self.mcp_server_key, plan.mcp_server_key
            )));
        }
        if !is_ours(&self.install_id, &plan.mcp_server_key) {
            return Err(SetupError::ManifestConflict(format!(
                "manifest install_id {:?} is not owned by {:?}",
                self.install_id, plan.mcp_server_key
            )));
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let raw =
            std::fs::read_to_string(path).map_err(|e| SetupError::io(path.to_path_buf(), e))?;
        let m: Self = serde_json::from_str(&raw).map_err(|e| SetupError::InvalidJson {
            path: path.to_path_buf(),
            source: e,
        })?;
        if m.schema != 1 && m.schema != MANIFEST_SCHEMA {
            return Err(SetupError::ManifestConflict(format!(
                "unsupported manifest schema {} (expected 1 or {MANIFEST_SCHEMA})",
                m.schema
            )));
        }
        Ok(Some(m))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| SetupError::io(parent.to_path_buf(), e))?;
        }
        let raw = serde_json::to_string_pretty(self).map_err(|e| SetupError::InvalidJson {
            path: path.to_path_buf(),
            source: e,
        })?;
        std::fs::write(path, raw).map_err(|e| SetupError::io(path.to_path_buf(), e))?;
        Ok(())
    }

    pub fn remove_file(path: &Path) -> Result<()> {
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| SetupError::io(path.to_path_buf(), e))?;
        }
        Ok(())
    }
}
