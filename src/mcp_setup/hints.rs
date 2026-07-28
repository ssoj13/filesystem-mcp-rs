//! The managed Markdown block inside an agent's context file.
//!
//! An outer `<!-- mcp-setup:<token>:begin/end -->` region is owned by us; inside it, only the
//! `managed:` slice is overwritten on apply, so notes a user writes in the outer region survive.
//! `remove` deletes the whole outer region. The token is derived from key + install id, so two
//! different servers never fight over the same block.

use std::path::{Path, PathBuf};

use crate::mcp_setup::backup::backup_file_if_exists;
use crate::mcp_setup::client::ContextFile;
use crate::mcp_setup::error::{Result, SetupError};
use crate::mcp_setup::manifest::InstallManifest;
use crate::mcp_setup::marked_md::{
    marker_token_from, read_or_empty, remove_marked_section, upsert_marked_section_with_preamble,
    write_or_delete_if_empty,
};
use crate::mcp_setup::types::{ApplyReport, InstallPlan, RemoveReport, Scope};

/// Identity of the client whose context file we are writing into.
#[derive(Debug, Clone, Copy)]
pub struct ClientDoc {
    pub label: &'static str,
    pub config_hint: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct HintOutcome {
    pub path: Option<PathBuf>,
    pub changed: bool,
    pub backup_path: Option<PathBuf>,
    pub marker_token: Option<String>,
}

fn body(plan: &InstallPlan, client: ClientDoc) -> String {
    if let Some(ref override_body) = plan.hints.body_override {
        return override_body.clone();
    }
    plan.docs
        .render(&plan.mcp_server_key, client.label, client.config_hint)
}

/// Compares through the filesystem, so `~/a/../a/X.md` and `~/a/X.md` are recognised as one file.
fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

fn resolve_snippet(scope: &Scope, home: &Path, rel: &Path) -> PathBuf {
    if rel.is_absolute() {
        rel.to_path_buf()
    } else {
        ContextFile::snippet_base(scope, home).join(rel)
    }
}

/// The snippet is a *user-owned* file merged as preamble. Pointing it at the integrated context
/// file would make apply feed the file into itself, so that is rejected outright.
fn snippet_preamble(
    plan: &InstallPlan,
    scope: &Scope,
    home: &Path,
    integrated: &Path,
) -> Result<Option<String>> {
    let Some(ref rel) = plan.hints.snippet_source else {
        return Ok(None);
    };
    if rel.as_os_str().is_empty() {
        return Err(SetupError::InvalidBundle(
            "hints snippet path is empty".to_string(),
        ));
    }
    let resolved = resolve_snippet(scope, home, rel);
    if resolved == integrated || same_file(&resolved, integrated) {
        return Err(SetupError::InvalidBundle(format!(
            "hints snippet must not be the integrated context file ({}) — use a separate file",
            integrated.display()
        )));
    }
    if !resolved.is_file() {
        return Err(SetupError::InvalidBundle(format!(
            "hints snippet not found: {}",
            resolved.display()
        )));
    }
    read_or_empty(&resolved).map(Some)
}

/// Upsert the managed block. No-ops when hints are disabled, the client has no context file for
/// this scope, or the host supplied no docs.
pub fn apply(
    plan: &InstallPlan,
    context: &ContextFile,
    client: ClientDoc,
    scope: &Scope,
    home: &Path,
) -> Result<HintOutcome> {
    if !plan.hints.enabled {
        return Ok(HintOutcome::default());
    }
    let Some(path) = context.path(scope, home) else {
        return Ok(HintOutcome::default());
    };
    let body = body(plan, client);
    if body.trim().is_empty() {
        return Ok(HintOutcome::default());
    }

    let marker_token = marker_token_from(&plan.install_id, &plan.mcp_server_key);
    let before = read_or_empty(&path)?;
    let snippet = snippet_preamble(plan, scope, home, &path)?;
    let (after, changed) =
        upsert_marked_section_with_preamble(&before, &marker_token, &body, snippet.as_deref());

    let backup_path = if changed {
        backup_file_if_exists(&path)?
    } else {
        None
    };
    if changed {
        write_or_delete_if_empty(&path, &after)?;
    }

    Ok(HintOutcome {
        path: Some(path),
        changed,
        backup_path,
        marker_token: Some(marker_token),
    })
}

/// Remove the managed block recorded in the manifest. Without a manifest we do nothing: guessing
/// which block was ours would risk eating a user's own notes.
pub fn remove_from_manifest(manifest: &InstallManifest) -> Result<(bool, Option<PathBuf>)> {
    let (Some(path), Some(tok)) = (&manifest.hints_file, &manifest.hints_marker) else {
        return Ok((false, None));
    };
    let before = read_or_empty(path)?;
    let (after, changed) = remove_marked_section(&before, tok);
    if !changed {
        return Ok((false, None));
    }
    let backup = backup_file_if_exists(path)?;
    write_or_delete_if_empty(path, &after)?;
    Ok((true, backup))
}

/// Apply hints, then fold the outcome into the manifest and the apply report.
pub fn apply_to_manifest_and_report(
    plan: &InstallPlan,
    manifest: &mut InstallManifest,
    report: &mut ApplyReport,
    context: &ContextFile,
    client: ClientDoc,
    scope: &Scope,
    home: &Path,
) -> Result<()> {
    let outcome = apply(plan, context, client, scope, home)?;
    manifest.hints_file = outcome.path.clone();
    manifest.hints_marker = outcome.marker_token.clone();
    report.hints_path = outcome.path;
    report.hints_changed = outcome.changed;
    report.hints_backup = outcome.backup_path;
    report.changed |= outcome.changed;
    Ok(())
}

/// Remove hints via manifest metadata and fold into the remove report.
pub fn merge_remove_report(
    manifest: Option<&InstallManifest>,
    report: &mut RemoveReport,
) -> Result<()> {
    let Some(m) = manifest else {
        return Ok(());
    };
    let (changed, backup) = remove_from_manifest(m)?;
    report.hints_changed = changed;
    report.hints_backup = backup;
    Ok(())
}
