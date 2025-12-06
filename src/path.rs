use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use tokio::fs;

use crate::allowed::AllowedDirs;

/// Normalize path separators and collapse `.`/`..` where possible.
fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();

    for comp in path.components() {
        match comp {
            Component::CurDir => continue,
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }

    out
}

fn is_within_allowed(target: &Path, allowed: &[PathBuf]) -> bool {
    allowed.iter().any(|dir| target.starts_with(dir))
}

/// Resolve and validate a requested path against allowed directories.
///
/// Rules:
/// - Relative paths resolved against current_dir.
/// - Uses canonicalized real path when it exists (symlink-safe).
/// - For non-existent paths, validates canonicalized parent dir.
pub async fn resolve_validated_path(
    requested: &str,
    allowed: &AllowedDirs,
    allow_symlink_escape: bool,
) -> Result<PathBuf> {
    let raw = PathBuf::from(requested);
    let absolute = if raw.is_absolute() {
        raw
    } else {
        std::env::current_dir()
            .context("cannot get current_dir")?
            .join(raw)
    };
    let normalized = normalize_path(&absolute);

    let allowed_snapshot = allowed.snapshot().await;
    if allowed_snapshot.is_empty() {
        bail!("Access denied - no allowed directories configured");
    }

    // First try canonicalization (handles symlinks).
    match normalized.canonicalize() {
        Ok(real) => {
            if !is_within_allowed(&real, &allowed_snapshot) {
                if allow_symlink_escape {
                    let meta = fs::symlink_metadata(&normalized).await?;
                    if meta.file_type().is_symlink() && is_within_allowed(&normalized, &allowed_snapshot) {
                        return Ok(normalized);
                    }
                }
                bail!(
                    "Access denied - path outside allowed directories: {}",
                    real.display()
                );
            }
            Ok(real)
        }
        Err(err) => {
            // If file does not exist, validate parent dir real path.
            if err.kind() == std::io::ErrorKind::NotFound {
                let mut cursor = normalized.as_path();
                let mut existing_parent: Option<PathBuf> = None;
                while let Some(parent) = cursor.parent() {
                    if parent.exists() {
                        existing_parent = Some(parent.to_path_buf());
                        break;
                    }
                    cursor = parent;
                }

                let parent = existing_parent.ok_or_else(|| {
                    anyhow!(
                        "Parent directory does not exist: {}",
                        normalized.display()
                    )
                })?;
                let parent_real = parent
                    .canonicalize()
                    .with_context(|| format!("Parent directory does not exist: {}", parent.display()))?;
                if !is_within_allowed(&parent_real, &allowed_snapshot) {
                    bail!(
                        "Access denied - parent directory outside allowed directories: {}",
                        parent_real.display()
                    );
                }
                Ok(normalized)
            } else {
                Err(err).with_context(|| format!("Failed to access path: {}", normalized.display()))
            }
        }
    }
}
