use std::path::PathBuf;

use anyhow::Result;
use globset::{Glob, GlobSet, GlobSetBuilder};
use tokio::fs;

use crate::allowed::AllowedDirs;
use crate::path::resolve_validated_path;

pub async fn search_paths(
    root: &str,
    pattern: &str,
    exclude_patterns: &[String],
    allowed: &AllowedDirs,
    allow_symlink_escape: bool,
) -> Result<Vec<PathBuf>> {
    let root_path = resolve_validated_path(root, allowed, allow_symlink_escape).await?;
    let matcher = build_glob(pattern)?;
    let exclude = build_glob_set(exclude_patterns)?;

    let mut stack = vec![root_path.clone()];
    let mut results = Vec::new();

    while let Some(current) = stack.pop() {
        let mut dir = fs::read_dir(&current).await?;
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            let rel = path.strip_prefix(&root_path).unwrap_or(&path);
            let rel_str = rel.to_string_lossy();

            if exclude.is_match(rel_str.as_ref()) {
                continue;
            }

            // Validate each path (symlink-safe)
            let _ = resolve_validated_path(
                path.to_string_lossy().as_ref(),
                allowed,
                allow_symlink_escape,
            )
            .await?;

            if matcher.is_match(rel_str.as_ref()) {
                results.push(path.clone());
            }

            if entry.file_type().await?.is_dir() {
                stack.push(path);
            }
        }
    }

    Ok(results)
}

fn build_glob(pattern: &str) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    builder.add(Glob::new(pattern)?);
    Ok(builder.build()?)
}

fn build_glob_set(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pat in patterns {
        builder.add(Glob::new(pat)?);
    }
    Ok(builder.build()?)
}

pub fn build_exclude_set(patterns: &[String]) -> Result<GlobSet> {
    build_glob_set(patterns)
}
