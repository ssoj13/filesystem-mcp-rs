//! Shared glob utilities for file pattern matching.

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};

/// Build a GlobSet from a single pattern.
pub fn build_glob(pattern: &str) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    builder.add(Glob::new(pattern).with_context(|| format!("Invalid glob pattern: {}", pattern))?);
    Ok(builder.build()?)
}

/// Build a GlobSet from multiple patterns.
pub fn build_glob_set(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pat in patterns {
        builder.add(Glob::new(pat).with_context(|| format!("Invalid glob pattern: {}", pat))?);
    }
    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_glob_simple() {
        let glob = build_glob("*.txt").unwrap();
        assert!(glob.is_match("file.txt"));
        assert!(!glob.is_match("file.rs"));
    }

    #[test]
    fn test_build_glob_set_multiple() {
        let glob = build_glob_set(&["*.txt".to_string(), "*.rs".to_string()]).unwrap();
        assert!(glob.is_match("file.txt"));
        assert!(glob.is_match("main.rs"));
        assert!(!glob.is_match("file.md"));
    }

    #[test]
    fn test_build_glob_invalid() {
        let result = build_glob("[invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_build_glob_set_empty() {
        let glob = build_glob_set(&[]).unwrap();
        assert!(!glob.is_match("anything.txt"));
    }
}
