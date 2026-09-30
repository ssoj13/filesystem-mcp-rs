//! Filesystem traversal with streaming output and bounded in-process buffering.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use walkdir::WalkDir;

#[cfg(windows)]
mod ntfs;
#[cfg(windows)]
mod scanner;

#[cfg(windows)]
pub use ntfs::{
    diagnose_fsctl_enum_usn, is_ntfs_available, mft_dump_names, probe_raw_volume_access,
    scan_ntfs_tree, scan_ntfs_tree_with_options, scan_ntfs_tree_with_progress,
};
#[cfg(windows)]
pub use scanner::{
    ScanDiagnostics, ScanFailure, ScanMsg, ScanPhase, ScanProgressUpdate, TreeEntry,
};

#[cfg(windows)]
#[derive(Debug)]
pub enum NtfsStreamError {
    Backend(ScanFailure),
    Sink(anyhow::Error),
    Cancelled,
}

/// Stream a bounded NTFS tree through the same entry interface as the standard
/// backend. If the native backend is unavailable or its entry cap is reached,
/// this returns an error before publishing any entry to the sink.
#[cfg(windows)]
pub fn scan_ntfs_stream(
    root: &Path,
    cancel: &AtomicBool,
    include: impl Fn(&Path) -> bool,
    on_entry: impl FnMut(&Entry, Progress) -> anyhow::Result<Visit>,
) -> Result<Progress, NtfsStreamError> {
    let (tree, diagnostics) = scan_ntfs_tree(root, cancel).map_err(|error| match error {
        ScanFailure::Cancelled => NtfsStreamError::Cancelled,
        other => NtfsStreamError::Backend(other),
    })?;
    stream_ntfs_tree(&tree, &diagnostics, cancel, include, on_entry)
}

/// Stream an already scanned NTFS tree, allowing callers to report progress
/// during `scan_ntfs_tree_with_progress` before they begin publishing entries.
#[cfg(windows)]
pub fn stream_ntfs_tree(
    tree: &TreeEntry,
    diagnostics: &ScanDiagnostics,
    cancel: &AtomicBool,
    include: impl Fn(&Path) -> bool,
    mut on_entry: impl FnMut(&Entry, Progress) -> anyhow::Result<Visit>,
) -> Result<Progress, NtfsStreamError> {
    let mut progress = Progress {
        errors: diagnostics.total_errors(),
        ..Progress::default()
    };
    let mut pending = tree.children.iter().rev().collect::<Vec<_>>();
    while let Some(node) = pending.pop() {
        if cancel.load(Ordering::Acquire) {
            return Err(NtfsStreamError::Cancelled);
        }
        if !include(&node.path) {
            continue;
        }
        if node.is_dir {
            pending.extend(node.children.iter().rev());
            progress.directories = progress.directories.saturating_add(1);
        } else {
            progress.files = progress.files.saturating_add(1);
        }
        progress.entries = progress.entries.saturating_add(1);
        let entry = Entry {
            path: node.path.clone(),
            name: node.path.file_name().unwrap_or_default().to_owned(),
            kind: if node.is_dir {
                EntryKind::Directory
            } else {
                EntryKind::File
            },
            len: node.own_size,
            modified: node.modified_time.and_then(|seconds| {
                std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(seconds))
            }),
        };
        if on_entry(&entry, progress).map_err(NtfsStreamError::Sink)? == Visit::Stop {
            break;
        }
    }
    Ok(progress)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
}

#[derive(Debug)]
pub struct Entry {
    pub path: PathBuf,
    pub name: OsString,
    pub kind: EntryKind,
    pub len: u64,
    pub modified: Option<SystemTime>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Progress {
    pub entries: u64,
    pub files: u64,
    pub directories: u64,
    pub errors: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Visit {
    Continue,
    Stop,
}

#[derive(Debug)]
pub enum ScanError<E> {
    Cancelled,
    Root(walkdir::Error),
    Sink(E),
}

impl<E: std::fmt::Display> std::fmt::Display for ScanError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("scan cancelled"),
            Self::Root(error) => write!(f, "cannot scan root: {error}"),
            Self::Sink(error) => write!(f, "scan sink failed: {error}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ScanError<E> {}

/// Walk a directory without retaining entries. Directory errors count toward
/// `Progress::errors`; callers should treat a nonzero count as a partial scan.
/// `include` can reject a subtree before it is traversed.
pub fn scan_standard<E>(
    root: &Path,
    cancel: &AtomicBool,
    include: impl Fn(&Path) -> bool,
    mut on_entry: impl FnMut(&Entry, Progress) -> Result<Visit, E>,
) -> Result<Progress, ScanError<E>> {
    let walker = WalkDir::new(root)
        .follow_links(false)
        .max_open(16)
        .into_iter()
        .filter_entry(|entry| entry.depth() == 0 || include(entry.path()));
    let mut progress = Progress::default();
    for item in walker {
        if cancel.load(Ordering::Acquire) {
            return Err(ScanError::Cancelled);
        }
        let item = match item {
            Ok(item) => item,
            Err(error) if error.depth() == 0 => return Err(ScanError::Root(error)),
            Err(_) => {
                progress.errors = progress.errors.saturating_add(1);
                continue;
            }
        };
        if item.depth() == 0 {
            continue;
        }
        let kind = if item.file_type().is_symlink() {
            EntryKind::Symlink
        } else if item.file_type().is_dir() {
            EntryKind::Directory
        } else {
            EntryKind::File
        };
        let metadata = if kind == EntryKind::Symlink {
            std::fs::symlink_metadata(item.path()).ok()
        } else {
            item.metadata().ok()
        };
        let metadata = match metadata {
            Some(metadata) => metadata,
            None => {
                progress.errors = progress.errors.saturating_add(1);
                continue;
            }
        };
        progress.entries = progress.entries.saturating_add(1);
        match kind {
            EntryKind::Directory => progress.directories = progress.directories.saturating_add(1),
            EntryKind::File | EntryKind::Symlink => {
                progress.files = progress.files.saturating_add(1)
            }
        }
        let entry = Entry {
            path: item.path().to_path_buf(),
            name: item.file_name().to_owned(),
            kind,
            len: metadata.len(),
            modified: metadata.modified().ok(),
        };
        if on_entry(&entry, progress).map_err(ScanError::Sink)? == Visit::Stop {
            break;
        }
    }
    Ok(progress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streams_entries_and_skips_subtrees() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("keep")).unwrap();
        std::fs::create_dir(tmp.path().join("skip")).unwrap();
        std::fs::write(tmp.path().join("keep").join("one"), b"1").unwrap();
        std::fs::write(tmp.path().join("skip").join("two"), b"2").unwrap();
        let mut paths = Vec::new();
        let progress = scan_standard(
            tmp.path(),
            &AtomicBool::new(false),
            |path| !path.ends_with("skip"),
            |entry, _| {
                paths.push(entry.path.clone());
                Ok::<_, std::convert::Infallible>(Visit::Continue)
            },
        )
        .unwrap();
        assert_eq!(progress.entries, 2);
        assert!(paths.iter().any(|path| path.ends_with("one")));
        assert!(!paths.iter().any(|path| path.ends_with("two")));
    }

    #[test]
    fn cancellation_is_observed() {
        let tmp = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(true);
        let result = scan_standard(
            tmp.path(),
            &cancel,
            |_| true,
            |_, _| Ok::<_, std::convert::Infallible>(Visit::Continue),
        );
        assert!(matches!(result, Err(ScanError::Cancelled)));
    }

    #[cfg(windows)]
    #[test]
    fn ntfs_backend_streams_nested_temp_directory() {
        let tmp = tempfile::tempdir().unwrap();
        if !is_ntfs_available(tmp.path()) {
            return;
        }
        std::fs::create_dir(tmp.path().join("nested")).unwrap();
        std::fs::write(tmp.path().join("nested").join("needle.txt"), b"needle").unwrap();
        std::fs::hard_link(
            tmp.path().join("nested").join("needle.txt"),
            tmp.path().join("nested").join("alias.txt"),
        )
        .unwrap();
        let mut updates = 0;
        let (tree, diagnostics) =
            scan_ntfs_tree_with_progress(tmp.path(), &AtomicBool::new(false), |_| updates += 1)
                .unwrap();
        assert!(updates >= 1);
        let mut names = Vec::new();
        let progress = stream_ntfs_tree(
            &tree,
            &diagnostics,
            &AtomicBool::new(false),
            |_| true,
            |entry, _| {
                names.push(entry.name.clone());
                Ok(Visit::Continue)
            },
        )
        .unwrap_or_else(|error| panic!("NTFS scan failed: {error:?}"));
        assert!(progress.entries >= 2);
        assert!(
            names
                .iter()
                .any(|name| name == "needle.txt" || name == "alias.txt")
        );

        let (tree, diagnostics) =
            scan_ntfs_tree_with_options(tmp.path(), &AtomicBool::new(false), false, |_| {})
                .unwrap();
        let mut names = Vec::new();
        stream_ntfs_tree(
            &tree,
            &diagnostics,
            &AtomicBool::new(false),
            |_| true,
            |entry, _| {
                names.push(entry.name.clone());
                Ok(Visit::Continue)
            },
        )
        .unwrap();
        assert!(names.iter().any(|name| name == "needle.txt"));
        assert!(names.iter().any(|name| name == "alias.txt"));
    }
}
