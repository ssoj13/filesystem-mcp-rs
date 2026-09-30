use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use crossbeam_channel::{Sender, TrySendError};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanDiagnostics {
    pub walk_errors: u64,
    pub metadata_errors: u64,
    pub malformed_records: u64,
    pub depth_errors: u64,
}

impl ScanDiagnostics {
    pub fn total_errors(&self) -> u64 {
        self.walk_errors
            .saturating_add(self.metadata_errors)
            .saturating_add(self.malformed_records)
            .saturating_add(self.depth_errors)
    }
}

#[derive(Debug)]
pub struct TreeEntry {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
    pub own_size: u64,
    pub children: Vec<TreeEntry>,
    pub is_dir: bool,
    pub ext: String,
    pub file_count: u64,
    pub dir_count: u64,
    pub modified_time: Option<u64>,
}

impl TreeEntry {
    pub fn new_file(
        name: String,
        path: PathBuf,
        size: u64,
        ext: String,
        modified_time: Option<u64>,
    ) -> Self {
        Self {
            name,
            path,
            size,
            own_size: size,
            children: Vec::new(),
            is_dir: false,
            ext,
            file_count: 1,
            dir_count: 0,
            modified_time,
        }
    }

    pub fn new_dir(name: String, path: PathBuf) -> Self {
        Self {
            name,
            path,
            size: 0,
            own_size: 0,
            children: Vec::new(),
            is_dir: true,
            ext: String::new(),
            file_count: 0,
            dir_count: 0,
            modified_time: None,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Self> {
        let mut pending = vec![self];
        std::iter::from_fn(move || {
            let next = pending.pop()?;
            pending.extend(next.children.iter().rev());
            Some(next)
        })
    }
}

impl Drop for TreeEntry {
    fn drop(&mut self) {
        let mut pending = std::mem::take(&mut self.children);
        while let Some(mut child) = pending.pop() {
            pending.append(&mut child.children);
        }
    }
}

pub struct ScanBuild {
    pub tree: TreeEntry,
    pub diagnostics: ScanDiagnostics,
}

/// Failure from the native NTFS scanner. Backend unavailability permits a
/// standard-walker fallback; cancellation and other failures remain distinct.
#[derive(Debug)]
pub enum ScanFailure {
    Cancelled,
    BackendUnavailable(anyhow::Error),
    Failed(anyhow::Error),
}

impl std::fmt::Display for ScanFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("scan cancelled"),
            Self::BackendUnavailable(error) => write!(f, "scan backend unavailable: {error}"),
            Self::Failed(error) => write!(f, "scan failed: {error}"),
        }
    }
}

impl std::error::Error for ScanFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cancelled => None,
            Self::BackendUnavailable(error) | Self::Failed(error) => Some(error.as_ref()),
        }
    }
}

impl From<anyhow::Error> for ScanFailure {
    fn from(error: anyhow::Error) -> Self {
        Self::Failed(error)
    }
}

#[derive(Clone, Copy)]
pub enum ScanPhase {
    IndexingVolume,
    SelectingTree,
    MeasuringTree,
}

#[derive(Clone, Copy)]
pub struct ScanProgressUpdate {
    pub phase: ScanPhase,
    pub items: u64,
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    pub errors: u64,
}

pub enum ScanMsg {
    Progress(ScanProgressUpdate),
}

pub fn send_progress_update(
    tx: &Sender<ScanMsg>,
    cancel: &AtomicBool,
    update: ScanProgressUpdate,
) -> Result<(), ScanFailure> {
    if cancel.load(Ordering::Acquire) {
        return Err(ScanFailure::Cancelled);
    }
    match tx.try_send(ScanMsg::Progress(update)) {
        Ok(()) | Err(TrySendError::Full(_)) => Ok(()),
        Err(TrySendError::Disconnected(_)) => Err(ScanFailure::Cancelled),
    }
}
