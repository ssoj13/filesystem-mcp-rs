use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Receipt {
    pub request_id: String,
    pub target_seq: i64,
    pub status: String,
    pub work_root: PathBuf,
    pub next_scan_at_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct Status {
    pub state: String,
    pub active_generation: i64,
    pub desired_seq: i64,
    pub completed_seq: i64,
    pub last_verified: Option<i64>,
    pub last_error: Option<String>,
    pub next_scan_at_ms: Option<i64>,
    pub background: bool,
    /// `run`, `paused` or `stopped`: what an operator asked this root's scans to do.
    pub control: String,
    pub progress: Option<ScanProgress>,
}

/// What `Indexer::scan_control` does. The request is written to the database, so it reaches a
/// scan running in another process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanAction {
    /// Report only.
    Status,
    /// Let the root run again and queue a scan (needs a path).
    Start,
    /// End the running scan (its rows are kept for a later resume) and hold the root.
    Stop,
    /// Hold the running scan in place, and hold the root.
    Pause,
    /// Release a paused or stopped root; no new scan is queued.
    Resume,
}

#[derive(Debug, Clone)]
pub struct ScanInfo {
    pub path: PathBuf,
    pub status: Status,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanProgress {
    pub attempt_id: i64,
    pub attempt_state: String,
    pub entries_seen: u64,
    pub dirs_seen: u64,
    pub current_path: Option<PathBuf>,
    pub started: i64,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            state: "unindexed".into(),
            active_generation: 0,
            desired_seq: 0,
            completed_seq: 0,
            last_verified: None,
            last_error: None,
            next_scan_at_ms: None,
            background: false,
            control: "run".into(),
            progress: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Match {
    pub path: PathBuf,
    pub kind: String,
    pub size: u64,
    pub modified: Option<i64>,
}

#[derive(Debug, Clone, Copy)]
pub enum MatchMode {
    Exact,
    Prefix,
    Contains,
    Glob,
    Regex,
}

#[derive(Debug, Default, Clone)]
pub struct FragmentFilter {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct SearchFilters {
    pub name: FragmentFilter,
    pub extension: FragmentFilter,
    pub path: FragmentFilter,
    pub kind: EntryKind,
}

#[derive(Debug, Default, Clone, Copy)]
pub enum EntryKind {
    #[default]
    All,
    Files,
    Directories,
}

#[derive(Debug)]
pub struct SearchResult {
    pub matches: Vec<Match>,
    pub truncated: bool,
    pub status: Status,
}
