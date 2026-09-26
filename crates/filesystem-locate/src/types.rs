use std::path::{Path, PathBuf};
use std::time::Duration;

/// Knobs of the index worker. `Default` is the behaviour that ships; the MCP layer builds one
/// from `FS_MCP_LOCATE_*` (this crate reads no environment itself).
#[derive(Debug, Clone)]
pub struct IndexerConfig {
    /// Rows per scan commit.
    pub scan_batch: usize,
    /// After a commit the writer rests this many times as long as the commit took.
    pub write_rest: u32,
    /// Upper bound of that rest.
    pub write_pause_max: Duration,
    /// Normalised path prefixes the scanner does not enter (see [`IndexerConfig::with_exclude`]).
    pub exclude: Vec<String>,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            scan_batch: crate::DEFAULT_SCAN_BATCH,
            write_rest: crate::DEFAULT_WRITE_REST,
            write_pause_max: crate::DEFAULT_WRITE_PAUSE_MAX,
            exclude: Vec::new(),
        }
    }
}

impl IndexerConfig {
    /// Do not enter these directories. Each is matched as a whole path component prefix, so
    /// `C:\Windows\WinSxS` covers everything below it but not `C:\Windows\WinSxSExtra`; on
    /// Windows case, slash direction, a trailing slash and the `\\?\` prefix do not matter.
    pub fn with_exclude<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.exclude = paths
            .into_iter()
            .map(|path| normalize_for_match(path.as_ref()))
            .filter(|path| !path.is_empty())
            .collect();
        self
    }

    pub fn is_excluded(&self, path: &Path) -> bool {
        if self.exclude.is_empty() {
            return false;
        }
        let path = normalize_for_match(&path.to_string_lossy());
        self.exclude.iter().any(|prefix| {
            path == *prefix
                || path
                    .strip_prefix(prefix.as_str())
                    .is_some_and(|rest| prefix.ends_with(MATCH_SEP) || rest.starts_with(MATCH_SEP))
        })
    }
}

#[cfg(windows)]
const MATCH_SEP: char = '\\';
#[cfg(not(windows))]
const MATCH_SEP: char = '/';

/// The form two paths are compared in: no verbatim prefix, one separator, no trailing
/// separator (a bare drive root keeps its own), and on Windows no case.
fn normalize_for_match(path: &str) -> String {
    let path = path.trim();
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    #[cfg(windows)]
    let mut path = path.replace('/', "\\").to_lowercase();
    #[cfg(not(windows))]
    let mut path = path.to_owned();
    while path.ends_with(MATCH_SEP) && path.len() > 3 {
        path.pop();
    }
    path
}

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
