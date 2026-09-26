//! A local, process-shared filename index. Each process may enqueue a short
//! SQLite request; one process holds an OS file lock and performs scans.

use std::sync::atomic::AtomicU64;
use std::time::Duration;

mod db;
mod indexer;
mod roots;
mod time_util;
mod types;
mod worker;

pub use indexer::Indexer;
pub use types::{
    EntryKind, FragmentFilter, IndexerConfig, Match, MatchMode, Receipt, ScanAction, ScanInfo,
    ScanProgress, SearchFilters, SearchResult, Status,
};

pub(crate) use db::{connect, init_schema};
pub(crate) use roots::{
    absorb_descendants, active_provider, canonical_root, ensure_root, path_text, pending_ancestor,
    root_rows, schedule_debounce, status_by_id, status_for_path,
};
pub(crate) use time_util::{new_request_id, nonzero_time, now_millis, now_secs};
pub(crate) use worker::worker_loop;

#[cfg(test)]
pub(crate) use worker::{
    ScanStopped, Work, claim_next, fail_attempt, finish_partial_refresh, is_covered,
    pause_after_commit, process_next, publish, publish_partial_initial, recover, scan,
    update_progress,
};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
const POLL_INTERVAL: Duration = Duration::from_millis(350);
const ERROR_BACKOFF_SECS: i64 = 60;
/// Rows per delete transaction in recovery, where each row also pays two FTS deletes.
const BATCH_SIZE: usize = 500;
/// Rows per scan commit: fewer, larger commits mean fewer WAL syncs and page rewrites.
const DEFAULT_SCAN_BATCH: usize = 2_000;
const DEFAULT_WRITE_REST: u32 = 2;
const DEFAULT_WRITE_PAUSE_MAX: Duration = Duration::from_millis(2_000);
const MIN_COMMIT_PAUSE: Duration = Duration::from_millis(10);
const DEBOUNCE_QUIET_MS: i64 = 3_000;
const DEBOUNCE_MAX_MS: i64 = 10_000;
const DEBOUNCE_MAX_RESETS: i64 = 3;
const PROGRESS_LOG_INTERVAL_MS: i64 = 60_000;
/// How often a running scan looks for a stop or pause request, and how often a paused one
/// looks for the resume.
const CONTROL_CHECK_INTERVAL: Duration = Duration::from_millis(250);
const CONTROL_POLL: Duration = Duration::from_millis(250);

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
