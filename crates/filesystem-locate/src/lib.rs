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
    EntryKind, FragmentFilter, Match, MatchMode, Receipt, ScanProgress, SearchFilters,
    SearchResult, Status,
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
    BackgroundYield, Work, claim_next, fail_attempt, finish_partial_refresh, is_covered,
    process_next, publish, publish_partial_initial, recover, scan, update_progress,
    yield_background_attempt,
};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
const POLL_INTERVAL: Duration = Duration::from_millis(350);
const ERROR_BACKOFF_SECS: i64 = 60;
const BATCH_SIZE: usize = 500;
const DEBOUNCE_QUIET_MS: i64 = 3_000;
const DEBOUNCE_MAX_MS: i64 = 10_000;
const DEBOUNCE_MAX_RESETS: i64 = 3;
const BACKGROUND_RETRY_DELAY_MS: i64 = 15_000;
const PROGRESS_LOG_INTERVAL_MS: i64 = 60_000;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
