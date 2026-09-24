//! A local, process-shared filename index. Each process may enqueue a short
//! SQLite request; one process holds an OS file lock and performs scans.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use globset::Glob;
use regex::Regex;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
const POLL_INTERVAL: Duration = Duration::from_millis(350);
const ERROR_BACKOFF_SECS: i64 = 60;
const BATCH_SIZE: usize = 500;
const DEBOUNCE_QUIET_MS: i64 = 3_000;
const DEBOUNCE_MAX_MS: i64 = 10_000;
const DEBOUNCE_MAX_RESETS: i64 = 3;
const BACKGROUND_RETRY_DELAY_MS: i64 = 15_000;

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
    pub progress: Option<ScanProgress>,
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

/// Owns a background thread. Clone the surrounding `Arc<Indexer>` for MCP
/// connections; the thread itself never retains that Arc.
pub struct Indexer {
    db_path: PathBuf,
    stop: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl Indexer {
    pub fn open(state_root: &Path) -> Result<Self> {
        fs::create_dir_all(state_root)?;
        let state_root = fs::canonicalize(state_root)?;
        let db_path = state_root.join("everything.db");
        let lock_path = state_root.join("everything.lock");
        // Several MCP processes may open the same fresh database at once.
        // Retry only startup setup; ordinary short transactions use SQLite's
        // busy timeout and never hold a lock for the duration of a scan.
        for attempt in 0..20 {
            match connect(&db_path).and_then(|mut conn| init_schema(&mut conn)) {
                Ok(()) => break,
                Err(_) if attempt < 19 => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(error) => return Err(error.context("index database initialization failed")),
            }
        }

        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker_db = db_path.clone();
        let worker = thread::Builder::new()
            .name("filesystem-locate".into())
            .spawn(move || worker_loop(&worker_db, &lock_path, &state_root, &worker_stop))?;
        Ok(Self {
            db_path,
            stop,
            worker: Mutex::new(Some(worker)),
        })
    }

    /// Repeated request IDs are idempotent. Concurrent requests for the same
    /// root get distinct sequence numbers but are claimed by one scan batch.
    pub fn request_refresh(&self, root: &Path, request_id: Option<&str>) -> Result<Receipt> {
        let root = canonical_root(root)?;
        let request_id = request_id.map(str::to_owned).unwrap_or_else(new_request_id);
        if request_id.len() > 128 || request_id.is_empty() {
            bail!("request id must contain 1..=128 bytes");
        }
        let mut conn = connect(&self.db_path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let requested_path = path_text(&root)?;
        if let Some((existing_path, target_seq, status, work_root, next_scan_at_ms)) = tx
            .query_row(
                "SELECT s.requested_path,s.target_seq,s.status,r.path,r.debounce_until_ms
                 FROM scan_requests s JOIN roots r ON r.id=s.root_id WHERE s.request_id=?1",
                [&request_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?
        {
            if existing_path != requested_path {
                bail!("request id already belongs to another root");
            }
            tx.commit()?;
            return Ok(Receipt {
                request_id,
                target_seq,
                status,
                work_root: PathBuf::from(work_root),
                next_scan_at_ms: nonzero_time(next_scan_at_ms),
            });
        }
        let rows = root_rows(&tx)?;
        let (root_id, work_path) = if let Some(ancestor) = pending_ancestor(&rows, &root) {
            (ancestor.id, ancestor.path.clone())
        } else {
            (ensure_root(&tx, &root)?, root.clone())
        };
        tx.execute(
            "UPDATE roots SET desired_seq=desired_seq+1,covered_by=NULL,
             background=0,background_pause_ms=0,
             state=CASE WHEN state='building' THEN state WHEN state='partial' THEN state ELSE 'pending' END WHERE id=?1",
            [root_id],
        )?;
        schedule_debounce(&tx, root_id, now_millis())?;
        let target_seq: i64 = tx.query_row(
            "SELECT desired_seq FROM roots WHERE id=?1",
            [root_id],
            |row| row.get(0),
        )?;
        absorb_descendants(&tx, &rows, root_id, &work_path, target_seq)?;
        tx.execute(
            "INSERT INTO scan_requests(request_id,root_id,target_seq,status,requested_path)
             VALUES(?1,?2,?3,'pending',?4)",
            params![request_id, root_id, target_seq, requested_path],
        )?;
        let next_scan_at_ms = status_by_id(&tx, root_id)?.next_scan_at_ms;
        tx.commit()?;
        Ok(Receipt {
            request_id,
            target_seq,
            status: "pending".into(),
            work_root: work_path,
            next_scan_at_ms,
        })
    }

    /// Queue one initial scan. Repeated searches while it is pending do not
    /// create additional work or request records.
    pub fn ensure_index(&self, root: &Path) -> Result<Status> {
        let root = canonical_root(root)?;
        let mut conn = connect(&self.db_path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rows = root_rows(&tx)?;
        if pending_ancestor(&rows, &root).is_some() || active_provider(&rows, &root).is_some() {
            let status = status_for_path(&tx, &root)?;
            tx.commit()?;
            return Ok(status);
        }
        let root_id = ensure_root(&tx, &root)?;
        let queued = tx.execute(
            "UPDATE roots SET desired_seq=desired_seq+1, state='pending',background=0,background_pause_ms=0
             WHERE id=?1 AND active_generation=0 AND desired_seq=completed_seq AND retry_not_before<=?2",
            params![root_id, now_secs()],
        )?;
        if queued != 0 {
            schedule_debounce(&tx, root_id, now_millis())?;
        } else {
            tx.execute(
                "UPDATE roots SET background=0,background_pause_ms=0,debounce_until_ms=?2
                 WHERE id=?1 AND active_generation=0 AND desired_seq>completed_seq AND background=1",
                params![root_id, now_millis()],
            )?;
        }
        let status = status_for_path(&tx, &root)?;
        tx.commit()?;
        Ok(status)
    }

    /// Schedule a low-priority reconciliation when this root is due. Multiple
    /// MCP processes may call this; the immediate transaction makes it one job.
    pub fn schedule_background(
        &self,
        root: &Path,
        interval_secs: u64,
        pause_ms: u64,
        start_delay_ms: u64,
    ) -> Result<bool> {
        let root = canonical_root(root)?;
        let mut conn = connect(&self.db_path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let id = ensure_root(&tx, &root)?;
        let (desired, completed, last_verified, retry_not_before): (i64, i64, Option<i64>, i64) =
            tx.query_row(
                "SELECT desired_seq,completed_seq,last_verified,retry_not_before FROM roots WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
        let now = now_secs();
        let effective = status_for_path(&tx, &root)?;
        if desired > completed
            || retry_not_before > now
            || last_verified.is_some_and(|at| at.saturating_add(interval_secs as i64) > now)
            || effective.desired_seq > effective.completed_seq
            || effective
                .last_verified
                .is_some_and(|at| at.saturating_add(interval_secs as i64) > now)
        {
            tx.commit()?;
            return Ok(false);
        }
        tx.execute(
            "UPDATE roots SET desired_seq=desired_seq+1,state='pending',covered_by=NULL,
             background=1,background_pause_ms=?2,
             debounce_first_ms=?3,debounce_until_ms=?4,debounce_resets=0 WHERE id=?1",
            params![
                id,
                pause_ms.min(1_000) as i64,
                now_millis(),
                now_millis() + start_delay_ms.min(600_000) as i64
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn status(&self, root: &Path) -> Result<Status> {
        let root = canonical_root(root)?;
        let conn = connect(&self.db_path)?;
        status_for_path(&conn, &root)
    }

    pub fn request_status(&self, request_id: &str) -> Result<Option<Receipt>> {
        let conn = connect(&self.db_path)?;
        conn.query_row(
            "SELECT s.target_seq,s.status,r.path,r.debounce_until_ms
             FROM scan_requests s JOIN roots r ON r.id=s.root_id WHERE s.request_id=?1",
            [request_id],
            |row| {
                Ok(Receipt {
                    request_id: request_id.into(),
                    target_seq: row.get(0)?,
                    status: row.get(1)?,
                    work_root: PathBuf::from(row.get::<_, String>(2)?),
                    next_scan_at_ms: nonzero_time(row.get(3)?),
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn search(
        &self,
        root: &Path,
        query: &str,
        mode: MatchMode,
        limit: usize,
    ) -> Result<SearchResult> {
        self.search_filtered(root, Some((query, mode)), &SearchFilters::default(), limit)
    }

    pub fn search_filtered(
        &self,
        root: &Path,
        query: Option<(&str, MatchMode)>,
        filters: &SearchFilters,
        limit: usize,
    ) -> Result<SearchResult> {
        let root = canonical_root(root)?;
        let conn = connect(&self.db_path)?;
        let glob = if let Some((query, MatchMode::Glob)) = query {
            Some(Glob::new(query)?.compile_matcher())
        } else {
            None
        };
        let regex = if let Some((query, MatchMode::Regex)) = query {
            Some(Regex::new(query)?)
        } else {
            None
        };
        let name_candidate = filters
            .name
            .include
            .iter()
            .chain(filters.extension.include.iter())
            .filter(|part| part.chars().count() >= 3)
            .max_by_key(|part| part.chars().count())
            .map(String::as_str);
        let path_candidate = filters
            .path
            .include
            .iter()
            .filter(|part| part.chars().count() >= 3)
            .max_by_key(|part| part.chars().count())
            .map(String::as_str);
        let limit = limit.clamp(1, 1_000);
        // One read transaction pins both metadata and the selected generation.
        let tx = conn.unchecked_transaction()?;
        let status = status_for_path(&tx, &root)?;
        let rows = root_rows(&tx)?;
        let Some(provider) = active_provider(&rows, &root) else {
            return Ok(SearchResult {
                matches: Vec::new(),
                truncated: false,
                status,
            });
        };
        let exact = matches!(query, Some((_, MatchMode::Exact)));
        let prefix = matches!(query, Some((_, MatchMode::Prefix)));
        let contains_candidate = match query {
            Some((text, MatchMode::Contains)) if text.chars().count() >= 3 => Some(text),
            _ => None,
        };
        let name_trigram = [contains_candidate, name_candidate]
            .into_iter()
            .flatten()
            .max_by_key(|part| part.chars().count());
        let path_trigram = path_candidate.filter(|path_part| {
            name_trigram
                .is_none_or(|name_part| path_part.chars().count() > name_part.chars().count())
        });
        let name_trigram = if path_trigram.is_some() {
            None
        } else {
            name_trigram
        };
        let base_sql = if exact {
            "SELECT e.path,e.kind,e.size,e.modified,e.name FROM roots r JOIN entries e ON e.root_id=r.id AND e.generation=r.active_generation WHERE r.path=?1 AND e.name=?2"
        } else if prefix {
            "SELECT e.path,e.kind,e.size,e.modified,e.name FROM roots r JOIN entries e ON e.root_id=r.id AND e.generation=r.active_generation WHERE r.path=?1 AND e.name>=?2 AND e.name<?3"
        } else if name_trigram.is_some() {
            "SELECT e.path,e.kind,e.size,e.modified,e.name FROM entry_names_fts f JOIN entries e ON e.rowid=f.rowid JOIN roots r ON r.id=e.root_id AND r.active_generation=e.generation WHERE r.path=?1 AND entry_names_fts MATCH ?2"
        } else if path_trigram.is_some() {
            "SELECT e.path,e.kind,e.size,e.modified,e.name FROM entry_paths_fts f JOIN entries e ON e.rowid=f.rowid JOIN roots r ON r.id=e.root_id AND r.active_generation=e.generation WHERE r.path=?1 AND entry_paths_fts MATCH ?2"
        } else {
            "SELECT e.path,e.kind,e.size,e.modified,e.name FROM roots r JOIN entries e ON e.root_id=r.id AND e.generation=r.active_generation WHERE r.path=?1"
        };
        let kind_sql = match filters.kind {
            EntryKind::All => "",
            EntryKind::Files => " AND e.kind='file'",
            EntryKind::Directories => " AND e.kind='dir'",
        };
        let sql = format!("{base_sql}{kind_sql} ORDER BY e.path");
        let mut stmt = tx.prepare(&sql)?;
        let root_text = path_text(&provider.path)?;
        let mut rows = if exact {
            stmt.query(params![root_text, query.unwrap().0])?
        } else if prefix {
            let text = query.unwrap().0;
            stmt.query(params![root_text, text, format!("{text}\u{10ffff}")])?
        } else if let Some(text) = name_trigram.or(path_trigram) {
            stmt.query(params![
                root_text,
                format!("\"{}\"", text.replace('"', "\"\""))
            ])?
        } else {
            stmt.query([root_text])?
        };
        let mut matches = Vec::new();
        let mut truncated = false;
        while let Some(row) = rows.next()? {
            let path: String = row.get(0)?;
            if !Path::new(&path).starts_with(&root) {
                continue;
            }
            let kind: String = row.get(1)?;
            let name: String = row.get(4)?;
            let matched = match query {
                Some((text, MatchMode::Exact)) => name == text,
                Some((text, MatchMode::Prefix)) => name.starts_with(text),
                Some((text, MatchMode::Contains)) => name.contains(text),
                Some((_, MatchMode::Glob)) => glob.as_ref().is_some_and(|g| g.is_match(&name)),
                Some((_, MatchMode::Regex)) => regex.as_ref().is_some_and(|r| r.is_match(&name)),
                None => true,
            };
            let extension = Path::new(&name)
                .extension()
                .and_then(|part| part.to_str())
                .unwrap_or("");
            if !matched
                || !matches_fragments(&name, &filters.name)
                || !matches_fragments(extension, &filters.extension)
                || !matches_fragments(&path, &filters.path)
            {
                continue;
            }
            if matches.len() == limit {
                truncated = true;
                break;
            }
            matches.push(Match {
                path: PathBuf::from(path),
                kind,
                size: row.get::<_, i64>(2)?.max(0) as u64,
                modified: row.get(3)?,
            });
        }
        Ok(SearchResult {
            matches,
            truncated,
            status,
        })
    }
}

fn matches_fragments(value: &str, filter: &FragmentFilter) -> bool {
    filter.include.iter().all(|part| value.contains(part))
        && filter.exclude.iter().all(|part| !value.contains(part))
}

impl Drop for Indexer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(mut worker) = self.worker.lock()
            && let Some(handle) = worker.take()
        {
            let _ = handle.join();
        }
    }
}

fn connect(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    Ok(conn)
}

fn init_schema(conn: &mut Connection) -> Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS roots(
           id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE,
           active_generation INTEGER NOT NULL DEFAULT 0,
           desired_seq INTEGER NOT NULL DEFAULT 0,
           completed_seq INTEGER NOT NULL DEFAULT 0,
           state TEXT NOT NULL DEFAULT 'unindexed',
           last_verified INTEGER, last_error TEXT,
           retry_not_before INTEGER NOT NULL DEFAULT 0,
           last_started INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS scan_requests(
           request_id TEXT PRIMARY KEY, root_id INTEGER NOT NULL REFERENCES roots(id),
           target_seq INTEGER NOT NULL, status TEXT NOT NULL,
           result_generation INTEGER
         );
         CREATE TABLE IF NOT EXISTS scan_attempts(
           id INTEGER PRIMARY KEY, root_id INTEGER NOT NULL REFERENCES roots(id),
           claimed_seq INTEGER NOT NULL, state TEXT NOT NULL,
           started INTEGER NOT NULL, finished INTEGER, error TEXT
         );
         CREATE TABLE IF NOT EXISTS entries(
           root_id INTEGER NOT NULL REFERENCES roots(id), generation INTEGER NOT NULL,
           path TEXT NOT NULL, name TEXT NOT NULL, kind TEXT NOT NULL,
           size INTEGER NOT NULL, modified INTEGER,
           PRIMARY KEY(root_id,generation,path)
         );
         CREATE TABLE IF NOT EXISTS staged_entries(
           attempt_id INTEGER NOT NULL REFERENCES scan_attempts(id),
           path TEXT NOT NULL, name TEXT NOT NULL, kind TEXT NOT NULL,
           size INTEGER NOT NULL, modified INTEGER,
           PRIMARY KEY(attempt_id,path)
         ) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS entries_name ON entries(root_id,generation,name);
         CREATE INDEX IF NOT EXISTS requests_root_seq ON scan_requests(root_id,target_seq);",
    )?;
    // Serialized migration also upgrades a database written by the initial
    // non-FTS version of this crate without missing existing entries.
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version < 1 {
        tx.execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS entry_names_fts USING fts5(
               name, content='entries', content_rowid='rowid', tokenize='trigram'
             );
             CREATE TRIGGER IF NOT EXISTS entries_fts_insert AFTER INSERT ON entries BEGIN
               INSERT INTO entry_names_fts(rowid,name) VALUES(new.rowid,new.name);
             END;
             CREATE TRIGGER IF NOT EXISTS entries_fts_delete AFTER DELETE ON entries BEGIN
               INSERT INTO entry_names_fts(entry_names_fts,rowid,name)
               VALUES('delete',old.rowid,old.name);
             END;
             INSERT INTO entry_names_fts(entry_names_fts) VALUES('rebuild');
             PRAGMA user_version=1;",
        )?;
    }
    if version < 2 {
        tx.execute_batch(
            "ALTER TABLE roots ADD COLUMN debounce_first_ms INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE roots ADD COLUMN debounce_until_ms INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE roots ADD COLUMN debounce_resets INTEGER NOT NULL DEFAULT 0;
             PRAGMA user_version=2;",
        )?;
    }
    if version < 3 {
        tx.execute_batch(
            "ALTER TABLE roots ADD COLUMN covered_by INTEGER REFERENCES roots(id);
             ALTER TABLE scan_requests ADD COLUMN requested_path TEXT;
             UPDATE scan_requests SET requested_path=(
               SELECT path FROM roots WHERE roots.id=scan_requests.root_id
             ) WHERE requested_path IS NULL;
             CREATE INDEX IF NOT EXISTS roots_covered_by ON roots(covered_by);
             PRAGMA user_version=3;",
        )?;
    }
    if version < 4 {
        tx.execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS entry_paths_fts USING fts5(
               path, content='entries', content_rowid='rowid', tokenize='trigram'
             );
             CREATE TRIGGER IF NOT EXISTS entries_path_fts_insert AFTER INSERT ON entries BEGIN
               INSERT INTO entry_paths_fts(rowid,path) VALUES(new.rowid,new.path);
             END;
             CREATE TRIGGER IF NOT EXISTS entries_path_fts_delete AFTER DELETE ON entries BEGIN
               INSERT INTO entry_paths_fts(entry_paths_fts,rowid,path)
               VALUES('delete',old.rowid,old.path);
             END;
             INSERT INTO entry_paths_fts(entry_paths_fts) VALUES('rebuild');
             PRAGMA user_version=4;",
        )?;
    }
    if version < 5 {
        tx.execute_batch(
            "CREATE INDEX IF NOT EXISTS entries_kind ON entries(root_id,generation,kind,path);
             PRAGMA user_version=5;",
        )?;
    }
    if version < 6 {
        tx.execute_batch(
            "ALTER TABLE roots ADD COLUMN published_attempt INTEGER NOT NULL DEFAULT 0;
             UPDATE roots SET published_attempt=active_generation WHERE active_generation>0;
             PRAGMA user_version=6;",
        )?;
    }
    if version < 7 {
        tx.execute_batch(
            "ALTER TABLE roots ADD COLUMN background INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE roots ADD COLUMN background_pause_ms INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE scan_attempts ADD COLUMN entries_seen INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE scan_attempts ADD COLUMN dirs_seen INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE scan_attempts ADD COLUMN current_path TEXT;
             PRAGMA user_version=7;",
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn canonical_root(path: &Path) -> Result<PathBuf> {
    let root =
        fs::canonicalize(path).with_context(|| format!("cannot resolve {}", path.display()))?;
    if !root.is_dir() {
        bail!("index root is not a directory: {}", root.display());
    }
    path_text(&root)?;
    Ok(root)
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("non-Unicode paths are not supported by this index"))
}

fn ensure_root(conn: &Connection, path: &Path) -> Result<i64> {
    let text = path_text(path)?;
    conn.execute("INSERT OR IGNORE INTO roots(path) VALUES(?1)", [text])?;
    Ok(
        conn.query_row("SELECT id FROM roots WHERE path=?1", [text], |row| {
            row.get(0)
        })?,
    )
}

#[derive(Debug)]
struct RootRow {
    id: i64,
    path: PathBuf,
    active_generation: i64,
    published_attempt: i64,
    desired_seq: i64,
    completed_seq: i64,
    covered_by: Option<i64>,
    background: bool,
}

fn root_rows(conn: &Connection) -> Result<Vec<RootRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,path,active_generation,desired_seq,completed_seq,covered_by,published_attempt,background FROM roots",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(RootRow {
            id: row.get(0)?,
            path: PathBuf::from(row.get::<_, String>(1)?),
            active_generation: row.get(2)?,
            desired_seq: row.get(3)?,
            completed_seq: row.get(4)?,
            covered_by: row.get(5)?,
            published_attempt: row.get(6)?,
            background: row.get(7)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn pending_ancestor<'a>(rows: &'a [RootRow], path: &Path) -> Option<&'a RootRow> {
    rows.iter()
        .filter(|row| {
            path.starts_with(&row.path)
                && row.covered_by.is_none()
                && !row.background
                && row.desired_seq > row.completed_seq
        })
        .min_by_key(|row| row.path.components().count())
}

fn pending_background_ancestor<'a>(rows: &'a [RootRow], path: &Path) -> Option<&'a RootRow> {
    rows.iter()
        .filter(|row| {
            path.starts_with(&row.path)
                && row.covered_by.is_none()
                && row.background
                && row.desired_seq > row.completed_seq
        })
        .min_by_key(|row| row.path.components().count())
}

fn active_provider<'a>(rows: &'a [RootRow], path: &Path) -> Option<&'a RootRow> {
    rows.iter()
        .filter(|row| path.starts_with(&row.path) && row.active_generation > 0)
        .max_by_key(|row| row.published_attempt)
}

fn status_for_path(conn: &Connection, path: &Path) -> Result<Status> {
    let rows = root_rows(conn)?;
    if let Some(pending) = pending_ancestor(&rows, path) {
        return status_by_id(conn, pending.id);
    }
    if let Some(pending) = pending_background_ancestor(&rows, path) {
        return status_by_id(conn, pending.id);
    }
    if let Some(exact) = rows.iter().find(|row| row.path == path)
        && let Some(owner) = exact.covered_by
    {
        return status_by_id(conn, owner);
    }
    if let Some(provider) = active_provider(&rows, path) {
        return status_by_id(conn, provider.id);
    }
    status_by_path(conn, path)
}

fn absorb_descendants(
    conn: &Connection,
    rows: &[RootRow],
    parent_id: i64,
    parent_path: &Path,
    target_seq: i64,
) -> Result<()> {
    for child in rows.iter().filter(|row| {
        row.id != parent_id
            && row.path.starts_with(parent_path)
            && (row.desired_seq > row.completed_seq || row.covered_by.is_some())
    }) {
        conn.execute(
            "UPDATE roots SET covered_by=?2,state='covered',desired_seq=completed_seq,
             debounce_first_ms=0,debounce_until_ms=0,debounce_resets=0 WHERE id=?1",
            params![child.id, parent_id],
        )?;
        conn.execute(
            "UPDATE scan_requests SET root_id=?2,target_seq=?3,status='pending'
             WHERE root_id=?1 AND status IN ('pending','partial')",
            params![child.id, parent_id, target_seq],
        )?;
    }
    Ok(())
}

/// A durable trailing-edge timer with both a reset count and an absolute cap.
/// Called inside the same write transaction that advances desired_seq.
fn schedule_debounce(conn: &Connection, root_id: i64, now_ms: i64) -> Result<()> {
    let (first, until, resets): (i64, i64, i64) = conn.query_row(
        "SELECT debounce_first_ms,debounce_until_ms,debounce_resets FROM roots WHERE id=?1",
        [root_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if until == 0 {
        conn.execute(
            "UPDATE roots SET debounce_first_ms=?2,debounce_until_ms=?3,debounce_resets=0 WHERE id=?1",
            params![root_id, now_ms, now_ms + DEBOUNCE_QUIET_MS],
        )?;
    } else if resets < DEBOUNCE_MAX_RESETS {
        let due = (now_ms + DEBOUNCE_QUIET_MS).min(first + DEBOUNCE_MAX_MS);
        conn.execute(
            "UPDATE roots SET debounce_until_ms=?2,debounce_resets=debounce_resets+1 WHERE id=?1",
            params![root_id, due.max(until)],
        )?;
    }
    Ok(())
}

fn status_by_path(conn: &Connection, path: &Path) -> Result<Status> {
    let text = path_text(path)?;
    let id: Option<i64> = conn
        .query_row("SELECT id FROM roots WHERE path=?1", [text], |row| {
            row.get(0)
        })
        .optional()?;
    id.map(|id| status_by_id(conn, id))
        .transpose()
        .map(|status| status.unwrap_or_default())
}

fn status_by_id(conn: &Connection, id: i64) -> Result<Status> {
    let mut status = conn.query_row(
        "SELECT state,active_generation,desired_seq,completed_seq,last_verified,last_error,debounce_until_ms,background FROM roots WHERE id=?1",
        [id],
        parse_status,
    )?;
    status.progress = conn
        .query_row(
            "SELECT id,state,entries_seen,dirs_seen,current_path,started FROM scan_attempts
             WHERE root_id=?1 ORDER BY id DESC LIMIT 1",
            [id],
            |row| {
                Ok(ScanProgress {
                    attempt_id: row.get(0)?,
                    attempt_state: row.get(1)?,
                    entries_seen: row.get::<_, i64>(2)?.max(0) as u64,
                    dirs_seen: row.get::<_, i64>(3)?.max(0) as u64,
                    current_path: row.get::<_, Option<String>>(4)?.map(PathBuf::from),
                    started: row.get(5)?,
                })
            },
        )
        .optional()?;
    Ok(status)
}

fn parse_status(row: &rusqlite::Row<'_>) -> rusqlite::Result<Status> {
    Ok(Status {
        state: row.get(0)?,
        active_generation: row.get(1)?,
        desired_seq: row.get(2)?,
        completed_seq: row.get(3)?,
        last_verified: row.get(4)?,
        last_error: row.get(5)?,
        next_scan_at_ms: match row.get::<_, i64>(6)? {
            0 => None,
            when => Some(when),
        },
        background: row.get(7)?,
        progress: None,
    })
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn nonzero_time(value: i64) -> Option<i64> {
    (value != 0).then_some(value)
}

fn new_request_id() -> String {
    let n = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{stamp:x}-{n:x}", std::process::id())
}

fn worker_loop(db_path: &Path, lock_path: &Path, state_root: &Path, stop: &AtomicBool) {
    let lock_file = match File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
    {
        Ok(file) => file,
        Err(_) => return,
    };
    let mut owner = false;
    while !stop.load(Ordering::Acquire) {
        if !owner {
            if lock_file.try_lock().is_ok() {
                owner = true;
                if let Ok(conn) = connect(db_path) {
                    let _ = recover(&conn);
                }
            } else {
                thread::sleep(POLL_INTERVAL);
                continue;
            }
        }
        if let Ok(mut conn) = connect(db_path)
            && process_next(&mut conn, state_root, stop).is_err()
        {
            let _ = recover(&conn);
        }
        thread::sleep(POLL_INTERVAL);
    }
    if owner {
        let _ = lock_file.unlock();
    }
}

fn recover(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "UPDATE scan_attempts SET state='abandoned',finished=strftime('%s','now') WHERE state='running';
         UPDATE roots SET state='pending' WHERE state='building' AND covered_by IS NULL;
         UPDATE roots SET state='covered',desired_seq=completed_seq
           WHERE state='building' AND covered_by IS NOT NULL;
         DELETE FROM entries WHERE NOT EXISTS (
           SELECT 1 FROM roots WHERE roots.id=entries.root_id
             AND roots.active_generation=entries.generation
         );
         DELETE FROM staged_entries;",
    )?;
    Ok(())
}

struct Work {
    root_id: i64,
    root: PathBuf,
    claimed_seq: i64,
    attempt_id: i64,
    active_generation: i64,
    background: bool,
    background_pause_ms: u64,
}

fn claim_next(conn: &mut Connection) -> Result<Option<Work>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let next = tx
        .query_row(
            "SELECT id,path,desired_seq,active_generation,background,background_pause_ms FROM roots
             WHERE desired_seq>completed_seq AND state!='building'
               AND covered_by IS NULL
               AND retry_not_before<=?1
               AND debounce_until_ms<=?2
             ORDER BY background ASC,last_started,id LIMIT 1",
            params![now_secs(), now_millis()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, bool>(4)?,
                    row.get::<_, i64>(5)?.max(0) as u64,
                ))
            },
        )
        .optional()?;
    let Some((root_id, root, claimed_seq, active_generation, background, background_pause_ms)) =
        next
    else {
        tx.commit()?;
        return Ok(None);
    };
    tx.execute(
        "INSERT INTO scan_attempts(root_id,claimed_seq,state,started) VALUES(?1,?2,'running',?3)",
        params![root_id, claimed_seq, now_secs()],
    )?;
    let attempt_id = tx.last_insert_rowid();
    tx.execute(
        "UPDATE roots SET state='building',last_started=?2,
         debounce_first_ms=0,debounce_until_ms=0,debounce_resets=0 WHERE id=?1",
        params![root_id, now_secs()],
    )?;
    tx.commit()?;
    Ok(Some(Work {
        root_id,
        root: PathBuf::from(root),
        claimed_seq,
        attempt_id,
        active_generation,
        background,
        background_pause_ms,
    }))
}

fn process_next(conn: &mut Connection, state_root: &Path, stop: &AtomicBool) -> Result<()> {
    let Some(work) = claim_next(conn)? else {
        return Ok(());
    };
    let background_priority = BackgroundPriority::enter(work.background);
    let outcome = scan(conn, &work, state_root, stop);
    drop(background_priority);
    if is_covered(conn, work.root_id)? {
        return abandon_covered_attempt(conn, &work);
    }
    if work.background && foreground_work_pending(conn)? {
        return yield_background_attempt(conn, &work);
    }
    match outcome {
        Ok(0) => publish(conn, &work),
        Ok(errors) => fail_attempt(
            conn,
            &work,
            &format!("{errors} entries could not be indexed"),
        ),
        Err(error) if error.downcast_ref::<BackgroundYield>().is_some() => {
            yield_background_attempt(conn, &work)
        }
        Err(error) => fail_attempt(conn, &work, &error.to_string()),
    }
}

struct BackgroundPriority {
    #[cfg(windows)]
    active: bool,
}

impl BackgroundPriority {
    fn enter(background: bool) -> Self {
        #[cfg(windows)]
        {
            use windows::Win32::System::Threading::{
                GetCurrentThread, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN,
            };
            let active = background
                && unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) }
                    .is_ok();
            Self { active }
        }
        #[cfg(not(windows))]
        {
            let _ = background;
            Self {}
        }
    }
}

impl Drop for BackgroundPriority {
    fn drop(&mut self) {
        #[cfg(windows)]
        if self.active {
            use windows::Win32::System::Threading::{
                GetCurrentThread, SetThreadPriority, THREAD_MODE_BACKGROUND_END,
            };
            let _ = unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END) };
        }
    }
}

#[derive(Debug)]
struct BackgroundYield;

impl std::fmt::Display for BackgroundYield {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("background scan yielded to foreground work")
    }
}

impl std::error::Error for BackgroundYield {}

fn foreground_work_pending(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM roots WHERE desired_seq>completed_seq
         AND covered_by IS NULL AND background=0)",
        [],
        |row| row.get(0),
    )?)
}

fn yield_background_attempt(conn: &mut Connection, work: &Work) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "UPDATE roots SET state='pending',
         debounce_until_ms=CASE WHEN background=0 THEN ?2 ELSE ?3 END
         WHERE id=?1 AND covered_by IS NULL",
        params![
            work.root_id,
            now_millis(),
            now_millis() + BACKGROUND_RETRY_DELAY_MS
        ],
    )?;
    tx.execute(
        "UPDATE scan_attempts SET state='yielded',finished=?2 WHERE id=?1",
        params![work.attempt_id, now_secs()],
    )?;
    tx.commit()?;
    conn.execute(
        "DELETE FROM entries WHERE root_id=?1 AND generation=?2",
        params![work.root_id, work.attempt_id],
    )?;
    conn.execute(
        "DELETE FROM staged_entries WHERE attempt_id=?1",
        [work.attempt_id],
    )?;
    Ok(())
}

fn is_covered(conn: &Connection, root_id: i64) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT covered_by IS NOT NULL FROM roots WHERE id=?1",
        [root_id],
        |row| row.get(0),
    )?)
}

fn abandon_covered_attempt(conn: &mut Connection, work: &Work) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "UPDATE scan_attempts SET state='superseded',finished=?2 WHERE id=?1",
        params![work.attempt_id, now_secs()],
    )?;
    tx.execute(
        "UPDATE roots SET state='covered',desired_seq=completed_seq WHERE id=?1 AND covered_by IS NOT NULL",
        [work.root_id],
    )?;
    tx.commit()?;
    conn.execute(
        "DELETE FROM entries WHERE root_id=?1 AND generation=?2",
        params![work.root_id, work.attempt_id],
    )?;
    conn.execute(
        "DELETE FROM staged_entries WHERE attempt_id=?1",
        [work.attempt_id],
    )?;
    Ok(())
}

fn scan(conn: &mut Connection, work: &Work, state_root: &Path, stop: &AtomicBool) -> Result<u64> {
    let mut batch = Vec::with_capacity(BATCH_SIZE);
    let mut extra_errors = 0u64;
    let mut last_progress = Instant::now();
    #[cfg(windows)]
    let mut native_progress_error = None;
    #[cfg(windows)]
    let native_tree = if !work.background
        && work.root.parent().is_some()
        && fscan_rs::is_ntfs_available(&work.root)
    {
        let result = fscan_rs::scan_ntfs_tree_with_options(&work.root, stop, false, |progress| {
            if native_progress_error.is_none() {
                native_progress_error =
                    update_progress(conn, work, progress.items, progress.dirs, &work.root).err();
            }
        });
        match result {
            Ok(tree) => Some(tree),
            Err(error) => {
                tracing::warn!(
                    "NTFS scan unavailable for {}: {error:#}; using standard traversal",
                    work.root.display()
                );
                None
            }
        }
    } else {
        None
    };
    #[cfg(windows)]
    if let Some(error) = native_progress_error {
        return Err(error);
    }
    let mut visit =
        |entry: &fscan_rs::Entry, progress: fscan_rs::Progress| -> Result<fscan_rs::Visit> {
            if work.background
                && entry.kind == fscan_rs::EntryKind::Directory
                && (progress.directories + 1).is_multiple_of(16)
                && foreground_work_pending(conn)?
            {
                return Err(BackgroundYield.into());
            }
            if entry.kind == fscan_rs::EntryKind::Directory
                && (progress.directories + 1).is_multiple_of(128)
                && is_covered(conn, work.root_id)?
            {
                bail!("scan superseded by an ancestor request");
            }
            if last_progress.elapsed() >= Duration::from_millis(500) {
                update_progress(
                    conn,
                    work,
                    progress.entries,
                    progress.directories + 1,
                    &entry.path,
                )?;
                last_progress = Instant::now();
            }
            if progress.entries.is_multiple_of(64) && work.background {
                thread::sleep(Duration::from_millis(work.background_pause_ms));
                thread::yield_now();
                if foreground_work_pending(conn)? {
                    return Err(BackgroundYield.into());
                }
            }
            let (Some(path), Some(name)) = (entry.path.to_str(), entry.name.to_str()) else {
                extra_errors += 1;
                return Ok(fscan_rs::Visit::Continue);
            };
            let kind = match entry.kind {
                fscan_rs::EntryKind::File => "file",
                fscan_rs::EntryKind::Directory => "dir",
                fscan_rs::EntryKind::Symlink => "symlink",
            };
            let modified = entry
                .modified
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs() as i64);
            batch.push((
                path.to_owned(),
                name.to_owned(),
                kind,
                entry.len as i64,
                modified,
            ));
            if batch.len() >= BATCH_SIZE {
                flush_batch(conn, work, &mut batch)?;
                if is_covered(conn, work.root_id)? {
                    bail!("scan superseded by an ancestor request");
                }
            }
            Ok(fscan_rs::Visit::Continue)
        };
    #[cfg(windows)]
    let native_progress = if let Some((tree, diagnostics)) = native_tree.as_ref() {
        match fscan_rs::stream_ntfs_tree(
            tree,
            diagnostics,
            stop,
            |path| !path.starts_with(state_root),
            &mut visit,
        ) {
            Ok(progress) => Some(progress),
            Err(fscan_rs::NtfsStreamError::Sink(error)) => return Err(error),
            Err(fscan_rs::NtfsStreamError::Cancelled) => bail!("scan cancelled during shutdown"),
            Err(fscan_rs::NtfsStreamError::Backend(error)) => return Err(error),
        }
    } else {
        None
    };
    #[cfg(not(windows))]
    let native_progress: Option<fscan_rs::Progress> = None;
    let progress = match native_progress {
        Some(progress) => progress,
        None => fscan_rs::scan_standard(
            &work.root,
            stop,
            |path| !path.starts_with(state_root),
            &mut visit,
        )
        .map_err(|error| match error {
            fscan_rs::ScanError::Cancelled => anyhow::anyhow!("scan cancelled during shutdown"),
            fscan_rs::ScanError::Root(error) => anyhow::Error::new(error),
            fscan_rs::ScanError::Sink(error) => error,
        })?,
    };
    flush_batch(conn, work, &mut batch)?;
    update_progress(
        conn,
        work,
        progress.entries,
        progress.directories + 1,
        &work.root,
    )?;
    Ok(progress.errors.saturating_add(extra_errors))
}

fn update_progress(
    conn: &Connection,
    work: &Work,
    entries_seen: u64,
    dirs_seen: u64,
    current_path: &Path,
) -> Result<()> {
    conn.execute(
        "UPDATE scan_attempts SET entries_seen=?2,dirs_seen=?3,current_path=?4 WHERE id=?1",
        params![
            work.attempt_id,
            entries_seen.min(i64::MAX as u64) as i64,
            dirs_seen.min(i64::MAX as u64) as i64,
            path_text(current_path)?
        ],
    )?;
    Ok(())
}

type EntryBatch = Vec<(String, String, &'static str, i64, Option<i64>)>;

fn flush_batch(conn: &mut Connection, work: &Work, batch: &mut EntryBatch) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if work.active_generation == 0 {
        let mut insert = tx.prepare_cached(
            "INSERT OR REPLACE INTO entries(root_id,generation,path,name,kind,size,modified)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
        )?;
        for (path, name, kind, size, modified) in batch.drain(..) {
            insert.execute(params![
                work.root_id,
                work.attempt_id,
                path,
                name,
                kind,
                size,
                modified
            ])?;
        }
    } else {
        let mut insert = tx.prepare_cached(
            "INSERT OR REPLACE INTO staged_entries(attempt_id,path,name,kind,size,modified)
             VALUES(?1,?2,?3,?4,?5,?6)",
        )?;
        for (path, name, kind, size, modified) in batch.drain(..) {
            insert.execute(params![work.attempt_id, path, name, kind, size, modified])?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn publish(conn: &mut Connection, work: &Work) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current_generation: Option<i64> = tx
        .query_row(
            "SELECT active_generation FROM roots WHERE id=?1 AND covered_by IS NULL",
            [work.root_id],
            |row| row.get(0),
        )
        .optional()?;
    if current_generation.is_none() {
        drop(tx);
        return abandon_covered_attempt(conn, work);
    }
    if current_generation != Some(work.active_generation) {
        bail!("active index generation changed during scan");
    }
    let published_generation = if work.active_generation == 0 {
        work.attempt_id
    } else {
        apply_delta(&tx, work)?;
        work.active_generation
    };
    let changed = tx.execute(
        "UPDATE roots SET active_generation=?2,completed_seq=?3,last_verified=?4,published_attempt=?5,
         last_error=NULL,state=CASE WHEN desired_seq>?3 THEN 'pending' ELSE 'ready' END
         WHERE id=?1 AND covered_by IS NULL",
        params![
            work.root_id,
            published_generation,
            work.claimed_seq,
            now_secs(),
            work.attempt_id
        ],
    )?;
    if changed == 0 {
        drop(tx);
        return abandon_covered_attempt(conn, work);
    }
    tx.execute(
        "UPDATE scan_requests SET status='complete',result_generation=?3
         WHERE root_id=?1 AND target_seq<=?2 AND status IN ('pending','partial')",
        params![work.root_id, work.claimed_seq, published_generation],
    )?;
    tx.execute(
        "UPDATE scan_attempts SET state='complete',finished=?2 WHERE id=?1",
        params![work.attempt_id, now_secs()],
    )?;
    // The parent generation now serves every covered child. Retire their old
    // generations so overlapping root requests do not multiply disk usage.
    let covered_children: Vec<i64> = {
        let mut stmt = tx.prepare("SELECT id FROM roots WHERE covered_by=?1")?;
        stmt.query_map([work.root_id], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?
    };
    tx.execute(
        "UPDATE roots SET active_generation=0 WHERE covered_by=?1",
        [work.root_id],
    )?;
    tx.commit()?;
    // A reader can still hold a snapshot of the old generation. SQLite keeps
    // those pages alive until it ends; delete in a separate transaction.
    conn.execute(
        "DELETE FROM entries WHERE root_id=?1 AND generation!=?2",
        params![work.root_id, published_generation],
    )?;
    for child_id in covered_children {
        conn.execute("DELETE FROM entries WHERE root_id=?1", [child_id])?;
    }
    Ok(())
}

fn apply_delta(tx: &rusqlite::Transaction<'_>, work: &Work) -> Result<()> {
    tx.execute(
        "DELETE FROM entries AS e WHERE e.root_id=?1 AND e.generation=?2
         AND NOT EXISTS (SELECT 1 FROM staged_entries AS s
                         WHERE s.attempt_id=?3 AND s.path=e.path
                           AND s.name=e.name AND s.kind=e.kind AND s.size=e.size
                           AND s.modified IS e.modified)",
        params![work.root_id, work.active_generation, work.attempt_id],
    )?;
    tx.execute(
        "INSERT INTO entries(root_id,generation,path,name,kind,size,modified)
         SELECT ?1,?2,s.path,s.name,s.kind,s.size,s.modified FROM staged_entries AS s
         LEFT JOIN entries AS e ON e.root_id=?1 AND e.generation=?2 AND e.path=s.path
         WHERE s.attempt_id=?3 AND e.path IS NULL",
        params![work.root_id, work.active_generation, work.attempt_id],
    )?;
    tx.execute(
        "DELETE FROM staged_entries WHERE attempt_id=?1",
        [work.attempt_id],
    )?;
    Ok(())
}

fn fail_attempt(conn: &mut Connection, work: &Work, error: &str) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let changed = tx.execute(
        "UPDATE roots SET state='partial',last_error=?2,retry_not_before=?3 WHERE id=?1 AND covered_by IS NULL",
        params![work.root_id, error, now_secs() + ERROR_BACKOFF_SECS],
    )?;
    if changed == 0 {
        drop(tx);
        return abandon_covered_attempt(conn, work);
    }
    tx.execute(
        "UPDATE scan_requests SET status='partial' WHERE root_id=?1 AND target_seq<=?2 AND status='pending'",
        params![work.root_id, work.claimed_seq],
    )?;
    tx.execute(
        "UPDATE scan_attempts SET state='partial',finished=?2,error=?3 WHERE id=?1",
        params![work.attempt_id, now_secs(), error],
    )?;
    tx.commit()?;
    conn.execute(
        "DELETE FROM entries WHERE root_id=?1 AND generation=?2",
        params![work.root_id, work.attempt_id],
    )?;
    conn.execute(
        "DELETE FROM staged_entries WHERE attempt_id=?1",
        [work.attempt_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn await_status(indexer: &Indexer, id: &str) -> String {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let status = indexer.request_status(id).unwrap().unwrap().status;
            if status != "pending" || std::time::Instant::now() >= deadline {
                return status;
            }
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn force_due(conn: &Connection, root: &Path) {
        conn.execute(
            "UPDATE roots SET debounce_until_ms=0 WHERE path=?1",
            [path_text(&canonical_root(root).unwrap()).unwrap()],
        )
        .unwrap();
    }

    #[test]
    fn debounce_resets_stop_at_three_and_never_pass_ten_seconds() {
        let temp = tempdir().unwrap();
        let mut conn = connect(&temp.path().join("everything.db")).unwrap();
        init_schema(&mut conn).unwrap();
        let root_id = ensure_root(&conn, temp.path()).unwrap();
        let due = |conn: &Connection| -> (i64, i64) {
            conn.query_row(
                "SELECT debounce_until_ms,debounce_resets FROM roots WHERE id=?1",
                [root_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
        };
        schedule_debounce(&conn, root_id, 100_000).unwrap();
        assert_eq!(due(&conn), (103_000, 0));
        schedule_debounce(&conn, root_id, 102_900).unwrap();
        assert_eq!(due(&conn), (105_900, 1));
        schedule_debounce(&conn, root_id, 105_800).unwrap();
        assert_eq!(due(&conn), (108_800, 2));
        schedule_debounce(&conn, root_id, 108_700).unwrap();
        assert_eq!(due(&conn), (110_000, 3));
        schedule_debounce(&conn, root_id, 109_900).unwrap();
        assert_eq!(due(&conn), (110_000, 3));
    }

    #[test]
    fn debounce_deadline_survives_restart_and_idempotent_retry() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("root");
        let state = temp.path().join("state");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&state).unwrap();
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state.join("everything.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        let first = Indexer::open(&state).unwrap();
        first.request_refresh(&root, Some("stable-id")).unwrap();
        let deadline = first.status(&root).unwrap().next_scan_at_ms;
        assert!(deadline.is_some());
        first.request_refresh(&root, Some("stable-id")).unwrap();
        assert_eq!(first.status(&root).unwrap().next_scan_at_ms, deadline);
        drop(first);
        let second = Indexer::open(&state).unwrap();
        assert_eq!(second.status(&root).unwrap().next_scan_at_ms, deadline);
        lock.unlock().unwrap();
    }

    #[test]
    fn concurrent_requests_coalesce_into_one_scan_and_retry_is_idempotent() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("root");
        let state = temp.path().join("state");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(root.join("alpha.txt"), b"one").unwrap();

        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state.join("everything.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        let first = Indexer::open(&state).unwrap();
        let second = Indexer::open(&state).unwrap();
        let a = first.request_refresh(&root, Some("client-a")).unwrap();
        let b = second.request_refresh(&root, Some("client-b")).unwrap();
        let c = first.request_refresh(&root, Some("client-c")).unwrap();
        let repeated = second.request_refresh(&root, Some("client-a")).unwrap();
        assert_eq!(a.target_seq, repeated.target_seq);
        assert_eq!((a.target_seq, b.target_seq, c.target_seq), (1, 2, 3));
        lock.unlock().unwrap();

        for id in ["client-a", "client-b", "client-c"] {
            assert_eq!(await_status(&first, id), "complete");
        }
        let conn = connect(&state.join("everything.db")).unwrap();
        let attempts: i64 = conn
            .query_row("SELECT count(*) FROM scan_attempts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(attempts, 1);
        let result = second
            .search(&root, "alpha", MatchMode::Prefix, 10)
            .unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.status.completed_seq, 3);
        assert_eq!(
            second
                .search(&root, "pha.tx", MatchMode::Contains, 10)
                .unwrap()
                .matches
                .len(),
            1
        );
        assert_eq!(
            second
                .search(&root, "ha", MatchMode::Contains, 10)
                .unwrap()
                .matches
                .len(),
            1
        );
    }

    #[test]
    fn failed_scan_preserves_published_generation_and_retries_after_backoff() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("root");
        let state = temp.path().join("state");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(root.join("old.txt"), b"old").unwrap();
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state.join("everything.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        let indexer = Indexer::open(&state).unwrap();
        let first = indexer.request_refresh(&root, None).unwrap();
        let mut conn = connect(&state.join("everything.db")).unwrap();
        force_due(&conn, &root);
        let work = claim_next(&mut conn).unwrap().unwrap();
        assert_eq!(
            scan(&mut conn, &work, &state, &AtomicBool::new(false)).unwrap(),
            0
        );
        publish(&mut conn, &work).unwrap();
        assert_eq!(
            indexer
                .request_status(&first.request_id)
                .unwrap()
                .unwrap()
                .status,
            "complete"
        );

        let receipt = indexer.request_refresh(&root, None).unwrap();
        force_due(&conn, &root);
        let work = claim_next(&mut conn).unwrap().unwrap();
        fail_attempt(&mut conn, &work, "simulated read error").unwrap();
        let result = indexer
            .search(&root, "old.txt", MatchMode::Exact, 10)
            .unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.status.state, "partial");
        assert_eq!(
            indexer
                .request_status(&receipt.request_id)
                .unwrap()
                .unwrap()
                .status,
            "partial"
        );
        // Fresh clients can append work without resetting the recovery delay.
        indexer
            .request_refresh(&root, Some("later-client"))
            .unwrap();
        force_due(&conn, &root);
        assert!(claim_next(&mut conn).unwrap().is_none());
        lock.unlock().unwrap();
    }

    #[test]
    fn refresh_keeps_unchanged_rows_and_applies_only_the_delta() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("root");
        let state = temp.path().join("state");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&state).unwrap();
        let keep = root.join("keep.txt");
        let change = root.join("change.txt");
        let remove = root.join("remove.txt");
        fs::write(&keep, b"keep").unwrap();
        fs::write(&change, b"old").unwrap();
        fs::write(&remove, b"remove").unwrap();
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state.join("everything.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        let indexer = Indexer::open(&state).unwrap();
        let mut conn = connect(&state.join("everything.db")).unwrap();
        let refresh = |conn: &mut Connection| {
            indexer.request_refresh(&root, None).unwrap();
            force_due(conn, &root);
            let work = claim_next(conn).unwrap().unwrap();
            assert_eq!(
                scan(conn, &work, &state, &AtomicBool::new(false)).unwrap(),
                0
            );
            work
        };
        let first = refresh(&mut conn);
        assert_eq!(first.active_generation, 0);
        publish(&mut conn, &first).unwrap();
        let original_generation = indexer.status(&root).unwrap().active_generation;
        let keep_canonical = fs::canonicalize(&keep).unwrap();
        let rowid = |conn: &Connection| -> i64 {
            conn.query_row(
                "SELECT rowid FROM entries WHERE root_id=?1 AND generation=?2 AND path=?3",
                params![
                    first.root_id,
                    original_generation,
                    path_text(&keep_canonical).unwrap()
                ],
                |row| row.get(0),
            )
            .unwrap()
        };
        let keep_rowid = rowid(&conn);

        let unchanged = refresh(&mut conn);
        assert_eq!(unchanged.active_generation, original_generation);
        let staged: i64 = conn
            .query_row(
                "SELECT count(*) FROM staged_entries WHERE attempt_id=?1",
                [unchanged.attempt_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(staged, 3);
        publish(&mut conn, &unchanged).unwrap();
        assert_eq!(
            indexer.status(&root).unwrap().active_generation,
            original_generation
        );
        assert_eq!(rowid(&conn), keep_rowid);
        let staged: i64 = conn
            .query_row("SELECT count(*) FROM staged_entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(staged, 0);

        fs::write(&change, b"new-longer-data").unwrap();
        fs::remove_file(&remove).unwrap();
        fs::write(root.join("added.txt"), b"added").unwrap();
        let changed = refresh(&mut conn);
        publish(&mut conn, &changed).unwrap();
        assert_eq!(rowid(&conn), keep_rowid);
        assert_eq!(
            indexer.status(&root).unwrap().active_generation,
            original_generation
        );
        assert!(
            indexer
                .search(&root, "remove", MatchMode::Contains, 10)
                .unwrap()
                .matches
                .is_empty()
        );
        assert_eq!(
            indexer
                .search(&root, "added", MatchMode::Contains, 10)
                .unwrap()
                .matches
                .len(),
            1
        );
        assert_eq!(
            indexer
                .search(&root, "change.txt", MatchMode::Exact, 10)
                .unwrap()
                .matches[0]
                .size,
            15
        );

        let failed = refresh(&mut conn);
        fail_attempt(&mut conn, &failed, "simulated failure").unwrap();
        let staged: i64 = conn
            .query_row("SELECT count(*) FROM staged_entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(staged, 0);
        assert_eq!(rowid(&conn), keep_rowid);
        lock.unlock().unwrap();
    }

    #[test]
    fn newer_parent_delta_serves_child_even_with_an_older_generation_number() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("root");
        let child = root.join("child");
        let state = temp.path().join("state");
        fs::create_dir_all(&child).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(child.join("old.txt"), b"old").unwrap();
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state.join("everything.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        let indexer = Indexer::open(&state).unwrap();
        let mut conn = connect(&state.join("everything.db")).unwrap();
        let refresh = |conn: &mut Connection, path: &Path| {
            indexer.request_refresh(path, None).unwrap();
            force_due(conn, path);
            let work = claim_next(conn).unwrap().unwrap();
            assert_eq!(work.root, canonical_root(path).unwrap());
            assert_eq!(
                scan(conn, &work, &state, &AtomicBool::new(false)).unwrap(),
                0
            );
            publish(conn, &work).unwrap();
            work
        };
        refresh(&mut conn, &child);
        let first_parent = refresh(&mut conn, &root);
        let later_child = refresh(&mut conn, &child);
        assert!(later_child.attempt_id > first_parent.attempt_id);
        fs::write(child.join("new.txt"), b"new").unwrap();
        let later_parent = refresh(&mut conn, &root);
        assert_eq!(later_parent.active_generation, first_parent.attempt_id);
        assert!(later_parent.attempt_id > later_child.attempt_id);
        assert_eq!(
            indexer
                .search(&child, "new.txt", MatchMode::Exact, 10)
                .unwrap()
                .matches
                .len(),
            1
        );
        let child_canonical = canonical_root(&child).unwrap();
        conn.execute(
            "UPDATE roots SET last_verified=0 WHERE path=?1",
            [path_text(&child_canonical).unwrap()],
        )
        .unwrap();
        assert!(!indexer.schedule_background(&child, 3_600, 1, 0).unwrap());
        lock.unlock().unwrap();
    }

    #[test]
    fn background_scan_reports_progress_and_yields_to_foreground() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("root");
        let child = root.join("child");
        let state = temp.path().join("state");
        fs::create_dir_all(&child).unwrap();
        fs::create_dir_all(&state).unwrap();
        for n in 0..70 {
            fs::write(child.join(format!("file-{n:03}.txt")), b"x").unwrap();
        }
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state.join("everything.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        let indexer = Indexer::open(&state).unwrap();
        assert!(indexer.schedule_background(&root, 60, 1, 0).unwrap());
        assert!(!indexer.schedule_background(&root, 60, 1, 0).unwrap());
        let mut conn = connect(&state.join("everything.db")).unwrap();
        indexer.ensure_index(&child).unwrap();
        force_due(&conn, &child);
        let foreground = claim_next(&mut conn).unwrap().unwrap();
        assert_eq!(foreground.root, canonical_root(&child).unwrap());
        assert!(!foreground.background);
        scan(&mut conn, &foreground, &state, &AtomicBool::new(false)).unwrap();
        publish(&mut conn, &foreground).unwrap();

        force_due(&conn, &root);
        let background = claim_next(&mut conn).unwrap().unwrap();
        assert!(background.background);
        update_progress(&conn, &background, 12, 2, &child).unwrap();
        let status = indexer.status(&root).unwrap();
        assert!(status.background);
        assert_eq!(status.progress.unwrap().entries_seen, 12);

        indexer.request_refresh(&child, None).unwrap();
        let error = scan(&mut conn, &background, &state, &AtomicBool::new(false)).unwrap_err();
        assert!(error.downcast_ref::<BackgroundYield>().is_some());
        yield_background_attempt(&mut conn, &background).unwrap();
        force_due(&conn, &child);
        let next = claim_next(&mut conn).unwrap().unwrap();
        assert!(!next.background);
        assert_eq!(next.root, canonical_root(&child).unwrap());
        lock.unlock().unwrap();
    }

    #[test]
    fn request_during_scan_is_served_by_the_next_generation() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("root");
        let state = temp.path().join("state");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(root.join("first.txt"), b"first").unwrap();
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state.join("everything.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        let indexer = Indexer::open(&state).unwrap();
        let first = indexer.request_refresh(&root, Some("first")).unwrap();
        let mut conn = connect(&state.join("everything.db")).unwrap();
        force_due(&conn, &root);
        let first_work = claim_next(&mut conn).unwrap().unwrap();
        let second = indexer.request_refresh(&root, Some("second")).unwrap();
        fs::write(root.join("second.txt"), b"second").unwrap();
        scan(&mut conn, &first_work, &state, &AtomicBool::new(false)).unwrap();
        publish(&mut conn, &first_work).unwrap();
        assert_eq!(
            indexer
                .request_status(&first.request_id)
                .unwrap()
                .unwrap()
                .status,
            "complete"
        );
        assert_eq!(
            indexer
                .request_status(&second.request_id)
                .unwrap()
                .unwrap()
                .status,
            "pending"
        );
        force_due(&conn, &root);
        let second_work = claim_next(&mut conn).unwrap().unwrap();
        assert_eq!(second_work.claimed_seq, second.target_seq);
        scan(&mut conn, &second_work, &state, &AtomicBool::new(false)).unwrap();
        publish(&mut conn, &second_work).unwrap();
        assert_eq!(
            indexer
                .request_status(&second.request_id)
                .unwrap()
                .unwrap()
                .status,
            "complete"
        );
        lock.unlock().unwrap();
    }

    #[test]
    fn parent_scan_covers_child_request_and_child_search() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("root");
        let child = root.join("child");
        let state = temp.path().join("state");
        fs::create_dir_all(&child).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(child.join("needle.txt"), b"found").unwrap();
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state.join("everything.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        let indexer = Indexer::open(&state).unwrap();
        let parent_request = indexer.request_refresh(&root, Some("parent")).unwrap();
        let child_request = indexer.request_refresh(&child, Some("child")).unwrap();
        let mut conn = connect(&state.join("everything.db")).unwrap();
        let request_roots: Vec<i64> = {
            let mut stmt = conn
                .prepare("SELECT root_id FROM scan_requests ORDER BY request_id")
                .unwrap();
            stmt.query_map([], |row| row.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(request_roots.len(), 2);
        assert_eq!(request_roots[0], request_roots[1]);
        force_due(&conn, &root);
        let work = claim_next(&mut conn).unwrap().unwrap();
        scan(&mut conn, &work, &state, &AtomicBool::new(false)).unwrap();
        publish(&mut conn, &work).unwrap();
        assert_eq!(
            indexer
                .request_status(&parent_request.request_id)
                .unwrap()
                .unwrap()
                .status,
            "complete"
        );
        assert_eq!(
            indexer
                .request_status(&child_request.request_id)
                .unwrap()
                .unwrap()
                .status,
            "complete"
        );
        assert_eq!(
            indexer
                .search(&child, "needle", MatchMode::Contains, 10)
                .unwrap()
                .matches
                .len(),
            1
        );
        assert!(claim_next(&mut conn).unwrap().is_none());
        lock.unlock().unwrap();
    }

    #[test]
    fn later_parent_absorbs_pending_child_without_scanning_child() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("root");
        let child = root.join("child");
        let state = temp.path().join("state");
        fs::create_dir_all(&child).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(child.join("needle.txt"), b"found").unwrap();
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state.join("everything.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        let indexer = Indexer::open(&state).unwrap();
        let child_request = indexer
            .request_refresh(&child, Some("child-first"))
            .unwrap();
        let parent_request = indexer
            .request_refresh(&root, Some("parent-second"))
            .unwrap();
        let mut conn = connect(&state.join("everything.db")).unwrap();
        force_due(&conn, &root);
        let work = claim_next(&mut conn).unwrap().unwrap();
        assert_eq!(work.root, canonical_root(&root).unwrap());
        scan(&mut conn, &work, &state, &AtomicBool::new(false)).unwrap();
        publish(&mut conn, &work).unwrap();
        assert_eq!(
            indexer
                .request_status(&child_request.request_id)
                .unwrap()
                .unwrap()
                .status,
            "complete"
        );
        assert_eq!(
            indexer
                .request_status(&parent_request.request_id)
                .unwrap()
                .unwrap()
                .status,
            "complete"
        );
        assert_eq!(
            indexer
                .search(&child, "needle.txt", MatchMode::Exact, 10)
                .unwrap()
                .matches
                .len(),
            1
        );
        let attempts: i64 = conn
            .query_row("SELECT count(*) FROM scan_attempts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(attempts, 1);
        lock.unlock().unwrap();
    }

    #[test]
    fn parent_supersedes_an_already_claimed_child_scan() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("root");
        let child = root.join("child");
        let state = temp.path().join("state");
        fs::create_dir_all(&child).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(child.join("needle.txt"), b"found").unwrap();
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state.join("everything.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        let indexer = Indexer::open(&state).unwrap();
        let child_request = indexer
            .request_refresh(&child, Some("claimed-child"))
            .unwrap();
        let mut conn = connect(&state.join("everything.db")).unwrap();
        force_due(&conn, &child);
        let child_work = claim_next(&mut conn).unwrap().unwrap();
        let parent_request = indexer.request_refresh(&root, Some("new-parent")).unwrap();
        assert!(is_covered(&conn, child_work.root_id).unwrap());
        scan(&mut conn, &child_work, &state, &AtomicBool::new(false)).unwrap();
        publish(&mut conn, &child_work).unwrap();
        let child_attempt_state: String = conn
            .query_row(
                "SELECT state FROM scan_attempts WHERE id=?1",
                [child_work.attempt_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(child_attempt_state, "superseded");
        force_due(&conn, &root);
        let parent_work = claim_next(&mut conn).unwrap().unwrap();
        scan(&mut conn, &parent_work, &state, &AtomicBool::new(false)).unwrap();
        publish(&mut conn, &parent_work).unwrap();
        assert_eq!(
            indexer
                .request_status(&child_request.request_id)
                .unwrap()
                .unwrap()
                .status,
            "complete"
        );
        assert_eq!(
            indexer
                .request_status(&parent_request.request_id)
                .unwrap()
                .unwrap()
                .status,
            "complete"
        );
        lock.unlock().unwrap();
    }

    #[test]
    fn grandparent_absorbs_an_already_coalesced_subtree() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("root");
        let child = root.join("child");
        let grandchild = child.join("grandchild");
        let state = temp.path().join("state");
        fs::create_dir_all(&grandchild).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(grandchild.join("deep.txt"), b"deep").unwrap();
        let lock = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state.join("everything.lock"))
            .unwrap();
        lock.try_lock().unwrap();
        let indexer = Indexer::open(&state).unwrap();
        let a = indexer.request_refresh(&grandchild, Some("deep")).unwrap();
        let b = indexer.request_refresh(&child, Some("middle")).unwrap();
        let c = indexer.request_refresh(&root, Some("top")).unwrap();
        let mut conn = connect(&state.join("everything.db")).unwrap();
        force_due(&conn, &root);
        let work = claim_next(&mut conn).unwrap().unwrap();
        assert_eq!(work.root, canonical_root(&root).unwrap());
        scan(&mut conn, &work, &state, &AtomicBool::new(false)).unwrap();
        publish(&mut conn, &work).unwrap();
        for id in [a.request_id, b.request_id, c.request_id] {
            assert_eq!(
                indexer.request_status(&id).unwrap().unwrap().status,
                "complete"
            );
        }
        assert_eq!(
            indexer
                .search(&grandchild, "deep.txt", MatchMode::Exact, 10)
                .unwrap()
                .matches
                .len(),
            1
        );
        let attempts: i64 = conn
            .query_row("SELECT count(*) FROM scan_attempts", [], |row| row.get(0))
            .unwrap();
        assert_eq!(attempts, 1);
        lock.unlock().unwrap();
    }
}
