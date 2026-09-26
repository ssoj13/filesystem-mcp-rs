use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Result, bail};
use globset::Glob;
use regex::Regex;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::*;

/// Owns a background thread. Clone the surrounding `Arc<Indexer>` for MCP
/// connections; the thread itself never retains that Arc.
pub struct Indexer {
    db_path: PathBuf,
    stop: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl Indexer {
    pub fn open(state_root: &Path) -> Result<Self> {
        Self::open_with(state_root, IndexerConfig::default())
    }

    pub fn open_with(state_root: &Path, config: IndexerConfig) -> Result<Self> {
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
            .spawn(move || {
                worker_loop(&worker_db, &lock_path, &state_root, &worker_stop, &config)
            })?;
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
        let requested_path = path_text(&root)?;
        if let Some((existing_path, receipt)) = request_receipt(&conn, &request_id)? {
            if existing_path != requested_path {
                bail!("request id already belongs to another root");
            }
            return Ok(receipt);
        }
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((existing_path, receipt)) = request_receipt(&tx, &request_id)? {
            if existing_path != requested_path {
                bail!("request id already belongs to another root");
            }
            tx.commit()?;
            return Ok(receipt);
        }
        let rows = root_rows(&tx)?;
        let (root_id, work_path) = if let Some(ancestor) = pending_ancestor(&rows, &root) {
            (ancestor.id, ancestor.path.clone())
        } else {
            (ensure_root(&tx, &root)?, root.clone())
        };
        tx.execute(
            "UPDATE roots SET desired_seq=desired_seq+1,covered_by=NULL,
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

    /// Control the scans of one root (`root`) or of every known root (`None`). The request is
    /// stored in the database, so it takes effect in whichever process runs the scan: a stop
    /// ends the running scan within a fraction of a second and keeps its rows for a later
    /// `Start`, a pause holds it in place. `Start` needs a path; every other action treats a
    /// path that was never indexed as an error rather than silently doing nothing.
    pub fn scan_control(&self, action: ScanAction, root: Option<&Path>) -> Result<Vec<ScanInfo>> {
        let root = root.map(canonical_root).transpose()?;
        if action == ScanAction::Start && root.is_none() {
            bail!("start needs a path");
        }
        let mut conn = connect(&self.db_path)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let selected: Vec<(i64, PathBuf)> = root_rows(&tx)?
            .into_iter()
            .filter(|row| root.as_ref().is_none_or(|wanted| &row.path == wanted))
            .map(|row| (row.id, row.path))
            .collect();
        if selected.is_empty() && root.is_some() && action != ScanAction::Start {
            bail!("no scans are registered for that path");
        }
        let control = match action {
            ScanAction::Status => None,
            ScanAction::Stop => Some("stopped"),
            ScanAction::Pause => Some("paused"),
            ScanAction::Start | ScanAction::Resume => Some("run"),
        };
        if let Some(control) = control {
            for (id, _) in &selected {
                tx.execute(
                    "UPDATE roots SET control=?2 WHERE id=?1",
                    params![id, control],
                )?;
            }
        }
        tx.commit()?;
        if action == ScanAction::Start
            && let Some(root) = &root
        {
            self.request_refresh(root, None)?;
        }
        let conn = connect(&self.db_path)?;
        let mut infos = Vec::new();
        for (id, path) in root_rows(&conn)?
            .into_iter()
            .filter(|row| root.as_ref().is_none_or(|wanted| &row.path == wanted))
            .map(|row| (row.id, row.path))
        {
            infos.push(ScanInfo {
                path,
                status: status_by_id(&conn, id)?,
            });
        }
        Ok(infos)
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

fn request_receipt(conn: &Connection, request_id: &str) -> Result<Option<(String, Receipt)>> {
    conn.query_row(
        "SELECT s.requested_path,s.target_seq,s.status,r.path,r.debounce_until_ms
         FROM scan_requests s JOIN roots r ON r.id=s.root_id WHERE s.request_id=?1",
        [request_id],
        |row| {
            Ok((
                row.get(0)?,
                Receipt {
                    request_id: request_id.to_owned(),
                    target_seq: row.get(1)?,
                    status: row.get(2)?,
                    work_root: PathBuf::from(row.get::<_, String>(3)?),
                    next_scan_at_ms: nonzero_time(row.get(4)?),
                },
            ))
        },
    )
    .optional()
    .map_err(Into::into)
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
