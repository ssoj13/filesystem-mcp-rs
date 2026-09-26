use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

use anyhow::{Result, bail};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::*;

pub(crate) fn worker_loop(
    db_path: &Path,
    lock_path: &Path,
    state_root: &Path,
    stop: &AtomicBool,
    config: &IndexerConfig,
) {
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
            && process_next(&mut conn, state_root, stop, config).is_err()
        {
            let _ = recover(&conn);
        }
        thread::sleep(POLL_INTERVAL);
    }
    if owner {
        let _ = lock_file.unlock();
    }
}

pub(crate) fn recover(conn: &Connection) -> Result<()> {
    // A scan of a root that was never published has nothing else to fall back on and can
    // cost hours: its rows stay under `resume_generation` and the next attempt continues
    // them. A refresh only ever staged a delta against a published generation, which is
    // cheap to redo, so that attempt is abandoned.
    let interrupted = conn.execute(
        "UPDATE scan_attempts SET finished=strftime('%s','now'),
           state=CASE WHEN (SELECT active_generation FROM roots WHERE roots.id=scan_attempts.root_id)=0
                      THEN 'interrupted' ELSE 'abandoned' END
         WHERE state='running'",
        [],
    )?;
    conn.execute_batch(
        "UPDATE roots SET state='pending' WHERE state='building' AND covered_by IS NULL;
         UPDATE roots SET state='covered',desired_seq=completed_seq
           WHERE state='building' AND covered_by IS NOT NULL;",
    )?;
    if interrupted > 0 {
        tracing::info!(
            interrupted,
            "locate recovery: scans of a dead process closed"
        );
    }
    // Rows that nothing can resume or serve are leftovers of an older layout or a superseded
    // scan. Deleting them in one statement holds the writer lock for minutes and grows the
    // WAL while every foreground locate request times out. Delete in bounded commits.
    let roots: Vec<(i64, i64, i64)> = {
        let mut stmt = conn.prepare("SELECT id,active_generation,resume_generation FROM roots")?;
        stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    for (root_id, active_generation, resume_generation) in roots {
        let stale_generations: Vec<i64> = {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT generation FROM entries
                 WHERE root_id=?1 AND generation!=?2 AND generation!=?3",
            )?;
            stmt.query_map(
                params![root_id, active_generation, resume_generation],
                |row| row.get(0),
            )?
            .collect::<rusqlite::Result<_>>()?
        };
        for generation in stale_generations {
            loop {
                let deleted = conn.execute(
                    "DELETE FROM entries WHERE rowid IN (
                       SELECT rowid FROM entries WHERE root_id=?1 AND generation=?2 LIMIT ?3
                     )",
                    params![root_id, generation, BATCH_SIZE as i64],
                )?;
                if deleted == 0 {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
    loop {
        let deleted = conn.execute(
            "DELETE FROM staged_entries WHERE (attempt_id,path) IN (
               SELECT attempt_id,path FROM staged_entries LIMIT ?1
             )",
            [BATCH_SIZE as i64],
        )?;
        if deleted == 0 {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

/// How long the writer rests after a commit that took `commit_took`. Proportional, so a slow
/// disk (or a huge FTS merge) is given more room rather than the same fixed slice: the scan
/// holds the disk about a third of the time however slow the commits get. The floor still
/// hands the single writer slot to other processes; the ceiling keeps one bad commit from
/// parking the scan.
pub(crate) fn pause_after_commit(commit_took: Duration, rest: u32, max: Duration) -> Duration {
    (commit_took * rest).clamp(MIN_COMMIT_PAUSE, max.max(MIN_COMMIT_PAUSE))
}

pub(crate) struct Work {
    pub(crate) root_id: i64,
    pub(crate) root: PathBuf,
    pub(crate) claimed_seq: i64,
    pub(crate) attempt_id: i64,
    /// Generation this attempt's rows are written under (initial scans only; a resumed scan
    /// reuses the generation of the attempt it continues).
    pub(crate) generation: i64,
    pub(crate) active_generation: i64,
    pub(crate) settings: IndexerConfig,
}

pub(crate) fn claim_next(conn: &mut Connection) -> Result<Option<Work>> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let next = tx
        .query_row(
            "SELECT id,path,desired_seq,active_generation,resume_generation FROM roots
             WHERE desired_seq>completed_seq AND state!='building'
               AND covered_by IS NULL AND control='run'
               AND retry_not_before<=?1
               AND debounce_until_ms<=?2
             ORDER BY last_started,id LIMIT 1",
            params![now_secs(), now_millis()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((root_id, root, claimed_seq, active_generation, resume_generation)) = next else {
        tx.commit()?;
        return Ok(None);
    };
    tx.execute(
        "INSERT INTO scan_attempts(root_id,claimed_seq,state,started) VALUES(?1,?2,'running',?3)",
        params![root_id, claimed_seq, now_secs()],
    )?;
    let attempt_id = tx.last_insert_rowid();
    // An initial scan writes its rows under a generation of its own. It keeps that number
    // across attempts (recorded now, so it outlives a crash) until the root is published.
    let generation = if active_generation == 0 && resume_generation != 0 {
        resume_generation
    } else {
        attempt_id
    };
    tx.execute(
        "UPDATE roots SET state='building',last_started=?2,
         resume_generation=CASE WHEN active_generation=0 THEN ?3 ELSE 0 END,
         debounce_first_ms=0,debounce_until_ms=0,debounce_resets=0 WHERE id=?1",
        params![root_id, now_secs(), generation],
    )?;
    tx.commit()?;
    Ok(Some(Work {
        root_id,
        root: PathBuf::from(root),
        claimed_seq,
        attempt_id,
        generation,
        active_generation,
        settings: IndexerConfig::default(),
    }))
}

pub(crate) fn process_next(
    conn: &mut Connection,
    state_root: &Path,
    stop: &AtomicBool,
    config: &IndexerConfig,
) -> Result<()> {
    let Some(mut work) = claim_next(conn)? else {
        return Ok(());
    };
    work.settings = config.clone();
    let started = Instant::now();
    tracing::info!(
        root = %work.root.display(),
        attempt = work.attempt_id,
        generation = work.generation,
        resumed = work.generation != work.attempt_id,
        refresh = work.active_generation != 0,
        "locate scan started"
    );
    let outcome = scan(conn, &work, state_root, stop);
    if is_covered(conn, work.root_id)? {
        return abandon_covered_attempt(conn, &work);
    }
    // A completed traversal with skipped entries is usable but incomplete.
    // Only an aborted traversal needs the short automatic retry backoff.
    let elapsed_secs = started.elapsed().as_secs();
    match outcome {
        Ok(0) => {
            tracing::info!(root = %work.root.display(), elapsed_secs, "locate scan complete");
            publish(conn, &work)
        }
        Ok(errors) if work.active_generation == 0 => {
            tracing::warn!(root = %work.root.display(), errors, elapsed_secs, "locate scan complete with skipped entries");
            publish_partial_initial(
                conn,
                &work,
                &format!("{errors} entries could not be indexed"),
            )
        }
        Ok(errors) => {
            tracing::warn!(root = %work.root.display(), errors, elapsed_secs, "locate refresh complete with skipped entries");
            finish_partial_refresh(
                conn,
                &work,
                &format!("{errors} entries could not be indexed"),
            )
        }
        // Shutting down is not a failure: no backoff, and nothing built so far is thrown away.
        Err(error)
            if stop.load(Ordering::Acquire) || error.downcast_ref::<ScanStopped>().is_some() =>
        {
            tracing::info!(root = %work.root.display(), elapsed_secs, "locate scan interrupted: {error:#}");
            interrupt_attempt(conn, &work)
        }
        Err(error) => {
            tracing::warn!(root = %work.root.display(), elapsed_secs, "locate scan failed: {error:#}");
            fail_attempt(conn, &work, &error.to_string())
        }
    }
}

/// Close an attempt that was cut short from outside (shutdown) without penalty. An initial
/// scan keeps its rows for the next attempt to continue; a refresh drops its cheap staging.
pub(crate) fn interrupt_attempt(conn: &mut Connection, work: &Work) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "UPDATE scan_attempts SET state='interrupted',finished=?2 WHERE id=?1",
        params![work.attempt_id, now_secs()],
    )?;
    tx.execute(
        "UPDATE roots SET state='pending' WHERE id=?1 AND covered_by IS NULL",
        [work.root_id],
    )?;
    tx.commit()?;
    conn.execute(
        "DELETE FROM staged_entries WHERE attempt_id=?1",
        [work.attempt_id],
    )?;
    Ok(())
}

/// The scan was ended on request (`Indexer::scan_control`), not by a failure.
#[derive(Debug)]
pub(crate) struct ScanStopped;

impl std::fmt::Display for ScanStopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("scan stopped by request")
    }
}

impl std::error::Error for ScanStopped {}

/// Obey an operator's request (`Indexer::scan_control`) for this root: fail with
/// [`ScanStopped`] when stopped, and wait here while paused. The request lives in the
/// database, so it reaches a scan that runs in another process. A shutdown ends the wait.
fn honour_control(conn: &Connection, root_id: i64, stop: &AtomicBool) -> Result<()> {
    loop {
        let control: String =
            conn.query_row("SELECT control FROM roots WHERE id=?1", [root_id], |row| {
                row.get(0)
            })?;
        match control.as_str() {
            "stopped" => return Err(ScanStopped.into()),
            "paused" if !stop.load(Ordering::Acquire) => thread::sleep(CONTROL_POLL),
            _ => return Ok(()),
        }
    }
}

pub(crate) fn is_covered(conn: &Connection, root_id: i64) -> Result<bool> {
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
        "UPDATE roots SET state='covered',desired_seq=completed_seq,resume_generation=0
         WHERE id=?1 AND covered_by IS NOT NULL",
        [work.root_id],
    )?;
    tx.commit()?;
    conn.execute(
        "DELETE FROM entries WHERE root_id=?1 AND generation=?2",
        params![work.root_id, work.generation],
    )?;
    conn.execute(
        "DELETE FROM staged_entries WHERE attempt_id=?1",
        [work.attempt_id],
    )?;
    Ok(())
}

pub(crate) fn scan(
    conn: &mut Connection,
    work: &Work,
    state_root: &Path,
    stop: &AtomicBool,
) -> Result<u64> {
    let mut batch = Vec::with_capacity(work.settings.scan_batch);
    let mut extra_errors = 0u64;
    let mut last_progress = Instant::now();
    #[cfg(windows)]
    let mut native_progress_error = None;
    #[cfg(windows)]
    let cancel = AtomicBool::new(false);
    #[cfg(windows)]
    let mut last_control_check: Option<Instant> = None;
    #[cfg(windows)]
    let native_tree = if work.root.parent().is_some() && fscan_rs::is_ntfs_available(&work.root) {
        // The tree read cannot be told to stop except through the flag it is given, so the
        // callback forwards a shutdown or an operator's stop into a flag of its own.
        let result =
            fscan_rs::scan_ntfs_tree_with_options(&work.root, &cancel, false, |progress| {
                if native_progress_error.is_none() {
                    native_progress_error =
                        update_progress(conn, work, progress.items, progress.dirs, &work.root)
                            .err();
                }
                if native_progress_error.is_none()
                    && last_control_check.is_none_or(|at| at.elapsed() >= CONTROL_CHECK_INTERVAL)
                {
                    native_progress_error = honour_control(conn, work.root_id, stop).err();
                    last_control_check = Some(Instant::now());
                }
                if native_progress_error.is_some() || stop.load(Ordering::Acquire) {
                    cancel.store(true, Ordering::Release);
                }
            });
        match result {
            Ok(tree) => Some(tree),
            Err(fscan_rs::ScanFailure::Cancelled) => {
                if let Some(error) = native_progress_error.take() {
                    return Err(error);
                }
                bail!("scan cancelled during shutdown")
            }
            Err(error) => {
                tracing::warn!(
                    "NTFS scan failed for {}: {error:#}; using standard traversal",
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
    let mut visit_control_check: Option<Instant> = None;
    let mut visit =
        |entry: &fscan_rs::Entry, progress: fscan_rs::Progress| -> Result<fscan_rs::Visit> {
            if visit_control_check.is_none_or(|at| at.elapsed() >= CONTROL_CHECK_INTERVAL) {
                honour_control(conn, work.root_id, stop)?;
                visit_control_check = Some(Instant::now());
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
            if batch.len() >= work.settings.scan_batch {
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
            |path| !path.starts_with(state_root) && !work.settings.is_excluded(path),
            &mut visit,
        ) {
            Ok(progress) => Some(progress),
            Err(fscan_rs::NtfsStreamError::Sink(error)) => return Err(error),
            Err(fscan_rs::NtfsStreamError::Cancelled) => bail!("scan cancelled during shutdown"),
            Err(fscan_rs::NtfsStreamError::Backend(error)) => return Err(error.into()),
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
            |path| !path.starts_with(state_root) && !work.settings.is_excluded(path),
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

pub(crate) fn update_progress(
    conn: &Connection,
    work: &Work,
    entries_seen: u64,
    dirs_seen: u64,
    current_path: &Path,
) -> Result<()> {
    // The row above is for pollers; this line is for whoever reads the log after a crash.
    // One scan runs per process, so one process-wide timestamp throttles it.
    static LAST_LOGGED_MS: AtomicI64 = AtomicI64::new(0);
    let now = now_millis();
    if now - LAST_LOGGED_MS.load(Ordering::Relaxed) >= PROGRESS_LOG_INTERVAL_MS {
        LAST_LOGGED_MS.store(now, Ordering::Relaxed);
        tracing::info!(
            attempt = work.attempt_id,
            entries = entries_seen,
            dirs = dirs_seen,
            at = %current_path.display(),
            "locate scan progress"
        );
    }
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
    let commit_started = Instant::now();
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if work.active_generation == 0 {
        // A resumed scan meets rows it wrote before. Unchanged ones cost a lookup and no
        // write; changed ones take the new metadata. (REPLACE would skip the delete trigger
        // that keeps the FTS indexes in step, and a plain upsert never touches path or name.)
        let mut insert = tx.prepare_cached(
            "INSERT INTO entries(root_id,generation,path,name,kind,size,modified)
             VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(root_id,generation,path) DO UPDATE SET
               kind=excluded.kind,size=excluded.size,modified=excluded.modified
             WHERE entries.kind IS NOT excluded.kind OR entries.size IS NOT excluded.size
                OR entries.modified IS NOT excluded.modified",
        )?;
        for (path, name, kind, size, modified) in batch.drain(..) {
            insert.execute(params![
                work.root_id,
                work.generation,
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
    // A large scan otherwise reacquires SQLite's single writer slot almost
    // immediately. Give other requests a
    // chance to acquire it between batches, even across MCP processes.
    thread::sleep(pause_after_commit(
        commit_started.elapsed(),
        work.settings.write_rest,
        work.settings.write_pause_max,
    ));
    Ok(())
}

pub(crate) fn publish(conn: &mut Connection, work: &Work) -> Result<()> {
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
        work.generation
    } else {
        apply_delta(&tx, work)?;
        work.active_generation
    };
    let changed = tx.execute(
        "UPDATE roots SET active_generation=?2,completed_seq=?3,last_verified=?4,published_attempt=?5,
         resume_generation=0,last_error=NULL,state=CASE WHEN desired_seq>?3 THEN 'pending' ELSE 'ready' END
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

pub(crate) fn publish_partial_initial(
    conn: &mut Connection,
    work: &Work,
    error: &str,
) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let changed = tx.execute(
        "UPDATE roots SET active_generation=?2,published_attempt=?6,completed_seq=?3,
         resume_generation=0,last_verified=?4,last_error=?5,retry_not_before=0,
         state=CASE WHEN desired_seq>?3 THEN 'pending' ELSE 'partial' END
         WHERE id=?1 AND active_generation=0 AND covered_by IS NULL",
        params![
            work.root_id,
            work.generation,
            work.claimed_seq,
            now_secs(),
            error,
            work.attempt_id
        ],
    )?;
    if changed == 0 {
        drop(tx);
        return fail_attempt(conn, work, error);
    }
    tx.execute(
        "UPDATE scan_requests SET status='partial',result_generation=?3
         WHERE root_id=?1 AND target_seq<=?2 AND status='pending'",
        params![work.root_id, work.claimed_seq, work.generation],
    )?;
    tx.execute(
        "UPDATE scan_attempts SET state='partial',finished=?2,error=?3 WHERE id=?1",
        params![work.attempt_id, now_secs(), error],
    )?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn finish_partial_refresh(
    conn: &mut Connection,
    work: &Work,
    error: &str,
) -> Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let changed = tx.execute(
        "UPDATE roots SET completed_seq=?3,last_verified=?4,last_error=?5,retry_not_before=0,
         state=CASE WHEN desired_seq>?3 THEN 'pending' ELSE 'partial' END
         WHERE id=?1 AND active_generation=?2 AND covered_by IS NULL",
        params![
            work.root_id,
            work.active_generation,
            work.claimed_seq,
            now_secs(),
            error
        ],
    )?;
    if changed == 0 {
        drop(tx);
        return abandon_covered_attempt(conn, work);
    }
    tx.execute(
        "UPDATE scan_requests SET status='partial',result_generation=?3
         WHERE root_id=?1 AND target_seq<=?2 AND status='pending'",
        params![work.root_id, work.claimed_seq, work.active_generation],
    )?;
    tx.execute(
        "UPDATE scan_attempts SET state='partial',finished=?2,error=?3 WHERE id=?1",
        params![work.attempt_id, now_secs(), error],
    )?;
    tx.commit()?;
    conn.execute(
        "DELETE FROM staged_entries WHERE attempt_id=?1",
        [work.attempt_id],
    )?;
    Ok(())
}

pub(crate) fn fail_attempt(conn: &mut Connection, work: &Work, error: &str) -> Result<()> {
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
    // A failed initial scan keeps what it read: the retry continues it instead of paying for
    // the whole tree again.
    conn.execute(
        "DELETE FROM staged_entries WHERE attempt_id=?1",
        [work.attempt_id],
    )?;
    Ok(())
}
