use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

use anyhow::{Result, bail};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::*;

pub(crate) fn worker_loop(db_path: &Path, lock_path: &Path, state_root: &Path, stop: &AtomicBool) {
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

pub(crate) struct Work {
    pub(crate) root_id: i64,
    pub(crate) root: PathBuf,
    pub(crate) claimed_seq: i64,
    pub(crate) attempt_id: i64,
    pub(crate) active_generation: i64,
    pub(crate) background: bool,
    pub(crate) background_pause_ms: u64,
}

pub(crate) fn claim_next(conn: &mut Connection) -> Result<Option<Work>> {
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
pub(crate) struct BackgroundYield;

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

pub(crate) fn yield_background_attempt(conn: &mut Connection, work: &Work) -> Result<()> {
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

pub(crate) fn scan(conn: &mut Connection, work: &Work, state_root: &Path, stop: &AtomicBool) -> Result<u64> {
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
            Err(fscan_rs::ScanFailure::Cancelled) => {
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

pub(crate) fn update_progress(
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
