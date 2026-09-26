use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};

use crate::types::{ScanProgress, Status};
use crate::{DEBOUNCE_MAX_MS, DEBOUNCE_MAX_RESETS, DEBOUNCE_QUIET_MS};

pub(crate) fn canonical_root(path: &Path) -> Result<PathBuf> {
    let root =
        fs::canonicalize(path).with_context(|| format!("cannot resolve {}", path.display()))?;
    if !root.is_dir() {
        bail!("index root is not a directory: {}", root.display());
    }
    path_text(&root)?;
    Ok(root)
}

pub(crate) fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("non-Unicode paths are not supported by this index"))
}

pub(crate) fn ensure_root(conn: &Connection, path: &Path) -> Result<i64> {
    let text = path_text(path)?;
    conn.execute("INSERT OR IGNORE INTO roots(path) VALUES(?1)", [text])?;
    Ok(
        conn.query_row("SELECT id FROM roots WHERE path=?1", [text], |row| {
            row.get(0)
        })?,
    )
}

#[derive(Debug)]
pub(crate) struct RootRow {
    pub(crate) id: i64,
    pub(crate) path: PathBuf,
    pub(crate) active_generation: i64,
    pub(crate) state: String,
    pub(crate) published_attempt: i64,
    pub(crate) desired_seq: i64,
    pub(crate) completed_seq: i64,
    pub(crate) covered_by: Option<i64>,
    pub(crate) background: bool,
}

pub(crate) fn root_rows(conn: &Connection) -> Result<Vec<RootRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,path,active_generation,desired_seq,completed_seq,covered_by,published_attempt,background,state FROM roots",
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
            state: row.get(8)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub(crate) fn pending_ancestor<'a>(rows: &'a [RootRow], path: &Path) -> Option<&'a RootRow> {
    rows.iter()
        .filter(|row| {
            path.starts_with(&row.path)
                && (path == row.path || row.state != "partial")
                && row.covered_by.is_none()
                && !row.background
                && row.desired_seq > row.completed_seq
        })
        .min_by_key(|row| row.path.components().count())
}

pub(crate) fn pending_background_ancestor<'a>(
    rows: &'a [RootRow],
    path: &Path,
) -> Option<&'a RootRow> {
    rows.iter()
        .filter(|row| {
            path.starts_with(&row.path)
                && row.covered_by.is_none()
                && row.background
                && row.desired_seq > row.completed_seq
        })
        .min_by_key(|row| row.path.components().count())
}

pub(crate) fn active_provider<'a>(rows: &'a [RootRow], path: &Path) -> Option<&'a RootRow> {
    rows.iter()
        .filter(|row| path.starts_with(&row.path) && row.active_generation > 0)
        .max_by_key(|row| row.published_attempt)
}

pub(crate) fn status_for_path(conn: &Connection, path: &Path) -> Result<Status> {
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

pub(crate) fn absorb_descendants(
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
pub(crate) fn schedule_debounce(conn: &Connection, root_id: i64, now_ms: i64) -> Result<()> {
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

pub(crate) fn status_by_path(conn: &Connection, path: &Path) -> Result<Status> {
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

pub(crate) fn status_by_id(conn: &Connection, id: i64) -> Result<Status> {
    let mut status = conn.query_row(
        "SELECT state,active_generation,desired_seq,completed_seq,last_verified,last_error,debounce_until_ms,background,control FROM roots WHERE id=?1",
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
        control: row.get(8)?,
        progress: None,
    })
}
