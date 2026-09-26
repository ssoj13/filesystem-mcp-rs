use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use rusqlite::{Connection, TransactionBehavior};

pub(crate) fn connect(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    // WAL + NORMAL never corrupts the file; a power cut can only drop the newest commits,
    // and this index is rebuildable. FULL would fsync on every scan batch. A larger
    // checkpoint interval rewrites hot b-tree pages to the main file once per checkpoint
    // instead of once per 4 MB of WAL, and the size limit gives the space back afterwards.
    conn.execute_batch(
        "PRAGMA foreign_keys=ON;
         PRAGMA synchronous=NORMAL;
         PRAGMA wal_autocheckpoint=8000;
         PRAGMA journal_size_limit=268435456;",
    )?;
    Ok(conn)
}

pub(crate) fn init_schema(conn: &mut Connection) -> Result<()> {
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
    if version < 8 {
        tx.execute_batch(
            "ALTER TABLE roots ADD COLUMN resume_generation INTEGER NOT NULL DEFAULT 0;
             PRAGMA user_version=8;",
        )?;
    }
    if version < 9 {
        tx.execute_batch(
            "ALTER TABLE roots ADD COLUMN control TEXT NOT NULL DEFAULT 'run';
             PRAGMA user_version=9;",
        )?;
    }
    tx.commit()?;
    Ok(())
}
