//! The statistics database: one door in, additive rows inside.
//!
//! Every process that runs this server writes tool-call counters into *one* shared SQLite file
//! under the state root. Dozens of them are alive at once, so the schema is built around two
//! properties rather than around what is convenient to query:
//!
//! 1. **Every stored column is an INTEGER counter merged in place** ([`UPSERT_AGG`]). A write
//!    therefore never has to read a row first, which is what makes `SQLITE_BUSY_SNAPSHOT`
//!    *unreachable* rather than merely handled: that code is returned when a deferred
//!    transaction that has already taken a read snapshot tries to upgrade to a write lock, and
//!    `busy_timeout` does not retry it. A TEXT payload (a latency histogram blob, say) would
//!    force a SELECT-parse-UPDATE cycle and bring the whole failure mode back.
//! 2. **`instance_id` is part of every primary key.** Two concurrent processes can then never
//!    target the same row, so cross-process double counting is structurally impossible and the
//!    only interaction left between writers is the file write lock.
//!
//! [`open`] is the single door: nothing else in the crate opens this file, so the pragmas, the
//! schema and the version check cannot be applied by one caller and skipped by another.
//! Everything here is blocking `rusqlite` and must be called from `spawn_blocking`, never from
//! the async runtime.
//!
//! Used by the flush task (writes), by the `stats_*` read tools (via [`open_read_only`]) and by
//! the housekeeping sweep (compaction).

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, TransactionBehavior, ffi};

/// The schema this build writes and understands, stored in `PRAGMA user_version`.
///
/// A file carrying a *larger* number was written by a newer build whose columns may mean
/// something else, and [`open`] refuses it rather than adding to counters it cannot interpret.
pub const SCHEMA_VERSION: i32 = 1;

/// How long a writer waits for the single write lock before giving up.
///
/// Five seconds is far beyond the ~2 transactions/second that fifty servers produce; it exists
/// for the pathological case (a laptop resuming, a virus scanner holding the file), where
/// failing the flush would merely postpone the same rows to the next one anyway.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling for the `-wal` sidecar, in bytes, applied after every checkpoint.
///
/// Without it a single long-lived reader pins the write-ahead log and it grows without bound -
/// `memory_v2` has exactly that latent bug today, which is why this is set here and not copied
/// from there. 16 MiB is orders of magnitude more than a flush of a few hundred counter rows
/// needs, so the limit only ever truncates pathological growth.
const JOURNAL_SIZE_LIMIT: i64 = 16 * 1024 * 1024;

/// The whole schema, applied by [`open`] when the file is new.
///
/// `STRICT` on every table so a mis-bound parameter is rejected at the write instead of storing
/// a string where a counter belongs and poisoning every later `SUM`. `WITHOUT ROWID` because
/// every table here is fully described by its primary key - the hidden rowid and its second
/// b-tree would be pure overhead.
///
/// `tool_agg`'s key **starts with `bucket`** so that "sum by tool over a time range" is a prefix
/// range scan rather than a full scan, and so pruning deletes a contiguous prefix.
///
/// `sessions`' key is `(started_day, pid, instance_id, session_id)`, not `(instance_id,
/// session_id)`: [`crate::core::instance::id`] is a per-process *nonce*, not a unique id, and a
/// persistent key must be the same triple the log file name carries
/// (`<YYYY-MM-DD>/fsmcp-<pid>-<instance>.log`) or a session row cannot name the log file it
/// describes. `tool_agg` needs no such correction: its `bucket` already scopes the key in time.
///
/// There is no `housekeeping` table - the retention lease is wave 1's marker file, which
/// [`crate::core::housekeeping`] owns for every kind of sweep.
///
/// Errors are counters only, never message text: a message would drag filesystem paths into a
/// database that lives for years. `cwd` is stored, because the file is per-user and already sits
/// under that user's own home directory.
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS tool_agg (
    bucket       INTEGER NOT NULL,          -- floor(unix_epoch / 600), UTC
    tool         TEXT    NOT NULL,
    instance_id  TEXT    NOT NULL,
    session_id   TEXT    NOT NULL,
    ok           INTEGER NOT NULL,
    err_flagged  INTEGER NOT NULL,          -- an Ok result carrying is_error = true
    err_params   INTEGER NOT NULL,          -- rmcp -32602: the caller got the schema wrong
    err_internal INTEGER NOT NULL,          -- rmcp -32603: the tool broke
    deferred     INTEGER NOT NULL,          -- InputRequired / Task: not a completion
    ns_total     INTEGER NOT NULL,
    ns_max       INTEGER NOT NULL,
    bytes_out    INTEGER NOT NULL,
    PRIMARY KEY (bucket, tool, instance_id, session_id)
) STRICT, WITHOUT ROWID;

-- "what did this one session do", which the bucket-first primary key cannot answer.
CREATE INDEX IF NOT EXISTS ix_agg_session ON tool_agg(session_id, bucket);

CREATE TABLE IF NOT EXISTS tool_daily (
    day          TEXT    NOT NULL,          -- YYYY-MM-DD, UTC
    tool         TEXT    NOT NULL,
    ok           INTEGER NOT NULL,
    err_flagged  INTEGER NOT NULL,
    err_params   INTEGER NOT NULL,
    err_internal INTEGER NOT NULL,
    deferred     INTEGER NOT NULL,
    ns_total     INTEGER NOT NULL,
    ns_max       INTEGER NOT NULL,
    bytes_out    INTEGER NOT NULL,
    PRIMARY KEY (day, tool)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS tool_catalog (
    fingerprint  TEXT    NOT NULL,          -- identifies the build whose tool list this is
    tool         TEXT    NOT NULL,
    PRIMARY KEY (fingerprint, tool)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS sessions (
    started_day    TEXT    NOT NULL,        -- YYYY-MM-DD, UTC: the log directory's name
    pid            INTEGER NOT NULL,
    instance_id    TEXT    NOT NULL,
    session_id     TEXT    NOT NULL,
    transport      TEXT,
    version        TEXT,
    features       TEXT,
    client_name    TEXT,
    client_version TEXT,
    cwd            TEXT,
    label          TEXT,
    started_at     INTEGER,
    last_seen      INTEGER,
    PRIMARY KEY (started_day, pid, instance_id, session_id)
) STRICT, WITHOUT ROWID;
"#;

/// The only statement that writes `tool_agg`, merging a delta into whatever is already there.
///
/// Read-free by construction: the conflict clause adds `excluded` to the stored value, so a
/// flush never issues a SELECT and never holds a read snapshot it would have to upgrade. Every
/// column accumulates by addition except `ns_max`, which takes the larger of the two - still a
/// scalar merge computed inside the statement, so the read-free property is intact.
///
/// A constant rather than a function because the flush task prepares it once and reuses the
/// prepared statement for every row of a delta.
pub const UPSERT_AGG: &str = r#"
INSERT INTO tool_agg (bucket, tool, instance_id, session_id,
                      ok, err_flagged, err_params, err_internal, deferred,
                      ns_total, ns_max, bytes_out)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
ON CONFLICT (bucket, tool, instance_id, session_id) DO UPDATE SET
    ok           = tool_agg.ok           + excluded.ok,
    err_flagged  = tool_agg.err_flagged  + excluded.err_flagged,
    err_params   = tool_agg.err_params   + excluded.err_params,
    err_internal = tool_agg.err_internal + excluded.err_internal,
    deferred     = tool_agg.deferred     + excluded.deferred,
    ns_total     = tool_agg.ns_total     + excluded.ns_total,
    ns_max       = max(tool_agg.ns_max,    excluded.ns_max),
    bytes_out    = tool_agg.bytes_out    + excluded.bytes_out
"#;

/// Open the statistics database for writing, creating and migrating it as needed.
///
/// The one door (invariant I7): the pragmas below, the schema and the version check are applied
/// here or nowhere. Blocking - call it inside `spawn_blocking`.
///
/// The pragmas, in the order they are applied and for the reason each is applied:
///
/// - `journal_mode = WAL` - persisted in the file header, so it is really set once and merely
///   re-confirmed afterwards. Without it every writer serialises on one global lock. If it
///   cannot be established (a network share, a sync-backed directory) the caller is told, not
///   quietly handed a slower database: the correct response is to disable statistics with the
///   reason recorded, not to fall back to `journal_mode = delete`.
/// - `synchronous = NORMAL` - per connection. Durable against a *process* crash, which is the
///   failure this subsystem actually meets, at one fsync fewer per commit. `memory_v2` keeps the
///   default `FULL` and should: losing a memory item to a power cut is a real loss, whereas
///   losing the last few seconds of counters is not.
/// - `busy_timeout` - per connection; see [`BUSY_TIMEOUT`].
/// - `journal_size_limit` - per connection; see [`JOURNAL_SIZE_LIMIT`].
///
/// Then `user_version` decides: equal proceeds, older migrates, newer is refused with an error
/// naming both versions.
pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        return Err(fail(
            ffi::SQLITE_CANTOPEN,
            format!(
                "the statistics database directory {} could not be created: {e}",
                parent.display()
            ),
        ));
    }

    let mut conn = Connection::open(path)?;

    // `PRAGMA journal_mode = ...` answers with the mode actually in force, which is the only way
    // to learn that the request did not take; a plain `pragma_update` would also fail on the
    // returned row.
    let mode: String = conn.pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(fail(
            ffi::SQLITE_CANTOPEN,
            format!(
                "the statistics database {} could not be put into WAL mode (SQLite reports \
                 journal_mode={mode}); refusing rather than serialising every writer on one \
                 global lock",
                path.display()
            ),
        ));
    }
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.pragma_update_and_check(None, "journal_size_limit", JOURNAL_SIZE_LIMIT, |r| {
        r.get::<_, i64>(0)
    })?;

    let found: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    match found.cmp(&SCHEMA_VERSION) {
        std::cmp::Ordering::Equal => {}
        std::cmp::Ordering::Less => migrate(&mut conn, found)?,
        std::cmp::Ordering::Greater => {
            return Err(fail(
                ffi::SQLITE_ERROR,
                format!(
                    "the statistics database {} is at schema version {found}, newer than the \
                     {SCHEMA_VERSION} this build understands; refusing to write, because its \
                     columns may mean something else",
                    path.display()
                ),
            ));
        }
    }

    Ok(conn)
}

/// Open the statistics database for reading only.
///
/// The read tools use this so that a query can never take the write lock, however long it runs.
/// `SQLITE_OPEN_READ_ONLY` also means no pragma here may write: `journal_mode` and `synchronous`
/// belong to [`open`], and a reader simply inherits the WAL mode recorded in the file header.
///
/// A database at a newer schema version is refused here too - reading columns whose meaning may
/// have changed produces a confident wrong answer, which is worse than no answer. Blocking.
pub fn open_read_only(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(BUSY_TIMEOUT)?;

    let found: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if found > SCHEMA_VERSION {
        return Err(fail(
            ffi::SQLITE_ERROR,
            format!(
                "the statistics database {} is at schema version {found}, newer than the \
                 {SCHEMA_VERSION} this build understands; refusing to read columns whose \
                 meaning may have changed",
                path.display()
            ),
        ));
    }
    Ok(conn)
}

/// Bring a database at version `from` up to [`SCHEMA_VERSION`].
///
/// One `IMMEDIATE` transaction, so two servers starting at the same moment cannot half-apply it
/// between them: the loser waits, then finds every `IF NOT EXISTS` already satisfied. The
/// version bump is inside the transaction because `user_version` lives in the database header
/// and is rolled back with everything else.
fn migrate(conn: &mut Connection, from: i32) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // Version 0 is "no schema at all" - a file SQLite has just created, or an empty one. There
    // is no shipped version between 0 and 1, so this is the only step that exists today; a later
    // version adds its own `if from < N { .. }` beneath this one.
    if from <= 0 {
        tx.execute_batch(SCHEMA)?;
    }
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()
}

/// Present a failure that SQLite did not itself report as a `rusqlite::Error`, so that [`open`]
/// has one error type and the message reaches the caller through `Display` unchanged.
fn fail(code: std::ffi::c_int, msg: String) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(ffi::Error::new(code), Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bind one delta row through the production statement. The tests drive [`UPSERT_AGG`]
    /// itself rather than a copy of it, so a change to the merge semantics is caught here.
    fn record_row(
        conn: &Connection,
        bucket: i64,
        tool: &str,
        instance_id: &str,
        session_id: &str,
        ok: i64,
    ) -> rusqlite::Result<usize> {
        conn.execute(
            UPSERT_AGG,
            rusqlite::params![
                bucket,
                tool,
                instance_id,
                session_id,
                ok,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ],
        )
    }

    fn total_ok(conn: &Connection, tool: &str) -> i64 {
        conn.query_row(
            "SELECT coalesce(sum(ok), 0) FROM tool_agg WHERE tool = ?1",
            [tool],
            |r| r.get(0),
        )
        .expect("sum ok")
    }

    fn rows(conn: &Connection) -> i64 {
        conn.query_row("SELECT count(*) FROM tool_agg", [], |r| r.get(0))
            .expect("count rows")
    }

    /// Two processes never target the same row: `instance_id` is in the primary key, so the only
    /// cross-process interaction left is the file write lock.
    #[test]
    fn upsert_accumulates_per_instance() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db = dir.path().join("stats.db");
        let a = open(&db).expect("open a");
        let b = open(&db).expect("open b");
        record_row(&a, 100, "read_text_file", "inst-a", "-", 3).expect("a writes");
        record_row(&b, 100, "read_text_file", "inst-b", "-", 5).expect("b writes");
        record_row(&a, 100, "read_text_file", "inst-a", "-", 2).expect("a writes again");
        assert_eq!(total_ok(&a, "read_text_file"), 10, "sums across instances");
        assert_eq!(rows(&a), 2, "one row per instance, not per write");
    }

    /// A database written by a NEWER build is not written into: its columns may mean something
    /// else.
    #[test]
    fn a_newer_schema_is_refused() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db = dir.path().join("stats.db");
        open(&db).expect("create");
        rusqlite::Connection::open(&db)
            .expect("raw")
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .expect("bump");
        let err = open(&db).expect_err("must refuse a newer schema");
        let msg = err.to_string();
        assert!(
            msg.contains("newer") && msg.contains(&(SCHEMA_VERSION + 1).to_string()),
            "{msg}"
        );
    }

    /// WAL is required: without it dozens of writers serialise on one global lock. If it cannot
    /// be established the caller is told, not silently given a slower database.
    #[test]
    fn wal_is_established_or_reported() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let conn = open(&dir.path().join("stats.db")).expect("open");
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .expect("journal_mode");
        assert_eq!(mode.to_lowercase(), "wal");
    }

    /// A reader takes no write lock and is refused a database it cannot interpret - the same
    /// judgement as [`open`], for the same reason.
    #[test]
    fn a_reader_sees_the_schema_and_refuses_a_newer_one() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db = dir.path().join("stats.db");
        open(&db).expect("create");
        let ro = open_read_only(&db).expect("open read-only");
        assert_eq!(rows(&ro), 0, "the schema is visible to a reader");
        assert!(
            ro.execute_batch("DELETE FROM tool_agg").is_err(),
            "a read-only connection must not be able to write"
        );
        drop(ro);

        rusqlite::Connection::open(&db)
            .expect("raw")
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .expect("bump");
        let msg = open_read_only(&db).expect_err("must refuse").to_string();
        assert!(msg.contains("newer"), "{msg}");
    }
}
