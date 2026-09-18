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
//! 2. **`instance_id` is part of the primary key of every table two processes write
//!    concurrently** - which is `tool_agg`, the one the flush path touches. Two concurrent
//!    flushes can then never target the same row, so cross-process double counting is
//!    structurally impossible and the only interaction left between writers is the file write
//!    lock.
//!
//!    `tool_daily` and `tool_catalog` deliberately do *not* carry it, and the difference is not
//!    cosmetic: their keys are shared by every process, so additive merges into them are safe
//!    **only** while something outside the database guarantees a single writer. For `tool_daily`
//!    that guarantee is the housekeeping lease (see [`SCHEMA`]); nothing may compact into it
//!    without holding one.
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
/// `tool_daily`'s key is `(day, tool)` with no `instance_id`, which makes it the one table whose
/// rows every process shares. Its counters are additive like every other, so two sweeps
/// compacting the same day would double it - permanently, because compaction deletes the detail
/// rows it read. **It is safe only because the housekeeping lease serialises the writer**, and
/// nothing may write it without holding one. `tool_catalog` shares its key too but stores no
/// counters: its rows are idempotent facts about a build, so a repeated insert is a no-op.
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
/// - `busy_timeout` - **first**, and the order is load-bearing. rusqlite installs no busy
///   handler by default, so anything before this line runs with zero retry. The very first
///   `journal_mode = WAL` on a fresh state root *converts* the file, which needs an exclusive
///   lock; with dozens of servers launching together everyone arriving mid-conversion would take
///   an immediate `SQLITE_BUSY` and lose statistics for the whole process - reported as "could
///   not be put into WAL mode", which names the wrong cause. It bites once per machine and looks
///   exactly like flakiness. See [`BUSY_TIMEOUT`].
/// - `journal_mode = WAL` - persisted in the file header, so it is really set once and merely
///   re-confirmed afterwards. Without it every writer serialises on one global lock. If it
///   cannot be established (a network share, a sync-backed directory) the caller is told, not
///   quietly handed a slower database: the correct response is to disable statistics with the
///   reason recorded, not to fall back to `journal_mode = delete`.
/// - `synchronous = NORMAL` - per connection. Durable against a *process* crash, which is the
///   failure this subsystem actually meets, at one fsync fewer per commit. `memory_v2` keeps the
///   default `FULL` and should: losing a memory item to a power cut is a real loss, whereas
///   losing the last few seconds of counters is not.
/// - `journal_size_limit` - per connection; see [`JOURNAL_SIZE_LIMIT`].
///
/// Then [`gate`] decides on `user_version`: equal proceeds, older migrates, newer is refused with
/// an error naming both versions.
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

    // Before anything that can contend - see the rustdoc above; this line is not where it is for
    // tidiness.
    conn.busy_timeout(BUSY_TIMEOUT)?;

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
    conn.pragma_update_and_check(None, "journal_size_limit", JOURNAL_SIZE_LIMIT, |r| {
        r.get::<_, i64>(0)
    })?;

    gate(&mut conn, path)?;
    Ok(conn)
}

/// Open the statistics database for reading only.
///
/// The read tools use this so that a query can never take the write lock, however long it runs.
/// Only `busy_timeout` is set here, and not because the flags forbid the rest: `journal_mode` is
/// already recorded in the file header and is simply inherited, `synchronous` governs how a
/// *write* is flushed and so means nothing on a connection that never writes, and
/// `journal_size_limit` is applied by whoever checkpoints the `-wal` - which a reader never does,
/// so setting it here would be a no-op rather than a safeguard.
///
/// A database at a newer schema version is refused here too - reading columns whose meaning may
/// have changed produces a confident wrong answer, which is worse than no answer. Blocking.
///
/// **A failure to open is not necessarily a broken subsystem.** A read-only connection to a WAL
/// database still has to create the `-shm` file, so a directory with no `stats.db` yet (or one
/// nothing has written) comes back as `SQLITE_CANTOPEN` or `SQLITE_READONLY_CANTINIT`. Both mean
/// "there are no statistics yet", and a caller must report that as an empty result, never as a
/// fault.
pub fn open_read_only(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    // SQLite's own message names no file ("unable to open database file"), which leaves an
    // operator with nothing to check. The extended code is carried through unchanged so a caller
    // can still distinguish "not there yet" from a real fault.
    .map_err(|e| match e {
        rusqlite::Error::SqliteFailure(inner, detail) => fail(
            inner.extended_code,
            format!(
                "the statistics database {} could not be opened for reading: {}",
                path.display(),
                detail.unwrap_or_else(|| inner.to_string())
            ),
        ),
        other => other,
    })?;
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

/// Read `user_version` and act on it, both **inside one `IMMEDIATE` transaction**.
///
/// Reading the version outside the transaction that acts on it would leave the decision and its
/// consequence separated by a window: a process could read `1`, satisfy the newer-refuses check,
/// and then be writing while another process migrated the file to `2` underneath it. Nothing
/// exploits that today, because `SCHEMA_VERSION` is `1` and there is no migration to race with -
/// but it is the shape that makes such a bug possible, and closing it is one line now versus a
/// thing to reason about later.
///
/// `IMMEDIATE` also means two servers starting at the same instant cannot half-apply the schema
/// between them: the loser waits out [`BUSY_TIMEOUT`], then finds every `IF NOT EXISTS` already
/// satisfied. The version bump is inside the transaction too, because `user_version` lives in
/// the database header and is rolled back with everything else.
fn gate(conn: &mut Connection, path: &Path) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let found: i32 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    match found.cmp(&SCHEMA_VERSION) {
        std::cmp::Ordering::Equal => {}
        std::cmp::Ordering::Less => {
            // Version 0 is "no schema at all" - a file SQLite has just created, or an empty one.
            // There is no shipped version between 0 and 1, so this is the only step that exists
            // today; a later version adds its own `if found < N { .. }` beneath this one.
            if found <= 0 {
                tx.execute_batch(SCHEMA)?;
            }
            tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        // Dropping `tx` unread rolls the (empty) transaction back and releases the lock.
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

    /// The eight counters of one delta row, in the order [`UPSERT_AGG`] binds them:
    /// `ok, err_flagged, err_params, err_internal, deferred, ns_total, ns_max, bytes_out`.
    ///
    /// A fixed-width array rather than eight arguments so that a test can state the whole
    /// expected row in one literal and compare it in one assertion - which is what makes a
    /// swapped pair of merge lines visible.
    type Counts = [i64; 8];

    /// Bind one delta row through the production statement. The tests drive [`UPSERT_AGG`]
    /// itself rather than a copy of it, so a change to the merge semantics is caught here.
    fn record_row(
        conn: &Connection,
        bucket: i64,
        tool: &str,
        instance_id: &str,
        session_id: &str,
        c: Counts,
    ) -> rusqlite::Result<usize> {
        conn.execute(
            UPSERT_AGG,
            rusqlite::params![
                bucket,
                tool,
                instance_id,
                session_id,
                c[0],
                c[1],
                c[2],
                c[3],
                c[4],
                c[5],
                c[6],
                c[7]
            ],
        )
    }

    /// Every counter of one row, so an assertion can cover all eight rather than the one that
    /// happened to be non-zero.
    fn row_of(conn: &Connection, tool: &str, instance_id: &str) -> Counts {
        conn.query_row(
            "SELECT ok, err_flagged, err_params, err_internal, deferred, ns_total, ns_max, \
             bytes_out FROM tool_agg WHERE tool = ?1 AND instance_id = ?2",
            [tool, instance_id],
            |r| {
                Ok([
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ])
            },
        )
        .expect("row")
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
    /// cross-process interaction left is the file write lock. And each of the eight counters
    /// merges into *its own* column.
    ///
    /// Every value here is distinct, and distinct again between the two writes, which is the
    /// point: with zeroes in seven columns the seven identically-shaped `x = x + excluded.x`
    /// lines of [`UPSERT_AGG`] are interchangeable, and swapping two of them - or turning one
    /// into a plain `= excluded.x` - would leave the assertions green. `ns_max` is deliberately
    /// *smaller* on the second write, so the one merge that is a `max(..)` rather than a sum is
    /// pinned in the direction a careless rewrite gets wrong.
    #[test]
    fn upsert_accumulates_per_instance() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db = dir.path().join("stats.db");
        let a = open(&db).expect("open a");
        let b = open(&db).expect("open b");

        let tool = "read_text_file";
        record_row(&a, 100, tool, "inst-a", "-", [3, 5, 7, 11, 13, 17, 900, 23]).expect("a writes");
        record_row(
            &b,
            100,
            tool,
            "inst-b",
            "-",
            [100, 200, 300, 400, 500, 600, 7000, 800],
        )
        .expect("b writes");
        record_row(
            &a,
            100,
            tool,
            "inst-a",
            "-",
            [2, 40, 60, 80, 120, 160, 90, 240],
        )
        .expect("a writes again");

        assert_eq!(
            row_of(&a, tool, "inst-a"),
            [5, 45, 67, 91, 133, 177, 900, 263],
            "each counter accumulates into its own column, and ns_max keeps the larger"
        );
        assert_eq!(
            row_of(&a, tool, "inst-b"),
            [100, 200, 300, 400, 500, 600, 7000, 800],
            "one process's writes never reach another's row"
        );
        assert_eq!(total_ok(&a, tool), 105, "sums across instances");
        assert_eq!(rows(&a), 2, "one row per instance, not per write");
    }

    /// `ns_max` is the only counter that is not a sum, and both directions matter: a later call
    /// that was slower must raise it, one that was faster must not lower it. Tested apart from
    /// the accumulation above so that neither direction can be lost in a rewrite of that test.
    #[test]
    fn ns_max_rises_but_never_falls() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let conn = open(&dir.path().join("stats.db")).expect("open");
        let ns_max = |c: &Connection| row_of(c, "grep_files", "inst")[6];

        record_row(
            &conn,
            7,
            "grep_files",
            "inst",
            "-",
            [1, 0, 0, 0, 0, 500, 500, 0],
        )
        .expect("first");
        assert_eq!(ns_max(&conn), 500);

        record_row(
            &conn,
            7,
            "grep_files",
            "inst",
            "-",
            [1, 0, 0, 0, 0, 10, 10, 0],
        )
        .expect("a faster call");
        assert_eq!(
            ns_max(&conn),
            500,
            "a faster call must not lower the maximum"
        );

        record_row(
            &conn,
            7,
            "grep_files",
            "inst",
            "-",
            [1, 0, 0, 0, 0, 900, 900, 0],
        )
        .expect("a slower call");
        assert_eq!(ns_max(&conn), 900, "a slower call must raise it");

        assert_eq!(
            row_of(&conn, "grep_files", "inst")[5],
            1410,
            "ns_total still sums while ns_max does not"
        );
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
