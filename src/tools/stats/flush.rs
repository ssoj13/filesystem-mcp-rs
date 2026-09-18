//! The flush task: drain the counters, write them in one transaction, take them back if it fails.
//!
//! [`super::collect::Collector`] accumulates on a path that cannot fail; this is where everything
//! fallible lives. A background task drains the map every `FS_MCP_STATS_FLUSH_SEC` and writes the
//! drained rows through [`super::db::UPSERT_AGG`].
//!
//! Three steps, each of them load-bearing:
//!
//! 1. **`mem::take` under the lock, then drop the lock before touching the database.**
//!    [`super::collect::Collector::take_delta`] does exactly that and nothing else, so tool calls
//!    arriving during a flush accumulate into a fresh map instead of queueing behind SQLite. The
//!    collector's lock is sub-microsecond and must stay that way: the server is cloned per HTTP
//!    connection, so calls really are concurrent and really do contend for it.
//! 2. **Every row of the delta in ONE `BEGIN IMMEDIATE` transaction.** `Immediate` is not
//!    decoration. A deferred transaction takes a read snapshot first, and upgrading that to a
//!    write lock returns `SQLITE_BUSY_SNAPSHOT` - which `busy_timeout` does **not** retry. It
//!    fails at once, under load, and reads in the log like a deadlock.
//! 3. **On error, merge the delta back into the live map by addition**
//!    ([`super::collect::Collector::merge_back`]). This is safe **only** because step 2 is a
//!    single transaction: a loop of autocommitted upserts would re-add every row that had already
//!    committed, and no test would show it, because reaching that state needs a failure part-way
//!    through a flush.
//!
//! On top of that a **heartbeat** writes `sessions.last_seen` unconditionally at most every
//! [`HEARTBEAT`], even when there is nothing to flush. Wave 1 learned this on the housekeeping
//! lease: a process that writes only when it has something to say is indistinguishable from a
//! dead one, and liveness here is `last_seen` measured against three heartbeats.
//!
//! [`flush_once`] holds every decision and no timer, so the tests drive it directly; [`spawn`] is
//! the thin part - a sleep, a `spawn_blocking`, and what to do with the delta afterwards.
//! Statistics observe and never alter behaviour: no failure here is propagated, none is a panic,
//! and none stops the loop.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, TransactionBehavior, params};
use tracing::{error, warn};

use super::collect::{Collector, Delta};
use super::db;

/// How often `sessions.last_seen` is written even with nothing else to say.
///
/// Liveness is derived from this column against three heartbeats, so the interval is the
/// resolution of "is that process still there": three minutes of silence means gone. A minute is
/// far longer than the default five-second flush, so on a busy server the heartbeat costs
/// nothing at all - it rides along inside a transaction that was happening anyway.
pub const HEARTBEAT: Duration = Duration::from_secs(60);

/// How far either side of the configured interval a flush may land, as a percentage.
///
/// One client starting dozens of servers starts them within milliseconds of each other, and with
/// a fixed interval those processes would then contend for the single write lock in lockstep
/// forever. Re-rolled on every tick rather than once per process, so two processes that happen to
/// draw the same first offset still drift apart.
const JITTER_PERCENT: u64 = 20;

/// The shortest interval [`jittered`] will return, whatever it is given.
///
/// `flush_secs()` already clamps a configured zero up to one second, so no operator can reach
/// this - but [`spawn`] is `pub`, and a caller inside this crate passing [`Duration::ZERO`] would
/// otherwise turn the loop into a busy loop that pins a core and takes the collector lock as fast
/// as it can. A public function should not depend on a validation two modules away for its own
/// safety. 100 ms is two orders of magnitude below the smallest interval anything can actually
/// configure, so it never changes a real flush; it only bounds a mistake to ten ticks a second.
const MIN_INTERVAL: Duration = Duration::from_millis(100);

/// Consecutive failures after which the log stops describing a hiccup and says statistics have
/// stopped.
///
/// About five minutes at the default five-second interval - long past anything a busy database or
/// a resuming laptop explains. Deliberately a power of two, so it *replaces* the `warn!` that
/// [`note`] would have emitted at that count rather than adding a second line beside it.
const ESCALATE_AFTER: u32 = 64;

/// Who is writing: the four columns that identify this process's rows.
///
/// The same values key `tool_agg` and `sessions`, so they are resolved once in `main.rs` and
/// carried here rather than read from the environment on every tick. `started_day`, `pid` and
/// `instance_id` are the triple [`crate::core::instance::id`] insists on - the same one the log
/// file name carries - so a session row can name the log file it describes.
#[derive(Debug, Clone)]
pub struct Identity {
    /// `YYYY-MM-DD`, UTC, of when this process started: the name of its log directory.
    pub started_day: String,
    /// This process's pid. Never identity on its own; pids are reused.
    pub pid: i64,
    /// This process's nonce from [`crate::core::instance::id`].
    pub instance_id: String,
    /// The MCP session this process's calls are attributed to.
    pub session_id: String,
}

/// The heartbeat, and the only statement in this module that writes `sessions`.
///
/// An upsert rather than an `UPDATE`, so that liveness does not depend on some earlier startup
/// write having succeeded: if the session row is missing - because writing it failed, and that
/// failure is logged and swallowed - the heartbeat creates one carrying the identity and nothing
/// else. The descriptive columns are deliberately left alone by the conflict clause, so a
/// heartbeat can never overwrite what the startup row said with the nothing this statement knows.
const TOUCH_SESSION: &str = r#"
INSERT INTO sessions (started_day, pid, instance_id, session_id, last_seen)
VALUES (?1, ?2, ?3, ?4, ?5)
ON CONFLICT (started_day, pid, instance_id, session_id) DO UPDATE SET
    last_seen = excluded.last_seen
"#;

/// Write one drained delta and the heartbeat, in one `BEGIN IMMEDIATE` transaction.
///
/// The testable core: no timer, no spawning, no clock of its own - `now` is given. Returns
/// `Err` without having written anything, because every statement below is inside the one
/// transaction and any failure rolls it back (including a failing `COMMIT`, which rusqlite's
/// `Transaction` rolls back as it drops). That all-or-nothing property is precisely what makes
/// [`Collector::merge_back`] safe for the caller to apply on the error path.
///
/// `delta` is borrowed rather than consumed, so the caller still owns the rows it may have to
/// hand back; the caller is [`spawn`]'s loop.
///
/// Blocking `rusqlite` - call it from `spawn_blocking`, never on the async runtime.
pub(crate) fn flush_once(
    conn: &mut Connection,
    id: &Identity,
    delta: &Delta,
    now: SystemTime,
) -> rusqlite::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    {
        // Prepared once per flush and cached on the connection, so a delta of a few hundred rows
        // costs one parse rather than one per row.
        let mut upsert = tx.prepare_cached(db::UPSERT_AGG)?;
        for (key, counts) in delta {
            upsert.execute(params![
                key.bucket,
                &*key.tool,
                &id.instance_id,
                &id.session_id,
                as_i64(counts.ok),
                as_i64(counts.err_flagged),
                as_i64(counts.err_params),
                as_i64(counts.err_internal),
                as_i64(counts.deferred),
                as_i64(counts.ns_total),
                as_i64(counts.ns_max),
                as_i64(counts.content_bytes),
            ])?;
        }
    }
    tx.execute(
        TOUCH_SESSION,
        params![
            &id.started_day,
            id.pid,
            &id.instance_id,
            &id.session_id,
            unix_secs(now),
        ],
    )?;
    tx.commit()
}

/// Start the flush loop for this process. Returns immediately; the loop runs until the process
/// ends.
///
/// Called once from `main.rs` after the transport is chosen and only when statistics are on.
///
/// The shape is a tokio task that sleeps and a `spawn_blocking` that writes, rather than one
/// blocking loop: `rusqlite` may not run on the async runtime, and an endless *blocking* task
/// would also outlive the runtime it belongs to - tokio waits for blocking tasks as it shuts
/// down, so the process would hang on exit instead of stopping. The async task is dropped with
/// the runtime, and the only thing that can still be in flight is one short transaction.
///
/// The connection is opened on the first tick that has something to write, not here: an operator
/// whose database is unusable should not pay for it before the first flush, and reopening is how
/// the loop recovers if opening ever fails.
pub fn spawn(collector: Arc<Collector>, db_path: PathBuf, id: Identity, every: Duration) {
    tokio::spawn(async move {
        // Held across ticks so that the pragmas, the schema gate and the prepared-statement cache
        // are paid for once rather than every few seconds.
        let mut conn: Option<Connection> = None;
        let mut last_beat: Option<SystemTime> = None;
        let mut failures: u32 = 0;

        loop {
            tokio::time::sleep(jittered(every)).await;

            let now = SystemTime::now();
            let delta = collector.take_delta();
            if delta.is_empty() && !beat_due(last_beat, now) {
                continue;
            }

            let path = db_path.clone();
            let ident = id.clone();
            let taken = conn.take();
            // The delta goes into the blocking closure and comes back out of it, because the
            // async side has to hand it to `merge_back` if the write failed.
            let joined = tokio::task::spawn_blocking(move || {
                let mut open = match taken {
                    Some(open) => open,
                    None => match db::open(&path) {
                        Ok(open) => open,
                        Err(e) => return (None, delta, Err(e)),
                    },
                };
                let outcome = flush_once(&mut open, &ident, &delta, now);
                (Some(open), delta, outcome)
            })
            .await;

            match joined {
                Ok((open, _written, Ok(()))) => {
                    conn = open;
                    last_beat = Some(now);
                    failures = 0;
                }
                Ok((open, delta, Err(e))) => {
                    // Kept rather than discarded: a busy or momentarily locked database leaves a
                    // perfectly usable connection, and `open` is already `None` in the one case
                    // where opening itself failed, so the next tick reopens exactly then.
                    conn = open;
                    collector.merge_back(delta);
                    note(&collector, &mut failures, &e.to_string());
                }
                Err(join) => {
                    // The blocking task panicked or was cancelled: the delta went with it and
                    // those counters are lost. Rare and never silent - it is the one path on
                    // which a flush failure costs data rather than postponing it.
                    note(
                        &collector,
                        &mut failures,
                        &format!("the flush task did not finish ({join}); its counters are lost"),
                    );
                }
            }
        }
    });
}

/// Record a failed flush and report it without flooding the log.
///
/// Counted in [`super::collect::Health`] every time, because that is what the health tool reads
/// and an operator must be able to see that flushing is failing at all. Logged on the 1st, 2nd,
/// 4th, 8th, ... consecutive failure: a database that is unusable for a day would otherwise write
/// seventeen thousand identical lines into the log directory that another sweep then has to
/// reclaim.
///
/// At [`ESCALATE_AFTER`] the level rises to `error!` **once**, because by then this is no longer a
/// hiccup and the log should say so itself rather than wait for someone to think of asking the
/// health tool - with per-process file logging on by default, that line lands somewhere a person
/// will find it. After that the loop goes quiet until it succeeds again and `failures` is reset
/// to zero by the caller; the error line was the whole statement, and repeating it in different
/// words every few minutes would only bury it.
///
/// Going quiet past [`ESCALATE_AFTER`] also settles what the saturating counter would otherwise
/// do: nothing reads its exact value up there, so it cannot matter that a count stuck at
/// `u32::MAX` is not a power of two and would have silenced the `warn!` arm forever. A saturating
/// counter feeding a predicate that only fires on exact values is a shape worth not leaving
/// behind, even six centuries out of reach.
fn note(collector: &Collector, failures: &mut u32, reason: &str) {
    collector.note_flush_failure();
    *failures = failures.saturating_add(1);
    if *failures == ESCALATE_AFTER {
        error!(
            "Statistics: flush has failed {failures} times in a row - counters are no longer \
             being written and are accumulating in memory: {reason}"
        );
    } else if *failures < ESCALATE_AFTER && failures.is_power_of_two() {
        warn!("Statistics: flush failed ({failures} in a row, counters kept in memory): {reason}");
    }
}

/// Is a heartbeat owed? Yes if none has been written, or if [`HEARTBEAT`] has passed.
///
/// A clock that moved backwards makes `duration_since` fail, and that counts as due: writing one
/// heartbeat too many is nothing, whereas treating it as not-due would let an operator's clock
/// adjustment make a live process look dead.
fn beat_due(last_beat: Option<SystemTime>, now: SystemTime) -> bool {
    match last_beat {
        None => true,
        Some(then) => now
            .duration_since(then)
            .map(|since| since >= HEARTBEAT)
            .unwrap_or(true),
    }
}

/// `every`, moved by up to [`JITTER_PERCENT`] in either direction, and never below
/// [`MIN_INTERVAL`].
///
/// Randomness comes from a v4 uuid rather than a new dependency: this needs to spread processes
/// apart, not to resist anyone, and `uuid` is already how [`crate::core::instance::id`] draws its
/// nonce.
fn jittered(every: Duration) -> Duration {
    let base = every.as_millis().min(u128::from(u64::MAX)) as u64;
    let fifth = base / (100 / JITTER_PERCENT);
    let span = fifth.saturating_mul(2);
    let offset = if span == 0 {
        0
    } else {
        (uuid::Uuid::new_v4().as_u64_pair().0) % (span + 1)
    };
    Duration::from_millis(base.saturating_sub(fifth).saturating_add(offset)).max(MIN_INTERVAL)
}

/// Whole seconds since the epoch, for `sessions.last_seen`.
///
/// A clock before 1970 cannot describe a process that is running now, but the clock is the
/// operator's, so this floors to zero rather than failing a flush over it.
fn unix_secs(now: SystemTime) -> i64 {
    now.duration_since(UNIX_EPOCH)
        .map(|since| i64::try_from(since.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// A counter as SQLite stores it.
///
/// The collector counts in `u64` and every column is a signed `INTEGER`. The difference is
/// unreachable - `ns_total` would need ~292 years of accumulated tool time inside one ten-minute
/// bucket - but saturating keeps that a local fact instead of a `try_from(..).expect(..)` on a
/// path whose whole purpose is that it cannot take the server down.
fn as_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::stats::collect::Counts;
    use crate::tools::stats::outcome::Outcome;

    fn identity() -> Identity {
        Identity {
            started_day: "2026-09-18".to_string(),
            pid: 4242,
            instance_id: "0123456789abcdef".to_string(),
            session_id: "sess-1".to_string(),
        }
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn collector() -> Collector {
        Collector::new(["read_text_file", "grep_files"])
    }

    /// Everything stored for one tool, summed across buckets.
    fn stored(conn: &Connection, tool: &str) -> Counts {
        conn.query_row(
            "SELECT coalesce(sum(ok), 0), coalesce(sum(err_flagged), 0), \
             coalesce(sum(err_params), 0), coalesce(sum(err_internal), 0), \
             coalesce(sum(deferred), 0), coalesce(sum(ns_total), 0), \
             coalesce(max(ns_max), 0), coalesce(sum(content_bytes), 0) \
             FROM tool_agg WHERE tool = ?1",
            [tool],
            |r| {
                Ok(Counts {
                    ok: r.get::<_, i64>(0)? as u64,
                    err_flagged: r.get::<_, i64>(1)? as u64,
                    err_params: r.get::<_, i64>(2)? as u64,
                    err_internal: r.get::<_, i64>(3)? as u64,
                    deferred: r.get::<_, i64>(4)? as u64,
                    ns_total: r.get::<_, i64>(5)? as u64,
                    ns_max: r.get::<_, i64>(6)? as u64,
                    content_bytes: r.get::<_, i64>(7)? as u64,
                })
            },
        )
        .expect("aggregate")
    }

    fn agg_rows(conn: &Connection) -> i64 {
        conn.query_row("SELECT count(*) FROM tool_agg", [], |r| r.get(0))
            .expect("count")
    }

    /// `last_seen`, or `None` when no heartbeat has been written at all.
    fn last_seen(conn: &Connection) -> Option<i64> {
        use rusqlite::OptionalExtension;
        conn.query_row("SELECT last_seen FROM sessions", [], |r| {
            r.get::<_, Option<i64>>(0)
        })
        .optional()
        .expect("sessions")
        .flatten()
    }

    /// A drained delta reaches the database once, and the next flush adds nothing.
    ///
    /// The property the whole drain-write-maybe-hand-back protocol rests on. Flushing the *same*
    /// delta object twice would genuinely double the stored counts, because every column of
    /// [`db::UPSERT_AGG`] merges by addition - which is why a flush that succeeded must never
    /// hand its rows back, and why the second flush here goes through a fresh `take_delta` the
    /// way the loop does.
    #[test]
    fn a_flushed_delta_is_not_written_a_second_time() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("stats.db");
        let mut conn = db::open(&path).expect("open");
        let c = collector();
        let id = identity();

        c.record("read_text_file", Outcome::Ok, 500, 7, at(6_000));
        c.record("read_text_file", Outcome::ErrFlagged, 900, 3, at(6_000));

        flush_once(&mut conn, &id, &c.take_delta(), at(6_001)).expect("first flush");
        let after_one = stored(&conn, "read_text_file");
        assert_eq!(
            after_one,
            Counts {
                ok: 1,
                err_flagged: 1,
                ns_total: 1_400,
                ns_max: 900,
                content_bytes: 10,
                ..Counts::default()
            }
        );

        flush_once(&mut conn, &id, &c.take_delta(), at(6_002)).expect("second flush");
        assert_eq!(
            stored(&conn, "read_text_file"),
            after_one,
            "the map was drained, so there is nothing left to add"
        );
        assert_eq!(agg_rows(&conn), 1, "one bucket, one tool, one row");
    }

    /// A failure **after** the upserts have run leaves nothing behind, so the retry does not
    /// double the stored counts.
    ///
    /// This is the test that pins the single transaction, and nothing else does. Every other
    /// failing case in this module fails on the *first* statement - a read-only connection cannot
    /// even begin - and with autocommitted upserts that first statement writes nothing either, so
    /// those tests cannot tell a transaction from no transaction at all. Replace the
    /// `BEGIN IMMEDIATE` in [`flush_once`] with a loop of autocommitted upserts and they all stay
    /// green; only this one turns red.
    ///
    /// The shape is forced by what it has to reproduce: the failure must come **last**, once
    /// every row is already written, which is what a `BEFORE INSERT` trigger on `sessions` buys -
    /// the heartbeat is the final statement of the flush. Without the transaction, those rows are
    /// durable, `merge_back` hands them back in full, and the next flush adds them a second time.
    /// `tool_agg` is then permanently inflated with no error anywhere to explain it - the one
    /// failure mode of this design that is silent, which is exactly why it gets a test of its own.
    ///
    /// Two tools rather than one, so that "rows 1..k already committed" is what is being measured
    /// and not just a single lucky statement.
    #[test]
    fn a_failure_after_the_upserts_does_not_double_count() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut conn = db::open(&dir.path().join("stats.db")).expect("open");
        let c = collector();
        let id = identity();

        c.record("read_text_file", Outcome::Ok, 500, 7, at(6_000));
        c.record("grep_files", Outcome::Ok, 300, 5, at(6_000));

        // Fails the heartbeat, which `flush_once` issues after every upsert - so the abort lands
        // with the whole delta already written, which is the only state that can double-count.
        conn.execute_batch(
            "CREATE TRIGGER boom BEFORE INSERT ON sessions BEGIN SELECT raise(ABORT, 'no'); END",
        )
        .expect("arm the trigger");

        let delta = c.take_delta();
        flush_once(&mut conn, &id, &delta, at(6_001))
            .expect_err("the heartbeat must abort the flush");
        c.merge_back(delta);

        conn.execute_batch("DROP TRIGGER boom").expect("disarm");
        flush_once(&mut conn, &id, &c.take_delta(), at(6_002)).expect("the retry");

        assert_eq!(
            stored(&conn, "read_text_file").ok,
            1,
            "the failed flush wrote nothing, so the retry must store exactly one call"
        );
        assert_eq!(
            stored(&conn, "grep_files").ok,
            1,
            "and the same for a row that was written before the one that failed"
        );
        assert_eq!(
            stored(&conn, "read_text_file").content_bytes,
            7,
            "every counter of a rolled-back row, not only the call count"
        );
    }

    /// A flush that fails writes nothing and leaves the caller holding every counter.
    ///
    /// A read-only connection is the cheapest honest failure: the transaction cannot take the
    /// write lock. It fails on the *first* statement, so - unlike
    /// [`a_failure_after_the_upserts_does_not_double_count`] - it says nothing about whether the
    /// write was one transaction. What is asserted is both halves of the contract - the database is untouched,
    /// and the delta handed back through `merge_back` restores the collector exactly.
    #[test]
    fn a_failing_flush_writes_nothing_and_the_delta_survives() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let path = dir.path().join("stats.db");
        drop(db::open(&path).expect("create"));

        let c = collector();
        c.record("grep_files", Outcome::Ok, 11, 13, at(6_000));
        c.record("grep_files", Outcome::ErrInternal, 17, 0, at(6_000));
        let delta = c.take_delta();
        let before = delta.clone();

        let mut ro = db::open_read_only(&path).expect("open read-only");
        let err = flush_once(&mut ro, &identity(), &delta, at(6_001))
            .expect_err("a read-only connection cannot be written");
        assert!(!err.to_string().is_empty());
        drop(ro);

        let check = db::open_read_only(&path).expect("reopen");
        assert_eq!(agg_rows(&check), 0, "nothing was written");
        assert_eq!(last_seen(&check), None, "not even the heartbeat");

        c.merge_back(delta);
        assert_eq!(
            c.take_delta(),
            before,
            "every counter came back for the next flush to try again"
        );
    }

    /// The heartbeat is written even with nothing to flush, and it moves on every flush.
    ///
    /// A process that writes only when it has something to say is indistinguishable from a dead
    /// one, and liveness is `last_seen` against three heartbeats.
    #[test]
    fn the_heartbeat_is_written_with_an_empty_delta() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut conn = db::open(&dir.path().join("stats.db")).expect("open");
        let id = identity();

        flush_once(&mut conn, &id, &Delta::new(), at(1_000)).expect("first heartbeat");
        assert_eq!(last_seen(&conn), Some(1_000));
        assert_eq!(agg_rows(&conn), 0, "an empty delta writes no counters");

        flush_once(&mut conn, &id, &Delta::new(), at(1_060)).expect("second heartbeat");
        assert_eq!(
            last_seen(&conn),
            Some(1_060),
            "it moves, and does not duplicate"
        );
        assert_eq!(
            conn.query_row("SELECT count(*) FROM sessions", [], |r| r.get::<_, i64>(0))
                .expect("count"),
            1,
            "one row per identity, however many heartbeats"
        );
    }

    /// The heartbeat is owed immediately, then only once per [`HEARTBEAT`] - and again at once if
    /// the operator's clock moves backwards.
    #[test]
    fn a_heartbeat_is_owed_on_the_minute_and_after_a_clock_jump() {
        assert!(beat_due(None, at(1_000)), "nothing written yet");
        assert!(!beat_due(Some(at(1_000)), at(1_059)));
        assert!(beat_due(Some(at(1_000)), at(1_060)));
        assert!(
            beat_due(Some(at(1_000)), at(900)),
            "a clock that moved back must not make a live process look dead"
        );
    }

    /// Jitter stays inside the advertised band and really does vary, which is the whole point:
    /// dozens of servers started by one client must not flush in lockstep.
    #[test]
    fn the_interval_is_jittered_within_twenty_percent() {
        let every = Duration::from_secs(5);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let d = jittered(every);
            assert!(
                d >= Duration::from_millis(4_000) && d <= Duration::from_millis(6_000),
                "{d:?} is outside 5s +/- 20%"
            );
            seen.insert(d);
        }
        assert!(seen.len() > 1, "a constant interval is not jitter");
    }

    /// An interval of zero cannot make the loop spin.
    ///
    /// Unreachable through configuration - `flush_secs()` clamps zero up to one second - but
    /// [`spawn`] is `pub`, and a function should not depend on a validation two modules away to
    /// stay safe. Without the floor this returns `Duration::ZERO`, the loop's `sleep` returns
    /// immediately, and it pins a core while taking the collector lock as fast as it can.
    #[test]
    fn a_zero_interval_is_floored_rather_than_spinning() {
        assert_eq!(jittered(Duration::ZERO), MIN_INTERVAL);
        assert!(jittered(Duration::from_millis(1)) >= MIN_INTERVAL);
    }

    /// Every failure is counted, and the escalation replaces a warning rather than joining it.
    ///
    /// The log level is not observable from here, so what is pinned is the arithmetic the levels
    /// are chosen by: the count rises on every call, [`ESCALATE_AFTER`] is a power of two - so the
    /// `error!` takes the place of the `warn!` that count would have produced - and `Health` keeps
    /// counting past it, including the failures the loop deliberately stops logging.
    #[test]
    fn every_failure_is_counted_and_escalation_replaces_a_warning() {
        assert!(
            ESCALATE_AFTER.is_power_of_two(),
            "otherwise the escalation prints beside a warning instead of replacing it"
        );

        let c = collector();
        let mut failures = 0u32;
        let total = ESCALATE_AFTER + 4;
        for expected in 1..=total {
            note(&c, &mut failures, "a reason");
            assert_eq!(failures, expected, "the count rises on every failure");
        }
        assert_eq!(
            c.health().flush_failures,
            u64::from(total),
            "health counts them all, including the ones past escalation that are never logged"
        );
    }
}
