use std::collections::BTreeMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::thread::{self};
use std::time::Duration;

use anyhow::Result;
use rusqlite::{Connection, params};

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
fn recovery_cleans_large_abandoned_scan_without_dropping_published_entries() {
    let temp = tempdir().unwrap();
    let mut conn = connect(&temp.path().join("everything.db")).unwrap();
    init_schema(&mut conn).unwrap();
    let root_id = ensure_root(&conn, temp.path()).unwrap();
    conn.execute(
        "UPDATE roots SET active_generation=7,desired_seq=2,completed_seq=1,state='building' WHERE id=?1",
        [root_id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO scan_attempts(root_id,claimed_seq,state,started) VALUES(?1,2,'running',0)",
        [root_id],
    )
    .unwrap();
    let attempt_id = conn.last_insert_rowid();
    let tx = conn.transaction().unwrap();
    for index in 0..1_101 {
        let path = format!("stale-{index:04}.txt");
        tx.execute(
            "INSERT INTO entries(root_id,generation,path,name,kind,size) VALUES(?1,?2,?3,?3,'file',0)",
            params![root_id, attempt_id, path],
        )
        .unwrap();
        let path = format!("stage-{index:04}.txt");
        tx.execute(
            "INSERT INTO staged_entries(attempt_id,path,name,kind,size) VALUES(?1,?2,?2,'file',0)",
            params![attempt_id, path],
        )
        .unwrap();
    }
    tx.execute(
        "INSERT INTO entries(root_id,generation,path,name,kind,size) VALUES(?1,7,'kept.txt','kept.txt','file',0)",
        [root_id],
    )
    .unwrap();
    tx.commit().unwrap();

    recover(&conn).unwrap();
    let (state, desired, completed): (String, i64, i64) = conn
        .query_row(
            "SELECT state,desired_seq,completed_seq FROM roots WHERE id=?1",
            [root_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((state.as_str(), desired, completed), ("pending", 2, 1));
    let entries: Vec<String> = conn
        .prepare("SELECT path FROM entries ORDER BY path")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(entries, ["kept.txt"]);
    let staged: i64 = conn
        .query_row("SELECT count(*) FROM staged_entries", [], |row| row.get(0))
        .unwrap();
    assert_eq!(staged, 0);
    let attempt_state: String = conn
        .query_row(
            "SELECT state FROM scan_attempts WHERE id=?1",
            [attempt_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(attempt_state, "abandoned");
}

/// A never-published root with a claimed attempt and `paths` already written under its
/// generation: the shape an initial scan has when its process dies mid-way.
fn interrupted_initial_scan(conn: &mut Connection, root: &Path, paths: &[&str]) -> Work {
    let root = canonical_root(root).unwrap();
    let root_id = ensure_root(conn, &root).unwrap();
    conn.execute(
        "UPDATE roots SET desired_seq=1,state='pending',debounce_until_ms=0 WHERE id=?1",
        [root_id],
    )
    .unwrap();
    let work = claim_next(conn).unwrap().unwrap();
    for path in paths {
        let full = root.join(path);
        conn.execute(
            "INSERT INTO entries(root_id,generation,path,name,kind,size,modified)
             VALUES(?1,?2,?3,?4,'file',999,1)",
            params![
                work.root_id,
                work.generation,
                path_text(&full).unwrap(),
                path
            ],
        )
        .unwrap();
    }
    work
}

fn entry_count(conn: &Connection) -> i64 {
    conn.query_row("SELECT count(*) FROM entries", [], |row| row.get(0))
        .unwrap()
}

fn resume_generation(conn: &Connection, root_id: i64) -> i64 {
    conn.query_row(
        "SELECT resume_generation FROM roots WHERE id=?1",
        [root_id],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn recovery_keeps_an_interrupted_initial_scan_so_it_can_resume() {
    let temp = tempdir().unwrap();
    let mut conn = connect(&temp.path().join("everything.db")).unwrap();
    init_schema(&mut conn).unwrap();
    let work = interrupted_initial_scan(&mut conn, temp.path(), &["a.txt", "b.txt"]);

    recover(&conn).unwrap();

    assert_eq!(
        entry_count(&conn),
        2,
        "recovery threw the partial scan away"
    );
    assert_eq!(resume_generation(&conn, work.root_id), work.generation);
    let attempt_state: String = conn
        .query_row(
            "SELECT state FROM scan_attempts WHERE id=?1",
            [work.attempt_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(attempt_state, "interrupted");
    let next = claim_next(&mut conn).unwrap().unwrap();
    assert_ne!(next.attempt_id, work.attempt_id);
    assert_eq!(
        next.generation, work.generation,
        "resume must reuse the generation"
    );
}

#[test]
fn recovery_still_drops_generations_that_nothing_can_resume() {
    let temp = tempdir().unwrap();
    let mut conn = connect(&temp.path().join("everything.db")).unwrap();
    init_schema(&mut conn).unwrap();
    let work = interrupted_initial_scan(&mut conn, temp.path(), &["keep.txt"]);
    conn.execute(
        "INSERT INTO entries(root_id,generation,path,name,kind,size)
         VALUES(?1,?2,'orphan.txt','orphan.txt','file',0)",
        params![work.root_id, work.generation + 1_000],
    )
    .unwrap();

    recover(&conn).unwrap();

    let left: Vec<String> = conn
        .prepare("SELECT name FROM entries")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(left, ["keep.txt"]);
}

#[test]
fn resumed_scan_publishes_the_same_generation_without_duplicates() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("root");
    let state = temp.path().join("state");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&state).unwrap();
    fs::write(root.join("a.txt"), b"a").unwrap();
    fs::write(root.join("b.txt"), b"bb").unwrap();
    fs::write(root.join("c.txt"), b"ccc").unwrap();
    let mut conn = connect(&state.join("everything.db")).unwrap();
    init_schema(&mut conn).unwrap();
    // a.txt was written before the interruption, with metadata that has since gone stale.
    let first = interrupted_initial_scan(&mut conn, &root, &["a.txt"]);
    recover(&conn).unwrap();

    let second = claim_next(&mut conn).unwrap().unwrap();
    assert_eq!(second.generation, first.generation);
    assert_eq!(
        scan(&mut conn, &second, &state, &AtomicBool::new(false)).unwrap(),
        0
    );
    publish(&mut conn, &second).unwrap();

    let status = status_for_path(&conn, &canonical_root(&root).unwrap()).unwrap();
    assert_eq!(status.active_generation, first.generation);
    assert_eq!(resume_generation(&conn, second.root_id), 0);
    let rows: Vec<(String, i64)> = conn
        .prepare("SELECT name,size FROM entries ORDER BY name")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let names: Vec<&str> = rows.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["a.txt", "b.txt", "c.txt"]);
    assert_eq!(rows[0].1, 1, "a stale row must take the rescanned size");
    // The FTS index has to agree with the table after an upsert, not just the table.
    let hits: i64 = conn
        .query_row(
            "SELECT count(*) FROM entry_names_fts WHERE entry_names_fts MATCH '\"a.tx\"'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(hits, 1);
}

#[test]
fn failed_initial_scan_keeps_its_entries_for_the_retry() {
    let temp = tempdir().unwrap();
    let mut conn = connect(&temp.path().join("everything.db")).unwrap();
    init_schema(&mut conn).unwrap();
    let work = interrupted_initial_scan(&mut conn, temp.path(), &["a.txt", "b.txt"]);

    fail_attempt(&mut conn, &work, "simulated read error").unwrap();

    assert_eq!(entry_count(&conn), 2);
    assert_eq!(resume_generation(&conn, work.root_id), work.generation);
}

#[test]
fn shutdown_during_an_initial_scan_interrupts_instead_of_deleting() {
    let temp = tempdir().unwrap();
    let state = temp.path().join("state");
    fs::create_dir_all(&state).unwrap();
    let mut conn = connect(&state.join("everything.db")).unwrap();
    init_schema(&mut conn).unwrap();
    let work = interrupted_initial_scan(&mut conn, temp.path(), &["a.txt", "b.txt"]);
    recover(&conn).unwrap();

    process_next(
        &mut conn,
        &state,
        &AtomicBool::new(true),
        &IndexerConfig::default(),
    )
    .unwrap();

    assert_eq!(entry_count(&conn), 2, "a clean shutdown discarded the scan");
    let (root_state, retry): (String, i64) = conn
        .query_row(
            "SELECT state,retry_not_before FROM roots WHERE id=?1",
            [work.root_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(root_state, "pending");
    assert_eq!(retry, 0, "shutdown is not a failure and must not back off");
    let last: String = conn
        .query_row(
            "SELECT state FROM scan_attempts ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(last, "interrupted");
}

fn set_control(conn: &Connection, root_id: i64, control: &str) {
    conn.execute(
        "UPDATE roots SET control=?2 WHERE id=?1",
        params![root_id, control],
    )
    .unwrap();
}

#[test]
fn a_stopped_or_paused_root_is_not_claimed_until_it_runs_again() {
    let temp = tempdir().unwrap();
    let mut conn = connect(&temp.path().join("everything.db")).unwrap();
    init_schema(&mut conn).unwrap();
    let root_id = ensure_root(&conn, &canonical_root(temp.path()).unwrap()).unwrap();
    conn.execute(
        "UPDATE roots SET desired_seq=1,state='pending',debounce_until_ms=0 WHERE id=?1",
        [root_id],
    )
    .unwrap();
    for held in ["stopped", "paused"] {
        set_control(&conn, root_id, held);
        assert!(
            claim_next(&mut conn).unwrap().is_none(),
            "{held} root was claimed"
        );
    }
    set_control(&conn, root_id, "run");
    assert!(claim_next(&mut conn).unwrap().is_some());
}

#[test]
fn scan_control_stops_and_restarts_a_root_and_reports_it() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("root");
    let other = temp.path().join("other");
    let state = temp.path().join("state");
    for dir in [&root, &other, &state] {
        fs::create_dir_all(dir).unwrap();
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
    indexer.request_refresh(&root, Some("r")).unwrap();
    indexer.request_refresh(&other, Some("o")).unwrap();
    let mut conn = connect(&state.join("everything.db")).unwrap();
    force_due(&conn, &root);
    force_due(&conn, &other);

    // One root by path: only that one is held back.
    let held = indexer.scan_control(ScanAction::Stop, Some(&root)).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].status.control, "stopped");
    let claimed = claim_next(&mut conn).unwrap().unwrap();
    assert_eq!(claimed.root, canonical_root(&other).unwrap());
    assert!(
        claim_next(&mut conn).unwrap().is_none(),
        "the stopped root ran"
    );

    // No path: everything is held, and status sees it.
    indexer.scan_control(ScanAction::Stop, None).unwrap();
    let all = indexer.scan_control(ScanAction::Status, None).unwrap();
    assert_eq!(all.len(), 2);
    assert!(all.iter().all(|info| info.status.control == "stopped"));

    // Start runs it again and asks for a scan; an unknown path is an error, not a no-op.
    let started = indexer
        .scan_control(ScanAction::Start, Some(&root))
        .unwrap();
    assert_eq!(started[0].status.control, "run");
    // An existing directory that was never indexed is refused for a reason of its own, not
    // because the path failed to resolve.
    let stranger = temp.path().join("stranger");
    fs::create_dir_all(&stranger).unwrap();
    let refused = indexer
        .scan_control(ScanAction::Stop, Some(&stranger))
        .unwrap_err();
    assert!(
        format!("{refused}").contains("no scans are registered"),
        "{refused}"
    );
    lock.unlock().unwrap();
}

#[test]
fn a_stopped_scan_ends_with_its_rows_kept() {
    let temp = tempdir().unwrap();
    let state = temp.path().join("state");
    fs::create_dir_all(&state).unwrap();
    fs::write(temp.path().join("a.txt"), b"a").unwrap();
    let mut conn = connect(&state.join("everything.db")).unwrap();
    init_schema(&mut conn).unwrap();
    let work = interrupted_initial_scan(&mut conn, temp.path(), &["earlier.txt"]);
    set_control(&conn, work.root_id, "stopped");

    let error = scan(&mut conn, &work, &state, &AtomicBool::new(false)).unwrap_err();

    assert!(error.downcast_ref::<ScanStopped>().is_some(), "{error:#}");
    assert!(entry_count(&conn) >= 1, "stopping threw the rows away");
}

#[test]
fn a_paused_scan_waits_for_resume_and_then_completes() {
    let temp = tempdir().unwrap();
    let state = temp.path().join("state");
    fs::create_dir_all(&state).unwrap();
    fs::write(temp.path().join("a.txt"), b"a").unwrap();
    let mut conn = connect(&state.join("everything.db")).unwrap();
    init_schema(&mut conn).unwrap();
    let work = interrupted_initial_scan(&mut conn, temp.path(), &[]);
    set_control(&conn, work.root_id, "paused");
    let db = state.join("everything.db");
    let root_id = work.root_id;
    let resumer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(700));
        set_control(&connect(&db).unwrap(), root_id, "run");
    });

    let started = std::time::Instant::now();
    let outcome = scan(&mut conn, &work, &state, &AtomicBool::new(false));
    // Measured before the join: the resumer thread itself sleeps 700 ms.
    let waited = started.elapsed();
    resumer.join().unwrap();

    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(
        waited >= Duration::from_millis(600),
        "the scan did not wait for the resume ({waited:?})"
    );
    assert!(entry_count(&conn) >= 1);
}

#[test]
fn every_connection_commits_without_an_fsync_each_in_wal_mode() {
    // The index can be rebuilt, so a power cut may cost the last commits but never the file.
    // FULL would fsync the WAL on every batch of a multi-million-row scan.
    let temp = tempdir().unwrap();
    let mut conn = connect(&temp.path().join("everything.db")).unwrap();
    init_schema(&mut conn).unwrap();
    let pragma = |name: &str| -> i64 {
        conn.query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
            .unwrap()
    };
    assert_eq!(pragma("synchronous"), 1, "NORMAL");
    assert_eq!(pragma("wal_autocheckpoint"), 8_000);
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
}

#[test]
fn writer_pause_grows_with_the_commit_and_stays_within_bounds() {
    let ms = Duration::from_millis;
    let pause = |took: Duration, rest: u32| pause_after_commit(took, rest, ms(2_000));
    // Trivial commits still yield the writer slot to other processes.
    assert_eq!(pause(ms(0), 2), ms(10));
    // A slow commit (busy disk) earns `rest` times its own length in rest, so the writer
    // holds the disk 1/(rest+1) of the time however slow it is.
    assert_eq!(pause(ms(300), 2), ms(600));
    assert_eq!(pause(ms(300), 4), ms(1_200));
    // rest = 0 switches the proportional part off; only the floor remains.
    assert_eq!(pause(ms(300), 0), ms(10));
    // A pathological commit cannot park the scan past the configured ceiling.
    assert_eq!(pause(Duration::from_secs(60), 2), ms(2_000));
    assert_eq!(
        pause_after_commit(Duration::from_secs(60), 2, ms(500)),
        ms(500)
    );
}

#[test]
fn exclusions_match_whole_components_ignoring_case_and_the_verbatim_prefix() {
    let config = IndexerConfig::default().with_exclude([
        r"C:\ProgramData\Microsoft\Windows\Containers",
        r"c:/Windows/WinSxS/",
    ]);
    let hit = |path: &str| config.is_excluded(Path::new(path));
    assert!(hit(r"C:\ProgramData\Microsoft\Windows\Containers"));
    assert!(hit(
        r"C:\ProgramData\Microsoft\Windows\Containers\Layers\x.dll"
    ));
    assert!(hit(r"\\?\C:\Windows\WinSxS\amd64_x\y.dll"));
    // Case and slash direction are not part of a Windows path's identity.
    assert!(hit(r"c:\programdata\MICROSOFT\windows\containers\a"));
    // A shared name prefix is not a shared directory.
    assert!(!hit(
        r"C:\ProgramData\Microsoft\Windows\ContainersBackup\a.txt"
    ));
    assert!(!hit(r"C:\Windows\WinSxSExtra\a.txt"));
    assert!(!hit(r"C:\Windows\System32\a.dll"));
    assert!(!IndexerConfig::default().is_excluded(Path::new(r"C:\Windows\WinSxS")));
}

#[test]
fn a_scan_skips_an_excluded_subtree_and_keeps_the_rest() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("root");
    let state = temp.path().join("state");
    fs::create_dir_all(root.join("keep")).unwrap();
    fs::create_dir_all(root.join("skip").join("deep")).unwrap();
    fs::create_dir_all(&state).unwrap();
    fs::write(root.join("keep").join("wanted.txt"), b"1").unwrap();
    fs::write(root.join("skip").join("deep").join("unwanted.txt"), b"1").unwrap();
    let mut conn = connect(&state.join("everything.db")).unwrap();
    init_schema(&mut conn).unwrap();
    let mut work = interrupted_initial_scan(&mut conn, &root, &[]);
    let skipped = canonical_root(&root).unwrap().join("skip");
    work.settings = IndexerConfig::default().with_exclude([skipped.to_str().unwrap()]);

    assert_eq!(
        scan(&mut conn, &work, &state, &AtomicBool::new(false)).unwrap(),
        0
    );

    let names: Vec<String> = conn
        .prepare("SELECT name FROM entries ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(names, ["keep", "wanted.txt"]);
}

#[test]
fn pending_index_status_does_not_wait_for_a_writer() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("root");
    let state = temp.path().join("state");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&state).unwrap();
    let worker_lock = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state.join("everything.lock"))
        .unwrap();
    worker_lock.try_lock().unwrap();
    let indexer = Indexer::open(&state).unwrap();
    let receipt = indexer
        .request_refresh(&root, Some("pending-request"))
        .unwrap();
    let mut conn = connect(&state.join("everything.db")).unwrap();
    let writer = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert_eq!(indexer.status(&root).unwrap().state, "pending");
    assert_eq!(
        indexer
            .request_refresh(&root, Some("pending-request"))
            .unwrap()
            .target_seq,
        receipt.target_seq
    );
    drop(writer);
    worker_lock.unlock().unwrap();
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
fn incomplete_initial_scan_keeps_usable_entries_and_allows_narrow_refresh() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("root");
    let child = root.join("child");
    let state = temp.path().join("state");
    fs::create_dir_all(&child).unwrap();
    fs::create_dir_all(&state).unwrap();
    let worker_lock = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state.join("everything.lock"))
        .unwrap();
    worker_lock.try_lock().unwrap();
    let indexer = Indexer::open(&state).unwrap();
    let first = indexer.request_refresh(&root, Some("wide")).unwrap();
    let mut conn = connect(&state.join("everything.db")).unwrap();
    force_due(&conn, &root);
    let work = claim_next(&mut conn).unwrap().unwrap();
    let path = canonical_root(&child).unwrap().join("found.txt");
    conn.execute(
            "INSERT INTO entries(root_id,generation,path,name,kind,size) VALUES(?1,?2,?3,'found.txt','file',1)",
            params![work.root_id, work.attempt_id, path_text(&path).unwrap()],
        ).unwrap();
    publish_partial_initial(&mut conn, &work, "1 entry could not be indexed").unwrap();
    let result = indexer
        .search(&child, "found.txt", MatchMode::Exact, 10)
        .unwrap();
    assert_eq!(result.matches.len(), 1);
    assert_eq!(result.status.state, "partial");
    assert_eq!(result.status.completed_seq, first.target_seq);
    force_due(&conn, &root);
    assert!(claim_next(&mut conn).unwrap().is_none());
    assert_eq!(
        indexer
            .request_status(&first.request_id)
            .unwrap()
            .unwrap()
            .status,
        "partial"
    );
    let narrow = indexer.request_refresh(&child, Some("narrow")).unwrap();
    assert_eq!(narrow.work_root, canonical_root(&child).unwrap());
    worker_lock.unlock().unwrap();
}

#[test]
fn incomplete_refresh_preserves_published_entries_without_retry_loop() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("root");
    let state = temp.path().join("state");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&state).unwrap();
    fs::write(root.join("found.txt"), b"found").unwrap();
    let worker_lock = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state.join("everything.lock"))
        .unwrap();
    worker_lock.try_lock().unwrap();
    let indexer = Indexer::open(&state).unwrap();
    indexer.request_refresh(&root, Some("first")).unwrap();
    let mut conn = connect(&state.join("everything.db")).unwrap();
    force_due(&conn, &root);
    let first = claim_next(&mut conn).unwrap().unwrap();
    assert_eq!(
        scan(&mut conn, &first, &state, &AtomicBool::new(false)).unwrap(),
        0
    );
    publish(&mut conn, &first).unwrap();
    let receipt = indexer.request_refresh(&root, Some("incomplete")).unwrap();
    force_due(&conn, &root);
    let second = claim_next(&mut conn).unwrap().unwrap();
    finish_partial_refresh(&mut conn, &second, "1 entry could not be indexed").unwrap();
    let result = indexer
        .search(&root, "found.txt", MatchMode::Exact, 10)
        .unwrap();
    assert_eq!(result.matches.len(), 1);
    assert_eq!(result.status.state, "partial");
    assert_eq!(result.status.completed_seq, receipt.target_seq);
    assert!(claim_next(&mut conn).unwrap().is_none());
    worker_lock.unlock().unwrap();
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
    lock.unlock().unwrap();
}

#[test]
fn status_reports_the_progress_of_the_running_attempt() {
    let temp = tempdir().unwrap();
    let mut conn = connect(&temp.path().join("everything.db")).unwrap();
    init_schema(&mut conn).unwrap();
    let work = interrupted_initial_scan(&mut conn, temp.path(), &[]);
    let child = canonical_root(temp.path()).unwrap().join("child");

    update_progress(&conn, &work, 12, 2, &child).unwrap();

    let status = status_for_path(&conn, &canonical_root(temp.path()).unwrap()).unwrap();
    let progress = status.progress.unwrap();
    assert_eq!((progress.entries_seen, progress.dirs_seen), (12, 2));
    assert_eq!(progress.attempt_state, "running");
    assert_eq!(progress.current_path.as_deref(), Some(child.as_path()));
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

/// root/a/x.bin (100), root/a/b/y.bin (50), root/a-b/z.bin (3), root/c.bin (7), root/e/ (empty).
/// `a-b` sorts between `a` and `a\b` in byte order, which a naive roll-up gets wrong.
fn totals_tree(base: &Path) -> PathBuf {
    let root = base.join("root");
    fs::create_dir_all(root.join("a").join("b")).unwrap();
    fs::create_dir_all(root.join("a-b")).unwrap();
    fs::create_dir_all(root.join("e")).unwrap();
    fs::write(root.join("a").join("x.bin"), [0u8; 100]).unwrap();
    fs::write(root.join("a").join("b").join("y.bin"), [0u8; 50]).unwrap();
    fs::write(root.join("a-b").join("z.bin"), [0u8; 3]).unwrap();
    fs::write(root.join("c.bin"), [0u8; 7]).unwrap();
    root
}

/// The tree scanned and published: (root, state dir, connection, the scan's work).
fn published_tree(base: &Path) -> (PathBuf, PathBuf, Connection, Work) {
    let root = totals_tree(base);
    let state = base.join("state");
    fs::create_dir_all(&state).unwrap();
    let mut conn = connect(&state.join("everything.db")).unwrap();
    init_schema(&mut conn).unwrap();
    let work = interrupted_initial_scan(&mut conn, &root, &[]);
    assert_eq!(
        scan(&mut conn, &work, &state, &AtomicBool::new(false)).unwrap(),
        0
    );
    publish(&mut conn, &work).unwrap();
    (root, state, conn, work)
}

type StoredTotals = BTreeMap<String, (i64, i64, i64)>;

fn stored_totals(conn: &Connection, root_id: i64) -> StoredTotals {
    conn.prepare("SELECT path,bytes,files,dirs FROM dir_stats WHERE root_id=?1")
        .unwrap()
        .query_map([root_id], |row| {
            Ok((row.get(0)?, (row.get(1)?, row.get(2)?, row.get(3)?)))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn indexed_path(root: &Path, relative: &[&str]) -> String {
    let mut path = canonical_root(root).unwrap();
    path.extend(relative);
    path_text(&path).unwrap().to_owned()
}

fn expected_totals(root: &Path) -> StoredTotals {
    BTreeMap::from([
        (indexed_path(root, &[]), (160, 4, 4)),
        (indexed_path(root, &["a"]), (150, 2, 1)),
        (indexed_path(root, &["a", "b"]), (50, 1, 0)),
        (indexed_path(root, &["a-b"]), (3, 1, 0)),
        (indexed_path(root, &["e"]), (0, 0, 0)),
    ])
}

fn dir_stats_rows(conn: &Connection) -> i64 {
    conn.query_row("SELECT count(*) FROM dir_stats", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn a_scan_stores_subtree_totals_for_every_directory() {
    let temp = tempdir().unwrap();
    let (root, _state, conn, work) = published_tree(temp.path());

    assert_eq!(stored_totals(&conn, work.root_id), expected_totals(&root));
}

#[test]
fn backfill_rebuilds_missing_totals_and_leaves_a_complete_set_alone() {
    let temp = tempdir().unwrap();
    let (root, _state, mut conn, work) = published_tree(temp.path());
    let stop = AtomicBool::new(false);
    let settings = IndexerConfig::default();

    // A root indexed before totals existed.
    conn.execute("DELETE FROM dir_stats", []).unwrap();
    backfill_dir_stats(&mut conn, &stop, &settings).unwrap();
    assert_eq!(stored_totals(&conn, work.root_id), expected_totals(&root));

    // Complete: nothing is rewritten.
    let a = indexed_path(&root, &["a"]);
    conn.execute("UPDATE dir_stats SET bytes=999999 WHERE path=?1", [&a])
        .unwrap();
    backfill_dir_stats(&mut conn, &stop, &settings).unwrap();
    assert_eq!(stored_totals(&conn, work.root_id)[&a].0, 999_999);

    // The root's own row says the set is complete; without it the set is redone.
    conn.execute(
        "DELETE FROM dir_stats WHERE path=(SELECT path FROM roots WHERE id=?1)",
        [work.root_id],
    )
    .unwrap();
    backfill_dir_stats(&mut conn, &stop, &settings).unwrap();
    assert_eq!(stored_totals(&conn, work.root_id), expected_totals(&root));
}

#[test]
fn a_refresh_replaces_the_previous_totals() {
    let temp = tempdir().unwrap();
    let (root, state, mut conn, first) = published_tree(temp.path());
    fs::write(root.join("a").join("new.bin"), [0u8; 1000]).unwrap();
    conn.execute(
        "UPDATE roots SET desired_seq=desired_seq+1,state='pending',debounce_until_ms=0 WHERE id=?1",
        [first.root_id],
    )
    .unwrap();
    let second = claim_next(&mut conn).unwrap().unwrap();
    assert_ne!(second.attempt_id, first.attempt_id);
    assert_ne!(second.active_generation, 0, "this must be a refresh");

    scan(&mut conn, &second, &state, &AtomicBool::new(false)).unwrap();
    publish(&mut conn, &second).unwrap();

    let got = stored_totals(&conn, first.root_id);
    assert_eq!(got[&indexed_path(&root, &[])].0, 1160);
    assert_eq!(got[&indexed_path(&root, &["a"])].0, 1150);
    assert_eq!(dir_stats_rows(&conn), 5, "the old totals were kept");
}

#[test]
fn a_partial_refresh_keeps_the_published_totals_and_drops_its_own() {
    let temp = tempdir().unwrap();
    let (root, state, mut conn, first) = published_tree(temp.path());
    fs::write(root.join("a").join("new.bin"), [0u8; 1000]).unwrap();
    conn.execute(
        "UPDATE roots SET desired_seq=desired_seq+1,state='pending',debounce_until_ms=0 WHERE id=?1",
        [first.root_id],
    )
    .unwrap();
    let second = claim_next(&mut conn).unwrap().unwrap();
    scan(&mut conn, &second, &state, &AtomicBool::new(false)).unwrap();
    assert_eq!(dir_stats_rows(&conn), 10, "both scans store totals");

    finish_partial_refresh(&mut conn, &second, "1 entries could not be indexed").unwrap();

    assert_eq!(dir_stats_rows(&conn), 5);
    assert_eq!(stored_totals(&conn, first.root_id), expected_totals(&root));
}

#[test]
fn recovery_drops_totals_that_no_published_generation_points_at() {
    let temp = tempdir().unwrap();
    let (root, _state, conn, work) = published_tree(temp.path());
    conn.execute(
        "INSERT INTO dir_stats(root_id,generation,path,bytes,files,dirs) VALUES(?1,999999,'stray',1,1,0)",
        [work.root_id],
    )
    .unwrap();
    assert_eq!(dir_stats_rows(&conn), 6);

    recover(&conn).unwrap();

    assert_eq!(dir_stats_rows(&conn), 5);
    assert_eq!(stored_totals(&conn, work.root_id), expected_totals(&root));
}

#[test]
fn search_and_dir_stats_report_directory_totals() {
    let temp = tempdir().unwrap();
    let (root, state, _conn, _work) = published_tree(temp.path());
    // Hold the worker lock so this process's own worker stays idle.
    let lock = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state.join("everything.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    let indexer = Indexer::open(&state).unwrap();

    let dir = indexer
        .search(&root, "a", MatchMode::Exact, 10)
        .unwrap()
        .matches;
    assert_eq!(dir.len(), 1);
    assert_eq!(
        (dir[0].size, dir[0].files, dir[0].dirs),
        (150, Some(2), Some(1))
    );
    let file = indexer
        .search(&root, "c.bin", MatchMode::Exact, 10)
        .unwrap()
        .matches;
    assert_eq!((file[0].size, file[0].files, file[0].dirs), (7, None, None));

    let stats = indexer
        .dir_stats(&[root.join("a"), root.join("missing"), root.clone()])
        .unwrap();
    let first = stats[0].as_ref().unwrap();
    assert_eq!((first.bytes, first.files, first.dirs), (150, 2, 1));
    assert!(!first.partial);
    assert!(first.as_of.is_some());
    assert!(stats[1].is_none());
    assert_eq!(stats[2].as_ref().unwrap().bytes, 160);
    lock.unlock().unwrap();
}

/// The worker lock is held so the indexer this returns stays idle; keep the file alive.
fn idle_indexer(state: &Path) -> (File, Indexer) {
    let lock = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state.join("everything.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    (lock, Indexer::open(state).unwrap())
}

fn run_sql(indexer: &Indexer, allowed: &[PathBuf], sql: &str) -> Result<Vec<Vec<SqlValue>>> {
    let mut rows = Vec::new();
    indexer.query_each(
        &SqlQuery {
            sql,
            allowed,
            timeout: Duration::from_secs(20),
        },
        |_, values| {
            rows.push(values.to_vec());
            Ok(true)
        },
    )?;
    Ok(rows)
}

fn text(value: &str) -> SqlValue {
    SqlValue::Text(value.to_owned())
}

#[test]
fn sql_sees_directory_totals_extensions_and_parents() {
    let temp = tempdir().unwrap();
    let (root, state, _conn, _work) = published_tree(temp.path());
    let (_lock, indexer) = idle_indexer(&state);
    let allowed = [canonical_root(&root).unwrap()];

    let dir = run_sql(
        &indexer,
        &allowed,
        "SELECT size,files,dirs FROM fs_entries WHERE name='a' AND kind='dir'",
    )
    .unwrap();
    assert_eq!(
        dir,
        [[SqlValue::Int(150), SqlValue::Int(2), SqlValue::Int(1)]]
    );
    let by_ext = run_sql(
        &indexer,
        &allowed,
        "SELECT ext,count(*),sum(size) FROM fs_entries WHERE kind='file' GROUP BY ext",
    )
    .unwrap();
    assert_eq!(
        by_ext,
        [[text("bin"), SqlValue::Int(4), SqlValue::Int(160)]]
    );
    let parent = run_sql(
        &indexer,
        &allowed,
        "SELECT dir FROM fs_entries WHERE name='y.bin'",
    )
    .unwrap();
    assert_eq!(parent, [[text(&indexed_path(&root, &["a", "b"]))]]);
    let functions = run_sql(
        &indexer,
        &allowed,
        "SELECT name FROM fs_entries WHERE name REGEXP '^[xy][.]bin$' ORDER BY name",
    )
    .unwrap();
    assert_eq!(functions, [[text("x.bin")], [text("y.bin")]]);
}

#[test]
fn sql_subtree_ranges_and_sibling_lookups_are_exact() {
    let temp = tempdir().unwrap();
    let (root, state, _conn, _work) = published_tree(temp.path());
    let (_lock, indexer) = idle_indexer(&state);
    let allowed = [canonical_root(&root).unwrap()];
    let a = indexed_path(&root, &["a"]);

    // `a-b` sorts between `a` and `a\b`, and is not beneath `a`.
    let beneath = run_sql(
        &indexer,
        &allowed,
        &format!("SELECT name FROM fs_entries WHERE path>='{a}\\' AND path<'{a}]' ORDER BY name"),
    )
    .unwrap();
    assert_eq!(beneath, [[text("b")], [text("x.bin")], [text("y.bin")]]);

    let holding_both = run_sql(
        &indexer,
        &allowed,
        "SELECT a.dir FROM fs_entries a WHERE a.name='b' AND a.kind='dir'
         AND EXISTS (SELECT 1 FROM fs_entries s WHERE s.path=a.dir||'\\x.bin')",
    )
    .unwrap();
    assert_eq!(holding_both, [[text(&a)]]);
}

#[test]
fn sql_refuses_everything_but_a_select_over_the_views() {
    let temp = tempdir().unwrap();
    let (root, state, conn, work) = published_tree(temp.path());
    let (_lock, indexer) = idle_indexer(&state);
    let allowed = [canonical_root(&root).unwrap()];
    let before = (entry_count(&conn), dir_stats_rows(&conn));

    for sql in [
        "DELETE FROM entries",
        "DELETE FROM fs_entries",
        "INSERT INTO dir_stats VALUES(1,1,'x',1,1,1)",
        "UPDATE roots SET state='x'",
        "DROP TABLE entries",
        "CREATE TABLE t(x)",
        "PRAGMA query_only=OFF",
        "ATTACH DATABASE 'other.db' AS other",
        "SELECT * FROM entries",
        "SELECT * FROM roots",
        "SELECT * FROM dir_stats",
        "SELECT * FROM sqlite_master",
        "SELECT * FROM staged_entries",
        "SELECT 1; SELECT 2",
        "SELECT zeroblob(10)",
        "SELECT load_extension('x')",
    ] {
        assert!(
            run_sql(&indexer, &allowed, sql).is_err(),
            "was allowed: {sql}"
        );
    }

    assert_eq!((entry_count(&conn), dir_stats_rows(&conn)), before);
    let state_after: String = conn
        .query_row(
            "SELECT state FROM roots WHERE id=?1",
            [work.root_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state_after, "ready");
}

#[test]
fn sql_sees_only_the_directories_it_is_allowed() {
    let temp = tempdir().unwrap();
    let (root, state, _conn, _work) = published_tree(temp.path());
    let (_lock, indexer) = idle_indexer(&state);

    let only_a_b = run_sql(
        &indexer,
        &[canonical_root(&root).unwrap().join("a-b")],
        "SELECT name FROM fs_entries ORDER BY name",
    )
    .unwrap();
    assert_eq!(only_a_b, [[text("a-b")], [text("z.bin")]]);
    let nothing = run_sql(&indexer, &[], "SELECT name FROM fs_entries").unwrap();
    assert!(nothing.is_empty());
}

#[test]
fn sql_is_stopped_at_its_time_limit_and_can_be_stopped_early() {
    let temp = tempdir().unwrap();
    let (root, state, _conn, _work) = published_tree(temp.path());
    let (_lock, indexer) = idle_indexer(&state);
    let allowed = [canonical_root(&root).unwrap()];

    let error = indexer
        .query_each(
            &SqlQuery {
                sql: "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c)
                      SELECT count(*) FROM c",
                allowed: &allowed,
                timeout: Duration::from_millis(100),
            },
            |_, _| Ok(true),
        )
        .unwrap_err();
    assert!(format!("{error}").contains("time limit"), "{error}");

    let mut seen = 0;
    let outcome = indexer
        .query_each(
            &SqlQuery {
                sql: "SELECT name FROM fs_entries",
                allowed: &allowed,
                timeout: Duration::from_secs(10),
            },
            |columns, _| {
                assert_eq!(columns, ["name"]);
                seen += 1;
                Ok(seen < 2)
            },
        )
        .unwrap();
    assert_eq!((outcome.rows, outcome.stopped), (2, true));
    assert_eq!(outcome.roots.len(), 1);
    assert_eq!(outcome.roots[0].state, "ready");
    assert!(outcome.roots[0].last_verified.is_some());
}

/// Timings of typical `locate_sql` questions on a COPY of a real index, run by hand:
/// `LOCATE_DB_COPY=<dir> cargo test -p filesystem-locate --release real_index_sql -- --ignored --nocapture`.
#[test]
#[ignore]
fn real_index_sql_answers_typical_questions_in_reasonable_time() {
    let Ok(dir) = std::env::var("LOCATE_DB_COPY") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let indexer = Indexer::open(&dir).unwrap();
    let everything = [PathBuf::from(r"\\?\C:\"), PathBuf::from(r"\\?\D:\")];
    let queries = [
        (
            "largest files under a folder",
            r"SELECT path,size FROM fs_entries WHERE kind='file' AND path>='\\?\C:\Users\joss1\' AND path<'\\?\C:\Users\joss1]' ORDER BY size DESC LIMIT 10",
        ),
        (
            "children of a folder by size",
            r"SELECT name,size,files FROM fs_entries WHERE path>='\\?\C:\Users\joss1\' AND path<'\\?\C:\Users\joss1]' AND dir='\\?\C:\Users\joss1' ORDER BY size DESC LIMIT 10",
        ),
        (
            "size per extension over the volume",
            r"SELECT ext,count(*) n,sum(size) bytes FROM fs_entries WHERE kind='file' AND path>='\\?\C:\' AND path<'\\?\C:]' GROUP BY ext ORDER BY bytes DESC LIMIT 10",
        ),
        (
            "Unity projects (two siblings)",
            r"SELECT a.dir FROM fs_entries a WHERE a.name='Assets' AND a.kind='dir' AND EXISTS (SELECT 1 FROM fs_entries b WHERE b.path=a.dir||'\ProjectSettings') LIMIT 20",
        ),
        (
            "top-level node_modules by size",
            r"SELECT path,size FROM fs_entries WHERE name='node_modules' AND kind='dir' AND instr(path,'\node_modules\')=0 ORDER BY size DESC LIMIT 10",
        ),
        (
            "target folders by size",
            r"SELECT path,size FROM fs_entries WHERE name='target' AND kind='dir' ORDER BY size DESC LIMIT 10",
        ),
        (
            "old big files",
            r"SELECT path,size FROM fs_entries WHERE kind='file' AND size>1000000000 AND modified < strftime('%s','now','-1 year') ORDER BY size DESC LIMIT 10",
        ),
    ];
    for (title, sql) in queries {
        if std::env::var("LOCATE_SQL_PLAN").is_ok() {
            let plan = format!("EXPLAIN QUERY PLAN {sql}");
            println!("{title}");
            let _ = indexer.query_each(
                &SqlQuery {
                    sql: &plan,
                    allowed: &everything,
                    timeout: Duration::from_secs(60),
                },
                |_, values| {
                    println!("  plan: {:?}", values.last());
                    Ok(true)
                },
            );
            if std::env::var("LOCATE_SQL_PLAN").as_deref() == Ok("only") {
                continue;
            }
        }
        let started = std::time::Instant::now();
        let outcome = indexer.query_each(
            &SqlQuery {
                sql,
                allowed: &everything,
                timeout: Duration::from_secs(600),
            },
            |_, values| {
                println!("    {values:?}");
                Ok(true)
            },
        );
        match outcome {
            Ok(outcome) => println!(
                "{title}: {} rows in {:.1}s\n",
                outcome.rows,
                started.elapsed().as_secs_f32()
            ),
            Err(error) => println!("{title}: FAILED {error:#}\n"),
        }
    }
}

/// Real-data check, run by hand against a COPY of a real index:
/// `LOCATE_DB_COPY=<dir holding everything.db> cargo test -p filesystem-locate --release
/// real_index_totals -- --ignored --nocapture`. The worker backfills the totals; each root's
/// row must then equal what its entries add up to.
#[test]
#[ignore]
fn real_index_totals_match_the_entries_they_summarise() {
    let Ok(dir) = std::env::var("LOCATE_DB_COPY") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let started = std::time::Instant::now();
    let _indexer = Indexer::open(&dir).unwrap();
    let conn = connect(&dir.join("everything.db")).unwrap();
    let roots: Vec<(i64, String, i64, i64)> = conn
        .prepare(
            "SELECT id,path,active_generation,published_attempt FROM roots
             WHERE active_generation>0 AND covered_by IS NULL",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(!roots.is_empty(), "the copy holds no published root");
    for (root_id, root, generation, attempt) in roots {
        let deadline = std::time::Instant::now() + Duration::from_secs(45 * 60);
        let stored: (i64, i64, i64) = loop {
            let row = conn
                .query_row(
                    "SELECT bytes,files,dirs FROM dir_stats WHERE root_id=?1 AND generation=?2 AND path=?3",
                    params![root_id, attempt, root],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .ok();
            if let Some(row) = row {
                break row;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no totals for {root} after 45 minutes"
            );
            thread::sleep(Duration::from_secs(2));
        };
        let summed: (i64, i64, i64) = conn
            .query_row(
                "SELECT COALESCE(SUM(CASE WHEN kind!='dir' THEN size END),0),
                        COUNT(CASE WHEN kind!='dir' THEN 1 END),
                        COUNT(CASE WHEN kind='dir' THEN 1 END)
                 FROM entries WHERE root_id=?1 AND generation=?2",
                params![root_id, generation],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let rows: i64 = conn
            .query_row(
                "SELECT count(*) FROM dir_stats WHERE root_id=?1 AND generation=?2",
                params![root_id, attempt],
                |row| row.get(0),
            )
            .unwrap();
        println!(
            "{root}: totals {stored:?}, entries add up to {summed:?}, {rows} directory rows, {}s since start",
            started.elapsed().as_secs()
        );
        assert_eq!(stored, summed, "{root}");
    }
}
