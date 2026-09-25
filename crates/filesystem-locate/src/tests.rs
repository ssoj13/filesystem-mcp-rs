use std::fs::{self, File};
use std::path::Path;
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
    assert_eq!(indexer.ensure_index(&root).unwrap().state, "pending");
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
