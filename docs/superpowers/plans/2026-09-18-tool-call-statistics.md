# Wave 3 — Tool-Call Statistics Implementation Plan


> **Superseded — kept as a record of intent, not as a description of the code.**
>
> Wave 3 was replanned mid-flight and built far smaller than this. There is no SQLite file, no flush task, no lease, no compaction and no reader tool: counters live in memory and are written once, as JSON, to `<state>/stats/<date>/<machine>_<timestamp>_<instance>.json`. `FS_MCP_STATS` is the only key; `FS_MCP_STATS_DB`, `_FLUSH_SEC`, `_EVERY`, `_DETAIL_DAYS` and `_LABEL` never shipped.
>
> The body below is left exactly as it was written, because a plan edited after the fact stops
> being evidence of what was decided and why. For what the code actually does now, read
> `README.md`, `CLAUDE.md` and the rustdoc on the modules named there.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Know which of this server's 132 tools are used, which fail and how, across the dozens of processes that run at once — including the tools nobody ever calls.

**Architecture:** Counters accumulate in memory keyed by `(tool, 10-minute bucket)`; a background task flushes DELTAS into one shared SQLite file under the state root, where `instance_id` is part of every primary key so two processes never write the same row. Retention reuses wave 1's housekeeping lease with a new `kind`. Two read tools expose it, one of which reports the subsystem's own health because a statistics subsystem that dies quietly is worse than none.

**Tech Stack:** Rust edition 2024, `rusqlite` 0.40 (already an unconditional dependency, used by `memory_v2`), `tokio`, `core::paths`, `core::instance`, `core::housekeeping` — all from waves 1-2.

**Spec:** `docs/superpowers/specs/2026-09-17-state-dir-logging-stats-design.md` §6 (and §3's invariants I1-I9)

## Global Constraints

- **The hot path cannot fail.** `Collector::record(..)` returns `()` and only locks a mutex and adds integers. Everything fallible happens in the flush task inside `spawn_blocking` — `rusqlite` is blocking and must never run on the async runtime.
- **Statistics must never fail, stall or slow a tool call.** If the database is unusable the server serves exactly as before.
- Every path comes from `core::paths`; `paths_are_centralized` fails the build otherwise. Tool descriptions obey `docs/TOOL_STYLE.md` and `tool_surface_guard` enforces it.
- No silent fallbacks. Never discard errors with `let _ =`; avoid `unwrap()`/`expect()` outside tests.
- Tests use `tempfile::TempDir`, never `std::env::temp_dir()`, and never touch the real `~/.filesystem-mcp-rs/`. A test that spawns the server passes `FS_MCP_STATE_DIR` on the CHILD's `Command`.
- `FS_MCP_*` keys live only in `src/env_spec.rs`, each with a real reader; a registered key with no reader fails `every_registered_key_is_read_somewhere_in_the_sources`. A constant and its registry default must be asserted equal, not kept in step by a comment.
- Retention knobs: `0 = disabled`, matching `FS_MCP_TMP_KEEP_HOURS` and `FS_MCP_LOG_KEEP_DAYS`.
- Gates: plain `cargo test` (all three suites — `--bin` silently skips 68 tests), `cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`.
- Rustdoc on every public item: what it is, why it exists, where it is used. No agent co-authorship trailers.

---

### Task 1: the database — one door, additive rows

**Files:**
- Create: `src/tools/stats/mod.rs`, `src/tools/stats/db.rs`
- Modify: `src/tools/mod.rs`, `src/env_spec.rs`, `Cargo.toml` (feature `stats-tools`, added to `default`)

**Interfaces:**
- Produces: `pub fn open(path: &Path) -> rusqlite::Result<Connection>` (the writer), `pub fn open_read_only(path: &Path)`, `SCHEMA_VERSION`, and the readers `enabled()`, `detail_days()`, `label()`.

This is invariant I7 — one door — and I3: every column is an INTEGER counter merged with `x = x + excluded.x`, so a write never has to read first. That is what makes `SQLITE_BUSY_SNAPSHOT` unreachable rather than handled.

- [ ] **Step 1: Write the failing tests**

```rust
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

/// A database written by a NEWER build is not written into: its columns may mean something else.
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
    assert!(msg.contains("newer") && msg.contains(&(SCHEMA_VERSION + 1).to_string()), "{msg}");
}

/// WAL is required: without it dozens of writers serialise on one global lock. If it cannot be
/// established the caller is told, not silently given a slower database.
#[test]
fn wal_is_established_or_reported() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let conn = open(&dir.path().join("stats.db")).expect("open");
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .expect("journal_mode");
    assert_eq!(mode.to_lowercase(), "wal");
}
```

- [ ] **Step 2: Run them** — `cargo test --bin filesystem-mcp-rs stats::db` fails to compile: the module does not exist.

- [ ] **Step 3: Implement**

`open` applies, in this order and all per-connection except the first: `journal_mode = WAL` (persisted in the file header), `synchronous = NORMAL` (durable against process crash, one fsync fewer per commit — `memory_v2` keeps FULL, statistics do not need it), `busy_timeout = 5000`, `journal_size_limit` (without it one long-lived reader pins the `-wal` and it grows forever — `memory_v2` has that latent bug, do not copy it), then the `user_version` check: equal → proceed, older → migrate, newer → refuse with an error naming both versions.

**One correction to §6.3, from the wave-2 review:** the `sessions` primary key is
`(started_day, pid, instance_id, session_id)`, NOT `(instance_id, session_id)` as the spec drafts
it. `core::instance::id()` is a nonce, not a unique id — its own rustdoc now says so in bold, and
spells the rule: a persistent key must be (day, pid, instance), never the instance alone, because
that is exactly the triple the log file name carries (`<YYYY-MM-DD>/fsmcp-<pid>-<instance>.log`)
and a session row that cannot name its own log file is useless. `tool_agg` is unaffected: its
`bucket` already plays the day's role, so the key is time-scoped by construction.

Schema otherwise as §6.3: `tool_agg` (`STRICT`, `WITHOUT ROWID`, PK `(bucket, tool, instance_id, session_id)` — the key starts with `bucket` so a time range is a prefix scan and pruning deletes a contiguous prefix), `ix_agg_session`, `tool_daily`, `tool_catalog`, `sessions`. **No `housekeeping` table** — §5 says the lease is wave 1's marker file and wave 3 must reuse it.

Env keys in `env_spec.rs`: `FS_MCP_STATS` (`on`), `FS_MCP_STATS_DB` (blank = `<state>/stats.db`), `FS_MCP_STATS_FLUSH_SEC` (`5`), `FS_MCP_STATS_DETAIL_DAYS` (`14`), `FS_MCP_STATS_LABEL` (blank). Readers live in this module, next to what they govern, as `tmp_keep_hours` does for `tmp/`.

- [ ] **Step 4: Run the tests** — PASS, 3 tests.

- [ ] **Step 5: Commit** `feat(stats): the statistics database, additive rows behind one door`

---

### Task 2: classify the outcome, once and exhaustively

**Files:**
- Create: `src/tools/stats/outcome.rs`
- Modify: `src/main.rs` (the hand-written `call_tool` — find it by shape: it builds a `ToolCallContext`, calls `self.tool_router.call(ctx)`, then stamps the session footer)

**Interfaces:**
- Produces: `pub enum Outcome { Ok, ErrFlagged, ErrParams, ErrInternal, Deferred }` and
  `pub fn classify(result: &Result<CallToolResponse, McpError>) -> Outcome`.

This is invariant I5, and it is the difference between a table that tells the truth and one that reports ~0% errors for a server that is failing constantly. **Tool-level failure is reported INSIDE a successful result** in this codebase: `r.is_error = Some(..)` is set for a parse error, for a `run_command` that was killed or timed out, and for a failed `kill_process`. A classifier that only looks at `Result` counts the most interesting failure in the server as a success.

- [ ] **Step 1: Write the failing test** — table-driven over every shape:

```rust
#[test]
fn every_outcome_shape_is_classified() {
    let ok = CallToolResult::success(vec![]);
    let flagged = { let mut r = CallToolResult::success(vec![]); r.is_error = Some(true); r };
    let not_flagged = { let mut r = CallToolResult::success(vec![]); r.is_error = Some(false); r };
    assert_eq!(classify(&Ok(CallToolResponse::Complete(ok))), Outcome::Ok);
    assert_eq!(classify(&Ok(CallToolResponse::Complete(flagged))), Outcome::ErrFlagged);
    assert_eq!(classify(&Ok(CallToolResponse::Complete(not_flagged))), Outcome::Ok);
    assert_eq!(classify(&Err(McpError::invalid_params("x", None))), Outcome::ErrParams);
    assert_eq!(classify(&Err(McpError::internal_error("x", None))), Outcome::ErrInternal);
}
```

- [ ] **Step 2: Run it** — fails to compile.

- [ ] **Step 3: Implement** with a `match` that has **no `_` arm** over `CallToolResponse`'s variants and over the error code. When rmcp adds a variant the build must break rather than silently count it as a success — that compiler error is the whole point of the design, so do not reach for a catch-all to make the code tidier.

- [ ] **Step 4: Run** — PASS.

- [ ] **Step 5: Commit** `feat(stats): classify a call's outcome in one exhaustive place`

---

### Task 3: the collector and the seam

**Files:**
- Create: `src/tools/stats/collect.rs`
- Modify: `src/main.rs` (`call_tool`, and `FileSystemServer`'s fields + construction)

**Interfaces:**
- Produces: `pub struct Collector` with `pub fn record(&self, tool: &str, outcome: Outcome, ns: u64, bytes_out: u64, now: SystemTime)` returning `()`, `pub fn take_delta(&self)`, `pub fn merge_back(&self, delta)`, `pub fn health(&self) -> Health`.

Three rules decide the shape, each from a defect this project already paid for:

- **The bucket is computed at CALL time** and is part of the map key. Wave 1 shipped a sweep that aged entries by the wrong clock for exactly this reason: taken at flush time, a long session would attribute every call to whichever ten minutes the flush happened in.
- **The tool name is interned against the router's own list**; anything else becomes `__unknown`. A name arrives from the wire before the router rejects it, and an un-interned key would grow the map without bound from a typo.
- **`record` cannot fail.** No `Result`, no I/O, no allocation beyond the map entry. `bytes_out` is the sum of already-materialised content-block lengths on the `Complete` arm, never a re-serialisation; `bytes_in` is not recorded at all, because measuring it would mean re-serialising the arguments on every call.

- [ ] **Step 1: Write the failing tests** covering three properties: two calls 700 seconds apart produce two rows even when flushed together; three unknown names collapse into one `__unknown` key; and `take_delta` clears the map while `merge_back` restores counts by addition without doubling (record 5 ns, take, record 7 ns, merge back, expect ok=2 and ns_total=12).

- [ ] **Step 2: Run them** - fail to compile.

- [ ] **Step 3: Implement**, then wire the seam. In `call_tool`: `Instant::now()` before the existing dispatch, `classify()` after it, `record(..)` with the elapsed nanos and the content-block byte sum. The existing session-footer stamping stays exactly as it is - statistics observe, they do not alter the response.

- [ ] **Step 4: Run** - PASS, and the FULL suite still green: wiring the seam must not change any existing tool's behaviour.

- [ ] **Step 5: Commit** `feat(stats): count every tool call without being able to fail`

---

### Task 4: the flush task

**Files:**
- Create: `src/tools/stats/flush.rs`
- Modify: `src/main.rs` (spawn it after the transport is chosen)

**Interfaces:**
- Produces: `pub fn spawn(collector: Arc<Collector>, db: PathBuf, every: Duration)` and the testable core `pub(crate) fn flush_once(conn: &mut Connection, delta, now) -> rusqlite::Result<()>`.

The three-step dance from the spec is load-bearing and each step has its reason:

1. `mem::take` under the lock, then **drop the lock** before touching the database - concurrent calls accumulate into a fresh map instead of waiting on I/O.
2. Every row of the delta in **one** `BEGIN IMMEDIATE` transaction. `Immediate` because a deferred transaction that upgrades to a write lock returns `SQLITE_BUSY_SNAPSHOT`, which `busy_timeout` does not retry - it fails at once and reads like a deadlock in the log.
3. On error, merge the delta back by addition. Safe **only** because step 2 is a single transaction; a loop of autocommitted upserts would double-count every row already committed, and no test would show it because it needs a failure mid-flush.

Also: a heartbeat writes `sessions.last_seen` unconditionally at most every 60 s even when the delta is empty. Wave 1 learned this on the housekeeping lease - a process that writes only when it has something to say is indistinguishable from a dead one.

- [ ] **Step 1** Write the failing tests: flushing the same delta twice does not double the stored counts; a read-only connection makes the flush fail and the delta comes back intact with the database unchanged; the heartbeat updates `last_seen` with an empty delta.
- [ ] **Step 2** Run them - fail to compile.
- [ ] **Step 3** Implement. The loop runs in `spawn_blocking` with plus/minus 20% jitter on the interval - dozens of processes started by one client would otherwise flush in lockstep. A flush error is counted in `Health` and logged, never propagated, never a panic.
- [ ] **Step 4** Run - PASS.
- [ ] **Step 5** Commit `feat(stats): flush deltas in one transaction, and take them back if it fails`

---

### Task 5: sessions and the catalogue - including the tools nobody calls

**Files:**
- Modify: `src/tools/stats/db.rs`, `src/main.rs` (write the session row at startup)

**Interfaces:**
- Produces: `pub fn upsert_session(conn, &SessionRow)` and `pub fn record_catalog(conn, fingerprint, tools)`.

`tool_catalog` is the reason this wave exists. Unused tools have no `tool_agg` rows at all, so without a list of what the build exposes, "which of the 132 tools does nobody call" is unanswerable - and that question is the point of collecting anything.

The session row carries `instance_id` (from `core::instance`), the MCP `session_id`, pid, transport, version, the client name and version from `initialize`, `cwd` and the optional `FS_MCP_STATS_LABEL`. Two facts settled during design, not to be re-derived: stdio has **no** session id in the protocol (one process is one session - use the synthesized per-process id), and in HTTP the id is reachable only from `ctx.extensions.get::<http::request::Parts>()` then the `mcp-session-id` header. There is no `ended_at` column: hosts kill stdio servers without ceremony, so the field would almost always lie; liveness is `last_seen` against three heartbeats.

- [ ] **Step 1** Write tests: a session row upserts rather than duplicating; the catalogue is idempotent per fingerprint; a summary LEFT JOIN over the catalogue reports a never-called tool as zero rather than omitting it.
- [ ] **Step 2** Run them - fail.
- [ ] **Step 3** Implement, writing the session row and the catalogue once at startup, inside `spawn_blocking`, failure logged and swallowed.
- [ ] **Step 4** Run - PASS.
- [ ] **Step 5** Commit `feat(stats): record the session and every tool this build exposes`

---

### Task 6: the two read tools

**Files:**
- Create: `src/tools/stats/server.rs` (its own `#[tool_router]`, merged in `build_tool_router`)

One tool per verb, matching every other group in this server (`mem_*`, `s3_*`, `win_*`); there is no `action`-dispatching tool in this codebase and this is not the place to introduce the first one. Both descriptions obey `docs/TOOL_STYLE.md` and are measured by `tool_surface_guard` - budget first, prose second.

- `stats_summary { group_by, since, until, tool, session_id }` - per-outcome counts, error rate, mean and max latency, bytes, **including tools with zero calls**, plus a `health` section. **Build that channel, do not assume it exists** — the wave-2 review found that `logging::degraded_reason()` had no reader that could work, and the fix carries the reason in `Plan` plus a marker file beside the log; there is no general-purpose health channel in this crate. `health` reports: last successful flush, flush error count, last error, database path, AND the logging subsystem's degraded reason when there is one. That last part matters because the two failures share a cause — an unusable state root breaks logging and statistics together — and an operator asking one subsystem why it is quiet should not have to know to ask the other. In stdio there may be no log subscriber at all to say any of it.
- `stats_sessions { status }` - sessions with metadata and `live | stale`, plus a `skew` flag when a row's `last_seen` is in the reader's future. Skewed rows land in the wrong bucket permanently and cannot be repaired, so they are detected and reported, never "corrected".

Reads use a **separate read-only connection** so a query can never take the write lock or block a flush. No `prune` tool: a multi-second `DELETE` holding the single write lock must not be invokable by any agent.

- [ ] **Step 1** Write tests over a seeded temp database: a zero-call tool appears with zeros; the error rate is computed from the four outcome counters rather than from `ok` alone; `health` reports a flush failure.
- [ ] **Step 2** Run - fail.
- [ ] **Step 3** Implement.
- [ ] **Step 4** Run, plus a live handshake: `tools/list` shows both tools and `tool_surface_guard` passes.
- [ ] **Step 5** Commit `feat(stats): report usage, the zero-use tail, and the subsystem's own health`

---

### Task 7: retention, under the lease that already exists

**Files:**
- Modify: `src/core/housekeeping.rs` (a `stats` kind), `src/tools/stats/db.rs` (compaction)

The spec is explicit: **reuse the marker-file lease, do not add a `housekeeping` table**. Invariant I9 is already honestly reduced to "one lease, one age rule" - a second mechanism would finish it off.

Compaction is not deletion: rows older than `FS_MCP_STATS_DETAIL_DAYS` are summed into `tool_daily` (instance and session dropped) and only then removed, so the history worth keeping survives in a few megabytes while the detail does not accumulate. Two lessons from waves 1-2 apply directly: `Sweep::Ran` does not distinguish "ran" from "ran but the lease was not recorded", so if compaction needs that distinction it must add a variant rather than infer one; and the days-to-seconds conversion must saturate, because an absurd env value would otherwise panic in housekeeping before the transport starts.

- [ ] **Step 1** Write tests: compaction sums detail into `tool_daily` and removes exactly the compacted rows; running it twice does not double the daily totals; `FS_MCP_STATS_DETAIL_DAYS=0` disables it.
- [ ] **Step 2** Run - fail.
- [ ] **Step 3** Implement and call it from the housekeeping pass.
- [ ] **Step 4** Run - PASS.
- [ ] **Step 5** Commit `feat(stats): compact detail into daily history under the shared lease`

---

### Task 8: prove it on the real server, then write it down

**Files:** `README.md`, `CLAUDE.md`, `CHANGELOG.md`, and the spec if anything was built differently

- [ ] **Step 1 - END TO END, reported verbatim.** With `FS_MCP_STATE_DIR` on a temp directory: run a real stdio session (initialize, notifications/initialized, several `tools/call` including one that fails with invalid params and one `run_command` killed by its timeout), stop the server, start a second one and read `stats_summary`. Show: the killed `run_command` counted as `err_flagged` and NOT as `ok`; the bad-arguments call counted as `err_params`; a never-called tool appearing with zeros; `health` naming the database. Paste commands and output.
- [ ] **Step 2** Two servers concurrently: both write, no row is lost, `stats_sessions` lists two live sessions.
- [ ] **Step 3** Mutation-test the load-bearing parts only - `classify`, the flush's take/merge-back, compaction - per the project rule that mutation testing is mandatory where code deletes or overwrites data or guards an invariant, and accepted-with-a-comment elsewhere. Report the surviving mutants and why each is accepted.
- [ ] **Step 4** Docs, then the full gates.
- [ ] **Step 5** Commit `docs: record the statistics subsystem and what it measured`

---

## Self-review notes

- **Spec coverage:** collection (Tasks 2-3), flush and heartbeat (Task 4), schema (Task 1) with sessions and catalogue (Task 5), the two tools (Task 6), retention (Task 7), proof and docs (Task 8).
- **Deliberately not built:** a latency histogram (mean and max are exact; honest quantiles need DDSketch and nobody has asked), `bytes_in` (a re-serialisation per call), a `prune` tool (a long `DELETE` under the write lock, invokable by any agent), an `ended_at` column (it would lie).
- **Type consistency:** `Outcome`, `Collector`, `Agg`, `Health` are spelled identically across tasks; `Sweep` and the lease come from wave 1 unchanged.
- **The risk to watch:** Task 3 touches `call_tool`, the one seam every tool call passes through. A mistake there is not a statistics bug, it is a server bug - which is why `record` is infallible by signature and why the full suite, not merely the new tests, must stay green at Step 4.
