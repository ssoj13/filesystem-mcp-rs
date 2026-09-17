# Design: unified state dir, multi-process logging, tool-call statistics

Date: 2026-09-17 · Status: approved design, not yet implemented · Crate: filesystem-mcp-rs

## 1. Why

Dozens of `filesystem-mcp-rs` processes run at once (one per agent session, stdio transport;
plus an HTTP mode where one process serves several MCP sessions). Three problems, one root
cause — nothing in the server has a single, systematic answer for "where does state live and
how do many processes share it":

1. **State is scattered over four roots**, two of which differ per OS and even per Windows
   account (`AppData\Local` vs `AppData\Roaming`), and some still carry the old
   `computer-mcp-rs` name from the extracted crate.
2. **Logging is effectively absent in the default deployment**: in stdio mode without `--log`
   no subscriber is installed at all (`src/core/logging.rs:26-33`), so every `warn!` is dropped.
3. **There is no usage data**: we cannot say which of the ~130 tools are used, which fail, or
   which nobody has ever called — the one fact needed to keep the toolset slim.

The design goal is not three features but three applications of one rule: **one place, one
resolver, one writer per resource, no shared mutable file between processes.**

## 2. Current state (verified, file:line)

> **Historical as of wave 1 (2026-09-17).** The table below is the layout *before* the state-dir
> unification, kept as the record of what the move started from. Every row now resolves through
> `core::paths` under `~/.filesystem-mcp-rs/` (§4); the `main.rs` line numbers have also moved.

| What | Where before wave 1 |
|---|---|
| `panic.log` | `<data_local>/filesystem-mcp-rs/` — `main.rs:7473` |
| `memory2.db` | `<data_local>/filesystem-mcp-rs/` — `main.rs:7614` |
| ocrs models | `<data>/computer-mcp-rs/ocrs` — `ocrs_local.rs:37` |
| window layouts | `<data>/computer-mcp-rs/layouts` — `portable.rs:70` |
| ctl safety state | `<data>/computer-mcp-rs` — `safety.rs:220` |
| capture/annotate images | `<temp>/computer-mcp-rs` — `capture.rs:179`, `annotate.rs:100` |
| `run_command` output | `<temp>/filesystem-mcp` — `main.rs:7813` |
| temporary `.bat` | `<temp>` — `process.rs:762` |

Other verified facts this design relies on:

- `call_tool` is a hand-written override at `src/main.rs:7393` — the single tool-dispatch seam.
  `LlmMcpServer` (`src/tools/llm/mod.rs:425`) defines only `get_info` and is never independently
  served; its tools are invoked from inside `FileSystemServer`'s own `#[tool]` fns, so they pass
  through the same seam. HTTP transport funnels through it too. There is no bypass.
- Tool-level failure is reported **inside a successful result**: `r.is_error = Some(...)` at
  `main.rs:5869` (parse error), `main.rs:6422` (`run_command` killed/timed out/cancelled),
  `main.rs:6483` (`kill_process` failed). `run_command` deliberately reports `is_error=false`
  for a non-zero exit code (`main.rs:6411-6421`).
- `Cargo.toml:26` pins **rmcp 3.1.3** (CLAUDE.md wrongly says 3.1.4 — fixed in wave 4).
- rmcp 3.1.3: `RequestContext` has no session id. Client identity is
  `context.peer.peer_info().map(|i| i.client_info.clone())`. The HTTP session id is reachable
  only via `ctx.extensions.get::<http::request::Parts>()` → `mcp-session-id` header. Stdio has
  no session concept at all.
- `CallToolResponse` has three variants: `Complete` / `InputRequired` / `Task` (rmcp `model/mrtr.rs`).
- `src/env_spec.rs:28-33` (`vars()`) is the ONE registry of `FS_MCP_*`; groups are added as
  `fn *_vars()` (see `memory_vars()` at `:56-69`).
- `rusqlite` is already an unconditional dependency (`Cargo.toml:98`); `memory_v2` sets
  `busy_timeout` per connection and `journal_mode=WAL` once (`memory_v2/sqlite.rs:87-92, 209`),
  but never `journal_size_limit` — a latent unbounded `-wal` growth, tracked in wave 4.

## 3. Invariants (each one removes a class of bugs)

**I1 — One state root, one resolver.** `core::paths::state_dir()` = `dirs::home_dir()/.filesystem-mcp-rs`,
identical on Windows, macOS and Linux. Every path is derived from it. No `data_dir()`,
`data_local_dir()` or `temp_dir()` call survives anywhere in the crate. A future "I'll just put
it here" cannot happen because there is nowhere else to put it.

**I2 — No file is written by two processes.** Logs are per process; the stats DB is per-row
partitioned by `instance_id` so two processes never target the same row. Rotation, interleaving
and rename races cease to exist rather than being handled.

**I3 — Everything persisted is additive.** Every stats column is an INTEGER counter merged with
`x = x + excluded.x` (or `max()`), so a write never needs to read first. Read-then-write races
and `SQLITE_BUSY_SNAPSHOT` have no code path to occur on.

**I4 — The hot path cannot fail.** `Collector::record()` returns `()` and only locks a mutex and
adds integers. Everything fallible happens in the flush task inside `spawn_blocking` (rusqlite
is blocking). Telemetry cannot fail or stall a tool call, by signature.

**I5 — Outcome is classified in exactly one exhaustive place.** `fn classify(&Result<CallToolResponse,
McpError>) -> Outcome` matches with **no `_` arm** over the response variants, over `is_error`
inside `Complete`, and over the `McpError` code. When rmcp adds a variant the build breaks
instead of silently counting it as success.

**I6 — Health is data, not a log line.** Subsystem health is returned by the stats tool from the
in-process collector, so a broken telemetry path reports itself even where logging is off.

**I7 — One door to the database.** A single `open()` applies WAL, `synchronous=NORMAL`,
`busy_timeout`, `journal_size_limit` and the `user_version` check. Mixed binary versions against
one shared file cannot silently write into columns whose meaning changed.

**I8 — Closed key sets.** Tool names are interned against the router's own list; anything else
becomes `__unknown`. Cardinality cannot grow from the wire.

**I9 — One retention mechanism.** A single leased housekeeping sweep applies age rules to
`tmp/`, `logs/` and the stats DB. One process does it per interval, not fifty.

## 4. Wave 1 — unified state directory

```
~/.filesystem-mcp-rs/
  stats.db        tool-call statistics (wave 3)
  memory2.db      memory store (migrated)
  panic.log
  logs/           per-process log files (wave 2)
  ocrs/           OCR models
  layouts/        window layouts
  safety/         ctl safety state
  tmp/            captures, run_command output, temporary .bat — swept by age
```

`core::paths` exposes `state_dir()` plus one accessor per subdir, each creating the directory on
first use. All call sites listed in §2 are rewritten to use them.

**Migration, per migrated file** (`memory2.db`, `ocrs/`, `layouts/`, `safety/`):

- old exists, new absent → `rename` (same volume; falls back to copy+remove across volumes), logged;
- both exist → **do not guess**. For `memory2.db` the memory store refuses to initialise and
  reports which file to keep — memory tools are then visibly unavailable rather than silently
  bound to the wrong database. For the regenerable dirs (`ocrs/`, `layouts/`, `safety/`) the new
  location wins and the old one is left untouched for manual cleanup;
- neither exists → create fresh.

`tmp/` is swept at startup: files older than `FS_MCP_TMP_KEEP_HOURS` (default 24) are deleted,
under the same lease as §5 so only one process sweeps.

## 5. Wave 2 — logging that survives dozens of processes

**No shared log file.** Each process writes `logs/<YYYY-MM-DD>/fsmcp-<pid>-<instance>.log`.
Rotation as a mechanism disappears: a new process is a new file, a new day is a new directory.
No renames, no interleaved partial lines, no per-process rotation timers fighting each other.

**File logging is on by default, including stdio.** The existing prohibition is specifically about
**stderr** — any stderr output during handshake breaks MCP clients (`logging.rs:27-28`) — and it
stays. A file sink is safe, and without it every `warn!` in the default deployment is lost
(`logging.rs:32`). `--log` keeps overriding the path; `FS_MCP_LOG` sets the level, `off` disables.

**Retention.** The housekeeping sweep deletes log directories older than `FS_MCP_LOG_KEEP_DAYS`
(default 14) and, within the current day, files over `FS_MCP_LOG_MAX_MB` total, oldest first. The
lease is a row in `stats.db` (`housekeeping(kind, leased_until, by_instance)`): one process per
interval does the work, the rest skip. If stats are disabled the sweep falls back to a lock file
in the state root — the same lease semantics, no second mechanism.

## 6. Wave 3 — tool-call statistics

### 6.1 Collection

`Collector` holds `Mutex<HashMap<(ToolId, Bucket), Agg>>` plus process metadata. The bucket is
**computed at call time** (`floor(unix_epoch / 600)`, UTC) and is part of the map key — otherwise
a long session attributes every call to the bucket in which the flush happened.

In `call_tool` (`main.rs:7393`): take `Instant::now()`, run the existing dispatch, then
`classify()` the outcome (I5) and record. `bytes_out` is the sum of the already-materialised
content-block lengths on the `Complete` arm only — no re-serialisation, no extra allocation.
`bytes_in` is not recorded: measuring it would require re-serialising the arguments.
`InputRequired` / `Task` are counted as `deferred` with no latency, since they are not completions.

Counters per row: `ok`, `err_flagged` (an `Ok` carrying `is_error=true`), `err_params` (rmcp
`-32602`, i.e. the agent got the schema wrong), `err_internal` (`-32603`, i.e. the tool broke),
`deferred`, `ns_total`, `ns_max`, `bytes_out`. Splitting these four is the difference between a
table that reports the truth and one that reports ~0% errors for a server that is failing
constantly (see the `is_error` sites in §2).

No latency histogram in v1: `ns_total`/`ns_max` give exact mean and max; honest quantiles would
need a DDSketch-style log grid (γ=1.09, ~64 bins, ≤4.5% relative error) and are deferred until
someone actually needs them. A 16-bin log2 histogram was rejected: ±41%/−29% error makes a printed
`p95` a lie, and storing bins as a TEXT blob would break I3.

### 6.2 Flush

Every ~5 s with ±20% jitter, inside `spawn_blocking`:

1. `let delta = mem::take(&mut *guard)` under the lock, then **drop the lock** — concurrent calls
   accumulate into a fresh map.
2. Write every row of `delta` in **one** `BEGIN IMMEDIATE` transaction. `Immediate` is required:
   a deferred transaction that upgrades to a write lock returns `SQLITE_BUSY_SNAPSHOT`, which
   `busy_timeout` does not retry.
3. On error, merge `delta` back into the live map by addition. This is safe **only** because
   step 2 is a single transaction — a loop of autocommitted upserts would double-count every row
   already committed.

A heartbeat (`UPDATE sessions SET last_seen`) runs unconditionally at most every 60 s even when
the delta is empty; otherwise an idle-but-alive session looks dead. Liveness is derived from
`last_seen` (`stale := last_seen < now - 3 × heartbeat`); there is no `ended_at` column, because
hosts kill stdio servers without ceremony and the field would almost always lie. `pid` is stored
for debugging only, never for liveness.

A SIGKILL loses exactly the delta accumulated since the last flush (≤5 s) — no partial rows, no
corruption. Tool output states that counts may lag by up to one flush interval.

### 6.3 Schema (`~/.filesystem-mcp-rs/stats.db`, `PRAGMA user_version = 1`)

```sql
CREATE TABLE tool_agg (                    -- STRICT, WITHOUT ROWID
  bucket INTEGER NOT NULL, tool TEXT NOT NULL,
  instance_id TEXT NOT NULL, session_id TEXT NOT NULL,
  ok INTEGER NOT NULL, err_flagged INTEGER NOT NULL,
  err_params INTEGER NOT NULL, err_internal INTEGER NOT NULL,
  deferred INTEGER NOT NULL,
  ns_total INTEGER NOT NULL, ns_max INTEGER NOT NULL, bytes_out INTEGER NOT NULL,
  PRIMARY KEY (bucket, tool, instance_id, session_id));
CREATE INDEX ix_agg_session ON tool_agg(session_id, bucket);

CREATE TABLE tool_daily (                  -- compacted history, instance/session dropped
  day TEXT NOT NULL, tool TEXT NOT NULL,
  ok INTEGER NOT NULL, err_flagged INTEGER NOT NULL,
  err_params INTEGER NOT NULL, err_internal INTEGER NOT NULL,
  deferred INTEGER NOT NULL,
  ns_total INTEGER NOT NULL, ns_max INTEGER NOT NULL, bytes_out INTEGER NOT NULL,
  PRIMARY KEY (day, tool)) WITHOUT ROWID;

CREATE TABLE tool_catalog (                -- every tool this build exposes
  fingerprint TEXT NOT NULL, tool TEXT NOT NULL,
  PRIMARY KEY (fingerprint, tool)) WITHOUT ROWID;

CREATE TABLE sessions (
  instance_id TEXT NOT NULL, session_id TEXT NOT NULL,
  pid INTEGER, transport TEXT, version TEXT, features TEXT,
  client_name TEXT, client_version TEXT, cwd TEXT, label TEXT,
  started_at INTEGER, last_seen INTEGER,
  PRIMARY KEY (instance_id, session_id));

CREATE TABLE housekeeping (kind TEXT PRIMARY KEY, leased_until INTEGER, by_instance TEXT);
```

`instance_id` is in the primary key, so **two processes never write the same row** — cross-process
double counting is structurally impossible and the only interaction left is file write-lock
contention (~2 transactions/second at fifty processes). The key **starts with `bucket`** so that
"sum by tool over a time range" is a prefix range scan rather than a full scan, and so pruning
deletes a contiguous prefix.

`tool_catalog` is what makes the **zero-use tail** answerable: unused tools have no `tool_agg`
rows at all, so without the catalogue "which of the 130 tools does nobody call" is unanswerable.
`summary` LEFT JOINs it, and a zero shows up as a zero.

`session_id` is the `mcp-session-id` header in HTTP mode and the synthesised per-process id in
stdio (where one process is one session by definition).

Errors are stored as counters only — never message text, which would drag filesystem paths
(`main.rs:369/389`) into a long-lived database. `cwd` **is** stored: the database is per-user,
under the user's own home directory.

### 6.4 Tools

`stats_summary` and `stats_sessions`, in `src/tools/stats_telemetry/server.rs` behind its own
`#[tool_router]`. One tool per verb, matching every other group in this server (`mem_*`, `s3_*`,
`win_*`); there is no `action`-dispatching tool anywhere in the codebase and this is not the
place to introduce the first one.

- `stats_summary { group_by, since, until, tool, session_id }` → counts split by outcome class,
  error rate, mean/max latency, bytes, **including zero-use tools**, plus a `health` section
  (`last_flush_at`, `flush_errors`, `last_error`, `db_path`) read from the live collector (I6).
- `stats_sessions { status }` → sessions with metadata, `live|stale`, and a `skew` flag for a
  writer whose `last_seen` is in the reader's future (skewed rows land in the wrong bucket
  permanently and are unrepairable — detect, never "correct").

No `prune` tool: a multi-second `DELETE` holding the single write lock must not be invokable by
any agent. Retention is housekeeping (I9): 14 days of 10-minute detail, then compaction into
`tool_daily`, which stays for years in a few megabytes.

Reads use a separate `SQLITE_OPEN_READ_ONLY` connection so a query can never take the write lock.

### 6.5 Config

New `stats_vars()` in `src/env_spec.rs`, extended into `vars()` — the only registration point:
`FS_MCP_STATS` (`on`), `FS_MCP_STATS_DB` (blank = `~/.filesystem-mcp-rs/stats.db`),
`FS_MCP_STATS_FLUSH_SEC` (`5`), `FS_MCP_STATS_DETAIL_DAYS` (`14`), `FS_MCP_STATS_LABEL` (blank).
Waves 1-2 add `FS_MCP_TMP_KEEP_HOURS` (`24`), `FS_MCP_LOG` (`warn`), `FS_MCP_LOG_KEEP_DAYS`
(`14`), `FS_MCP_LOG_MAX_MB` (`512`). Feature `stats-tools`, added to `default`; the only new
dependency surface is `rusqlite`, already unconditional, so no cross-platform build risk.

If WAL cannot be established (network share, sync-backed directory), stats are **disabled with
the reason recorded in `health`** rather than falling back to `journal_mode=delete`, which would
serialise all fifty processes on one global file lock.

## 7. Wave 4 — documentation and debts

- CLAUDE.md: rmcp version corrected to 3.1.3; new state layout; logging behaviour.
- `env_spec` help texts for existing keys still describe the old paths.
- `memory_v2` does not set `journal_size_limit` — same latent unbounded `-wal` growth this design
  fixes for stats; patch separately, not inside these waves.

## 8. Testing

- **Paths**: `state_dir()` resolution per OS; every subdir accessor creates its directory; a
  repo-wide test asserting no `data_dir`/`data_local_dir`/`temp_dir` call remains outside
  `core::paths` (this is what keeps I1 true over time).
- **Migration**: old-only → moved; both → memory store refuses with the expected message;
  neither → created.
- **Classification**: a table-driven test over every `CallToolResponse` variant, `is_error` true
  and false, and both error codes — including a `run_command`-shaped result that is `Ok` with
  `is_error=true` and must count as `err_flagged`, not `ok`.
- **Flush**: delta take/merge-back on a failed transaction does not double count; repeated flushes
  of the same delta are idempotent; bucket flooring at a 600-second boundary.
- **Concurrency**: two collectors flushing into one temporary database concurrently produce exactly
  the expected sums — the property the whole design exists for.
- **Failure**: an unwritable database path never breaks `call_tool` and is reported in `health`.
- **Logging**: two processes logging simultaneously produce two intact files with no interleaving;
  the sweep deletes only what is past retention.
