//! The in-memory collector: every tool call counted, on a path that cannot fail.
//!
//! Counters accumulate in one map keyed by `(10-minute bucket, tool)` and the flush task drains
//! them with [`Collector::take_delta`], writes the drained rows through [`super::db::UPSERT_AGG`]
//! and hands anything it could not write back with [`Collector::merge_back`]. Nothing here
//! touches the database, the clock beyond the [`SystemTime`] it is given, or the filesystem.
//!
//! Three rules decide the shape, each of them paid for:
//!
//! 1. **The bucket is computed at call time and is part of the key.** Taken at flush time
//!    instead, a long-lived session would attribute every call it ever made to whichever ten
//!    minutes the flush happened to land in. Wave 1 shipped a sweep that aged entries by the
//!    wrong clock for exactly this reason.
//! 2. **The tool name is interned against the router's own list** and anything else becomes
//!    [`UNKNOWN_TOOL`]. A name arrives from the wire *before* the router rejects it - rmcp
//!    answers an unknown tool with `invalid_params("tool not found")`, which
//!    [`super::outcome::classify`] scores [`Outcome::ErrParams`], so those calls do reach this
//!    map - and an un-interned key would grow it without bound from a single typo.
//! 3. **[`Collector::record_interned`] cannot fail**: no `Result`, no I/O, no allocation beyond
//!    the map entry. It takes a mutex, adds integers, releases. Everything fallible belongs to
//!    the flush.
//!
//! Used from `main.rs`'s `call_tool`, once per tool call, on the way out.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rmcp::model::{ContentBlock, ResourceContents};

use super::outcome::Outcome;

/// The tool name every call this build does not have a route for is attributed to.
///
/// Double-underscored so it cannot collide with a real tool: `tool_surface_guard` rejects a
/// leading underscore in a tool name, so no route can ever be spelled this way.
pub const UNKNOWN_TOOL: &str = "__unknown";

/// Seconds per aggregation bucket, matching `tool_agg.bucket` in [`super::db`].
pub const BUCKET_SECS: u64 = 600;

/// One row's worth of counters, in the order [`super::db::UPSERT_AGG`] binds them.
///
/// Every field is a plain `u64` merged by addition except [`Counts::ns_max`], which takes the
/// larger - the same merge the database performs, so an in-memory merge and a flushed one cannot
/// disagree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// Calls that completed and reported no failure.
    pub ok: u64,
    /// Calls that completed carrying `is_error = true`.
    pub err_flagged: u64,
    /// Calls rmcp rejected as `-32602`, including a tool name this build does not have.
    pub err_params: u64,
    /// Calls that broke below the handler.
    pub err_internal: u64,
    /// Calls that did not complete, plus the unrecognised response shapes - see
    /// [`Outcome::UnknownShape`], which is stored here and counted apart in [`Health`].
    pub deferred: u64,
    /// Summed wall-clock nanoseconds of the calls counted here.
    pub ns_total: u64,
    /// The slowest single call counted here, in nanoseconds.
    pub ns_max: u64,
    /// Summed content-block payload bytes returned by the calls counted here.
    pub bytes_out: u64,
}

impl Counts {
    /// Merge `other` into `self` with the database's semantics: add, except `ns_max`, which takes
    /// the larger.
    ///
    /// Saturating rather than wrapping because a counter that silently restarts at zero after
    /// `u64::MAX` would make a rate look negative; saturating at least stops being wrong in a
    /// direction anyone can misread. Neither is reachable - `ns_total` would need ~584 years of
    /// accumulated tool time - but the arithmetic must not be a debug-build panic on the hot path.
    fn merge(&mut self, other: Self) {
        self.ok = self.ok.saturating_add(other.ok);
        self.err_flagged = self.err_flagged.saturating_add(other.err_flagged);
        self.err_params = self.err_params.saturating_add(other.err_params);
        self.err_internal = self.err_internal.saturating_add(other.err_internal);
        self.deferred = self.deferred.saturating_add(other.deferred);
        self.ns_total = self.ns_total.saturating_add(other.ns_total);
        self.ns_max = self.ns_max.max(other.ns_max);
        self.bytes_out = self.bytes_out.saturating_add(other.bytes_out);
    }
}

/// What one map entry is keyed by: the bucket the call happened in, and the interned tool name.
///
/// `bucket` first because that is the order `tool_agg`'s primary key uses, so a drained delta
/// binds straight into it without re-ordering.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    /// `floor(unix_epoch / 600)`, UTC, taken when the call finished.
    pub bucket: i64,
    /// An interned name: either one the router serves, or [`UNKNOWN_TOOL`].
    pub tool: Arc<str>,
}

/// A drained set of counters, ready for the flush task to bind and write.
pub type Delta = HashMap<Key, Counts>;

/// What the collector can say about itself, for the health section of the read tools.
///
/// A statistics subsystem that dies quietly is worse than none, so these are reported rather than
/// logged: under stdio there may be no subscriber at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Health {
    /// Every call this process has recorded since it started, drained deltas included.
    pub calls: u64,
    /// Calls whose response was a [`CallToolResponse`](rmcp::model::CallToolResponse) variant
    /// this build does not know.
    ///
    /// Counted apart from [`Counts::deferred`], which stores it, because an operator must be able
    /// to tell "the server deferred" from "this build does not understand rmcp's answer". They
    /// are the same number in the database and entirely different problems.
    pub unknown_shape: u64,
    /// Rows waiting for the next flush. Growing without bound means the flush is not running.
    pub pending_rows: usize,
}

/// The in-memory counters for one server process.
///
/// Built once in `FileSystemServer::new` from the router's own tool list, and shared with the
/// flush task; `None` in place of one is how `FS_MCP_STATS=off` is expressed, so that switching
/// statistics off costs the hot path a single branch rather than a mutex nobody drains.
pub struct Collector {
    /// The router's tool names, interned once so that a map key is an `Arc` clone rather than an
    /// allocation. `Arc<str>: Borrow<str>` is what lets a wire name be looked up without one.
    known: HashSet<Arc<str>>,
    /// [`UNKNOWN_TOOL`] interned, so attributing a call to it costs no allocation either.
    unknown: Arc<str>,
    /// The counters themselves. Held only for the few instructions it takes to add integers.
    rows: Mutex<Delta>,
    /// See [`Health::calls`]. Separate from `rows` because a drain must not reset it.
    calls: AtomicU64,
    /// See [`Health::unknown_shape`].
    unknown_shape: AtomicU64,
}

impl Collector {
    /// Intern `names` - the router's tool list - and start with an empty map.
    pub fn new<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            known: names
                .into_iter()
                .map(|n| Arc::from(n.as_ref()))
                .collect::<HashSet<Arc<str>>>(),
            unknown: Arc::from(UNKNOWN_TOOL),
            rows: Mutex::new(Delta::new()),
            calls: AtomicU64::new(0),
            unknown_shape: AtomicU64::new(0),
        }
    }

    /// Resolve a name from the wire to the interned key it will be counted under.
    ///
    /// Public and separate from [`Collector::record_interned`] because the seam interns *before*
    /// dispatch, where the request still owns its name, and records after it. One hash lookup and
    /// at most an `Arc` clone; never an allocation.
    pub fn intern(&self, tool: &str) -> Arc<str> {
        self.known
            .get(tool)
            .cloned()
            .unwrap_or_else(|| Arc::clone(&self.unknown))
    }

    /// Count one finished call under a name resolved by [`Collector::intern`].
    ///
    /// Infallible by signature, and the body keeps that promise: a poisoned mutex is recovered
    /// from rather than unwrapped, because a panic somewhere else in the process is no reason for
    /// the *next* tool call to panic too.
    pub fn record_interned(
        &self,
        tool: Arc<str>,
        outcome: Outcome,
        ns: u64,
        bytes_out: u64,
        now: SystemTime,
    ) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if outcome == Outcome::UnknownShape {
            self.unknown_shape.fetch_add(1, Ordering::Relaxed);
        }

        let mut one = Counts {
            ns_total: ns,
            ns_max: ns,
            bytes_out,
            ..Counts::default()
        };
        match outcome {
            Outcome::Ok => one.ok = 1,
            Outcome::ErrFlagged => one.err_flagged = 1,
            Outcome::ErrParams => one.err_params = 1,
            Outcome::ErrInternal => one.err_internal = 1,
            // Both are stored in the one "did not complete" column; the unknown shape is what the
            // atomic above keeps apart. See [`Health::unknown_shape`].
            Outcome::Deferred | Outcome::UnknownShape => one.deferred = 1,
        }

        let key = Key {
            bucket: bucket_of(now),
            tool,
        };
        self.lock().entry(key).or_default().merge(one);
    }

    /// Count one finished call by name, interning it first.
    ///
    /// The plain form, used by the tests and by any caller that holds the name and not the
    /// interned handle. Delegates, so there is one accumulation path and not two.
    pub fn record(&self, tool: &str, outcome: Outcome, ns: u64, bytes_out: u64, now: SystemTime) {
        self.record_interned(self.intern(tool), outcome, ns, bytes_out, now);
    }

    /// Take everything accumulated so far, leaving the map empty.
    ///
    /// The flush writes what it is given here and hands back, via [`Collector::merge_back`],
    /// whatever it could not write. Taking rather than copying is what keeps the lock held for
    /// one `mem::take` instead of for the length of a database transaction.
    pub fn take_delta(&self) -> Delta {
        std::mem::take(&mut *self.lock())
    }

    /// Return a delta the flush could not write, merging it into whatever has accumulated since.
    ///
    /// Additive, so a row that was recorded again in the meantime keeps both contributions; the
    /// alternative - replacing - would drop the newer calls, and inserting a second row is
    /// impossible because the key is the same.
    pub fn merge_back(&self, delta: Delta) {
        let mut rows = self.lock();
        for (key, counts) in delta {
            rows.entry(key).or_default().merge(counts);
        }
    }

    /// What this collector can say about itself; see [`Health`].
    pub fn health(&self) -> Health {
        Health {
            calls: self.calls.load(Ordering::Relaxed),
            unknown_shape: self.unknown_shape.load(Ordering::Relaxed),
            pending_rows: self.lock().len(),
        }
    }

    /// Take the counter lock, recovering a poisoned one.
    ///
    /// Nothing inside the critical section can panic - it is integer arithmetic on a map entry -
    /// so poisoning can only arrive from a panic elsewhere while this lock happened to be held,
    /// and the counters behind it are still consistent. Propagating that panic into every later
    /// tool call is the one outcome this subsystem must never produce.
    fn lock(&self) -> std::sync::MutexGuard<'_, Delta> {
        self.rows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The 10-minute bucket a call belongs to: `floor(unix_epoch / 600)`, UTC.
///
/// A `SystemTime` before the epoch cannot come from a call that just finished, but the clock is
/// the operator's and this function may not fail, so it floors to bucket zero rather than
/// panicking: one misattributed row beats a dead tool call.
fn bucket_of(now: SystemTime) -> i64 {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    (secs / BUCKET_SECS) as i64
}

/// Payload bytes of an already-materialised content list.
///
/// Measured off the blocks the tool has *already* built, never by re-serialising the result: a
/// second serialisation would double the cost of every large read, which is the one thing this
/// subsystem is not allowed to do. `bytes_in` is not measured at all for the same reason - it
/// would mean re-serialising the arguments on every call.
///
/// A `ResourceLink` is a URI and a name, not a payload, and contributes nothing; so does a block
/// from an rmcp version newer than this build, which `#[non_exhaustive]` lets through. Both
/// under-count rather than guess, which is the safe direction for a size.
pub fn bytes_of(content: &[ContentBlock]) -> u64 {
    content
        .iter()
        .map(|block| match block {
            ContentBlock::Text(text) => text.text.len(),
            ContentBlock::Image(image) => image.data.len(),
            ContentBlock::Audio(audio) => audio.data.len(),
            ContentBlock::Resource(resource) => match &resource.resource {
                ResourceContents::TextResourceContents { text, .. } => text.len(),
                ResourceContents::BlobResourceContents { blob, .. } => blob.len(),
                _ => 0,
            },
            ContentBlock::ResourceLink(_) => 0,
            _ => 0,
        })
        .fold(0u64, |total, len| total.saturating_add(len as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A collector that serves two tools, which is all any of these tests needs.
    fn collector() -> Collector {
        Collector::new(["read_text_file", "grep_files"])
    }

    /// `t` seconds after the epoch, so that a test can state the bucket it expects.
    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(secs)
    }

    /// The single row of a one-row delta, by tool name.
    fn only_row(delta: &Delta, tool: &str) -> Counts {
        let mut found = delta.iter().filter(|(key, _)| &*key.tool == tool);
        let (_, counts) = found.next().expect("a row for this tool");
        assert!(
            found.next().is_none(),
            "expected exactly one row for {tool}"
        );
        *counts
    }

    /// Two calls 700 seconds apart are two rows, even though they are flushed together.
    ///
    /// This is the property the whole key exists for: the bucket is a fact about *the call*, not
    /// about the flush that happened to carry it. Taken at flush time, both of these would land
    /// in whichever ten minutes the drain ran in and the second one's latency would be reported
    /// against the wrong window.
    #[test]
    fn two_calls_in_different_buckets_stay_two_rows() {
        let c = collector();
        c.record("read_text_file", Outcome::Ok, 5, 0, at(1_000));
        c.record("read_text_file", Outcome::Ok, 7, 0, at(1_700));

        let delta = c.take_delta();
        assert_eq!(delta.len(), 2, "one row per bucket, not one per tool");

        let mut buckets: Vec<i64> = delta.keys().map(|key| key.bucket).collect();
        buckets.sort_unstable();
        assert_eq!(
            buckets,
            vec![1, 2],
            "700 seconds crosses one 600-second edge"
        );
        for (key, counts) in &delta {
            assert_eq!(counts.ok, 1, "each bucket holds its own call ({key:?})");
        }
    }

    /// Two calls inside the same bucket are one row - the other half of the same property.
    #[test]
    fn two_calls_in_one_bucket_merge_into_one_row() {
        let c = collector();
        c.record("grep_files", Outcome::Ok, 5, 11, at(1_000));
        c.record("grep_files", Outcome::ErrFlagged, 7, 13, at(1_199));

        let delta = c.take_delta();
        assert_eq!(delta.len(), 1);
        assert_eq!(
            only_row(&delta, "grep_files"),
            Counts {
                ok: 1,
                err_flagged: 1,
                ns_total: 12,
                ns_max: 7,
                bytes_out: 24,
                ..Counts::default()
            }
        );
    }

    /// Every name the router does not serve collapses into one `__unknown` key.
    ///
    /// Not cosmetic: rmcp rejects an unknown tool with `invalid_params`, which is classified and
    /// therefore recorded, so an un-interned key would let a client grow this map without bound
    /// by mistyping a name in a loop.
    #[test]
    fn unknown_names_collapse_into_one_key() {
        let c = collector();
        for name in ["read_text_fil", "raed_text_file", "definitely_not_a_tool"] {
            c.record(name, Outcome::ErrParams, 3, 0, at(1_000));
        }

        let delta = c.take_delta();
        assert_eq!(delta.len(), 1, "three typos must not be three keys");
        assert_eq!(
            only_row(&delta, UNKNOWN_TOOL),
            Counts {
                err_params: 3,
                ns_total: 9,
                ns_max: 3,
                ..Counts::default()
            }
        );
    }

    /// A drain empties the map, and handing it back adds rather than replaces or doubles.
    ///
    /// The flush path is drain-write-maybe-hand-back, so both halves matter: a drain that copied
    /// would double every row the next flush wrote, and a `merge_back` that replaced would drop
    /// whatever was recorded while the flush was in flight.
    #[test]
    fn a_drain_empties_and_merging_back_adds_without_doubling() {
        let c = collector();
        c.record("read_text_file", Outcome::Ok, 5, 2, at(1_000));

        let taken = c.take_delta();
        assert_eq!(only_row(&taken, "read_text_file").ns_total, 5);
        assert!(c.take_delta().is_empty(), "a drain leaves the map empty");

        c.record("read_text_file", Outcome::Ok, 7, 3, at(1_000));
        c.merge_back(taken);

        assert_eq!(
            only_row(&c.take_delta(), "read_text_file"),
            Counts {
                ok: 2,
                ns_total: 12,
                ns_max: 7,
                bytes_out: 5,
                ..Counts::default()
            },
            "the returned delta is added to what arrived while the flush ran"
        );
    }

    /// An unrecognised response shape is stored with the deferred calls and counted apart from
    /// them, which is the whole reason [`Outcome::UnknownShape`] exists as its own variant.
    #[test]
    fn an_unknown_shape_is_stored_as_deferred_but_counted_apart() {
        let c = collector();
        c.record("grep_files", Outcome::Deferred, 1, 0, at(1_000));
        c.record("grep_files", Outcome::UnknownShape, 1, 0, at(1_000));

        assert_eq!(
            only_row(&c.take_delta(), "grep_files").deferred,
            2,
            "the schema has one column for 'did not complete'"
        );
        let health = c.health();
        assert_eq!(health.unknown_shape, 1, "but the two are distinguishable");
        assert_eq!(health.calls, 2);
    }

    /// Health counts survive a drain: they describe the process, not the pending map.
    #[test]
    fn health_counts_survive_a_drain() {
        let c = collector();
        c.record("grep_files", Outcome::Ok, 1, 0, at(1_000));
        assert_eq!(c.health().pending_rows, 1);

        c.take_delta();
        let health = c.health();
        assert_eq!(health.pending_rows, 0, "the map was drained");
        assert_eq!(health.calls, 1, "the process still made the call");
    }

    /// The real router's every tool interns to itself, and only a name it does not serve becomes
    /// [`UNKNOWN_TOOL`].
    ///
    /// Driven from [`crate::FileSystemServer::build_tool_router`] - the same router `tools/list`
    /// serves and the same one the seam builds the collector from - so a tool added, renamed or
    /// cfg-gated out cannot quietly start being counted as unknown.
    #[test]
    fn every_tool_the_router_serves_interns_to_itself() {
        let names: Vec<String> = crate::FileSystemServer::build_tool_router()
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert!(
            names.iter().any(|n| n == "read_text_file"),
            "the router served no recognisable tool list"
        );

        let c = Collector::new(&names);
        for name in &names {
            assert_eq!(
                &*c.intern(name),
                name.as_str(),
                "a tool the router serves must be counted under its own name"
            );
            assert_ne!(
                name.as_str(),
                UNKNOWN_TOOL,
                "a real tool may not be {UNKNOWN_TOOL}"
            );
        }
        assert_eq!(
            &*c.intern("read_text_fil"),
            UNKNOWN_TOOL,
            "and a name it does not serve must not become a key of its own"
        );
    }

    /// Bytes are counted off the blocks a tool already built, for every payload-carrying shape.
    ///
    /// The `ResourceLink` case is asserted deliberately: it is a reference, not a payload, and
    /// counting its URI would attribute bytes the server never sent.
    #[test]
    fn payload_bytes_are_summed_and_references_are_not() {
        use rmcp::model::{EmbeddedResource, Resource};

        let blocks = vec![
            ContentBlock::text("abcde"),
            ContentBlock::image("0123", "image/png"),
            ContentBlock::audio("012345", "audio/wav"),
            ContentBlock::Resource(EmbeddedResource::new(ResourceContents::text(
                "xy",
                "file:///x",
            ))),
            ContentBlock::ResourceLink(Resource::new(
                "file:///a/very/long/uri/that/is/not/a/payload",
                "name",
            )),
        ];
        assert_eq!(bytes_of(&blocks), 5 + 4 + 6 + 2);
        assert_eq!(bytes_of(&[]), 0, "a result with no content costs nothing");
    }
}
