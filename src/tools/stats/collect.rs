//! The in-memory collector: every tool call counted, on a path that cannot fail.
//!
//! Counters accumulate in one map keyed by the interned tool name and stay there for the life of
//! the process. Nothing here touches a database, a clock or the filesystem.
//!
//! Three rules decide the shape, each of them paid for:
//!
//! 1. **The key is the tool name and nothing else.** There is no time dimension: with nothing
//!    persisted to slice, a time bucket would only make the map grow without bound in a
//!    long-lived process while answering a question the log dump does not ask.
//! 2. **The tool name is interned against the router's own list** and anything else becomes
//!    [`UNKNOWN_TOOL`]. A name arrives from the wire *before* the router rejects it - rmcp
//!    answers an unknown tool with `invalid_params("tool not found")`, which
//!    [`super::outcome::classify`] scores [`Outcome::ErrParams`], so those calls do reach this
//!    map - and an un-interned key would grow it without bound from a single typo.
//! 3. **[`Collector::record_interned`] cannot fail**: no `Result`, no I/O, no allocation beyond
//!    the map entry. It takes a mutex, adds integers, releases. Every `FS_MCP_STATS_EVERY`
//!    calls it also writes the table to the log, which is the only place these counters are
//!    ever read.
//!
//! Used from `main.rs`'s `call_tool`, once per tool call, on the way out.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rmcp::model::{ContentBlock, ResourceContents};
use tracing::info;

use super::outcome::Outcome;

/// The tool name every call this build does not have a route for is attributed to.
///
/// Double-underscored so it cannot collide with a real tool: `tool_surface_guard` rejects a
/// leading underscore in a tool name, so no route can ever be spelled this way.
pub const UNKNOWN_TOOL: &str = "__unknown";

/// One tool's counters.
///
/// Every field is a plain `u64` merged by addition except [`Counts::ns_max`], which takes the
/// larger.
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
    /// Summed length of the **content blocks** the calls counted here returned.
    ///
    /// Named for what it holds rather than for what a reader might wish it held. Around ninety
    /// call sites in `main.rs` return a short text summary in the content and the real payload in
    /// `structured_content`, which is deliberately **not** measured: that `Value` is already
    /// materialised, so sizing it would mean serialising it a second time and doubling the cost
    /// of every large response. A tool that answers in structured output therefore shows a small
    /// `content_bytes`, and nobody may read that as "this tool returns little". `bytes_in` is
    /// absent for the same reason - it would mean re-serialising the arguments on every call.
    pub content_bytes: u64,
}

impl Counts {
    /// Merge `other` into `self`: add, except `ns_max`, which takes the larger.
    ///
    /// `saturating_add` and not `+`, because a debug-build overflow panic on the hot path is not
    /// acceptable and a counter that silently restarted at zero would make a rate look negative.
    /// `ns_total` would need ~584 years of accumulated tool time to reach the ceiling.
    fn merge(&mut self, other: Self) {
        self.ok = self.ok.saturating_add(other.ok);
        self.err_flagged = self.err_flagged.saturating_add(other.err_flagged);
        self.err_params = self.err_params.saturating_add(other.err_params);
        self.err_internal = self.err_internal.saturating_add(other.err_internal);
        self.deferred = self.deferred.saturating_add(other.deferred);
        self.ns_total = self.ns_total.saturating_add(other.ns_total);
        self.ns_max = self.ns_max.max(other.ns_max);
        self.content_bytes = self.content_bytes.saturating_add(other.content_bytes);
    }

    /// Calls counted here, whatever their outcome.
    ///
    /// Summed rather than kept as a sixth field: the five outcome columns partition the calls, so
    /// a stored total would be one more number that can drift out of step with them.
    pub fn calls(&self) -> u64 {
        self.ok
            .saturating_add(self.err_flagged)
            .saturating_add(self.err_params)
            .saturating_add(self.err_internal)
            .saturating_add(self.deferred)
    }
}

/// The whole table: one row per interned tool name.
pub type Table = HashMap<Arc<str>, Counts>;

/// What the collector can say about the process as a whole, as opposed to about one tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Health {
    /// Every call this process has recorded since it started.
    pub calls: u64,
    /// Calls whose response was a [`CallToolResponse`](rmcp::model::CallToolResponse) variant
    /// this build does not know.
    ///
    /// Counted apart from [`Counts::deferred`], which stores it, because an operator must be able
    /// to tell "the server deferred" from "this build does not understand rmcp's answer". They
    /// are the same number in the table and entirely different problems.
    pub unknown_shape: u64,
}

/// The in-memory counters for one server process.
///
/// Built once in `FileSystemServer::new` from the router's own tool list; `None` in place of one
/// is how `FS_MCP_STATS=off` is expressed, so that switching statistics off costs the hot path a
/// single branch rather than a mutex nobody reads.
pub struct Collector {
    /// The router's tool names, interned once so that a map key is an `Arc` clone rather than an
    /// allocation. `Arc<str>: Borrow<str>` is what lets a wire name be looked up without one.
    known: HashSet<Arc<str>>,
    /// [`UNKNOWN_TOOL`] interned, so attributing a call to it costs no allocation either.
    unknown: Arc<str>,
    /// The counters themselves. Held only for the few instructions it takes to add integers.
    rows: Mutex<Table>,
    /// See [`Health::calls`].
    calls: AtomicU64,
    /// See [`Health::unknown_shape`].
    unknown_shape: AtomicU64,
    /// Calls between log dumps, or `0` to keep counting and never dump.
    ///
    /// Read once at construction rather than per call: the hot path may not touch the process
    /// environment, and a knob that changed mid-process would make the interval unexplainable
    /// from the log it produced.
    dump_every: u64,
}

impl Collector {
    /// Intern `names` - the router's tool list - and start with an empty table, dumping on the
    /// schedule `FS_MCP_STATS_EVERY` asks for.
    pub fn new<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::with_dump_every(names, super::dump_every())
    }

    /// The same, with the dump schedule given rather than read from the environment.
    ///
    /// Exists so the tests can pin a schedule without setting a process-wide variable that every
    /// other test in this binary would then have to be serialised against.
    pub fn with_dump_every<I, S>(names: I, dump_every: u64) -> Self
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
            rows: Mutex::new(Table::new()),
            calls: AtomicU64::new(0),
            unknown_shape: AtomicU64::new(0),
            dump_every,
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
    pub fn record_interned(&self, tool: Arc<str>, outcome: Outcome, ns: u64, content_bytes: u64) {
        // `fetch_add` returns the previous value, so the first call is call number 1.
        let calls = self.calls.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if outcome == Outcome::UnknownShape {
            self.unknown_shape.fetch_add(1, Ordering::Relaxed);
        }

        let mut one = Counts {
            ns_total: ns,
            ns_max: ns,
            content_bytes,
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

        self.lock().entry(tool).or_default().merge(one);

        // After the merge, deliberately: the dump reads the same table, and the call that
        // triggered it must already be in what it prints.
        if due(calls, self.dump_every) {
            self.dump();
        }
    }

    /// Write the whole table to the log, one line per tool, busiest first.
    ///
    /// `info!` and not `debug!`: this is the entire visible output of the subsystem and the
    /// default level is `info`, so anything quieter would mean counters collected by default and
    /// seen by nobody. Formatting happens off the lock - [`Collector::snapshot`] copies - so a
    /// large table does not hold up the tool calls arriving behind it.
    pub fn dump(&self) {
        for line in lines(&self.snapshot(), self.health()) {
            info!("{line}");
        }
    }

    /// A copy of the table, for a reader that must not hold the lock while it formats.
    pub fn snapshot(&self) -> Table {
        self.lock().clone()
    }

    /// What this collector can say about the process; see [`Health`].
    pub fn health(&self) -> Health {
        Health {
            calls: self.calls.load(Ordering::Relaxed),
            unknown_shape: self.unknown_shape.load(Ordering::Relaxed),
        }
    }

    /// Take the counter lock, recovering a poisoned one.
    ///
    /// The critical section is one `entry(..).or_default()` and eight integer adds - well under a
    /// microsecond, and never an allocation unless the tool name is new. That is the whole
    /// argument for a plain `Mutex` here, and it must not be replaced by "calls are serialised
    /// anyway": they are under stdio, but the server is cloned per connection for the HTTP
    /// transport, so over HTTP tool calls really are concurrent and really do contend for this
    /// lock. The section is short enough that they may.
    ///
    /// Nothing inside the critical section can panic - it is integer arithmetic on a map entry -
    /// so poisoning can only arrive from a panic elsewhere while this lock happened to be held,
    /// and the counters behind it are still consistent. Propagating that panic into every later
    /// tool call is the one outcome this subsystem must never produce.
    fn lock(&self) -> std::sync::MutexGuard<'_, Table> {
        self.rows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Is this the call a dump is owed on?
///
/// A free function so the schedule can be asserted without a log subscriber to read it back:
/// `every == 0` is the documented "never dump", and the modulo is what makes the dumps land on
/// 200, 400, 600 rather than drifting with whatever else the process is doing.
fn due(calls: u64, every: u64) -> bool {
    // `calls != 0` because zero is a multiple of everything: without it a caller counting from
    // zero rather than from one would dump a table that has nothing in it yet.
    calls != 0 && every != 0 && calls.is_multiple_of(every)
}

/// The dump, as text: a line naming the process totals, then one line per tool, busiest first.
///
/// Separated from [`Collector::dump`] so that the shape of the output - the ordering above all -
/// is something the tests can hold, rather than something only a log subscriber could see.
///
/// Ordering is by call count descending and then by name, so that the interesting rows come first
/// and two dumps of the same counters print the same lines: a `HashMap`'s own order is randomised
/// per process, which would make two dumps impossible to diff.
fn lines(table: &Table, health: Health) -> Vec<String> {
    let mut rows: Vec<(&Arc<str>, &Counts)> = table.iter().collect();
    rows.sort_by(|(a_name, a), (b_name, b)| {
        b.calls().cmp(&a.calls()).then_with(|| a_name.cmp(b_name))
    });

    let mut out = Vec::with_capacity(rows.len() + 1);
    out.push(format!(
        "stats: {} calls over {} tools, {} of a shape this build does not know",
        health.calls,
        rows.len(),
        health.unknown_shape
    ));
    out.extend(rows.into_iter().map(|(name, c)| {
        format!(
            "stats: {name} calls={} ok={} err_flagged={} err_params={} err_internal={} deferred={} ns_total={} ns_max={} content_bytes={}",
            c.calls(),
            c.ok,
            c.err_flagged,
            c.err_params,
            c.err_internal,
            c.deferred,
            c.ns_total,
            c.ns_max,
            c.content_bytes
        )
    }));
    out
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

    /// The exact line one busy tool produces, spelled out once so that a change to the format is
    /// a change a reader must make on purpose.
    const EXPECTED_BUSIEST_LINE: &str = "stats: grep_files calls=3 ok=3 err_flagged=0 err_params=0 err_internal=0 deferred=0 ns_total=15 ns_max=5 content_bytes=3";

    /// A collector that serves two tools and never dumps, which is all most of these tests need.
    fn collector() -> Collector {
        Collector::with_dump_every(["read_text_file", "grep_files"], 0)
    }

    /// Record by name, interning first: the seam holds the interned handle, the tests do not.
    fn record(c: &Collector, tool: &str, outcome: Outcome, ns: u64, bytes: u64) {
        c.record_interned(c.intern(tool), outcome, ns, bytes);
    }

    /// The single row of a one-row table, by tool name.
    fn only_row(table: &Table, tool: &str) -> Counts {
        let mut found = table.iter().filter(|(key, _)| &***key == tool);
        let (_, counts) = found.next().expect("a row for this tool");
        assert!(
            found.next().is_none(),
            "expected exactly one row for {tool}"
        );
        *counts
    }

    /// Two calls to one tool are one row: merged, not replaced, and `ns_max` takes the larger.
    #[test]
    fn two_calls_to_one_tool_merge_into_one_row() {
        let c = collector();
        record(&c, "grep_files", Outcome::Ok, 5, 11);
        record(&c, "grep_files", Outcome::ErrFlagged, 7, 13);

        let table = c.snapshot();
        assert_eq!(table.len(), 1);
        assert_eq!(
            only_row(&table, "grep_files"),
            Counts {
                ok: 1,
                err_flagged: 1,
                ns_total: 12,
                ns_max: 7,
                content_bytes: 24,
                ..Counts::default()
            }
        );
        assert_eq!(only_row(&table, "grep_files").calls(), 2);
    }

    /// Two tools are two rows, and neither borrows the other's counters.
    #[test]
    fn two_tools_stay_two_rows() {
        let c = collector();
        record(&c, "grep_files", Outcome::Ok, 5, 0);
        record(&c, "read_text_file", Outcome::Ok, 7, 0);

        let table = c.snapshot();
        assert_eq!(table.len(), 2);
        assert_eq!(only_row(&table, "grep_files").ns_total, 5);
        assert_eq!(only_row(&table, "read_text_file").ns_total, 7);
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
            record(&c, name, Outcome::ErrParams, 3, 0);
        }

        let table = c.snapshot();
        assert_eq!(table.len(), 1, "three typos must not be three keys");
        assert_eq!(
            only_row(&table, UNKNOWN_TOOL),
            Counts {
                err_params: 3,
                ns_total: 9,
                ns_max: 3,
                ..Counts::default()
            }
        );
    }

    /// A snapshot copies rather than drains: these counters describe the whole process life, and
    /// a reader that emptied the table would make every later dump a lie.
    #[test]
    fn a_snapshot_leaves_the_table_intact() {
        let c = collector();
        record(&c, "read_text_file", Outcome::Ok, 5, 2);

        assert_eq!(only_row(&c.snapshot(), "read_text_file").ns_total, 5);
        assert_eq!(
            only_row(&c.snapshot(), "read_text_file").ns_total,
            5,
            "a second reader must see the same row"
        );
    }

    /// An unrecognised response shape is stored with the deferred calls and counted apart from
    /// them, which is the whole reason [`Outcome::UnknownShape`] exists as its own variant.
    #[test]
    fn an_unknown_shape_is_stored_as_deferred_but_counted_apart() {
        let c = collector();
        record(&c, "grep_files", Outcome::Deferred, 1, 0);
        record(&c, "grep_files", Outcome::UnknownShape, 1, 0);

        assert_eq!(
            only_row(&c.snapshot(), "grep_files").deferred,
            2,
            "the table has one column for 'did not complete'"
        );
        let health = c.health();
        assert_eq!(health.unknown_shape, 1, "but the two are distinguishable");
        assert_eq!(health.calls, 2);
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

        let c = Collector::with_dump_every(&names, 0);
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

    /// The dump lands on multiples of the interval, and `0` never dumps at all.
    #[test]
    fn the_dump_schedule_is_every_nth_call_and_zero_is_never() {
        assert!(!due(0, 200), "no call has been made yet");
        assert!(!due(199, 200));
        assert!(due(200, 200));
        assert!(due(400, 200));
        assert!(due(7, 1), "an interval of one dumps on every call");
        for calls in [0, 1, 200, u64::MAX] {
            assert!(!due(calls, 0), "zero must never dump ({calls})");
        }
    }

    /// The busiest tool is printed first, ties break by name, and the header counts the process.
    ///
    /// Ordering is the property worth pinning: a `HashMap` iterates in an order randomised per
    /// process, so without the sort two dumps of identical counters could not be diffed.
    #[test]
    fn the_dump_leads_with_the_process_then_the_busiest_tool() {
        let c = collector();
        for _ in 0..3 {
            record(&c, "grep_files", Outcome::Ok, 5, 1);
        }
        record(&c, "read_text_file", Outcome::ErrFlagged, 9, 2);
        record(&c, "definitely_not_a_tool", Outcome::ErrParams, 1, 0);

        let out = lines(&c.snapshot(), c.health());
        assert_eq!(out.len(), 4, "a header and one line per tool");
        assert_eq!(
            out[0],
            "stats: 5 calls over 3 tools, 0 of a shape this build does not know"
        );
        assert_eq!(out[1], EXPECTED_BUSIEST_LINE);
        // The two one-call rows tie, so the name decides: `__unknown` sorts before `read_...`.
        assert!(out[2].contains(UNKNOWN_TOOL), "{}", out[2]);
        assert!(out[3].contains("read_text_file"), "{}", out[3]);
    }

    /// An empty table still says something: a server that served nothing is a real answer, and a
    /// dump that printed no lines at all would look like a broken subsystem instead.
    #[test]
    fn an_empty_table_still_reports_the_process() {
        let c = collector();
        let out = lines(&c.snapshot(), c.health());
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0],
            "stats: 0 calls over 0 tools, 0 of a shape this build does not know"
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
