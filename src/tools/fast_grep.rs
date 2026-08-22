use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use grep_regex::RegexMatcherBuilder;
use grep_searcher::{BinaryDetection, SearcherBuilder};
use ignore::{DirEntry, WalkBuilder, WalkState};

use crate::core::allowed::AllowedDirs;
use crate::core::path::resolve_validated_path;
use crate::tools::grep::{
    GrepCount, GrepEngine, GrepMatch, GrepOutputMode, GrepParams, GrepResult,
};

#[derive(Debug, Clone, Default)]
pub struct GrepStats {
    pub elapsed_ms: u64,
    pub visited_entries: u64,
    pub visited_dirs: u64,
    pub files_seen: u64,
    pub files_searched: u64,
    pub bytes_searched: u64,
    pub matches_found: u64,
    pub skipped_binary: u64,
    pub skipped_unreadable: u64,
    pub threads: usize,
    pub stopped_reason: Option<String>,
}

pub struct FastGrepResult {
    pub result: GrepResult,
    pub stats: GrepStats,
}

#[derive(Clone)]
pub struct ProgressSnapshot {
    pub stats: GrepStats,
    pub current_path: Option<PathBuf>,
}

pub type ProgressCallback = Arc<dyn Fn(ProgressSnapshot) + Send + Sync>;

struct Shared {
    output_mode: GrepOutputMode,
    max_matches: usize,
    stop: AtomicBool,
    total_matches: AtomicUsize,
    visited_entries: AtomicU64,
    visited_dirs: AtomicU64,
    files_seen: AtomicU64,
    files_searched: AtomicU64,
    bytes_searched: AtomicU64,
    skipped_binary: AtomicU64,
    skipped_unreadable: AtomicU64,
    current_path: Mutex<Option<PathBuf>>,
    matches: Mutex<Vec<GrepMatch>>,
    counts: Mutex<Vec<GrepCount>>,
    files: Mutex<Vec<PathBuf>>,
    stopped_reason: Mutex<Option<String>>,
    /// First fatal search error (e.g. a fancy-regex runtime error). When set,
    /// the walk is stopped and the error is propagated to the caller instead of
    /// being silently swallowed as a partial success (BH-11).
    search_error: Mutex<Option<String>>,
}

impl Shared {
    fn new(output_mode: GrepOutputMode, max_matches: usize) -> Shared {
        Shared {
            output_mode,
            max_matches,
            stop: AtomicBool::new(false),
            total_matches: AtomicUsize::new(0),
            visited_entries: AtomicU64::new(0),
            visited_dirs: AtomicU64::new(0),
            files_seen: AtomicU64::new(0),
            files_searched: AtomicU64::new(0),
            bytes_searched: AtomicU64::new(0),
            skipped_binary: AtomicU64::new(0),
            skipped_unreadable: AtomicU64::new(0),
            current_path: Mutex::new(None),
            matches: Mutex::new(Vec::new()),
            counts: Mutex::new(Vec::new()),
            files: Mutex::new(Vec::new()),
            stopped_reason: Mutex::new(None),
            search_error: Mutex::new(None),
        }
    }

    fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn stop_with(&self, reason: &'static str) {
        self.stop.store(true, Ordering::Relaxed);
        let mut stopped = self.stopped_reason.lock().unwrap();
        if stopped.is_none() {
            *stopped = Some(reason.to_string());
        }
    }

    fn reserve_match_slot(&self) -> bool {
        if self.max_matches == 0 {
            return true;
        }
        loop {
            let current = self.total_matches.load(Ordering::Relaxed);
            if current >= self.max_matches {
                self.stop_with("maxMatches reached");
                return false;
            }
            if self
                .total_matches
                .compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                if current + 1 >= self.max_matches {
                    self.stop_with("maxMatches reached");
                }
                return true;
            }
        }
    }

    /// Append one file's already-built matches to the shared collection as a
    /// contiguous batch. Order within the batch is preserved; order across
    /// files is nondeterministic (worker-thread dependent), as before.
    fn push_file_matches(&self, batch: Vec<GrepMatch>) {
        if batch.is_empty() {
            return;
        }
        self.matches.lock().unwrap().extend(batch);
    }

    /// Reserve up to `want` match slots against the global `max_matches` budget
    /// for count mode. Returns how many were actually granted (0..=want).
    /// `max_matches == 0` means unlimited, so the full `want` is granted. When
    /// the budget is exhausted the walk is stopped so no further files start.
    fn reserve_counts(&self, want: usize) -> usize {
        if self.max_matches == 0 {
            // Unlimited: still track the total so matchesFound is accurate.
            self.total_matches.fetch_add(want, Ordering::Relaxed);
            return want;
        }
        loop {
            let current = self.total_matches.load(Ordering::Relaxed);
            if current >= self.max_matches {
                self.stop_with("maxMatches reached");
                return 0;
            }
            let grant = want.min(self.max_matches - current);
            if self
                .total_matches
                .compare_exchange_weak(
                    current,
                    current + grant,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                if current + grant >= self.max_matches {
                    self.stop_with("maxMatches reached");
                }
                return grant;
            }
        }
    }

    /// Record a fatal search error once and stop the walk so it surfaces to the
    /// caller instead of being swallowed as a silent partial result (BH-11).
    fn set_error(&self, msg: String) {
        {
            let mut slot = self.search_error.lock().unwrap();
            if slot.is_none() {
                *slot = Some(msg);
            }
        }
        self.stop_with("search error");
    }

    fn record_count(&self, path: PathBuf, count: usize) {
        if count == 0 {
            return;
        }
        // Count mode honours maxMatches too (BH-23): cap the recorded count by
        // the remaining global budget and feed it into total_matches so
        // matchesFound reflects the real number of matches (0 = unlimited).
        let granted = self.reserve_counts(count);
        if granted > 0 {
            self.counts.lock().unwrap().push(GrepCount {
                path,
                count: granted,
            });
        }
    }

    fn record_file(&self, path: PathBuf) {
        if self.max_matches > 0 {
            let current = self.total_matches.fetch_add(1, Ordering::Relaxed) + 1;
            if current > self.max_matches {
                self.stop_with("maxMatches reached");
                return;
            }
            if current >= self.max_matches {
                self.stop_with("maxMatches reached");
            }
        }
        self.files.lock().unwrap().push(path);
    }

    fn snapshot(&self, started: Instant, threads: usize) -> ProgressSnapshot {
        ProgressSnapshot {
            stats: GrepStats {
                elapsed_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                visited_entries: self.visited_entries.load(Ordering::Relaxed),
                visited_dirs: self.visited_dirs.load(Ordering::Relaxed),
                files_seen: self.files_seen.load(Ordering::Relaxed),
                files_searched: self.files_searched.load(Ordering::Relaxed),
                bytes_searched: self.bytes_searched.load(Ordering::Relaxed),
                matches_found: self.total_matches.load(Ordering::Relaxed) as u64,
                skipped_binary: self.skipped_binary.load(Ordering::Relaxed),
                skipped_unreadable: self.skipped_unreadable.load(Ordering::Relaxed),
                threads,
                stopped_reason: self.stopped_reason.lock().unwrap().clone(),
            },
            current_path: self.current_path.lock().unwrap().clone(),
        }
    }
}

struct ContentSink {
    path: PathBuf,
    shared: Arc<Shared>,
    /// Before-context lines accumulated for the NEXT match in this file.
    current_before: Vec<String>,
    /// Matches collected for THIS file only. Kept in a per-sink buffer (rather
    /// than pushed straight into `Shared::matches`) so that after-context —
    /// which grep-searcher delivers right after each match — is attached to
    /// this sink's own match and never to another worker thread's match. The
    /// batch is flushed into `Shared::matches` as one contiguous, in-order run
    /// once the file's search finishes (see the ContentBlock walker branch).
    matches: Vec<GrepMatch>,
    /// Set when grep-searcher reports binary data, so the walker can avoid
    /// billing this file as actually searched (BH-24).
    saw_binary: bool,
}

impl ContentSink {
    fn new(path: PathBuf, shared: Arc<Shared>) -> ContentSink {
        ContentSink {
            path,
            shared,
            current_before: Vec::new(),
            matches: Vec::new(),
            saw_binary: false,
        }
    }

    fn clean_line(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes)
            .trim_end_matches(['\r', '\n'])
            .to_string()
    }
}

impl grep_searcher::Sink for ContentSink {
    type Error = io::Error;

    fn matched(
        &mut self,
        _searcher: &grep_searcher::Searcher,
        mat: &grep_searcher::SinkMatch<'_>,
    ) -> io::Result<bool> {
        if !self.shared.reserve_match_slot() {
            // Global cap reached: stop searching this file. Any after-context
            // for the previously matched line has already been delivered.
            return Ok(false);
        }
        let grep_match = GrepMatch {
            path: self.path.clone(),
            line_number: mat.line_number().unwrap_or(0) as usize,
            line: Self::clean_line(mat.bytes()),
            before_context: std::mem::take(&mut self.current_before),
            after_context: Vec::new(),
        };
        self.matches.push(grep_match);
        // Keep searching regardless of the global stop flag so grep-searcher can
        // deliver this match's trailing after-context before the file ends. New
        // files are prevented from starting by the walker's should_stop() check,
        // and further matches in this file fail reserve_match_slot() above.
        Ok(true)
    }

    fn context(
        &mut self,
        _searcher: &grep_searcher::Searcher,
        context: &grep_searcher::SinkContext<'_>,
    ) -> io::Result<bool> {
        let line = Self::clean_line(context.bytes());
        match context.kind() {
            grep_searcher::SinkContextKind::Before => {
                self.current_before.push(line);
            }
            grep_searcher::SinkContextKind::After => {
                if let Some(last) = self.matches.last_mut() {
                    last.after_context.push(line);
                }
            }
            grep_searcher::SinkContextKind::Other => {}
        }
        Ok(true)
    }

    fn binary_data(
        &mut self,
        _searcher: &grep_searcher::Searcher,
        _binary_byte_offset: u64,
    ) -> io::Result<bool> {
        self.saw_binary = true;
        self.shared.skipped_binary.fetch_add(1, Ordering::Relaxed);
        Ok(false)
    }
}

struct CountSink {
    count: usize,
    /// See BH-24: distinguishes a binary file (skipped) from a real text scan.
    saw_binary: bool,
}

impl grep_searcher::Sink for CountSink {
    type Error = io::Error;

    fn matched(
        &mut self,
        _searcher: &grep_searcher::Searcher,
        _mat: &grep_searcher::SinkMatch<'_>,
    ) -> io::Result<bool> {
        self.count += 1;
        Ok(true)
    }

    fn binary_data(
        &mut self,
        _searcher: &grep_searcher::Searcher,
        _binary_byte_offset: u64,
    ) -> io::Result<bool> {
        self.saw_binary = true;
        Ok(false)
    }
}

struct HasMatchSink {
    found: bool,
    stop_after_first: bool,
    /// See BH-24: distinguishes a binary file (skipped) from a real text scan.
    saw_binary: bool,
}

impl grep_searcher::Sink for HasMatchSink {
    type Error = io::Error;

    fn matched(
        &mut self,
        _searcher: &grep_searcher::Searcher,
        _mat: &grep_searcher::SinkMatch<'_>,
    ) -> io::Result<bool> {
        self.found = true;
        Ok(!self.stop_after_first)
    }

    fn binary_data(
        &mut self,
        _searcher: &grep_searcher::Searcher,
        _binary_byte_offset: u64,
    ) -> io::Result<bool> {
        self.saw_binary = true;
        Ok(false)
    }
}

pub async fn grep_files_fast(
    params: GrepParams,
    allowed: &AllowedDirs,
    allow_symlink_escape: bool,
    progress: Option<ProgressCallback>,
) -> Result<FastGrepResult> {
    let root_path = resolve_validated_path(&params.root, allowed, allow_symlink_escape)
        .await
        .context("Invalid root path")?;

    tokio::task::spawn_blocking(move || grep_files_fast_blocking(params, root_path, progress))
        .await
        .context("grep worker panicked")?
}

fn grep_files_fast_blocking(
    params: GrepParams,
    root_path: PathBuf,
    progress: Option<ProgressCallback>,
) -> Result<FastGrepResult> {
    let started = Instant::now();
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(12);
    // Route to fancy engine if requested. Fancy bypasses grep-searcher and
    // matches per file via fancy_regex (no SIMD, but supports look-around).
    if params.engine == GrepEngine::Fancy {
        return fancy_grep_blocking(params, root_path, progress, started, threads);
    }

    let mut matcher_builder = RegexMatcherBuilder::new();
    matcher_builder
        .case_insensitive(params.case_insensitive)
        .fixed_strings(params.fixed_strings)
        .word(params.whole_word);
    if params.multiline {
        // Multi-line mode: no line_terminator (else grep-regex rejects `\n` in pattern).
        // `crlf` is incompatible with multi_line for the same reason.
        matcher_builder.multi_line(true).dot_matches_new_line(true);
    } else {
        // CRLF handling is always enabled in single-line mode — safe on `\n`-only
        // files and fixes `$` anchors on Windows. (Internally sets a CRLF
        // line_terminator, which is why we only enable it here.)
        matcher_builder.crlf(true);
        matcher_builder.line_terminator(Some(b'\n'));
    }
    let matcher = matcher_builder
        .build(&params.pattern)
        .context("Invalid regex pattern")?;

    let mut walk_builder = WalkBuilder::new(&root_path);
    walk_builder
        .threads(threads)
        .hidden(false)
        .parents(true)
        .ignore(true)
        .git_global(true)
        .git_ignore(true)
        .git_exclude(true);
    if params.max_depth > 0 {
        walk_builder.max_depth(Some(params.max_depth));
    }
    if params.max_filesize > 0 {
        walk_builder.max_filesize(Some(params.max_filesize));
    }
    apply_overrides(&mut walk_builder, &root_path, &params)?;

    let shared = Arc::new(Shared::new(params.output_mode, params.max_matches));
    let last_progress = Arc::new(Mutex::new(Instant::now() - Duration::from_secs(2)));
    let matcher = Arc::new(matcher);

    walk_builder.build_parallel().run(|| {
        let shared = shared.clone();
        let matcher = matcher.clone();
        let progress = progress.clone();
        let last_progress = last_progress.clone();
        let mut searcher_builder = SearcherBuilder::new();
        searcher_builder
            .binary_detection(BinaryDetection::quit(b'\0'))
            .line_number(true)
            .before_context(params.context_before)
            .after_context(params.context_after)
            .invert_match(params.invert_match)
            .multi_line(params.multiline);
        if params.heap_limit_mb > 0 {
            searcher_builder.heap_limit(Some(params.heap_limit_mb * 1024 * 1024));
        }
        if let Some(enc_name) = &params.encoding
            && let Ok(enc) = grep_searcher::Encoding::new(enc_name)
        {
            searcher_builder.encoding(Some(enc));
        }
        let mut searcher = searcher_builder.build();

        Box::new(move |entry| {
            if shared.should_stop() {
                return WalkState::Quit;
            }
            shared.visited_entries.fetch_add(1, Ordering::Relaxed);
            let dent = match entry {
                Ok(dent) => dent,
                Err(_) => {
                    shared.skipped_unreadable.fetch_add(1, Ordering::Relaxed);
                    return WalkState::Continue;
                }
            };
            maybe_report_progress(&shared, started, threads, &progress, &last_progress);
            if is_dir(&dent) {
                shared.visited_dirs.fetch_add(1, Ordering::Relaxed);
                return WalkState::Continue;
            }
            if !is_file(&dent) {
                return WalkState::Continue;
            }

            let path = dent.path().to_path_buf();
            shared.files_seen.fetch_add(1, Ordering::Relaxed);
            *shared.current_path.lock().unwrap() = Some(path.clone());
            // Grab the size up front, but only bill it to bytes_searched once
            // the file is actually read and scanned (BH-24).
            let file_len = dent.metadata().map(|m| m.len()).unwrap_or(0);

            // `searched` is true only when the file was actually opened, read,
            // and scanned as text (not skipped as unreadable or binary), so the
            // files_searched / bytes_searched stats reflect real work (BH-24).
            let searched = match shared.output_mode {
                GrepOutputMode::ContentBlock => {
                    let mut sink = ContentSink::new(path.clone(), shared.clone());
                    let ok = match searcher.search_path(&*matcher, &path, &mut sink) {
                        Ok(()) => true,
                        Err(err) => {
                            if err.kind() != io::ErrorKind::InvalidData {
                                shared.skipped_unreadable.fetch_add(1, Ordering::Relaxed);
                            }
                            false
                        }
                    };
                    let saw_binary = sink.saw_binary;
                    // Move this file's matches into the shared collection as a
                    // single contiguous, in-order batch under one lock. Done
                    // here (not incrementally in `matched`) so after-context
                    // stays bound to the correct match under concurrency.
                    shared.push_file_matches(std::mem::take(&mut sink.matches));
                    ok && !saw_binary
                }
                GrepOutputMode::CountOnly => {
                    let mut sink = CountSink {
                        count: 0,
                        saw_binary: false,
                    };
                    match searcher.search_path(&*matcher, &path, &mut sink) {
                        Ok(()) => {
                            if sink.saw_binary {
                                shared.skipped_binary.fetch_add(1, Ordering::Relaxed);
                            } else if sink.count > 0 {
                                shared.record_count(path, sink.count);
                            }
                            !sink.saw_binary
                        }
                        Err(_) => {
                            shared.skipped_unreadable.fetch_add(1, Ordering::Relaxed);
                            false
                        }
                    }
                }
                GrepOutputMode::FilesWithMatches => {
                    let mut sink = HasMatchSink {
                        found: false,
                        stop_after_first: true,
                        saw_binary: false,
                    };
                    match searcher.search_path(&*matcher, &path, &mut sink) {
                        Ok(()) => {
                            if sink.saw_binary {
                                shared.skipped_binary.fetch_add(1, Ordering::Relaxed);
                            } else if sink.found {
                                shared.record_file(path);
                            }
                            !sink.saw_binary
                        }
                        Err(_) => {
                            shared.skipped_unreadable.fetch_add(1, Ordering::Relaxed);
                            false
                        }
                    }
                }
                GrepOutputMode::FilesWithoutMatch => {
                    // One matching line is enough to disqualify the file, so
                    // stop at the first hit instead of scanning to EOF (BH-23).
                    let mut sink = HasMatchSink {
                        found: false,
                        stop_after_first: true,
                        saw_binary: false,
                    };
                    match searcher.search_path(&*matcher, &path, &mut sink) {
                        Ok(()) => {
                            if sink.saw_binary {
                                shared.skipped_binary.fetch_add(1, Ordering::Relaxed);
                            } else if !sink.found {
                                shared.record_file(path);
                            }
                            !sink.saw_binary
                        }
                        Err(_) => {
                            shared.skipped_unreadable.fetch_add(1, Ordering::Relaxed);
                            false
                        }
                    }
                }
            };
            if searched {
                shared.files_searched.fetch_add(1, Ordering::Relaxed);
                shared.bytes_searched.fetch_add(file_len, Ordering::Relaxed);
            }

            if shared.should_stop() {
                WalkState::Quit
            } else {
                WalkState::Continue
            }
        })
    });

    let snapshot = shared.snapshot(started, threads);
    if let Some(progress) = progress {
        progress(snapshot.clone());
    }

    let result = match params.output_mode {
        GrepOutputMode::ContentBlock => {
            GrepResult::Matches(std::mem::take(&mut *shared.matches.lock().unwrap()))
        }
        GrepOutputMode::CountOnly => {
            GrepResult::Counts(std::mem::take(&mut *shared.counts.lock().unwrap()))
        }
        GrepOutputMode::FilesWithMatches | GrepOutputMode::FilesWithoutMatch => {
            GrepResult::Files(std::mem::take(&mut *shared.files.lock().unwrap()))
        }
    };
    Ok(FastGrepResult {
        result,
        stats: snapshot.stats,
    })
}

/// Parallel directory walk + `fancy_regex` matching per file. Used when the
/// caller opts into the fancy engine (look-around / backreferences).
fn fancy_grep_blocking(
    params: GrepParams,
    root_path: PathBuf,
    progress: Option<ProgressCallback>,
    started: Instant,
    threads: usize,
) -> Result<FastGrepResult> {
    // Apply pattern transforms equivalent to the regex engine's fixed_strings / whole_word.
    let mut pattern = params.pattern.clone();
    if params.fixed_strings {
        pattern = fancy_regex::escape(&pattern).to_string();
    }
    if params.whole_word {
        pattern = format!(r"\b(?:{pattern})\b");
    }
    if params.case_insensitive {
        pattern = format!("(?i){pattern}");
    }
    // Bring anchors into line with the regex engine (BH-11): `(?m)` makes
    // `^`/`$` match at line boundaries (the regex path searches line-by-line),
    // and multiline additionally enables dot-matches-newline to mirror the
    // regex path's `dot_matches_new_line(true)`.
    //
    // Remaining, documented divergence from the regex engine: this path always
    // reads whole files via `std::fs::read` (params.heap_limit_mb is not
    // applied), ignores params.encoding (bytes are interpreted as UTF-8), and
    // uses its own NUL-in-first-8KB binary heuristic rather than grep-searcher's
    // BinaryDetection. Also, an explicit `\n` in the pattern is rejected by the
    // regex engine when multiline is off, but fancy-regex still matches across
    // lines. Fully unifying these would require routing fancy_regex through the
    // same Searcher, which is out of scope here.
    if params.multiline {
        pattern = format!("(?sm){pattern}");
    } else {
        pattern = format!("(?m){pattern}");
    }
    let matcher = fancy_regex::Regex::new(&pattern).context("Invalid fancy-regex pattern")?;

    let mut walk_builder = WalkBuilder::new(&root_path);
    walk_builder
        .threads(threads)
        .hidden(false)
        .parents(true)
        .ignore(true)
        .git_global(true)
        .git_ignore(true)
        .git_exclude(true);
    if params.max_depth > 0 {
        walk_builder.max_depth(Some(params.max_depth));
    }
    if params.max_filesize > 0 {
        walk_builder.max_filesize(Some(params.max_filesize));
    }
    apply_overrides(&mut walk_builder, &root_path, &params)?;

    let shared = Arc::new(Shared::new(params.output_mode, params.max_matches));
    let last_progress = Arc::new(Mutex::new(Instant::now() - Duration::from_secs(2)));
    let matcher = Arc::new(matcher);
    let ctx_before = params.context_before;
    let ctx_after = params.context_after;
    let invert = params.invert_match;
    let output_mode = params.output_mode;

    walk_builder.build_parallel().run(|| {
        let shared = shared.clone();
        let matcher = matcher.clone();
        let progress = progress.clone();
        let last_progress = last_progress.clone();

        Box::new(move |entry| {
            if shared.should_stop() {
                return WalkState::Quit;
            }
            shared.visited_entries.fetch_add(1, Ordering::Relaxed);
            let dent = match entry {
                Ok(d) => d,
                Err(_) => {
                    shared.skipped_unreadable.fetch_add(1, Ordering::Relaxed);
                    return WalkState::Continue;
                }
            };
            maybe_report_progress(&shared, started, threads, &progress, &last_progress);
            if is_dir(&dent) {
                shared.visited_dirs.fetch_add(1, Ordering::Relaxed);
                return WalkState::Continue;
            }
            if !is_file(&dent) {
                return WalkState::Continue;
            }

            let path = dent.path().to_path_buf();
            shared.files_seen.fetch_add(1, Ordering::Relaxed);
            *shared.current_path.lock().unwrap() = Some(path.clone());

            let content = match std::fs::read(&path) {
                Ok(b) => b,
                Err(_) => {
                    shared.skipped_unreadable.fetch_add(1, Ordering::Relaxed);
                    return WalkState::Continue;
                }
            };
            // Skip binary files quickly: NUL byte in the first 8KB.
            if content.iter().take(8192).any(|&b| b == 0) {
                shared.skipped_binary.fetch_add(1, Ordering::Relaxed);
                return WalkState::Continue;
            }
            let text = match std::str::from_utf8(&content) {
                Ok(s) => s,
                Err(_) => {
                    shared.skipped_unreadable.fetch_add(1, Ordering::Relaxed);
                    return WalkState::Continue;
                }
            };
            // Only bill the file as searched once it has actually been opened,
            // read, and confirmed as searchable text; bytes_searched reflects
            // bytes actually consumed (BH-24).
            shared.files_searched.fetch_add(1, Ordering::Relaxed);
            shared
                .bytes_searched
                .fetch_add(content.len() as u64, Ordering::Relaxed);

            let line_starts = compute_line_starts(text);
            let lines: Vec<&str> = text.split_inclusive('\n').collect();

            // Collect raw match (byte_offset, line_index) tuples.
            let mut hits: Vec<usize> = Vec::new();
            let mut cursor = 0usize;
            while cursor <= text.len() {
                match matcher.find_from_pos(text, cursor) {
                    Ok(Some(m)) => {
                        let line_idx = line_index_for_offset(&line_starts, m.start());
                        hits.push(line_idx);
                        cursor = if m.end() == m.start() {
                            m.end() + 1
                        } else {
                            m.end()
                        };
                    }
                    Ok(None) => break,
                    Err(e) => {
                        // Propagate fancy-regex runtime errors (e.g. a
                        // backtrack-limit overflow) instead of silently
                        // returning a partial result for this file (BH-11).
                        shared.set_error(format!(
                            "fancy-regex runtime error while searching {}: {e}",
                            path.display()
                        ));
                        return WalkState::Quit;
                    }
                }
            }

            // Apply invert_match semantics on lines (line is a hit if any match
            // started on it; invert flips that).
            let mut matched_lines: Vec<usize> = if invert {
                let hit_set: std::collections::HashSet<usize> = hits.iter().copied().collect();
                (0..lines.len()).filter(|i| !hit_set.contains(i)).collect()
            } else {
                // De-dup line indices but preserve order.
                let mut seen = std::collections::HashSet::new();
                hits.iter().copied().filter(|i| seen.insert(*i)).collect()
            };
            matched_lines.sort_unstable();

            match output_mode {
                GrepOutputMode::ContentBlock => {
                    for line_idx in &matched_lines {
                        if !shared.reserve_match_slot() {
                            break;
                        }
                        let before_start = line_idx.saturating_sub(ctx_before);
                        // Saturating math so a caller-supplied huge contextAfter
                        // (up to usize::MAX) cannot overflow and panic (BH-31).
                        let after_start = line_idx.saturating_add(1).min(lines.len());
                        let after_end = line_idx
                            .saturating_add(1)
                            .saturating_add(ctx_after)
                            .min(lines.len());
                        let strip = |s: &&str| s.trim_end_matches(['\r', '\n']).to_string();
                        let before_context: Vec<String> =
                            lines[before_start..*line_idx].iter().map(strip).collect();
                        let after_context: Vec<String> =
                            lines[after_start..after_end].iter().map(strip).collect();
                        let line = strip(&lines[*line_idx]);
                        shared.matches.lock().unwrap().push(GrepMatch {
                            path: path.clone(),
                            line_number: line_idx + 1,
                            line,
                            before_context,
                            after_context,
                        });
                    }
                }
                GrepOutputMode::CountOnly => {
                    let n = matched_lines.len();
                    if n > 0 {
                        shared.record_count(path.clone(), n);
                    }
                }
                GrepOutputMode::FilesWithMatches => {
                    if !matched_lines.is_empty() {
                        shared.record_file(path.clone());
                    }
                }
                GrepOutputMode::FilesWithoutMatch => {
                    if matched_lines.is_empty() {
                        shared.record_file(path.clone());
                    }
                }
            }

            if shared.should_stop() {
                WalkState::Quit
            } else {
                WalkState::Continue
            }
        })
    });

    let snapshot = shared.snapshot(started, threads);
    if let Some(progress) = progress {
        progress(snapshot.clone());
    }
    // Surface any fatal fancy-regex runtime error captured during the walk
    // rather than returning a silent partial result (BH-11).
    if let Some(msg) = shared.search_error.lock().unwrap().take() {
        return Err(anyhow::anyhow!(msg));
    }
    let result = match params.output_mode {
        GrepOutputMode::ContentBlock => {
            GrepResult::Matches(std::mem::take(&mut *shared.matches.lock().unwrap()))
        }
        GrepOutputMode::CountOnly => {
            GrepResult::Counts(std::mem::take(&mut *shared.counts.lock().unwrap()))
        }
        GrepOutputMode::FilesWithMatches | GrepOutputMode::FilesWithoutMatch => {
            GrepResult::Files(std::mem::take(&mut *shared.files.lock().unwrap()))
        }
    };
    Ok(FastGrepResult {
        result,
        stats: snapshot.stats,
    })
}

fn compute_line_starts(content: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    for (i, b) in content.bytes().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

fn line_index_for_offset(starts: &[usize], offset: usize) -> usize {
    // Binary search for the line that contains `offset`.
    let mut low = 0usize;
    let mut high = starts.len();
    while low < high {
        let mid = (low + high) / 2;
        if starts[mid] <= offset {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    low.saturating_sub(1)
}

fn apply_overrides(builder: &mut WalkBuilder, root: &Path, params: &GrepParams) -> Result<()> {
    if params.file_pattern.is_none() && params.exclude_patterns.is_empty() {
        return Ok(());
    }

    let mut overrides = ignore::overrides::OverrideBuilder::new(root);
    if let Some(pattern) = &params.file_pattern {
        overrides
            .add(pattern)
            .with_context(|| format!("Invalid filePattern: {pattern}"))?;
    }
    for pattern in &params.exclude_patterns {
        let negated = if pattern.starts_with('!') {
            pattern.clone()
        } else {
            format!("!{pattern}")
        };
        overrides
            .add(&negated)
            .with_context(|| format!("Invalid exclude pattern: {pattern}"))?;
    }
    builder.overrides(overrides.build()?);
    Ok(())
}

fn is_file(dent: &DirEntry) -> bool {
    dent.file_type().map(|ft| ft.is_file()).unwrap_or(false)
}

fn is_dir(dent: &DirEntry) -> bool {
    dent.file_type().map(|ft| ft.is_dir()).unwrap_or(false)
}

fn maybe_report_progress(
    shared: &Shared,
    started: Instant,
    threads: usize,
    progress: &Option<ProgressCallback>,
    last_progress: &Mutex<Instant>,
) {
    let Some(progress) = progress else {
        return;
    };
    let now = Instant::now();
    let mut last = last_progress.lock().unwrap();
    if now.duration_since(*last) < Duration::from_secs(1) {
        return;
    }
    *last = now;
    progress(shared.snapshot(started, threads));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn base_params(root: &str, pattern: &str) -> GrepParams {
        GrepParams {
            root: root.to_string(),
            pattern: pattern.to_string(),
            file_pattern: None,
            exclude_patterns: Vec::new(),
            case_insensitive: false,
            context_before: 0,
            context_after: 0,
            max_matches: 0,
            invert_match: false,
            output_mode: GrepOutputMode::ContentBlock,
            multiline: false,
            fixed_strings: false,
            whole_word: false,
            max_depth: 0,
            max_filesize: 0,
            encoding: None,
            heap_limit_mb: 0,
            engine: GrepEngine::Regex,
        }
    }

    /// BUG #2: pattern containing `\n` must be allowed in multiline mode.
    #[tokio::test]
    async fn test_multiline_pattern_across_lines() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        std::fs::write(
            root.join("a.rs"),
            "fn foo() {\n    let x = 1;\n    let y = 2;\n}\n",
        )
        .unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);
        let mut params = base_params(&root.to_string_lossy(), r"let x = 1;\n\s*let y");
        params.multiline = true;
        params.file_pattern = Some("*.rs".into());

        let res = grep_files_fast(params, &allowed, false, None)
            .await
            .unwrap();
        match res.result {
            GrepResult::Matches(m) => {
                assert!(!m.is_empty(), "multiline pattern should match across lines");
            }
            _ => panic!("unexpected result variant"),
        }
    }

    /// Multiline disabled — same pattern with literal `\n` should fail to build.
    #[tokio::test]
    async fn test_newline_rejected_without_multiline() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        std::fs::write(root.join("a.rs"), "hello\nworld\n").unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);
        let params = base_params(&root.to_string_lossy(), r"hello\nworld");

        let res = grep_files_fast(params, &allowed, false, None).await;
        assert!(
            res.is_err(),
            "\\n in pattern should error when multiline=false"
        );
    }

    /// rg `-F` equivalent — special regex chars treated as literals.
    #[tokio::test]
    async fn test_fixed_strings_literal_search() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        std::fs::write(root.join("a.txt"), "price: $9.99 USD\nprice: $99 USD\n").unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);
        let mut params = base_params(&root.to_string_lossy(), "$9.99");
        params.fixed_strings = true;

        let res = grep_files_fast(params, &allowed, false, None)
            .await
            .unwrap();
        match res.result {
            GrepResult::Matches(m) => {
                assert_eq!(m.len(), 1);
                assert!(m[0].line.contains("$9.99"));
            }
            _ => panic!("unexpected variant"),
        }
    }

    /// rg `-w` equivalent — word boundary required.
    #[tokio::test]
    async fn test_whole_word_match() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        std::fs::write(
            root.join("a.txt"),
            "foo\nfoobar\nbarfoo\nfoo_baz\n  foo  \n",
        )
        .unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);
        let mut params = base_params(&root.to_string_lossy(), "foo");
        params.whole_word = true;

        let res = grep_files_fast(params, &allowed, false, None)
            .await
            .unwrap();
        match res.result {
            GrepResult::Matches(m) => {
                // "foo" and "  foo  " match; "foobar", "barfoo", "foo_baz" do not.
                assert_eq!(
                    m.len(),
                    2,
                    "got: {:?}",
                    m.iter().map(|x| &x.line).collect::<Vec<_>>()
                );
            }
            _ => panic!("unexpected variant"),
        }
    }

    /// fancy engine: backreferences work (impossible with the regex crate).
    #[tokio::test]
    async fn test_fancy_backreference_grep() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        std::fs::write(
            root.join("a.rs"),
            "hello hello world\nfoo bar baz\nrepeat repeat now\n",
        )
        .unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);
        // Match `word word` — the same word twice in a row.
        let mut params = base_params(&root.to_string_lossy(), r"\b(\w+) \1\b");
        params.engine = GrepEngine::Fancy;
        params.file_pattern = Some("*.rs".into());

        let res = grep_files_fast(params, &allowed, false, None)
            .await
            .unwrap();
        match res.result {
            GrepResult::Matches(m) => {
                // "hello hello" + "repeat repeat" — two matched lines.
                assert_eq!(
                    m.len(),
                    2,
                    "got {:?}",
                    m.iter().map(|x| &x.line).collect::<Vec<_>>()
                );
            }
            _ => panic!("unexpected variant"),
        }
    }

    /// BUG BH-10: after-context from one file must never attach to a match in a
    /// different file. The parallel walker previously appended After-context
    /// lines to a single shared `Vec::last_mut()`, so with multiple worker
    /// threads the trailing context of file A could land on a match from file B.
    #[tokio::test]
    async fn test_after_context_not_cross_file_contaminated() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();

        // Many small files maximise cross-thread interleaving of pushes. Each
        // file has exactly one matching line plus one unique after-context
        // line, both tagged with the file index so mismatched attribution is
        // detectable per match.
        const FILES: usize = 200;
        for i in 0..FILES {
            std::fs::write(
                root.join(format!("f{i:04}.txt")),
                format!("MATCHLINE {i}\nAFTERLINE {i}\n"),
            )
            .unwrap();
        }

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        // The assertion is deterministic (any mismatch fails); repetition just
        // makes the old buggy behaviour essentially certain to surface.
        for _ in 0..10 {
            let mut params = base_params(&root.to_string_lossy(), r"^MATCHLINE (\d+)$");
            params.context_after = 1;
            params.file_pattern = Some("*.txt".into());

            let res = grep_files_fast(params, &allowed, false, None)
                .await
                .unwrap();
            let matches = match res.result {
                GrepResult::Matches(m) => m,
                _ => panic!("unexpected variant"),
            };
            assert_eq!(matches.len(), FILES, "every file should match exactly once");
            for m in &matches {
                let match_idx = m.line.trim_start_matches("MATCHLINE ").trim();
                assert_eq!(
                    m.after_context.len(),
                    1,
                    "match {:?} has wrong after-context {:?}",
                    m.line,
                    m.after_context
                );
                let after_idx = m.after_context[0].trim_start_matches("AFTERLINE ").trim();
                assert_eq!(
                    match_idx, after_idx,
                    "after-context {:?} does not belong to match {:?} (cross-file contamination)",
                    m.after_context[0], m.line
                );
            }
        }
    }

    /// `maxDepth` caps directory recursion.
    #[tokio::test]
    async fn test_max_depth_limit() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        std::fs::write(root.join("top.txt"), "FINDME\n").unwrap();
        let sub = root.join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("deep.txt"), "FINDME\n").unwrap();

        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);
        let mut params = base_params(&root.to_string_lossy(), "FINDME");
        params.max_depth = 1; // only root level

        let res = grep_files_fast(params, &allowed, false, None)
            .await
            .unwrap();
        match res.result {
            GrepResult::Matches(m) => {
                assert_eq!(m.len(), 1, "only top.txt should be matched");
                assert!(m[0].path.to_string_lossy().contains("top.txt"));
            }
            _ => panic!("unexpected variant"),
        }
    }

    /// BH-31: a caller-supplied enormous contextAfter must never overflow and
    /// panic ("grep worker panicked"). The fancy path did unchecked
    /// `line_idx + 1 + ctx_after` arithmetic; the regex path forwards the value
    /// to grep-searcher. Both must survive `usize::MAX` and return the match.
    #[tokio::test]
    async fn test_huge_context_after_no_panic() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        std::fs::write(root.join("a.txt"), "one\nFINDME\nthree\n").unwrap();
        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        for engine in [GrepEngine::Regex, GrepEngine::Fancy] {
            let mut params = base_params(&root.to_string_lossy(), "FINDME");
            params.context_after = usize::MAX;
            params.context_before = usize::MAX;
            params.file_pattern = Some("*.txt".into());
            params.engine = engine;

            let res = grep_files_fast(params, &allowed, false, None)
                .await
                .unwrap_or_else(|e| panic!("engine {engine:?} errored: {e}"));
            match res.result {
                GrepResult::Matches(m) => {
                    assert_eq!(m.len(), 1, "engine {engine:?} should find one match");
                    assert!(m[0].line.contains("FINDME"));
                    // Clamped to the single trailing line, not usize::MAX.
                    assert_eq!(m[0].after_context, vec!["three".to_string()]);
                    assert_eq!(m[0].before_context, vec!["one".to_string()]);
                }
                _ => panic!("unexpected variant"),
            }
        }
    }

    /// BH-23: count mode must honour maxMatches (cap the total counted) and
    /// report the true total via stats.matches_found (previously always 0).
    #[tokio::test]
    async fn test_count_mode_respects_max_matches() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        // 3 files, 2 matching lines each => 6 matches total.
        for i in 0..3 {
            std::fs::write(root.join(format!("f{i}.txt")), "HIT one\nmiss\nHIT two\n").unwrap();
        }
        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        // Unlimited: total counted == 6, matches_found == 6.
        {
            let mut params = base_params(&root.to_string_lossy(), "HIT");
            params.output_mode = GrepOutputMode::CountOnly;
            params.file_pattern = Some("*.txt".into());
            let res = grep_files_fast(params, &allowed, false, None)
                .await
                .unwrap();
            let total: usize = match res.result {
                GrepResult::Counts(c) => c.iter().map(|g| g.count).sum(),
                _ => panic!("unexpected variant"),
            };
            assert_eq!(total, 6, "unlimited count total");
            assert_eq!(res.stats.matches_found, 6, "matchesFound in count mode");
        }

        // Capped at 4: total counted must not exceed the budget, and
        // matches_found must equal the capped total (not 0).
        {
            let mut params = base_params(&root.to_string_lossy(), "HIT");
            params.output_mode = GrepOutputMode::CountOnly;
            params.file_pattern = Some("*.txt".into());
            params.max_matches = 4;
            let res = grep_files_fast(params, &allowed, false, None)
                .await
                .unwrap();
            let total: usize = match res.result {
                GrepResult::Counts(c) => c.iter().map(|g| g.count).sum(),
                _ => panic!("unexpected variant"),
            };
            assert!(total <= 4, "count total {total} must respect maxMatches=4");
            assert_eq!(
                res.stats.matches_found as usize, total,
                "matchesFound must equal the capped count total"
            );
        }
    }

    /// BH-24: a binary (or unreadable) file encountered during the walk must not
    /// be billed as searched. files_searched / bytes_searched should reflect the
    /// single text file actually read, and the binary file should be counted as
    /// skipped.
    #[tokio::test]
    async fn test_binary_file_not_counted_as_searched() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        std::fs::write(root.join("a.txt"), "FINDME here\n").unwrap();
        // NUL bytes trigger grep-searcher's binary detection.
        std::fs::write(root.join("b.bin"), b"\x00\x01\x02BINARY\x00DATA\x00").unwrap();
        let a_len = std::fs::metadata(root.join("a.txt")).unwrap().len();
        let allowed = AllowedDirs::new(vec![root.to_path_buf()]);

        for engine in [GrepEngine::Regex, GrepEngine::Fancy] {
            let mut params = base_params(&root.to_string_lossy(), "FINDME");
            params.engine = engine;
            let res = grep_files_fast(params, &allowed, false, None)
                .await
                .unwrap();
            let stats = res.stats;
            assert_eq!(
                stats.files_seen, 2,
                "engine {engine:?}: both files are candidates"
            );
            assert_eq!(
                stats.files_searched, 1,
                "engine {engine:?}: only the text file is actually searched"
            );
            assert_eq!(
                stats.bytes_searched, a_len,
                "engine {engine:?}: bytes_searched excludes the binary file"
            );
            assert_eq!(
                stats.skipped_binary, 1,
                "engine {engine:?}: binary file skipped"
            );
        }
    }
}
