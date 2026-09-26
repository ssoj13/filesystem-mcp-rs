//! Statistics for a file or a directory tree: totals, a breakdown by extension, the largest
//! files and a per-child (`du`-style) breakdown.
//!
//! The walk is parallel and tolerates what it cannot read: an unreadable directory is counted
//! and reported, not fatal. A summary (`StatsOptions::summary`) can be answered from the
//! locate index instead of the disk, which is instant but only as fresh as the last scan.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::ffi::OsString;
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::{DirEntry, ParallelVisitor, ParallelVisitorBuilder, WalkBuilder, WalkState};

use crate::core::format::format_size;

/// Statistics about a file or directory
#[derive(Debug, Clone)]
pub struct FileStats {
    /// Total number of files
    pub total_files: usize,
    /// Total number of directories (beneath the path, not counting it)
    pub total_dirs: usize,
    /// Total size in bytes
    pub total_size: u64,
    /// Human-readable size
    pub total_size_human: String,
    /// Breakdown by extension
    pub by_extension: HashMap<String, ExtensionStats>,
    /// Largest files (sorted by size desc)
    pub largest_files: Vec<FileInfo>,
    /// Direct children of the path, largest first (only when asked for)
    pub by_child: Vec<ChildStats>,
    /// What the children beyond the limit add up to
    pub children_omitted: Option<ChildStats>,
    /// Symlinks and junctions met; they are not followed
    pub links: usize,
    /// Files whose content lives only in the cloud (OneDrive, iCloud, Dropbox placeholders):
    /// counted in the totals, but taking no room on the disk
    pub cloud_only_files: usize,
    pub cloud_only_bytes: u64,
    /// What could not be read
    pub skipped: Skipped,
    /// The walk hit its time limit: the numbers are lower bounds
    pub incomplete: bool,
    pub source: Source,
    /// Index answers only: when the index was last checked against the disk (unix seconds)
    pub as_of: Option<i64>,
    /// Index answers only: the index skipped entries it could not read
    pub index_partial: bool,
    /// Index answers only: something changed in these directories after the index was checked
    pub changed_since_scan: bool,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Live,
    Index,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Live => "live",
            Source::Index => "index",
        }
    }
}

/// Stats per extension
#[derive(Debug, Clone, Default)]
pub struct ExtensionStats {
    pub count: usize,
    pub size: u64,
}

/// Info about a single file
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: String,
    pub size: u64,
}

/// One direct child of the path, with everything beneath it.
#[derive(Debug, Clone, Default)]
pub struct ChildStats {
    pub name: String,
    pub is_dir: bool,
    pub bytes: u64,
    pub files: u64,
    pub dirs: u64,
}

#[derive(Debug, Clone, Default)]
pub struct Skipped {
    pub count: usize,
    pub examples: Vec<String>,
}

const SKIP_EXAMPLES: usize = 20;

/// Totals the locate index holds for one directory.
#[derive(Debug, Clone)]
pub struct IndexedTotals {
    pub bytes: u64,
    pub files: u64,
    pub dirs: u64,
    pub as_of: Option<i64>,
    pub partial: bool,
}

/// Looks directories up in the index, in order; `None` where it has nothing.
pub type IndexLookup = Arc<dyn Fn(&[PathBuf]) -> Vec<Option<IndexedTotals>> + Send + Sync>;

#[derive(Debug, Clone)]
pub struct StatsOptions {
    /// Descend into subdirectories (default true)
    pub recursive: bool,
    /// How many of the largest files to return
    pub largest_count: usize,
    /// Files smaller than this are left out of the largest list (they still count)
    pub min_size: u64,
    /// Deepest level to walk, counted from the path (1 = its direct children)
    pub max_depth: Option<usize>,
    /// Globs of names or relative paths to skip, with everything beneath a matching directory
    pub exclude: Vec<String>,
    /// Return the per-child breakdown
    pub children: bool,
    pub children_limit: usize,
    /// Extensions listed individually; the rest fall into "(other)"
    pub extensions_limit: usize,
    /// Give up walking after this long and say so (`None`: no limit)
    pub timeout: Option<Duration>,
    /// Totals and children only, taken from the index when it can answer
    pub summary: bool,
    /// Never answer from the index
    pub fresh: bool,
}

impl Default for StatsOptions {
    fn default() -> Self {
        Self {
            recursive: true,
            largest_count: 10,
            min_size: 0,
            max_depth: None,
            exclude: Vec::new(),
            children: false,
            children_limit: 50,
            extensions_limit: 100,
            timeout: Some(Duration::from_secs(120)),
            summary: false,
            fresh: false,
        }
    }
}

/// Get statistics for a file or directory
pub async fn file_stats_with(
    path: &Path,
    options: StatsOptions,
    index: Option<IndexLookup>,
) -> Result<FileStats> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || file_stats_sync(&path, &options, index.as_ref())).await?
}

fn file_stats_sync(
    path: &Path,
    options: &StatsOptions,
    index: Option<&IndexLookup>,
) -> Result<FileStats> {
    let started = Instant::now();
    let meta = std::fs::metadata(path)
        .with_context(|| format!("Path does not exist: {}", path.display()))?;
    if meta.is_file() {
        return Ok(single_file(path, &meta, started));
    }
    if !meta.is_dir() {
        bail!("Path does not exist: {}", path.display());
    }
    if options.summary
        && !options.fresh
        && let Some(lookup) = index
        && let Some(stats) = from_index(path, options, lookup, started)?
    {
        return Ok(stats);
    }
    live_walk(path, options, started)
}

fn empty_stats(source: Source, started: Instant) -> FileStats {
    FileStats {
        total_files: 0,
        total_dirs: 0,
        total_size: 0,
        total_size_human: format_size(0),
        by_extension: HashMap::new(),
        largest_files: Vec::new(),
        by_child: Vec::new(),
        children_omitted: None,
        links: 0,
        cloud_only_files: 0,
        cloud_only_bytes: 0,
        skipped: Skipped::default(),
        incomplete: false,
        source,
        as_of: None,
        index_partial: false,
        changed_since_scan: false,
        elapsed_ms: started.elapsed().as_millis() as u64,
    }
}

fn single_file(path: &Path, meta: &Metadata, started: Instant) -> FileStats {
    let size = meta.len();
    let mut stats = empty_stats(Source::Live, started);
    stats.total_files = 1;
    stats.total_size = size;
    stats.total_size_human = format_size(size);
    stats.by_extension.insert(
        extension_label(&extension_key(path)),
        ExtensionStats { count: 1, size },
    );
    stats.largest_files.push(FileInfo {
        path: path.display().to_string(),
        size,
    });
    stats.elapsed_ms = started.elapsed().as_millis() as u64;
    stats
}

/// Totals and children straight from the index. `None` when the index cannot vouch for
/// every directory involved, so the caller walks the disk instead.
fn from_index(
    path: &Path,
    options: &StatsOptions,
    lookup: &IndexLookup,
    started: Instant,
) -> Result<Option<FileStats>> {
    // The index holds whole-subtree totals only.
    if !options.recursive || options.max_depth.is_some() || !options.exclude.is_empty() {
        return Ok(None);
    }
    let mut dirs: Vec<(String, PathBuf)> = Vec::new();
    let mut files: Vec<ChildStats> = Vec::new();
    for entry in std::fs::read_dir(path)
        .with_context(|| format!("Cannot read directory: {}", path.display()))?
    {
        let Ok(entry) = entry else { continue };
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        if kind.is_dir() {
            dirs.push((name, entry.path()));
        } else if kind.is_file() {
            files.push(ChildStats {
                name,
                is_dir: false,
                bytes: entry.metadata().map(|meta| meta.len()).unwrap_or(0),
                files: 1,
                dirs: 0,
            });
        }
    }
    let mut asked = vec![path.to_path_buf()];
    asked.extend(dirs.iter().map(|(_, dir)| dir.clone()));
    let answers = lookup(&asked);
    let Some(Some(root)) = answers.first() else {
        return Ok(None);
    };
    let mut children = files;
    let mut as_of = root.as_of;
    let mut partial = root.partial;
    for ((name, _), answer) in dirs.iter().zip(&answers[1..]) {
        // A directory the index does not know is newer than the index: do not guess.
        let Some(totals) = answer else {
            return Ok(None);
        };
        as_of = match (as_of, totals.as_of) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        partial |= totals.partial;
        children.push(ChildStats {
            name: name.clone(),
            is_dir: true,
            bytes: totals.bytes,
            files: totals.files,
            dirs: totals.dirs,
        });
    }
    let mut stats = empty_stats(Source::Index, started);
    stats.total_files = root.files as usize;
    stats.total_dirs = root.dirs as usize;
    stats.total_size = root.bytes;
    stats.total_size_human = format_size(root.bytes);
    stats.as_of = as_of;
    stats.index_partial = partial;
    stats.changed_since_scan = as_of.is_some_and(|checked| {
        std::iter::once(path)
            .chain(dirs.iter().map(|(_, dir)| dir.as_path()))
            .any(|dir| modified_secs(dir).is_some_and(|modified| modified > checked))
    });
    if options.children {
        (stats.by_child, stats.children_omitted) = limit_children(children, options.children_limit);
    }
    stats.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(Some(stats))
}

fn modified_secs(path: &Path) -> Option<i64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let secs = modified
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(secs as i64)
}

/// Largest first; whatever is beyond `limit` is folded into one remainder row.
fn limit_children(
    mut children: Vec<ChildStats>,
    limit: usize,
) -> (Vec<ChildStats>, Option<ChildStats>) {
    children.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));
    if children.len() <= limit {
        return (children, None);
    }
    let mut rest = ChildStats {
        name: format!("({} more)", children.len() - limit),
        ..ChildStats::default()
    };
    for child in children.split_off(limit) {
        rest.bytes += child.bytes;
        rest.files += child.files;
        rest.dirs += child.dirs;
    }
    (children, Some(rest))
}

fn build_excludes(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(
            Glob::new(pattern).with_context(|| format!("Invalid exclude pattern: {pattern}"))?,
        );
    }
    Ok(builder.build()?)
}

fn is_excluded(set: &GlobSet, base: &Path, path: &Path) -> bool {
    let relative = path.strip_prefix(base).unwrap_or(path);
    set.is_match(relative)
        || path
            .file_name()
            .is_some_and(|name| set.is_match(Path::new(name)))
}

/// One walker thread's tally, merged into the shared one when the thread is done.
#[derive(Default)]
struct Tally {
    files: usize,
    dirs: usize,
    size: u64,
    links: usize,
    cloud_files: usize,
    cloud_bytes: u64,
    /// Lowercased extension without the dot; empty for none
    by_extension: HashMap<String, ExtensionStats>,
    /// Smallest of the kept files on top
    largest: BinaryHeap<Reverse<(u64, String)>>,
    children: HashMap<OsString, ChildStats>,
    skipped: Skipped,
}

impl Tally {
    fn skip(&mut self, what: String) {
        self.skipped.count += 1;
        if self.skipped.examples.len() < SKIP_EXAMPLES {
            self.skipped.examples.push(what);
        }
    }

    fn keep_largest(&mut self, limit: usize, size: u64, describe: impl FnOnce() -> String) {
        if limit == 0 {
            return;
        }
        if self.largest.len() < limit {
            self.largest.push(Reverse((size, describe())));
        } else if let Some(Reverse((smallest, _))) = self.largest.peek()
            && size > *smallest
        {
            self.largest.pop();
            self.largest.push(Reverse((size, describe())));
        }
    }

    fn merge(&mut self, other: Tally, limit: usize) {
        self.files += other.files;
        self.dirs += other.dirs;
        self.size = self.size.saturating_add(other.size);
        self.links += other.links;
        self.cloud_files += other.cloud_files;
        self.cloud_bytes = self.cloud_bytes.saturating_add(other.cloud_bytes);
        for (key, stats) in other.by_extension {
            let mine = self.by_extension.entry(key).or_default();
            mine.count += stats.count;
            mine.size = mine.size.saturating_add(stats.size);
        }
        for Reverse((size, path)) in other.largest {
            self.keep_largest(limit, size, || path);
        }
        for (name, child) in other.children {
            let mine = self.children.entry(name).or_default();
            if mine.name.is_empty() {
                mine.name = child.name;
            }
            mine.is_dir |= child.is_dir;
            mine.bytes = mine.bytes.saturating_add(child.bytes);
            mine.files += child.files;
            mine.dirs += child.dirs;
        }
        self.skipped.count += other.skipped.count;
        for example in other.skipped.examples {
            if self.skipped.examples.len() < SKIP_EXAMPLES {
                self.skipped.examples.push(example);
            }
        }
    }
}

struct Shared {
    base: PathBuf,
    largest: usize,
    min_size: u64,
    children: bool,
    deadline: Option<Instant>,
    timed_out: AtomicBool,
    total: Mutex<Tally>,
}

struct VisitorBuilder<'s> {
    shared: &'s Shared,
}

impl<'s> ParallelVisitorBuilder<'s> for VisitorBuilder<'s> {
    fn build(&mut self) -> Box<dyn ParallelVisitor + 's> {
        Box::new(Visitor {
            shared: self.shared,
            tally: Tally::default(),
        })
    }
}

struct Visitor<'s> {
    shared: &'s Shared,
    tally: Tally,
}

impl Drop for Visitor<'_> {
    fn drop(&mut self) {
        let tally = std::mem::take(&mut self.tally);
        if let Ok(mut total) = self.shared.total.lock() {
            total.merge(tally, self.shared.largest);
        }
    }
}

impl Visitor<'_> {
    /// The direct child of the base that `entry` lies in or is.
    fn child_of(&mut self, entry: &DirEntry) -> Option<&mut ChildStats> {
        let relative = entry.path().strip_prefix(&self.shared.base).ok()?;
        let first = relative.components().next()?;
        let key = first.as_os_str();
        if !self.tally.children.contains_key(key) {
            self.tally.children.insert(
                key.to_os_string(),
                ChildStats {
                    name: key.to_string_lossy().into_owned(),
                    ..ChildStats::default()
                },
            );
        }
        self.tally.children.get_mut(key)
    }
}

impl ParallelVisitor for Visitor<'_> {
    fn visit(&mut self, entry: Result<DirEntry, ignore::Error>) -> WalkState {
        if let Some(deadline) = self.shared.deadline
            && Instant::now() >= deadline
        {
            self.shared.timed_out.store(true, Ordering::Relaxed);
            return WalkState::Quit;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                self.tally.skip(error.to_string());
                return WalkState::Continue;
            }
        };
        if entry.depth() == 0 {
            return WalkState::Continue;
        }
        let Some(kind) = entry.file_type() else {
            return WalkState::Continue;
        };
        let direct = entry.depth() == 1;
        if kind.is_dir() {
            self.tally.dirs += 1;
            if self.shared.children
                && let Some(child) = self.child_of(&entry)
            {
                child.is_dir = true;
                if !direct {
                    child.dirs += 1;
                }
            }
            return WalkState::Continue;
        }
        if kind.is_symlink() {
            self.tally.links += 1;
            return WalkState::Continue;
        }
        let meta = match entry.metadata() {
            Ok(meta) => meta,
            Err(error) => {
                self.tally.skip(error.to_string());
                return WalkState::Continue;
            }
        };
        let size = meta.len();
        self.tally.files += 1;
        self.tally.size = self.tally.size.saturating_add(size);
        if is_cloud_only(&meta) {
            self.tally.cloud_files += 1;
            self.tally.cloud_bytes = self.tally.cloud_bytes.saturating_add(size);
        }
        let key = extension_key(entry.path());
        match self.tally.by_extension.get_mut(&key) {
            Some(stats) => {
                stats.count += 1;
                stats.size = stats.size.saturating_add(size);
            }
            None => {
                self.tally
                    .by_extension
                    .insert(key, ExtensionStats { count: 1, size });
            }
        }
        if size >= self.shared.min_size {
            let base = &self.shared.base;
            let path = entry.path();
            let limit = self.shared.largest;
            self.tally.keep_largest(limit, size, || {
                path.strip_prefix(base)
                    .map(|relative| relative.display().to_string())
                    .unwrap_or_else(|_| path.display().to_string())
            });
        }
        if self.shared.children
            && let Some(child) = self.child_of(&entry)
        {
            child.bytes = child.bytes.saturating_add(size);
            child.files += 1;
        }
        WalkState::Continue
    }
}

fn live_walk(path: &Path, options: &StatsOptions, started: Instant) -> Result<FileStats> {
    let excludes = build_excludes(&options.exclude)?;
    let mut builder = WalkBuilder::new(path);
    builder
        .standard_filters(false)
        .hidden(false)
        .follow_links(false)
        .threads(
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .min(8),
        )
        .max_depth(if options.recursive {
            options.max_depth
        } else {
            Some(1)
        });
    if !options.exclude.is_empty() {
        let base = path.to_path_buf();
        builder.filter_entry(move |entry| !is_excluded(&excludes, &base, entry.path()));
    }
    let shared = Shared {
        base: path.to_path_buf(),
        largest: options.largest_count,
        min_size: options.min_size,
        children: options.children,
        deadline: options.timeout.map(|limit| started + limit),
        timed_out: AtomicBool::new(false),
        total: Mutex::new(Tally::default()),
    };
    builder
        .build_parallel()
        .visit(&mut VisitorBuilder { shared: &shared });
    let incomplete = shared.timed_out.load(Ordering::Relaxed);
    let tally = shared
        .total
        .into_inner()
        .map_err(|_| anyhow::anyhow!("a walker thread panicked"))?;

    let mut stats = empty_stats(Source::Live, started);
    stats.total_files = tally.files;
    stats.total_dirs = tally.dirs;
    stats.total_size = tally.size;
    stats.total_size_human = format_size(tally.size);
    stats.links = tally.links;
    stats.cloud_only_files = tally.cloud_files;
    stats.cloud_only_bytes = tally.cloud_bytes;
    stats.skipped = tally.skipped;
    stats.incomplete = incomplete;
    stats.by_extension = fold_extensions(tally.by_extension, options.extensions_limit);
    // Sort files by size (descending); the heap kept only the top N
    let mut largest: Vec<(u64, String)> = tally
        .largest
        .into_iter()
        .map(|Reverse(entry)| entry)
        .collect();
    largest.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    stats.largest_files = largest
        .into_iter()
        .map(|(size, path)| FileInfo { path, size })
        .collect();
    if options.children {
        (stats.by_child, stats.children_omitted) = limit_children(
            tally.children.into_values().collect(),
            options.children_limit,
        );
    }
    stats.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(stats)
}

/// The `limit` biggest extensions by size keep their own entry; the rest become "(other)".
fn fold_extensions(
    by_extension: HashMap<String, ExtensionStats>,
    limit: usize,
) -> HashMap<String, ExtensionStats> {
    let mut all: Vec<(String, ExtensionStats)> = by_extension.into_iter().collect();
    all.sort_by(|a, b| b.1.size.cmp(&a.1.size).then_with(|| a.0.cmp(&b.0)));
    let mut out = HashMap::new();
    let mut other = ExtensionStats::default();
    for (index, (key, stats)) in all.into_iter().enumerate() {
        if index < limit.max(1) {
            out.insert(extension_label(&key), stats);
        } else {
            other.count += stats.count;
            other.size = other.size.saturating_add(stats.size);
        }
    }
    if other.count > 0 {
        out.insert("(other)".to_string(), other);
    }
    out
}

/// Lowercased extension without the dot; empty when there is none.
fn extension_key(path: &Path) -> String {
    path.extension()
        .map(|e| {
            let text = e.to_string_lossy();
            if text.bytes().any(|b| b.is_ascii_uppercase()) {
                text.to_lowercase()
            } else {
                text.into_owned()
            }
        })
        .unwrap_or_default()
}

fn extension_label(key: &str) -> String {
    if key.is_empty() {
        "(no extension)".to_string()
    } else {
        format!(".{key}")
    }
}

/// A placeholder whose content is not on this disk (OneDrive, iCloud and Dropbox files
/// that are online-only).
#[cfg(windows)]
fn is_cloud_only(meta: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const OFFLINE: u32 = 0x0000_1000;
    const RECALL_ON_OPEN: u32 = 0x0004_0000;
    const RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
    meta.file_attributes() & (OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS) != 0
}

#[cfg(not(windows))]
fn is_cloud_only(_meta: &Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    async fn file_stats(path: &Path, recursive: bool, largest_count: usize) -> Result<FileStats> {
        file_stats_with(
            path,
            StatsOptions {
                recursive,
                largest_count,
                ..StatsOptions::default()
            },
            None,
        )
        .await
    }

    #[tokio::test]
    async fn test_single_file_stats() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("test.txt");
        fs::write(&file, "hello world").unwrap();

        let stats = file_stats(&file, true, 10).await.unwrap();

        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_dirs, 0);
        assert_eq!(stats.total_size, 11); // "hello world" = 11 bytes
        assert_eq!(stats.by_extension.get(".txt").unwrap().count, 1);
        assert_eq!(stats.largest_files.len(), 1);
    }

    #[tokio::test]
    async fn test_directory_stats_recursive() {
        let dir = tempdir().unwrap();

        // Create structure:
        // /
        //   file1.txt (10 bytes)
        //   subdir/
        //     file2.rs (20 bytes)
        //     file3.rs (30 bytes)

        fs::write(dir.path().join("file1.txt"), "0123456789").unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        fs::write(dir.path().join("subdir/file2.rs"), "01234567890123456789").unwrap();
        fs::write(
            dir.path().join("subdir/file3.rs"),
            "012345678901234567890123456789",
        )
        .unwrap();

        let stats = file_stats(dir.path(), true, 10).await.unwrap();

        assert_eq!(stats.total_files, 3);
        assert_eq!(stats.total_dirs, 1);
        assert_eq!(stats.total_size, 60);

        assert_eq!(stats.by_extension.get(".txt").unwrap().count, 1);
        assert_eq!(stats.by_extension.get(".rs").unwrap().count, 2);

        // Largest file should be first
        assert!(stats.largest_files[0].path.contains("file3.rs"));
        assert_eq!(stats.largest_files[0].size, 30);
    }

    #[tokio::test]
    async fn test_directory_stats_non_recursive() {
        let dir = tempdir().unwrap();

        fs::write(dir.path().join("file1.txt"), "test").unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        fs::write(dir.path().join("subdir/file2.txt"), "nested").unwrap();

        let stats = file_stats(dir.path(), false, 10).await.unwrap();

        // Should only count top-level file
        assert_eq!(stats.total_files, 1);
        assert_eq!(stats.total_dirs, 1);
        assert_eq!(stats.total_size, 4);
    }

    #[tokio::test]
    async fn test_largest_files_limit() {
        let dir = tempdir().unwrap();

        // Create 5 files
        for i in 1..=5 {
            let content = "x".repeat(i * 10);
            fs::write(dir.path().join(format!("file{}.txt", i)), content).unwrap();
        }

        let stats = file_stats(dir.path(), true, 3).await.unwrap();

        // Should only return top 3
        assert_eq!(stats.largest_files.len(), 3);
        assert_eq!(stats.largest_files[0].size, 50);
        assert_eq!(stats.largest_files[1].size, 40);
        assert_eq!(stats.largest_files[2].size, 30);
    }

    #[tokio::test]
    async fn test_nonexistent_path() {
        let result = file_stats(Path::new("/nonexistent/path"), true, 10).await;
        assert!(result.is_err());
    }

    /// a/x.bin (100), a/b/y.bin (50), a/b/skip.log (5), c.bin (7)
    fn tree() -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("a").join("b")).unwrap();
        fs::write(dir.path().join("a").join("x.bin"), [0u8; 100]).unwrap();
        fs::write(dir.path().join("a").join("b").join("y.bin"), [0u8; 50]).unwrap();
        fs::write(dir.path().join("a").join("b").join("skip.log"), [0u8; 5]).unwrap();
        fs::write(dir.path().join("c.bin"), [0u8; 7]).unwrap();
        dir
    }

    fn child_options() -> StatsOptions {
        StatsOptions {
            children: true,
            ..StatsOptions::default()
        }
    }

    #[tokio::test]
    async fn children_break_the_total_down_largest_first() {
        let dir = tree();

        let stats = file_stats_with(dir.path(), child_options(), None)
            .await
            .unwrap();

        assert_eq!(stats.source, Source::Live);
        assert_eq!(stats.total_size, 162);
        let got: Vec<_> = stats
            .by_child
            .iter()
            .map(|c| (c.name.as_str(), c.is_dir, c.bytes, c.files, c.dirs))
            .collect();
        assert_eq!(got, [("a", true, 155, 3, 1), ("c.bin", false, 7, 1, 0)]);
        assert!(stats.children_omitted.is_none());
    }

    #[tokio::test]
    async fn children_beyond_the_limit_are_folded_into_one_row() {
        let dir = tree();
        let options = StatsOptions {
            children_limit: 1,
            ..child_options()
        };

        let stats = file_stats_with(dir.path(), options, None).await.unwrap();

        assert_eq!(stats.by_child.len(), 1);
        let rest = stats.children_omitted.unwrap();
        assert_eq!(
            (rest.name.as_str(), rest.bytes, rest.files),
            ("(1 more)", 7, 1)
        );
    }

    #[tokio::test]
    async fn exclude_skips_matching_names_with_everything_beneath() {
        let dir = tree();
        let options = StatsOptions {
            exclude: vec!["b".into(), "*.log".into()],
            ..child_options()
        };

        let stats = file_stats_with(dir.path(), options, None).await.unwrap();

        assert_eq!(stats.total_size, 107);
        assert_eq!(stats.total_dirs, 1);
        assert_eq!(stats.by_child[0].bytes, 100);
    }

    #[tokio::test]
    async fn max_depth_stops_at_the_given_level() {
        let dir = tree();
        let options = StatsOptions {
            max_depth: Some(2),
            ..StatsOptions::default()
        };

        let stats = file_stats_with(dir.path(), options, None).await.unwrap();

        // a\x.bin and c.bin; a\b is seen but not entered.
        assert_eq!(stats.total_size, 107);
        assert_eq!(stats.total_dirs, 2);
    }

    #[tokio::test]
    async fn extensions_beyond_the_limit_become_other() {
        let dir = tree();
        let options = StatsOptions {
            extensions_limit: 1,
            ..StatsOptions::default()
        };

        let stats = file_stats_with(dir.path(), options, None).await.unwrap();

        assert_eq!(stats.by_extension[".bin"].size, 157);
        assert_eq!(stats.by_extension["(other)"].count, 1);
        assert_eq!(stats.by_extension.len(), 2);
    }

    #[tokio::test]
    async fn min_size_only_filters_the_largest_list() {
        let dir = tree();
        let options = StatsOptions {
            min_size: 50,
            ..StatsOptions::default()
        };

        let stats = file_stats_with(dir.path(), options, None).await.unwrap();

        assert_eq!(stats.total_files, 4);
        let sizes: Vec<u64> = stats.largest_files.iter().map(|f| f.size).collect();
        assert_eq!(sizes, [100, 50]);
    }

    #[tokio::test]
    async fn a_walk_past_its_time_limit_says_so() {
        let dir = tree();
        let options = StatsOptions {
            timeout: Some(Duration::ZERO),
            ..StatsOptions::default()
        };

        let stats = file_stats_with(dir.path(), options, None).await.unwrap();

        assert!(stats.incomplete);
    }

    fn lookup(known: Vec<(PathBuf, IndexedTotals)>) -> IndexLookup {
        Arc::new(move |paths: &[PathBuf]| {
            paths
                .iter()
                .map(|path| {
                    known
                        .iter()
                        .find(|(known, _)| known == path)
                        .map(|(_, totals)| totals.clone())
                })
                .collect()
        })
    }

    fn totals(bytes: u64, files: u64, dirs: u64) -> IndexedTotals {
        IndexedTotals {
            bytes,
            files,
            dirs,
            as_of: Some(i64::MAX),
            partial: false,
        }
    }

    #[tokio::test]
    async fn a_summary_is_answered_from_the_index_when_it_knows_every_directory() {
        let dir = tree();
        let root = dir.path().to_path_buf();
        // Numbers the disk would not give, to show which source answered.
        let index = lookup(vec![
            (root.clone(), totals(1000, 9, 3)),
            (root.join("a"), totals(900, 8, 2)),
        ]);
        let options = StatsOptions {
            summary: true,
            ..child_options()
        };

        let stats = file_stats_with(&root, options, Some(index)).await.unwrap();

        assert_eq!(stats.source, Source::Index);
        assert_eq!(
            (stats.total_size, stats.total_files, stats.total_dirs),
            (1000, 9, 3)
        );
        let got: Vec<_> = stats
            .by_child
            .iter()
            .map(|c| (c.name.as_str(), c.bytes))
            .collect();
        assert_eq!(got, [("a", 900), ("c.bin", 7)]);
        assert!(!stats.changed_since_scan);
        assert!(stats.by_extension.is_empty());
    }

    #[tokio::test]
    async fn a_summary_walks_the_disk_when_the_index_misses_a_directory() {
        let dir = tree();
        let root = dir.path().to_path_buf();
        let index = lookup(vec![(root.clone(), totals(1000, 9, 3))]);
        let options = StatsOptions {
            summary: true,
            ..child_options()
        };

        let stats = file_stats_with(&root, options, Some(index)).await.unwrap();

        assert_eq!(stats.source, Source::Live);
        assert_eq!(stats.total_size, 162);
    }

    #[tokio::test]
    async fn fresh_never_uses_the_index() {
        let dir = tree();
        let root = dir.path().to_path_buf();
        let index = lookup(vec![
            (root.clone(), totals(1000, 9, 3)),
            (root.join("a"), totals(900, 8, 2)),
        ]);
        let options = StatsOptions {
            summary: true,
            fresh: true,
            ..child_options()
        };

        let stats = file_stats_with(&root, options, Some(index)).await.unwrap();

        assert_eq!(stats.source, Source::Live);
        assert_eq!(stats.total_size, 162);
    }

    #[tokio::test]
    async fn a_directory_changed_after_the_scan_is_flagged() {
        let dir = tree();
        let root = dir.path().to_path_buf();
        let mut stale = totals(1000, 9, 3);
        stale.as_of = Some(1);
        let index = lookup(vec![(root.clone(), stale.clone()), (root.join("a"), stale)]);
        let options = StatsOptions {
            summary: true,
            ..StatsOptions::default()
        };

        let stats = file_stats_with(&root, options, Some(index)).await.unwrap();

        assert_eq!(stats.source, Source::Index);
        assert!(stats.changed_since_scan);
    }
}
