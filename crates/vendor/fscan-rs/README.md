# fscan-rs

`fscan-rs` provides the filesystem scan engines shared by Squarebob and filesystem Locate. The portable engine streams entries to a caller-owned sink. The Windows NTFS engine uses Squarebob's batched directory enumeration and MFT code, with a hard entry limit before the caller receives its result.

## Scan a directory

```rust
use fscan_rs::{Visit, scan_standard};
use std::path::Path;
use std::sync::atomic::AtomicBool;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cancel = AtomicBool::new(false);
    let progress = scan_standard(
        Path::new("."),
        &cancel,
        |_| true,
        |entry, _| {
            println!("{}", entry.path.display());
            Ok::<Visit, std::io::Error>(Visit::Continue)
        },
    )?;
    eprintln!("{} entries, {} errors", progress.entries, progress.errors);
    Ok(())
}
```

The `include` callback rejects a path and, for directories, its entire subtree. Set the `AtomicBool` to cancel a running scan. The sink can return `Visit::Stop` to finish early. A sink error stops the scan and is returned as `ScanError::Sink`.

## Memory and scan results

The standard backend uses a depth-first iterator with at most 16 open directory handles. It does not collect paths into a queue or a tree. A consumer's own storage is separate: Squarebob builds a complete tree for its UI, while Locate writes batches to SQLite. This crate does not make Squarebob's UI tree memory bounded.

An unreadable child path increments `Progress::errors`; callers should treat a nonzero count as a partial scan. Failure to open the root is an error. The scanner does not follow symlinks. File names remain `OsString`, so callers can decide how to handle paths that are not UTF-8.

## Choose a backend

`scan_standard` runs on Windows, Linux, and macOS and is the low-memory choice. On Windows, `scan_ntfs_tree` returns a measured tree, and `scan_ntfs_stream` sends that tree's entries to a sink. `scan_ntfs_tree_with_progress` reports NTFS scan phases while it works. `scan_ntfs_tree_with_options(root, cancel, dedupe_hardlinks, on_progress)` lets an indexer keep every hard-link name by passing `false`; tree consumers that count disk usage can pass `true`. A native scan may need raw-volume access; its caller can fall back to `scan_standard` if NTFS is unavailable.

The NTFS backend currently materializes a tree before returning or streaming entries. It refuses scans above 250,000 nodes or MFT records, so large scans should fall back to the standard backend. This is a safety limit, not an optimized disk-backed MFT index. Native volume-root scans can require elevation and may omit alternate hard-link names; name indexes should scan volume roots with `scan_standard`. A new scan with either backend still traverses the filesystem; this crate does not implement incremental watching.

## Development

```text
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The NTFS implementation was extracted from Squarebob. The crate is independent of Squarebob's UI, cache format, and Locate's SQLite schema.
