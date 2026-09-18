pub mod archive;
pub mod binary;
pub mod bulk_edit;
pub mod compare;
pub mod diff;
pub mod docx;
pub mod duplicates;
pub mod edit;
pub mod fast_grep;
// The `file_stats` tool. Named for the tool rather than for `stats`, which this wave gives to
// the tool-call statistics subsystem below.
pub mod file_stats;
pub mod fs_ops;
pub mod grep;
pub mod hash;
#[cfg(feature = "http-tools")]
pub mod http_tools;
pub mod json_reader;
pub mod line_edit;
pub mod llm;
pub mod media;
pub mod memory_v2;
pub mod mime;
pub mod murmur3;
pub mod pdf_reader;
pub mod process;
#[cfg(feature = "s3-tools")]
pub mod s3_tools;
#[cfg(feature = "screenshot-tools")]
pub mod screenshot;
// Computer control (mouse/keyboard/windows/UIA/OCR) — self-contained module.
#[cfg(any(
    feature = "ctl-input",
    feature = "ctl-uia",
    feature = "ctl-ocr",
    feature = "ctl-notify",
    feature = "ctl-clip-files"
))]
pub mod computer;
pub mod search;
pub mod spooky;
/// Tool-call statistics: which of this server's tools are used, which fail and how.
#[cfg(feature = "stats-tools")]
pub mod stats;
pub mod thinking;
pub mod watch;
pub mod wave2;
pub mod xlsx;
