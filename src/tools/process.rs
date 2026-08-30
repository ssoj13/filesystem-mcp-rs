use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use regex::Regex;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::RwLock;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::core::serde::ShellKind;

/// Default number of trailing output lines retained in memory for the inline
/// result when the caller requests no head/tail/filter and a log file exists.
/// The full output is always written to the log file regardless of this cap,
/// so nothing is lost — this only bounds RAM and what we echo back inline.
const DEFAULT_INLINE_TAIL_LINES: usize = 200;

/// Hard ceiling (bytes) on the assembled inline stdout/stderr string. Guards
/// the caller's context against a few pathologically long lines. Full output
/// still lives in the log file.
const MAX_INLINE_BYTES: usize = 16 * 1024;

/// How long to keep draining stdout/stderr after the process has exited before
/// giving up. EOF normally arrives within milliseconds of exit; a longer wait
/// only matters when a lingering grandchild still holds the pipe's write end
/// open (e.g. an inherited handle on Windows). On timeout we flag
/// `capture_truncated` instead of silently returning empty output.
const POST_EXIT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Last-resort guard: keep an inline string within `MAX_INLINE_BYTES`, keeping
/// the trailing (most recent) bytes and prefixing a marker. The full output is
/// always available in the log file.
fn cap_inline_bytes(s: String) -> String {
    if s.len() <= MAX_INLINE_BYTES {
        return s;
    }
    let mut start = s.len() - MAX_INLINE_BYTES;
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    format!(
        "…[inline output truncated — full output in log file]\n{}",
        &s[start..]
    )
}

// ---------------------------------------------------------------------------
// Output filter — grep-like filtering for command output
// ---------------------------------------------------------------------------

/// Grep-like filter applied to captured output before returning to caller.
/// Full output always goes to log files; this only affects inline results.
#[derive(Debug, Clone, Default)]
pub struct OutputFilter {
    /// Regex patterns — show lines matching ANY of these
    pub include: Vec<Regex>,
    /// Regex patterns — hide lines matching ANY of these (applied after include)
    pub exclude: Vec<Regex>,
    /// Context lines before each match (like grep -B)
    pub context_before: usize,
    /// Context lines after each match (like grep -A)
    pub context_after: usize,
    /// Maximum filtered lines to return (prevents context overflow)
    pub max_lines: Option<usize>,
}

impl OutputFilter {
    pub fn is_active(&self) -> bool {
        // An exclude-only filter is still a filter; keying only on `include`
        // made exclude-only filters silently inert (fail-open).
        !self.include.is_empty() || !self.exclude.is_empty()
    }
}

/// Apply grep-like filtering with context lines to output.
pub fn filter_lines(lines: &[String], filter: &OutputFilter) -> Vec<String> {
    if !filter.is_active() {
        return lines.to_vec();
    }

    // Find matching line indices. An empty `include` set means "match all",
    // then `exclude` removes lines; otherwise a line must match some include.
    let mut match_indices: Vec<bool> = vec![false; lines.len()];
    for (i, line) in lines.iter().enumerate() {
        let included =
            filter.include.is_empty() || filter.include.iter().any(|re| re.is_match(line));
        if !included {
            continue;
        }
        let excluded = filter.exclude.iter().any(|re| re.is_match(line));
        if excluded {
            continue;
        }
        match_indices[i] = true;
    }

    // Expand context windows around matches
    let mut visible: Vec<bool> = vec![false; lines.len()];
    for (i, is_match) in match_indices.iter().enumerate() {
        if !is_match {
            continue;
        }
        let start = i.saturating_sub(filter.context_before);
        let end = (i + filter.context_after + 1).min(lines.len());
        for v in &mut visible[start..end] {
            *v = true;
        }
    }

    // Collect visible lines with separator for gaps. The `max_lines` cap counts
    // only real content lines (not separators/marker) and is checked BEFORE
    // pushing, so max_lines == 0 yields no content lines instead of one.
    let total_matches = match_indices.iter().filter(|&&m| m).count();
    let mut result = Vec::new();
    let mut content_count = 0usize;
    let mut prev_visible = false;
    for (i, line) in lines.iter().enumerate() {
        if !visible[i] {
            prev_visible = false;
            continue;
        }
        if let Some(max) = filter.max_lines
            && content_count >= max
        {
            result.push(format!("... (truncated, {} total matches)", total_matches));
            break;
        }
        if !prev_visible && !result.is_empty() {
            result.push("---".to_string());
        }
        result.push(line.clone());
        content_count += 1;
        prev_visible = true;
    }
    result
}

// ---------------------------------------------------------------------------
// Output processing — combines head + filter + tail
// ---------------------------------------------------------------------------

/// Processed output with head/filter/tail sections
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct ProcessedOutput {
    pub head: Vec<String>,
    pub filtered: Vec<String>,
    pub tail: Vec<String>,
    pub total_lines: usize,
}

impl ProcessedOutput {
    /// Format into a single string with section headers
    pub fn format(&self) -> String {
        let mut parts = Vec::new();
        if !self.head.is_empty() {
            parts.push(self.head.join("\n"));
        }
        if !self.filtered.is_empty() {
            if !self.head.is_empty() {
                parts.push(format!(
                    "--- filtered ({} matches) ---",
                    self.filtered.len()
                ));
            }
            parts.push(self.filtered.join("\n"));
        }
        if !self.tail.is_empty() {
            if !parts.is_empty() {
                parts.push(format!("--- tail ({} lines) ---", self.tail.len()));
            }
            parts.push(self.tail.join("\n"));
        }
        parts.join("\n")
    }
}

/// Apply head + filter + tail processing to output lines
pub fn process_output(
    lines: &[String],
    head: Option<usize>,
    tail: Option<usize>,
    filter: Option<&OutputFilter>,
) -> ProcessedOutput {
    let total_lines = lines.len();

    // Simple case: no processing
    if head.is_none() && tail.is_none() && filter.is_none_or(|f| !f.is_active()) {
        return ProcessedOutput {
            head: Vec::new(),
            filtered: Vec::new(),
            tail: lines.to_vec(),
            total_lines,
        };
    }

    // Simple tail-only case (backward compat)
    if head.is_none() && filter.is_none_or(|f| !f.is_active()) {
        if let Some(n) = tail
            && n > 0
            && n < lines.len()
        {
            return ProcessedOutput {
                head: Vec::new(),
                filtered: Vec::new(),
                tail: lines[lines.len() - n..].to_vec(),
                total_lines,
            };
        }
        return ProcessedOutput {
            head: Vec::new(),
            filtered: Vec::new(),
            tail: lines.to_vec(),
            total_lines,
        };
    }

    let head_n = head.unwrap_or(0);
    let tail_n = tail.unwrap_or(0);
    let head_section: Vec<String> = if head_n > 0 {
        lines[..head_n.min(lines.len())].to_vec()
    } else {
        Vec::new()
    };

    let tail_section: Vec<String> = if tail_n > 0 && lines.len() > tail_n {
        let start = lines.len() - tail_n;
        // Don't overlap with head
        let start = start.max(head_n);
        if start < lines.len() {
            lines[start..].to_vec()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let filtered_section = if let Some(f) = filter {
        if f.is_active() {
            // Filter the middle section (between head and tail)
            let filter_start = head_n.min(lines.len());
            let filter_end = if tail_n > 0 && lines.len() > tail_n {
                (lines.len() - tail_n).max(filter_start)
            } else {
                lines.len()
            };
            if filter_start < filter_end {
                filter_lines(&lines[filter_start..filter_end], f)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    ProcessedOutput {
        head: head_section,
        filtered: filtered_section,
        tail: tail_section,
        total_lines,
    }
}

// ---------------------------------------------------------------------------
// Parameters and result types
// ---------------------------------------------------------------------------

/// Execution mode for run_command
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RunMode {
    /// Run synchronously, send heartbeat progress every ~30s to prevent client timeout
    #[default]
    Sync,
    /// Run in foreground, send progress notifications with output snippets every ~10s
    Managed,
    /// Run in background, return immediately with PID
    Detached,
}

/// Parameters for running a command
#[derive(Debug, Clone, Default)]
pub struct RunParams {
    /// Working directory
    pub cwd: Option<String>,
    /// Environment variables (added to current env)
    pub env: Option<HashMap<String, String>>,
    /// Clear environment before adding env vars
    pub clear_env: bool,
    /// Prepend to existing env vars (value is prepended to current value)
    pub env_prepend: Option<HashMap<String, String>>,
    /// Append to existing env vars (value is appended to current value)
    pub env_append: Option<HashMap<String, String>>,
    /// Timeout for command execution (ms)
    pub timeout_ms: Option<u64>,
    /// Watchdog: kill if still running after this time (ms)
    pub kill_after_ms: Option<u64>,
    /// Redirect stdout to file
    pub stdout_file: Option<String>,
    /// Redirect stderr to file
    pub stderr_file: Option<String>,
    /// Raw stdin bytes (from Content Plane). None = no stdin pipe.
    pub stdin_bytes: Option<Vec<u8>>,
    /// Return only first N lines of stdout
    pub stdout_head: Option<usize>,
    /// Return only last N lines of stdout
    pub stdout_tail: Option<usize>,
    /// Return only first N lines of stderr
    pub stderr_head: Option<usize>,
    /// Return only last N lines of stderr
    pub stderr_tail: Option<usize>,
    /// Output filter (grep-like) for inline results
    pub output_filter: Option<OutputFilter>,
    /// Execution mode
    pub mode: RunMode,
    /// Which shell to wrap the command in (`ShellKind::None` = spawn directly).
    pub shell: ShellKind,
    /// Capture stdout/stderr in memory and return them in result (default: true when None)
    pub capture_output: Option<bool>,
}

/// Result of command execution
#[derive(Debug, Clone)]
pub struct RunResult {
    /// Exit code (None if killed or background)
    pub exit_code: Option<i32>,
    /// Stdout output (possibly processed by head/tail/filter)
    pub stdout: String,
    /// Stderr output (possibly processed by head/tail/filter)
    pub stderr: String,
    /// Processed stdout (with sections) — only set when head/filter are used
    #[allow(dead_code)]
    pub stdout_processed: Option<ProcessedOutput>,
    /// Processed stderr (with sections) — only set when head/filter are used
    #[allow(dead_code)]
    pub stderr_processed: Option<ProcessedOutput>,
    /// Process ID (for background processes)
    pub pid: Option<u32>,
    /// Was killed by timeout/watchdog/cancellation
    pub killed: bool,
    /// Timed out waiting
    pub timed_out: bool,
    /// Cancelled by client
    pub cancelled: bool,
    /// Execution duration in ms
    pub duration_ms: u64,
    /// Running in background/detached
    pub background: bool,
    /// Timestamp when process started (Unix ms)
    pub started_at: u64,
    /// Timestamp when process finished (Unix ms)
    pub finished_at: u64,
    /// Total stdout lines before processing
    pub stdout_total_lines: usize,
    /// Total stderr lines before processing
    pub stderr_total_lines: usize,
    /// Output capture did not reach EOF before the post-exit drain timeout
    /// (e.g. a child process still holds the stdout pipe open). When true the
    /// inline stdout/stderr may be incomplete — read the log file for the full
    /// output. This never silently masquerades as empty success.
    pub capture_truncated: bool,
}

/// Background process info
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub command: String,
    pub args: Vec<String>,
    pub started_at: Instant,
    pub cwd: Option<String>,
}

/// Manager for background processes
#[derive(Clone, Default)]
pub struct ProcessManager {
    processes: Arc<RwLock<HashMap<u32, ProcessInfo>>>,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            processes: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a background process
    pub async fn register(
        &self,
        pid: u32,
        command: String,
        args: Vec<String>,
        cwd: Option<String>,
    ) {
        let mut procs = self.processes.write().await;
        procs.insert(
            pid,
            ProcessInfo {
                pid,
                command,
                args,
                started_at: Instant::now(),
                cwd,
            },
        );
    }

    /// Unregister a process (when it exits)
    pub async fn unregister(&self, pid: u32) {
        let mut procs = self.processes.write().await;
        procs.remove(&pid);
    }

    /// List all tracked background processes
    pub async fn list(&self) -> Vec<ProcessInfo> {
        let procs = self.processes.read().await;
        procs.values().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Progress callback for managed mode
// ---------------------------------------------------------------------------

/// Callback invoked periodically during command execution.
/// `elapsed_ms` = time since start, `new_lines` = recently captured output lines.
pub type ProgressCallback = Box<
    dyn Fn(u64, &[String]) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

// ---------------------------------------------------------------------------
// Shell wrapping
// ---------------------------------------------------------------------------

/// A resolved shell invocation: the program to launch plus the arguments that
/// precede the user command line.
struct ShellSpawn {
    /// Shell program to spawn (e.g. `cmd`, `sh`, `bash`, `pwsh`).
    program: String,
    /// Leading args ending with the combined command line, e.g.
    /// `["/C", line]`, `["-c", line]`, or `["-NoProfile", "-Command", line]`.
    args: Vec<String>,
    /// Windows only: append `args` to the child command line verbatim via
    /// `raw_arg` instead of MSVCRT-escaping them. Required for `cmd.exe`, whose
    /// command-line parsing does not follow the MSVCRT convention; other shells
    /// (bash/pwsh) are ordinary programs and use normal escaping. Read only on
    /// Windows, hence the platform-gated lint allowance. See `fsmcp_bug.md` #1/#2.
    #[cfg_attr(not(windows), allow(dead_code))]
    windows_raw_arg: bool,
}

/// Build the shell invocation for `kind`, or `None` when no shell is requested
/// (`ShellKind::None`), in which case the program is spawned directly.
///
/// `command` and `args` are joined into a single command line passed as the
/// final argument (`/C`, `-c`, or `-Command`). `Default` resolves to the
/// platform shell: `cmd.exe` on Windows, `sh` on Unix. `bash`/`pwsh` work on
/// every platform provided the binary is on `PATH` (git bash / PowerShell 7) —
/// this is what lets unix-style pipelines (`a | b ; c`, `tail`, `grep`) run on
/// Windows, where `cmd.exe` understands neither `;` nor those tools. See
/// `fsmcp_bug.md` #1.
fn shell_wrap(kind: ShellKind, command: &str, args: &[&str]) -> Option<ShellSpawn> {
    // Resolve the platform default to a concrete shell first, so `args` can be
    // quoted with that shell's rules before being joined onto the command line.
    let resolved = match kind {
        ShellKind::None => return None,
        ShellKind::Default if cfg!(windows) => ShellKind::Cmd,
        ShellKind::Default => ShellKind::Sh,
        other => other,
    };

    // Quote each argument per the target shell so one containing spaces or shell
    // metacharacters stays a single literal token instead of being re-split or
    // interpreted as syntax (the old `args.join(" ")` lost all argument
    // boundaries).
    let build_line = |quote: fn(&str) -> String| {
        if args.is_empty() {
            command.to_string()
        } else {
            let quoted: Vec<String> = args.iter().map(|a| quote(a)).collect();
            format!("{} {}", command, quoted.join(" "))
        }
    };

    let spawn = match resolved {
        ShellKind::Cmd => ShellSpawn {
            program: "cmd".to_string(),
            args: vec!["/C".to_string(), build_line(quote_cmd)],
            windows_raw_arg: true,
        },
        ShellKind::Sh => ShellSpawn {
            program: "sh".to_string(),
            args: vec!["-c".to_string(), build_line(quote_posix)],
            windows_raw_arg: false,
        },
        ShellKind::Bash => ShellSpawn {
            program: "bash".to_string(),
            args: vec!["-c".to_string(), build_line(quote_posix)],
            windows_raw_arg: false,
        },
        ShellKind::Pwsh => ShellSpawn {
            program: "pwsh".to_string(),
            args: vec![
                "-NoProfile".to_string(),
                "-Command".to_string(),
                build_line(quote_pwsh),
            ],
            windows_raw_arg: false,
        },
        // None returned early above; Default was resolved to Cmd/Sh.
        ShellKind::None | ShellKind::Default => unreachable!("none/default resolved above"),
    };
    Some(spawn)
}

/// Quote one argument for POSIX shells (sh/bash). Safe unquoted tokens pass
/// through; everything else is single-quoted with embedded `'` escaped as
/// `'\''`, which is fully literal in POSIX shells.
fn quote_posix(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@%_+=:,./-".contains(&b));
    if safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

/// Quote one argument for PowerShell. Safe unquoted tokens pass through;
/// otherwise single-quote and double any embedded single quote (PowerShell's
/// literal-string escaping).
fn quote_pwsh(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@%_+=:,./-".contains(&b));
    if safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "''"))
    }
}

/// Quote one argument for `cmd.exe`. Tokens with no whitespace or cmd
/// metacharacters pass through; otherwise double-quote and double embedded
/// quotes. cmd quoting is inherently imperfect (e.g. literal `%` still triggers
/// variable expansion), but this correctly handles the common case of a path or
/// value containing spaces, which the old space-join broke outright.
fn quote_cmd(arg: &str) -> String {
    let needs_quote = arg.is_empty()
        || arg
            .chars()
            .any(|c| c.is_whitespace() || "&|<>^\"()".contains(c));
    if needs_quote {
        format!("\"{}\"", arg.replace('"', "\"\""))
    } else {
        arg.to_string()
    }
}

// ---------------------------------------------------------------------------
// Temp .bat for multi-line cmd.exe (BUG5)
// ---------------------------------------------------------------------------

/// Owns a temporary `.bat` script used to run a multi-line `cmd.exe` command.
///
/// `cmd /C "<string>"` executes only the FIRST line of a multi-line string —
/// cmd does not treat embedded newlines as statement separators (unlike a batch
/// file or PowerShell `-Command`). To run every line we write the command to a
/// `.bat` (which cmd executes line-by-line) and invoke `cmd /C "<path>"`.
///
/// cmd reads the batch file LAZILY during execution, so the file must outlive
/// the child process; the guard is therefore held until the child has been
/// awaited (to the end of `run_command` for foreground runs, or moved into the
/// detached reaper task) and removes the file on `Drop`. See `BUG5.md`.
#[cfg(windows)]
struct TempScript {
    path: std::path::PathBuf,
}

#[cfg(windows)]
impl TempScript {
    /// Write `line` (the joined command, possibly multi-line) to a fresh
    /// `fsmcp-cmd-<uuid>.bat` in the system temp dir.
    ///
    /// Lines are normalized to CRLF (any existing `\r` is stripped first so a
    /// CRLF input does not become `\r\r\n`) with a trailing newline, and
    /// prefixed with `@echo off` so the command lines themselves are not echoed
    /// to stdout — matching the output of `cmd /C <string>`. A write failure is
    /// propagated rather than silently falling back to the broken single-line
    /// path, so the caller sees a real error instead of lost output.
    ///
    /// The file is written as UTF-8 and starts with `chcp 65001 >nul` so cmd
    /// interprets the subsequent (UTF-8) command lines as UTF-8 regardless of
    /// the console's default code page — otherwise a non-ASCII command (e.g. a
    /// Cyrillic path) would be read in the active code page and mojibake'd.
    async fn create(line: &str) -> Result<Self> {
        let path = std::env::temp_dir().join(format!("fsmcp-cmd-{}.bat", uuid::Uuid::new_v4()));
        let mut body = String::with_capacity(line.len() + "@echo off\r\nchcp 65001 >nul\r\n".len());
        body.push_str("@echo off\r\n");
        body.push_str("chcp 65001 >nul\r\n");
        for l in line.split('\n') {
            body.push_str(l.strip_suffix('\r').unwrap_or(l));
            body.push_str("\r\n");
        }
        tokio::fs::write(&path, body)
            .await
            .with_context(|| format!("Failed to write temp cmd script: {}", path.display()))?;
        Ok(Self { path })
    }
}

#[cfg(windows)]
impl Drop for TempScript {
    /// Best-effort removal of the temp script. The owner is dropped only after
    /// the child has exited, so cmd is no longer reading the file. An error is
    /// logged (not silently swallowed); a leftover `fsmcp-cmd-*.bat` in TEMP is
    /// harmless and only possible if the whole server is hard-killed.
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.path) {
            tracing::warn!(
                "failed to remove temp cmd script '{}': {e}",
                self.path.display()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Process tree kill
// ---------------------------------------------------------------------------

/// Kill a process and all its children (process tree kill).
/// Uses sysinfo to enumerate children recursively, then kills bottom-up.
pub fn kill_process_tree(pid: u32, force: bool) -> Result<u32> {
    use sysinfo::{Pid, Signal, System};

    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let target = Pid::from_u32(pid);

    // Collect all descendants (BFS)
    let mut to_kill = Vec::new();
    let mut queue = vec![target];
    while let Some(current) = queue.pop() {
        to_kill.push(current);
        for (child_pid, proc_info) in sys.processes() {
            if proc_info.parent() == Some(current) && !to_kill.contains(child_pid) {
                queue.push(*child_pid);
            }
        }
    }

    // Kill bottom-up (children first, then parent)
    to_kill.reverse();
    let signal = if force { Signal::Kill } else { Signal::Term };
    let mut killed_count = 0u32;
    for pid in &to_kill {
        if let Some(process) = sys.process(*pid)
            && process.kill_with(signal).unwrap_or(false)
        {
            killed_count += 1;
        }
    }
    Ok(killed_count)
}

/// Kill a process by PID using native API via sysinfo
pub fn kill_process(pid: u32, force: bool) -> Result<bool> {
    use sysinfo::{Pid, Signal, System};

    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let sysinfo_pid = Pid::from_u32(pid);

    if let Some(process) = sys.process(sysinfo_pid) {
        let signal = if force { Signal::Kill } else { Signal::Term };
        Ok(process.kill_with(signal).unwrap_or(false))
    } else {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Run a command with full control over execution, output, and lifecycle.
pub async fn run_command(
    command: &str,
    args: &[&str],
    params: RunParams,
    manager: Option<&ProcessManager>,
    cancel: Option<CancellationToken>,
    progress_cb: Option<ProgressCallback>,
) -> Result<RunResult> {
    let now_ms = || {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    };
    let started_at = now_ms();
    let start = Instant::now();

    // Shell wrapping. `shell_wrap` returns None for `ShellKind::None` (spawn the
    // program directly) or the resolved program + leading args otherwise.
    let shell_spawn = shell_wrap(params.shell, command, args);

    // BUG5: a multi-line command under cmd.exe (`shell:"cmd"`, or `shell:true`/
    // default on Windows, which both resolve to cmd) would lose every line past
    // the first, because `cmd /C "<string>"` runs only the first line. When the
    // resolved shell is cmd (the only kind that sets `windows_raw_arg`) and the
    // command line contains a newline, materialize it as a temp `.bat` and run
    // `cmd /C "<bat>"` instead. The guard keeps the file alive until the child
    // exits (foreground: to end of fn; detached: moved into the reaper) and
    // removes it on drop. Single-line cmd and every other shell are left exactly
    // as resolved by `shell_wrap`, so their behavior is unchanged.
    #[cfg(windows)]
    let mut _bat_guard: Option<TempScript> = None;
    #[cfg(windows)]
    let shell_spawn = match shell_spawn {
        Some(s) if s.windows_raw_arg && s.args.last().is_some_and(|l| l.contains('\n')) => {
            // The match guard already verified `args.last()` is Some; re-match
            // (instead of `.expect()`) to honor the project's no-panic rule.
            let line = match s.args.last() {
                Some(l) => l.clone(),
                None => bail!("cmd spawn missing command line"),
            };
            let script = TempScript::create(&line).await?;
            // Quote the path (TEMP may contain spaces). Plain `/C "<path>"`
            // handles spaces correctly; `/S` was verified to BREAK such paths,
            // so it is intentionally not used.
            let quoted = format!("\"{}\"", script.path.display());
            _bat_guard = Some(script);
            Some(ShellSpawn {
                program: s.program,
                args: vec!["/C".to_string(), quoted],
                windows_raw_arg: true,
            })
        }
        other => other,
    };

    // cmd.exe needs its command line appended verbatim (raw_arg); computed only
    // on Windows so the flag is never an unused variable on Unix.
    #[cfg(windows)]
    let windows_raw_arg = shell_spawn.as_ref().is_some_and(|s| s.windows_raw_arg);
    let (effective_cmd, effective_args_owned): (String, Vec<String>) = match shell_spawn {
        Some(s) => (s.program, s.args),
        None => (
            command.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        ),
    };
    let effective_args: Vec<&str> = effective_args_owned.iter().map(|s| s.as_str()).collect();

    // Build command.
    //
    // On Windows the `cmd.exe` command line must be handed over verbatim.
    // `std::process::Command` escapes every argument using the MSVCRT
    // convention (wrap args containing spaces in double quotes, rewrite `"` as
    // `\"`, and double the run of backslashes that precedes a quote). `cmd.exe`
    // does not parse its command line that way, so a wrapped command carrying
    // quoted Windows paths — e.g. `type "C:\dir\file"` — arrives as
    // `type \"C:\dir\file\"`; cmd treats the stray `\"` as part of the name and
    // aborts with ERROR_INVALID_NAME (os error 123). `raw_arg` appends the text
    // with no escaping, so `cmd /C <line>` is parsed exactly as if typed at the
    // prompt. This applies ONLY to cmd.exe (`windows_raw_arg`): direct spawns
    // and other shells (bash/pwsh) are ordinary programs that DO follow the
    // MSVCRT convention, so they keep normal escaping. See `fsmcp_bug.md` #1/#2.
    let mut cmd = Command::new(&effective_cmd);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        if windows_raw_arg {
            // effective_args == ["/C", "<full command line>"]; std joins
            // successive raw args with a single space, yielding `cmd /C <line>`.
            let std_cmd = cmd.as_std_mut();
            for arg in effective_args.iter().copied() {
                std_cmd.raw_arg(arg);
            }
        } else {
            cmd.args(&effective_args);
        }
    }
    #[cfg(not(windows))]
    {
        cmd.args(&effective_args);
    }

    // Set working directory
    if let Some(ref cwd) = params.cwd {
        let cwd_path = Path::new(cwd);
        if !cwd_path.exists() {
            bail!("Working directory does not exist: {}", cwd);
        }
        cmd.current_dir(cwd_path);
    }

    // Compose the child environment in one map so prepend+append stack against
    // each other (not against the server env each time) and clear_env is
    // honored (the old code re-read std::env::var after env_clear, injecting the
    // server's values back in, and append overwrote the prepend composition).
    let mut child_env: HashMap<String, String> = if params.clear_env {
        HashMap::new()
    } else {
        std::env::vars().collect()
    };
    if let Some(ref prepend) = params.env_prepend {
        for (key, prefix) in prepend {
            let current = child_env.get(key).cloned().unwrap_or_default();
            child_env.insert(key.clone(), format!("{}{}", prefix, current));
        }
    }
    if let Some(ref append) = params.env_append {
        for (key, suffix) in append {
            let current = child_env.get(key).cloned().unwrap_or_default();
            child_env.insert(key.clone(), format!("{}{}", current, suffix));
        }
    }
    if let Some(ref env) = params.env {
        for (key, value) in env {
            child_env.insert(key.clone(), value.clone());
        }
    }
    cmd.env_clear();
    cmd.envs(&child_env);

    // Create new process group for tree-kill support
    #[cfg(unix)]
    {
        // `pre_exec` is an inherent method on tokio's Command — no std trait import.
        // SAFETY: setpgid is async-signal-safe
        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        // CREATE_NEW_PROCESS_GROUP = 0x00000200
        cmd.creation_flags(0x00000200);
    }

    // Set up stdio
    let stdin_bytes = if let Some(ref data) = params.stdin_bytes {
        cmd.stdin(Stdio::piped());
        Some(data.clone())
    } else {
        cmd.stdin(Stdio::null());
        None
    };

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Spawn process
    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn command: {}", effective_cmd))?;

    let pid = child.id();

    // Handle stdin
    if let Some(data) = stdin_bytes
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin.write_all(&data).await?;
        stdin.flush().await?;
        drop(stdin);
    }

    // Detached mode: return immediately
    if params.mode == RunMode::Detached {
        let stdout_handle = child.stdout.take();
        let stderr_handle = child.stderr.take();

        spawn_drain_task(stdout_handle, params.stdout_file.clone());
        spawn_drain_task(stderr_handle, params.stderr_file.clone());

        // A multi-line cmd run uses a temp `.bat` that cmd reads lazily; in
        // detached mode the child outlives this function, so the guard must be
        // moved into a reaper task and dropped only after the child exits
        // (BUG5). Dropping it here would delete the .bat mid-execution.
        #[cfg(windows)]
        let bat_guard = _bat_guard.take();

        if let (Some(manager), Some(pid)) = (manager, pid) {
            manager
                .register(
                    pid,
                    command.to_string(),
                    args.iter().map(|s| s.to_string()).collect(),
                    params.cwd.clone(),
                )
                .await;

            let manager = manager.clone();
            tokio::spawn(async move {
                #[cfg(windows)]
                let _bat = bat_guard;
                let _ = child.wait().await;
                manager.unregister(pid).await;
            });
        } else {
            // No manager to reap the child. With a temp `.bat` guard we still
            // must await the child before dropping it, or the file would be
            // removed while cmd is still reading it. Without a guard, preserve
            // the existing behavior (the child handle is simply dropped).
            #[cfg(windows)]
            if bat_guard.is_some() {
                tokio::spawn(async move {
                    let _bat = bat_guard;
                    let _ = child.wait().await;
                });
            }
        }

        return Ok(RunResult {
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            stdout_processed: None,
            stderr_processed: None,
            pid,
            killed: false,
            timed_out: false,
            cancelled: false,
            duration_ms: start.elapsed().as_millis() as u64,
            background: true,
            started_at,
            finished_at: now_ms(),
            stdout_total_lines: 0,
            stderr_total_lines: 0,
            capture_truncated: false,
        });
    }

    // Foreground mode (Sync or Managed): wait for completion
    wait_for_process(
        child,
        &params,
        start,
        started_at,
        now_ms,
        cancel,
        progress_cb,
    )
    .await
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Open the caller-requested log file for truncating writes.
///
/// `Ok(None)` = no path requested; `Ok(Some)` = opened; `Err` = a path was
/// requested but could not be opened. The error must NOT be swallowed: the
/// retain window is trimmed on the assumption the file holds the full output,
/// so a silently-failed open would drop most of the output while the response
/// still looked like a clean success.
async fn open_output_file(path: Option<String>) -> Result<Option<tokio::fs::File>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .await
        .with_context(|| format!("Cannot open output file: {path}"))?;
    Ok(Some(file))
}

fn spawn_drain_task<R>(
    handle: Option<R>,
    output_file: Option<String>,
) -> tokio::task::JoinHandle<Result<()>>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move { drain_stream(handle, output_file).await })
}

async fn drain_stream<R>(handle: Option<R>, output_file: Option<String>) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let Some(handle) = handle else {
        return Ok(());
    };

    let mut writer = open_output_file(output_file).await?;
    let mut reader = BufReader::new(handle);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let read = reader.read_until(b'\n', &mut buf).await?;
        if read == 0 {
            break;
        }
        if let Some(ref mut file) = writer {
            file.write_all(&buf).await?;
        }
    }
    if let Some(ref mut file) = writer {
        file.flush().await?;
    }
    Ok(())
}

/// Collect stream lines, teeing every line to the log file (when set) while
/// retaining lines for the inline result. `retain_cap` bounds the retained
/// window: `None` keeps every line (needed for head/filter or when there is no
/// log-file fallback); `Some(n)` keeps only the last `n` lines so a huge build
/// cannot exhaust RAM. Returns `(retained_lines, total_lines)` — `total_lines`
/// is the true count regardless of the cap. The shared `line_buffer` (managed
/// mode progress) still receives every line.
async fn collect_stream_lines<R>(
    handle: Option<R>,
    output_file: Option<String>,
    line_buffer: Option<Arc<tokio::sync::Mutex<Vec<String>>>>,
    retain_cap: Option<usize>,
) -> Result<(Vec<String>, usize)>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let Some(handle) = handle else {
        return Ok((Vec::new(), 0));
    };

    let mut retained: VecDeque<String> = VecDeque::new();
    let mut total = 0usize;
    let mut writer = open_output_file(output_file).await?;
    let mut reader = BufReader::new(handle);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let read = reader.read_until(b'\n', &mut buf).await?;
        if read == 0 {
            break;
        }
        if let Some(ref mut file) = writer {
            file.write_all(&buf).await?;
        }
        let mut line = String::from_utf8_lossy(&buf).to_string();
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        if let Some(ref buf) = line_buffer {
            buf.lock().await.push(line.clone());
        }
        total += 1;
        retained.push_back(line);
        if let Some(cap) = retain_cap {
            while retained.len() > cap {
                retained.pop_front();
            }
        }
    }
    if let Some(ref mut file) = writer {
        file.flush().await?;
    }
    Ok((retained.into(), total))
}

/// Wait for process with timeout/watchdog/cancellation handling + progress
async fn wait_for_process(
    mut child: Child,
    params: &RunParams,
    start: Instant,
    started_at: u64,
    now_ms: impl Fn() -> u64,
    cancel: Option<CancellationToken>,
    progress_cb: Option<ProgressCallback>,
) -> Result<RunResult> {
    let pid = child.id();
    // head/tail/filter processing requires lines in memory — override caller opt-out.
    let capture_output = params.capture_output.unwrap_or(true)
        || params.stdout_head.is_some()
        || params.stdout_tail.is_some()
        || params.stderr_head.is_some()
        || params.stderr_tail.is_some()
        || params.output_filter.as_ref().is_some_and(|f| f.is_active());
    let is_managed = params.mode == RunMode::Managed;

    // Determine effective timeout: kill_after stacks on top of timeout
    let timeout_duration = match (params.timeout_ms, params.kill_after_ms) {
        // saturating so two large caller-supplied values cannot wrap to a tiny
        // (or zero) deadline and kill the child almost immediately.
        (Some(t), Some(k)) => Some(Duration::from_millis(t.saturating_add(k))),
        (Some(t), None) => Some(Duration::from_millis(t)),
        (None, Some(k)) => Some(Duration::from_millis(k)),
        (None, None) => None,
    };

    // Shared line buffer for managed mode progress reporting
    let managed_stdout_buf: Option<Arc<tokio::sync::Mutex<Vec<String>>>> =
        if is_managed && progress_cb.is_some() {
            Some(Arc::new(tokio::sync::Mutex::new(Vec::new())))
        } else {
            None
        };

    // Collect stdout/stderr. Capture and file-streaming are INDEPENDENT: the
    // capture tasks tee every line to the log file (when set) AND retain lines
    // for the inline result. `full_capture` (head/filter, or no log-file
    // fallback) keeps every line in memory; otherwise only a trailing window is
    // retained so a huge build cannot exhaust RAM — the full output is in the file.
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    let full_capture = params.stdout_head.is_some()
        || params.stderr_head.is_some()
        || params.output_filter.as_ref().is_some_and(|f| f.is_active());
    let stdout_retain = if full_capture || params.stdout_file.is_none() {
        None
    } else {
        Some(DEFAULT_INLINE_TAIL_LINES.max(params.stdout_tail.unwrap_or(0)))
    };
    let stderr_retain = if full_capture || params.stderr_file.is_none() {
        None
    } else {
        Some(DEFAULT_INLINE_TAIL_LINES.max(params.stderr_tail.unwrap_or(0)))
    };

    enum OutputTasks {
        Capture(
            tokio::task::JoinHandle<Result<(Vec<String>, usize)>>,
            tokio::task::JoinHandle<Result<(Vec<String>, usize)>>,
        ),
        Drain(
            tokio::task::JoinHandle<Result<()>>,
            tokio::task::JoinHandle<Result<()>>,
        ),
    }

    let output_tasks = if capture_output {
        let stdout_buf = managed_stdout_buf.clone();
        let stdout_file = params.stdout_file.clone();
        let stderr_file = params.stderr_file.clone();
        // Return the Result as-is: a read/write/log-open failure must not be
        // flattened into an empty-but-successful capture (which would report a
        // command that "produced no output" while it actually produced plenty).
        let stdout_task = tokio::spawn(async move {
            collect_stream_lines(stdout_handle, stdout_file, stdout_buf, stdout_retain).await
        });
        let stderr_task = tokio::spawn(async move {
            collect_stream_lines(stderr_handle, stderr_file, None, stderr_retain).await
        });
        OutputTasks::Capture(stdout_task, stderr_task)
    } else {
        let stdout_file = params.stdout_file.clone();
        let stderr_file = params.stderr_file.clone();
        let stdout_task = spawn_drain_task(stdout_handle, stdout_file);
        let stderr_task = spawn_drain_task(stderr_handle, stderr_file);
        OutputTasks::Drain(stdout_task, stderr_task)
    };

    // Progress ticker for managed/sync mode heartbeat
    let progress_interval = if is_managed {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(30)
    };

    // Main wait loop: process completion vs timeout vs cancellation vs progress
    let (exit_status, killed, timed_out, cancelled) = wait_with_progress_and_cancel(
        &mut child,
        pid,
        timeout_duration,
        cancel,
        progress_cb.as_ref(),
        &managed_stdout_buf,
        progress_interval,
        start,
    )
    .await?;

    let (stdout_lines, stdout_total, stderr_lines, stderr_total, capture_truncated) =
        match output_tasks {
            OutputTasks::Capture(stdout_task, stderr_task) => {
                // EOF normally arrives within ms of process exit. Wait
                // generously so output is never silently dropped, but bound it
                // so a lingering child still holding the pipe's write end open
                // cannot hang us. On timeout we flag `capture_truncated` rather
                // than returning empty output that looks like clean success.
                // Drain both streams concurrently so a hung pipe caps the
                // wait at one POST_EXIT_DRAIN_TIMEOUT, not the sum of two.
                let (so_res, se_res) = tokio::join!(
                    timeout(POST_EXIT_DRAIN_TIMEOUT, stdout_task),
                    timeout(POST_EXIT_DRAIN_TIMEOUT, stderr_task),
                );
                // Triple-nested: timeout(Elapsed) -> join(JoinError) -> collect(io).
                // Any layer failing means the capture is incomplete, so flag it.
                let (so, so_total, so_ok) = match so_res {
                    Ok(Ok(Ok((lines, total)))) => (lines, total, true),
                    _ => (Vec::new(), 0, false),
                };
                let (se, se_total, se_ok) = match se_res {
                    Ok(Ok(Ok((lines, total)))) => (lines, total, true),
                    _ => (Vec::new(), 0, false),
                };
                (so, so_total, se, se_total, !(so_ok && se_ok))
            }
            OutputTasks::Drain(stdout_task, stderr_task) => {
                // A drained stream still has a log file; a failed drain/log write
                // must surface as truncated rather than silent success.
                let so_ok = matches!(
                    timeout(POST_EXIT_DRAIN_TIMEOUT, stdout_task).await,
                    Ok(Ok(Ok(())))
                );
                let se_ok = matches!(
                    timeout(POST_EXIT_DRAIN_TIMEOUT, stderr_task).await,
                    Ok(Ok(Ok(())))
                );
                (Vec::new(), 0, Vec::new(), 0, !(so_ok && se_ok))
            }
        };

    // Apply output processing (head + filter + tail)
    let has_processing = params.stdout_head.is_some()
        || params.stderr_head.is_some()
        || params.output_filter.as_ref().is_some_and(|f| f.is_active());

    let (stdout, stdout_processed) = if has_processing {
        let processed = process_output(
            &stdout_lines,
            params.stdout_head,
            params.stdout_tail,
            params.output_filter.as_ref(),
        );
        let text = processed.format();
        (text, Some(processed))
    } else {
        (apply_tail(stdout_lines, params.stdout_tail), None)
    };

    let (stderr, stderr_processed) = if has_processing {
        let processed = process_output(
            &stderr_lines,
            params.stderr_head,
            params.stderr_tail,
            params.output_filter.as_ref(),
        );
        let text = processed.format();
        (text, Some(processed))
    } else {
        (apply_tail(stderr_lines, params.stderr_tail), None)
    };

    // Last-resort context guard; the full output is already in the log file.
    let stdout = cap_inline_bytes(stdout);
    let stderr = cap_inline_bytes(stderr);

    let exit_code = exit_status.and_then(|s| s.code());

    Ok(RunResult {
        exit_code,
        stdout,
        stderr,
        stdout_processed,
        stderr_processed,
        pid,
        killed,
        timed_out,
        cancelled,
        duration_ms: start.elapsed().as_millis() as u64,
        background: false,
        started_at,
        finished_at: now_ms(),
        stdout_total_lines: stdout_total,
        stderr_total_lines: stderr_total,
        capture_truncated,
    })
}

/// Core wait loop: race between process completion, timeout, cancellation, and progress ticks
#[allow(clippy::too_many_arguments)]
async fn wait_with_progress_and_cancel(
    child: &mut Child,
    pid: Option<u32>,
    timeout_duration: Option<Duration>,
    cancel: Option<CancellationToken>,
    progress_cb: Option<&ProgressCallback>,
    managed_buf: &Option<Arc<tokio::sync::Mutex<Vec<String>>>>,
    progress_interval: Duration,
    start: Instant,
) -> Result<(Option<std::process::ExitStatus>, bool, bool, bool)> {
    let mut progress_ticker = tokio::time::interval(progress_interval);
    progress_ticker.tick().await; // consume first immediate tick
    let mut last_reported_line = 0usize;

    loop {
        // Build the timeout future
        let deadline_remaining = timeout_duration.map(|d| {
            let elapsed = start.elapsed();
            d.checked_sub(elapsed).unwrap_or(Duration::ZERO)
        });

        tokio::select! {
            // Process completes
            result = child.wait() => {
                return match result {
                    Ok(status) => Ok((Some(status), false, false, false)),
                    Err(e) => Err(e.into()),
                };
            }

            // Timeout
            _ = async {
                if let Some(remaining) = deadline_remaining {
                    tokio::time::sleep(remaining).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                // Kill process tree on timeout
                if let Some(pid) = pid {
                    let _ = kill_process_tree(pid, true);
                }
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Ok((None, true, true, false));
            }

            // Cancellation from MCP client
            _ = async {
                if let Some(ref ct) = cancel {
                    ct.cancelled().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                // Kill process tree on cancellation
                if let Some(pid) = pid {
                    let _ = kill_process_tree(pid, true);
                }
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Ok((None, true, false, true));
            }

            // Progress heartbeat tick
            _ = progress_ticker.tick() => {
                if let Some(cb) = progress_cb {
                    let elapsed_ms = start.elapsed().as_millis() as u64;

                    // In managed mode, grab new lines from buffer
                    let new_lines = if let Some(buf) = managed_buf {
                        let locked = buf.lock().await;
                        let new = locked[last_reported_line..].to_vec();
                        last_reported_line = locked.len();
                        new
                    } else {
                        Vec::new()
                    };

                    cb(elapsed_ms, &new_lines).await;
                }
            }
        }
    }
}

/// Apply tail to output lines (backward compat)
fn apply_tail(lines: Vec<String>, tail: Option<usize>) -> String {
    match tail {
        Some(n) if n > 0 && n < lines.len() => lines[lines.len() - n..].join("\n"),
        _ => lines.join("\n"),
    }
}

// ---------------------------------------------------------------------------
// Process info queries
// ---------------------------------------------------------------------------

/// Process info from system search
#[derive(Debug, Clone, serde::Serialize)]
pub struct SystemProcessInfo {
    pub pid: u32,
    pub name: String,
    pub command_line: Option<String>,
    pub exe_path: Option<String>,
    pub memory_bytes: u64,
    pub cpu_percent: f32,
    pub status: String,
    pub user: Option<String>,
}

/// Search for processes by name pattern and/or command line pattern
pub fn search_processes(
    name_pattern: Option<&str>,
    cmdline_pattern: Option<&str>,
) -> Result<Vec<SystemProcessInfo>> {
    use sysinfo::System;

    let mut sys = System::new_all();
    sys.refresh_all();

    let name_re = name_pattern
        .map(|p| Regex::new(&format!("(?i){}", p)))
        .transpose()
        .context("Invalid name pattern regex")?;
    let cmdline_re = cmdline_pattern
        .map(|p| Regex::new(&format!("(?i){}", p)))
        .transpose()
        .context("Invalid cmdline pattern regex")?;

    let mut results = Vec::new();

    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_string();
        let cmd = process.cmd();
        let command_line = if cmd.is_empty() {
            None
        } else {
            Some(
                cmd.iter()
                    .map(|s| s.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        };

        if let Some(ref re) = name_re
            && !re.is_match(&name)
        {
            continue;
        }

        if let Some(ref re) = cmdline_re {
            if let Some(ref cmdline) = command_line {
                if !re.is_match(cmdline) {
                    continue;
                }
            } else {
                continue;
            }
        }

        results.push(SystemProcessInfo {
            pid: pid.as_u32(),
            name,
            command_line,
            exe_path: process.exe().map(|p| p.to_string_lossy().to_string()),
            memory_bytes: process.memory(),
            cpu_percent: process.cpu_usage(),
            status: format!("{:?}", process.status()),
            user: process.user_id().map(|u| u.to_string()),
        });
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_run_simple_command() {
        #[cfg(windows)]
        let (cmd, args) = ("cmd", vec!["/C", "echo hello"]);
        #[cfg(unix)]
        let (cmd, args) = ("echo", vec!["hello"]);

        let result = run_command(cmd, &args, RunParams::default(), None, None, None)
            .await
            .unwrap();

        assert!(!result.killed);
        assert!(!result.timed_out);
        assert!(!result.cancelled);
        assert!(result.stdout.contains("hello"));
        assert!(result.started_at > 0);
        assert!(result.finished_at >= result.started_at);
    }

    /// BUG5: `cmd /C "<string>"` ran only the first line of a multi-line
    /// command, silently dropping the rest. With the temp-`.bat` path every
    /// line must run.
    #[cfg(windows)]
    #[tokio::test]
    async fn test_cmd_multiline_runs_all_lines() {
        let params = RunParams {
            shell: ShellKind::Cmd,
            ..Default::default()
        };
        let result = run_command(
            "echo LINE_A\necho LINE_B\necho LINE_C",
            &[],
            params,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, Some(0), "stdout: {}", result.stdout);
        assert!(
            result.stdout.contains("LINE_A"),
            "stdout: {}",
            result.stdout
        );
        assert!(
            result.stdout.contains("LINE_B"),
            "stdout: {}",
            result.stdout
        );
        assert!(
            result.stdout.contains("LINE_C"),
            "stdout: {}",
            result.stdout
        );
    }

    /// The exit code of a multi-line cmd run is that of the LAST line
    /// (batch semantics); `exit /b N` must propagate through `cmd /C <bat>`.
    #[cfg(windows)]
    #[tokio::test]
    async fn test_cmd_multiline_exit_code() {
        let params = RunParams {
            shell: ShellKind::Cmd,
            ..Default::default()
        };
        let result = run_command("echo before\nexit /b 42", &[], params, None, None, None)
            .await
            .unwrap();
        assert_eq!(result.exit_code, Some(42), "stdout: {}", result.stdout);
    }

    /// BUG5 secondary symptom: a multi-line `set "PATH=...;%PATH%"` (with
    /// parentheses in the value) plus a `>nul` redirect must run cleanly via the
    /// temp `.bat` — the fragile single-line `&&` chain was what failed before.
    #[cfg(windows)]
    #[tokio::test]
    async fn test_cmd_multiline_set_path_and_redirect() {
        let params = RunParams {
            shell: ShellKind::Cmd,
            ..Default::default()
        };
        let result = run_command(
            "set \"PATH=C:\\Program Files (x86)\\Foo;%PATH%\"\necho OK>nul\necho DONE",
            &[],
            params,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(result.exit_code, Some(0), "stdout: {}", result.stdout);
        assert!(result.stdout.contains("DONE"), "stdout: {}", result.stdout);
    }

    /// A single-line cmd command must keep the original verbatim `cmd /C <line>`
    /// path (no temp `.bat`), so its behavior is unchanged by the BUG5 fix.
    #[cfg(windows)]
    #[tokio::test]
    async fn test_cmd_singleline_unchanged() {
        let params = RunParams {
            shell: ShellKind::Cmd,
            ..Default::default()
        };
        let result = run_command("echo single_line_ok", &[], params, None, None, None)
            .await
            .unwrap();
        assert_eq!(result.exit_code, Some(0), "stdout: {}", result.stdout);
        assert!(
            result.stdout.contains("single_line_ok"),
            "stdout: {}",
            result.stdout
        );
    }

    /// `TempScript::create` normalizes mixed line endings to CRLF, prefixes
    /// `@echo off` + `chcp 65001` (UTF-8), and the file is removed on drop.
    #[cfg(windows)]
    #[tokio::test]
    async fn test_tempscript_create_and_drop() {
        let script = TempScript::create("a\nb\r\nc").await.unwrap();
        let path = script.path.clone();
        let body = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(body, "@echo off\r\nchcp 65001 >nul\r\na\r\nb\r\nc\r\n");
        drop(script);
        assert!(!path.exists(), "temp .bat must be removed on drop");
    }

    #[tokio::test]
    async fn test_run_with_env() {
        let mut env = HashMap::new();
        env.insert("MY_VAR".to_string(), "test_value".to_string());

        #[cfg(windows)]
        let (cmd, args) = ("cmd", vec!["/C", "echo %MY_VAR%"]);
        #[cfg(unix)]
        let (cmd, args) = ("sh", vec!["-c", "echo $MY_VAR"]);

        let params = RunParams {
            env: Some(env),
            ..Default::default()
        };

        let result = run_command(cmd, &args, params, None, None, None)
            .await
            .unwrap();
        assert!(result.stdout.contains("test_value"));
    }

    #[tokio::test]
    async fn test_run_with_env_prepend_append() {
        // Set a base var, then prepend and append to it
        let mut env = HashMap::new();
        env.insert("TEST_COMBO".to_string(), "MIDDLE".to_string());
        let mut prepend = HashMap::new();
        prepend.insert("TEST_COMBO".to_string(), "START_".to_string());
        let mut append = HashMap::new();
        append.insert("TEST_COMBO".to_string(), "_END".to_string());

        // env overrides last, so prepend/append run on the original env,
        // then env sets the final value. To test prepend/append alone,
        // use a var that only gets prepend+append without override.
        let mut prepend_only = HashMap::new();
        prepend_only.insert("MY_PATH_TEST".to_string(), "PREFIX;".to_string());

        // Set a known base value first
        // SAFETY: test runs single-threaded for this env var
        unsafe { std::env::set_var("MY_PATH_TEST", "original") };

        #[cfg(windows)]
        let (cmd, args) = ("cmd", vec!["/C", "echo %MY_PATH_TEST%"]);
        #[cfg(unix)]
        let (cmd, args) = ("sh", vec!["-c", "echo $MY_PATH_TEST"]);

        let params = RunParams {
            env_prepend: Some(prepend_only),
            ..Default::default()
        };

        let result = run_command(cmd, &args, params, None, None, None)
            .await
            .unwrap();
        assert!(
            result.stdout.contains("PREFIX;original"),
            "got: {}",
            result.stdout
        );

        // Cleanup
        // SAFETY: test cleanup
        unsafe { std::env::remove_var("MY_PATH_TEST") };
    }

    #[tokio::test]
    async fn test_run_with_cwd() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path().to_string_lossy().to_string();

        #[cfg(windows)]
        let (cmd, args) = ("cmd", vec!["/C", "cd"]);
        #[cfg(unix)]
        let (cmd, args) = ("pwd", vec![]);

        let params = RunParams {
            cwd: Some(dir_path.clone()),
            ..Default::default()
        };

        let result = run_command(cmd, &args, params, None, None, None)
            .await
            .unwrap();

        let output = result.stdout.trim().replace('\\', "/").to_lowercase();
        let expected = dir_path.replace('\\', "/").to_lowercase();
        assert!(output.contains(&expected) || expected.contains(&output));
    }

    #[tokio::test]
    async fn test_run_with_timeout() {
        #[cfg(windows)]
        let (cmd, args) = ("ping", vec!["-n", "100", "127.0.0.1"]);
        #[cfg(unix)]
        let (cmd, args) = ("sleep", vec!["10"]);

        let params = RunParams {
            timeout_ms: Some(500),
            ..Default::default()
        };

        let result = run_command(cmd, &args, params, None, None, None)
            .await
            .unwrap();

        assert!(result.killed);
        assert!(result.timed_out);
        assert!(result.duration_ms < 5000);
    }

    #[tokio::test]
    async fn test_run_with_cancellation() {
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        // Cancel after 500ms
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            cancel_clone.cancel();
        });

        #[cfg(windows)]
        let (cmd, args) = ("ping", vec!["-n", "100", "127.0.0.1"]);
        #[cfg(unix)]
        let (cmd, args) = ("sleep", vec!["10"]);

        let result = run_command(cmd, &args, RunParams::default(), None, Some(cancel), None)
            .await
            .unwrap();

        assert!(result.killed);
        assert!(result.cancelled);
        assert!(result.duration_ms < 5000);
    }

    #[tokio::test]
    async fn test_run_with_stdout_tail() {
        #[cfg(windows)]
        let (cmd, args) = ("cmd", vec!["/C", "echo line1 && echo line2 && echo line3"]);
        #[cfg(unix)]
        let (cmd, args) = ("sh", vec!["-c", "echo line1; echo line2; echo line3"]);

        let params = RunParams {
            stdout_tail: Some(2),
            ..Default::default()
        };

        let result = run_command(cmd, &args, params, None, None, None)
            .await
            .unwrap();

        assert!(!result.stdout.contains("line1"));
        assert!(result.stdout.contains("line2"));
        assert!(result.stdout.contains("line3"));
    }

    /// Regression: stdout_head must return inline content even when capture_output=false
    /// (stream_output=true is the default in run_command MCP args, which sets capture_output=false).
    #[tokio::test]
    async fn test_head_overrides_capture_false() {
        let dir = tempdir().unwrap();
        let stdout_path = dir.path().join("out.log");

        #[cfg(windows)]
        let (cmd, args) = ("cmd", vec!["/C", "echo line1 && echo line2 && echo line3"]);
        #[cfg(unix)]
        let (cmd, args) = ("sh", vec!["-c", "echo line1; echo line2; echo line3"]);

        let params = RunParams {
            stdout_file: Some(stdout_path.to_string_lossy().to_string()),
            capture_output: Some(false), // caller opts out of capture (file streaming mode)
            stdout_head: Some(1),        // but requests inline head — must still work
            ..Default::default()
        };

        let result = run_command(cmd, &args, params, None, None, None)
            .await
            .unwrap();

        // Inline head must be populated despite capture_output=false
        assert!(
            result.stdout.contains("line1"),
            "stdout_head must return inline content even when capture_output=false; got: {:?}",
            result.stdout
        );
        assert!(
            !result.stdout.contains("line2"),
            "head=1 must not include line2"
        );
        // Full output still written to file
        let file_content = std::fs::read_to_string(&stdout_path).unwrap();
        assert!(
            file_content.contains("line3"),
            "file must still have full output"
        );
    }

    #[tokio::test]
    async fn test_run_with_stdin_bytes() {
        #[cfg(windows)]
        let (cmd, args) = ("cmd", vec!["/C", "findstr ."]);
        #[cfg(unix)]
        let (cmd, args) = ("cat", vec![]);

        let params = RunParams {
            stdin_bytes: Some(b"hello from stdin_bytes".to_vec()),
            ..Default::default()
        };

        let result = run_command(cmd, &args, params, None, None, None)
            .await
            .unwrap();
        assert!(result.stdout.contains("hello from stdin_bytes"));
    }

    #[tokio::test]
    async fn test_run_with_stdout_file() {
        let dir = tempdir().unwrap();
        let stdout_path = dir.path().join("output.txt");

        #[cfg(windows)]
        let (cmd, args) = ("cmd", vec!["/C", "echo test output"]);
        #[cfg(unix)]
        let (cmd, args) = ("echo", vec!["test output"]);

        let params = RunParams {
            stdout_file: Some(stdout_path.to_string_lossy().to_string()),
            ..Default::default()
        };

        let _ = run_command(cmd, &args, params, None, None, None)
            .await
            .unwrap();

        let content = std::fs::read_to_string(&stdout_path).unwrap();
        assert!(content.contains("test output"));
    }

    #[tokio::test]
    async fn test_run_stream_to_file_without_inline_capture() {
        let dir = tempdir().unwrap();
        let stdout_path = dir.path().join("stream_stdout.txt");

        #[cfg(windows)]
        let (cmd, args) = ("cmd", vec!["/C", "echo streamed output"]);
        #[cfg(unix)]
        let (cmd, args) = ("echo", vec!["streamed output"]);

        let params = RunParams {
            stdout_file: Some(stdout_path.to_string_lossy().to_string()),
            capture_output: Some(false),
            ..Default::default()
        };

        let result = run_command(cmd, &args, params, None, None, None)
            .await
            .unwrap();

        assert!(result.stdout.is_empty());
        let content = std::fs::read_to_string(&stdout_path).unwrap();
        assert!(content.contains("streamed output"));
    }

    #[tokio::test]
    async fn test_default_captures_inline_and_streams_to_file() {
        // Regression: with default params (capture_output = None) the inline
        // stdout must be populated AND the log file written — the two are
        // independent. Previously the MCP layer forced capture_output=false
        // while streaming, silently returning empty inline stdout with exit 0.
        let dir = tempdir().unwrap();
        let stdout_path = dir.path().join("both.txt");

        #[cfg(windows)]
        let (cmd, args) = ("cmd", vec!["/C", "echo inline_and_file"]);
        #[cfg(unix)]
        let (cmd, args) = ("echo", vec!["inline_and_file"]);

        let params = RunParams {
            stdout_file: Some(stdout_path.to_string_lossy().to_string()),
            ..Default::default()
        };

        let result = run_command(cmd, &args, params, None, None, None)
            .await
            .unwrap();

        assert!(result.stdout.contains("inline_and_file"));
        assert_eq!(result.stdout_total_lines, 1);
        assert!(!result.capture_truncated);
        let content = std::fs::read_to_string(&stdout_path).unwrap();
        assert!(content.contains("inline_and_file"));
    }

    #[tokio::test]
    async fn test_run_background() {
        let manager = ProcessManager::new();

        #[cfg(windows)]
        let (cmd, args) = ("cmd", vec!["/C", "ping -n 3 127.0.0.1"]);
        #[cfg(unix)]
        let (cmd, args) = ("sleep", vec!["2"]);

        let params = RunParams {
            mode: RunMode::Detached,
            ..Default::default()
        };

        let result = run_command(cmd, &args, params, Some(&manager), None, None)
            .await
            .unwrap();

        assert!(result.background);
        assert!(result.pid.is_some());
        assert!(result.duration_ms < 1000);

        let pid = result.pid.unwrap();
        assert!(manager.list().await.iter().any(|p| p.pid == pid));

        // Wait for it to finish and unregister
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(!manager.list().await.iter().any(|p| p.pid == pid));
    }

    #[tokio::test]
    async fn test_shell_mode() {
        let params = RunParams {
            shell: ShellKind::Default,
            ..Default::default()
        };

        #[cfg(windows)]
        let (cmd, args) = ("echo hello && echo world", vec![]);
        #[cfg(unix)]
        let (cmd, args) = ("echo hello && echo world", vec![]);

        let result = run_command(cmd, &args, params, None, None, None)
            .await
            .unwrap();
        assert!(result.stdout.contains("hello"));
        assert!(result.stdout.contains("world"));
    }

    /// Regression for bug.md #1/#2: a shell command embedding an absolute
    /// Windows path (backslashes + a space in the dir name) must reach cmd.exe
    /// intact. Before the `raw_arg` fix, Rust's MSVCRT escaping turned the
    /// quoted path into `\"C:\..\"` and `if exist`/`type` failed with
    /// ERROR_INVALID_NAME, so this printed `NO`.
    #[cfg(windows)]
    #[tokio::test]
    async fn test_shell_backslash_path() {
        use std::io::Write;
        let dir = tempdir().unwrap();
        let sub = dir.path().join("a b"); // space forces quoting
        std::fs::create_dir(&sub).unwrap();
        let file = sub.join("probe.txt");
        write!(std::fs::File::create(&file).unwrap(), "PROBE_OK").unwrap();
        let path = file.to_string_lossy().replace('/', "\\"); // ensure backslashes

        let params = RunParams {
            shell: ShellKind::Default,
            ..Default::default()
        };
        let cmd = format!("if exist \"{path}\" (type \"{path}\") else (echo NO)");
        let result = run_command(&cmd, &[], params, None, None, None)
            .await
            .unwrap();
        assert!(
            result.stdout.contains("PROBE_OK"),
            "backslash path mangled; stdout={:?}",
            result.stdout
        );
        assert!(!result.stdout.contains("NO"));
    }

    #[tokio::test]
    async fn test_exit_code() {
        #[cfg(windows)]
        let (cmd, args) = ("cmd", vec!["/C", "exit 42"]);
        #[cfg(unix)]
        let (cmd, args) = ("sh", vec!["-c", "exit 42"]);

        let result = run_command(cmd, &args, RunParams::default(), None, None, None)
            .await
            .unwrap();
        assert_eq!(result.exit_code, Some(42));
    }

    #[test]
    fn test_apply_tail() {
        let lines = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];

        assert_eq!(apply_tail(lines.clone(), Some(2)), "c\nd");
        assert_eq!(apply_tail(lines.clone(), Some(10)), "a\nb\nc\nd");
        assert_eq!(apply_tail(lines.clone(), None), "a\nb\nc\nd");
        assert_eq!(apply_tail(lines.clone(), Some(0)), "a\nb\nc\nd");
    }

    #[test]
    fn test_filter_lines() {
        let lines: Vec<String> = vec![
            "line 1 normal",
            "line 2 normal",
            "line 3 error: bad thing",
            "line 4 details",
            "line 5 normal",
            "line 6 warning: something",
            "line 7 normal",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let filter = OutputFilter {
            include: vec![Regex::new("error|warning").unwrap()],
            exclude: vec![],
            context_before: 1,
            context_after: 1,
            max_lines: None,
        };

        let result = filter_lines(&lines, &filter);
        assert!(result.contains(&"line 2 normal".to_string())); // context before error
        assert!(result.contains(&"line 3 error: bad thing".to_string()));
        assert!(result.contains(&"line 4 details".to_string())); // context after error
        assert!(result.contains(&"line 5 normal".to_string())); // context before warning
        assert!(result.contains(&"line 6 warning: something".to_string()));
        assert!(result.contains(&"line 7 normal".to_string())); // context after warning
    }

    #[test]
    fn test_filter_with_exclude() {
        let lines: Vec<String> = vec![
            "error: real problem",
            "error: note: this is fine",
            "warning: something",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let filter = OutputFilter {
            include: vec![Regex::new("error|warning").unwrap()],
            exclude: vec![Regex::new("note:").unwrap()],
            context_before: 0,
            context_after: 0,
            max_lines: None,
        };

        let result = filter_lines(&lines, &filter);
        assert!(result.contains(&"error: real problem".to_string()));
        assert!(!result.contains(&"error: note: this is fine".to_string()));
        assert!(result.contains(&"warning: something".to_string()));
    }

    #[test]
    fn test_process_output_head_tail_filter() {
        let lines: Vec<String> = (0..20)
            .map(|i| {
                if i == 10 {
                    "ERROR: something broke".to_string()
                } else {
                    format!("line {}", i)
                }
            })
            .collect();

        let filter = OutputFilter {
            include: vec![Regex::new("ERROR").unwrap()],
            exclude: vec![],
            context_before: 1,
            context_after: 1,
            max_lines: None,
        };

        let processed = process_output(&lines, Some(3), Some(3), Some(&filter));
        assert_eq!(processed.head.len(), 3);
        assert_eq!(processed.head[0], "line 0");
        assert_eq!(processed.tail.len(), 3);
        assert_eq!(processed.tail[2], "line 19");
        assert!(processed.filtered.iter().any(|l| l.contains("ERROR")));
    }

    #[tokio::test]
    async fn test_process_manager() {
        let manager = ProcessManager::new();

        manager
            .register(123, "test".to_string(), vec![], None)
            .await;

        let list = manager.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].pid, 123);

        manager.unregister(123).await;
        assert!(manager.list().await.is_empty());
    }

    #[test]
    fn test_search_processes() {
        let results = search_processes(Some("cargo|rust"), None).unwrap();
        assert!(
            !results.is_empty(),
            "Should find at least one cargo/rust process"
        );
        for p in &results {
            assert!(!p.name.is_empty());
            assert!(p.pid > 0);
        }
    }

    #[test]
    fn test_kill_nonexistent_process() {
        let result = kill_process(999999999, false);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Killing non-existent process should return false"
        );
    }

    #[test]
    fn test_kill_system_process_access_denied() {
        #[cfg(unix)]
        let system_pid = 1;
        #[cfg(windows)]
        let system_pid = 4;

        let result = kill_process(system_pid, false);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Should not be able to kill system process"
        );
    }

    #[test]
    fn test_shell_wrap() {
        // Default resolves to the platform shell with verbatim (raw_arg) only on
        // Windows cmd.exe.
        let s = shell_wrap(ShellKind::Default, "echo", &["hello", "world"]).unwrap();
        #[cfg(windows)]
        {
            assert_eq!(s.program, "cmd");
            assert_eq!(s.args, vec!["/C", "echo hello world"]);
            assert!(s.windows_raw_arg);
        }
        #[cfg(unix)]
        {
            assert_eq!(s.program, "sh");
            assert_eq!(s.args, vec!["-c", "echo hello world"]);
            assert!(!s.windows_raw_arg);
        }

        // bash is the cross-platform unix dialect and never uses raw_arg.
        let b = shell_wrap(ShellKind::Bash, "echo", &["hi"]).unwrap();
        assert_eq!(b.program, "bash");
        assert_eq!(b.args, vec!["-c", "echo hi"]);
        assert!(!b.windows_raw_arg);

        // pwsh uses -NoProfile -Command.
        let p = shell_wrap(ShellKind::Pwsh, "echo", &["hi"]).unwrap();
        assert_eq!(p.program, "pwsh");
        assert_eq!(p.args, vec!["-NoProfile", "-Command", "echo hi"]);

        // None means no shell wrapping at all.
        assert!(shell_wrap(ShellKind::None, "echo", &["hi"]).is_none());
    }

    // BH-15: an argument with spaces / metacharacters must stay ONE token.
    #[test]
    fn test_shell_wrap_quotes_arguments() {
        let b = shell_wrap(ShellKind::Bash, "echo", &["a b"]).unwrap();
        assert_eq!(b.args, vec!["-c", "echo 'a b'"]);

        let p = shell_wrap(ShellKind::Pwsh, "echo", &["a b"]).unwrap();
        assert_eq!(p.args, vec!["-NoProfile", "-Command", "echo 'a b'"]);

        // POSIX single-quote escaping: a'b -> 'a'\''b'.
        let e = shell_wrap(ShellKind::Sh, "echo", &["a'b"]).unwrap();
        assert_eq!(e.args, vec!["-c", "echo 'a'\\''b'"]);

        // cmd double-quotes a spaced arg.
        let c = shell_wrap(ShellKind::Cmd, "type", &["C:/Program Files/a.txt"]).unwrap();
        assert_eq!(c.args, vec!["/C", "type \"C:/Program Files/a.txt\""]);
    }

    // BH-26: exclude-only filters are active; max_lines == 0 yields no content.
    #[test]
    fn test_output_filter_exclude_only_and_max_lines() {
        let lines: Vec<String> = ["keep one", "warn: bad", "keep two"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let f = OutputFilter {
            include: vec![],
            exclude: vec![Regex::new("^warn:").unwrap()],
            context_before: 0,
            context_after: 0,
            max_lines: None,
        };
        assert!(f.is_active(), "exclude-only filter must be active");
        let out = filter_lines(&lines, &f);
        assert!(out.contains(&"keep one".to_string()));
        assert!(out.contains(&"keep two".to_string()));
        assert!(!out.iter().any(|l| l.contains("warn")), "{out:?}");

        let f0 = OutputFilter {
            include: vec![Regex::new("keep").unwrap()],
            exclude: vec![],
            context_before: 0,
            context_after: 0,
            max_lines: Some(0),
        };
        let out0 = filter_lines(&lines, &f0);
        assert!(
            !out0.iter().any(|l| l.contains("keep")),
            "max_lines=0 must not return content lines, got {out0:?}"
        );
    }
}
