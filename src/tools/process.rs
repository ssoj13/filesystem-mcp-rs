use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::RwLock;
use tokio::time::timeout;

/// Parameters for running a command
#[derive(Debug, Clone, Default)]
pub struct RunParams {
    /// Working directory
    pub cwd: Option<String>,
    /// Environment variables (added to current env)
    pub env: Option<HashMap<String, String>>,
    /// Clear environment before adding env vars
    pub clear_env: bool,
    /// Timeout for command execution (ms)
    pub timeout_ms: Option<u64>,
    /// Watchdog: kill if still running after this time (ms)
    pub kill_after_ms: Option<u64>,
    /// Redirect stdout to file
    pub stdout_file: Option<String>,
    /// Redirect stderr to file
    pub stderr_file: Option<String>,
    /// Read stdin from file
    pub stdin_file: Option<String>,
    /// Return only last N lines of stdout
    pub stdout_tail: Option<usize>,
    /// Return only last N lines of stderr
    pub stderr_tail: Option<usize>,
    /// Run in background (don't wait for completion)
    pub background: bool,
}

/// Result of command execution
#[derive(Debug, Clone)]
pub struct RunResult {
    /// Exit code (None if killed or background)
    pub exit_code: Option<i32>,
    /// Stdout output (possibly tailed)
    pub stdout: String,
    /// Stderr output (possibly tailed)
    pub stderr: String,
    /// Process ID (for background processes)
    pub pid: Option<u32>,
    /// Was killed by timeout/watchdog
    pub killed: bool,
    /// Timed out waiting
    pub timed_out: bool,
    /// Execution duration in ms
    pub duration_ms: u64,
    /// Running in background
    pub background: bool,
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
    pub async fn register(&self, pid: u32, command: String, args: Vec<String>, cwd: Option<String>) {
        let mut procs = self.processes.write().await;
        procs.insert(pid, ProcessInfo {
            pid,
            command,
            args,
            started_at: Instant::now(),
            cwd,
        });
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

/// Run a command with full control
pub async fn run_command(
    command: &str,
    args: &[&str],
    params: RunParams,
    manager: Option<&ProcessManager>,
) -> Result<RunResult> {
    let start = Instant::now();
    
    // Build command
    let mut cmd = Command::new(command);
    cmd.args(args);
    
    // Set working directory
    if let Some(ref cwd) = params.cwd {
        let cwd_path = Path::new(cwd);
        if !cwd_path.exists() {
            bail!("Working directory does not exist: {}", cwd);
        }
        cmd.current_dir(cwd_path);
    }
    
    // Set environment
    if params.clear_env {
        cmd.env_clear();
    }
    if let Some(ref env) = params.env {
        for (key, value) in env {
            cmd.env(key, value);
        }
    }
    
    // Set up stdio
    let stdin_data = if let Some(ref stdin_file) = params.stdin_file {
        let data = tokio::fs::read_to_string(stdin_file).await
            .with_context(|| format!("Failed to read stdin file: {}", stdin_file))?;
        cmd.stdin(Stdio::piped());
        Some(data)
    } else {
        cmd.stdin(Stdio::null());
        None
    };
    
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    
    // Spawn process
    let mut child = cmd.spawn()
        .with_context(|| format!("Failed to spawn command: {}", command))?;
    
    let pid = child.id();
    
    // Handle stdin
    if let Some(data) = stdin_data {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data.as_bytes()).await?;
            drop(stdin);
        }
    }
    
    // Background mode: return immediately
    if params.background {
        let stdout_handle = child.stdout.take();
        let stderr_handle = child.stderr.take();

        spawn_output_task(stdout_handle, params.stdout_file.clone());
        spawn_output_task(stderr_handle, params.stderr_file.clone());

        if let (Some(manager), Some(pid)) = (manager, pid) {
            manager.register(
                pid,
                command.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
                params.cwd.clone(),
            ).await;
            
            // Spawn task to clean up when process exits
            let manager = manager.clone();
            tokio::spawn(async move {
                let _ = child.wait().await;
                manager.unregister(pid).await;
            });
        }
        
    return Ok(RunResult {
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            pid,
            killed: false,
            timed_out: false,
            duration_ms: start.elapsed().as_millis() as u64,
            background: true,
        });
    }
    
    // Foreground mode: wait for completion with optional timeout
    wait_for_process(
        child,
        &params,
        start,
        params.stdout_file.clone(),
        params.stderr_file.clone(),
    )
    .await
}

async fn open_output_file(path: Option<String>) -> Option<tokio::fs::File> {
    let Some(path) = path else {
        return None;
    };

    tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .await
        .ok()
}

fn spawn_output_task<R>(handle: Option<R>, output_file: Option<String>)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let Some(handle) = handle else {
            return;
        };

        let reader = BufReader::new(handle);
        let mut line_reader = reader.lines();

        let mut writer = open_output_file(output_file).await;
        while let Ok(Some(line)) = line_reader.next_line().await {
            if let Some(ref mut file) = writer {
                if file.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
                if file.write_all(b"\n").await.is_err() {
                    break;
                }
            }
        }
    });
}

/// Wait for process with timeout/watchdog handling
async fn wait_for_process(
    mut child: Child,
    params: &RunParams,
    start: Instant,
    stdout_file: Option<String>,
    stderr_file: Option<String>,
) -> Result<RunResult> {
    let pid = child.id();
    
    // Determine effective timeout
    let timeout_duration = match (params.timeout_ms, params.kill_after_ms) {
        (Some(t), Some(k)) => Some(Duration::from_millis(t.max(k))),
        (Some(t), None) => Some(Duration::from_millis(t)),
        (None, Some(k)) => Some(Duration::from_millis(k)),
        (None, None) => None,
    };
    
    // Collect stdout/stderr
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();
    
    let stdout_task = tokio::spawn(async move {
        let mut lines = Vec::new();
        if let Some(stdout) = stdout_handle {
            let mut writer = open_output_file(stdout_file).await;
            let reader = BufReader::new(stdout);
            let mut line_reader = reader.lines();
            while let Ok(Some(line)) = line_reader.next_line().await {
                if let Some(ref mut file) = writer {
                    let _ = file.write_all(line.as_bytes()).await;
                    let _ = file.write_all(b"\n").await;
                }
                lines.push(line);
            }
        }
        lines
    });
    
    let stderr_task = tokio::spawn(async move {
        let mut lines = Vec::new();
        if let Some(stderr) = stderr_handle {
            let mut writer = open_output_file(stderr_file).await;
            let reader = BufReader::new(stderr);
            let mut line_reader = reader.lines();
            while let Ok(Some(line)) = line_reader.next_line().await {
                if let Some(ref mut file) = writer {
                    let _ = file.write_all(line.as_bytes()).await;
                    let _ = file.write_all(b"\n").await;
                }
                lines.push(line);
            }
        }
        lines
    });
    
    // Wait for process with optional timeout
    let (exit_status, killed, timed_out) = if let Some(duration) = timeout_duration {
        match timeout(duration, child.wait()).await {
            Ok(Ok(status)) => (Some(status), false, false),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                // Timeout - kill the process
                let _ = child.kill().await;
                // Wait for the killed process to avoid zombie
                let _ = child.wait().await;
                (None, true, true)
            }
        }
    } else {
        let status = child.wait().await?;
        (Some(status), false, false)
    };
    
    // Collect output (with timeout to avoid hangs on killed processes)
    let stdout_lines = timeout(Duration::from_millis(100), stdout_task)
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();
    let stderr_lines = timeout(Duration::from_millis(100), stderr_task)
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();
    
    // Apply tail if requested
    let stdout = apply_tail(stdout_lines, params.stdout_tail);
    let stderr = apply_tail(stderr_lines, params.stderr_tail);
    
    let exit_code = exit_status.and_then(|s| s.code());
    
    Ok(RunResult {
        exit_code,
        stdout,
        stderr,
        pid,
        killed,
        timed_out,
        duration_ms: start.elapsed().as_millis() as u64,
        background: false,
    })
}

/// Apply tail to output lines
fn apply_tail(lines: Vec<String>, tail: Option<usize>) -> String {
    match tail {
        Some(n) if n > 0 && n < lines.len() => {
            lines[lines.len() - n..].join("\n")
        }
        _ => lines.join("\n"),
    }
}

/// Kill a process by PID using native API via sysinfo
pub fn kill_process(pid: u32, force: bool) -> Result<bool> {
    use sysinfo::{Pid, Signal, System};
    
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    
    let sysinfo_pid = Pid::from_u32(pid);
    
    if let Some(process) = sys.process(sysinfo_pid) {
        let signal = if force {
            Signal::Kill  // SIGKILL on Unix, TerminateProcess on Windows
        } else {
            Signal::Term  // SIGTERM on Unix, TerminateProcess on Windows
        };
        Ok(process.kill_with(signal).unwrap_or(false))
    } else {
        Ok(false)  // Process not found
    }
}

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
    use regex::Regex;
    
    let mut sys = System::new_all();
    sys.refresh_all();
    
    // Compile regex patterns (case-insensitive)
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
            Some(cmd.iter().map(|s| s.to_string_lossy().to_string()).collect::<Vec<_>>().join(" "))
        };
        
        // Apply name filter
        if let Some(ref re) = name_re {
            if !re.is_match(&name) {
                continue;
            }
        }
        
        // Apply cmdline filter
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
        
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
        let result = run_command(cmd, &args_refs, RunParams::default(), None).await.unwrap();
        
        assert!(!result.killed);
        assert!(!result.timed_out);
        assert!(result.stdout.contains("hello"));
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
        
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
        let result = run_command(cmd, &args_refs, params, None).await.unwrap();
        
        assert!(result.stdout.contains("test_value"));
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
        
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
        let result = run_command(cmd, &args_refs, params, None).await.unwrap();
        
        // Normalize paths for comparison
        let output = result.stdout.trim().replace('\\', "/").to_lowercase();
        let expected = dir_path.replace('\\', "/").to_lowercase();
        assert!(output.contains(&expected) || expected.contains(&output));
    }

    #[tokio::test]
    async fn test_run_with_timeout() {
        // Use ping with long timeout to test process killing
        #[cfg(windows)]
        let (cmd, args) = ("ping", vec!["-n", "100", "127.0.0.1"]);
        #[cfg(unix)]
        let (cmd, args) = ("sleep", vec!["10"]);
        
        let params = RunParams {
            timeout_ms: Some(500),
            ..Default::default()
        };
        
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
        let result = run_command(cmd, &args_refs, params, None).await.unwrap();
        
        assert!(result.killed);
        assert!(result.timed_out);
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
        
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
        let result = run_command(cmd, &args_refs, params, None).await.unwrap();
        
        assert!(!result.stdout.contains("line1"));
        assert!(result.stdout.contains("line2"));
        assert!(result.stdout.contains("line3"));
    }

    #[tokio::test]
    async fn test_run_with_stdin_file() {
        let dir = tempdir().unwrap();
        let stdin_path = dir.path().join("input.txt");
        tokio::fs::write(&stdin_path, "hello from file").await.unwrap();
        
        #[cfg(windows)]
        let (cmd, args) = ("cmd", vec!["/C", "findstr ."]);
        #[cfg(unix)]
        let (cmd, args) = ("cat", vec![]);
        
        let params = RunParams {
            stdin_file: Some(stdin_path.to_string_lossy().to_string()),
            ..Default::default()
        };
        
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
        let result = run_command(cmd, &args_refs, params, None).await.unwrap();
        
        assert!(result.stdout.contains("hello from file"));
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
        
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
        let _ = run_command(cmd, &args_refs, params, None).await.unwrap();
        
        let content = tokio::fs::read_to_string(&stdout_path).await.unwrap();
        assert!(content.contains("test output"));
    }

    #[tokio::test]
    async fn test_run_background() {
        let manager = ProcessManager::new();
        
        #[cfg(windows)]
        let (cmd, args) = ("cmd", vec!["/C", "ping -n 3 127.0.0.1"]);
        #[cfg(unix)]
        let (cmd, args) = ("sleep", vec!["2"]);
        
        let params = RunParams {
            background: true,
            ..Default::default()
        };
        
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
        let result = run_command(cmd, &args_refs, params, Some(&manager)).await.unwrap();
        
        assert!(result.background);
        assert!(result.pid.is_some());
        assert!(result.duration_ms < 1000); // Should return immediately
        
        // Process should be registered
        let pid = result.pid.unwrap();
        assert!(manager.list().await.iter().any(|p| p.pid == pid));
        
        // Wait for it to finish and unregister
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert!(!manager.list().await.iter().any(|p| p.pid == pid));
    }

    #[tokio::test]
    async fn test_exit_code() {
        #[cfg(windows)]
        let (cmd, args) = ("cmd", vec!["/C", "exit 42"]);
        #[cfg(unix)]
        let (cmd, args) = ("sh", vec!["-c", "exit 42"]);
        
        let args_refs: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
        let result = run_command(cmd, &args_refs, RunParams::default(), None).await.unwrap();
        
        assert_eq!(result.exit_code, Some(42));
    }

    #[test]
    fn test_apply_tail() {
        let lines = vec!["a".to_string(), "b".to_string(), "c".to_string(), "d".to_string()];
        
        assert_eq!(apply_tail(lines.clone(), Some(2)), "c\nd");
        assert_eq!(apply_tail(lines.clone(), Some(10)), "a\nb\nc\nd");
        assert_eq!(apply_tail(lines.clone(), None), "a\nb\nc\nd");
        assert_eq!(apply_tail(lines.clone(), Some(0)), "a\nb\nc\nd");
    }

    #[tokio::test]
    async fn test_process_manager() {
        let manager = ProcessManager::new();
        
        manager.register(123, "test".to_string(), vec![], None).await;
        
        let list = manager.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].pid, 123);
        
        manager.unregister(123).await;
        assert!(manager.list().await.is_empty());
    }

    #[test]
    fn test_search_processes() {
        // Search for current test process (cargo or rust)
        let results = search_processes(
            Some("cargo|rust"),
            None,
        ).unwrap();
        
        // Should find at least one process (this test itself)
        assert!(!results.is_empty(), "Should find at least one cargo/rust process");
        
        // All results should have a name
        for p in &results {
            assert!(!p.name.is_empty());
            assert!(p.pid > 0);
        }
    }

    #[test]
    fn test_kill_nonexistent_process() {
        // Try to kill a non-existent PID
        let result = kill_process(999999999, false);
        // Should return Ok(false) - process not found, no error
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Killing non-existent process should return false");
    }

    #[test]
    fn test_kill_system_process_access_denied() {
        // Try to kill PID 1 (init on Unix) or PID 4 (System on Windows)
        // This should fail with access denied or similar
        #[cfg(unix)]
        let system_pid = 1; // init/systemd
        #[cfg(windows)]
        let system_pid = 4; // System process
        
        let result = kill_process(system_pid, false);
        // Should return Ok(false) - failed to kill due to access denied
        // The function catches errors and returns false, not an error
        assert!(result.is_ok());
        // System process should not be killable
        assert!(!result.unwrap(), "Should not be able to kill system process");
    }
}
