//! Process utilities - proc_tree, proc_env, proc_files.

use serde_json::{json, Value};
use std::collections::HashMap;
use sysinfo::{System, Pid};

/// Get process tree (all processes with parent-child relationships)
pub fn proc_tree(root_pid: Option<u32>) -> Result<Value, String> {
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    
    // Build parent -> children map
    let mut children_map: HashMap<Option<Pid>, Vec<Pid>> = HashMap::new();
    for (pid, proc) in sys.processes() {
        let parent = proc.parent();
        children_map.entry(parent).or_default().push(*pid);
    }
    
    // Build tree from root
    fn build_tree(sys: &System, pid: Pid, children_map: &HashMap<Option<Pid>, Vec<Pid>>, depth: usize) -> Value {
        let proc = sys.process(pid);
        let name = proc.map(|p| p.name().to_string_lossy().to_string()).unwrap_or_default();
        let cmd = proc.map(|p| p.cmd().iter().map(|s| s.to_string_lossy().to_string()).collect::<Vec<_>>()).unwrap_or_default();
        let cpu = proc.map(|p| p.cpu_usage()).unwrap_or(0.0);
        let mem = proc.map(|p| p.memory()).unwrap_or(0);
        
        let children: Vec<Value> = children_map
            .get(&Some(pid))
            .map(|pids| pids.iter().map(|&child_pid| build_tree(sys, child_pid, children_map, depth + 1)).collect())
            .unwrap_or_default();
        
        json!({
            "pid": pid.as_u32(),
            "name": name,
            "cmd": cmd,
            "cpu_percent": cpu,
            "memory_bytes": mem,
            "children": children
        })
    }
    
    if let Some(root) = root_pid {
        // Build tree from specific PID
        let pid = Pid::from_u32(root);
        if sys.process(pid).is_none() {
            return Err(format!("Process {} not found", root));
        }
        Ok(build_tree(&sys, pid, &children_map, 0))
    } else {
        // Build forest of all root processes
        let roots: Vec<Value> = children_map
            .get(&None)
            .map(|pids| pids.iter().map(|&pid| build_tree(&sys, pid, &children_map, 0)).collect())
            .unwrap_or_default();
        Ok(json!({
            "processes": roots,
            "total_count": sys.processes().len()
        }))
    }
}

/// Get environment variables of a process
pub fn proc_env(pid: u32) -> Result<Value, String> {
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    
    let pid = Pid::from_u32(pid);
    let proc = sys.process(pid)
        .ok_or_else(|| format!("Process {} not found", pid))?;
    
    let environ = proc.environ();
    let env_map: HashMap<String, String> = environ
        .iter()
        .filter_map(|s| {
            let s = s.to_string_lossy();
            s.find('=').map(|i| (s[..i].to_string(), s[i+1..].to_string()))
        })
        .collect();
    
    Ok(json!({
        "pid": pid.as_u32(),
        "name": proc.name().to_string_lossy(),
        "env_count": env_map.len(),
        "environment": env_map
    }))
}

/// Get open files of a process (Linux/macOS only, limited on Windows)
pub fn proc_files(pid: u32) -> Result<Value, String> {
    #[cfg(target_os = "linux")]
    {
        proc_files_linux(pid)
    }
    #[cfg(target_os = "macos")]
    {
        proc_files_macos(pid)
    }
    #[cfg(target_os = "windows")]
    {
        proc_files_windows(pid)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err("Unsupported platform".to_string())
    }
}

#[cfg(target_os = "linux")]
fn proc_files_linux(pid: u32) -> Result<Value, String> {
    use std::fs;
    use std::path::PathBuf;
    
    let fd_dir = PathBuf::from(format!("/proc/{}/fd", pid));
    if !fd_dir.exists() {
        return Err(format!("Process {} not found or no permission", pid));
    }
    
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(&fd_dir) {
        for entry in entries.flatten() {
            if let Ok(link) = fs::read_link(entry.path()) {
                let fd = entry.file_name().to_string_lossy().to_string();
                files.push(json!({
                    "fd": fd,
                    "path": link.to_string_lossy()
                }));
            }
        }
    }
    
    Ok(json!({
        "pid": pid,
        "file_count": files.len(),
        "files": files
    }))
}

#[cfg(target_os = "macos")]
fn proc_files_macos(pid: u32) -> Result<Value, String> {
    use std::process::Command;
    
    let output = Command::new("lsof")
        .args(["-p", &pid.to_string()])
        .output()
        .map_err(|e| format!("Failed to run lsof: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut files = Vec::new();
    
    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 9 {
            files.push(json!({
                "fd": parts[3],
                "type": parts[4],
                "path": parts.get(8).unwrap_or(&"")
            }));
        }
    }
    
    Ok(json!({
        "pid": pid,
        "file_count": files.len(),
        "files": files
    }))
}

#[cfg(target_os = "windows")]
fn proc_files_windows(pid: u32) -> Result<Value, String> {
    // Windows doesn't have easy way to list open files without handle.exe
    // Return basic process info instead
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    
    let pid_sys = Pid::from_u32(pid);
    let proc = sys.process(pid_sys)
        .ok_or_else(|| format!("Process {} not found", pid))?;
    
    Ok(json!({
        "pid": pid,
        "name": proc.name().to_string_lossy(),
        "note": "Open files listing requires external tool (handle.exe) on Windows",
        "exe": proc.exe().map(|p| p.to_string_lossy().to_string()),
        "cwd": proc.cwd().map(|p| p.to_string_lossy().to_string())
    }))
}
