//! Network utilities - port_users, net_connections, port_available.

use serde_json::{json, Value};
use std::net::TcpListener;
use std::process::Command;
use sysinfo::{System, Pid};

/// Check if port is available (not in use)
pub fn port_available(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

/// Get processes using a specific port
pub fn port_users(port: u16) -> Result<Vec<Value>, String> {
    let connections = get_connections()?;
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    
    let mut results = Vec::new();
    for conn in connections {
        if conn.local_port == port || conn.remote_port == Some(port) {
            let proc_name = conn.pid
                .and_then(|pid| sys.process(Pid::from_u32(pid)))
                .map(|p| p.name().to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            
            results.push(json!({
                "pid": conn.pid,
                "name": proc_name,
                "protocol": conn.protocol,
                "local_addr": conn.local_addr,
                "local_port": conn.local_port,
                "remote_addr": conn.remote_addr,
                "remote_port": conn.remote_port,
                "state": conn.state
            }));
        }
    }
    Ok(results)
}

/// Get all network connections, optionally filtered by PID
pub fn net_connections(pid: Option<u32>) -> Result<Vec<Value>, String> {
    let connections = get_connections()?;
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    
    let mut results = Vec::new();
    for conn in connections {
        // Filter by PID if specified
        if let Some(filter_pid) = pid {
            if conn.pid != Some(filter_pid) {
                continue;
            }
        }
        
        let proc_name = conn.pid
            .and_then(|pid| sys.process(Pid::from_u32(pid)))
            .map(|p| p.name().to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        results.push(json!({
            "pid": conn.pid,
            "name": proc_name,
            "protocol": conn.protocol,
            "local_addr": conn.local_addr,
            "local_port": conn.local_port,
            "remote_addr": conn.remote_addr,
            "remote_port": conn.remote_port,
            "state": conn.state
        }));
    }
    Ok(results)
}

#[derive(Debug)]
struct Connection {
    protocol: String,
    local_addr: String,
    local_port: u16,
    remote_addr: Option<String>,
    remote_port: Option<u16>,
    state: String,
    pid: Option<u32>,
}

/// Parse network connections from system commands
fn get_connections() -> Result<Vec<Connection>, String> {
    #[cfg(target_os = "windows")]
    {
        get_connections_windows()
    }
    #[cfg(target_os = "linux")]
    {
        get_connections_linux()
    }
    #[cfg(target_os = "macos")]
    {
        get_connections_macos()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err("Unsupported platform".to_string())
    }
}

#[cfg(target_os = "windows")]
fn get_connections_windows() -> Result<Vec<Connection>, String> {
    // Use netstat -ano for Windows
    let output = Command::new("netstat")
        .args(["-ano"])
        .output()
        .map_err(|e| format!("Failed to run netstat: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut connections = Vec::new();
    
    for line in stdout.lines().skip(4) {
        // Skip header lines
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        
        let protocol = parts[0].to_uppercase();
        if protocol != "TCP" && protocol != "UDP" {
            continue;
        }
        
        // Parse local address
        let (local_addr, local_port) = parse_addr_port(parts[1])?;
        
        // Parse remote address (may be *:* for listening)
        let (remote_addr, remote_port) = if parts.len() > 2 && parts[2] != "*:*" {
            let (addr, port) = parse_addr_port(parts[2]).unwrap_or(("*".to_string(), 0));
            (Some(addr), if port > 0 { Some(port) } else { None })
        } else {
            (None, None)
        };
        
        // State and PID
        let (state, pid) = if protocol == "TCP" && parts.len() >= 5 {
            (parts[3].to_string(), parts[4].parse().ok())
        } else if protocol == "UDP" && parts.len() >= 4 {
            ("".to_string(), parts[3].parse().ok())
        } else {
            ("".to_string(), None)
        };
        
        connections.push(Connection {
            protocol,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
            pid,
        });
    }
    
    Ok(connections)
}

#[cfg(target_os = "linux")]
fn get_connections_linux() -> Result<Vec<Connection>, String> {
    // Use ss command for Linux
    let output = Command::new("ss")
        .args(["-tunap"])
        .output()
        .map_err(|e| format!("Failed to run ss: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut connections = Vec::new();
    
    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        
        let protocol = parts[0].to_uppercase();
        let state = parts[1].to_string();
        
        let (local_addr, local_port) = parse_addr_port_linux(parts[4])?;
        let (remote_addr, remote_port) = if parts.len() > 5 {
            let (addr, port) = parse_addr_port_linux(parts[5]).unwrap_or(("*".to_string(), 0));
            (Some(addr), if port > 0 { Some(port) } else { None })
        } else {
            (None, None)
        };
        
        // Extract PID from last column (e.g., "users:((\"node\",pid=1234,fd=3))")
        let pid = parts.last()
            .and_then(|s| {
                s.find("pid=")
                    .map(|i| &s[i+4..])
                    .and_then(|s| s.split(|c| c == ',' || c == ')').next())
                    .and_then(|s| s.parse().ok())
            });
        
        connections.push(Connection {
            protocol,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
            pid,
        });
    }
    
    Ok(connections)
}

#[cfg(target_os = "macos")]
fn get_connections_macos() -> Result<Vec<Connection>, String> {
    // Use netstat for macOS
    let output = Command::new("netstat")
        .args(["-anv", "-p", "tcp"])
        .output()
        .map_err(|e| format!("Failed to run netstat: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut connections = Vec::new();
    
    for line in stdout.lines().skip(2) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        
        let protocol = parts[0].to_uppercase();
        if !protocol.starts_with("TCP") {
            continue;
        }
        
        let (local_addr, local_port) = parse_addr_port_macos(parts[3])?;
        let (remote_addr, remote_port) = {
            let (addr, port) = parse_addr_port_macos(parts[4]).unwrap_or(("*".to_string(), 0));
            (Some(addr), if port > 0 { Some(port) } else { None })
        };
        
        let state = parts[5].to_string();
        let pid = parts.last().and_then(|s| s.parse().ok());
        
        connections.push(Connection {
            protocol: "TCP".to_string(),
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
            pid,
        });
    }
    
    Ok(connections)
}

fn parse_addr_port(s: &str) -> Result<(String, u16), String> {
    // Handle IPv6 [addr]:port and IPv4 addr:port
    if let Some(idx) = s.rfind(':') {
        let addr = &s[..idx];
        let port = s[idx+1..].parse().unwrap_or(0);
        Ok((addr.trim_matches(|c| c == '[' || c == ']').to_string(), port))
    } else {
        Err(format!("Invalid address format: {}", s))
    }
}

#[cfg(target_os = "linux")]
fn parse_addr_port_linux(s: &str) -> Result<(String, u16), String> {
    parse_addr_port(s)
}

#[cfg(target_os = "macos")]
fn parse_addr_port_macos(s: &str) -> Result<(String, u16), String> {
    // macOS uses addr.port format
    if let Some(idx) = s.rfind('.') {
        let addr = &s[..idx];
        let port = s[idx+1..].parse().unwrap_or(0);
        Ok((addr.to_string(), port))
    } else {
        Err(format!("Invalid address format: {}", s))
    }
}
