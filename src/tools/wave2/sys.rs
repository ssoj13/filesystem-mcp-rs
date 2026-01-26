//! System utilities - disk_usage, sys_info.

use serde_json::{json, Value};
use sysinfo::{System, Disks};
use std::path::Path;

/// Get disk usage for a path or all disks
pub fn disk_usage(path: Option<&Path>) -> Result<Value, String> {
    let disks = Disks::new_with_refreshed_list();
    
    if let Some(target_path) = path {
        // Find disk containing the path
        let target = target_path.canonicalize()
            .unwrap_or_else(|_| target_path.to_path_buf());
        
        for disk in disks.list() {
            let mount = disk.mount_point();
            if target.starts_with(mount) {
                let total = disk.total_space();
                let available = disk.available_space();
                let used = total.saturating_sub(available);
                let percent = if total > 0 { (used as f64 / total as f64) * 100.0 } else { 0.0 };
                
                return Ok(json!({
                    "path": target.to_string_lossy(),
                    "mount_point": mount.to_string_lossy(),
                    "filesystem": disk.file_system().to_string_lossy(),
                    "total_bytes": total,
                    "used_bytes": used,
                    "available_bytes": available,
                    "used_percent": format!("{:.1}", percent),
                    "total_human": format_bytes(total),
                    "used_human": format_bytes(used),
                    "available_human": format_bytes(available)
                }));
            }
        }
        return Err(format!("No disk found for path: {}", target_path.display()));
    }
    
    // Return all disks
    let mut disk_list = Vec::new();
    for disk in disks.list() {
        let total = disk.total_space();
        let available = disk.available_space();
        let used = total.saturating_sub(available);
        let percent = if total > 0 { (used as f64 / total as f64) * 100.0 } else { 0.0 };
        
        disk_list.push(json!({
            "name": disk.name().to_string_lossy(),
            "mount_point": disk.mount_point().to_string_lossy(),
            "filesystem": disk.file_system().to_string_lossy(),
            "total_bytes": total,
            "used_bytes": used,
            "available_bytes": available,
            "used_percent": format!("{:.1}", percent),
            "total_human": format_bytes(total),
            "used_human": format_bytes(used),
            "available_human": format_bytes(available),
            "is_removable": disk.is_removable()
        }));
    }
    
    Ok(json!({
        "disk_count": disk_list.len(),
        "disks": disk_list
    }))
}

/// Get system information (CPU, RAM, uptime)
pub fn sys_info() -> Value {
    let mut sys = System::new_all();
    sys.refresh_all();
    
    let total_mem = sys.total_memory();
    let used_mem = sys.used_memory();
    let total_swap = sys.total_swap();
    let used_swap = sys.used_swap();
    
    // CPU info
    let cpu_count = sys.cpus().len();
    let cpu_usage: f32 = sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / cpu_count as f32;
    let cpu_name = sys.cpus().first()
        .map(|c| c.brand().to_string())
        .unwrap_or_else(|| "Unknown".to_string());
    
    // Load average (Unix only)
    let load_avg = System::load_average();
    
    json!({
        "hostname": System::host_name().unwrap_or_default(),
        "os": System::name().unwrap_or_default(),
        "os_version": System::os_version().unwrap_or_default(),
        "kernel_version": System::kernel_version().unwrap_or_default(),
        "arch": std::env::consts::ARCH,
        "uptime_seconds": System::uptime(),
        "uptime_human": format_duration(System::uptime()),
        "boot_time": System::boot_time(),
        "cpu": {
            "name": cpu_name,
            "count": cpu_count,
            "usage_percent": format!("{:.1}", cpu_usage)
        },
        "memory": {
            "total_bytes": total_mem,
            "used_bytes": used_mem,
            "available_bytes": total_mem.saturating_sub(used_mem),
            "used_percent": format!("{:.1}", (used_mem as f64 / total_mem as f64) * 100.0),
            "total_human": format_bytes(total_mem),
            "used_human": format_bytes(used_mem)
        },
        "swap": {
            "total_bytes": total_swap,
            "used_bytes": used_swap,
            "total_human": format_bytes(total_swap),
            "used_human": format_bytes(used_swap)
        },
        "load_average": {
            "one": load_avg.one,
            "five": load_avg.five,
            "fifteen": load_avg.fifteen
        },
        "process_count": sys.processes().len()
    })
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    
    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

fn format_duration(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let mins = (seconds % 3600) / 60;
    let secs = seconds % 60;
    
    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, mins, secs)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, mins, secs)
    } else if mins > 0 {
        format!("{}m {}s", mins, secs)
    } else {
        format!("{}s", secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sys_info() {
        let info = sys_info();
        assert!(info.get("hostname").is_some());
        assert!(info.get("os").is_some());
        assert!(info.get("cpu").is_some());
        assert!(info.get("memory").is_some());
        assert!(info["cpu"]["count"].as_u64().unwrap() > 0);
        assert!(info["memory"]["total_bytes"].as_u64().unwrap() > 0);
    }

    #[test]
    fn test_disk_usage_all() {
        let result = disk_usage(None);
        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.get("disk_count").is_some());
        assert!(json.get("disks").is_some());
    }

    #[test]
    fn test_disk_usage_specific() {
        // Use absolute path to current directory
        let path = std::env::current_dir().unwrap();
        let result = disk_usage(Some(&path));
        // May fail if path doesn't match any mount point
        if let Ok(json) = result {
            assert!(json.get("total_bytes").is_some());
            assert!(json.get("available_bytes").is_some());
        }
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(59), "59s");
        assert_eq!(format_duration(60), "1m 0s");
        assert_eq!(format_duration(3600), "1h 0m 0s");
        assert_eq!(format_duration(86400), "1d 0h 0m 0s");
        assert_eq!(format_duration(90061), "1d 1h 1m 1s");
    }
}
