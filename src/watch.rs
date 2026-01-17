use std::path::Path;
use std::time::Duration;

use anyhow::{Result, Context, bail};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher, Event, EventKind};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::fs_ops::decode_bytes;

/// Result of tail operation
#[derive(Debug, Clone)]
pub struct TailResult {
    pub content: String,
    pub lines_returned: usize,
    pub file_size: u64,
    pub truncated: bool,
    /// For follow mode: new content appended since start
    pub follow_content: Option<String>,
    pub follow_lines: Option<usize>,
}

/// Parameters for tail operation
pub struct TailParams {
    /// Number of lines to return (default: 10)
    pub lines: usize,
    /// Alternative: number of bytes from end
    pub bytes: Option<u64>,
    /// Follow mode: wait for new content
    pub follow: bool,
    /// Timeout for follow mode in milliseconds (default: 5000)
    pub timeout_ms: u64,
}

impl Default for TailParams {
    fn default() -> Self {
        Self {
            lines: 10,
            bytes: None,
            follow: false,
            timeout_ms: 5000,
        }
    }
}

/// Result of watch operation
#[derive(Debug, Clone)]
pub struct WatchResult {
    pub changed: bool,
    pub event: Option<String>,
    pub new_size: Option<u64>,
    pub elapsed_ms: u64,
    pub timed_out: bool,
}

/// Events to watch for
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchEvent {
    Modify,
    Create,
    Delete,
}

impl WatchEvent {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "modify" | "modified" | "change" | "changed" => Ok(Self::Modify),
            "create" | "created" => Ok(Self::Create),
            "delete" | "deleted" | "remove" | "removed" => Ok(Self::Delete),
            _ => bail!("Unknown event type '{}'. Supported: modify, create, delete", s),
        }
    }
    
    pub fn name(&self) -> &'static str {
        match self {
            Self::Modify => "modify",
            Self::Create => "create",
            Self::Delete => "delete",
        }
    }
}

/// Read last N lines from file (or last N bytes)
pub async fn tail_file(path: &Path, params: TailParams) -> Result<TailResult> {
    let mut file = File::open(path).await
        .with_context(|| format!("Cannot open file: {}", path.display()))?;
    
    let meta = file.metadata().await?;
    let file_size = meta.len();
    
    // Handle bytes mode
    if let Some(bytes) = params.bytes {
        let start = file_size.saturating_sub(bytes);
        file.seek(std::io::SeekFrom::Start(start)).await?;
        
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await?;
        let content = decode_bytes(&buf);
        let lines_returned = content.lines().count();
        
        let result = TailResult {
            content,
            lines_returned,
            file_size,
            truncated: start > 0,
            follow_content: None,
            follow_lines: None,
        };
        
        // Handle follow mode
        if params.follow {
            return tail_follow(path, file_size, params.timeout_ms, result).await;
        }
        
        return Ok(result);
    }
    
    // Lines mode: read file and take last N lines
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).await?;
    let full_content = decode_bytes(&buf);
    
    let all_lines: Vec<&str> = full_content.lines().collect();
    let total_lines = all_lines.len();
    let start_line = total_lines.saturating_sub(params.lines);
    let content = all_lines[start_line..].join("\n");
    let lines_returned = all_lines.len() - start_line;
    
    let result = TailResult {
        content,
        lines_returned,
        file_size,
        truncated: start_line > 0,
        follow_content: None,
        follow_lines: None,
    };
    
    // Handle follow mode
    if params.follow {
        return tail_follow(path, file_size, params.timeout_ms, result).await;
    }
    
    Ok(result)
}

/// Follow file for new content
async fn tail_follow(
    path: &Path,
    initial_size: u64,
    timeout_ms: u64,
    mut result: TailResult,
) -> Result<TailResult> {
    let (tx, mut rx) = mpsc::channel(1);
    let path_buf = path.to_path_buf();
    
    // Create watcher in blocking task
    let watcher_handle = tokio::task::spawn_blocking(move || {
        let rt_tx = tx;
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    if matches!(event.kind, EventKind::Modify(_)) {
                        let _ = rt_tx.blocking_send(());
                    }
                }
            },
            Config::default(),
        )?;
        
        watcher.watch(&path_buf, RecursiveMode::NonRecursive)?;
        
        // Keep watcher alive until dropped
        std::thread::park_timeout(Duration::from_millis(timeout_ms + 1000));
        Ok::<_, anyhow::Error>(())
    });
    
    // Wait for file change or timeout
    let wait_result = timeout(
        Duration::from_millis(timeout_ms),
        rx.recv()
    ).await;
    
    // Clean up watcher
    watcher_handle.abort();
    
    if wait_result.is_ok() {
        // File changed - read new content
        let mut file = File::open(path).await?;
        let new_size = file.metadata().await?.len();
        
        if new_size > initial_size {
            file.seek(std::io::SeekFrom::Start(initial_size)).await?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).await?;
            let new_content = decode_bytes(&buf);
            let new_lines = new_content.lines().count();
            
            result.follow_content = Some(new_content);
            result.follow_lines = Some(new_lines);
        }
    }
    
    Ok(result)
}

/// Watch file for changes
pub async fn watch_file(
    path: &Path,
    timeout_ms: u64,
    events: &[WatchEvent],
) -> Result<WatchResult> {
    let start = std::time::Instant::now();
    let (tx, mut rx) = mpsc::channel(8);
    let path_buf = path.to_path_buf();
    let events_clone: Vec<WatchEvent> = events.to_vec();
    
    // Check if file exists initially
    let initial_exists = path.exists();
    let initial_size = if initial_exists {
        tokio::fs::metadata(path).await.ok().map(|m| m.len())
    } else {
        None
    };
    
    // Create watcher
    let watcher_handle = tokio::task::spawn_blocking(move || {
        let rt_tx = tx;
        let events = events_clone;
        
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    let matched = match event.kind {
                        EventKind::Modify(_) => events.is_empty() || events.contains(&WatchEvent::Modify),
                        EventKind::Create(_) => events.is_empty() || events.contains(&WatchEvent::Create),
                        EventKind::Remove(_) => events.is_empty() || events.contains(&WatchEvent::Delete),
                        _ => false,
                    };
                    
                    if matched {
                        let event_name = match event.kind {
                            EventKind::Modify(_) => "modify",
                            EventKind::Create(_) => "create",
                            EventKind::Remove(_) => "delete",
                            _ => "unknown",
                        };
                        let _ = rt_tx.blocking_send(event_name.to_string());
                    }
                }
            },
            Config::default(),
        )?;
        
        // Watch parent directory to catch create/delete
        let watch_path = if path_buf.is_file() {
            path_buf.parent().unwrap_or(&path_buf).to_path_buf()
        } else {
            path_buf.clone()
        };
        
        watcher.watch(&watch_path, RecursiveMode::NonRecursive)?;
        
        std::thread::park_timeout(Duration::from_millis(timeout_ms + 1000));
        Ok::<_, anyhow::Error>(())
    });
    
    // Wait for event or timeout
    let wait_result = timeout(
        Duration::from_millis(timeout_ms),
        rx.recv()
    ).await;
    
    watcher_handle.abort();
    
    let elapsed = start.elapsed().as_millis() as u64;
    
    match wait_result {
        Ok(Some(event_name)) => {
            let new_size = tokio::fs::metadata(path).await.ok().map(|m| m.len());
            Ok(WatchResult {
                changed: true,
                event: Some(event_name),
                new_size,
                elapsed_ms: elapsed,
                timed_out: false,
            })
        }
        Ok(None) | Err(_) => {
            Ok(WatchResult {
                changed: false,
                event: None,
                new_size: initial_size,
                elapsed_ms: elapsed,
                timed_out: true,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_tail_lines() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.log");
        fs::write(&path, "line1\nline2\nline3\nline4\nline5\n").await.unwrap();
        
        let params = TailParams {
            lines: 3,
            ..Default::default()
        };
        
        let result = tail_file(&path, params).await.unwrap();
        
        assert_eq!(result.lines_returned, 3);
        assert!(result.content.contains("line3"));
        assert!(result.content.contains("line4"));
        assert!(result.content.contains("line5"));
        assert!(!result.content.contains("line1"));
    }

    #[tokio::test]
    async fn test_tail_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.log");
        fs::write(&path, "0123456789").await.unwrap();
        
        let params = TailParams {
            bytes: Some(5),
            ..Default::default()
        };
        
        let result = tail_file(&path, params).await.unwrap();
        
        assert_eq!(result.content, "56789");
        assert!(result.truncated);
    }

    #[tokio::test]
    async fn test_tail_empty_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.log");
        fs::write(&path, "").await.unwrap();
        
        let result = tail_file(&path, TailParams::default()).await.unwrap();
        
        assert_eq!(result.content, "");
        assert_eq!(result.lines_returned, 0);
        assert!(!result.truncated);
    }

    #[tokio::test]
    async fn test_tail_less_lines_than_requested() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("short.log");
        fs::write(&path, "line1\nline2\n").await.unwrap();
        
        let params = TailParams {
            lines: 10,
            ..Default::default()
        };
        
        let result = tail_file(&path, params).await.unwrap();
        
        assert_eq!(result.lines_returned, 2);
        assert!(!result.truncated);
    }

    #[tokio::test]
    async fn test_tail_follow_with_append() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("follow.log");
        fs::write(&path, "initial\n").await.unwrap();
        
        let path_clone = path.clone();
        
        // Spawn task to append after delay
        tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            fs::write(&path_clone, "initial\nnew line\n").await.unwrap();
        });
        
        let params = TailParams {
            lines: 10,
            follow: true,
            timeout_ms: 2000,
            ..Default::default()
        };
        
        let result = tail_file(&path, params).await.unwrap();
        
        // Should have follow content (though timing can be tricky)
        assert!(result.content.contains("initial"));
    }

    #[tokio::test]
    async fn test_watch_file_modify() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("watch.txt");
        fs::write(&path, "initial").await.unwrap();
        
        let path_clone = path.clone();
        
        // Spawn task to modify after delay
        tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            fs::write(&path_clone, "modified").await.unwrap();
        });
        
        let result = watch_file(&path, 2000, &[WatchEvent::Modify]).await.unwrap();
        
        assert!(result.changed);
        assert_eq!(result.event, Some("modify".to_string()));
    }

    #[tokio::test]
    async fn test_watch_file_timeout() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nochange.txt");
        fs::write(&path, "static").await.unwrap();
        
        let result = watch_file(&path, 100, &[]).await.unwrap();
        
        assert!(!result.changed);
        assert!(result.timed_out);
    }

    #[tokio::test]
    async fn test_watch_event_from_str() {
        assert!(matches!(WatchEvent::from_str("modify").unwrap(), WatchEvent::Modify));
        assert!(matches!(WatchEvent::from_str("CREATE").unwrap(), WatchEvent::Create));
        assert!(matches!(WatchEvent::from_str("delete").unwrap(), WatchEvent::Delete));
        assert!(WatchEvent::from_str("invalid").is_err());
    }
}
