use std::path::Path;

use anyhow::Result;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt};

/// Read full file as UTF-8 text.
pub async fn read_text(path: &Path) -> Result<String> {
    let content = fs::read_to_string(path).await?;
    Ok(content)
}

/// Return first N lines.
pub async fn head(path: &Path, lines: usize) -> Result<String> {
    let mut file = fs::File::open(path).await?;
    let mut reader = tokio::io::BufReader::new(&mut file);
    let mut buf = String::new();
    let mut out = Vec::new();

    while out.len() < lines {
        buf.clear();
        let n = reader.read_line(&mut buf).await?;
        if n == 0 {
            break;
        }
        if buf.ends_with('\n') {
            buf.pop();
            if buf.ends_with('\r') {
                buf.pop();
            }
        }
        out.push(buf.clone());
    }

    Ok(out.join("\n"))
}

/// Return last N lines; reads from end in chunks.
pub async fn tail(path: &Path, lines: usize) -> Result<String> {
    const CHUNK: usize = 4096;
    let mut file = fs::File::open(path).await?;
    let metadata = file.metadata().await?;
    let size = metadata.len();
    if size == 0 || lines == 0 {
        return Ok(String::new());
    }

    let mut pos: i64 = size as i64;
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut newline_count = 0usize;

    while pos > 0 && newline_count <= lines {
        let read_size = CHUNK.min(pos as usize);
        pos -= read_size as i64;
        let mut chunk = vec![0u8; read_size];
        file.seek(std::io::SeekFrom::Start(pos as u64)).await?;
        let n = file.read(&mut chunk).await?;
        chunk.truncate(n);
        newline_count += chunk.iter().filter(|b| **b == b'\n').count();
        chunks.push(chunk);
        if newline_count > lines {
            break;
        }
    }

    let mut combined = Vec::new();
    for chunk in chunks.iter().rev() {
        combined.extend_from_slice(chunk);
    }
    let text = String::from_utf8_lossy(&combined).into_owned();
    let lines_vec: Vec<&str> = text.lines().collect();
    let start = lines_vec.len().saturating_sub(lines);
    Ok(lines_vec[start..].join("\n"))
}
