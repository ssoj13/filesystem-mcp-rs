use std::path::Path;

use anyhow::Result;
use base64::Engine;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use crate::tools::mime::mime_for_ext;

pub async fn read_media_base64(path: &Path) -> Result<(String, String)> {
    let mut file = File::open(path).await?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).await?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(buf);
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| format!(".{}", s.to_ascii_lowercase()))
        .unwrap_or_default();
    let mime = mime_for_ext(&ext).to_string();
    Ok((encoded, mime))
}
