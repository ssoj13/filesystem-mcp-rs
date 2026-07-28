use std::path::Path;

use anyhow::Result;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use crate::tools::binary::to_base64;
use crate::tools::mime::mime_for_ext;

pub async fn read_media_base64(path: &Path) -> Result<(String, String)> {
    let mut file = File::open(path).await?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).await?;
    let encoded = to_base64(&buf);
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| format!(".{}", s.to_ascii_lowercase()))
        .unwrap_or_default();
    let mime = mime_for_ext(&ext).to_string();
    Ok((encoded, mime))
}
