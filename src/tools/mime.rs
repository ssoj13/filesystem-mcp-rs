use std::collections::HashMap;

use std::sync::LazyLock;

pub fn mime_for_ext(ext: &str) -> &str {
    static MAP: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
        HashMap::from([
            (".png", "image/png"),
            (".jpg", "image/jpeg"),
            (".jpeg", "image/jpeg"),
            (".gif", "image/gif"),
            (".webp", "image/webp"),
            (".bmp", "image/bmp"),
            (".svg", "image/svg+xml"),
            (".mp3", "audio/mpeg"),
            (".wav", "audio/wav"),
            (".ogg", "audio/ogg"),
            (".flac", "audio/flac"),
        ])
    });
    MAP.get(ext).copied().unwrap_or("application/octet-stream")
}
