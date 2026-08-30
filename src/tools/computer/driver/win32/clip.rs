//! Clipboard file lists (CF_HDROP) via clipboard-win — arboard has no file
//! support (PLAN2.md §2). One facade for all clipboard access in this crate:
//! both arboard (text, in input::type_text) and clipboard-win (files, here)
//! open the clipboard, so every access goes through the same mutex to avoid
//! open/close races (critic §10.7).

use std::sync::Mutex;

use anyhow::Context as _;

/// Clipboard opens must not interleave (arboard and clipboard-win share it).
pub static CLIP_MTX: Mutex<()> = Mutex::new(());

/// Put a file list on the clipboard (paste into Explorer/apps).
pub fn set_files(files: &[String]) -> anyhow::Result<()> {
    use clipboard_win::{Clipboard, Setter, formats};
    if files.is_empty() {
        return Err(anyhow::anyhow!("empty file list"));
    }
    let _guard = CLIP_MTX.lock().expect("clipboard mutex poisoned");
    let _clip = Clipboard::new_attempts(10).context("open clipboard")?;
    formats::FileList
        .write_clipboard(files)
        .map_err(|e| anyhow::anyhow!("write CF_HDROP: {e}"))
}

/// Read the file list currently on the clipboard (empty when none).
pub fn get_files() -> anyhow::Result<Vec<String>> {
    use clipboard_win::{Clipboard, Getter, formats};
    let _guard = CLIP_MTX.lock().expect("clipboard mutex poisoned");
    let _clip = Clipboard::new_attempts(10).context("open clipboard")?;
    let mut out: Vec<String> = Vec::new();
    formats::FileList
        .read_clipboard(&mut out)
        .map_err(|e| anyhow::anyhow!("read CF_HDROP: {e}"))?;
    Ok(out)
}
