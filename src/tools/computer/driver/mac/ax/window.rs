//! Window-level AX operations keyed by CGWindowList metadata.

use super::{require_trusted, resolve_window, Element};
use crate::tools::computer::driver::mac::win::WindowMeta;

/// Bring the application frontmost and raise the matched AX window.
pub fn focus(meta: &WindowMeta) -> anyhow::Result<()> {
    require_trusted()?;
    let app = Element::application(meta.pid)?;
    app.set_bool("AXFrontmost", true)?;
    let win = resolve_window(meta)?;
    win.set_bool("AXMain", true)?;
    win.perform("AXRaise")?;
    Ok(())
}

pub fn set_minimized(meta: &WindowMeta, min: bool) -> anyhow::Result<()> {
    let win = resolve_window(meta)?;
    win.set_bool("AXMinimized", min)
}

pub fn set_frame(meta: &WindowMeta, x: i32, y: i32, w: i32, h: i32) -> anyhow::Result<()> {
    let win = resolve_window(meta)?;
    win.set_position(x, y)?;
    win.set_size(w, h)
}

/// macOS zoom (green button) — the platform maximize analogue.
pub fn zoom(meta: &WindowMeta) -> anyhow::Result<()> {
    let win = resolve_window(meta)?;
    let btn = win.child("AXZoomButton")?;
    btn.perform("AXPress")
}

pub fn close(meta: &WindowMeta) -> anyhow::Result<()> {
    let win = resolve_window(meta)?;
    let btn = win.child("AXCloseButton")?;
    btn.perform("AXPress")
}

pub fn is_minimized(meta: &WindowMeta) -> anyhow::Result<bool> {
    Ok(resolve_window(meta)?.minimized())
}
