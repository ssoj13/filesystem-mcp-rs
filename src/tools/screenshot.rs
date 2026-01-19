//! Screenshot capture and clipboard helpers (xcap + arboard).

use std::borrow::Cow;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use arboard::{Clipboard, ImageData};
use image::RgbaImage;
use serde::Serialize;
use xcap::{Monitor, Window};

/// Monitor information for MCP response.
#[derive(Debug, Clone, Serialize)]
pub struct MonitorInfo {
    pub id: u32,
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub is_primary: bool,
    pub scale_factor: f32,
}

/// Window information for MCP response.
#[derive(Debug, Clone, Serialize)]
pub struct WindowInfo {
    pub id: u32,
    pub title: String,
    pub app_name: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub is_minimized: bool,
}

/// Get all available monitors.
pub fn list_monitors() -> Result<Vec<MonitorInfo>> {
    let monitors = Monitor::all().context("Failed to enumerate monitors")?;

    let infos: Vec<MonitorInfo> = monitors
        .into_iter()
        .enumerate()
        .map(|(idx, m)| MonitorInfo {
            id: idx as u32,
            name: m.name().unwrap_or_else(|_| format!("Display {}", idx)),
            x: m.x().unwrap_or(0),
            y: m.y().unwrap_or(0),
            width: m.width().unwrap_or(0),
            height: m.height().unwrap_or(0),
            is_primary: m.is_primary().unwrap_or(false),
            scale_factor: m.scale_factor().unwrap_or(1.0),
        })
        .collect();

    Ok(infos)
}

/// Get all visible windows.
pub fn list_windows() -> Result<Vec<WindowInfo>> {
    let windows = Window::all().context("Failed to enumerate windows")?;

    let infos: Vec<WindowInfo> = windows
        .into_iter()
        .filter(|w| {
            let title = w.title().unwrap_or_default();
            let width = w.width().unwrap_or(0);
            let height = w.height().unwrap_or(0);
            !title.is_empty() && width > 0 && height > 0
        })
        .map(|w| WindowInfo {
            id: w.id().unwrap_or(0),
            title: w.title().unwrap_or_default(),
            app_name: w.app_name().unwrap_or_default(),
            x: w.x().unwrap_or(0),
            y: w.y().unwrap_or(0),
            width: w.width().unwrap_or(0),
            height: w.height().unwrap_or(0),
            is_minimized: w.is_minimized().unwrap_or(false),
        })
        .collect();

    Ok(infos)
}

fn get_monitor(id: Option<u32>) -> Result<Monitor> {
    let monitors = Monitor::all().context("Failed to enumerate monitors")?;
    if monitors.is_empty() {
        return Err(anyhow!("No monitors found"));
    }

    match id {
        Some(idx) => monitors
            .into_iter()
            .nth(idx as usize)
            .ok_or_else(|| anyhow!("Monitor {} not found", idx)),
        None => monitors
            .iter()
            .find(|m| m.is_primary().unwrap_or(false))
            .cloned()
            .or_else(|| monitors.into_iter().next())
            .ok_or_else(|| anyhow!("No primary monitor found")),
    }
}

/// Capture entire monitor.
pub fn capture_monitor(monitor_id: Option<u32>) -> Result<RgbaImage> {
    let monitor = get_monitor(monitor_id)?;
    monitor.capture_image().context("Failed to capture monitor")
}

/// Capture region of monitor by capturing full screen and cropping.
pub fn capture_region(
    monitor_id: Option<u32>,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
) -> Result<RgbaImage> {
    let monitor = get_monitor(monitor_id)?;

    let mon_width = monitor.width().unwrap_or(0);
    let mon_height = monitor.height().unwrap_or(0);

    if x < 0 || y < 0 {
        return Err(anyhow!("Region coordinates must be non-negative"));
    }
    if width == 0 || height == 0 {
        return Err(anyhow!("Region dimensions must be positive"));
    }
    if (x as u32 + width) > mon_width || (y as u32 + height) > mon_height {
        return Err(anyhow!(
            "Region {}x{}+{}+{} exceeds monitor bounds {}x{}",
            width,
            height,
            x,
            y,
            mon_width,
            mon_height
        ));
    }

    let full_image = monitor.capture_image().context("Failed to capture monitor")?;
    let cropped = image::imageops::crop_imm(&full_image, x as u32, y as u32, width, height).to_image();
    Ok(cropped)
}

/// Capture window by ID.
pub fn capture_window_by_id(window_id: u32) -> Result<RgbaImage> {
    let windows = Window::all().context("Failed to enumerate windows")?;

    let window = windows
        .into_iter()
        .find(|w| w.id().unwrap_or(0) == window_id)
        .ok_or_else(|| anyhow!("Window with ID {} not found", window_id))?;

    window.capture_image().context("Failed to capture window")
}

/// Capture window by title (partial match, case-insensitive).
pub fn capture_window_by_title(title: &str) -> Result<RgbaImage> {
    let windows = Window::all().context("Failed to enumerate windows")?;
    let title_lower = title.to_lowercase();

    let window = windows
        .into_iter()
        .find(|w| {
            w.title()
                .unwrap_or_default()
                .to_lowercase()
                .contains(&title_lower)
        })
        .ok_or_else(|| anyhow!("Window with title containing '{}' not found", title))?;

    window.capture_image().context("Failed to capture window")
}

/// Save image to PNG file.
pub fn save_png(image: &RgbaImage, path: &Path) -> Result<()> {
    image.save(path).context("Failed to save PNG")?;
    Ok(())
}

/// Encode image to base64 PNG.
pub fn to_base64(image: &RgbaImage) -> Result<String> {
    use base64::Engine;
    use image::ImageEncoder;
    use std::io::Cursor;

    let mut buf = Cursor::new(Vec::new());
    image::codecs::png::PngEncoder::new(&mut buf)
        .write_image(
            image.as_raw(),
            image.width(),
            image.height(),
            image::ExtendedColorType::Rgba8,
        )
        .context("Failed to encode PNG")?;

    Ok(base64::engine::general_purpose::STANDARD.encode(buf.into_inner()))
}

/// Copy RgbaImage to system clipboard.
pub fn copy_image(image: &RgbaImage) -> Result<()> {
    let mut clipboard = Clipboard::new().context("Failed to access clipboard")?;
    let img_data = ImageData {
        width: image.width() as usize,
        height: image.height() as usize,
        bytes: Cow::Borrowed(image.as_raw()),
    };
    clipboard
        .set_image(img_data)
        .context("Failed to copy image to clipboard")?;
    Ok(())
}

/// Load PNG from file and copy to clipboard.
pub fn copy_file(path: &Path) -> Result<()> {
    let image = image::open(path)
        .context("Failed to open image file")?
        .to_rgba8();
    copy_image(&image)
}
