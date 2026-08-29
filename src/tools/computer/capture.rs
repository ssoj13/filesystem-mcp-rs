//! Screen capture (xcap) with cursor/monitor/window/rect targets + dhash.
//!
//! Coordinates are virtual-screen physical pixels with NEGATIVE origins
//! supported (PLAN2.md critic §10.5): we locate the monitor containing the
//! rect's center, capture that monitor and crop with validated offsets —
//! never a silent clamp. Results go to disk; inline base64 is opt-in at the
//! srv layer (token economy, §2).

use image::RgbaImage;
use serde::Serialize;
use xcap::Monitor;

use super::Rect;
use super::win;

/// Monitor info (agent-facing shape).
#[derive(Debug, Clone, Serialize)]
pub struct MonInfo {
    pub id: u32,
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
    pub primary: bool,
    pub scale: f32,
}

/// Capture target (PLAN2.md §3 `capture`). `Cursor` is a square of `size` px
/// centered on the cursor — the "look where I am" probe. Untagged serde type:
/// the MCP layer, macro steps and wait all reuse it directly (dedup).
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum CapTarget {
    Monitor { monitor: u32 },
    Win { win: u32 },
    Rect { x: i32, y: i32, w: u32, h: u32 },
    Cursor { size: u32 },
}

/// Default cursor-square side (PLAN2.md §3).
pub fn default_cursor_size() -> u32 {
    400
}

/// Capture outcome: PNG path, content hash, captured rect.
#[derive(Debug, Clone, Serialize)]
pub struct CapResult {
    pub path: String,
    pub hash: u64,
    pub rect: Rect,
}

/// List monitors.
pub fn monitors() -> anyhow::Result<Vec<MonInfo>> {
    let all = Monitor::all().map_err(|e| anyhow::anyhow!("enumerate monitors: {e}"))?;
    let mut out = Vec::with_capacity(all.len());
    for (idx, m) in all.into_iter().enumerate() {
        out.push(MonInfo {
            id: idx as u32,
            name: m.name().unwrap_or_else(|_| format!("Display {idx}")),
            x: m.x().unwrap_or(0),
            y: m.y().unwrap_or(0),
            w: m.width().unwrap_or(0),
            h: m.height().unwrap_or(0),
            primary: m.is_primary().unwrap_or(false),
            scale: m.scale_factor().unwrap_or(1.0),
        });
    }
    if out.is_empty() {
        return Err(anyhow::anyhow!("no monitors found"));
    }
    Ok(out)
}

/// Capture `target` to a PNG; returns path + dhash + rect.
pub fn capture(target: CapTarget) -> anyhow::Result<CapResult> {
    if let CapTarget::Win { win: id } = target {
        let wins = xcap::Window::all().map_err(|e| anyhow::anyhow!("enum windows: {e}"))?;
        let w = wins
            .into_iter()
            .find(|w| w.id().unwrap_or(0) == id)
            .ok_or_else(|| anyhow::anyhow!("window {id} not found"))?;
        let img = w.capture_image().map_err(|e| anyhow::anyhow!("capture window: {e}"))?;
        let rect = Rect::new(w.x().unwrap_or(0), w.y().unwrap_or(0), w.width().unwrap_or(0), w.height().unwrap_or(0));
        return save(img, rect);
    }
    // Monitor / Rect / Cursor: resolve a rect, then monitor-crop.
    let (vx, vy, vw, vh) = win::virtual_screen();
    let bounds = Rect::new(vx, vy, vw as u32, vh as u32);
    let wanted = match target {
        CapTarget::Monitor { monitor: idx } => {
            let ms = monitors()?;
            let m = ms.get(idx as usize).ok_or_else(|| anyhow::anyhow!("monitor {idx} not found"))?;
            Rect::new(m.x, m.y, m.w, m.h)
        }
        CapTarget::Rect { x, y, w, h } => Rect::new(x, y, w, h),
        CapTarget::Cursor { size } => {
            let (cx, cy) = cursor()?;
            let half = (size / 2) as i32;
            Rect::new(cx - half, cy - half, size, size)
        }
        CapTarget::Win { .. } => unreachable!("handled above"),
    };
    let rect = wanted
        .clamp_into(&bounds)
        .ok_or_else(|| anyhow::anyhow!("target rect entirely outside virtual screen"))?;
    let mon = monitor_for(&rect)?;
    let img = mon.capture_image().map_err(|e| anyhow::anyhow!("capture monitor: {e}"))?;
    let mx = mon.x().unwrap_or(0);
    let my = mon.y().unwrap_or(0);
    let mw = mon.width().unwrap_or(0);
    let mh = mon.height().unwrap_or(0);
    let ox = (rect.x - mx).max(0) as u32;
    let oy = (rect.y - my).max(0) as u32;
    if ox + rect.w > mw || oy + rect.h > mh {
        return Err(anyhow::anyhow!(
            "rect {rect:?} exceeds monitor {mw}x{mh} at {mx},{my}"
        ));
    }
    let crop = image::imageops::crop_imm(&img, ox, oy, rect.w, rect.h).to_image();
    save(crop, rect)
}

/// Monitor containing the rect's center (primary fallback with explicit error).
fn monitor_for(rect: &Rect) -> anyhow::Result<Monitor> {
    let all = Monitor::all().map_err(|e| anyhow::anyhow!("enumerate monitors: {e}"))?;
    let cx = rect.x + rect.w as i32 / 2;
    let cy = rect.y + rect.h as i32 / 2;
    for m in &all {
        let (x, y) = (m.x().unwrap_or(0), m.y().unwrap_or(0));
        let (w, h) = (m.width().unwrap_or(0) as i32, m.height().unwrap_or(0) as i32);
        if cx >= x && cx < x + w && cy >= y && cy < y + h {
            return Ok(m.clone());
        }
    }
    all.into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no monitor contains rect {rect:?}"))
}

/// Cursor position via the platform driver (real on win32; unsupported
/// elsewhere until a non-Windows cursor backend lands).
fn cursor() -> anyhow::Result<(i32, i32)> {
    super::driver::cursor_pos()
}

fn save(img: RgbaImage, rect: Rect) -> anyhow::Result<CapResult> {
    let dir = std::env::temp_dir().join("computer-mcp-rs");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("capture-{}-{}.png", now_ms(), std::process::id()));
    img.save_with_format(&path, image::ImageFormat::Png)?;
    Ok(CapResult { path: path.display().to_string(), hash: dhash64(&img), rect })
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// 64-bit dhash: 9x8 luma downscale, horizontal gradient per row.
/// Used by `wait_screen_change` (P2) as a cheap change gate (§6.6).
pub fn dhash64(img: &RgbaImage) -> u64 {
    const W: usize = 9;
    const H: usize = 8;
    let small = image::imageops::resize(img, W as u32, H as u32, image::imageops::FilterType::Triangle);
    let luma = |x: usize, y: usize| -> u32 {
        let p = small.get_pixel(x as u32, y as u32).0;
        (p[0] as u32 * 299 + p[1] as u32 * 587 + p[2] as u32 * 114) / 1000
    };
    let mut hash = 0u64;
    for y in 0..H {
        for x in 0..W - 1 {
            hash <<= 1;
            if luma(x, y) > luma(x + 1, y) {
                hash |= 1;
            }
        }
    }
    hash
}

/// Hamming distance between two dhashes; `<= eps` means "same screen" (§6.6).
pub fn hash_dist(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhash_stable_and_sensitive() {
        // Horizontal gradients are the canonical dhash probe:
        // increasing luma -> all bits 0, decreasing -> all bits 1.
        let grad = RgbaImage::from_fn(64, 64, |x, _y| image::Rgba([(x * 4) as u8, (x * 4) as u8, (x * 4) as u8, 255]));
        let inv = RgbaImage::from_fn(64, 64, |x, _y| image::Rgba([(255 - x * 4) as u8, (255 - x * 4) as u8, (255 - x * 4) as u8, 255]));
        assert_eq!(dhash64(&grad), dhash64(&grad));
        assert_ne!(dhash64(&grad), dhash64(&inv));
    }
}
