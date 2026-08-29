//! Waits: screen-change / window / clipboard-change polls with timeout
//! (PLAN2.md §3 `wait`) — replaces sleep-polling in agent loops.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows::Win32::System::DataExchange::GetClipboardSequenceNumber;

use super::capture::{self, CapTarget, hash_dist, default_cursor_size};
use super::driver;
use super::win::WinQuery;

/// Default dhash distance for "screen changed" (§6.6).
const CHANGE_EPS: u32 = 6;

/// What to wait for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    ScreenChange,
    Window,
    Clipboard,
    /// Pixel at (x, y) reaches the target RGB within tolerance.
    Color,
}

/// Pixel-color target for [`Kind::Color`].
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct ColorTarget {
    pub x: i32,
    pub y: i32,
    pub r: u8,
    pub g: u8,
    pub b: u8,
    /// Max per-channel delta (default 12).
    #[serde(default = "default_color_tol")]
    pub tol: u8,
}

fn default_color_tol() -> u8 {
    12
}

/// Wait outcome.
#[derive(Debug, Serialize)]
pub struct WaitResult {
    pub ok: bool,
    /// ScreenChange: current hash. Window: matched window count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wins: Option<u32>,
    /// Color: the pixel color actually observed when the wait succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rgb: Option<(u8, u8, u8)>,
}

/// Poll for a condition. Blocks — call from spawn_blocking.
#[allow(clippy::too_many_arguments)]
pub fn wait(
    kind: Kind,
    win_query: Option<WinQuery>,
    cap_target: Option<CapTarget>,
    since: Option<u64>,
    color: Option<ColorTarget>,
    timeout_ms: u32,
    poll_ms: u32,
) -> anyhow::Result<WaitResult> {
    let deadline = Duration::from_millis(timeout_ms as u64);
    let poll = Duration::from_millis(poll_ms.max(50) as u64);
    let started = Instant::now();
    match kind {
        Kind::ScreenChange => {
            let cap = cap_target.unwrap_or(CapTarget::Cursor { size: default_cursor_size() });
            let baseline = match since {
                Some(h) => h,
                None => capture::capture(cap.clone())?.hash,
            };
            loop {
                if started.elapsed() > deadline {
                    return Ok(WaitResult { ok: false, hash: None, wins: None, rgb: None });
                }
                std::thread::sleep(poll);
                let now = capture::capture(cap.clone())?.hash;
                if hash_dist(baseline, now) > CHANGE_EPS {
                    return Ok(WaitResult { ok: true, hash: Some(now), wins: None, rgb: None });
                }
            }
        }
        Kind::Window => {
            let q = win_query.clone().unwrap_or_default();
            loop {
                if started.elapsed() > deadline {
                    return Ok(WaitResult { ok: false, hash: None, wins: None, rgb: None });
                }
                std::thread::sleep(poll);
                let wins = driver::list_windows(Some(q.clone()))?;
                if !wins.is_empty() {
                    return Ok(WaitResult { ok: true, hash: None, wins: Some(wins.len() as u32), rgb: None });
                }
            }
        }
        Kind::Clipboard => {
            let base = clipboard_seq();
            loop {
                if started.elapsed() > deadline {
                    return Ok(WaitResult { ok: false, hash: None, wins: None, rgb: None });
                }
                std::thread::sleep(poll);
                if clipboard_seq() != base {
                    return Ok(WaitResult { ok: true, hash: None, wins: None, rgb: None });
                }
            }
        }
        Kind::Color => {
            let t = color.ok_or_else(|| anyhow::anyhow!("kind=color requires x,y,r,g,b"))?;
            let near = |c: (u8, u8, u8)| {
                (c.0.abs_diff(t.r) <= t.tol)
                    && (c.1.abs_diff(t.g) <= t.tol)
                    && (c.2.abs_diff(t.b) <= t.tol)
            };
            loop {
                if started.elapsed() > deadline {
                    return Ok(WaitResult { ok: false, hash: None, wins: None, rgb: None });
                }
                let c = super::driver::color_at(t.x, t.y)?;
                if near(c) {
                    return Ok(WaitResult { ok: true, hash: None, wins: None, rgb: Some(c) });
                }
                std::thread::sleep(poll);
            }
        }
    }
}

/// Clipboard change counter (cheap; no clipboard open needed).
fn clipboard_seq() -> u32 {
    // SAFETY: pure query.
    unsafe { GetClipboardSequenceNumber() }
}
