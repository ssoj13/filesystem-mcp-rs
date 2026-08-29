//! Platform driver: the OS seam of the computer module.
//!
//! Portable core modules (`safety`, `steps`, `wait`, `find`, `ocrs_local`)
//! call ONLY this layer; each OS backend implements the same function set
//! (module `imp`, selected at compile time). Backend selection:
//!
//! - `win32` (Windows): full parity — SendInput input, HWND window ops,
//!   GDI pixel/color, WinRT OCR + toast, CF_HDROP files.
//! - non-Windows v1: real implementations where the portable stack reaches
//!   (window listing/capture via xcap, color via 1×1 capture, OCR via ocrs)
//!   and LOUD `unsupported` errors everywhere else — never silent fallbacks.
//!
//! Platform-neutral types live HERE so every backend and the core share one
//! definition (window id = u32; HWND on Windows, opaque elsewhere).

/// Modifier keys, platform-neutral (wire + macro steps use these names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum KeyMod {
    Ctrl,
    Alt,
    Shift,
    Win,
}

/// Parse modifier names (loud error on unknown, never silent).
pub fn parse_keymods(mods: Option<&[String]>) -> anyhow::Result<Vec<KeyMod>> {
    let Some(names) = mods else {
        return Ok(Vec::new());
    };
    names
        .iter()
        .map(|n| match n.trim().to_ascii_lowercase().as_str() {
            "ctrl" | "control" => Ok(KeyMod::Ctrl),
            "alt" => Ok(KeyMod::Alt),
            "shift" => Ok(KeyMod::Shift),
            "win" | "meta" => Ok(KeyMod::Win),
            other => Err(anyhow::anyhow!("unknown modifier {other:?} (ctrl|alt|shift|win)")),
        })
        .collect()
}

/// Mouse button.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Btn {
    Left,
    Right,
    Middle,
}

/// Drag trajectory easing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Ease {
    Linear,
    Out,
}

/// Focus snapshot returned with input actions (hwnd = platform window id:
/// HWND on Windows, opaque elsewhere).
#[derive(Debug, Clone, serde::Serialize)]
pub struct FocusInfo {
    pub hwnd: u32,
    pub title: String,
}

/// Result of typing: which path ran, clipboard outcome, post-type focus.
#[derive(Debug, serde::Serialize)]
pub struct TypeResult {
    pub mode: &'static str,
    pub chars: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clipboard_restored: Option<bool>,
    pub focus: FocusInfo,
}

/// One visible top-level window (agent-facing shape).
#[derive(Debug, Clone, serde::Serialize)]
pub struct WinInfo {
    pub id: u32,
    pub title: String,
    pub exe: String,
    pub pid: u32,
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub z: i32,
    pub active: bool,
    pub minimized: bool,
    pub maximized: bool,
}

/// Window filter (case-insensitive substrings).
#[derive(Debug, Clone, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct WinQuery {
    pub title: Option<String>,
    pub exe: Option<String>,
}

/// How to address a window: {"id":n} | {"title":s} | {"exe":s}.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum WinTarget {
    Id { id: u32 },
    Title { title: String },
    Exe { exe: String },
}

/// Saved window position (layout snapshot entry; portable shape).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LayoutEntry {
    pub id: u32,
    pub title: String,
    pub exe: String,
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// Capability groups the active backend provides. Agents can check this
/// instead of tripping `unsupported` errors.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Caps {
    pub input: bool,
    pub window: bool,
    pub uia: bool,
    pub ocr_media: bool,
    pub clip_files: bool,
    pub notify: bool,
    /// Capture/monitors/color — portable via xcap on all OSes.
    pub capture: bool,
    /// ocrs engine — pure Rust, all OSes.
    pub ocr_ocrs: bool,
}

#[cfg(windows)]
pub const CAPS: Caps = Caps {
    input: true,
    window: true,
    uia: true,
    ocr_media: true,
    clip_files: true,
    notify: true,
    capture: true,
    ocr_ocrs: true,
};

#[cfg(not(windows))]
pub const CAPS: Caps = Caps {
    input: false,
    window: false,
    uia: false,
    ocr_media: false,
    clip_files: false,
    notify: false,
    capture: true,
    ocr_ocrs: true,
};

/// Loud, specific unsupported error (never a silent fallback).
/// Used by the non-Windows fallback backend; kept cross-platform.
#[cfg_attr(windows, allow(dead_code))]
pub fn unsupported(what: &str) -> anyhow::Error {
    anyhow::anyhow!("unsupported on this platform: {what}")
}
// ---- Unified backend interface ----------------------------------------------
//
// Both backends implement the same function set; `imp` selects one at
// compile time. Windows delegates to the domain modules (input/win/notify/
// clip); non-Windows gets the portable subset + loud errors.

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::tools::computer::safety::SafetyGate;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Input::KeyboardAndMouse::VIRTUAL_KEY;

    pub(crate) fn hwnd(id: u32) -> HWND {
        HWND(id as usize as *mut core::ffi::c_void)
    }

    pub fn move_cursor(x: i32, y: i32) -> anyhow::Result<FocusInfo> {
        super::super::input::move_cursor(x, y)
    }

    pub fn click(
        gate: &SafetyGate,
        x: Option<i32>,
        y: Option<i32>,
        btn: Btn,
        clicks: u32,
        mods: &[KeyMod],
    ) -> anyhow::Result<FocusInfo> {
        // KeyMod -> VK codes: win32-specific mapping lives in the backend.
        let vks: Vec<VIRTUAL_KEY> = mods
            .iter()
            .map(|m| match m {
                KeyMod::Ctrl => VIRTUAL_KEY(0x11),
                KeyMod::Alt => VIRTUAL_KEY(0x12),
                KeyMod::Shift => VIRTUAL_KEY(0x10),
                KeyMod::Win => VIRTUAL_KEY(0x5B),
            })
            .collect();
        super::super::input::click(gate, x, y, btn, clicks, &vks)
    }

    pub fn drag(
        gate: &SafetyGate,
        from: (i32, i32),
        to: (i32, i32),
        btn: Btn,
        duration_ms: u32,
        ease: Ease,
        hold_ms: u32,
    ) -> anyhow::Result<FocusInfo> {
        super::super::input::drag(gate, from, to, btn, duration_ms, ease, hold_ms)
    }

    pub fn scroll(gate: &SafetyGate, dy: i32, dx: i32) -> anyhow::Result<FocusInfo> {
        super::super::input::scroll(gate, dy, dx)
    }

    pub fn color_at(x: i32, y: i32) -> anyhow::Result<(u8, u8, u8)> {
        super::super::input::color_at(x, y)
    }

    pub fn key_tap(gate: &SafetyGate, combo: &str, hold_ms: u32) -> anyhow::Result<FocusInfo> {
        super::super::input::key_tap(gate, combo, hold_ms)
    }

    pub fn type_text(
        gate: &SafetyGate,
        text: &str,
        paste: bool,
        interval_ms: u32,
        expect: Option<u32>,
    ) -> anyhow::Result<TypeResult> {
        super::super::input::type_text(gate, text, paste, interval_ms, expect)
    }

    pub fn focus() -> FocusInfo {
        super::super::input::focus()
    }

    pub fn cursor_pos() -> anyhow::Result<(i32, i32)> {
        super::super::input::cursor_pos().ok_or_else(|| unsupported("cursor position query"))
    }

    pub fn list_windows(query: Option<WinQuery>) -> anyhow::Result<Vec<WinInfo>> {
        super::super::win::list_windows(query)
    }

    pub fn resolve_target(target: &WinTarget) -> anyhow::Result<u32> {
        Ok(super::super::win::resolve_target(target)?.0 as u32)
    }

    pub fn focus_window(id: u32) -> anyhow::Result<()> {
        super::super::win::focus_window(hwnd(id))
    }

    /// Foreground window (used by tests; part of the portable surface).
    #[cfg_attr(windows, allow(dead_code))]
    pub fn active() -> anyhow::Result<Option<WinInfo>> {
        super::super::win::active()
    }

    pub fn geom(
        id: u32,
        x: Option<i32>,
        y: Option<i32>,
        w: Option<i32>,
        h: Option<i32>,
        state: Option<&str>,
    ) -> anyhow::Result<WinInfo> {
        super::super::win::geom(hwnd(id), x, y, w, h, state)
    }

    pub fn close_window(id: u32) -> anyhow::Result<()> {
        super::super::win::close(hwnd(id))
    }

    pub fn to_monitor(id: u32, monitor: u32) -> anyhow::Result<WinInfo> {
        super::super::win::to_monitor(hwnd(id), monitor)
    }

    pub fn layout_save(name: &str) -> anyhow::Result<Vec<LayoutEntry>> {
        super::super::win::layout_save(name)
    }

    pub fn layout_load(name: &str, dry_run: bool) -> anyhow::Result<Vec<(LayoutEntry, bool)>> {
        super::super::win::layout_load(name, dry_run)
    }

    pub fn notify(title: Option<&str>, msg: &str) -> anyhow::Result<()> {
        super::super::notify::notify(title, msg)
    }

    pub fn set_files(files: &[String]) -> anyhow::Result<()> {
        super::super::clip::set_files(files)
    }

    pub fn get_files() -> anyhow::Result<Vec<String>> {
        super::super::clip::get_files()
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use crate::tools::computer::safety::SafetyGate;

    pub fn move_cursor(_x: i32, _y: i32) -> anyhow::Result<FocusInfo> {
        Err(unsupported("input injection (mouse move)"))
    }

    pub fn click(
        _gate: &SafetyGate,
        _x: Option<i32>,
        _y: Option<i32>,
        _btn: Btn,
        _clicks: u32,
        _mods: &[KeyMod],
    ) -> anyhow::Result<FocusInfo> {
        Err(unsupported("input injection (click)"))
    }

    pub fn drag(
        _gate: &SafetyGate,
        _from: (i32, i32),
        _to: (i32, i32),
        _btn: Btn,
        _duration_ms: u32,
        _ease: Ease,
        _hold_ms: u32,
    ) -> anyhow::Result<FocusInfo> {
        Err(unsupported("input injection (drag)"))
    }

    pub fn scroll(_gate: &SafetyGate, _dy: i32, _dx: i32) -> anyhow::Result<FocusInfo> {
        Err(unsupported("input injection (scroll)"))
    }

    pub fn key_tap(_gate: &SafetyGate, _combo: &str, _hold_ms: u32) -> anyhow::Result<FocusInfo> {
        Err(unsupported("input injection (keyboard)"))
    }

    pub fn type_text(
        _gate: &SafetyGate,
        _text: &str,
        _paste: bool,
        _interval_ms: u32,
        _expect: Option<u32>,
    ) -> anyhow::Result<TypeResult> {
        Err(unsupported("input injection (typing)"))
    }

    pub fn focus() -> anyhow::Result<FocusInfo> {
        Err(unsupported("foreground window query"))
    }

    pub fn cursor_pos() -> anyhow::Result<(i32, i32)> {
        Err(unsupported("cursor position query"))
    }

    /// Portable window listing via xcap. exe falls back to the app name —
    /// QueryFullProcessImageName is Windows-only; the field stays honest.
    pub fn list_windows(query: Option<WinQuery>) -> anyhow::Result<Vec<WinInfo>> {
        let q = query.unwrap_or_default();
        let wins = xcap::Window::all().map_err(|e| anyhow::anyhow!("enum windows: {e}"))?;
        let fg = wins
            .iter()
            .find(|w| w.is_focused().unwrap_or(false))
            .map(|w| w.id().unwrap_or(0));
        let mut out = Vec::new();
        for (z, w) in wins.into_iter().enumerate() {
            let title = w.title().unwrap_or_default();
            let (x, y) = (w.x().unwrap_or(0), w.y().unwrap_or(0));
            let (w_, h_) = (w.width().unwrap_or(0) as i32, w.height().unwrap_or(0) as i32);
            if title.is_empty() || w_ == 0 || h_ == 0 {
                continue;
            }
            let info = WinInfo {
                id: w.id().unwrap_or(0),
                exe: w.app_name().unwrap_or_default(),
                pid: w.pid().unwrap_or(0),
                x,
                y,
                w: w_,
                h: h_,
                z: z as i32,
                active: fg == Some(w.id().unwrap_or(0)),
                minimized: w.is_minimized().unwrap_or(false),
                maximized: w.is_maximized().unwrap_or(false),
                title,
            };
            let ci = |hay: &str, needle: &Option<String>| {
                needle.as_ref().map_or(true, |n| hay.to_lowercase().contains(&n.to_lowercase()))
            };
            if ci(&info.title, &q.title) && ci(&info.exe, &q.exe) {
                out.push(info);
            }
        }
        Ok(out)
    }

    pub fn resolve_target(target: &WinTarget) -> anyhow::Result<u32> {
        let wins = list_windows(None)?;
        let hit = |w: &WinInfo| match target {
            WinTarget::Id { id } => w.id == *id,
            WinTarget::Title { title } => w.title.to_lowercase().contains(&title.to_lowercase()),
            WinTarget::Exe { exe } => w.exe.to_lowercase().contains(&exe.to_lowercase()),
        };
        let matches: Vec<&WinInfo> = wins.iter().filter(|w| hit(w)).collect();
        match matches.len() {
            1 => Ok(matches[0].id),
            0 => Err(anyhow::Error::new(crate::safety::CtlError::NoMatch {
                reason: format!("no visible window matches {target:?}"),
            })),
            n => Err(anyhow::Error::new(crate::safety::CtlError::NoMatch {
                reason: format!("{n} windows match {target:?}"),
            })),
        }
    }

    pub fn focus_window(_id: u32) -> anyhow::Result<()> {
        Err(unsupported("window focus"))
    }

    pub fn active() -> anyhow::Result<Option<WinInfo>> {
        Ok(list_windows(None)?.into_iter().find(|w| w.active))
    }

    pub fn geom(
        _id: u32,
        _x: Option<i32>,
        _y: Option<i32>,
        _w: Option<i32>,
        _h: Option<i32>,
        _state: Option<&str>,
    ) -> anyhow::Result<WinInfo> {
        Err(unsupported("window geometry"))
    }

    pub fn close_window(_id: u32) -> anyhow::Result<()> {
        Err(unsupported("window close"))
    }

    pub fn to_monitor(_id: u32, _monitor: u32) -> anyhow::Result<WinInfo> {
        Err(unsupported("window to-monitor"))
    }

    pub fn layout_save(_name: &str) -> anyhow::Result<Vec<LayoutEntry>> {
        Err(unsupported("window layout save"))
    }

    pub fn layout_load(_name: &str, _dry_run: bool) -> anyhow::Result<Vec<(LayoutEntry, bool)>> {
        Err(unsupported("window layout load"))
    }

    pub fn notify(_title: Option<&str>, _msg: &str) -> anyhow::Result<()> {
        Err(unsupported("toast notifications"))
    }

    pub fn set_files(_files: &[String]) -> anyhow::Result<()> {
        Err(unsupported("clipboard file lists"))
    }

    pub fn get_files() -> anyhow::Result<Vec<String>> {
        Err(unsupported("clipboard file lists"))
    }
}

pub use imp::*;
