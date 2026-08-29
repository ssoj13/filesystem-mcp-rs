//! Window enumeration, targeting and focus (Windows).
//!
//! Enumeration runs top-to-bottom in z-order (EnumWindows order), which becomes
//! our `z` field. `id` is the HWND (xcap parity: `Window::id() == hwnd`).

use windows::core::BOOL;
use windows::Win32::Foundation::{CloseHandle, HWND, LPARAM, RECT, WPARAM};
use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, SendInput, VK_MENU,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetForegroundWindow, GetSystemMetrics, GetWindowRect, GetWindowTextW,
    GetWindowThreadProcessId, IsIconic, IsWindow, IsWindowVisible, IsZoomed,
    MoveWindow, PostMessageW, SetForegroundWindow, SetWindowPos, ShowWindow,
    SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    SW_MAXIMIZE, SW_MINIMIZE, SW_RESTORE, SWP_NOACTIVATE, SWP_NOZORDER, WM_CLOSE,
};

pub use super::driver::{LayoutEntry, WinInfo, WinQuery, WinTarget};
use super::safety::CtlError;

/// Virtual screen metrics: (x, y, width, height) in physical pixels.
pub fn virtual_screen() -> (i32, i32, i32, i32) {
    // SAFETY: pure queries, no invariants.
    unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    }
}

/// Window title (lossy UTF-16, empty when unavailable).
pub fn win_title(hwnd: HWND) -> String {
    let mut buf = [0u16; 512];
    let n = unsafe { GetWindowTextW(hwnd, &mut buf) };
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

/// Executable file name owning `pid` (empty when access is denied — e.g.
/// elevated processes; logged, never silent).
pub fn win_exe(pid: u32) -> String {
    // SAFETY: handle is closed below on every path.
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            tracing::warn!("OpenProcess({pid}) denied; exe unknown");
            return String::new();
        };
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            h,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
        );
        if let Err(e) = CloseHandle(h) {
            tracing::warn!("CloseHandle: {e}");
        }
        if ok.is_err() || len == 0 {
            return String::new();
        }
        let full = String::from_utf16_lossy(&buf[..len as usize]);
        std::path::Path::new(&full)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

unsafe extern "system" fn enum_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let out = unsafe { &mut *(lparam.0 as *mut Vec<HWND>) };
    out.push(hwnd);
    true.into()
}

/// All top-level HWNDs in z-order (front first).
fn hwnds() -> anyhow::Result<Vec<HWND>> {
    let mut out: Vec<HWND> = Vec::new();
    let lp = LPARAM(&mut out as *mut Vec<HWND> as isize);
    // SAFETY: callback only pushes into our out-vec; outlives the call.
    unsafe { EnumWindows(Some(enum_cb), lp)? };
    Ok(out)
}

/// DWM cloaked check (UWP ghosts). DWM error = not cloaked.
fn is_cloaked(hwnd: HWND) -> bool {
    let mut flag: u32 = 0;
    // SAFETY: correctly sized out-buffer for a u32 attribute.
    unsafe {
        DwmGetWindowAttribute(
            hwnd,
            DWMWA_CLOAKED,
            &mut flag as *mut u32 as *mut core::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
        )
        .is_ok_and(|_| flag != 0)
    }
}
fn info_of(hwnd: HWND, z: i32) -> WinInfo {
    let mut pid = 0u32;
    // SAFETY: valid out-pointer for the pid.
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    let mut rect = RECT::default();
    // GetWindowRect can fail on a dying window; zero rect beats aborting the listing.
    if unsafe { GetWindowRect(hwnd, &mut rect) }.is_err() {
        rect = RECT::default();
    }
    WinInfo {
        id: hwnd.0 as u32,
        title: win_title(hwnd),
        exe: win_exe(pid),
        pid,
        x: rect.left,
        y: rect.top,
        w: rect.right - rect.left,
        h: rect.bottom - rect.top,
        z,
        active: unsafe { GetForegroundWindow() } == hwnd,
        minimized: unsafe { IsIconic(hwnd) }.as_bool(),
        maximized: unsafe { IsZoomed(hwnd) }.as_bool(),
    }
}

/// Visible top-level windows, optionally filtered (case-insensitive substrings).
pub fn list_windows(query: Option<WinQuery>) -> anyhow::Result<Vec<WinInfo>> {
    let q = query.unwrap_or_default();
    let ci = |hay: &str, needle: &Option<String>| {
        needle.as_ref().is_none_or(|n| hay.to_lowercase().contains(&n.to_lowercase()))
    };
    let mut out = Vec::new();
    for (z, hwnd) in hwnds()?.into_iter().enumerate() {
        // SAFETY: plain window queries.
        unsafe {
            if !IsWindow(Some(hwnd)).as_bool() || !IsWindowVisible(hwnd).as_bool() || is_cloaked(hwnd) {
                continue;
            }
        }
        let info = info_of(hwnd, z as i32);
        if info.title.is_empty() {
            continue;
        }
        if !ci(&info.title, &q.title) || !ci(&info.exe, &q.exe) {
            continue;
        }
        out.push(info);
    }
    Ok(out)
}

/// Resolve a [`WinTarget`] to exactly one HWND; ambiguity or zero hits is an
/// explicit [`CtlError::NoMatch`] (never "first match wins").
pub fn resolve_target(target: &WinTarget) -> anyhow::Result<HWND> {
    let wins = list_windows(None)?;
    let hit = |w: &WinInfo| match target {
        WinTarget::Id { id } => w.id == *id,
        WinTarget::Title { title } => w.title.to_lowercase().contains(&title.to_lowercase()),
        WinTarget::Exe { exe } => w.exe.to_lowercase().contains(&exe.to_lowercase()),
    };
    let matches: Vec<&WinInfo> = wins.iter().filter(|w| hit(w)).collect();
    match matches.len() {
        1 => Ok(HWND(matches[0].id as usize as *mut core::ffi::c_void)),
        0 => Err(anyhow::Error::new(CtlError::NoMatch {
            reason: format!("no visible window matches {target:?}"),
        })),
        n => {
            let names: Vec<String> = matches
                .iter()
                .take(5)
                .map(|w| format!("{}({})", w.title, w.exe))
                .collect();
            Err(anyhow::Error::new(CtlError::NoMatch {
                reason: format!("{n} windows match {target:?}: {}", names.join(", ")),
            }))
        }
    }
}

fn alt_input(up: bool) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VK_MENU,
                wScan: 0,
                dwFlags: if up { KEYEVENTF_KEYUP } else { Default::default() },
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn send(batch: &mut [INPUT]) {
    // SAFETY: SendInput with correct struct size; partial delivery is checked by callers.
    unsafe { SendInput(batch, std::mem::size_of::<INPUT>() as i32) };
}

fn foreground_is(hwnd: HWND) -> bool {
    let fg = unsafe { GetForegroundWindow() };
    fg == hwnd
}

/// Bring `hwnd` to the foreground and VERIFY it (PLAN2.md §6.1).
/// Chain: restore-if-minimized → plain SetForegroundWindow → ALT-key trick.
/// Both failure paths are loud ([`CtlError::FocusFailed`]); no silent fallback.
pub fn focus_window(hwnd: HWND) -> anyhow::Result<()> {
    if unsafe { IsIconic(hwnd) }.as_bool() {
        let shown = unsafe { ShowWindow(hwnd, SW_RESTORE) };
        if !shown.as_bool() {
            tracing::debug!("ShowWindow(SW_RESTORE) returned false for {hwnd:?}");
        }
    }
    // SAFETY: plain window ops.
    let raised = unsafe { SetForegroundWindow(hwnd) };
    if !raised.as_bool() {
        tracing::debug!("SetForegroundWindow declined (expected: foreground lock)");
    }
    for _ in 0..5 {
        if foreground_is(hwnd) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // Foreground-lock workaround: a synthetic ALT press grants our thread
    // foreground rights (SetForegroundWindow contract, Win8+).
    let mut batch = [alt_input(false), alt_input(true)];
    send(&mut batch);
    let raised2 = unsafe { SetForegroundWindow(hwnd) };
    if !raised2.as_bool() {
        tracing::debug!("SetForegroundWindow declined after ALT-trick");
    }
    for _ in 0..10 {
        if foreground_is(hwnd) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(anyhow::Error::new(CtlError::FocusFailed { hwnd: hwnd.0 as u32 }))
}

/// Currently focused window (None on the rare empty foreground).
/// Used by the canary test; kept as part of the extractable module API.
#[cfg_attr(not(test), allow(dead_code))]
pub fn active() -> anyhow::Result<Option<WinInfo>> {
    let hwnd = unsafe { GetForegroundWindow() };
    if hwnd.0.is_null() {
        return Ok(None);
    }
    Ok(Some(info_of(hwnd, 0)))
}

/// Move a window fully onto monitor `idx` (top-left corner at the monitor's
/// origin, sized to the monitor) and return fresh geometry. Useful after
/// monitor changes or for multi-monitor layouts.
pub fn to_monitor(hwnd: HWND, monitor: u32) -> anyhow::Result<WinInfo> {
    let ms = super::capture::monitors()?;
    let m = ms
        .get(monitor as usize)
        .ok_or_else(|| anyhow::anyhow!("monitor {monitor} not found (0..={})", ms.len() - 1))?;
    // Restore first: a maximized window ignores MoveWindow geometry.
    if unsafe { IsIconic(hwnd) }.as_bool() {
        let shown = unsafe { ShowWindow(hwnd, SW_RESTORE) };
        if !shown.as_bool() {
            tracing::debug!("ShowWindow(SW_RESTORE) returned false for {hwnd:?}");
        }
    }
    unsafe { MoveWindow(hwnd, m.x, m.y, m.w as i32, m.h as i32, true) }
        .map_err(|e| anyhow::anyhow!("MoveWindow({hwnd:?} -> monitor {monitor}): {e}"))?;
    Ok(info_of(hwnd, 0))
}

/// Move/resize and/or set window state (`min` | `max` | `restore`).
/// State applies first, then geometry (all four of x/y/w/h must be given).
/// Returns fresh geometry after the operation.
pub fn geom(
    hwnd: HWND,
    x: Option<i32>,
    y: Option<i32>,
    w: Option<i32>,
    h: Option<i32>,
    state: Option<&str>,
) -> anyhow::Result<WinInfo> {
    let sw = match state {
        Some("min") => Some(SW_MINIMIZE),
        Some("max") => Some(SW_MAXIMIZE),
        Some("restore") => Some(SW_RESTORE),
        Some(other) => return Err(anyhow::anyhow!("unknown state {other:?} (min|max|restore)")),
        None => None,
    };
    if let Some(cmd) = sw {
        let shown = unsafe { ShowWindow(hwnd, cmd) };
        if !shown.as_bool() {
            tracing::debug!("ShowWindow({state:?}) returned false for {hwnd:?}");
        }
    }
    if let (Some(x), Some(y), Some(w), Some(h)) = (x, y, w, h) {
        // MoveWindow returns Result<()> in windows 0.62.
        unsafe { MoveWindow(hwnd, x, y, w, h, true) }
            .map_err(|e| anyhow::anyhow!("MoveWindow({hwnd:?}): {e}"))?;
    }
    Ok(info_of(hwnd, 0))
}

/// Graceful close: post WM_CLOSE, then VERIFY the window is gone within 1 s.
/// Still alive -> loud error (no force-kill here; that is run_command territory).
pub fn close(hwnd: HWND) -> anyhow::Result<()> {
    // SAFETY: plain message post (Option<HWND> per windows 0.62).
    unsafe { PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)) }
        .map_err(|e| anyhow::anyhow!("PostMessageW(WM_CLOSE): {e}"))?;
    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if !unsafe { IsWindow(Some(hwnd)) }.as_bool() {
            return Ok(());
        }
    }
    Err(anyhow::anyhow!(
        "window {} still alive after WM_CLOSE (app may show a save prompt)",
        hwnd.0 as u32
    ))
}

/// Snapshot every visible top-level window into `<data>/computer-mcp-rs/layouts/<name>.json`.
pub fn layout_save(name: &str) -> anyhow::Result<Vec<LayoutEntry>> {
    let entries: Vec<LayoutEntry> = list_windows(None)?
        .into_iter()
        .filter(|w| w.w > 0 && w.h > 0)
        .map(|w| LayoutEntry { id: w.id, title: w.title, exe: w.exe, x: w.x, y: w.y, w: w.w, h: w.h })
        .collect();
    let path = layout_path(name)?;
    let json = serde_json::to_string_pretty(&entries)?;
    std::fs::write(&path, json)?;
    Ok(entries)
}

/// Restore a layout by window id. `dry_run` reports what WOULD move without
/// touching anything. Ids are HWND-bound: windows reopened since the save keep
/// their id only by luck — the response lists applied/skipped so the agent sees it.
pub fn layout_load(name: &str, dry_run: bool) -> anyhow::Result<Vec<(LayoutEntry, bool)>> {
    let raw = std::fs::read_to_string(layout_path(name)?)?;
    let entries: Vec<LayoutEntry> = serde_json::from_str(&raw)?;
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        if dry_run {
            out.push((e, false));
            continue;
        }
        let hwnd = HWND(e.id as usize as *mut core::ffi::c_void);
        if !unsafe { IsWindow(Some(hwnd)) }.as_bool() {
            out.push((e, false));
            continue;
        }
        let placed = unsafe {
            SetWindowPos(hwnd, None, e.x, e.y, e.w, e.h, SWP_NOZORDER | SWP_NOACTIVATE)
        };
        out.push((e, placed.is_ok()));
    }
    Ok(out)
}

fn layout_path(name: &str) -> anyhow::Result<std::path::PathBuf> {
    let safe: String = name.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
    if safe.is_empty() {
        return Err(anyhow::anyhow!("layout name must be alphanumeric"));
    }
    let dir = dirs::data_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("computer-mcp-rs")
        .join("layouts");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{safe}.json")))
}
