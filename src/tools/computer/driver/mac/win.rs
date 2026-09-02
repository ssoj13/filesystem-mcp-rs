//! Window enumeration (CGWindowList) and manipulation (AppKit + AX).
//!
//! CGWindowList is the source of stable `u32` ids and coarse geometry.
//! Focus and geometry mutations go through AX after AppKit activation.

use core_foundation::base::{TCFType, ToVoid};
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_graphics::window::{
    copy_window_info, kCGNullWindowID, kCGWindowListExcludeDesktopElements,
    kCGWindowListOptionAll, kCGWindowListOptionOnScreenOnly,
};
use objc2_app_kit::{NSApplicationActivationOptions, NSRunningApplication, NSWorkspace};
use objc2_foundation::NSAutoreleasePool;

use crate::tools::computer::driver::{WinInfo, WinQuery};
use crate::tools::computer::safety::CtlError;

use super::ax;

#[derive(Debug, Clone)]
pub struct WindowMeta {
    pub id: u32,
    pub title: String,
    pub exe: String,
    pub pid: i32,
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub on_screen: bool,
}

fn key(s: &str) -> CFString {
    CFString::new(s)
}

fn cf_num_i32(dict: &CFDictionary, name: &str) -> Option<i32> {
    let v = dict.find(key(name).to_void())?;
    let n = unsafe { CFNumber::wrap_under_get_rule(*v as *const _) };
    n.to_i32()
}

fn cf_num_f64(dict: &CFDictionary, name: &str) -> Option<f64> {
    let v = dict.find(key(name).to_void())?;
    let n = unsafe { CFNumber::wrap_under_get_rule(*v as *const _) };
    n.to_f64()
}

fn cf_str(dict: &CFDictionary, name: &str) -> Option<String> {
    let v = dict.find(key(name).to_void())?;
    Some(unsafe { CFString::wrap_under_get_rule(*v as *const _).to_string() })
}

fn cf_bool(dict: &CFDictionary, name: &str) -> Option<bool> {
    let v = dict.find(key(name).to_void())?;
    Some(*v as usize != 0)
}

fn parse_bounds(dict: &CFDictionary) -> Option<(i32, i32, i32, i32)> {
    let bounds_ptr = dict.find(key("kCGWindowBounds").to_void())?;
    let b = unsafe { CFDictionary::wrap_under_get_rule(*bounds_ptr as *const _) };
    Some((
        cf_num_f64(&b, "X")? as i32,
        cf_num_f64(&b, "Y")? as i32,
        cf_num_f64(&b, "Width")? as i32,
        cf_num_f64(&b, "Height")? as i32,
    ))
}

fn parse_window(dict: &CFDictionary) -> Option<WindowMeta> {
    let layer = cf_num_i32(dict, "kCGWindowLayer")?;
    if layer != 0 {
        return None;
    }
    let id = cf_num_i32(dict, "kCGWindowNumber")? as u32;
    let pid = cf_num_i32(dict, "kCGWindowOwnerPID")?;
    let owner = cf_str(dict, "kCGWindowOwnerName").unwrap_or_default();
    let name = cf_str(dict, "kCGWindowName").unwrap_or_default();
    let mut title = if name.is_empty() { owner.clone() } else { name };
    if title.is_empty() {
        title = format!("window-{id}");
    }
    let (x, y, w, h) = parse_bounds(dict)?;
    if w <= 0 || h <= 0 {
        return None;
    }
    let on_screen = cf_bool(dict, "kCGWindowIsOnscreen").unwrap_or(true);
    Some(WindowMeta { id, title, exe: owner, pid, x, y, w, h, on_screen })
}

fn all_windows() -> anyhow::Result<Vec<WindowMeta>> {
    let mut out = Vec::new();
    for opt in [
        kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements,
        kCGWindowListOptionOnScreenOnly,
        kCGWindowListOptionAll,
    ] {
        let Some(arr) = copy_window_info(opt, kCGNullWindowID) else {
            continue;
        };
        for i in 0..arr.len() {
            let Some(item) = arr.get(i) else { continue };
            let dict = unsafe { CFDictionary::wrap_under_get_rule(*item as *const _) };
            if let Some(w) = parse_window(&dict) {
                if !out.iter().any(|e: &WindowMeta| e.id == w.id) {
                    out.push(w);
                }
            }
        }
        if !out.is_empty() {
            break;
        }
    }
    if out.is_empty() {
        return Err(anyhow::anyhow!(
            "no windows from CGWindowListCopyWindowInfo — grant Screen Recording to the host app"
        ));
    }
    Ok(out)
}

pub fn meta(id: u32) -> anyhow::Result<WindowMeta> {
    all_windows()?
        .into_iter()
        .find(|w| w.id == id)
        .ok_or_else(|| anyhow::anyhow!("window {id} not found"))
}

pub fn alive(id: u32) -> bool {
    meta(id).is_ok()
}

fn frontmost_pid() -> Option<i32> {
    unsafe {
        let _pool = NSAutoreleasePool::new();
        let app = NSWorkspace::sharedWorkspace().frontmostApplication()?;
        Some(app.processIdentifier())
    }
}

fn activate_application(pid: i32) -> anyhow::Result<()> {
    unsafe {
        let _pool = NSAutoreleasePool::new();
        let app = NSRunningApplication::runningApplicationWithProcessIdentifier(pid)
            .ok_or_else(|| anyhow::anyhow!("no NSRunningApplication for pid {pid}"))?;
        if !app.activateWithOptions(NSApplicationActivationOptions::ActivateAllWindows) {
            return Err(anyhow::anyhow!(
                "NSRunningApplication.activateWithOptions declined for pid {pid}"
            ));
        }
    }
    Ok(())
}

fn wait_frontmost(pid: i32, tries: usize) -> bool {
    for _ in 0..tries {
        if frontmost_pid() == Some(pid) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

pub fn list_windows(query: Option<WinQuery>) -> anyhow::Result<Vec<WinInfo>> {
    let q = query.unwrap_or_default();
    let fg = frontmost_pid();
    let mut out = Vec::new();
    for (z, w) in all_windows()?.into_iter().enumerate() {
        if !q.accepts(&w.title, &w.exe) {
            continue;
        }
        out.push(WinInfo {
            id: w.id,
            title: w.title,
            exe: w.exe,
            pid: w.pid as u32,
            x: w.x,
            y: w.y,
            w: w.w,
            h: w.h,
            z: z as i32,
            active: fg == Some(w.pid),
            minimized: !w.on_screen,
            maximized: false,
        });
    }
    Ok(out)
}

/// Bring a window to the foreground and verify its owning app is frontmost.
pub fn focus_window(id: u32) -> anyhow::Result<()> {
    let w = meta(id)?;
    if !w.on_screen || ax::window::is_minimized(&w).unwrap_or(false) {
        ax::window::set_minimized(&w, false)?;
        std::thread::sleep(std::time::Duration::from_millis(150));
    }

    activate_application(w.pid)?;
    if wait_frontmost(w.pid, 20) {
        return Ok(());
    }

    ax::window::focus(&w)?;
    if wait_frontmost(w.pid, 40) {
        return Ok(());
    }

    Err(anyhow::Error::new(CtlError::FocusFailed { hwnd: id }))
}

pub fn geom(
    id: u32,
    x: Option<i32>,
    y: Option<i32>,
    w: Option<i32>,
    h: Option<i32>,
    state: Option<&str>,
) -> anyhow::Result<WinInfo> {
    let meta = meta(id)?;
    if let Some(st) = state {
        match st {
            "min" => ax::window::set_minimized(&meta, true)?,
            "restore" => ax::window::set_minimized(&meta, false)?,
            "max" => ax::window::zoom(&meta)?,
            other => return Err(anyhow::anyhow!("unknown state {other:?} (min|max|restore)")),
        }
    }
    if let (Some(x), Some(y), Some(w), Some(h)) = (x, y, w, h) {
        ax::window::set_frame(&meta, x, y, w, h)?;
    }
    list_windows(None)?
        .into_iter()
        .find(|w| w.id == id)
        .ok_or_else(|| anyhow::anyhow!("window {id} vanished after geom"))
}

pub fn close(id: u32) -> anyhow::Result<()> {
    let meta = meta(id)?;
    ax::window::close(&meta)?;
    for _ in 0..20 {
        if !alive(id) {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(anyhow::anyhow!("window {id} still alive after close"))
}
