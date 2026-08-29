//! Windows UI Automation (COM) — structured element access (PLAN2.md §8 P3).
//!
//! Click hierarchy (PLAN2.md §2): UIA element -> OCR text -> pixels. This
//! module implements the reliable head of that chain: enumerate elements with
//! names/roles/rects, click by name (Invoke pattern first, real click
//! fallback), set values via the Value pattern.
//!
//! COM lifecycle: `UIAutomation::new()` initializes COM per calling thread;
//! tokio's blocking pool reuses threads, so init cost amortizes. Every op is
//! self-contained (no element handles cross the MCP boundary) — stateless by
//! design, matching the P3 acceptance "click by element name".
//!
//! uiautomation 0.25 API ground truth (verified against crate sources):
//! element_from_handle(Handle::from(hwnd)); UIMatcher::new(automation).from(el)
//! .depth(d).timeout(ms).find_all(); get_bounding_rectangle() -> windows Rect
//! (f32); patterns via get_pattern::<T>().

use serde::Serialize;
use uiautomation::types::Handle;
use uiautomation::{UIAutomation, UIMatcher, UIElement};

use super::input;
use super::safety::SafetyGate;
use super::win::{self, WinTarget};

/// One UI element (agent-facing shape).
#[derive(Debug, Clone, Serialize)]
pub struct UiElem {
    pub name: String,
    pub role: String,
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub enabled: bool,
}

/// Resolve the window to work in (target or active foreground).
fn target_hwnd(win_target: Option<WinTarget>) -> anyhow::Result<windows::Win32::Foundation::HWND> {
    match win_target {
        Some(t) => win::resolve_target(&t),
        None => {
            let fg = unsafe { windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow() };
            if fg.0.is_null() {
                return Err(anyhow::anyhow!("no active window"));
            }
            Ok(fg)
        }
    }
}

/// Matcher rooted at a window, depth-limited, no retry-wait (instant misses).
fn matcher(automation: UIAutomation, hwnd: windows::Win32::Foundation::HWND, depth: u32) -> anyhow::Result<UIMatcher> {
    let root = automation
        .element_from_handle(Handle::from(hwnd))
        .map_err(|e| anyhow::anyhow!("root element: {e}"))?;
    Ok(UIMatcher::new(automation)
        .from(root)
        .depth(depth)
        .timeout(200))
}

/// Enumerate elements under a window (defaults to the active window).
/// `query` filters names case-insensitively; `max` caps the result size
/// (raw UIA trees are token bombs — server-side filter is mandatory, §3).
pub fn tree(
    win_target: Option<WinTarget>,
    query: Option<String>,
    depth: u32,
    max: usize,
) -> anyhow::Result<Vec<UiElem>> {
    let hwnd = target_hwnd(win_target)?;
    let automation = UIAutomation::new().map_err(|e| anyhow::anyhow!("COM/UIA init: {e}"))?;
    let elements = matcher(automation, hwnd, depth)?
        .find_all()
        .map_err(|e| anyhow::anyhow!("find_all: {e}"))?;
    let needle = query.as_deref().map(|q| q.to_lowercase());
    let mut out = Vec::new();
    for el in elements {
        let name = el.get_name().unwrap_or_default();
        if let Some(q) = &needle
            && !name.to_lowercase().contains(q)
        {
            continue;
        }
        let (x, y, w, h) = rect_of(&el);
        let role = el
            .get_control_type()
            .map(|t| format!("{t:?}"))
            .unwrap_or_else(|_| "Unknown".to_string());
        out.push(UiElem {
            name,
            role,
            x,
            y,
            w,
            h,
            enabled: el.is_enabled().unwrap_or(false),
        });
        if out.len() >= max {
            break;
        }
    }
    Ok(out)
}

/// Find elements by name (CI substring) under a window, depth-limited.
fn find_named(automation: UIAutomation, hwnd: windows::Win32::Foundation::HWND, name: &str, depth: u32) -> anyhow::Result<Vec<UIElement>> {
    let needle = name.to_lowercase();
    let elements = matcher(automation, hwnd, depth)?
        .find_all()
        .map_err(|e| anyhow::anyhow!("find_all: {e}"))?;
    Ok(elements
        .into_iter()
        .filter(|el| el.get_name().unwrap_or_default().to_lowercase().contains(&needle))
        .collect())
}

fn rect_of(el: &UIElement) -> (i32, i32, i32, i32) {
    match el.get_bounding_rectangle() {
        Ok(r) => (r.get_left(), r.get_top(), r.get_width(), r.get_height()),
        Err(_) => (0, 0, 0, 0),
    }
}

/// Click an element matched by name. Invoke pattern first (works without
/// focus); real synthesized click at the element center as fallback
/// (requires the gate — it IS an input action).
pub fn click(
    gate: &SafetyGate,
    win_target: Option<WinTarget>,
    name: &str,
    idx: usize,
) -> anyhow::Result<serde_json::Value> {
    let hwnd = target_hwnd(win_target)?;
    let automation = UIAutomation::new().map_err(|e| anyhow::anyhow!("COM/UIA init: {e}"))?;
    let matches = find_named(automation, hwnd, name, 8)?;
    let el = matches
        .get(idx)
        .ok_or_else(|| anyhow::anyhow!("{}/{} matches for {name:?}", matches.len(), idx))?;
    // Invoke pattern: works for buttons/links/menu items regardless of occlusion.
    if let Ok(invoke) = el.get_pattern::<uiautomation::patterns::UIInvokePattern>() {
        invoke.invoke().map_err(|e| anyhow::anyhow!("invoke: {e}"))?;
        gate.record("ui_click", serde_json::json!({ "via": "invoke", "name": name, "idx": idx }))?;
        return Ok(serde_json::json!({ "via": "invoke", "focus": input::focus() }));
    }
    // Fallback: synthesized click at the element center (armed input).
    let (x, y, w, h) = rect_of(el);
    if w == 0 || h == 0 {
        return Err(anyhow::anyhow!("element {name:?} has an empty rect and no Invoke pattern"));
    }
    let (cx, cy) = (x + w / 2, y + h / 2);
    let focus = input::click(gate, Some(cx), Some(cy), input::Btn::Left, 1, &[])?;
    gate.record("ui_click", serde_json::json!({ "via": "click", "name": name, "idx": idx, "pos": [cx, cy] }))?;
    Ok(serde_json::json!({ "via": "click", "pos": [cx, cy], "focus": focus }))
}

/// Set an element's value via the UIA Value pattern (text fields, toggles).
pub fn set_value(
    win_target: Option<WinTarget>,
    name: &str,
    idx: usize,
    value: &str,
) -> anyhow::Result<()> {
    let hwnd = target_hwnd(win_target)?;
    let automation = UIAutomation::new().map_err(|e| anyhow::anyhow!("COM/UIA init: {e}"))?;
    let matches = find_named(automation, hwnd, name, 8)?;
    let el = matches
        .get(idx)
        .ok_or_else(|| anyhow::anyhow!("{}/{} matches for {name:?}", matches.len(), idx))?;
    let value_pattern = el
        .get_pattern::<uiautomation::patterns::UIValuePattern>()
        .map_err(|_| anyhow::anyhow!("element {name:?} has no Value pattern"))?;
    value_pattern
        .set_value(value)
        .map_err(|e| anyhow::anyhow!("set_value: {e}"))
}
