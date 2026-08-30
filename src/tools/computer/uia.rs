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
    /// AutomationId — stable across UI re-layouts (unlike name). Empty when
    /// the app doesn't provide one.
    pub auto_id: String,
    /// Win32 class name (e.g. "Button", "Edit") — useful for classic apps.
    pub class: String,
    /// UIA patterns the element supports (Invoke/Toggle/Value/ExpandCollapse...).
    pub patterns: Vec<String>,
    /// ToggleState for Toggle-pattern elements (On/Off/Indeterminate).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toggle: Option<String>,
    /// Current value for Value-pattern elements.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub enabled: bool,
    /// Element is offscreen (may need scroll_into_view before click).
    pub offscreen: bool,
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
            auto_id: el.get_automation_id().unwrap_or_default(),
            class: el.get_classname().unwrap_or_default(),
            patterns: patterns_of(&el),
            toggle: toggle_state_of(&el),
            value: value_of(&el),
            x,
            y,
            w,
            h,
            enabled: el.is_enabled().unwrap_or(false),
            offscreen: el.is_offscreen().unwrap_or(false),
        });
        if out.len() >= max {
            break;
        }
    }
    Ok(out)
}

/// Pattern names an element supports (the reliable action vocabulary).
fn patterns_of(el: &UIElement) -> Vec<String> {
    use uiautomation::patterns::*;
    let mut out = Vec::new();
    if el.get_pattern::<UIInvokePattern>().is_ok() {
        out.push("Invoke".into());
    }
    if el.get_pattern::<UITogglePattern>().is_ok() {
        out.push("Toggle".into());
    }
    if el.get_pattern::<UIValuePattern>().is_ok() {
        out.push("Value".into());
    }
    if el.get_pattern::<UIRangeValuePattern>().is_ok() {
        out.push("RangeValue".into());
    }
    if el.get_pattern::<UIExpandCollapsePattern>().is_ok() {
        out.push("ExpandCollapse".into());
    }
    if el.get_pattern::<UISelectionItemPattern>().is_ok() {
        out.push("SelectionItem".into());
    }
    if el.get_pattern::<UIScrollItemPattern>().is_ok() {
        out.push("ScrollItem".into());
    }
    out
}

/// ToggleState of a Toggle-pattern element, if it has one.
fn toggle_state_of(el: &UIElement) -> Option<String> {
    let toggle = el.get_pattern::<uiautomation::patterns::UITogglePattern>().ok()?;
    Some(format!("{:?}", toggle.get_toggle_state().ok()?))
}

/// Current value of a Value-pattern element (empty when none).
fn value_of(el: &UIElement) -> Option<String> {
    let v = el.get_pattern::<uiautomation::patterns::UIValuePattern>().ok()?;
    v.get_value().ok()
}

fn rect_of(el: &UIElement) -> (i32, i32, i32, i32) {
    match el.get_bounding_rectangle() {
        Ok(r) => (r.get_left(), r.get_top(), r.get_width(), r.get_height()),
        Err(_) => (0, 0, 0, 0),
    }
}

/// Click an element matched by name (or automation id — see `find_el`).
/// Pattern-aware action order: Invoke (buttons/links) → Toggle (checkboxes)
/// → ExpandCollapse (dropdowns) → SelectionItem (list items) → synthesized
/// click at element center as last resort (requires the gate).
pub fn click(
    gate: &SafetyGate,
    win_target: Option<WinTarget>,
    name: &str,
    idx: usize,
) -> anyhow::Result<serde_json::Value> {
    let hwnd = target_hwnd(win_target)?;
    let automation = UIAutomation::new().map_err(|e| anyhow::anyhow!("COM/UIA init: {e}"))?;
    let matches = find_el(automation, hwnd, name, 8)?;
    let el = matches
        .get(idx)
        .ok_or_else(|| anyhow::anyhow!("{}/{} matches for {name:?}", matches.len(), idx))?;
    use uiautomation::patterns::*;
    // Scroll offscreen elements into view first (pattern-free, always safe).
    if let Ok(scroll) = el.get_pattern::<UIScrollItemPattern>() {
        let _ = scroll.scroll_into_view();
    }
    if let Ok(invoke) = el.get_pattern::<UIInvokePattern>() {
        invoke.invoke().map_err(|e| anyhow::anyhow!("invoke: {e}"))?;
        gate.record("ui_click", serde_json::json!({ "via": "invoke", "name": name, "idx": idx }))?;
        return Ok(serde_json::json!({ "via": "invoke", "focus": input::focus() }));
    }
    if let Ok(toggle) = el.get_pattern::<UITogglePattern>() {
        toggle.toggle().map_err(|e| anyhow::anyhow!("toggle: {e}"))?;
        gate.record("ui_click", serde_json::json!({ "via": "toggle", "name": name, "idx": idx }))?;
        return Ok(serde_json::json!({ "via": "toggle", "focus": input::focus() }));
    }
    if let Ok(expand) = el.get_pattern::<UIExpandCollapsePattern>() {
        expand.expand().map_err(|e| anyhow::anyhow!("expand: {e}"))?;
        gate.record("ui_click", serde_json::json!({ "via": "expand", "name": name, "idx": idx }))?;
        return Ok(serde_json::json!({ "via": "expand", "focus": input::focus() }));
    }
    if let Ok(sel) = el.get_pattern::<UISelectionItemPattern>() {
        sel.select().map_err(|e| anyhow::anyhow!("select: {e}"))?;
        gate.record("ui_click", serde_json::json!({ "via": "select", "name": name, "idx": idx }))?;
        return Ok(serde_json::json!({ "via": "select", "focus": input::focus() }));
    }
    // Last resort: synthesized click at the element center (armed input).
    let (x, y, w, h) = rect_of(el);
    if w == 0 || h == 0 {
        return Err(anyhow::anyhow!("element {name:?} has an empty rect and no usable pattern"));
    }
    let (cx, cy) = (x + w / 2, y + h / 2);
    let focus = input::click(gate, Some(cx), Some(cy), input::Btn::Left, 1, &[])?;
    gate.record("ui_click", serde_json::json!({ "via": "click", "name": name, "idx": idx, "pos": [cx, cy] }))?;
    Ok(serde_json::json!({ "via": "click", "pos": [cx, cy], "focus": focus }))
}

/// Find by name OR automation id (exact match on auto_id preferred — it's
/// the stable handle; falls back to CI-substring name match).
fn find_el(automation: UIAutomation, hwnd: windows::Win32::Foundation::HWND, name: &str, depth: u32) -> anyhow::Result<Vec<UIElement>> {
    let elements = matcher(automation, hwnd, depth)?
        .find_all()
        .map_err(|e| anyhow::anyhow!("find_all: {e}"))?;
    // Exact automation-id match wins.
    let by_id: Vec<UIElement> = elements
        .iter()
        .filter(|el| el.get_automation_id().unwrap_or_default() == name)
        .cloned()
        .collect();
    if !by_id.is_empty() {
        return Ok(by_id);
    }
    let needle = name.to_lowercase();
    Ok(elements
        .into_iter()
        .filter(|el| el.get_name().unwrap_or_default().to_lowercase().contains(&needle))
        .collect())
}

/// Read element state by name/automation id: name, role, value, toggle,
/// patterns, rect. The agent's "look before acting" for UIA.
pub fn get(
    win_target: Option<WinTarget>,
    name: &str,
    idx: usize,
) -> anyhow::Result<serde_json::Value> {
    let hwnd = target_hwnd(win_target)?;
    let automation = UIAutomation::new().map_err(|e| anyhow::anyhow!("COM/UIA init: {e}"))?;
    let matches = find_el(automation, hwnd, name, 8)?;
    let el = matches
        .get(idx)
        .ok_or_else(|| anyhow::anyhow!("{}/{} matches for {name:?}", matches.len(), idx))?;
    let (x, y, w, h) = rect_of(el);
    Ok(serde_json::json!({
        "name": el.get_name().unwrap_or_default(),
        "role": el.get_control_type().map(|t| format!("{t:?}")).unwrap_or_default(),
        "auto_id": el.get_automation_id().unwrap_or_default(),
        "class": el.get_classname().unwrap_or_default(),
        "patterns": patterns_of(el),
        "toggle": toggle_state_of(el),
        "value": value_of(el),
        "enabled": el.is_enabled().unwrap_or(false),
        "offscreen": el.is_offscreen().unwrap_or(false),
        "rect": { "x": x, "y": y, "w": w, "h": h },
        "matches_total": matches.len(),
    }))
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
    let matches = find_el(automation, hwnd, name, 8)?;
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
