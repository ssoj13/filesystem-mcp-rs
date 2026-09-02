//! Accessibility element tree — macOS counterpart to Windows UI Automation.
//!
//! Same agent-facing shape as `win32::uia` so `ui` / `ui_click` / `ui_get` / `ui_set`
//! tools are platform-neutral at the MCP boundary.

use serde::Serialize;

use crate::tools::computer::driver::{resolve_target, Btn, WinTarget};
use crate::tools::computer::safety::SafetyGate;

use super::ax::{self, Element};
use super::input;
use super::win::{self, WindowMeta};

/// One UI element (agent-facing shape; mirrors `win32::uia::UiElem`).
#[derive(Debug, Clone, Serialize)]
pub struct UiElem {
    pub name: String,
    pub role: String,
    pub auto_id: String,
    pub class: String,
    pub patterns: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toggle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub enabled: bool,
    pub offscreen: bool,
}

fn target_meta(win_target: Option<WinTarget>) -> anyhow::Result<WindowMeta> {
    match win_target {
        Some(t) => win::meta(resolve_target(&t)?),
        None => {
            let wins = win::list_windows(None)?;
            let w = wins
                .into_iter()
                .find(|w| w.active)
                .ok_or_else(|| anyhow::anyhow!("no active window"))?;
            win::meta(w.id)
        }
    }
}

fn elem_of(el: &Element) -> UiElem {
    let (x, y, w, h) = el.bounds();
    let role = el.role();
    let value = el.value_string();
    let toggle = value.as_ref().and_then(|v| {
        if role.contains("CheckBox") || role.contains("RadioButton") {
            Some(v.clone())
        } else {
            None
        }
    });
    UiElem {
        name: el.title(),
        role,
        auto_id: el.identifier(),
        class: el.subrole(),
        patterns: el.action_names(),
        toggle,
        value,
        x,
        y,
        w,
        h,
        enabled: el.enabled(),
        offscreen: w == 0 || h == 0,
    }
}

fn walk_collect(el: &Element, depth: u32, out: &mut Vec<Element>) -> anyhow::Result<()> {
    out.push(el.duplicate());
    if depth == 0 {
        return Ok(());
    }
    for child in el.children().unwrap_or_default() {
        walk_collect(&child, depth.saturating_sub(1), out)?;
    }
    Ok(())
}

pub fn tree(
    win_target: Option<WinTarget>,
    query: Option<String>,
    depth: u32,
    max: usize,
) -> anyhow::Result<Vec<UiElem>> {
    ax::require_trusted()?;
    let meta = target_meta(win_target)?;
    let root = ax::resolve_window(&meta)?;
    let mut nodes = Vec::new();
    walk_collect(&root, depth, &mut nodes)?;
    let needle = query.as_deref().map(|q| q.to_lowercase());
    let mut out = Vec::new();
    for el in nodes {
        let e = elem_of(&el);
        if let Some(q) = &needle {
            let hay = format!("{} {}", e.name.to_lowercase(), e.auto_id.to_lowercase());
            if !hay.contains(q) {
                continue;
            }
        }
        out.push(e);
        if out.len() >= max {
            break;
        }
    }
    Ok(out)
}

fn find_matches(root: &Element, name: &str, depth: u32) -> anyhow::Result<Vec<Element>> {
    let mut nodes = Vec::new();
    walk_collect(root, depth, &mut nodes)?;
    let by_id: Vec<Element> = nodes.into_iter().filter(|e| e.identifier() == name).collect();
    if !by_id.is_empty() {
        return Ok(by_id);
    }
    let needle = name.to_lowercase();
    let mut nodes = Vec::new();
    walk_collect(root, depth, &mut nodes)?;
    Ok(nodes
        .into_iter()
        .filter(|e| e.title().to_lowercase().contains(&needle))
        .collect())
}

pub fn click(
    gate: &SafetyGate,
    win_target: Option<WinTarget>,
    name: &str,
    idx: usize,
) -> anyhow::Result<serde_json::Value> {
    ax::require_trusted()?;
    let meta = target_meta(win_target)?;
    let root = ax::resolve_window(&meta)?;
    let matches = find_matches(&root, name, 8)?;
    let el = matches
        .get(idx)
        .ok_or_else(|| anyhow::anyhow!("{}/{} matches for {name:?}", matches.len(), idx))?;

    let actions = el.action_names();
    if actions.iter().any(|a| a == "AXPress") {
        el.perform("AXPress")?;
        gate.record("ui_click", serde_json::json!({ "via": "press", "name": name, "idx": idx }))?;
        return Ok(serde_json::json!({ "via": "press", "focus": input::focus() }));
    }
    if actions.iter().any(|a| a == "AXShowMenu") {
        el.perform("AXShowMenu")?;
        gate.record("ui_click", serde_json::json!({ "via": "menu", "name": name, "idx": idx }))?;
        return Ok(serde_json::json!({ "via": "menu", "focus": input::focus() }));
    }

    let (x, y, w, h) = el.bounds();
    if w == 0 || h == 0 {
        return Err(anyhow::anyhow!("element {name:?} has an empty rect and no AXPress action"));
    }
    let (cx, cy) = (x + w / 2, y + h / 2);
    let focus = input::click(gate, Some(cx), Some(cy), Btn::Left, 1, &[])?;
    gate.record(
        "ui_click",
        serde_json::json!({ "via": "click", "name": name, "idx": idx, "pos": [cx, cy] }),
    )?;
    Ok(serde_json::json!({ "via": "click", "pos": [cx, cy], "focus": focus }))
}

pub fn get(
    win_target: Option<WinTarget>,
    name: &str,
    idx: usize,
) -> anyhow::Result<serde_json::Value> {
    ax::require_trusted()?;
    let meta = target_meta(win_target)?;
    let root = ax::resolve_window(&meta)?;
    let matches = find_matches(&root, name, 8)?;
    let el = matches
        .get(idx)
        .ok_or_else(|| anyhow::anyhow!("{}/{} matches for {name:?}", matches.len(), idx))?;
    let e = elem_of(el);
    Ok(serde_json::json!({
        "name": e.name,
        "role": e.role,
        "auto_id": e.auto_id,
        "class": e.class,
        "patterns": e.patterns,
        "toggle": e.toggle,
        "value": e.value,
        "enabled": e.enabled,
        "offscreen": e.offscreen,
        "rect": { "x": e.x, "y": e.y, "w": e.w, "h": e.h },
        "matches_total": matches.len(),
    }))
}

pub fn set_value(
    win_target: Option<WinTarget>,
    name: &str,
    idx: usize,
    value: &str,
) -> anyhow::Result<()> {
    ax::require_trusted()?;
    let meta = target_meta(win_target)?;
    let root = ax::resolve_window(&meta)?;
    let matches = find_matches(&root, name, 8)?;
    let el = matches
        .get(idx)
        .ok_or_else(|| anyhow::anyhow!("{}/{} matches for {name:?}", matches.len(), idx))?;
    el.set_string("AXValue", value)
}
