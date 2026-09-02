//! Mouse/keyboard input via CGEvent (macOS).

use std::sync::Mutex;

use anyhow::Context as _;
use arboard::Clipboard;
use core_graphics::event::{
    CGEvent, CGEventFlags, CGEventTapLocation, CGEventType, CGKeyCode, CGMouseButton, KeyCode,
    ScrollEventUnit,
};
use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
use core_graphics::geometry::CGPoint;

use crate::tools::computer::driver::{Btn, Ease, FocusInfo, KeyMod, TypeResult};
use crate::tools::computer::safety::{CtlError, SafetyGate};

use super::win;

static INPUT_MTX: Mutex<()> = Mutex::new(());

fn source() -> CGEventSource {
    CGEventSource::new(CGEventSourceStateID::CombinedSessionState).unwrap_or_else(|_| {
        CGEventSource::new(CGEventSourceStateID::HIDSystemState).expect("CGEventSource")
    })
}

fn post(event: &CGEvent) {
    let _guard = INPUT_MTX.lock().expect("input mutex poisoned");
    event.post(CGEventTapLocation::HID);
}

fn flags_for_mods(mods: &[KeyMod]) -> CGEventFlags {
    let mut f = CGEventFlags::empty();
    for m in mods {
        f |= match m {
            KeyMod::Ctrl => CGEventFlags::CGEventFlagControl,
            KeyMod::Alt => CGEventFlags::CGEventFlagAlternate,
            KeyMod::Shift => CGEventFlags::CGEventFlagShift,
            KeyMod::Win => CGEventFlags::CGEventFlagCommand,
        };
    }
    f
}

fn btn_cg(btn: Btn) -> CGMouseButton {
    match btn {
        Btn::Left => CGMouseButton::Left,
        Btn::Right => CGMouseButton::Right,
        Btn::Middle => CGMouseButton::Center,
    }
}

fn down_type(btn: Btn) -> CGEventType {
    match btn {
        Btn::Left => CGEventType::LeftMouseDown,
        Btn::Right => CGEventType::RightMouseDown,
        Btn::Middle => CGEventType::OtherMouseDown,
    }
}

fn up_type(btn: Btn) -> CGEventType {
    match btn {
        Btn::Left => CGEventType::LeftMouseUp,
        Btn::Right => CGEventType::RightMouseUp,
        Btn::Middle => CGEventType::OtherMouseUp,
    }
}

fn drag_type(btn: Btn) -> CGEventType {
    match btn {
        Btn::Left => CGEventType::LeftMouseDragged,
        Btn::Right => CGEventType::RightMouseDragged,
        Btn::Middle => CGEventType::OtherMouseDragged,
    }
}

pub fn focus() -> FocusInfo {
    if let Ok(wins) = win::list_windows(None) {
        if let Some(w) = wins.into_iter().find(|w| w.active) {
            return FocusInfo { hwnd: w.id, title: w.title };
        }
    }
    FocusInfo { hwnd: 0, title: String::new() }
}

pub fn cursor_pos() -> anyhow::Result<(i32, i32)> {
    let ev = CGEvent::new(source()).map_err(|_| anyhow::anyhow!("CGEvent::new failed"))?;
    let p = ev.location();
    Ok((p.x as i32, p.y as i32))
}

pub fn move_cursor(x: i32, y: i32) -> anyhow::Result<FocusInfo> {
    let pt = CGPoint::new(x as f64, y as f64);
    let ev = CGEvent::new_mouse_event(source(), CGEventType::MouseMoved, pt, CGMouseButton::Left)
        .map_err(|_| anyhow::anyhow!("mouse move event failed"))?;
    post(&ev);
    Ok(focus())
}

pub fn click(
    gate: &SafetyGate,
    x: Option<i32>,
    y: Option<i32>,
    btn: Btn,
    clicks: u32,
    mods: &[KeyMod],
) -> anyhow::Result<FocusInfo> {
    gate.check()?;
    let pos = match (x, y) {
        (Some(x), Some(y)) => move_cursor(x, y)?,
        _ => focus(),
    };
    if clicks == 0 {
        gate.record("mouse_hover", serde_json::json!({ "pos": [pos.hwnd, pos.title] }))?;
        return Ok(focus());
    }
    let pt = if let (Some(x), Some(y)) = (x, y) {
        CGPoint::new(x as f64, y as f64)
    } else {
        let p = cursor_pos()?;
        CGPoint::new(p.0 as f64, p.1 as f64)
    };
    let flags = flags_for_mods(mods);
    for _ in 0..clicks {
        let down = CGEvent::new_mouse_event(source(), down_type(btn), pt, btn_cg(btn))
            .map_err(|_| anyhow::anyhow!("mouse down failed"))?;
        down.set_flags(flags);
        post(&down);
        let up = CGEvent::new_mouse_event(source(), up_type(btn), pt, btn_cg(btn))
            .map_err(|_| anyhow::anyhow!("mouse up failed"))?;
        up.set_flags(flags);
        post(&up);
    }
    gate.record("mouse_click", serde_json::json!({ "clicks": clicks }))?;
    Ok(focus())
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
    gate.check()?;
    let from_pt = CGPoint::new(from.0 as f64, from.1 as f64);
    post(&CGEvent::new_mouse_event(source(), down_type(btn), from_pt, btn_cg(btn))
        .map_err(|_| anyhow::anyhow!("drag down failed"))?);
    if hold_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(hold_ms as u64));
    }
    let n = if duration_ms > 0 { (duration_ms / 16).clamp(2, 200) } else { 24 };
    let chunk = if duration_ms > 0 {
        std::time::Duration::from_millis((duration_ms / n).max(1) as u64)
    } else {
        std::time::Duration::ZERO
    };
    for i in 1..=n {
        let t = i as f64 / n as f64;
        let t = match ease {
            Ease::Linear => t,
            Ease::Out => 1.0 - (1.0 - t) * (1.0 - t),
        };
        let pt = CGPoint::new(
            from.0 as f64 + (to.0 - from.0) as f64 * t,
            from.1 as f64 + (to.1 - from.1) as f64 * t,
        );
        post(&CGEvent::new_mouse_event(source(), drag_type(btn), pt, btn_cg(btn))
            .map_err(|_| anyhow::anyhow!("drag move failed"))?);
        if !chunk.is_zero() && i < n {
            std::thread::sleep(chunk);
        }
    }
    let end = CGPoint::new(to.0 as f64, to.1 as f64);
    post(&CGEvent::new_mouse_event(source(), up_type(btn), end, btn_cg(btn))
        .map_err(|_| anyhow::anyhow!("drag up failed"))?);
    gate.record("mouse_drag", serde_json::json!({ "from": from, "to": to }))?;
    Ok(focus())
}

pub fn scroll(gate: &SafetyGate, dy: i32, dx: i32) -> anyhow::Result<FocusInfo> {
    gate.check()?;
    post(&CGEvent::new_scroll_event(source(), ScrollEventUnit::LINE, 2, -dy, dx, 0)
        .map_err(|_| anyhow::anyhow!("scroll event failed"))?);
    gate.record("mouse_scroll", serde_json::json!({ "dy": dy, "dx": dx }))?;
    Ok(focus())
}

fn key_code(name: &str) -> Option<CGKeyCode> {
    let n = name.to_ascii_lowercase();
    match n.as_str() {
        "ctrl" | "control" => Some(KeyCode::CONTROL),
        "alt" | "option" => Some(KeyCode::OPTION),
        "shift" => Some(KeyCode::SHIFT),
        "win" | "meta" | "cmd" | "command" => Some(KeyCode::COMMAND),
        "enter" | "return" => Some(KeyCode::RETURN),
        "tab" => Some(KeyCode::TAB),
        "esc" | "escape" => Some(KeyCode::ESCAPE),
        "space" => Some(KeyCode::SPACE),
        "backspace" | "bs" => Some(KeyCode::DELETE),
        "delete" | "del" => Some(KeyCode::FORWARD_DELETE),
        "home" => Some(KeyCode::HOME),
        "end" => Some(KeyCode::END),
        "pageup" | "pgup" => Some(KeyCode::PAGE_UP),
        "pagedown" | "pgdn" => Some(KeyCode::PAGE_DOWN),
        "up" => Some(KeyCode::UP_ARROW),
        "down" => Some(KeyCode::DOWN_ARROW),
        "left" => Some(KeyCode::LEFT_ARROW),
        "right" => Some(KeyCode::RIGHT_ARROW),
        _ => {
            let b = n.as_bytes();
            if b.len() == 1 && b[0].is_ascii_alphanumeric() {
                Some(b[0].to_ascii_lowercase() as CGKeyCode)
            } else if let Some(num) = n.strip_prefix('f').and_then(|r| r.parse::<u16>().ok()) {
                ((1..=20).contains(&num)).then(|| KeyCode::F1 + (num - 1) as CGKeyCode)
            } else {
                None
            }
        }
    }
}

fn parse_combo(combo: &str) -> anyhow::Result<Vec<CGKeyCode>> {
    let mut mods = Vec::new();
    let mut mains = Vec::new();
    for part in combo.split('+') {
        let p = part.trim();
        let code = key_code(p).ok_or_else(|| anyhow::anyhow!("unknown key {p:?} in {combo:?}"))?;
        if matches!(p.to_ascii_lowercase().as_str(), "ctrl" | "control" | "alt" | "option" | "shift" | "win" | "meta" | "cmd" | "command") {
            mods.push(code);
        } else {
            mains.push(code);
        }
    }
    if mains.len() != 1 {
        return Err(anyhow::anyhow!("combo {combo:?} must contain exactly one main key"));
    }
    mods.push(mains.remove(0));
    Ok(mods)
}

fn key_event(code: CGKeyCode, down: bool) -> anyhow::Result<CGEvent> {
    CGEvent::new_keyboard_event(source(), code, down).map_err(|_| anyhow::anyhow!("keyboard event failed"))
}

pub fn key_tap(gate: &SafetyGate, combo: &str, hold_ms: u32) -> anyhow::Result<FocusInfo> {
    gate.check()?;
    let codes = parse_combo(combo)?;
    for &c in &codes {
        post(&key_event(c, true)?);
    }
    if hold_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(hold_ms as u64));
    }
    for &c in codes.iter().rev() {
        post(&key_event(c, false)?);
    }
    gate.record("key_tap", serde_json::json!({ "combo": combo }))?;
    Ok(focus())
}

const PASTE_SETTLE_MS: u64 = 150;

enum ClipSnap {
    Text(String),
    Image(arboard::ImageData<'static>),
    None,
}

pub fn type_text(
    gate: &SafetyGate,
    text: &str,
    paste: bool,
    interval_ms: u32,
    expect_id: Option<u32>,
) -> anyhow::Result<TypeResult> {
    gate.check()?;
    let chars = text.chars().count();
    if paste {
        let cur = focus();
        if let Some(expect) = expect_id
            && cur.hwnd != expect
        {
            return Err(anyhow::Error::new(CtlError::FocusFailed { hwnd: cur.hwnd })
                .context("paste refused: focus changed before typing"));
        }
        let mut cb = Clipboard::new().context("open clipboard")?;
        let old = match cb.get_text() {
            Ok(prev) => ClipSnap::Text(prev),
            Err(_) => match cb.get_image() {
                Ok(img) => ClipSnap::Image(arboard::ImageData {
                    width: img.width,
                    height: img.height,
                    bytes: std::borrow::Cow::Owned(img.bytes.into_owned()),
                }),
                Err(_) => ClipSnap::None,
            },
        };
        cb.set_text(text.to_string()).context("set clipboard text")?;
        key_tap(gate, "cmd+v", 0)?;
        std::thread::sleep(std::time::Duration::from_millis(PASTE_SETTLE_MS));
        let hijacked = cb.get_text().ok().as_deref() != Some(text);
        let restored = if hijacked {
            false
        } else {
            match &old {
                ClipSnap::Text(prev) => cb.set_text(prev.clone()).is_ok(),
                ClipSnap::Image(img) => cb.set_image(img.clone()).is_ok(),
                ClipSnap::None => cb.clear().is_ok(),
            }
        };
        gate.record("key_type", serde_json::json!({ "mode": "paste", "chars": chars }))?;
        return Ok(TypeResult {
            mode: "paste",
            chars,
            clipboard_restored: Some(restored),
            focus: focus(),
        });
    }
    for ch in text.chars() {
        let ev = key_event(0, true)?;
        ev.set_string(&ch.to_string());
        post(&ev);
        let up = key_event(0, false)?;
        up.set_string(&ch.to_string());
        post(&up);
        if interval_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(interval_ms as u64));
        }
    }
    gate.record("key_type", serde_json::json!({ "mode": "unicode", "chars": chars }))?;
    Ok(TypeResult { mode: "unicode", chars, clipboard_restored: None, focus: focus() })
}
