//! Mouse/keyboard input via SendInput (Windows).
//!
//! All coordinates are virtual-screen physical pixels (multi-monitor, negative
//! origins allowed — PLAN2.md critic §10.5). SendInput batches are serialized by
//! one mutex so concurrent MCP calls cannot interleave down/up pairs (§5). Every
//! action returns the focus window so the agent catches a focus race for free.

use std::sync::Mutex;

use anyhow::Context as _;
use windows::Win32::Foundation::POINT;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT,
    KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, MOUSEEVENTF_ABSOLUTE,
    MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN,
    MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
    MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEINPUT, SendInput, VIRTUAL_KEY, VK_BACK,
    VK_CONTROL, VK_DELETE, VK_DOWN, VK_END, VK_ESCAPE, VK_F1, VK_HOME, VK_INSERT, VK_LEFT,
    VK_LWIN, VK_MENU, VK_NEXT, VK_PRIOR, VK_RETURN, VK_RIGHT, VK_SHIFT, VK_SPACE, VK_TAB,
    VK_UP, MOUSE_EVENT_FLAGS,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetCursorPos, GetForegroundWindow, WHEEL_DELTA,
};

// Platform-neutral types: defined in the driver, re-exported for callers that
// historically imported them from input (input::Btn etc.).
pub use super::driver::{Btn, Ease, FocusInfo, TypeResult};
use super::safety::{CtlError, SafetyGate};
use super::win;

/// One mutex serializes every SendInput batch (macro down/up ordering, §5).
static INPUT_MTX: Mutex<()> = Mutex::new(());

/// Mouse button down/up flag pair (win32 backend).
impl Btn {
    pub(crate) fn flags(self) -> (MOUSE_EVENT_FLAGS, MOUSE_EVENT_FLAGS) {
        match self {
            Btn::Left => (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
            Btn::Right => (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
            Btn::Middle => (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
        }
    }
}

/// Named-key -> VK map (combos resolve to VK codes: layout-independent, §10).
pub fn vk(name: &str) -> Option<VIRTUAL_KEY> {
    let n = name.to_ascii_lowercase();
    let k = match n.as_str() {
        "ctrl" | "control" => VK_CONTROL,
        "alt" => VK_MENU,
        "shift" => VK_SHIFT,
        "win" | "meta" => VK_LWIN,
        "enter" | "return" => VK_RETURN,
        "tab" => VK_TAB,
        "esc" | "escape" => VK_ESCAPE,
        "space" => VK_SPACE,
        "backspace" | "bs" => VK_BACK,
        "delete" | "del" => VK_DELETE,
        "insert" | "ins" => VK_INSERT,
        "home" => VK_HOME,
        "end" => VK_END,
        "pageup" | "pgup" => VK_PRIOR,
        "pagedown" | "pgdn" => VK_NEXT,
        "up" => VK_UP,
        "down" => VK_DOWN,
        "left" => VK_LEFT,
        "right" => VK_RIGHT,
        _ => {
            // a-z / 0-9 single chars map straight to their VK code.
            let bytes = n.as_bytes();
            if bytes.len() == 1 && bytes[0].is_ascii_alphanumeric() {
                return Some(VIRTUAL_KEY(bytes[0].to_ascii_uppercase() as u16));
            }
            // f1..f24
            if let Some(num) = n
                .strip_prefix('f')
                .and_then(|r| r.parse::<u16>().ok())
                .filter(|num| (1..=24).contains(num))
            {
                return Some(VIRTUAL_KEY(VK_F1.0 + num - 1));
            }
            return None;
        }
    };
    Some(k)
}

/// Parse "ctrl+shift+t" into VK codes, modifiers first (win > ctrl > alt > shift).
pub fn parse_combo(combo: &str) -> anyhow::Result<Vec<VIRTUAL_KEY>> {
    let mut mods: Vec<VIRTUAL_KEY> = Vec::new();
    let mut mains: Vec<VIRTUAL_KEY> = Vec::new();
    for part in combo.split('+') {
        let p = part.trim();
        if p.is_empty() {
            return Err(anyhow::anyhow!("empty combo part in {combo:?}"));
        }
        let code = vk(p).ok_or_else(|| anyhow::anyhow!("unknown key {p:?} in {combo:?}"))?;
        if matches!(code.0, 0x10..=0x12 | 0x5B) {
            mods.push(code);
        } else {
            mains.push(code);
        }
    }
    if mains.len() != 1 {
        return Err(anyhow::anyhow!(
            "combo {combo:?} must contain exactly one main key"
        ));
    }
    let rank = |code: u16| match code {
        0x5B => 0, // win
        0x11 => 1, // ctrl
        0x12 => 2, // alt
        0x10 => 3, // shift
        _ => 4,
    };
    mods.sort_by_key(|c| rank(c.0));
    mods.push(mains.remove(0));
    Ok(mods)
}

/// Dispatch one SendInput batch; error on partial delivery (never silently drop).
fn send_batch(batch: &[INPUT]) -> anyhow::Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let _guard = INPUT_MTX.lock().expect("input mutex poisoned");
    // SAFETY: correct count via slice length; correct struct size.
    let sent = unsafe { SendInput(batch, std::mem::size_of::<INPUT>() as i32) };
    if sent != batch.len() as u32 {
        return Err(anyhow::anyhow!("SendInput partial: {sent}/{}", batch.len()));
    }
    Ok(())
}

/// Build a keyboard INPUT carrying a UTF-16 unit (KEYEVENTF_UNICODE path;
/// wVk = 0 + wScan = unit is the documented unicode event shape).
fn key_scan(scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(0),
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Build a mouse INPUT (absolute virtual-screen coords or button/wheel events).
fn mouse(flags: MOUSE_EVENT_FLAGS, dx: i32, dy: i32, data: u32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT { dx, dy, mouseData: data, dwFlags: flags, time: 0, dwExtraInfo: 0 },
        },
    }
}

/// Build a keyboard INPUT from a VK code and flags.
fn key(vk_code: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(vk_code),
                wScan: 0,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

/// Virtual-screen -> normalized absolute coords for ABSOLUTE|VIRTUALDESK.
fn to_abs(x: i32, y: i32) -> (u32, u32) {
    let (vx, vy, vw, vh) = win::virtual_screen();
    if vw < 2 || vh < 2 {
        return (0, 0);
    }
    let nx = (((x - vx).max(0) as f64) * 65535.0 / (vw - 1) as f64) as u32;
    let ny = (((y - vy).max(0) as f64) * 65535.0 / (vh - 1) as f64) as u32;
    (nx.min(65535), ny.min(65535))
}

/// Current focus (hwnd + title).
pub fn focus() -> FocusInfo {
    let hwnd = unsafe { GetForegroundWindow() };
    FocusInfo {
        hwnd: hwnd.0 as u32,
        title: if hwnd.0.is_null() { String::new() } else { win::win_title(hwnd) },
    }
}

/// Post-move cursor verification (drift is a warning, not an error —
/// rounding across the 65535 normalization can shift by a pixel).
/// Cursor position (None when unavailable).
pub(crate) fn cursor_pos() -> Option<(i32, i32)> {
    let mut p = POINT::default();
    // SAFETY: out-pointer only.
    unsafe { GetCursorPos(&mut p) }
        .ok()
        .map(|_| (p.x, p.y))
}

/// Move-only hover (absolute virtual-screen coords).
pub fn move_cursor(x: i32, y: i32) -> anyhow::Result<FocusInfo> {
    let (nx, ny) = to_abs(x, y);
    let batch = [mouse(
        MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
        nx as i32,
        ny as i32,
        0,
    )];
    send_batch(&batch)?;
    if let Some((cx, cy)) = cursor_pos()
        && (cx, cy) != (x, y)
    {
        tracing::warn!("cursor drift: wanted {x},{y} got {cx},{cy}");
    }
    Ok(focus())
}

/// Click: optional pre-move, N clicks (0 = hover only), optional modifier keys
/// held across the clicks (ctrl/alt/shift/win — resolved via [`vk`]).
/// Returns post-click focus.
pub fn click(
    gate: &SafetyGate,
    x: Option<i32>,
    y: Option<i32>,
    btn: Btn,
    clicks: u32,
    mods: &[VIRTUAL_KEY],
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
    let (down, up) = btn.flags();
    // One batch: modifiers down -> click pairs -> modifiers up (reversed), so
    // ctrl/shift state cannot leak between the atomic click sequence.
    let mut batch = Vec::with_capacity(mods.len() * 2 + clicks as usize * 2);
    for m in mods {
        batch.push(key(m.0, KEYBD_EVENT_FLAGS(0)));
    }
    for _ in 0..clicks {
        batch.push(mouse(down, 0, 0, 0));
        batch.push(mouse(up, 0, 0, 0));
    }
    for m in mods.iter().rev() {
        batch.push(key(m.0, KEYEVENTF_KEYUP));
    }
    send_batch(&batch)?;
    gate.record(
        "mouse_click",
        serde_json::json!({ "btn": btn, "clicks": clicks, "mods": mods.len(), "pos": [pos.hwnd, pos.title] }),
    )?;
    Ok(focus())
}

/// Screen pixel color at virtual-screen coords. GetPixel returns 0x00BBGGRR;
/// CLR_INVALID (0xFFFFFFFF) means the coords are outside the screen.
pub fn color_at(x: i32, y: i32) -> anyhow::Result<(u8, u8, u8)> {
    use windows::Win32::Foundation::COLORREF;
    use windows::Win32::Graphics::Gdi::{GetDC, GetPixel, ReleaseDC};
    // SAFETY: screen DC acquired and released symmetrically.
    let hdc = unsafe { GetDC(None) };
    if hdc.is_invalid() {
        return Err(anyhow::anyhow!("GetDC(screen) failed"));
    }
    let px = unsafe { GetPixel(hdc, x, y) };
    unsafe { ReleaseDC(None, hdc) };
    if px == COLORREF(0xFFFF_FFFF) {
        return Err(anyhow::anyhow!("({x},{y}) is outside the visible screen"));
    }
    Ok((
        (px.0 & 0xFF) as u8,
        ((px.0 >> 8) & 0xFF) as u8,
        ((px.0 >> 16) & 0xFF) as u8,
    ))
}

/// Temporized drag: press at `from` (`hold_ms` settle with button down),
/// then move in ~16 ms chunks over `duration_ms` (0 = instant single batch),
/// then release. Chunked timing is what makes apps track the movement —
/// a single instant batch lands before drag targets notice the press.
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
    let (down, up) = btn.flags();
    let (fx, fy) = to_abs(from.0, from.1);
    let batch = vec![mouse(down, fx as i32, fy as i32, 0)];
    send_batch(&batch)?;
    if hold_ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(hold_ms as u64));
    }
    // Chunk count: ~16 ms per chunk when timed; a fixed density when instant.
    let n = if duration_ms > 0 {
        (duration_ms / 16).clamp(2, 200)
    } else {
        24
    };
    let chunk_sleep = if duration_ms > 0 {
        std::time::Duration::from_millis((duration_ms / n).max(1) as u64)
    } else {
        std::time::Duration::ZERO
    };
    for i in 1..=n {
        let t = i as f64 / n as f64;
        let t = match ease {
            Ease::Linear => t,
            // Ease-out: fast start, decelerating arrival (quadratic).
            Ease::Out => 1.0 - (1.0 - t) * (1.0 - t),
        };
        let x = from.0 as f64 + (to.0 - from.0) as f64 * t;
        let y = from.1 as f64 + (to.1 - from.1) as f64 * t;
        let (nx, ny) = to_abs(x as i32, y as i32);
        let chunk = [mouse(
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
            nx as i32,
            ny as i32,
            0,
        )];
        send_batch(&chunk)?;
        if !chunk_sleep.is_zero() && i < n {
            std::thread::sleep(chunk_sleep);
        }
    }
    let end = [mouse(up, 0, 0, 0)];
    send_batch(&end)?;
    gate.record(
        "mouse_drag",
        serde_json::json!({ "from": from, "to": to, "duration_ms": duration_ms, "ease": ease, "hold_ms": hold_ms }),
    )?;
    Ok(focus())
}

/// Wheel scroll: `dy > 0` scrolls down, `dx > 0` scrolls right (PLAN2.md §3).
pub fn scroll(gate: &SafetyGate, dy: i32, dx: i32) -> anyhow::Result<FocusInfo> {
    gate.check()?;
    let mut batch = Vec::new();
    if dy != 0 {
        // Windows wheel: positive delta = up, so invert for "dy>0 = down".
        batch.push(mouse(MOUSEEVENTF_WHEEL, 0, 0, (-dy * WHEEL_DELTA as i32) as u32));
    }
    if dx != 0 {
        batch.push(mouse(MOUSEEVENTF_HWHEEL, 0, 0, (dx * WHEEL_DELTA as i32) as u32));
    }
    send_batch(&batch)?;
    gate.record("mouse_scroll", serde_json::json!({ "dy": dy, "dx": dx }))?;
    Ok(focus())
}

/// Press a combo like "ctrl+shift+t". `hold_ms > 0` holds the main key down
/// between two batches (down / hold / up).
pub fn key_tap(gate: &SafetyGate, combo: &str, hold_ms: u32) -> anyhow::Result<FocusInfo> {
    gate.check()?;
    let codes = parse_combo(combo)?;
    let downs: Vec<INPUT> = codes.iter().map(|c| key(c.0, KEYBD_EVENT_FLAGS(0))).collect();
    let ups: Vec<INPUT> = codes
        .iter()
        .rev()
        .map(|c| key(c.0, KEYEVENTF_KEYUP))
        .collect();
    if hold_ms == 0 {
        let mut batch = downs;
        batch.extend(ups);
        send_batch(&batch)?;
    } else {
        send_batch(&downs)?;
        std::thread::sleep(std::time::Duration::from_millis(hold_ms as u64));
        send_batch(&ups)?;
    }
    gate.record("key_tap", serde_json::json!({ "combo": combo, "hold_ms": hold_ms }))?;
    Ok(focus())
}

const PASTE_SETTLE_MS: u64 = 150;

/// Clipboard snapshot for the paste-mode juggle: full save/restore of text or
/// image content; `None` = clipboard was empty (or an unsupported format).
enum ClipSnap {
    Text(String),
    Image(arboard::ImageData<'static>),
    None,
}

/// Type `text` into the focused window.
///
/// paste mode (default): save clipboard -> set text -> ctrl+v -> settle ->
/// restore clipboard. The settle wait exists because the target app processes
/// WM_PASTE asynchronously on its own UI thread — restoring the clipboard too
/// early makes it paste the OLD text (PLAN2.md critic §10.2/§10.5).
/// paste is refused (FocusFailed) when the focus moved away from `expect_hwnd`,
/// given by the caller that resolved the target window: pasting into the wrong
/// window is worse than slow typing.
pub fn type_text(
    gate: &SafetyGate,
    text: &str,
    paste: bool,
    interval_ms: u32,
    expect_hwnd: Option<u32>,
) -> anyhow::Result<TypeResult> {
    gate.check()?;
    let chars = text.chars().count();
    if paste {
        let cur = focus();
        if let Some(expect) = expect_hwnd
            && cur.hwnd != expect
        {
            return Err(anyhow::Error::new(CtlError::FocusFailed { hwnd: cur.hwnd })
                .context("paste refused: focus changed before typing"));
        }
        let mut cb = arboard::Clipboard::new().context("open clipboard")?;
        // Juggling: snapshot the old content in full (text OR image) so the
        // paste can be undone. Non-text-only snapshots keep the clipboard
        // restorable; an unsupported format simply arrives as `None` (empty).
        let old: ClipSnap = match cb.get_text() {
            Ok(prev) => ClipSnap::Text(prev),
            Err(_) => match cb.get_image() {
                Ok(img) => ClipSnap::Image(arboard::ImageData {
                    width: img.width,
                    height: img.height,
                    bytes: std::borrow::Cow::Owned(img.bytes.into_owned()),
                }),
                // Both reads failed -> empty clipboard.
                Err(_) => ClipSnap::None,
            },
        };
        cb.set_text(text.to_string()).context("set clipboard text")?;
        let batch = vec![
            key(VK_CONTROL.0, KEYBD_EVENT_FLAGS(0)),
            key(b'V' as u16, KEYBD_EVENT_FLAGS(0)),
            key(b'V' as u16, KEYEVENTF_KEYUP),
            key(VK_CONTROL.0, KEYEVENTF_KEYUP),
        ];
        send_batch(&batch)?;
        std::thread::sleep(std::time::Duration::from_millis(PASTE_SETTLE_MS));
        // Interloper guard: if the clipboard no longer holds OUR text, a
        // concurrent writer landed between set and restore (human sharing the
        // desktop). Restoring the snapshot would clobber THEIR newer data —
        // keep theirs and report the skip instead.
        let hijacked = cb.get_text().ok().as_deref() != Some(text);
        let restored = if hijacked {
            tracing::warn!(
                "clipboard changed concurrently during paste; foreign content kept, nothing restored"
            );
            false
        } else {
            let ok = match &old {
                ClipSnap::Text(prev) => cb.set_text(prev.clone()).is_ok(),
                ClipSnap::Image(img) => cb.set_image(img.clone()).is_ok(),
                ClipSnap::None => cb.clear().is_ok(),
            };
            if !ok {
                tracing::warn!("clipboard restore failed; previous content lost");
            }
            ok
        };
        gate.record("key_type", serde_json::json!({ "mode": "paste", "chars": chars }))?;
        return Ok(TypeResult {
            mode: "paste",
            chars,
            clipboard_restored: Some(restored),
            focus: focus(),
        });
    }
    // Unicode path: KEYEVENTF_UNICODE events (layout-independent; UTF-16 units
    // for astral chars). One batch per char when pacing is requested.
    for unit in text.encode_utf16() {
        let batch = [
            key_scan(unit, KEYEVENTF_UNICODE),
            key_scan(unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP),
        ];
        send_batch(&batch)?;
        if interval_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(interval_ms as u64));
        }
    }
    gate.record("key_type", serde_json::json!({ "mode": "unicode", "chars": chars }))?;
    Ok(TypeResult { mode: "unicode", chars, clipboard_restored: None, focus: focus() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combo_parser() {
        let codes = parse_combo("ctrl+shift+t").unwrap();
        assert_eq!(codes.iter().map(|c| c.0).collect::<Vec<_>>(), vec![0x11, 0x10, 0x54]); // shift = 0x10
        assert_eq!(parse_combo("Enter").unwrap()[0].0, VK_RETURN.0);
        assert_eq!(parse_combo("f5").unwrap()[0].0, VK_F1.0 + 4);
        assert_eq!(parse_combo("ctrl+alt+del").unwrap()[0].0, 0x11); // ctrl before alt
    }

    #[test]
    fn combo_errors() {
        assert!(parse_combo("ctrl+shift").is_err()); // no main key
        assert!(parse_combo("ctrl++").is_err()); // empty part
        assert!(parse_combo("ctrl+wat+enter").is_err()); // unknown key
        assert!(parse_combo("ctrl+enter+tab").is_err()); // two mains
    }

    #[test]
    fn vk_names() {
        assert_eq!(vk("ctrl").unwrap().0, VK_CONTROL.0);
        assert_eq!(vk("pgdn").unwrap().0, VK_NEXT.0);
        assert!(vk("wat").is_none());
    }
}
