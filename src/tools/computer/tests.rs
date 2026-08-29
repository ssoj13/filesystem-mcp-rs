//! Real-machine canary (PLAN2.md §9): NOT part of normal `cargo test`.
//!
//! Requires an interactive desktop. Runs the full acceptance loop against its
//! own Notepad instance:
//!
//! ```sh
//! cargo test --features computer-tools canary_notepad -- --ignored --nocapture
//! ```
//!
//! Spawns its own Notepad, focuses it, types ASCII+unicode synthetically,
//! verifies the screen hash changed and OCR sees the text, then kills only its
//! own instance (pid tracked from spawn).

use std::time::Duration;

use super::capture::{self, CapTarget, hash_dist};
use super::input;
use super::safety::SafetyGate;
use super::win::{self, WinQuery};

/// Full acceptance loop: focus → type → hash-change → OCR. #[ignore]d by
/// default (needs a human-visible desktop, no CI).
#[test]
#[ignore = "interactive desktop canary; run explicitly with --ignored"]
fn canary_notepad() {
    if let Err(e) = canary_run() {
        panic!("CANARY FAIL: {e:#}");
    }
}

fn canary_run() -> anyhow::Result<()> {
    super::ensure_dpi_aware()?;
    let gate = SafetyGate::new(240);
    gate.arm(Duration::from_secs(60));

    // 1. Snapshot existing Notepad windows; ours is the diff.
    let q = WinQuery { exe: Some("notepad".into()), title: None };
    let before: Vec<u32> = win::list_windows(Some(q.clone()))?.iter().map(|w| w.id).collect();

    // 2. Spawn Notepad; pid kept for cleanup.
    let child = std::process::Command::new("notepad.exe")
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn notepad: {e}"))?;
    let pid = child.id();
    println!("notepad pid={pid}, existing windows: {}", before.len());

    // 3. Poll up to 5 s for a NEW notepad window id.
    let mut id = 0u32;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        let fresh = win::list_windows(Some(q.clone()))?
            .into_iter()
            .filter(|w| !before.contains(&w.id))
            .collect::<Vec<_>>();
        if let Some(w) = fresh.first() {
            id = w.id;
            break;
        }
    }
    if id == 0 {
        kill(pid);
        panic!("notepad window did not appear in 5 s");
    }
    println!("notepad window id={id}");

    // 4. Focus + verify foreground is our window.
    let hwnd = windows::Win32::Foundation::HWND(id as usize as *mut core::ffi::c_void);
    win::focus_window(hwnd)?;
    let active = win::active()?.ok_or_else(|| anyhow::anyhow!("no active window"))?;
    assert_eq!(active.id, id, "focus verify failed");
    println!("focused: {} ({})", active.title, active.exe);

    // 5. Baseline capture of the edit-area strip (top-left client area).
    let strip = super::Rect::new(active.x + 20, active.y + 90, 400, 120);
    let base = capture::capture(CapTarget::Rect { x: strip.x, y: strip.y, w: 400, h: 120 })?;
    println!("baseline hash={:016x}", base.hash);

    // 6. Type ASCII + unicode synthetically (KEYEVENTF_UNICODE, paste=false).
    let r = input::type_text(&gate, "canary 123 — тест", false, 3, Some(id))?;
    println!("typed: mode={} chars={}", r.mode, r.chars);
    std::thread::sleep(Duration::from_millis(300));

    // 7. The same strip must now hash-differ.
    let after = capture::capture(CapTarget::Rect { x: strip.x, y: strip.y, w: 400, h: 120 })?;
    let dist = hash_dist(base.hash, after.hash);
    println!("after hash={:016x} dist={}", after.hash, dist);

    // 8. OCR the whole window: the typed ASCII must appear (PLAN2 §9).
    let win_cap = capture::capture(CapTarget::Win { win: id })?;
    let img = image::open(&win_cap.path)?;
    let ocr = super::ocr::recognize(&img.to_rgba8(), Some("canary"))?;
    let hits: Vec<&str> = ocr.matches.iter().map(|m| m.text.as_str()).collect();
    println!("ocr matches: {hits:?}");

    if dist <= 6 && ocr.matches.is_empty() {
        kill(pid);
        panic!("neither hash change nor OCR match detected");
    }

    // 9. Cleanup: kill OUR instance (unsaved text would make WM_CLOSE prompt).
    kill(pid);
    println!("cleanup: notepad {pid} killed");
    Ok(())
}

fn kill(pid: u32) {
    // CREATE_NO_WINDOW: cosmetic — no console flash for a kill helper.
    use std::os::windows::process::CommandExt;
    let _ = std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .creation_flags(0x0800_0000)
        .status();
}
