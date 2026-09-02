//! macOS real-machine canaries — run explicitly:
//!
//! ```sh
//! cargo test --bin filesystem-mcp-rs canary_mac -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Grant **Accessibility** to the test binary (or installed `filesystem-mcp-rs`).
//! **Screen Recording** improves window titles from CGWindowList.

use std::sync::Mutex;
use std::time::Duration;

use anyhow::Context as _;

use super::capture::{self, CapTarget, hash_dist};
use super::driver::{self};
use super::driver::mac;
use super::safety::SafetyGate;

static CANARY_LOCK: Mutex<()> = Mutex::new(());

fn with_lock<F: FnOnce() -> anyhow::Result<()>>(f: F) -> anyhow::Result<()> {
    let _g = CANARY_LOCK.lock().expect("canary lock poisoned");
    f()
}

/// Passive smoke: caps, monitors, window list, cursor — no input injection.
#[test]
#[ignore = "interactive desktop; run with --ignored"]
fn canary_mac_smoke() {
    if let Err(e) = with_lock(smoke_run) {
        panic!("MAC SMOKE FAIL: {e:#}");
    }
}

fn smoke_run() -> anyhow::Result<()> {
    super::ensure_dpi_aware()?;
    let caps = driver::caps();
    println!("caps: backend={} input={} window={} capture={}", caps.backend, caps.input, caps.window, caps.capture);
    assert_eq!(caps.backend, "mac");
    assert!(caps.input, "input domain expected on mac backend");
    assert!(caps.window, "window domain expected on mac backend");

    let mons = capture::monitors()?;
    println!("monitors: {}", mons.len());
    for m in &mons {
        println!("  {} {}x{} @ {},{} scale={} primary={}", m.name, m.w, m.h, m.x, m.y, m.scale, m.primary);
    }
    assert!(!mons.is_empty());

    let (vx, vy, vw, vh) = driver::virtual_screen()?;
    println!("virtual_screen: {vx},{vy} {vw}x{vh}");

    let wins = driver::list_windows(None)?;
    println!("windows: {}", wins.len());
    for w in wins.iter().take(8) {
        println!("  [{}] {} / {} active={}", w.id, w.title, w.exe, w.active);
    }

    let (cx, cy) = driver::cursor_pos()?;
    println!("cursor: {cx},{cy}");

    let cap = capture::capture(CapTarget::Monitor { monitor: 0 })?;
    println!("capture monitor0: {} hash={:016x}", cap.path, cap.hash);
    Ok(())
}

/// Full loop: spawn TextEdit → focus → type → hash change → cleanup.
#[test]
#[ignore = "interactive desktop; needs Accessibility permission"]
fn canary_mac_textedit() {
    if let Err(e) = with_lock(textedit_run) {
        panic!("MAC TEXTEDIT FAIL: {e:#}");
    }
}

fn textedit_run() -> anyhow::Result<()> {
    mac::require_accessibility().context("textedit canary needs Accessibility")?;
    super::ensure_dpi_aware()?;
    let gate = SafetyGate::new(240);
    gate.arm(Duration::from_secs(60));

    let before: Vec<u32> = driver::list_windows(None)?.iter().map(|w| w.id).collect();

    let _ = std::process::Command::new("osascript")
        .args(["-e", "tell application \"TextEdit\" to quit"])
        .status();
    std::thread::sleep(Duration::from_millis(400));

    let status = std::process::Command::new("open").args(["-a", "TextEdit"]).status()?;
    if !status.success() {
        return Err(anyhow::anyhow!("open -a TextEdit failed: {status}"));
    }
    println!("spawned TextEdit, existing windows: {}", before.len());

    let mut id = 0u32;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(200));
        let fresh: Vec<_> = driver::list_windows(None)?
            .into_iter()
            .filter(|w| !before.contains(&w.id))
            .collect();
        if let Some(w) = fresh.first() {
            id = w.id;
            break;
        }
    }
    if id == 0 {
        return Err(anyhow::anyhow!("TextEdit window did not appear in 10 s"));
    }
    println!("textedit window id={id}");

    driver::focus_window(id)?;
    let active = driver::list_windows(None)?
        .into_iter()
        .find(|w| w.active)
        .ok_or_else(|| anyhow::anyhow!("no active window after focus"))?;
    if active.id != id {
        return Err(anyhow::anyhow!("focus verify failed: wanted {id}, active {}", active.id));
    }
    println!("focused: {}", active.title);

    let strip = super::Rect::new(active.x + 20, active.y + 60, 400, 120);
    let base = capture::capture(CapTarget::Rect { x: strip.x, y: strip.y, w: strip.w, h: strip.h })?;
    println!("baseline hash={:016x}", base.hash);

    let r = driver::type_text(&gate, "canary mac 123", true, 0, Some(id))?;
    println!("typed: mode={} chars={} restored={:?}", r.mode, r.chars, r.clipboard_restored);
    std::thread::sleep(Duration::from_millis(500));

    let after = capture::capture(CapTarget::Rect { x: strip.x, y: strip.y, w: strip.w, h: strip.h })?;
    let dist = hash_dist(base.hash, after.hash);
    println!("after hash={:016x} dist={}", after.hash, dist);
    if dist <= 6 {
        close_textedit(id);
        return Err(anyhow::anyhow!("screen hash did not change after typing (Accessibility granted?)"));
    }

    close_textedit(id);
    println!("cleanup done");
    Ok(())
}

fn close_textedit(id: u32) {
    if driver::close_window(id).is_err() {
        let _ = std::process::Command::new("osascript")
            .args(["-e", "tell application \"TextEdit\" to quit"])
            .status();
    }
}
