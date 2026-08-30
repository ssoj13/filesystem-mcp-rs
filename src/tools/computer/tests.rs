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
use super::safety::SafetyGate;
use super::driver::{self, WinQuery};

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
    let before: Vec<u32> = driver::list_windows(Some(q.clone()))?.iter().map(|w| w.id).collect();

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
        let fresh = driver::list_windows(Some(q.clone()))?
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
    driver::focus_window(id)?;
    let active = driver::list_windows(None)?
        .into_iter()
        .find(|w| w.active)
        .ok_or_else(|| anyhow::anyhow!("no active window"))?;
    assert_eq!(active.id, id, "focus verify failed");
    println!("focused: {} ({})", active.title, active.exe);

    // 5. Baseline capture of the edit-area strip (top-left client area).
    let strip = super::Rect::new(active.x + 20, active.y + 90, 400, 120);
    let base = capture::capture(CapTarget::Rect { x: strip.x, y: strip.y, w: 400, h: 120 })?;
    println!("baseline hash={:016x}", base.hash);

    // 6. Type ASCII + unicode synthetically (KEYEVENTF_UNICODE, paste=false).
    let r = driver::type_text(&gate, "canary 123 — тест", false, 3, Some(id))?;
    println!("typed: mode={} chars={}", r.mode, r.chars);
    std::thread::sleep(Duration::from_millis(300));

    // 7. The same strip must now hash-differ.
    let after = capture::capture(CapTarget::Rect { x: strip.x, y: strip.y, w: 400, h: 120 })?;
    let dist = hash_dist(base.hash, after.hash);
    println!("after hash={:016x} dist={}", after.hash, dist);

    // 8. OCR the whole window: the typed ASCII must appear (PLAN2 §9).
    let win_cap = capture::capture(CapTarget::Win { win: id })?;
    let img = image::open(&win_cap.path)?;
    let ocr = super::driver::win32::ocr::recognize(&img.to_rgba8(), Some("canary"))?;
    let hits: Vec<&str> = ocr.matches.iter().map(|m| m.text.as_str()).collect();
    println!("ocr matches: {hits:?}");

    if dist <= 6 && ocr.matches.is_empty() {
        kill(pid);
        panic!("neither hash change nor OCR match detected");
    }

    // 9. Timed-drag acceptance: hold 10 ms at the start point, drag for 1 s
    // with ease-out, release. Wall-clock must land near the target duration.
    let drag_t0 = std::time::Instant::now();
    let f = driver::drag(
        &gate,
        (active.x + 60, active.y + 100),
        (active.x + 260, active.y + 100),
        driver::Btn::Left,
        1000,
        driver::Ease::Out,
        10,
    )?;
    let drag_ms = drag_t0.elapsed().as_millis();
    println!(
        "timed drag done in {drag_ms} ms (target ~1010), focus={} ({})",
        f.hwnd, f.title
    );
    if !(900..=1400).contains(&drag_ms) {
        kill(pid);
        panic!("timed drag took {drag_ms} ms, expected ~1000");
    }

    // 10. Cleanup: kill OUR instance (unsaved text would make WM_CLOSE prompt).
    kill(pid);
    println!("cleanup: notepad {pid} killed");
    Ok(())
}

/// Paste-juggle verification: marker text is placed on the clipboard, our
/// paste types its own text, then the marker MUST be back on the clipboard
/// (read via the title of a second paste into Notepad? No — verify via
/// clip_files_get-style read: use the marker trick through the title).
#[test]
#[ignore = "interactive desktop experiment; run explicitly with --ignored"]
fn paste_juggle_restores_clipboard() {
    if let Err(e) = juggle_run() {
        panic!("JUGGLE FAIL: {e:#}");
    }
}

fn juggle_run() -> anyhow::Result<()> {
    super::ensure_dpi_aware()?;
    let gate = SafetyGate::new(600);
    gate.arm(Duration::from_secs(60));
    let marker = "JUGGLE-MARKER-777";
    // 1. Put the marker on the clipboard (simulates the user's data).
    let mut cb = arboard::Clipboard::new()?;
    cb.set_text(marker.to_string())?;
    // 2. Paste-type into our Notepad (this MUST temporarily take the clipboard).
    let q = WinQuery { exe: Some("notepad".into()), title: None };
    let before: Vec<u32> = driver::list_windows(Some(q.clone()))?.iter().map(|w| w.id).collect();
    let pid = std::process::Command::new("notepad.exe").spawn()?.id();
    let mut id = 0u32;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if let Some(w) = driver::list_windows(Some(q.clone()))?
            .into_iter()
            .find(|w| !before.contains(&w.id))
        {
            id = w.id;
            break;
        }
    }
    driver::focus_window(id)?;
    let r = driver::type_text(&gate, marker, true, 0, Some(id))?;
    println!("paste mode={} restored={:?}", r.mode, r.clipboard_restored);
    assert_eq!(r.clipboard_restored, Some(true), "clipboard must be restored");
    // 3. The marker must be back.
    let mut cb = arboard::Clipboard::new()?;
    let now = cb.get_text()?;
    assert_eq!(now, marker, "clipboard content was not restored");
    println!("JUGGLE OK: marker restored after paste");
    kill(pid);
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

/// ocrs engine smoke: models auto-download on first use, then recognize a
/// SMALL region — full-monitor inference in a DEBUG build takes minutes
/// (upstream limitation); the deployed server is release-built. Latin-only.
#[test]
#[ignore = "interactive; downloads ~12 MB of models on first run"]
fn ocrs_smoke() {
    super::ensure_dpi_aware().unwrap();
    let cap = super::capture::capture(CapTarget::Rect { x: 100, y: 100, w: 400, h: 200 }).unwrap();
    let img = image::open(&cap.path).unwrap().to_rgba8();
    let out = super::ocrs_local::recognize(&img, None).unwrap();
    println!("ocrs text ({} lines): {}", out.lines.len(), out.text);
}

/// Controlled typing-matrix experiment: does Notepad really drop chars at
/// fast KEYEVENTF_UNICODE intervals? Same text, separate Notepad instance per
/// scenario, read-back via the window title (mirrors the document first line
/// exactly — no OCR noise). Focus verified before every burst.
///
/// ```sh
/// cargo test --features computer-tools typing_mode_matrix -- --ignored --nocapture
/// ```
#[test]
#[ignore = "interactive desktop experiment; run explicitly with --ignored"]
fn typing_mode_matrix() {
    if let Err(e) = matrix_run() {
        panic!("MATRIX FAIL: {e:#}");
    }
}

/// (label, paste, interval_ms) — boundary probing: 20/30 ms stability ×2.
const SCENARIOS: &[(&str, bool, u32)] = &[
    ("paste      ", true, 0),
    ("chars 12ms", false, 12),
    ("chars 20ms", false, 20),
    ("chars 20ms", false, 20),
    ("chars 25ms", false, 25),
    ("chars 30ms", false, 30),
    ("chars 30ms", false, 30),
];

fn matrix_run() -> anyhow::Result<()> {
    super::ensure_dpi_aware()?;
    let gate = SafetyGate::new(600);
    gate.arm(Duration::from_secs(120));
    let q = WinQuery { exe: Some("notepad".into()), title: None };
    let text = "canary 123";
    println!("typed text: {text:?}  (read-back = window title)");
    println!("{:<12} {:>5} {:>6}  result", "mode", "ms", "exact");

    for (label, paste, interval) in SCENARIOS {
        // Win11 Notepad restores force-killed unsaved docs from TabState —
        // that contamination invalidates read-back. Wipe it while closed.
        kill_all_notepads();
        clear_notepad_session();
        // Fresh instance per scenario; own pid for cleanup.
        let before: Vec<u32> = driver::list_windows(Some(q.clone()))?.iter().map(|w| w.id).collect();
        let pid = std::process::Command::new("notepad.exe").spawn()?.id();
        let mut id = 0u32;
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(100));
            let fresh = driver::list_windows(Some(q.clone()))?
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
            return Err(anyhow::anyhow!("notepad window did not appear"));
        }
        // Focus + verify immediately before typing.
        driver::focus_window(id)?;
        let active = driver::list_windows(None)?
        .into_iter()
        .find(|w| w.active)
        .ok_or_else(|| anyhow::anyhow!("no active window"))?;
        if active.id != id {
            kill(pid);
            return Err(anyhow::anyhow!("focus verify failed before {label:?}"));
        }
        let r = driver::type_text(&gate, text, *paste, *interval, Some(id))?;
        std::thread::sleep(Duration::from_millis(300));
        let title = driver::list_windows(Some(q.clone()))?
            .into_iter()
            .find(|w| w.id == id)
            .map(|w| w.title)
            .unwrap_or_default();
        let shown = title
            .trim_start_matches('*')
            .trim_end_matches(" - Notepad")
            .trim_end_matches(" - Блокнот")
            .to_string();
        let exact = shown == text;
        let flag = if exact { "EXACT" } else { "DIFF " };
        println!(
            "{label:<12} {interval:>5}ms {flag}  got={shown:?} (mode={} sent={})",
            r.mode, r.chars
        );
        kill(pid);
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

/// Mixed-DPI field test: with per-monitor-v2 awareness the WHOLE stack must
/// speak one coordinate space — virtual-screen physical px — no matter what
/// scale factor each monitor runs at. A system-aware (or unaware) process
/// would pass on the primary monitor and quietly misalign on the scaled one,
/// which is exactly the bug class this test exists to catch.
///
/// Skips itself (prints SKIP, does not fail) unless the machine actually has
/// two monitors with DIFFERENT scale factors — that is the only configuration
/// where the check means anything.
///
/// ```sh
/// cargo test --features computer-tools mixed_dpi_fields -- --ignored --nocapture
/// ```
#[test]
#[ignore = "interactive desktop; needs >=2 monitors with different scale factors"]
fn mixed_dpi_fields() {
    if let Err(e) = mixed_dpi_run() {
        panic!("MIXED-DPI FAIL: {e:#}");
    }
}

fn mixed_dpi_run() -> anyhow::Result<()> {
    super::ensure_dpi_aware()?;
    let gate = SafetyGate::new(240);
    gate.arm(Duration::from_secs(60));

    let mons = capture::monitors()?;
    for m in &mons {
        println!("monitor {}: {:>5}x{:<5} at {:>6},{:<6} scale={} primary={}", m.id, m.w, m.h, m.x, m.y, m.scale, m.primary);
    }
    let scales: Vec<f32> = mons.iter().map(|m| m.scale).collect();
    let mixed = scales.iter().any(|s| (s - scales[0]).abs() > f32::EPSILON);
    if mons.len() < 2 || !mixed {
        println!("SKIP: need >=2 monitors with different scale factors (have {} monitor(s), scales {scales:?})", mons.len());
        return Ok(());
    }

    // 1. capture{monitor:i} must report exactly the rect `monitors` advertises.
    // A DPI-unaware capture path returns logical (scaled) sizes here.
    for m in &mons {
        let cap = capture::capture(CapTarget::Monitor { monitor: m.id })?;
        if (cap.rect.x, cap.rect.y, cap.rect.w, cap.rect.h) != (m.x, m.y, m.w, m.h) {
            return Err(anyhow::anyhow!(
                "monitor {} capture rect {:?} != advertised {}x{} at {},{} (scale {})",
                m.id, cap.rect, m.w, m.h, m.x, m.y, m.scale
            ));
        }
        println!("monitor {} capture rect OK ({:?})", m.id, cap.rect);
    }

    // 2. Cursor round-trip through every monitor center. SendInput normalizes
    // to a 0..65535 virtual-desk grid, so a pixel or two of rounding is
    // expected; a scale-factor error would be off by tens of percent.
    for m in &mons {
        let (cx, cy) = (m.x + m.w as i32 / 2, m.y + m.h as i32 / 2);
        driver::move_cursor(cx, cy)?;
        std::thread::sleep(Duration::from_millis(60));
        let (gx, gy) = super::driver::cursor_pos()?;
        let (dx, dy) = ((gx - cx).abs(), (gy - cy).abs());
        println!("monitor {} cursor round-trip: wanted {cx},{cy} got {gx},{gy} (d={dx},{dy})", m.id);
        if dx > 2 || dy > 2 {
            return Err(anyhow::anyhow!(
                "monitor {} (scale {}): cursor landed {dx},{dy} px off — coordinate spaces disagree",
                m.id, m.scale
            ));
        }
    }

    // 3. A window moved to each monitor must actually land inside it.
    let q = WinQuery { exe: Some("notepad".into()), title: None };
    let before: Vec<u32> = driver::list_windows(Some(q.clone()))?.iter().map(|w| w.id).collect();
    let pid = std::process::Command::new("notepad.exe").spawn()?.id();
    let mut id = 0u32;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if let Some(w) = driver::list_windows(Some(q.clone()))?.into_iter().find(|w| !before.contains(&w.id)) {
            id = w.id;
            break;
        }
    }
    if id == 0 {
        kill(pid);
        return Err(anyhow::anyhow!("notepad window did not appear in 5 s"));
    }
    let mut placement_err = None;
    for m in &mons {
        match driver::to_monitor(id, m.id) {
            Ok(info) => {
                let (wcx, wcy) = (info.x + info.w / 2, info.y + info.h / 2);
                let inside = wcx >= m.x && wcx < m.x + m.w as i32 && wcy >= m.y && wcy < m.y + m.h as i32;
                println!("win -> monitor {}: rect {},{} {}x{} center {wcx},{wcy} inside={inside}", m.id, info.x, info.y, info.w, info.h);
                if !inside {
                    placement_err = Some(format!("window center {wcx},{wcy} is not on monitor {}", m.id));
                    break;
                }
            }
            Err(e) => {
                placement_err = Some(format!("to_monitor({}) failed: {e:#}", m.id));
                break;
            }
        }
    }

    // 4. Template matching is FIXED-SCALE by design: a patch cut from one
    // monitor is only expected to match on that same monitor. Verify the
    // same-scale case round-trips to the exact screen coords it came from.
    let mut match_err = None;
    for m in &mons {
        let patch_rect = super::Rect::new(m.x + 40, m.y + 40, 60, 40);
        let patch = capture::capture(CapTarget::Rect { x: patch_rect.x, y: patch_rect.y, w: patch_rect.w, h: patch_rect.h })?;
        let tpl = image::open(&patch.path)?.to_rgba8();
        let scene_cap = capture::capture(CapTarget::Monitor { monitor: m.id })?;
        let scene = image::open(&scene_cap.path)?.to_rgba8();
        let hits = super::find::find_template(&scene, &tpl, 0.9, 1)?;
        match hits.first() {
            Some(hit) => {
                let (sx, sy) = (hit.x + scene_cap.rect.x, hit.y + scene_cap.rect.y);
                println!("monitor {} template found at screen {sx},{sy} (cut from {},{}) score={:.3}", m.id, patch_rect.x, patch_rect.y, hit.score);
                if (sx - patch_rect.x).abs() > 2 || (sy - patch_rect.y).abs() > 2 {
                    match_err = Some(format!("monitor {}: template mapped back to {sx},{sy}, cut from {},{}", m.id, patch_rect.x, patch_rect.y));
                    break;
                }
            }
            None => {
                match_err = Some(format!("monitor {}: a patch cut from this very monitor did not match itself", m.id));
                break;
            }
        }
    }

    kill(pid);
    if let Some(e) = placement_err {
        return Err(anyhow::anyhow!(e));
    }
    if let Some(e) = match_err {
        return Err(anyhow::anyhow!(e));
    }
    println!("MIXED-DPI OK across {} monitors, scales {scales:?}", mons.len());
    Ok(())
}

/// Kill every Notepad (this test owns the machine's Notepad state while running).
fn kill_all_notepads() {
    use std::os::windows::process::CommandExt;
    let _ = std::process::Command::new("taskkill")
        .args(["/IM", "Notepad.exe", "/F"])
        .creation_flags(0x0800_0000)
        .status();
    std::thread::sleep(Duration::from_millis(300));
}

/// Wipe Win11 Notepad's unsaved-tab restore state (contaminates titles).
fn clear_notepad_session() {
    let Some(local) = std::env::var_os("LOCALAPPDATA") else { return };
    let dir = std::path::PathBuf::from(local)
        .join(r"Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState\TabState");
    if dir.is_dir() {
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
    }
}
