//! Platform driver: the OS seam of the computer module.
//!
//! Everything above this layer (`safety`, `steps`, `wait`, `find`, `capture`,
//! `annotate`, `ocrs_local`, the `server_*` tool files) is portable and reaches
//! the operating system ONLY through this module. `seam_guard` below enforces
//! that mechanically — it reads those sources and fails the build's test run if
//! a direct `windows::`/`x11rb::`/backend import ever creeps back in.
//!
//! ## Shape
//!
//! - **Portable types** (`Btn`, `Ease`, `KeyMod`, `FocusInfo`, `WinInfo`,
//!   `WinTarget`, `LayoutEntry`, `Caps`) live here so every backend and every
//!   caller share one definition. A window id is a `u32` (HWND on Windows,
//!   an opaque per-backend handle elsewhere).
//! - **Domain traits** (`InputDrv`, `WinDrv`, `ScreenDrv`, `ClipDrv`,
//!   `NotifyDrv`) split the surface so a backend implements only what its OS
//!   actually provides; an absent domain is `None`, which the facade turns into
//!   a loud `unsupported` — never a silent no-op.
//! - **Backends** live one per directory (`win32/`, later `x11/`, `wayland/`,
//!   `mac/`) plus `null` for unknown platforms. Adding or dropping one touches
//!   its directory, one line of `select()`, and one Cargo feature.
//! - **Selection is at RUNTIME** (`backend()`), not compile time: on Unix the
//!   choice between Wayland and X11 depends on the live session, and
//!   `FS_MCP_CTL_BACKEND` can pin it for tests.
//! - **Portable operations** built on top of the traits (`resolve_target`,
//!   `to_monitor`, `layout_save`, `layout_load`) are written once for every OS
//!   in `portable.rs`; only genuinely OS-specific calls belong in a backend.

pub mod portable;

#[cfg(windows)]
pub mod win32;

#[cfg(target_os = "macos")]
pub mod mac;

mod null;

/// Platform UI automation (`ui_*` tools): UIA on Windows, Accessibility on macOS.
#[cfg(feature = "ctl-uia")]
pub mod uia {
    #[cfg(windows)]
    pub use super::win32::uia::*;
    #[cfg(target_os = "macos")]
    pub use super::mac::uia::*;
}

pub use portable::{layout_load, layout_save, resolve_target, to_monitor};

/// Modifier keys, platform-neutral (wire + macro steps use these names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum KeyMod {
    Ctrl,
    Alt,
    Shift,
    Win,
}

/// Parse modifier names (loud error on unknown, never silent).
pub fn parse_keymods(mods: Option<&[String]>) -> anyhow::Result<Vec<KeyMod>> {
    let Some(names) = mods else {
        return Ok(Vec::new());
    };
    names
        .iter()
        .map(|n| match n.trim().to_ascii_lowercase().as_str() {
            "ctrl" | "control" => Ok(KeyMod::Ctrl),
            "alt" => Ok(KeyMod::Alt),
            "shift" => Ok(KeyMod::Shift),
            "win" | "meta" => Ok(KeyMod::Win),
            other => Err(anyhow::anyhow!("unknown modifier {other:?} (ctrl|alt|shift|win)")),
        })
        .collect()
}

/// Mouse button.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Btn {
    Left,
    Right,
    Middle,
}

/// Drag trajectory easing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Ease {
    Linear,
    Out,
}

/// Focus snapshot returned with input actions (hwnd = platform window id:
/// HWND on Windows, opaque elsewhere).
#[derive(Debug, Clone, serde::Serialize)]
pub struct FocusInfo {
    pub hwnd: u32,
    pub title: String,
}

/// Result of typing: which path ran, clipboard outcome, post-type focus.
#[derive(Debug, serde::Serialize)]
pub struct TypeResult {
    pub mode: &'static str,
    pub chars: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clipboard_restored: Option<bool>,
    pub focus: FocusInfo,
}

/// One visible top-level window (agent-facing shape).
#[derive(Debug, Clone, serde::Serialize)]
pub struct WinInfo {
    pub id: u32,
    pub title: String,
    pub exe: String,
    pub pid: u32,
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub z: i32,
    pub active: bool,
    pub minimized: bool,
    pub maximized: bool,
}

/// Window filter (case-insensitive substrings).
#[derive(Debug, Clone, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct WinQuery {
    pub title: Option<String>,
    pub exe: Option<String>,
}

impl WinQuery {
    /// Does a window pass this filter? Lives here so every backend applies the
    /// SAME rule (absent field = no constraint, present = case-insensitive
    /// substring) instead of reimplementing it per OS.
    pub fn accepts(&self, title: &str, exe: &str) -> bool {
        let ci = |hay: &str, needle: &Option<String>| {
            needle
                .as_ref()
                .is_none_or(|n| hay.to_lowercase().contains(&n.to_lowercase()))
        };
        ci(title, &self.title) && ci(exe, &self.exe)
    }
}

/// How to address a window: {"id":n} | {"title":s} | {"exe":s}.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum WinTarget {
    Id { id: u32 },
    Title { title: String },
    Exe { exe: String },
}

/// Saved window position (layout snapshot entry; portable shape).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LayoutEntry {
    pub id: u32,
    pub title: String,
    pub exe: String,
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// Capability map of the LIVE backend — agents check this instead of tripping
/// `unsupported` errors. Computed from the selected backend, never a const:
/// on Unix the same binary reports different capabilities under X11, Wayland
/// or a headless session.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Caps {
    /// Which backend answered: "win32" | "x11" | "wayland" | "mac" | "null".
    pub backend: &'static str,
    /// The backend has been exercised on real hardware (see driver/CLAUDE.md).
    pub verified_on_hardware: bool,
    pub input: bool,
    pub window: bool,
    pub uia: bool,
    pub ocr_media: bool,
    pub clip_files: bool,
    pub notify: bool,
    /// Capture/monitors — portable via xcap on all OSes.
    pub capture: bool,
    /// ocrs engine — pure Rust, all OSes.
    pub ocr_ocrs: bool,
}

/// Loud, specific unsupported error (never a silent fallback).
pub fn unsupported(what: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "unsupported on this platform ({}): {what}",
        backend().name()
    )
}

// ---- Domain traits ----------------------------------------------------------
//
// Split by domain so a backend implements only what its OS provides. Keep them
// object-safe: the registry hands out `&dyn`.

use crate::tools::computer::safety::SafetyGate;

/// Mouse + keyboard synthesis and the focus/cursor queries that go with it.
pub trait InputDrv: Send + Sync {
    fn move_cursor(&self, x: i32, y: i32) -> anyhow::Result<FocusInfo>;
    fn click(
        &self,
        gate: &SafetyGate,
        x: Option<i32>,
        y: Option<i32>,
        btn: Btn,
        clicks: u32,
        mods: &[KeyMod],
    ) -> anyhow::Result<FocusInfo>;
    #[allow(clippy::too_many_arguments)]
    fn drag(
        &self,
        gate: &SafetyGate,
        from: (i32, i32),
        to: (i32, i32),
        btn: Btn,
        duration_ms: u32,
        ease: Ease,
        hold_ms: u32,
    ) -> anyhow::Result<FocusInfo>;
    fn scroll(&self, gate: &SafetyGate, dy: i32, dx: i32) -> anyhow::Result<FocusInfo>;
    fn key_tap(&self, gate: &SafetyGate, combo: &str, hold_ms: u32) -> anyhow::Result<FocusInfo>;
    fn type_text(
        &self,
        gate: &SafetyGate,
        text: &str,
        paste: bool,
        interval_ms: u32,
        expect: Option<u32>,
    ) -> anyhow::Result<TypeResult>;
    fn cursor_pos(&self) -> anyhow::Result<(i32, i32)>;
    fn focus(&self) -> anyhow::Result<FocusInfo>;
}

/// Window enumeration and manipulation.
///
/// There is deliberately NO `active()` here: `list()` already marks the
/// foreground window with `WinInfo::active`, and `InputDrv::focus()` reports it
/// after an action. A third way to ask the same question is a third thing that
/// can disagree. `resolve_target`, `to_monitor` and the
/// layout snapshots are NOT here — they are portable logic over these calls.
pub trait WinDrv: Send + Sync {
    fn list(&self, query: Option<WinQuery>) -> anyhow::Result<Vec<WinInfo>>;
    fn focus_window(&self, id: u32) -> anyhow::Result<()>;
    fn geom(
        &self,
        id: u32,
        x: Option<i32>,
        y: Option<i32>,
        w: Option<i32>,
        h: Option<i32>,
        state: Option<&str>,
    ) -> anyhow::Result<WinInfo>;
    fn close(&self, id: u32) -> anyhow::Result<()>;
    /// Does this id still address a live window? (layout restore checks it.)
    fn alive(&self, id: u32) -> bool;
}

/// Screen geometry and pixel probing. Capture itself is portable (xcap).
pub trait ScreenDrv: Send + Sync {
    /// Virtual screen metrics (x, y, width, height) in physical pixels;
    /// the origin may be negative on multi-monitor setups.
    fn virtual_screen(&self) -> anyhow::Result<(i32, i32, i32, i32)>;
    fn color_at(&self, x: i32, y: i32) -> anyhow::Result<(u8, u8, u8)>;
}

/// Clipboard file lists plus the change counter `wait` polls.
pub trait ClipDrv: Send + Sync {
    fn get_files(&self) -> anyhow::Result<Vec<String>>;
    fn set_files(&self, files: &[String]) -> anyhow::Result<()>;
    /// Monotonic clipboard sequence number, for change detection.
    fn seq(&self) -> anyhow::Result<u32>;
}

/// Desktop notifications ("needs a human" signal).
pub trait NotifyDrv: Send + Sync {
    fn notify(&self, title: Option<&str>, msg: &str) -> anyhow::Result<()>;
}

/// One platform backend. Domains it cannot serve return `None`.
pub trait Backend: Send + Sync {
    fn name(&self) -> &'static str;
    /// False until someone has actually run this backend on real hardware.
    fn verified_on_hardware(&self) -> bool;
    fn input(&self) -> Option<&dyn InputDrv> {
        None
    }
    fn win(&self) -> Option<&dyn WinDrv> {
        None
    }
    fn screen(&self) -> Option<&dyn ScreenDrv> {
        None
    }
    fn clip(&self) -> Option<&dyn ClipDrv> {
        None
    }
    fn notify(&self) -> Option<&dyn NotifyDrv> {
        None
    }
    /// UI Automation trees. Windows-only for now (AX / AT-SPI would slot here).
    fn has_uia(&self) -> bool {
        false
    }
    /// WinRT OCR. Windows-only; the portable `ocrs` engine is always available.
    fn has_ocr_media(&self) -> bool {
        false
    }
}

// ---- Backend selection ------------------------------------------------------

/// The live backend, chosen once per process.
///
/// `FS_MCP_CTL_BACKEND` pins the choice (`null` is useful in tests to exercise
/// the unsupported paths on a machine that has a real desktop).
pub fn backend() -> &'static dyn Backend {
    static SELECTED: std::sync::OnceLock<&'static dyn Backend> = std::sync::OnceLock::new();
    *SELECTED.get_or_init(|| {
        let pinned = crate::env_spec::get("FS_MCP_CTL_BACKEND");
        let chosen = select(pinned.as_deref());
        tracing::debug!("computer-control backend: {}", chosen.name());
        chosen
    })
}

fn select(pinned: Option<&str>) -> &'static dyn Backend {
    if let Some("null") = pinned {
        return &null::Null;
    }
    #[cfg(windows)]
    {
        // One desktop API on Windows; nothing to choose at runtime.
        &win32::Win32
    }
    #[cfg(target_os = "macos")]
    {
        match pinned {
            Some("mac") | None => &mac::Mac,
            // x11/wayland pins on macOS are test hooks — fall through to null.
            _ => &null::Null,
        }
    }
    #[cfg(all(not(windows), not(target_os = "macos")))]
    {
        // Linux x11/wayland backends land here as they are implemented.
        &null::Null
    }
}

/// Capability map of the live backend (the `ctl_caps` tool).
pub fn caps() -> Caps {
    let b = backend();
    Caps {
        backend: b.name(),
        verified_on_hardware: b.verified_on_hardware(),
        input: b.input().is_some(),
        window: b.win().is_some(),
        uia: b.has_uia(),
        ocr_media: b.has_ocr_media(),
        clip_files: b.clip().is_some(),
        notify: b.notify().is_some(),
        capture: true,
        ocr_ocrs: true,
    }
}

// ---- Free-function facade ---------------------------------------------------
//
// Call sites keep using `driver::click(...)`; each function resolves the domain
// and turns an absent one into a loud, specific error.

fn input() -> anyhow::Result<&'static dyn InputDrv> {
    backend().input().ok_or_else(|| unsupported("input injection"))
}

fn win() -> anyhow::Result<&'static dyn WinDrv> {
    backend().win().ok_or_else(|| unsupported("window management"))
}

fn screen() -> anyhow::Result<&'static dyn ScreenDrv> {
    backend().screen().ok_or_else(|| unsupported("screen geometry"))
}

fn clip() -> anyhow::Result<&'static dyn ClipDrv> {
    backend().clip().ok_or_else(|| unsupported("clipboard file lists"))
}

pub fn move_cursor(x: i32, y: i32) -> anyhow::Result<FocusInfo> {
    input()?.move_cursor(x, y)
}

pub fn click(
    gate: &SafetyGate,
    x: Option<i32>,
    y: Option<i32>,
    btn: Btn,
    clicks: u32,
    mods: &[KeyMod],
) -> anyhow::Result<FocusInfo> {
    input()?.click(gate, x, y, btn, clicks, mods)
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
    input()?.drag(gate, from, to, btn, duration_ms, ease, hold_ms)
}

pub fn scroll(gate: &SafetyGate, dy: i32, dx: i32) -> anyhow::Result<FocusInfo> {
    input()?.scroll(gate, dy, dx)
}

pub fn key_tap(gate: &SafetyGate, combo: &str, hold_ms: u32) -> anyhow::Result<FocusInfo> {
    input()?.key_tap(gate, combo, hold_ms)
}

pub fn type_text(
    gate: &SafetyGate,
    text: &str,
    paste: bool,
    interval_ms: u32,
    expect: Option<u32>,
) -> anyhow::Result<TypeResult> {
    input()?.type_text(gate, text, paste, interval_ms, expect)
}

pub fn cursor_pos() -> anyhow::Result<(i32, i32)> {
    input()?.cursor_pos()
}

pub fn focus() -> anyhow::Result<FocusInfo> {
    input()?.focus()
}

pub fn list_windows(query: Option<WinQuery>) -> anyhow::Result<Vec<WinInfo>> {
    win()?.list(query)
}

pub fn focus_window(id: u32) -> anyhow::Result<()> {
    win()?.focus_window(id)
}

pub fn geom(
    id: u32,
    x: Option<i32>,
    y: Option<i32>,
    w: Option<i32>,
    h: Option<i32>,
    state: Option<&str>,
) -> anyhow::Result<WinInfo> {
    win()?.geom(id, x, y, w, h, state)
}

pub fn close_window(id: u32) -> anyhow::Result<()> {
    win()?.close(id)
}

pub fn virtual_screen() -> anyhow::Result<(i32, i32, i32, i32)> {
    screen()?.virtual_screen()
}

pub fn color_at(x: i32, y: i32) -> anyhow::Result<(u8, u8, u8)> {
    screen()?.color_at(x, y)
}

pub fn get_files() -> anyhow::Result<Vec<String>> {
    clip()?.get_files()
}

pub fn set_files(files: &[String]) -> anyhow::Result<()> {
    clip()?.set_files(files)
}

/// Clipboard change counter used by `wait {clipboard:true}`.
pub fn clipboard_seq() -> anyhow::Result<u32> {
    clip()?.seq()
}

/// Platform OCR engine (WinRT on Windows). The portable `ocrs` engine is
/// always available and lives above the seam — this is only the OS-provided
/// one, so a platform without it says so instead of silently substituting.
#[cfg(feature = "ctl-ocr")]
pub fn ocr_media(
    img: &image::RgbaImage,
    find: Option<&str>,
) -> anyhow::Result<crate::tools::computer::OcrOut> {
    #[cfg(windows)]
    {
        win32::ocr::recognize(img, find)
    }
    #[cfg(not(windows))]
    {
        let _ = (img, find);
        Err(unsupported("platform OCR engine (use engine=\"ocrs\")"))
    }
}

pub fn notify(title: Option<&str>, msg: &str) -> anyhow::Result<()> {
    backend()
        .notify()
        .ok_or_else(|| unsupported("desktop notifications"))?
        .notify(title, msg)
}

#[cfg(test)]
mod seam_guard {
    //! The seam is only real if nothing bypasses it. These sources are the
    //! portable half of the module; none of them may name an OS API or a
    //! backend module directly. Adding a portable file? Add it here too.

    const PORTABLE: &[(&str, &str)] = &[
        ("capture.rs", include_str!("../capture.rs")),
        ("find.rs", include_str!("../find.rs")),
        ("annotate.rs", include_str!("../annotate.rs")),
        ("safety.rs", include_str!("../safety.rs")),
        ("steps.rs", include_str!("../steps.rs")),
        ("wait.rs", include_str!("../wait.rs")),
        ("ocrs_local.rs", include_str!("../ocrs_local.rs")),
        ("server_input.rs", include_str!("../server_input.rs")),
        ("server_readonly.rs", include_str!("../server_readonly.rs")),
        ("server_misc.rs", include_str!("../server_misc.rs")),
        ("server_uia.rs", include_str!("../server_uia.rs")),
        ("driver/portable.rs", include_str!("portable.rs")),
    ];

    /// Imports that mean "this file talks to the OS behind the driver's back".
    const FORBIDDEN: &[&str] = &[
        "windows::",
        "uiautomation",
        "clipboard_win",
        "x11rb",
        "core_graphics",
        "objc2",
        "super::win::",
        "super::input::",
        "super::uia::",
        "super::notify::",
        "super::clip::",
        "driver::win32",
    ];

    #[test]
    fn portable_sources_reach_the_os_only_through_the_driver() {
        let mut sins = Vec::new();
        for (name, src) in PORTABLE {
            for (n, line) in src.lines().enumerate() {
                // Doc comments and prose legitimately mention these names.
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                for bad in FORBIDDEN {
                    if code.contains(bad) {
                        sins.push(format!("{name}:{}: {} -> {code}", n + 1, bad));
                    }
                }
            }
        }
        assert!(
            sins.is_empty(),
            "portable modules must go through `driver`, found:\n{}",
            sins.join("\n")
        );
    }
}
