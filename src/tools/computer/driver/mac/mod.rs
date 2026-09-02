//! macOS backend: CGEvent input, CGWindowList + AX windows, CGDisplay screen,
//! NSPasteboard clipboard, UserNotifications toasts, Accessibility UI tree.
//!
//! Permissions (System Settings → Privacy & Security):
//! - **Accessibility** — input injection, AX focus/geometry/ui_* tools
//! - **Screen Recording** — real window titles from CGWindowList (optional; synthetic ids otherwise)
//! - **Notifications** — `notify` tool

use crate::tools::computer::safety::SafetyGate;

use super::{
    Backend, Btn, ClipDrv, Ease, FocusInfo, InputDrv, KeyMod, NotifyDrv, ScreenDrv, TypeResult,
    WinDrv, WinInfo, WinQuery,
};

#[cfg(feature = "ctl-input")]
pub mod input;
#[cfg(any(feature = "ctl-input", feature = "ctl-uia", feature = "ctl-ocr"))]
pub mod win;
#[cfg(feature = "ctl-input")]
pub mod screen;
#[cfg(any(feature = "ctl-input", feature = "ctl-clip-files"))]
pub mod clip;
#[cfg(feature = "ctl-notify")]
pub mod notify;
#[cfg(feature = "ctl-uia")]
pub mod uia;

#[cfg(any(feature = "ctl-input", feature = "ctl-uia", feature = "ctl-ocr"))]
mod ax;

/// The macOS backend.
pub struct Mac;

/// Whether Accessibility is granted to this process.
pub fn accessibility_granted() -> bool {
    ax::is_trusted()
}

/// Loud error when Accessibility is missing.
pub fn require_accessibility() -> anyhow::Result<()> {
    ax::require_trusted()
}

impl Backend for Mac {
    fn name(&self) -> &'static str {
        "mac"
    }

    /// Flip to `true` after live canaries pass on real hardware with permissions granted.
    fn verified_on_hardware(&self) -> bool {
        false
    }

    fn input(&self) -> Option<&dyn InputDrv> {
        #[cfg(feature = "ctl-input")]
        {
            Some(self)
        }
        #[cfg(not(feature = "ctl-input"))]
        {
            None
        }
    }

    fn win(&self) -> Option<&dyn WinDrv> {
        #[cfg(any(feature = "ctl-input", feature = "ctl-uia", feature = "ctl-ocr"))]
        {
            Some(self)
        }
        #[cfg(not(any(feature = "ctl-input", feature = "ctl-uia", feature = "ctl-ocr")))]
        {
            None
        }
    }

    fn screen(&self) -> Option<&dyn ScreenDrv> {
        #[cfg(feature = "ctl-input")]
        {
            Some(self)
        }
        #[cfg(not(feature = "ctl-input"))]
        {
            None
        }
    }

    fn clip(&self) -> Option<&dyn ClipDrv> {
        #[cfg(any(feature = "ctl-input", feature = "ctl-clip-files"))]
        {
            Some(self)
        }
        #[cfg(not(any(feature = "ctl-input", feature = "ctl-clip-files")))]
        {
            None
        }
    }

    fn notify(&self) -> Option<&dyn NotifyDrv> {
        #[cfg(feature = "ctl-notify")]
        {
            Some(self)
        }
        #[cfg(not(feature = "ctl-notify"))]
        {
            None
        }
    }

    fn has_uia(&self) -> bool {
        cfg!(feature = "ctl-uia")
    }
}

#[cfg(feature = "ctl-input")]
impl InputDrv for Mac {
    fn move_cursor(&self, x: i32, y: i32) -> anyhow::Result<FocusInfo> {
        input::move_cursor(x, y)
    }

    fn click(
        &self,
        gate: &SafetyGate,
        x: Option<i32>,
        y: Option<i32>,
        btn: Btn,
        clicks: u32,
        mods: &[KeyMod],
    ) -> anyhow::Result<FocusInfo> {
        input::click(gate, x, y, btn, clicks, mods)
    }

    fn drag(
        &self,
        gate: &SafetyGate,
        from: (i32, i32),
        to: (i32, i32),
        btn: Btn,
        duration_ms: u32,
        ease: Ease,
        hold_ms: u32,
    ) -> anyhow::Result<FocusInfo> {
        input::drag(gate, from, to, btn, duration_ms, ease, hold_ms)
    }

    fn scroll(&self, gate: &SafetyGate, dy: i32, dx: i32) -> anyhow::Result<FocusInfo> {
        input::scroll(gate, dy, dx)
    }

    fn key_tap(&self, gate: &SafetyGate, combo: &str, hold_ms: u32) -> anyhow::Result<FocusInfo> {
        input::key_tap(gate, combo, hold_ms)
    }

    fn type_text(
        &self,
        gate: &SafetyGate,
        text: &str,
        paste: bool,
        interval_ms: u32,
        expect: Option<u32>,
    ) -> anyhow::Result<TypeResult> {
        input::type_text(gate, text, paste, interval_ms, expect)
    }

    fn cursor_pos(&self) -> anyhow::Result<(i32, i32)> {
        input::cursor_pos()
    }

    fn focus(&self) -> anyhow::Result<FocusInfo> {
        Ok(input::focus())
    }
}

#[cfg(any(feature = "ctl-input", feature = "ctl-uia", feature = "ctl-ocr"))]
impl WinDrv for Mac {
    fn list(&self, query: Option<WinQuery>) -> anyhow::Result<Vec<WinInfo>> {
        win::list_windows(query)
    }

    fn focus_window(&self, id: u32) -> anyhow::Result<()> {
        win::focus_window(id)
    }

    fn geom(
        &self,
        id: u32,
        x: Option<i32>,
        y: Option<i32>,
        w: Option<i32>,
        h: Option<i32>,
        state: Option<&str>,
    ) -> anyhow::Result<WinInfo> {
        win::geom(id, x, y, w, h, state)
    }

    fn close(&self, id: u32) -> anyhow::Result<()> {
        win::close(id)
    }

    fn alive(&self, id: u32) -> bool {
        win::alive(id)
    }
}

#[cfg(feature = "ctl-input")]
impl ScreenDrv for Mac {
    fn virtual_screen(&self) -> anyhow::Result<(i32, i32, i32, i32)> {
        screen::virtual_screen()
    }

    fn color_at(&self, x: i32, y: i32) -> anyhow::Result<(u8, u8, u8)> {
        screen::color_at(x, y)
    }
}

#[cfg(any(feature = "ctl-input", feature = "ctl-clip-files"))]
impl ClipDrv for Mac {
    fn get_files(&self) -> anyhow::Result<Vec<String>> {
        #[cfg(feature = "ctl-clip-files")]
        {
            clip::get_files()
        }
        #[cfg(not(feature = "ctl-clip-files"))]
        {
            Err(super::unsupported("clipboard file lists (build without ctl-clip-files)"))
        }
    }

    fn set_files(&self, files: &[String]) -> anyhow::Result<()> {
        #[cfg(feature = "ctl-clip-files")]
        {
            clip::set_files(files)
        }
        #[cfg(not(feature = "ctl-clip-files"))]
        {
            let _ = files;
            Err(super::unsupported("clipboard file lists (build without ctl-clip-files)"))
        }
    }

    fn seq(&self) -> anyhow::Result<u32> {
        clip::seq()
    }
}

#[cfg(feature = "ctl-notify")]
impl NotifyDrv for Mac {
    fn notify(&self, title: Option<&str>, msg: &str) -> anyhow::Result<()> {
        notify::notify(title, msg)
    }
}
