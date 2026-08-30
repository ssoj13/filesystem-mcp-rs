//! Windows backend: SendInput, HWND window management, GDI pixels, WinRT
//! toasts, CF_HDROP clipboard, UI Automation.
//!
//! Everything Win32-specific in the computer module lives under this directory;
//! the layer above only ever sees the driver traits. The submodules are the
//! original implementation files, unchanged in behaviour — this `mod.rs` is the
//! adapter that presents them as `Backend`.
//!
//! Feature gates mirror the domains: a build with only `ctl-ocr` gets windows +
//! screen but no input, and `backend().input()` correctly answers `None`.

use crate::tools::computer::safety::SafetyGate;

use super::{
    Backend, Btn, ClipDrv, Ease, FocusInfo, InputDrv, KeyMod, NotifyDrv, ScreenDrv, TypeResult,
    WinDrv, WinInfo, WinQuery,
};

#[cfg(feature = "ctl-input")]
pub mod input;
#[cfg(any(feature = "ctl-input", feature = "ctl-uia", feature = "ctl-ocr"))]
pub mod win;

#[cfg(feature = "ctl-uia")]
pub mod uia;
#[cfg(feature = "ctl-ocr")]
pub mod ocr;
#[cfg(feature = "ctl-notify")]
pub mod notify;
#[cfg(feature = "ctl-clip-files")]
pub mod clip;

/// The Windows backend. Unit struct: all state lives in the OS.
pub struct Win32;

/// Window ids cross the seam as `u32`; on Windows that is the HWND value.
#[cfg(any(feature = "ctl-input", feature = "ctl-uia", feature = "ctl-ocr"))]
pub(crate) fn hwnd(id: u32) -> windows::Win32::Foundation::HWND {
    windows::Win32::Foundation::HWND(id as usize as *mut core::ffi::c_void)
}

impl Backend for Win32 {
    fn name(&self) -> &'static str {
        "win32"
    }

    /// The only backend exercised on real hardware so far (see driver/CLAUDE.md).
    fn verified_on_hardware(&self) -> bool {
        true
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

    /// Clipboard is one domain but two features: `wait {clipboard:true}` needs
    /// only the change counter (`ctl-input`), file lists need `ctl-clip-files`.
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

    fn has_ocr_media(&self) -> bool {
        cfg!(feature = "ctl-ocr")
    }
}

#[cfg(feature = "ctl-input")]
impl InputDrv for Win32 {
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
        let vks: Vec<_> = mods.iter().map(|m| vk_of(*m)).collect();
        input::click(gate, x, y, btn, clicks, &vks)
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
        input::cursor_pos().ok_or_else(|| anyhow::anyhow!("GetCursorPos failed"))
    }

    fn focus(&self) -> anyhow::Result<FocusInfo> {
        Ok(input::focus())
    }
}

/// Modifier -> virtual-key code. The mapping is Win32-specific, so it lives in
/// the backend rather than leaking VK codes into the portable enum.
#[cfg(feature = "ctl-input")]
fn vk_of(m: KeyMod) -> windows::Win32::UI::Input::KeyboardAndMouse::VIRTUAL_KEY {
    use windows::Win32::UI::Input::KeyboardAndMouse::VIRTUAL_KEY;
    match m {
        KeyMod::Ctrl => VIRTUAL_KEY(0x11),
        KeyMod::Alt => VIRTUAL_KEY(0x12),
        KeyMod::Shift => VIRTUAL_KEY(0x10),
        KeyMod::Win => VIRTUAL_KEY(0x5B),
    }
}

#[cfg(any(feature = "ctl-input", feature = "ctl-uia", feature = "ctl-ocr"))]
impl WinDrv for Win32 {
    fn list(&self, query: Option<WinQuery>) -> anyhow::Result<Vec<WinInfo>> {
        win::list_windows(query)
    }

    fn focus_window(&self, id: u32) -> anyhow::Result<()> {
        win::focus_window(hwnd(id))
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
        win::geom(hwnd(id), x, y, w, h, state)
    }

    fn close(&self, id: u32) -> anyhow::Result<()> {
        win::close(hwnd(id))
    }

    fn alive(&self, id: u32) -> bool {
        // SAFETY: plain window query (Option<HWND> per windows 0.62).
        unsafe { windows::Win32::UI::WindowsAndMessaging::IsWindow(Some(hwnd(id))) }.as_bool()
    }
}

#[cfg(feature = "ctl-input")]
impl ScreenDrv for Win32 {
    fn virtual_screen(&self) -> anyhow::Result<(i32, i32, i32, i32)> {
        Ok(win::virtual_screen())
    }

    fn color_at(&self, x: i32, y: i32) -> anyhow::Result<(u8, u8, u8)> {
        input::color_at(x, y)
    }
}

#[cfg(any(feature = "ctl-input", feature = "ctl-clip-files"))]
impl ClipDrv for Win32 {
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
        // SAFETY: parameterless counter query; never fails, 0 means "no access".
        Ok(unsafe { windows::Win32::System::DataExchange::GetClipboardSequenceNumber() })
    }
}

#[cfg(feature = "ctl-notify")]
impl NotifyDrv for Win32 {
    fn notify(&self, title: Option<&str>, msg: &str) -> anyhow::Result<()> {
        notify::notify(title, msg)
    }
}
