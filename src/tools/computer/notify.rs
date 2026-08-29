//! Windows toast notifications (PLAN2.md §3 `notify`).
//!
//! GOTCHA (PLAN2.md §2): an unpackaged exe has no AUMID of its own — toasts
//! silently vanish unless we borrow an installed AUMID. We reuse PowerShell's,
//! which is present on stock Windows 10/11.

const BORROWED_AUMID: &str = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe";

/// Show a toast. Blocking (WinRT .get()); call from spawn_blocking.
pub fn notify(title: Option<&str>, msg: &str) -> anyhow::Result<()> {
    let title = title.unwrap_or("computer-mcp-rs");
    tauri_winrt_notification::Toast::new(BORROWED_AUMID)
        .title(title)
        .text1(msg)
        .show()
        .map_err(|e| anyhow::anyhow!("toast: {e}"))
}
