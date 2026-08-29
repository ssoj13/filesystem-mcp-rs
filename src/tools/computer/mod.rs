//! Computer control: mouse, keyboard, windows, capture, UIA, OCR (Windows).
//!
//! A self-contained module designed to be extracted back into a standalone
//! crate if it ever outgrows this host. Extraction recipe (reverse vendoring):
//!
//! ```sh
//! cp -r src/tools/computer <new-crate>/src && mv <new-crate>/src/mod.rs <new-crate>/src/computer.rs
//! find <new-crate>/src -name '*.rs' -exec sed -i 's/\bsuper::/crate::/g' {} +
//! # then re-add the crate scaffolding (see git history of cglibs/computer-mcp-rs).
//! ```
//!
//! Feature map (Cargo.toml): `computer-tools` = umbrella over
//! `ctl-input` / `ctl-uia` / `ctl-ocr` / `ctl-notify` / `ctl-clip-files`.
//! MCP tool routing lives in `server_*.rs` — per-domain `#[tool_router]` impls
//! merged into the host router (rmcp cannot cfg-gate methods inside one impl).
//!
//! Safety: the arm gate (`safety::SafetyGate`) is compiled in with any ctl-*
//! feature; every input tool re-checks it per call. Coordinates are
//! virtual-screen physical px (multi-monitor, negative origins allowed).

// Input core: gate, mouse/keyboard, windows, macros, waits.
#[cfg(feature = "ctl-input")]
pub mod input;
#[cfg(any(
    feature = "ctl-input",
    feature = "ctl-uia",
    feature = "ctl-ocr",
    feature = "ctl-notify",
    feature = "ctl-clip-files"
))]
pub mod safety;
#[cfg(feature = "ctl-input")]
pub mod steps;
#[cfg(feature = "ctl-input")]
pub mod wait;
#[cfg(any(feature = "ctl-input", feature = "ctl-uia", feature = "ctl-ocr"))]
pub mod win;

// Passive capture extensions (cursor-anchor, dhash) — needs xcap/image.
#[cfg(any(feature = "ctl-input", feature = "ctl-ocr"))]
pub mod capture;

// Screen understanding + extras.
#[cfg(feature = "ctl-uia")]
pub mod uia;
#[cfg(feature = "ctl-ocr")]
pub mod ocr;
#[cfg(feature = "ctl-notify")]
pub mod notify;
#[cfg(feature = "ctl-clip-files")]
pub mod clip;

#[cfg(any(
    feature = "ctl-input",
    feature = "ctl-uia",
    feature = "ctl-ocr",
    feature = "ctl-notify",
    feature = "ctl-clip-files"
))]
/// Downcast CtlError for a stable wire code prefix (PLAN2.md §3 codes:
/// not_armed / op_cap / no_match / focus_failed). Shared by all server files.
#[cfg(any(
    feature = "ctl-input",
    feature = "ctl-uia",
    feature = "ctl-ocr",
    feature = "ctl-notify",
    feature = "ctl-clip-files"
))]
pub(crate) fn ctl_err(e: anyhow::Error) -> rmcp::ErrorData {
    if let Some(ctl) = e.downcast_ref::<safety::CtlError>() {
        rmcp::ErrorData::invalid_params(format!("{}: {ctl}", ctl.code()), None)
    } else {
        rmcp::ErrorData::internal_error(e.to_string(), None)
    }
}

/// MCP tool routing: per-domain routers merged into the host router (S1 spike
/// verdict: rmcp cannot cfg-gate methods inside one shared impl).
#[cfg(feature = "ctl-input")]
pub(crate) mod server_input;
#[cfg(any(feature = "ctl-input", feature = "ctl-uia", feature = "ctl-ocr"))]
pub(crate) mod server_readonly;
#[cfg(feature = "ctl-uia")]
pub(crate) mod server_uia;
#[cfg(any(feature = "ctl-ocr", feature = "ctl-notify", feature = "ctl-clip-files"))]
pub(crate) mod server_misc;

/// Shared response helper for the ctl server files: text + structured JSON.
/// Uses the host's private `WithStructured` trait (main.rs) to fill
/// structured_content — same wire shape as the rest of the fs server.
#[cfg(any(
    feature = "ctl-input",
    feature = "ctl-uia",
    feature = "ctl-ocr",
    feature = "ctl-notify",
    feature = "ctl-clip-files"
))]
pub(crate) fn ok_json(
    v: serde_json::Value,
) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
    use crate::WithStructured;
    use rmcp::model::{CallToolResult, ContentBlock};
    Ok(CallToolResult::success(vec![ContentBlock::text(v.to_string())]).with_structured(v))
}

/// Virtual-screen rectangle in physical pixels (may have negative origin).
#[cfg(any(
    feature = "ctl-input",
    feature = "ctl-uia",
    feature = "ctl-ocr"
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
}

#[cfg(any(
    feature = "ctl-input",
    feature = "ctl-uia",
    feature = "ctl-ocr"
))]
impl Rect {
    pub fn new(x: i32, y: i32, w: u32, h: u32) -> Self {
        Self { x, y, w, h }
    }

    /// Clamp a rect into `bounds`, returning `None` if it lies entirely outside.
    pub fn clamp_into(&self, bounds: &Rect) -> Option<Rect> {
        let x1 = self.x.max(bounds.x);
        let y1 = self.y.max(bounds.y);
        let x2 = (self.x + self.w as i32).min(bounds.x + bounds.w as i32);
        let y2 = (self.y + self.h as i32).min(bounds.y + bounds.h as i32);
        if x2 <= x1 || y2 <= y1 {
            return None;
        }
        Some(Rect::new(x1, y1, (x2 - x1) as u32, (y2 - y1) as u32))
    }
}

/// Make the process per-monitor-v2 DPI aware.
///
/// Must run before any window/capture work. When a host app that embeds this
/// code already fixed awareness, the setter fails with E_ACCESSDENIED — that is
/// acceptable as long as the host chose SOME aware context (critic §10.4), so
/// we query the actual context and succeed; only a truly DPI-unaware process
/// is an error, because clicks/captures would land misaligned.
#[cfg(any(
    feature = "ctl-input",
    feature = "ctl-uia",
    feature = "ctl-ocr"
))]
pub fn ensure_dpi_aware() -> anyhow::Result<()> {
    use windows::Win32::UI::HiDpi::{
        AreDpiAwarenessContextsEqual, GetThreadDpiAwarenessContext, DPI_AWARENESS_CONTEXT,
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
        DPI_AWARENESS_CONTEXT_SYSTEM_AWARE, SetProcessDpiAwarenessContext,
    };

    let want = DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2;
    // SAFETY: plain Win32 DPI setters; no invariants beyond thread safety.
    if unsafe { SetProcessDpiAwarenessContext(want) }.is_ok() {
        return Ok(());
    }
    // Setter refused: awareness already fixed for this process. Thread-scoped
    // query is enough for the host-already-aware check (per-process getter
    // was dropped in windows 0.62).
    let actual = unsafe { GetThreadDpiAwarenessContext() };
    let eq = |c: DPI_AWARENESS_CONTEXT| unsafe { AreDpiAwarenessContextsEqual(actual, c) }.as_bool();
    if eq(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)
        || eq(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE)
        || eq(DPI_AWARENESS_CONTEXT_SYSTEM_AWARE)
    {
        tracing::debug!("DPI awareness already fixed by host (per-monitor/system aware)");
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "process DPI awareness is fixed to a non-aware context; input/capture would misalign"
        ))
    }
}

#[cfg(all(test, windows, feature = "ctl-input"))]
mod tests;
