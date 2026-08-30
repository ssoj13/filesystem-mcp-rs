//! ctl-uia server: ui / ui_click / ui_set (Windows UI Automation).
//!
//! Compiled under `ctl-uia`; ui_click's synthesized-click fallback needs the
//! arm gate, so the gate field exists when ctl-uia is on even without ctl-input.

use rmcp::{
    ErrorData as McpError,
    handler::server::wrapper::Parameters,
    model::{CallToolResult},
    serde::Deserialize,
    tool, tool_router,
};
use schemars::JsonSchema;
use serde_json::json;

use super::{ok_json, uia, win::WinTarget};
use crate::FileSystemServer;

#[cfg(feature = "ctl-uia")]
#[tool_router(router = ctl_uia_router, vis = "pub(crate)")]
impl FileSystemServer {
    #[tool(
        name = "ui",
        description = "UI Automation element list for a window (target | active): name, auto_id, role,\n\
            class, patterns, toggle state, value, rect, enabled, offscreen.\n\
            query filters names case-insensitively; max caps output (server-side filter is mandatory)."
    )]
    async fn ctl_ui(
        &self,
        Parameters(UiArgs { target, query, depth, max }): Parameters<UiArgs>,
    ) -> Result<CallToolResult, McpError> {
        let elems = tokio::task::spawn_blocking(move || {
            uia::tree(target, query, depth.unwrap_or(6), max.unwrap_or(50).min(200) as usize)
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(super::ctl_err)?;
        ok_json(json!({ "elems": elems }))
    }

    #[tool(
        name = "ui_click",
        description = "Click a UI element by name or automation id. Pattern-aware: Invoke -> Toggle ->\n\
            ExpandCollapse -> SelectionItem -> synthesized click fallback; offscreen elements are\n\
            scrolled into view first. Most reliable click path: UIA -> OCR -> pixels. Requires arm."
    )]
    async fn ctl_ui_click(
        &self,
        Parameters(UiClickArgs { target, name, idx }): Parameters<UiClickArgs>,
    ) -> Result<CallToolResult, McpError> {
        let gate = super::safety::gate();
        let res = tokio::task::spawn_blocking(move || {
            uia::click(&gate, target, &name, idx.unwrap_or(0))
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(super::ctl_err)?;
        ok_json(res)
    }

    #[tool(
        name = "ui_get",
        description = "Read one UI element's full state by name or automation id: name, role, auto_id,\n\
            class, patterns, toggle state, value, rect, enabled, offscreen, total matches.\n\
            The \"look before acting\" for UIA. No arm needed."
    )]
    async fn ctl_ui_get(
        &self,
        Parameters(UiClickArgs { target, name, idx }): Parameters<UiClickArgs>,
    ) -> Result<CallToolResult, McpError> {
        let res = tokio::task::spawn_blocking(move || uia::get(target, &name, idx.unwrap_or(0)))
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .map_err(super::ctl_err)?;
        ok_json(res)
    }

    #[tool(
        name = "ui_set",
        description = "Set an element's value via the UIA Value pattern (text fields, toggles).\n\
            Requires a target window; name selects the element."
    )]
    async fn ctl_ui_set(
        &self,
        Parameters(UiSetArgs { target, name, idx, value }): Parameters<UiSetArgs>,
    ) -> Result<CallToolResult, McpError> {
        tokio::task::spawn_blocking(move || uia::set_value(Some(target), &name, idx.unwrap_or(0), &value))
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .map_err(super::ctl_err)?;
        ok_json(json!({}))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UiArgs {
    /// Window to enumerate (defaults to the active one).
    pub target: Option<WinTarget>,
    /// Case-insensitive name substring filter.
    pub query: Option<String>,
    /// Tree depth (default 6).
    pub depth: Option<u32>,
    /// Result cap (default 50, hard max 200).
    pub max: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UiClickArgs {
    pub target: Option<WinTarget>,
    /// Element name (case-insensitive substring).
    pub name: String,
    /// Match index (default 0).
    pub idx: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UiSetArgs {
    pub target: WinTarget,
    pub name: String,
    pub idx: Option<usize>,
    pub value: String,
}
