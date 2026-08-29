//! Read-only ctl tools: capture / monitors / win_list.
//!
//! Compiled when ANY of ctl-input | ctl-uia | ctl-ocr is on — these are passive
//! (no arm gate) and shared across domains; the methods are defined once and
//! their router merged whenever a domain needs them.

use rmcp::{
    ErrorData as McpError,
    handler::server::wrapper::Parameters,
    model::{CallToolResult},
    serde::Deserialize,
    tool, tool_router,
};
use schemars::JsonSchema;
use serde_json::json;

use super::{capture::{self, CapTarget}, ok_json, win::{self, WinQuery}};
use crate::FileSystemServer;

#[cfg(any(feature = "ctl-input", feature = "ctl-uia", feature = "ctl-ocr"))]
#[tool_router(router = ctl_readonly_router, vis = "pub(crate)")]
impl FileSystemServer {
    #[tool(
        name = "capture",
        description = "Capture screen to PNG (path + dhash64 + rect; never inline by default).\n\
            target: {monitor:n} | {win:id} | {rect:{x,y,w,h}} | {cursor:{size?400}} — square around the mouse.\n\
            Coordinates: virtual-screen physical px, negative origins allowed."
    )]
    async fn ctl_capture(
        &self,
        Parameters(CapArgs { target, inline }): Parameters<CapArgs>,
    ) -> Result<CallToolResult, McpError> {
        let target = target.unwrap_or(CapTarget::Monitor { monitor: 0 });
        let res = tokio::task::spawn_blocking(move || capture::capture(target))
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .map_err(super::ctl_err)?;
        let mut out = json!({ "path": res.path, "hash": res.hash, "rect": res.rect });
        if inline == Some(true) {
            let bytes = std::fs::read(&res.path).map_err(|e| McpError::internal_error(format!("read png: {e}"), None))?;
            out["b64_png"] = json!(base64_encode(&bytes));
        }
        ok_json(out)
    }

    #[tool(
        name = "monitors",
        description = "List monitors: id, name, rect (virtual-screen px), primary, scale."
    )]
    async fn ctl_monitors(&self) -> Result<CallToolResult, McpError> {
        let ms = tokio::task::spawn_blocking(capture::monitors)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .map_err(super::ctl_err)?;
        ok_json(json!({ "monitors": ms }))
    }

    #[tool(
        name = "win_list",
        description = "List visible windows: id(=HWND), title, exe, pid, rect, z-order, active flag.\n\
            query: {title?, exe?} case-insensitive substrings. Read-only, no arm needed."
    )]
    async fn ctl_win_list(
        &self,
        Parameters(ListArgs { query }): Parameters<ListArgs>,
    ) -> Result<CallToolResult, McpError> {
        let wins = tokio::task::spawn_blocking(move || win::list_windows(query))
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .map_err(super::ctl_err)?;
        ok_json(json!({ "wins": wins }))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CapArgs {
    /// What to capture (defaults to primary monitor).
    pub target: Option<CapTarget>,
    /// Include base64 PNG in the response (token-heavy, opt-in).
    pub inline: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListArgs {
    /// {title?, exe?} case-insensitive substrings.
    pub query: Option<WinQuery>,
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}
