//! ctl-ocr server: ocr tool (Windows.Media.Ocr, offline).
//!
//! Compiled under `ctl-ocr`; captures via the shared capture module and runs
//! Windows.Media.Ocr with optional bbox `find` (click-by-text ladder:
//! UIA -> OCR -> pixels).

use rmcp::{
    ErrorData as McpError,
    handler::server::wrapper::Parameters,
    model::{CallToolResult},
    serde::Deserialize,
    tool, tool_router,
};
use schemars::JsonSchema;
use serde_json::json;

use super::ok_json;
#[cfg(feature = "ctl-ocr")]
use super::capture::CapTarget;
use crate::FileSystemServer;

#[cfg(feature = "ctl-ocr")]
#[tool_router(router = ctl_ocr_router, vis = "pub(crate)")]
impl FileSystemServer {
    #[tool(
        name = "ocr",
        description = "OCR a screen region (Windows.Media.Ocr, offline). target = capture target.\n\
            find (case-insensitive) switches on bbox matches — click-by-text: ocr -> mouse_click.\n\
            No per-word confidence exists in WinRT OCR. Missing language pack = explicit error."
    )]
    async fn ctl_ocr(
        &self,
        Parameters(OcrArgs { target, find }): Parameters<OcrArgs>,
    ) -> Result<CallToolResult, McpError> {
        let res = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
            let cap = target.unwrap_or(super::capture::CapTarget::Monitor { monitor: 0 });
            let captured = super::capture::capture(cap)?;
            let img = image::open(&captured.path).map_err(|e| anyhow::anyhow!("open capture: {e}"))?;
            let out = super::ocr::recognize(&img.to_rgba8(), find.as_deref())?;
            Ok(serde_json::to_value(&out)?)
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(super::ctl_err)?;
        ok_json(res)
    }
}

#[cfg(feature = "ctl-ocr")]
#[derive(Debug, Deserialize, JsonSchema)]
pub struct OcrArgs {
    /// Capture target (default primary monitor).
    pub target: Option<CapTarget>,
    /// Case-insensitive substring to match lines (returns bbox matches).
    pub find: Option<String>,
}

// ---- server_misc: notify (ctl-notify) + clipboard files (ctl-clip-files) ----

#[cfg(feature = "ctl-notify")]
#[tool_router(router = ctl_notify_router, vis = "pub(crate)")]
impl FileSystemServer {
    #[tool(
        name = "notify",
        description = "Windows toast notification — a \"needs human\" signal. No arm needed."
    )]
    async fn ctl_notify(
        &self,
        Parameters(NotifyArgs { title, msg }): Parameters<NotifyArgs>,
    ) -> Result<CallToolResult, McpError> {
        tokio::task::spawn_blocking(move || super::notify::notify(title.as_deref(), &msg))
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .map_err(super::ctl_err)?;
        ok_json(json!({}))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct NotifyArgs {
    pub title: Option<String>,
    pub msg: String,
}

#[cfg(feature = "ctl-clip-files")]
#[tool_router(router = ctl_clip_router, vis = "pub(crate)")]
impl FileSystemServer {
    #[tool(
        name = "clip_files_get",
        description = "Read the file list (CF_HDROP) currently on the clipboard."
    )]
    async fn ctl_clip_files_get(&self) -> Result<CallToolResult, McpError> {
        let files = tokio::task::spawn_blocking(super::clip::get_files)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .map_err(super::ctl_err)?;
        ok_json(json!({ "files": files }))
    }

    #[tool(
        name = "clip_files_set",
        description = "Put a file list (CF_HDROP) on the clipboard — paste into Explorer/apps."
    )]
    async fn ctl_clip_files_set(
        &self,
        Parameters(FilesArgs { files }): Parameters<FilesArgs>,
    ) -> Result<CallToolResult, McpError> {
        tokio::task::spawn_blocking(move || super::clip::set_files(&files))
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .map_err(super::ctl_err)?;
        ok_json(json!({}))
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FilesArgs {
    pub files: Vec<String>,
}
