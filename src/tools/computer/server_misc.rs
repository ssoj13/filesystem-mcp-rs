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
        description = "OCR a screen region, 100% local (no LLM tokens).\n\
            engine: \"media\" (default; Windows.Media.Ocr, Cyrillic OK) | \"ocrs\" (better Latin, models auto-download ~12 MB on first use).\n\
            target = capture target; find (case-insensitive) switches on bbox matches — click-by-text ladder."
    )]
    async fn ctl_ocr(
        &self,
        Parameters(OcrArgs { target, find, engine }): Parameters<OcrArgs>,
    ) -> Result<CallToolResult, McpError> {
        let res = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
            let cap = target.unwrap_or(super::capture::CapTarget::Monitor { monitor: 0 });
            let captured = super::capture::capture(cap)?;
            let img = image::open(&captured.path).map_err(|e| anyhow::anyhow!("open capture: {e}"))?.to_rgba8();
            let out = match engine.as_deref().unwrap_or("media") {
                "ocrs" => super::ocrs_local::recognize(&img, find.as_deref())?,
                "media" => super::ocr::recognize(&img, find.as_deref())?,
                other => anyhow::bail!("unknown engine {other:?} (media|ocrs)"),
            };
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
    /// \"media\" (default, Cyrillic-capable) | \"ocrs\" (better Latin).
    pub engine: Option<String>,
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
        tokio::task::spawn_blocking(move || super::driver::notify(title.as_deref(), &msg))
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
        let files = tokio::task::spawn_blocking(super::driver::get_files)
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
        tokio::task::spawn_blocking(move || super::driver::set_files(&files))
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
