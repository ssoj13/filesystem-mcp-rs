//! Read-only ctl tools: capture / monitors / color / find_image / annotate /
//! ctl_caps / win_list.
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

use super::{annotate::{self, Shape}, capture::{self, CapTarget}, driver::{self, WinQuery}, ok_json};
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
        name = "color",
        description = "Screen pixel color at x,y (virtual-screen px). Read-only, no arm.\n\
            Returns {rgb:[r,g,b], hex}."
    )]
    async fn color(
        &self,
        Parameters(ColorArgs { x, y }): Parameters<ColorArgs>,
    ) -> Result<CallToolResult, McpError> {
        let rgb = tokio::task::spawn_blocking(move || super::driver::color_at(x, y))
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .map_err(super::ctl_err)?;
        let hex = format!("#{:02x}{:02x}{:02x}", rgb.0, rgb.1, rgb.2);
        ok_json(json!({ "rgb": [rgb.0, rgb.1, rgb.2], "hex": hex }))
    }

    #[tool(
        name = "find_image",
        description = "Find a template image inside a screen capture (UIA -> OCR -> template -> pixels ladder).\n\
            template: PNG path (capture a small unique element first), target: where to search.\n\
            threshold: 0.5..=1.0 (default 0.85). Returns {found, matches:[{x,y,w,h,score}]} —\n\
            screen-space coords ready for mouse_click. Fixed-scale (same-DPI) matching."
    )]
    async fn find_image(
        &self,
        Parameters(FindArgs { template, target, threshold, max }): Parameters<FindArgs>,
    ) -> Result<CallToolResult, McpError> {
        let res = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
            let cap = target.unwrap_or(CapTarget::Monitor { monitor: 0 });
            let captured = super::capture::capture(cap)?;
            let scene = image::open(&captured.path).map_err(|e| anyhow::anyhow!("open capture: {e}"))?.to_rgba8();
            let tpl = image::open(&template).map_err(|e| anyhow::anyhow!("open template: {e}"))?.to_rgba8();
            let thr = threshold.unwrap_or(0.85);
            let matches = super::find::find_template(&scene, &tpl, thr, max.unwrap_or(5).max(1) as usize)?;
            // Screen-space: add the capture rect origin.
            let ox = captured.rect.x;
            let oy = captured.rect.y;
            let matches: Vec<_> = matches
                .into_iter()
                .map(|mut m| {
                    m.x += ox;
                    m.y += oy;
                    m
                })
                .collect();
            Ok(serde_json::json!({
                "found": !matches.is_empty(),
                "capture_rect": captured.rect,
                "matches": matches,
            }))
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(super::ctl_err)?;
        ok_json(res)
    }

    #[tool(
        name = "annotate",
        description = "Draw boxes/markers/labels onto a screenshot and save a new PNG.\n\
            Verification tool: ui/find_image/ocr return rects, this shows WHERE they landed\n\
            before you click. Source: src (existing PNG) OR target (capture first, default\n\
            primary monitor) — not both.\n\
            shapes: [{x,y,w?,h?,label?,color?}] — rect when w+h given, else a crosshair.\n\
            origin: image top-left in the shapes' coordinate space; defaults to the capture\n\
            rect origin (so screen coords work as-is) or {0,0} for a supplied src.\n\
            Returns {path, w, h, drawn, outside:[idx]} — shapes off the image are reported."
    )]
    async fn ctl_annotate(
        &self,
        Parameters(AnnArgs { src, target, origin, shapes, out, scale }): Parameters<AnnArgs>,
    ) -> Result<CallToolResult, McpError> {
        let res = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
            if src.is_some() && target.is_some() {
                return Err(anyhow::anyhow!("pass src OR target, not both"));
            }
            // Screen coords line up with the image only if we know its origin,
            // so a fresh capture defaults the origin to its own rect.
            let (path, default_origin) = match src {
                Some(p) => (p, (0, 0)),
                None => {
                    let cap = capture::capture(target.unwrap_or(CapTarget::Monitor { monitor: 0 }))?;
                    (cap.path, (cap.rect.x, cap.rect.y))
                }
            };
            let org = origin.map_or(default_origin, |p| (p.x, p.y));
            let mut img = image::open(&path)
                .map_err(|e| anyhow::anyhow!("open {path}: {e}"))?
                .to_rgba8();
            let outside = annotate::draw(&mut img, org, &shapes, scale.unwrap_or(2))?;
            let out = out.map_or_else(annotate::out_path, std::path::PathBuf::from);
            if let Some(dir) = out.parent() {
                std::fs::create_dir_all(dir)?;
            }
            img.save_with_format(&out, image::ImageFormat::Png)?;
            Ok(serde_json::json!({
                "path": out.display().to_string(),
                "w": img.width(),
                "h": img.height(),
                "origin": { "x": org.0, "y": org.1 },
                "drawn": shapes.len() - outside.len(),
                "outside": outside,
            }))
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(super::ctl_err)?;
        ok_json(res)
    }

    #[tool(
        name = "ctl_caps",
        description = "Capability map of the active platform driver: which ctl domains are real\n\
            on this OS (input/window/uia/ocr_media/clip_files/notify/capture/ocr_ocrs).\n\
            Read-only, no arm. Use it to adapt automation plans per platform."
    )]
    async fn ctl_caps(&self) -> Result<CallToolResult, McpError> {
        ok_json(serde_json::to_value(super::driver::caps()).map_err(|e| McpError::internal_error(e.to_string(), None))?)
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
        let wins = tokio::task::spawn_blocking(move || driver::list_windows(query))
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

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindArgs {
    /// PNG path of the template to search for.
    pub template: String,
    /// Where to search (default primary monitor).
    pub target: Option<CapTarget>,
    /// Score threshold 0.5..=1.0 (default 0.85).
    pub threshold: Option<f32>,
    /// Max matches (default 5).
    pub max: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AnnArgs {
    /// Existing PNG to annotate (mutually exclusive with `target`).
    pub src: Option<String>,
    /// Capture this first, then annotate it (default primary monitor).
    pub target: Option<CapTarget>,
    /// Image top-left in the shapes' coordinate space (see tool description).
    pub origin: Option<Pt>,
    /// Shapes to draw.
    pub shapes: Vec<Shape>,
    /// Output PNG path (default: a fresh file next to the captures).
    pub out: Option<String>,
    /// Label text scale, 1..=8 (default 2).
    pub scale: Option<u32>,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
pub struct Pt {
    pub x: i32,
    pub y: i32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ColorArgs {
    pub x: i32,
    pub y: i32,
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}
