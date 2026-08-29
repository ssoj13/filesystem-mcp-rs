//! ctl-input domain server: arm gate + mouse/keyboard + window management + macros/waits.
//!
//! One cfg-gated `#[tool_router]` impl per DOMAIN (rmcp cannot cfg-gate methods
//! inside a shared impl — S1 spike), merged into the host router in
//! `FileSystemServer::new()`. Every acting tool re-checks the arm gate.

use rmcp::{
    ErrorData as McpError,
    handler::server::wrapper::Parameters,
    model::{CallToolResult},
    serde::Deserialize,
    tool, tool_router,
};
use schemars::JsonSchema;
use serde_json::json;

use super::{
    capture::CapTarget,
    input::{self, Btn},
    ok_json,
    win::{self, WinTarget},
};
use crate::FileSystemServer;

#[cfg(feature = "ctl-input")]
#[tool_router(router = ctl_input_router, vis = "pub(crate)")]
impl FileSystemServer {
    #[tool(
        name = "arm",
        description = "Arm the input-safety gate (REQUIRED before mouse_*/key_*/win_focus/win_geom/win_close/win_layout).\n\
            TTL auto-expires (default 30000 ms); returns {armed_until} epoch ms. Re-arm per burst."
    )]
    async fn ctl_arm(
        &self,
        Parameters(ArmArgs { ttl_ms }): Parameters<ArmArgs>,
    ) -> Result<CallToolResult, McpError> {
        let ttl = std::time::Duration::from_millis(
            super::safety::resolve_arm_ttl_ms(ttl_ms) as u64,
        );
        let until = super::safety::gate().arm(ttl);
        ok_json(json!({ "armed_until": until }))
    }

    #[tool(
        name = "mouse_click",
        description = "Click at x,y (virtual-screen px; omit both to click at the current cursor).\n\
            button: left|right|middle; clicks: 0 = hover only, 2 = double-click. Requires arm.\n\
            Returns {focus} — catches focus loss for free."
    )]
    async fn ctl_mouse_click(
        &self,
        Parameters(ClickArgs { x, y, button, clicks }): Parameters<ClickArgs>,
    ) -> Result<CallToolResult, McpError> {
        let btn = parse_btn(button.as_deref())?;
        let gate = super::safety::gate();
        let focus = tokio::task::spawn_blocking(move || {
            input::click(&gate, x, y, btn, clicks.unwrap_or(1))
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(ctl_err)?;
        ok_json(json!({ "focus": focus }))
    }

    #[tool(
        name = "mouse_drag",
        description = "Drag from {x,y} to {x,y} with an interpolated path (drag&drop, marquee).\n\
            button: left|right|middle; steps: interpolation count (default 10). Requires arm."
    )]
    async fn ctl_mouse_drag(
        &self,
        Parameters(DragArgs { from, to, button, steps }): Parameters<DragArgs>,
    ) -> Result<CallToolResult, McpError> {
        let btn = parse_btn(button.as_deref())?;
        let gate = super::safety::gate();
        let focus = tokio::task::spawn_blocking(move || {
            input::drag(&gate, (from.x, from.y), (to.x, to.y), btn, steps.unwrap_or(10))
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(ctl_err)?;
        ok_json(json!({ "focus": focus }))
    }

    #[tool(
        name = "mouse_scroll",
        description = "Wheel scroll: dy > 0 = down, dx > 0 = right (wheel units). Requires arm.\n\
            Returns {focus}."
    )]
    async fn ctl_mouse_scroll(
        &self,
        Parameters(ScrollArgs { dy, dx }): Parameters<ScrollArgs>,
    ) -> Result<CallToolResult, McpError> {
        let gate = super::safety::gate();
        let focus = tokio::task::spawn_blocking(move || input::scroll(&gate, dy, dx.unwrap_or(0)))
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .map_err(ctl_err)?;
        ok_json(json!({ "focus": focus }))
    }

    #[tool(
        name = "key_tap",
        description = "Press a combo like \"ctrl+shift+t\" (VK codes, layout-independent; f1..f24,\n\
            enter/tab/esc/arrows/home/end/pgup/pgdn/del/ins). hold_ms holds the main key.\n\
            Requires arm. Returns {focus}."
    )]
    async fn ctl_key_tap(
        &self,
        Parameters(TapArgs { key, hold_ms }): Parameters<TapArgs>,
    ) -> Result<CallToolResult, McpError> {
        let gate = super::safety::gate();
        let focus = tokio::task::spawn_blocking(move || {
            input::key_tap(&gate, &key, hold_ms.unwrap_or(0))
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(ctl_err)?;
        ok_json(json!({ "focus": focus }))
    }

    #[tool(
        name = "key_type",
        description = "Type text into the focused window. paste=true (default): clipboard roundtrip\n\
            (save -> set -> ctrl+v -> restore) — fast and Unicode-safe; REFUSED if focus moved from\n\
            `target` when given. paste=false: per-char KEYEVENTF_UNICODE. Requires arm."
    )]
    async fn ctl_key_type(
        &self,
        Parameters(TypeArgs { text, paste, interval_ms, target }): Parameters<TypeArgs>,
    ) -> Result<CallToolResult, McpError> {
        let gate = super::safety::gate();
        // Mode/interval: explicit arg > FS_MCP_CTL_TYPE_MODE/INTERVAL_MS env > defaults.
        let paste = super::safety::resolve_paste(paste).map_err(super::ctl_err)?;
        let interval = super::safety::resolve_interval_ms(interval_ms, paste)
            .map_err(super::ctl_err)?;
        // Focus gate for paste: resolve the target window first so the paste
        // can never land in a wrong app (critic §10.2).
        let expect = match target {
            Some(t) => {
                let hwnd_id = tokio::task::spawn_blocking(move || {
                    win::resolve_target(&t).map(|h| h.0 as u32)
                })
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?
                .map_err(ctl_err)?;
                Some(hwnd_id)
            }
            None => None,
        };
        let res = tokio::task::spawn_blocking(move || {
            input::type_text(&gate, &text, paste, interval, expect)
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(ctl_err)?;
        ok_json(json!({
            "mode": res.mode, "chars": res.chars, "interval_ms": interval,
            "clipboard_restored": res.clipboard_restored, "focus": res.focus,
        }))
    }

    #[tool(
        name = "win_focus",
        description = "Focus a window (target: {id}|{title}|{exe}) and VERIFY foreground\n\
            (restore -> SetForegroundWindow -> ALT-trick fallback, PLAN2.md §6.1).\n\
            Requires arm. Returns {win: WinInfo}."
    )]
    async fn ctl_win_focus(
        &self,
        Parameters(FocusArgs { target }): Parameters<FocusArgs>,
    ) -> Result<CallToolResult, McpError> {
        let gate = super::safety::gate();
        let res = tokio::task::spawn_blocking(move || -> anyhow::Result<win::WinInfo> {
            let hwnd = win::resolve_target(&target)?;
            gate.check()?;
            win::focus_window(hwnd)?;
            win::list_windows(Some(win::WinQuery::default()))?
                .into_iter()
                .find(|w| w.id == hwnd.0 as u32)
                .ok_or_else(|| anyhow::anyhow!("focused window vanished"))
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(ctl_err)?;
        ok_json(json!({ "win": res }))
    }

    #[tool(
        name = "win_geom",
        description = "Move/resize (x,y,w,h — all four) and/or set state (min|max|restore). Requires arm.\n\
            Returns fresh geometry."
    )]
    async fn ctl_win_geom(
        &self,
        Parameters(GeomArgs { target, x, y, w, h, state }): Parameters<GeomArgs>,
    ) -> Result<CallToolResult, McpError> {
        let gate = super::safety::gate();
        let res = tokio::task::spawn_blocking(move || {
            gate.check()?;
            let hwnd = win::resolve_target(&target)?;
            win::geom(hwnd, x, y, w, h, state.as_deref())
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(ctl_err)?;
        ok_json(json!({ "win": res }))
    }

    #[tool(
        name = "win_close",
        description = "Gracefully close a window (WM_CLOSE + 1 s verify). SEPARATE tool name so per-tool\n\
            allowlists can exclude it. Requires arm."
    )]
    async fn ctl_win_close(
        &self,
        Parameters(FocusArgs { target }): Parameters<FocusArgs>,
    ) -> Result<CallToolResult, McpError> {
        let gate = super::safety::gate();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            gate.check()?;
            let hwnd = win::resolve_target(&target)?;
            win::close(hwnd)?;
            gate.record("win_close", json!({ "target": target }))?;
            Ok(())
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(ctl_err)?;
        ok_json(json!({}))
    }

    #[tool(
        name = "win_layout",
        description = "Save/restore positions of all visible windows (name identifies the snapshot).\n\
            op: save|load; load applies unless dry_run=true. Per-window applied flags — HWND-bound:\n\
            windows reopened since the save report applied=false. Requires arm."
    )]
    async fn ctl_win_layout(
        &self,
        Parameters(LayoutArgs { op, name, dry_run }): Parameters<LayoutArgs>,
    ) -> Result<CallToolResult, McpError> {
        let gate = super::safety::gate();
        let res = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
            match op.as_str() {
                "save" => {
                    let entries = win::layout_save(&name)?;
                    gate.record("win_layout_save", json!({ "name": name, "windows": entries.len() }))?;
                    Ok(json!({ "saved": entries }))
                }
                "load" => {
                    let applied = win::layout_load(&name, dry_run.unwrap_or(false))?;
                    gate.record("win_layout_load", json!({ "name": name, "dry_run": dry_run }))?;
                    Ok(json!({ "applied": applied }))
                }
                other => Err(anyhow::anyhow!("unknown op {other:?} (save|load)")),
            }
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(ctl_err)?;
        ok_json(res)
    }

    #[tool(
        name = "input_macro",
        description = "Execute a sequence of input/capture/wait steps in ONE round trip (the latency saver).\n\
            Steps: {t:move|click|drag|scroll|key|type|wait|wait_screen|capture|focus, ...}. Fail-fast,\\\n\
            per-step arm re-check, caps: 40 steps / 30 s. Requires arm. Returns index-aligned results."
    )]
    async fn ctl_input_macro(
        &self,
        Parameters(MacroArgs { steps, gap_ms, stop_on_fail }): Parameters<MacroArgs>,
    ) -> Result<CallToolResult, McpError> {
        let gate = super::safety::gate();
        let res = tokio::task::spawn_blocking(move || {
            super::steps::run(&gate, &steps, gap_ms.unwrap_or(30), stop_on_fail.unwrap_or(true))
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(ctl_err)?;
        ok_json(json!({ "results": res.results, "elapsed_ms": res.elapsed_ms }))
    }

    #[tool(
        name = "wait",
        description = "Poll for a condition instead of sleep-polling in the agent loop.\n\
            kind: screen_change (target: capture target; since: previous dhash) | window (query) | clipboard.\n\
            Returns {ok, hash?|wins?}; ok=false on timeout (not an error)."
    )]
    async fn ctl_wait(
        &self,
        Parameters(WaitArgs { kind, target, query, since, timeout_ms, poll_ms }): Parameters<WaitArgs>,
    ) -> Result<CallToolResult, McpError> {
        let kind = parse_wait_kind(&kind)?;
        let res = tokio::task::spawn_blocking(move || {
            super::wait::wait(
                kind,
                query,
                target,
                since,
                timeout_ms.unwrap_or(3000),
                poll_ms.unwrap_or(200),
            )
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?
        .map_err(ctl_err)?;
        ok_json(serde_json::to_value(&res).map_err(|e| McpError::internal_error(e.to_string(), None))?)
    }
}

/// Map a wire error string to a wait Kind.
fn parse_wait_kind(s: &str) -> Result<super::wait::Kind, McpError> {
    match s {
        "screen_change" => Ok(super::wait::Kind::ScreenChange),
        "window" => Ok(super::wait::Kind::Window),
        "clipboard" => Ok(super::wait::Kind::Clipboard),
        other => Err(McpError::invalid_params(format!("unknown kind {other:?}"), None)),
    }
}

/// Button string -> Btn.
fn parse_btn(s: Option<&str>) -> Result<Btn, McpError> {
    match s.unwrap_or("left") {
        "left" => Ok(Btn::Left),
        "right" => Ok(Btn::Right),
        "middle" => Ok(Btn::Middle),
        other => Err(McpError::invalid_params(format!("unknown button {other:?}"), None)),
    }
}

/// Downcast CtlError for a stable wire code prefix (see mod.rs ctl_err).
fn ctl_err(e: anyhow::Error) -> McpError {
    super::ctl_err(e)
}

/// Arm TTL args.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ArmArgs {
    /// TTL in ms (default 30000).
    pub ttl_ms: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClickArgs {
    pub x: Option<i32>,
    pub y: Option<i32>,
    /// left|right|middle (default left).
    pub button: Option<String>,
    /// 0 = hover, 1 = single, 2 = double (default 1).
    pub clicks: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DragArgs {
    pub from: PtArgs,
    pub to: PtArgs,
    /// left|right|middle (default left).
    pub button: Option<String>,
    /// Interpolation steps (default 10).
    pub steps: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PtArgs {
    pub x: i32,
    pub y: i32,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScrollArgs {
    /// Lines down (positive) / up (negative).
    pub dy: i32,
    /// Columns right (positive) / left (negative).
    pub dx: Option<i32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TapArgs {
    /// Combo: "ctrl+shift+t", "enter", "f5".
    pub key: String,
    /// Hold the main key this long (ms).
    pub hold_ms: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TypeArgs {
    pub text: String,
    /// Clipboard roundtrip (default true).
    pub paste: Option<bool>,
    /// Delay between chars in unicode mode (ms).
    pub interval_ms: Option<u32>,
    /// Optional target window the text must land in (focus gate for paste).
    pub target: Option<WinTarget>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FocusArgs {
    pub target: WinTarget,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GeomArgs {
    pub target: WinTarget,
    pub x: Option<i32>,
    pub y: Option<i32>,
    pub w: Option<i32>,
    pub h: Option<i32>,
    /// min | max | restore.
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LayoutArgs {
    /// save | load.
    pub op: String,
    /// Snapshot name (alphanumeric/-/_).
    pub name: String,
    /// load only: report what would move without moving (default false).
    pub dry_run: Option<bool>,
}

/// Step sequence for input_macro, e.g. [{t:"click",x,y},{t:"type",text},{t:"key",key:"enter"}].
#[derive(Debug, Deserialize, JsonSchema)]
pub struct MacroArgs {
    pub steps: Vec<super::steps::Step>,
    /// Delay between steps (ms, default 30).
    pub gap_ms: Option<u32>,
    /// Stop at first failed step (default true).
    pub stop_on_fail: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WaitArgs {
    /// screen_change | window | clipboard.
    pub kind: String,
    /// screen_change: capture target (default cursor square).
    pub target: Option<CapTarget>,
    /// window: filter (title/exe substrings).
    pub query: Option<win::WinQuery>,
    /// screen_change: previous dhash (omitted -> hash now, wait for change).
    pub since: Option<u64>,
    pub timeout_ms: Option<u32>,
    pub poll_ms: Option<u32>,
}
