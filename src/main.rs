use std::collections::BTreeMap;
use std::env;
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_recursion::async_recursion;
use clap::Parser;
use futures::future::join_all;
use rmcp::{
    ErrorData as McpError,
    RoleServer,
    ServerHandler,
    ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    // `ListRootsRequest` is referenced by full path inside `refresh_roots`, which carries the
    // `#[allow(deprecated)]` and the explanation — importing it here would warn crate-wide.
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
        ProgressNotificationParam, RequestMetaObject, ServerCapabilities, ServerInfo,
        ServerRequest,
    },
    serde::{Deserialize, Serialize},
    service::RequestContext,
    service::{Peer, ServiceError},
    tool,
    tool_handler,
    tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde_json::{Value, json};
use tokio::fs;
use tokio::sync::OnceCell;
use tracing::{info, warn};

use crate::core::agent_policy;
use crate::core::allowed::AllowedDirs;
use crate::core::content_plane::{
    ContentError, ContentMode, ContentPlane, ContentRef, TextOrRef, sha256_hex,
};
use crate::core::format;
use crate::core::path::resolve_validated_path;
use crate::core::schema::normalize_tool_schemas;
#[cfg(feature = "s3-tools")]
use crate::core::serde::deserialize_s3_args;
use crate::core::serde::{
    FlexBool, FlexI32, FlexU32, FlexU64, FlexUsize, RI32, RU16, RU32, RU64, RUsize, ShellArg,
    ShellKind, default_flex_true, map_or_json_string, number_or_string,
    option_object_or_json_string, vec_or_string,
};
use crate::tools::binary::{
    extract_bytes, from_base64, patch_bytes, read_bytes, to_base64, write_bytes,
};
use crate::tools::bulk_edit::{BulkEditResult, bulk_edit_files};
use crate::tools::edit::{EditEngine, FileEdit, apply_edits};
use crate::tools::fast_grep::{GrepStats, ProgressCallback, ProgressSnapshot, grep_files_fast};
use crate::tools::fs_ops::{head as head_lines, read_text, read_text_meta, tail as tail_lines};
use crate::tools::grep::{
    GrepContextParams, GrepEngine, GrepParams, NearbyDirection, NearbyMatchMode, grep_context_files,
};
#[cfg(feature = "http-tools")]
use crate::tools::http_tools::{
    HttpRequestParams, decode_body_text, http_request, http_request_batch, is_domain_allowed,
    parse_url,
};
use crate::tools::line_edit::{LineEdit, LineOperation, apply_line_edits};
use crate::tools::media::read_media_base64;
use crate::tools::memory_v2::{
    MemGetArgs, MemGetSummaryArgs, MemLinkArgs, MemPutArgs, MemSearchArgs, MemUpdateArgs,
    MemoryAccessMode as V2MemoryAccessMode, SqliteMemoryStore, mem_get, mem_get_summary, mem_link,
    mem_put, mem_search, mem_update,
};
#[cfg(feature = "s3-tools")]
use crate::tools::s3_tools::{
    S3CopyParams, S3Credentials, S3DeleteParams, S3GetParams, S3ListParams, S3PresignParams,
    S3PutParams, build_s3_client, build_s3_client_with_credentials, copy_object, delete_object,
    delete_objects, get_object, is_bucket_allowed, list_buckets, list_objects, presign, put_object,
    stat_object,
};
#[cfg(feature = "screenshot-tools")]
use crate::tools::screenshot;
use crate::tools::search::{FileTypeFilter, SearchParams, search_files_extended};
use crate::tools::thinking::{ThinkingState, ThoughtInput};
use crate::tools::{
    archive, compare, duplicates, grep, hash, json_reader, pdf_reader, process, search, stats,
    watch,
};
#[cfg(feature = "screenshot-tools")]
use image::RgbaImage;
#[cfg(feature = "http-tools")]
use reqwest::Client;
#[cfg(feature = "http-tools")]
use reqwest::Url;
#[cfg(feature = "http-tools")]
use reqwest::redirect::Policy;

mod core;
/// Vendored copy of the private `mcp-setup-rs` crate — see `src/mcp_setup/VENDOR.md`.
///
/// The upstream library API is kept verbatim so the copy can be resynced with a plain `cp` + the
/// mechanical `crate::` rewrite. As a library its `pub use` facade and full client matrix are the
/// public surface; inlined into this binary, the parts this host does not call are unused by
/// construction — that is vendoring, not dead code, so the lints are silenced here at the module
/// boundary rather than by deleting upstream items (which would diverge us from upstream).
#[allow(dead_code, unused_imports)]
mod mcp_setup;
mod setup;
mod tools;

use crate::core::logging::{TransportMode, init_logging};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Parser, Debug)]
#[command(
    name = "filesystem-mcp-rs",
    author,
    version,
    about = "High-performance filesystem MCP server (stdio/HTTP) and MCP client registration.",
    subcommand_negates_reqs = true
)]
struct TopCli {
    /// `install` / `uninstall` / `status`: manage this binary's registration in AI coding agents.
    #[command(subcommand)]
    setup: Option<mcp_setup::cli::SetupCommand>,
    #[command(flatten)]
    server: ServerArgs,
}

#[derive(Parser, Debug)]
struct ServerArgs {
    /// Allowed directories (fallback if client does not support roots).
    #[arg(value_name = "DIR", num_args = 0..)]
    allowed_dirs: Vec<PathBuf>,
    /// Allow symlinks to point outside the allowed directories (operations will follow them).
    #[arg(long, default_value_t = false)]
    allow_symlink_escape: bool,

    /// Enable streamable HTTP mode (default: stdio)
    #[arg(short = 's', long = "stream")]
    stream_mode: bool,

    /// HTTP port for stream mode
    #[arg(short = 'p', long, default_value = "8000")]
    port: u16,

    /// Bind address for stream mode
    #[arg(short = 'b', long, default_value = "127.0.0.1")]
    bind: String,

    /// Enable file logging. Optionally specify log file name (default: filesystem-mcp-rs.log)
    #[arg(short = 'l', long, value_name = "FILE", num_args = 0..=1, default_missing_value = "filesystem-mcp-rs.log")]
    log: Option<String>,

    /// Computer-control executed-input ops per minute cap (needs ctl-input/ctl-uia features).
    /// Precedence: this flag > FS_MCP_CTL_OPS_PER_MIN env > 240.
    #[cfg(any(feature = "ctl-input", feature = "ctl-uia"))]
    #[arg(long = "ctl-ops-per-min", value_name = "N")]
    ctl_ops_per_min: Option<u32>,

    /// HTTP allowlist domains (repeatable). Use "*" to allow all.
    #[cfg(feature = "http-tools")]
    #[arg(long = "http-allowlist-domain", value_name = "DOMAIN", action = clap::ArgAction::Append)]
    http_allowlist_domains: Vec<String>,

    /// S3 allowlist buckets (repeatable). Use "*" to allow all.
    #[cfg(feature = "s3-tools")]
    #[arg(long = "s3-allowlist-bucket", value_name = "BUCKET", action = clap::ArgAction::Append)]
    s3_allowlist_buckets: Vec<String>,

    /// List enabled features and exit
    #[arg(long = "list-features", short = 'L', action = clap::ArgAction::SetTrue)]
    list_features: bool,

    /// Memory database path (default: system data dir/filesystem-mcp-rs/memory2.db)
    #[arg(long = "memory-db", value_name = "PATH")]
    memory_db: Option<PathBuf>,

    /// Memory access mode: enforce_private_only (default), allow_all, or enforce_visibility
    #[arg(long = "memory-access-mode", value_name = "MODE")]
    memory_access_mode: Option<String>,

    /// Disable session-lock footer on tool text responses (integration tests / debugging).
    #[arg(long = "no-session-footer", default_value_t = false)]
    no_session_footer: bool,
}

#[derive(Clone)]
struct FileSystemServer {
    allowed: AllowedDirs,
    /// Tool dispatch must use this instance (see `#[tool_handler(router = self.tool_router)]`): it holds
    /// `normalize_tool_schemas` output. The inherent `fn tool_router()` alone would omit that step.
    tool_router: ToolRouter<Self>,
    allow_symlink_escape: bool,
    process_manager: process::ProcessManager,
    #[cfg(feature = "http-tools")]
    http_client_follow: Client,
    #[cfg(feature = "http-tools")]
    http_client_no_follow: Client,
    #[cfg(feature = "http-tools")]
    http_allowlist_domains: Vec<String>,
    #[cfg(feature = "s3-tools")]
    s3_allowlist_buckets: Vec<String>,
    #[cfg(feature = "s3-tools")]
    s3_client: Arc<OnceCell<aws_sdk_s3::Client>>,
    thinking_state: Arc<ThinkingState>,
    memory_store: Option<Arc<SqliteMemoryStore>>,
    llm_server: Option<tools::llm::LlmMcpServer>,
    session_footer: bool,
    content_plane: ContentPlane,
}

impl FileSystemServer {
    fn new(allowed: AllowedDirs) -> Self {
        let mut tool_router = Self::tool_router();
        // Computer-control domains: per-domain routers (S1 spike — rmcp cannot
        // cfg-gate methods inside one impl), merged before schema normalization.
        #[cfg(any(feature = "ctl-input", feature = "ctl-uia", feature = "ctl-ocr"))]
        tool_router.merge(Self::ctl_readonly_router());
        #[cfg(feature = "ctl-input")]
        tool_router.merge(Self::ctl_input_router());
        #[cfg(feature = "ctl-uia")]
        tool_router.merge(Self::ctl_uia_router());
        #[cfg(feature = "ctl-ocr")]
        tool_router.merge(Self::ctl_ocr_router());
        #[cfg(feature = "ctl-notify")]
        tool_router.merge(Self::ctl_notify_router());
        #[cfg(feature = "ctl-clip-files")]
        tool_router.merge(Self::ctl_clip_router());
        normalize_tool_schemas(&mut tool_router);
        Self {
            allowed,
            tool_router,
            allow_symlink_escape: false,
            process_manager: process::ProcessManager::new(),
            #[cfg(feature = "http-tools")]
            http_client_follow: Client::builder()
                .redirect(Policy::limited(10))
                .build()
                .unwrap_or_else(|e| {
                    warn!(
                        "Failed to build HTTP client with redirects: {}, using default",
                        e
                    );
                    Client::new()
                }),
            #[cfg(feature = "http-tools")]
            http_client_no_follow: Client::builder()
                .redirect(Policy::none())
                .build()
                .unwrap_or_else(|e| {
                    warn!(
                        "Failed to build HTTP client without redirects: {}, using default",
                        e
                    );
                    Client::new()
                }),
            #[cfg(feature = "http-tools")]
            http_allowlist_domains: Vec::new(),
            #[cfg(feature = "s3-tools")]
            s3_allowlist_buckets: Vec::new(),
            #[cfg(feature = "s3-tools")]
            s3_client: Arc::new(OnceCell::new()),
            thinking_state: Arc::new(ThinkingState::new()),
            memory_store: None,
            llm_server: None,
            session_footer: true,
            content_plane: ContentPlane::new().expect("content plane temp dir"),
        }
    }

    fn require_llm(&self) -> Result<&tools::llm::LlmMcpServer, McpError> {
        self.llm_server.as_ref().ok_or_else(|| {
            McpError::internal_error("LLM server not initialized (missing API keys?)", None)
        })
    }

    fn server_info(&self) -> ServerInfo {
        let mut impl_info = Implementation::default();
        impl_info.name = "filesystem-mcp-rs".to_string();
        impl_info.version = env!("CARGO_PKG_VERSION").to_string();
        impl_info.title = Some("High-Performance Filesystem MCP".to_string());

        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_tool_list_changed()
            .build();
        info.server_info = impl_info;
        info.instructions = Some(
            "== MCP SESSION LOCK (mandatory when this server is connected) ==\n\
            Calling ANY tool from this server locks the session to MCP-only for file/shell work.\n\
            Do NOT use built-in Read, Write, Edit, StrReplace, Grep, Glob, Delete, or Shell/run_terminal_cmd \
            for paths this server can access. Use ONLY tools from this server until the task ends.\n\n\
            == ENGINEERING DISCIPLINE ==\n\
            Do not guess the code — re-check everything (read, grep, search, run_command before asserting).\n\
            Favor systematic fixes over quick hacks (root cause, minimal correct change).\n\
            Verify after edits and commands (read_text_file, grep_files, tail_file, exit code).\n\n\
            IMPORTANT: This filesystem MCP server provides SUPERIOR file operations. \
            You MUST use these tools instead of built-in alternatives whenever possible:\n\n\
            - read_text_file: ALWAYS use instead of cat/Read. Supports pagination (offset/limit), \
              head/tail, max_chars truncation, and line_numbers (adds numbered output + structured lines).\n\
            - grep_files: ALWAYS use instead of grep/Grep. Faster, with regex, context lines, include/exclude filtering.\n\
            - grep_context: Use for context-aware searches (requires nearby terms in a window).\n\
            - Do NOT use rg/grep via run_command; use grep_files or search_files instead.\n\
            - run_command: For long/noisy commands, keep streamOutput at default (true), then read \
              stdoutFile/stderrFile with tail_file or read_text_file. Do not expect full stdout/stderr inline. \
              For long builds (cargo build, etc), use mode='managed' to get progress with output snippets. \
              Use outputFilter with include/exclude regex to get only relevant lines (errors/warnings). \
              Use shell=true for pipes and complex shell commands. \
              Supports stdin ContentRef, envPrepend/envAppend, stdoutHead/stderrHead, process tree kill on timeout.\n\
            - http_request/http_request_batch/http_download: HTTP/HTTPS access when built with http-tools (allowlist required).\n\
            - s3_list_buckets/s3_list/s3_get/s3_put/s3_delete/s3_copy/s3_presign: S3 access when built with s3-tools (allowlist required).\n\
            - screenshot_list_monitors/screenshot_list_windows/screenshot_capture_screen/screenshot_capture_window/screenshot_capture_region/screenshot_copy_to_clipboard: Screenshot capture when built with screenshot-tools.\n\
            - edit_file: ALWAYS use instead of sed/Edit. Returns unified diff, supports dry-run.\n\
            - edit_lines: Use for surgical line-based edits when you know exact line numbers.\n\
            - bulk_edits: Use for mass search/replace across multiple files at once.\n\
            - search_files: ALWAYS use instead of find/Glob. Glob + exclusions; filters: fileType, \
              minSize/maxSize, modifiedAfter/modifiedBefore (RFC3339 or duration like \"17m 20s\"). \
              Example — files touched in the last 17m 20s: \
              {path:\".\", pattern:\"**/*\", fileType:\"file\", modifiedAfter:\"17m 20s\"}. \
              Paths/metadata only; for text inside files use grep_files.\n\n\
            Each tool response includes a session-lock reminder. Host context files (CLAUDE.md, AGENTS.md, …) \
            installed via mcp-setup also embed Karpathy rules + MCP policy at session start.\n\n\
            These tools are optimized for LLM workflows: UTF-8 safe, pagination for token limits, \
            detailed error messages, and consistent JSON responses.\n\n\
            CONTENT PLANE: blob_* + ContentRef for large payloads; write/edit/run/write_binary use ContentRef.\n\n\
            NESTED ARGS: pass structs/maps/arrays as JSON objects/arrays, not as escaped JSON strings. \
            If a client double-serializes, the server still accepts object-or-string and array-or-string forms.\n\n\
            == PLANNING & MEMORY WORKFLOW ==\n\
            For complex multi-step tasks, use seq_think with scoped memory v2 tools:\n\n\
            1. PLAN with seq_think: Break down the task into numbered steps\n\
            2. RECALL context with mem_get_summary (default workspace level), then focused mem_search queries\n\
            3. LOAD exact records with mem_get by item UUID\n\
            4. SAVE with mem_put: workspaceId, actorId, item{ itemType, content }\n\
            5. REVISE with mem_update; CONNECT with mem_link when useful\n\n\
            Memory tools are strict: workspaceId and actorId required; item must be a JSON object.\n\n\
            Avoid full-memory reads. Scoped retrieval is the default memory workflow."
            .to_string()
        );
        info
    }

    async fn ensure_allowed(&self) -> Result<(), McpError> {
        if self.allowed.is_empty().await {
            return Err(McpError::invalid_params(
                "No allowed directories configured; provide CLI dirs or roots",
                None,
            ));
        }
        Ok(())
    }

    async fn resolve(&self, raw: &str) -> Result<PathBuf, McpError> {
        self.ensure_allowed().await?;
        resolve_validated_path(raw, &self.allowed, self.allow_symlink_escape)
            .await
            .map_err(|e| {
                let details = e.to_string();
                McpError::internal_error(
                    format!("Path validation failed: {}", details),
                    Some(json!({ "error": details })),
                )
            })
    }

    fn content_err(e: ContentError) -> McpError {
        McpError::invalid_params(e.to_string(), Some(e.to_json()))
    }

    async fn resolve_content(
        &self,
        content: &ContentRef,
        mode: ContentMode,
    ) -> Result<Vec<u8>, McpError> {
        match content {
            ContentRef::Path { path } => {
                let p = self.resolve(path).await?;
                let bytes = fs::read(&p).await.map_err(|e| {
                    McpError::internal_error(
                        format!("Failed to read content path {}: {}", p.display(), e),
                        None,
                    )
                })?;
                crate::core::content_plane::check_mode(&bytes, mode).map_err(Self::content_err)?;
                Ok(bytes)
            }
            other => self
                .content_plane
                .resolve(other, mode, |_| async {
                    Err(ContentError::Io(
                        "internal: path ContentRef should be handled above".into(),
                    ))
                })
                .await
                .map_err(Self::content_err),
        }
    }

    async fn resolve_content_checked(
        &self,
        content: &ContentRef,
        mode: ContentMode,
        expect_sha256: Option<&str>,
    ) -> Result<Vec<u8>, McpError> {
        let bytes = self.resolve_content(content, mode).await?;
        if let Some(expected) = expect_sha256 {
            let got = sha256_hex(&bytes);
            if !expected.eq_ignore_ascii_case(&got) {
                return Err(Self::content_err(ContentError::HashMismatch {
                    expected: expected.to_string(),
                    got,
                }));
            }
        }
        Ok(bytes)
    }

    #[cfg(feature = "http-tools")]
    fn http_client(&self, follow_redirects: bool) -> &Client {
        if follow_redirects {
            &self.http_client_follow
        } else {
            &self.http_client_no_follow
        }
    }

    #[cfg(feature = "http-tools")]
    fn ensure_http_allowed(&self, url: &str) -> Result<Url, McpError> {
        let parsed = parse_url(url).map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        let host = parsed.host_str().unwrap_or_default();
        if !is_domain_allowed(host, &self.http_allowlist_domains) {
            return Err(McpError::invalid_params(
                format!("HTTP domain '{host}' is not in allowlist"),
                None,
            ));
        }
        Ok(parsed)
    }

    #[cfg(feature = "s3-tools")]
    async fn s3_client(&self) -> Result<aws_sdk_s3::Client, McpError> {
        let client = self
            .s3_client
            .get_or_try_init(|| async {
                build_s3_client()
                    .await
                    .map_err(|e| McpError::internal_error(format!("S3 config failed: {e}"), None))
            })
            .await?;
        Ok(client.clone())
    }

    #[cfg(feature = "s3-tools")]
    async fn s3_client_for(
        &self,
        creds: &S3CredentialsArgs,
    ) -> Result<aws_sdk_s3::Client, McpError> {
        if let Some(creds) = creds.to_credentials() {
            return build_s3_client_with_credentials(Some(creds))
                .await
                .map_err(|e| McpError::internal_error(format!("S3 config failed: {e}"), None));
        }
        self.s3_client().await
    }

    #[cfg(feature = "screenshot-tools")]
    async fn handle_screenshot_output(
        &self,
        image: &RgbaImage,
        output: ScreenshotOutputMode,
        path: Option<&str>,
    ) -> Result<CallToolResult, McpError> {
        match output {
            ScreenshotOutputMode::File => {
                let raw_path = path.ok_or_else(|| {
                    McpError::invalid_params("path is required when output is 'file'", None)
                })?;
                let target = self.resolve(raw_path).await?;
                screenshot::save_png(image, &target)
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                let text = format!(
                    "Saved screenshot to {} ({}x{})",
                    target.display(),
                    image.width(),
                    image.height()
                );
                Ok(
                    CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(
                        json!({
                            "output": "file",
                            "path": target.display().to_string(),
                            "width": image.width(),
                            "height": image.height()
                        }),
                    ),
                )
            }
            ScreenshotOutputMode::Clipboard => {
                screenshot::copy_image(image)
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                let text = format!(
                    "Copied screenshot to clipboard ({}x{})",
                    image.width(),
                    image.height()
                );
                Ok(
                    CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(
                        json!({
                            "output": "clipboard",
                            "width": image.width(),
                            "height": image.height()
                        }),
                    ),
                )
            }
            ScreenshotOutputMode::Base64 => {
                let data = screenshot::to_base64(image)
                    .map_err(|e| McpError::internal_error(format!("Encode error: {e}"), None))?;
                let payload = json!({
                    "format": "png",
                    "encoding": "base64",
                    "data": data,
                    "width": image.width(),
                    "height": image.height()
                });
                Ok(
                    CallToolResult::success(vec![ContentBlock::text(payload.to_string())])
                        .with_structured(payload),
                )
            }
        }
    }

    /// Ask the client which directories we may touch.
    ///
    /// MCP deprecated `roots` in SEP-2577, and rmcp 2.x marks the types accordingly — but no
    /// replacement has shipped, and roots is still the only way a client can hand us its
    /// workspace. Until the successor exists, keep using it (the CLI allowlist stays the
    /// fallback for clients that never supported roots).
    #[allow(deprecated)]
    async fn refresh_roots(
        &self,
        peer: &rmcp::service::Peer<rmcp::RoleServer>,
    ) -> Result<(), McpError> {
        let response = peer
            .send_request(ServerRequest::ListRootsRequest(
                rmcp::model::ListRootsRequest::default(),
            ))
            .await
            .map_err(|e| service_error("list roots request failed", e))?;

        let roots = match response {
            rmcp::model::ClientResult::ListRootsResult(result) => result,
            other => {
                return Err(McpError::internal_error(
                    format!("Unexpected response to roots/list: {:?}", other),
                    None,
                ));
            }
        };

        let validated = self.parse_roots(&roots).await?;
        if !validated.is_empty() {
            self.allowed.set(validated).await;
        } else {
            warn!("Roots/list returned no valid directories; keeping existing allowlist");
        }
        Ok(())
    }

    /// See [`Self::refresh_roots`] for why the deprecated roots API is still in use.
    #[allow(deprecated)]
    async fn parse_roots(
        &self,
        result: &rmcp::model::ListRootsResult,
    ) -> Result<Vec<PathBuf>, McpError> {
        let mut dirs = Vec::new();
        for root in &result.roots {
            if let Some(path) = parse_root_uri(&root.uri) {
                match fs::metadata(&path).await {
                    Ok(meta) if meta.is_dir() => {
                        if let Ok(real) = tokio::fs::canonicalize(&path).await {
                            dirs.push(real);
                        } else {
                            dirs.push(path);
                        }
                    }
                    Ok(_) => warn!("Skipping non-directory root {}", path.display()),
                    Err(err) => warn!("Skipping root {}: {}", path.display(), err),
                }
            } else {
                warn!("Invalid root URI {}", root.uri);
            }
        }
        if dirs.is_empty() {
            return Err(McpError::invalid_params(
                "No valid roots supplied by client",
                None,
            ));
        }
        Ok(dirs)
    }

    fn diff_response(&self, diff: String) -> CallToolResult {
        CallToolResult::success(vec![ContentBlock::text(diff)])
    }

    #[async_recursion]
    async fn copy_dir_recursive(&self, src: &Path, dst: &Path) -> Result<(), McpError> {
        fs::create_dir_all(dst)
            .await
            .map_err(internal_err("Failed to create destination directory"))?;
        let mut rd = fs::read_dir(src)
            .await
            .map_err(internal_err("Failed to read source directory"))?;
        while let Some(entry) = rd
            .next_entry()
            .await
            .map_err(internal_err("Failed to iterate directory"))?
        {
            let ty = entry
                .file_type()
                .await
                .map_err(internal_err("Failed to stat entry"))?;
            let dest_path = dst.join(entry.file_name());
            if ty.is_dir() {
                self.copy_dir_recursive(&entry.path(), &dest_path).await?;
            } else {
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent)
                        .await
                        .map_err(internal_err("Failed to create destination parent"))?;
                }
                fs::copy(entry.path(), &dest_path)
                    .await
                    .map_err(internal_err("Failed to copy file"))?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ReadTextFileArgs {
    path: String,
    /// Return first N lines only (like Unix head)
    #[serde(default)]
    head: FlexU32,
    /// Return last N lines only (like Unix tail)
    #[serde(default)]
    tail: FlexU32,
    /// Start reading from line N (1-indexed, for pagination)
    #[serde(default)]
    offset: FlexU32,
    /// Read at most N lines (use with offset for pagination)
    #[serde(default)]
    limit: FlexU32,
    /// Maximum characters to return (truncates with "[truncated]" marker)
    #[serde(default)]
    max_chars: FlexUsize,
    /// Include line numbers in output (1-indexed) and structured line metadata
    #[serde(default)]
    line_numbers: FlexBool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ReadMediaArgs {
    path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ReadMultipleArgs {
    #[serde(deserialize_with = "vec_or_string")]
    paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct WriteFileArgs {
    path: String,
    /// Content via Content Plane (inline / base64 / path / blob).
    content: ContentRef,
    /// Optional sha256 hex of the resolved bytes (integrity check).
    #[serde(default, rename = "expectSha256", alias = "expect_sha256")]
    expect_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct BlobAppendArgs {
    session_id: String,
    /// UTF-8 text chunk (max INLINE/CHUNK limit).
    text: Option<String>,
    /// Base64-encoded chunk (alternative to text).
    #[serde(alias = "data_base64")]
    data_base64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct BlobFinalizeArgs {
    session_id: String,
    #[serde(default, alias = "expect_sha256")]
    expect_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct BlobStatArgs {
    /// Finalized blob id (sha256 hex).
    id: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
struct EditOperation {
    // Strings preferred for short snippets (hosts drop nested ContentRef
    // objects when `text` contains `{`). ContentRef still works for blobs.
    #[serde(rename = "oldText", alias = "old_text", alias = "old")]
    old_text: TextOrRef,
    #[serde(
        rename = "newText",
        alias = "new_text",
        alias = "new",
        alias = "replacement"
    )]
    new_text: TextOrRef,
    #[serde(default, rename = "isRegex", alias = "is_regex")]
    is_regex: FlexBool,
    #[serde(default, rename = "replaceAll", alias = "replace_all")]
    replace_all: FlexBool,
}

impl<'de> Deserialize<'de> for EditOperation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(rename = "oldText", alias = "old_text", alias = "old")]
            old_text: Option<TextOrRef>,
            #[serde(
                rename = "newText",
                alias = "new_text",
                alias = "new",
                alias = "replacement"
            )]
            new_text: Option<TextOrRef>,
            #[serde(default, rename = "isRegex", alias = "is_regex")]
            is_regex: FlexBool,
            #[serde(default, rename = "replaceAll", alias = "replace_all")]
            replace_all: FlexBool,
        }
        let raw = Raw::deserialize(deserializer)?;
        let old_text = raw.old_text.ok_or_else(|| {
            serde::de::Error::custom(
                "edit missing oldText: send a UTF-8 string, or {kind:inline,text}",
            )
        })?;
        let new_text = raw.new_text.ok_or_else(|| {
            serde::de::Error::custom(
                "edit missing newText: host may have dropped a ContentRef object; \
                 send a UTF-8 string (preferred for short snippets), or {kind:inline,text}, \
                 or {kind:blob,id}",
            )
        })?;
        Ok(Self {
            old_text,
            new_text,
            is_regex: raw.is_regex,
            replace_all: raw.replace_all,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct EditFileArgs {
    path: String,
    #[serde(deserialize_with = "vec_or_string")]
    edits: Vec<EditOperation>,
    #[serde(default, rename = "dryRun", alias = "dry_run")]
    dry_run: FlexBool,
}

#[cfg(test)]
mod edit_operation_serde_tests {
    use super::*;

    #[test]
    fn bare_string_with_braces() {
        let v: EditOperation = serde_json::from_value(serde_json::json!({
            "oldText": "use crate::foo",
            "newText": "use crate::foo::{Bar}"
        }))
        .expect("bare strings");
        match v.new_text.into_ref() {
            ContentRef::Inline { text } => assert_eq!(text, "use crate::foo::{Bar}"),
            _ => panic!("expected inline"),
        }
    }

    #[test]
    fn two_edits_array_bare_strings() {
        let edits: Vec<EditOperation> = serde_json::from_value(serde_json::json!([
            {"oldText": "a", "newText": "A"},
            {"oldText": "b", "newText": "B"}
        ]))
        .expect("two edits");
        assert_eq!(edits.len(), 2);
    }

    #[test]
    fn missing_new_text_names_the_contract() {
        let err = serde_json::from_value::<EditOperation>(serde_json::json!({
            "oldText": "a"
        }))
        .unwrap_err()
        .to_string();
        assert!(err.contains("missing newText"), "{err}");
        assert!(err.contains("UTF-8 string"), "{err}");
    }

    #[test]
    fn content_ref_object_still_works() {
        let v: EditOperation = serde_json::from_value(serde_json::json!({
            "oldText": {"kind": "inline", "text": "a"},
            "newText": {"kind": "inline", "text": "b"}
        }))
        .expect("content ref");
        match v.old_text.into_ref() {
            ContentRef::Inline { text } => assert_eq!(text, "a"),
            _ => panic!("expected inline"),
        }
    }
}

#[cfg(test)]
mod grep_files_args_serde_tests {
    use super::*;

    #[test]
    fn root_alias_fills_path() {
        let v: GrepFilesArgs = serde_json::from_value(serde_json::json!({
            "root": "C:/repo",
            "pattern": "foo"
        }))
        .expect("root alias");
        assert_eq!(v.path, "C:/repo");
    }

    #[test]
    fn missing_path_is_empty_not_serde_missing_field() {
        let v: GrepFilesArgs = serde_json::from_value(serde_json::json!({
            "pattern": "foo"
        }))
        .expect("path default");
        assert!(v.path.is_empty());
    }

    #[test]
    fn file_pattern_camel_and_glob() {
        let a: GrepFilesArgs = serde_json::from_value(serde_json::json!({
            "path": ".",
            "pattern": "x",
            "filePattern": "*.rs"
        }))
        .unwrap();
        assert_eq!(a.file_pattern.as_deref(), Some("*.rs"));
        let b: GrepFilesArgs = serde_json::from_value(serde_json::json!({
            "path": ".",
            "pattern": "x",
            "glob": "*.toml"
        }))
        .unwrap();
        assert_eq!(b.file_pattern.as_deref(), Some("*.toml"));
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct CreateDirArgs {
    path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ListDirArgs {
    path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ListDirWithSizesArgs {
    path: String,
    #[serde(default = "default_sort_by")]
    sort_by: SortBy,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum SortBy {
    Name,
    Size,
}

fn default_sort_by() -> SortBy {
    SortBy::Name
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct DirectoryTreeArgs {
    path: String,
    #[serde(default, alias = "exclude_patterns")]
    #[serde(deserialize_with = "vec_or_string")]
    exclude_patterns: Vec<String>,
    /// Maximum depth to traverse (0 = unlimited)
    #[serde(default)]
    max_depth: usize,
    /// Show file sizes in the output
    #[serde(default)]
    show_size: FlexBool,
    /// Show file hashes (sha256) in the output
    #[serde(default)]
    show_hash: FlexBool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct MoveFileArgs {
    source: String,
    destination: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CopyFileArgs {
    source: String,
    destination: String,
    #[serde(default)]
    overwrite: FlexBool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct DeletePathArgs {
    path: String,
    #[serde(default)]
    recursive: FlexBool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct SearchArgs {
    path: String,
    pattern: String,
    #[serde(default, alias = "exclude_patterns")]
    #[serde(deserialize_with = "vec_or_string")]
    exclude_patterns: Vec<String>,
    /// Filter by type: "file", "dir", "symlink", "any" (default)
    #[serde(skip_serializing_if = "Option::is_none")]
    file_type: Option<String>,
    /// Minimum file size in bytes
    #[serde(default)]
    min_size: FlexU64,
    /// Maximum file size in bytes
    #[serde(default)]
    max_size: FlexU64,
    /// Files with mtime >= cutoff. RFC3339 or relative duration (e.g. "17m 20s", "7d" = now minus span).
    #[serde(skip_serializing_if = "Option::is_none")]
    modified_after: Option<String>,
    /// Files with mtime <= cutoff. Same formats as modifiedAfter.
    #[serde(skip_serializing_if = "Option::is_none")]
    modified_before: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct FileInfoArgs {
    path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct GrepFilesArgs {
    /// Root directory to search
    #[serde(default, alias = "root", alias = "dir", alias = "directory")]
    path: String,
    /// Regex pattern to search for in file contents
    pattern: String,
    /// Glob pattern for files to include (e.g., "*.rs", "**/*.txt")
    // Aliases accept the built-in Grep/ripgrep vocabulary clients reflexively
    // send; without them `glob` was silently dropped and the search widened to
    // the whole tree (see BUG.md).
    #[serde(
        skip_serializing_if = "Option::is_none",
        alias = "glob",
        alias = "include",
        alias = "file_pattern"
    )]
    file_pattern: Option<String>,
    /// Accepted for compatibility with built-in Grep (`lineNumbers`, `-n`);
    /// line numbers are always returned, so this is ignored.
    #[serde(default, alias = "-n", alias = "n", skip_serializing)]
    #[allow(dead_code)]
    line_numbers: Option<serde_json::Value>,
    /// Glob patterns to exclude (e.g., "target/**", "**/*.min.js")
    #[serde(default, alias = "exclude_patterns")]
    #[serde(deserialize_with = "vec_or_string")]
    exclude_patterns: Vec<String>,
    /// Case-insensitive search
    #[serde(default, alias = "-i", alias = "ignoreCase", alias = "ignore_case")]
    case_insensitive: FlexBool,
    /// Number of context lines before match
    #[serde(
        default,
        deserialize_with = "number_or_string",
        alias = "-B",
        alias = "before"
    )]
    context_before: usize,
    /// Number of context lines after match
    #[serde(
        default,
        deserialize_with = "number_or_string",
        alias = "-A",
        alias = "after"
    )]
    context_after: usize,
    /// Maximum number of matches to return (0 = unlimited, default 100)
    #[serde(
        default = "default_max_matches",
        deserialize_with = "number_or_string",
        alias = "head_limit",
        alias = "headLimit",
        alias = "limit",
        alias = "maxCount",
        alias = "max_count"
    )]
    max_matches: usize,
    /// Invert match: show lines NOT matching the pattern
    #[serde(default)]
    invert_match: FlexBool,
    /// Output mode: "content" (default), "count", "files_with_matches", "files_without_match"
    #[serde(default)]
    output_mode: Option<String>,
    /// Enable multi-line mode: pattern can contain `\n` and span lines (like `rg --multiline -U`).
    #[serde(default)]
    multiline: FlexBool,
    /// Treat `pattern` as a fixed literal (no regex parsing). Like `rg -F`.
    #[serde(default)]
    fixed_strings: FlexBool,
    /// Constrain matches to word boundaries. Like `rg -w`.
    #[serde(default)]
    whole_word: FlexBool,
    /// Maximum recursion depth (0 = unlimited).
    #[serde(default, deserialize_with = "number_or_string")]
    max_depth: usize,
    /// Skip files larger than this many bytes (0 = no limit).
    #[serde(default, deserialize_with = "number_or_string")]
    max_filesize: u64,
    /// Force text encoding (e.g. "utf-8", "utf-16", "windows-1251"). None = auto.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encoding: Option<String>,
    /// Heap limit for the searcher in MB (0 = unlimited). Guards multi-line
    /// searches over huge single-line files.
    #[serde(default, deserialize_with = "number_or_string")]
    heap_limit_mb: usize,
    /// Regex engine: "regex" (default) | "fancy" (look-around + backreferences).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    engine: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct GrepContextArgs {
    /// Root directory to search
    #[serde(alias = "root", alias = "dir", alias = "directory")]
    path: String,
    /// Regex pattern to search for in file contents
    pattern: String,
    /// Glob pattern for files to include (e.g., "*.rs", "**/*.txt")
    // Aliases accept the built-in Grep/ripgrep vocabulary clients reflexively
    // send; without them `glob` was silently dropped and the search widened to
    // the whole tree (see BUG.md).
    #[serde(
        skip_serializing_if = "Option::is_none",
        alias = "glob",
        alias = "include",
        alias = "file_pattern"
    )]
    file_pattern: Option<String>,
    /// Accepted for compatibility with built-in Grep (`lineNumbers`, `-n`);
    /// line numbers are always returned, so this is ignored.
    #[serde(default, alias = "-n", alias = "n", skip_serializing)]
    #[allow(dead_code)]
    line_numbers: Option<serde_json::Value>,
    /// Glob patterns to exclude (e.g., "target/**", "**/*.min.js")
    #[serde(default, alias = "exclude_patterns")]
    #[serde(deserialize_with = "vec_or_string")]
    exclude_patterns: Vec<String>,
    /// Case-insensitive search
    #[serde(default, alias = "-i", alias = "ignoreCase", alias = "ignore_case")]
    case_insensitive: FlexBool,
    /// Number of context lines before match
    #[serde(
        default,
        deserialize_with = "number_or_string",
        alias = "-B",
        alias = "before"
    )]
    context_before: usize,
    /// Number of context lines after match
    #[serde(
        default,
        deserialize_with = "number_or_string",
        alias = "-A",
        alias = "after"
    )]
    context_after: usize,
    /// Maximum number of matches to return (0 = unlimited, default 100)
    #[serde(
        default = "default_max_matches",
        deserialize_with = "number_or_string",
        alias = "head_limit",
        alias = "headLimit",
        alias = "limit",
        alias = "maxCount",
        alias = "max_count"
    )]
    max_matches: usize,
    /// Output mode: "content" (default), "count", "files_with_matches", "files_without_match"
    #[serde(default)]
    output_mode: Option<String>,
    /// Nearby patterns that must appear within the window
    #[serde(default)]
    #[serde(deserialize_with = "vec_or_string")]
    nearby_patterns: Vec<String>,
    /// Treat nearby patterns as regex (false = literal)
    #[serde(default)]
    nearby_is_regex: FlexBool,
    /// Case-insensitive matching for nearby patterns
    #[serde(default)]
    nearby_case_insensitive: FlexBool,
    /// Direction for nearby patterns: "before", "after", "both" (default)
    #[serde(default)]
    nearby_direction: Option<String>,
    /// Window size in words (optional)
    #[serde(default)]
    nearby_window_words: FlexUsize,
    /// Window size in characters (optional)
    #[serde(default)]
    nearby_window_chars: FlexUsize,
    /// Match mode for multiple nearby patterns: "any" (default) or "all"
    #[serde(default)]
    nearby_match_mode: Option<String>,
    /// Treat `pattern` as a literal string.
    #[serde(default)]
    fixed_strings: FlexBool,
    /// Constrain matches to word boundaries.
    #[serde(default)]
    whole_word: FlexBool,
    /// Maximum recursion depth (0 = unlimited).
    #[serde(default, deserialize_with = "number_or_string")]
    max_depth: usize,
    /// Skip files larger than this many bytes (0 = no limit).
    #[serde(default, deserialize_with = "number_or_string")]
    max_filesize: u64,
    /// Regex engine: "regex" (default) | "fancy" (look-around + backreferences).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    engine: Option<String>,
}

fn default_max_matches() -> usize {
    100
}

#[cfg(feature = "http-tools")]
fn default_http_timeout_ms() -> u64 {
    30_000
}

#[cfg(feature = "http-tools")]
fn default_http_max_bytes() -> usize {
    1_000_000
}

#[cfg(feature = "http-tools")]
fn default_http_download_max_bytes() -> usize {
    50_000_000
}

#[cfg(feature = "http-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct HttpRequestArgs {
    method: String,
    url: String,
    #[serde(default, deserialize_with = "map_or_json_string")]
    headers: BTreeMap<String, String>,
    #[serde(default, deserialize_with = "map_or_json_string")]
    cookies: BTreeMap<String, String>,
    #[serde(default, deserialize_with = "map_or_json_string")]
    query: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(default)]
    body_base64: FlexBool,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_path: Option<String>,
    #[serde(default = "default_http_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_http_max_bytes")]
    max_bytes: usize,
    #[serde(default)]
    follow_redirects: FlexBool,
    #[serde(skip_serializing_if = "Option::is_none")]
    accept: Option<String>,
}

#[cfg(feature = "http-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct HttpRequestItemArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(flatten)]
    request: HttpRequestArgs,
}

#[cfg(feature = "http-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct HttpRequestBatchArgs {
    #[serde(deserialize_with = "vec_or_string")]
    requests: Vec<HttpRequestItemArgs>,
}

#[cfg(feature = "http-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct HttpDownloadArgs {
    url: String,
    path: String,
    #[serde(default, deserialize_with = "map_or_json_string")]
    headers: BTreeMap<String, String>,
    #[serde(default, deserialize_with = "map_or_json_string")]
    cookies: BTreeMap<String, String>,
    #[serde(default, deserialize_with = "map_or_json_string")]
    query: BTreeMap<String, String>,
    #[serde(default = "default_http_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_http_download_max_bytes")]
    max_bytes: usize,
    #[serde(default)]
    follow_redirects: FlexBool,
}

#[cfg(feature = "http-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct HttpDownloadBatchArgs {
    #[serde(deserialize_with = "vec_or_string")]
    downloads: Vec<HttpDownloadArgs>,
}

#[cfg(feature = "s3-tools")]
fn default_s3_max_bytes() -> usize {
    5_000_000
}

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3CredentialsArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    access_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_access_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,
}

#[cfg(feature = "s3-tools")]
macro_rules! impl_s3_args_deserialize {
    ($ty:ty) => {
        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                deserialize_s3_args(deserializer)
            }
        }
    };
}

#[cfg(feature = "s3-tools")]
impl S3CredentialsArgs {
    fn to_credentials(&self) -> Option<S3Credentials> {
        if self.access_key_id.is_none()
            && self.secret_access_key.is_none()
            && self.session_token.is_none()
            && self.region.is_none()
        {
            return None;
        }
        Some(S3Credentials {
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            session_token: self.session_token.clone(),
            region: self.region.clone(),
        })
    }
}

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3ListBucketsArgs {
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}
#[cfg(feature = "s3-tools")]
impl_s3_args_deserialize!(S3ListBucketsArgs);

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3ListArgs {
    bucket: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delimiter: Option<String>,
    #[serde(default)]
    max_keys: FlexI32,
    #[serde(skip_serializing_if = "Option::is_none")]
    continuation_token: Option<String>,
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}
#[cfg(feature = "s3-tools")]
impl_s3_args_deserialize!(S3ListArgs);

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3StatArgs {
    bucket: String,
    key: String,
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}
#[cfg(feature = "s3-tools")]
impl_s3_args_deserialize!(S3StatArgs);

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3GetArgs {
    bucket: String,
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    range: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_path: Option<String>,
    #[serde(default = "default_s3_max_bytes")]
    max_bytes: usize,
    #[serde(default)]
    accept_text: FlexBool,
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}
#[cfg(feature = "s3-tools")]
impl_s3_args_deserialize!(S3GetArgs);

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3PutArgs {
    bucket: String,
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(default)]
    body_base64: FlexBool,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_control: Option<String>,
    #[serde(default, deserialize_with = "map_or_json_string")]
    metadata: BTreeMap<String, String>,
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}
#[cfg(feature = "s3-tools")]
impl_s3_args_deserialize!(S3PutArgs);

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3CopyArgs {
    source_bucket: String,
    source_key: String,
    dest_bucket: String,
    dest_key: String,
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}
#[cfg(feature = "s3-tools")]
impl_s3_args_deserialize!(S3CopyArgs);

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3DeleteArgs {
    bucket: String,
    key: String,
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}
#[cfg(feature = "s3-tools")]
impl_s3_args_deserialize!(S3DeleteArgs);

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3DeleteBatchArgs {
    bucket: String,
    #[serde(deserialize_with = "vec_or_string")]
    keys: Vec<String>,
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}
#[cfg(feature = "s3-tools")]
impl_s3_args_deserialize!(S3DeleteBatchArgs);

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3PresignArgs {
    bucket: String,
    key: String,
    method: String,
    #[serde(default = "default_s3_presign_ttl")]
    expires_in_seconds: u64,
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}
#[cfg(feature = "s3-tools")]
impl_s3_args_deserialize!(S3PresignArgs);

#[cfg(feature = "s3-tools")]
fn default_s3_presign_ttl() -> u64 {
    900
}

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3GetBatchArgs {
    #[serde(deserialize_with = "vec_or_string")]
    requests: Vec<S3GetArgs>,
}

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3PutBatchArgs {
    #[serde(deserialize_with = "vec_or_string")]
    requests: Vec<S3PutArgs>,
}

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3CopyBatchArgs {
    #[serde(deserialize_with = "vec_or_string")]
    requests: Vec<S3CopyArgs>,
}

// ============================================================================
// New tools Args
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct FileHashArgs {
    /// Path to file
    path: String,
    /// Hash algorithm: md5, sha1, sha256 (default), sha512, xxh64, murmur3, spooky
    #[serde(default)]
    algorithm: Option<String>,
    /// Byte offset to start hashing from (0-indexed, default: 0)
    #[serde(default)]
    offset: FlexU64,
    /// Number of bytes to hash (default: entire file from offset)
    #[serde(default)]
    length: FlexU64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct FileHashMultipleArgs {
    /// Paths to files
    #[serde(deserialize_with = "vec_or_string")]
    paths: Vec<String>,
    /// Hash algorithm: md5, sha1, sha256 (default), sha512, xxh64, murmur3, spooky
    #[serde(default)]
    algorithm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CompareFilesArgs {
    /// First file path
    path1: String,
    /// Second file path
    path2: String,
    /// Maximum number of diff samples to return (default: 20)
    #[serde(default = "default_max_diffs")]
    max_diffs: usize,
    /// Bytes of context around differences (default: 8)
    #[serde(default = "default_context_bytes")]
    context_bytes: usize,
    /// Offset in first file (default: 0)
    #[serde(default)]
    offset1: u64,
    /// Offset in second file (default: 0)
    #[serde(default)]
    offset2: u64,
    /// Length to compare (0 = full file)
    #[serde(default)]
    length: u64,
}

fn default_max_diffs() -> usize {
    20
}
fn default_context_bytes() -> usize {
    8
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CompareDirsArgs {
    /// First directory path
    path1: String,
    /// Second directory path
    path2: String,
    /// Recursive comparison (default: true)
    #[serde(default = "default_flex_true")]
    recursive: FlexBool,
    /// Compare file content by hash (default: false, only name/size)
    #[serde(default)]
    compare_content: FlexBool,
    /// Glob patterns to ignore
    #[serde(default)]
    #[serde(deserialize_with = "vec_or_string")]
    ignore_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct TailFileArgs {
    /// Path to file
    path: String,
    /// Number of lines to read (default: 10)
    #[serde(default = "default_tail_lines", deserialize_with = "number_or_string")]
    lines: usize,
    /// Alternative: number of bytes to read
    #[serde(default)]
    bytes: FlexUsize,
    /// Follow mode: wait for new content
    #[serde(default)]
    follow: FlexBool,
    /// Timeout in ms for follow mode (default: 5000)
    #[serde(
        default = "default_follow_timeout",
        deserialize_with = "number_or_string"
    )]
    timeout_ms: u64,
}

fn default_tail_lines() -> usize {
    10
}
fn default_follow_timeout() -> u64 {
    5000
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct WatchFileArgs {
    /// Path to file or directory to watch
    path: String,
    /// Timeout in ms (default: 30000)
    #[serde(
        default = "default_watch_timeout",
        deserialize_with = "number_or_string"
    )]
    timeout_ms: u64,
    /// Events to watch: modify, create, delete (default: all)
    #[serde(default)]
    #[serde(deserialize_with = "vec_or_string")]
    events: Vec<String>,
}

fn default_watch_timeout() -> u64 {
    30000
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ReadJsonArgs {
    /// Path to JSON file
    path: String,
    /// JSONPath query (e.g., "$.users[*].name") or dot notation ("user.name")
    #[serde(default)]
    query: Option<String>,
    /// Pretty print output (default: true)
    #[serde(default = "default_flex_true")]
    pretty: FlexBool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ReadPdfArgs {
    /// Path to PDF file
    path: String,
    /// Page range: "1-5" or "1,3,5" or null for all
    #[serde(default)]
    pages: Option<String>,
    /// Maximum characters to return (default: 50000)
    #[serde(default = "default_max_chars")]
    max_chars: usize,
    /// Collapse ZWSP / spaced glyph artifacts (default: true)
    #[serde(default = "default_flex_true")]
    normalize: FlexBool,
    /// Also return unnormalized extract as rawText (default: false)
    #[serde(default)]
    include_raw: FlexBool,
}

fn default_max_chars() -> usize {
    50000
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ExtractArchiveArgs {
    /// Path to archive file
    path: String,
    /// Destination directory
    destination: String,
    /// Archive format: zip, tar, tar.gz (auto-detect by extension if not specified)
    #[serde(default)]
    format: Option<String>,
    /// Specific files to extract (extract all if not specified)
    #[serde(default)]
    #[serde(deserialize_with = "vec_or_string")]
    files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CreateArchiveArgs {
    /// Paths to files/directories to archive
    #[serde(deserialize_with = "vec_or_string")]
    paths: Vec<String>,
    /// Destination archive path
    destination: String,
    /// Archive format: zip (default), tar, tar.gz
    #[serde(default)]
    format: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct FileStatsArgs {
    /// Path to file or directory
    path: String,
    /// Recursive for directories (default: true)
    #[serde(default = "default_flex_true")]
    recursive: FlexBool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct FindDuplicatesArgs {
    /// Directory to search
    path: String,
    /// Minimum file size in bytes (default: 1, skip empty files)
    #[serde(default)]
    min_size: FlexU64,
    /// Compare by content hash (default: true). False = compare by size only
    #[serde(default = "default_flex_true")]
    by_content: FlexBool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum LineEditOperation {
    Replace,
    #[serde(rename = "insert_before")]
    InsertBefore,
    #[serde(rename = "insert_after")]
    InsertAfter,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct LineEditInstruction {
    /// Line number to edit (1-indexed)
    #[serde(deserialize_with = "number_or_string")]
    line: usize,
    /// End line for range operations (1-indexed, inclusive). If omitted, operates on single line.
    /// Also accepts snake_case `end_line` — without the alias LLMs silently drop the range and
    /// multiline replace mangles the file (single-line splice + leftover tail).
    #[serde(default, alias = "end_line")]
    end_line: FlexUsize,
    /// Operation: "replace", "insert_before", "insert_after", "delete"
    operation: LineEditOperation,
    /// Text content for replace/insert operations
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
}

#[cfg(test)]
mod line_edit_instruction_serde_tests {
    use super::*;

    /// camelCase `endLine` deserializes into end_line.
    #[test]
    fn end_line_camel_case_accepted() {
        let v: LineEditInstruction = serde_json::from_value(serde_json::json!({
            "line": 4,
            "endLine": 7,
            "operation": "replace",
            "text": "x"
        }))
        .expect("endLine should deserialize");
        assert_eq!(v.line, 4);
        assert_eq!(v.end_line.get(), Some(7));
    }

    /// snake_case `end_line` is accepted via alias (LLM-tolerant; was silently ignored).
    #[test]
    fn end_line_snake_case_accepted() {
        let v: LineEditInstruction = serde_json::from_value(serde_json::json!({
            "line": 4,
            "end_line": 7,
            "operation": "replace",
            "text": "x"
        }))
        .expect("end_line alias should deserialize");
        assert_eq!(v.line, 4);
        assert_eq!(v.end_line.get(), Some(7));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct EditLinesArgs {
    /// Path to file
    path: String,
    /// List of line-based edit operations
    #[serde(deserialize_with = "vec_or_string")]
    edits: Vec<LineEditInstruction>,
    /// Dry run mode - return diff without applying changes
    #[serde(default, alias = "dry_run")]
    dry_run: FlexBool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct BulkEditsArgs {
    /// Root directory to search for files
    path: String,
    /// Glob pattern for files to edit (e.g., "**/*.rs", "src/**/*.txt")
    #[serde(alias = "file_pattern")]
    file_pattern: String,
    /// Glob patterns to exclude (optional)
    #[serde(default, alias = "exclude_patterns")]
    #[serde(deserialize_with = "vec_or_string")]
    exclude_patterns: Vec<String>,
    /// List of search/replace operations to apply to all matching files
    #[serde(deserialize_with = "vec_or_string")]
    edits: Vec<EditOperation>,
    /// Dry run mode - return diffs without applying changes
    #[serde(default, alias = "dry_run")]
    dry_run: FlexBool,
    /// Fail when any edit has no match in a file
    #[serde(default, alias = "fail_on_no_match")]
    fail_on_no_match: FlexBool,
    /// Regex engine for `isRegex` edits: "regex" (default, linear time) or
    /// "fancy" (enables look-around / backreferences, backtracking).
    #[serde(default)]
    engine: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct TreeEntry {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    children: Option<Vec<TreeEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_human: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
}

// ============================================================================
// Extract tools - cut content from files and return it
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ExtractLinesArgs {
    /// Path to file
    path: String,
    /// Start line number (1-indexed)
    #[serde(deserialize_with = "number_or_string")]
    line: usize,
    /// End line number (1-indexed, inclusive). If omitted, extracts single line
    #[serde(default, alias = "end_line")]
    end_line: FlexUsize,
    /// Dry run mode - return content without removing from file
    #[serde(default, alias = "dry_run")]
    dry_run: FlexBool,
    /// Return extracted content in response (default: false to save tokens)
    #[serde(default, alias = "return_extracted")]
    return_extracted: FlexBool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ExtractSymbolsArgs {
    /// Path to file
    path: String,
    /// Start position (0-indexed, in Unicode characters, not bytes).
    /// Example: in "Hello" start=0 is 'H', start=4 is 'o'
    start: RUsize,
    /// End position (exclusive, 0-indexed). Use either 'end' or 'length', not both.
    /// Example: start=0, end=5 extracts "Hello" from "Hello World"
    #[serde(default)]
    end: FlexUsize,
    /// Number of characters to extract. Use either 'length' or 'end', not both.
    /// Example: start=0, length=5 extracts "Hello" from "Hello World"
    #[serde(default)]
    length: FlexUsize,
    /// Dry run mode - return content without removing from file
    #[serde(default, alias = "dry_run")]
    dry_run: FlexBool,
    /// Return extracted content in response (default: false to save tokens)
    #[serde(default, alias = "return_extracted")]
    return_extracted: FlexBool,
}

// ============================================================================
// Binary tools - read/write/edit binary files
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ReadBinaryArgs {
    /// Path to binary file
    path: String,
    /// Byte offset to start reading from (0-indexed)
    offset: RU64,
    /// Number of bytes to read
    length: RUsize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct WriteBinaryArgs {
    /// Path to binary file
    path: String,
    /// Byte offset to write at (0-indexed)
    offset: RU64,
    /// Bytes via Content Plane (binary mode).
    data: ContentRef,
    /// Write mode: "replace" overwrites bytes, "insert" shifts existing content
    #[serde(default = "default_write_mode")]
    mode: WriteBinaryMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
enum WriteBinaryMode {
    #[default]
    Replace,
    Insert,
}

fn default_write_mode() -> WriteBinaryMode {
    WriteBinaryMode::Replace
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ExtractBinaryArgs {
    /// Path to binary file
    path: String,
    /// Byte offset to start extraction (0-indexed)
    offset: RU64,
    /// Number of bytes to extract
    length: RUsize,
    /// Dry run mode - return content without removing from file
    #[serde(default)]
    dry_run: FlexBool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct PatchBinaryArgs {
    /// Path to binary file
    path: String,
    /// Base64-encoded pattern to find
    find: String,
    /// Base64-encoded replacement data
    replace: String,
    /// Replace all occurrences (default: false, replaces only first)
    #[serde(default)]
    all: FlexBool,
}

// === Process Management Args ===

/// Execution mode for run_command
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum RunModeArg {
    /// Wait for completion, send heartbeat every ~30s (default)
    #[default]
    Sync,
    /// Wait for completion, send progress with output snippets every ~10s
    Managed,
    /// Run in background, return immediately with PID
    Detached,
}

/// Output filter configuration (grep-like filtering of inline output)
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct OutputFilterArgs {
    /// Regex patterns to include (show lines matching ANY pattern)
    #[serde(default, deserialize_with = "vec_or_string")]
    include: Vec<String>,
    /// Regex patterns to exclude (hide lines matching ANY, applied after include)
    #[serde(default, deserialize_with = "vec_or_string")]
    exclude: Vec<String>,
    /// Context lines before each match (like grep -B)
    #[serde(default)]
    context_before: FlexUsize,
    /// Context lines after each match (like grep -A)
    #[serde(default)]
    context_after: FlexUsize,
    /// Context lines before AND after (like grep -C, overridden by specific before/after)
    #[serde(default)]
    context: FlexUsize,
    /// Max filtered lines to return (prevents context overflow)
    #[serde(default)]
    max_lines: FlexUsize,
}

/// Split a full command line into tokens, honoring single and double quotes.
///
/// Whitespace separates tokens except inside a matching quote pair; the quote
/// characters themselves are dropped. Backslashes are preserved verbatim and
/// are NOT treated as escape characters, so Windows paths such as
/// `C:\dir\tool.exe` survive intact (this is why we deliberately avoid a POSIX
/// shlex crate, which would consume those backslashes). Used to auto-split a
/// command line passed via `command` whenever no explicit `args` and no shell
/// are given; a program path containing spaces must therefore be quoted, the
/// same rule every shell uses. See `fsmcp_bug.md` #2.
fn split_command_line(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    // Tracks whether the current token has started, so empty quotes (`""`)
    // still yield a token while runs of whitespace collapse to nothing.
    let mut has_token = false;
    for ch in line.chars() {
        match quote {
            // Inside a quoted span only the matching quote can end it.
            Some(q) => {
                if ch == q {
                    quote = None;
                } else {
                    cur.push(ch);
                }
            }
            None => match ch {
                '\'' | '"' => {
                    quote = Some(ch);
                    has_token = true;
                }
                c if c.is_whitespace() => {
                    if has_token {
                        tokens.push(std::mem::take(&mut cur));
                        has_token = false;
                    }
                }
                c => {
                    cur.push(c);
                    has_token = true;
                }
            },
        }
    }
    if has_token {
        tokens.push(cur);
    }
    tokens
}

/// Detect a shell control metacharacter that appears OUTSIDE any quoted span in
/// a command line.
///
/// Used only to attach a *non-fatal* hint when a pipeline-looking string is run
/// without a shell (`shell:false`): there the command is split into program +
/// argv, so `|`, `;`, `&&`, `>`, `<`, backtick are handed to the program as
/// literal arguments rather than interpreted — which silently does the wrong
/// thing (e.g. `git tag | grep x` runs `git` with `|` and `grep` as args).
///
/// Returns the first such character so the caller can advise `shell:"bash"`. We
/// deliberately never reject on this — those characters are valid literal argv
/// for some programs — so a false positive only adds an advisory line. Quoting
/// rules mirror `split_command_line` (single/double quotes suppress detection;
/// backslashes are not escapes), keeping the two scanners consistent.
fn top_level_shell_meta(line: &str) -> Option<char> {
    let mut quote: Option<char> = None;
    for ch in line.chars() {
        match quote {
            // Inside a quoted span only the matching quote can end it; operators
            // there are intentional literals, never shell control.
            Some(q) => {
                if ch == q {
                    quote = None;
                }
            }
            None => match ch {
                '\'' | '"' => quote = Some(ch),
                '|' | ';' | '&' | '>' | '<' | '`' => return Some(ch),
                _ => {}
            },
        }
    }
    None
}

#[cfg(test)]
mod cmdline_tests {
    use super::{split_command_line, top_level_shell_meta};

    #[test]
    fn splits_simple_command_line() {
        assert_eq!(
            split_command_line("cargo test -p vfx-ocio --release aces2"),
            vec!["cargo", "test", "-p", "vfx-ocio", "--release", "aces2"]
        );
    }

    #[test]
    fn honors_quotes_and_collapses_whitespace() {
        assert_eq!(
            split_command_line("  tool   \"arg with space\"  'single quoted' "),
            vec!["tool", "arg with space", "single quoted"]
        );
    }

    #[test]
    fn preserves_backslashes_in_windows_paths() {
        // No backslash-escaping: a quoted Windows path round-trips unchanged.
        assert_eq!(
            split_command_line("\"C:\\Program Files\\app.exe\" --flag"),
            vec!["C:\\Program Files\\app.exe", "--flag"]
        );
    }

    #[test]
    fn empty_quotes_form_a_token() {
        assert_eq!(split_command_line("prog \"\" x"), vec!["prog", "", "x"]);
    }

    #[test]
    fn single_token_is_unchanged() {
        // The common `command: "cargo"` case round-trips to one token.
        assert_eq!(split_command_line("cargo"), vec!["cargo"]);
    }

    #[test]
    fn detects_top_level_pipe_and_redirects() {
        // The silent-pipe footgun: operators outside quotes are flagged.
        assert_eq!(top_level_shell_meta("git tag | grep v1"), Some('|'));
        assert_eq!(top_level_shell_meta("echo hi > out.txt"), Some('>'));
        assert_eq!(top_level_shell_meta("a && b"), Some('&'));
        assert_eq!(top_level_shell_meta("a; b"), Some(';'));
    }

    #[test]
    fn ignores_quoted_operators() {
        // Operators inside quotes are intentional literal argv — never flagged,
        // so legitimate calls like `rg "a|b"` are not nagged.
        assert_eq!(top_level_shell_meta("rg \"a|b\" file"), None);
        assert_eq!(top_level_shell_meta("find . -name '*|*'"), None);
        assert_eq!(top_level_shell_meta("echo '1 > 0'"), None);
    }

    #[test]
    fn none_for_plain_command_line() {
        assert_eq!(top_level_shell_meta("cargo test -p foo --release"), None);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct RunCommandArgs {
    /// Command to execute (e.g., "python", "node", "cargo"). A full command
    /// line (e.g. "cargo test -p foo") also works: when `args` is empty and
    /// `shell` is false, it is auto-split into program + arguments (quote-aware;
    /// backslashes preserved). Pass `args` or `shell: true` to bypass.
    ///
    /// WINDOWS PATHS: a backslash in a JSON string is an escape char, so a
    /// single-backslash path is consumed before it reaches this server
    /// (`\r`/`\t` become control chars; other `\x` is invalid JSON). Safe
    /// default: double every backslash — `"type \"C:\\dir\\file\""`. Forward
    /// slashes also work for most programs, but cmd.exe built-ins (`if exist`,
    /// `copy`, `dir`) can read a leading `/` as a switch, so prefer doubled
    /// backslashes in shell mode. Once the JSON is correct the path reaches the
    /// shell verbatim (no further mangling by this server).
    command: String,
    /// Command arguments
    #[serde(default, deserialize_with = "vec_or_string")]
    args: Vec<String>,
    /// Working directory (optional). Absolute path with forward slashes, e.g. `C:/repo`. Pass as a plain JSON string — do NOT embed quote characters inside the value.
    /// Aliases also accepted (a typo here is a common trap): `working_directory`, `workingDir`, `working_dir`, `workdir`, `dir`.
    #[serde(
        alias = "working_directory",
        alias = "workingDir",
        alias = "working_dir",
        alias = "workdir",
        alias = "dir"
    )]
    cwd: Option<String>,
    /// Environment variables to add (key-value pairs)
    #[serde(default, deserialize_with = "option_object_or_json_string")]
    env: Option<std::collections::HashMap<String, String>>,
    /// Clear existing environment before adding env vars
    #[serde(default, alias = "clear_env")]
    clear_env: FlexBool,
    /// Prepend to existing env vars (e.g. {"PATH": "C:/new/bin;"} prepends to current PATH)
    #[serde(
        default,
        deserialize_with = "option_object_or_json_string",
        alias = "env_prepend"
    )]
    env_prepend: Option<std::collections::HashMap<String, String>>,
    /// Append to existing env vars (e.g. {"PATH": ";C:/extra/bin"} appends to current PATH)
    #[serde(
        default,
        deserialize_with = "option_object_or_json_string",
        alias = "env_append"
    )]
    env_append: Option<std::collections::HashMap<String, String>>,
    /// Timeout in milliseconds (command will be killed after this time)
    #[serde(default, alias = "timeout_ms")]
    timeout_ms: FlexU64,
    /// Optional watchdog delay in milliseconds added on top of timeout_ms
    #[serde(default, alias = "kill_after_ms")]
    kill_after_ms: FlexU64,
    /// Redirect stdout to this file
    #[serde(alias = "stdout_file")]
    stdout_file: Option<String>,
    /// Redirect stderr to this file
    #[serde(alias = "stderr_file")]
    stderr_file: Option<String>,
    /// Stdin via Content Plane (inline/base64/path/blob). Large scripts: write file then exec.
    stdin: Option<ContentRef>,
    /// Return first N lines of stdout
    #[serde(default, alias = "stdout_head")]
    stdout_head: FlexUsize,
    /// Return only last N lines of stdout
    #[serde(default, alias = "stdout_tail")]
    stdout_tail: FlexUsize,
    /// Return first N lines of stderr
    #[serde(default, alias = "stderr_head")]
    stderr_head: FlexUsize,
    /// Return only last N lines of stderr
    #[serde(default, alias = "stderr_tail")]
    stderr_tail: FlexUsize,
    /// Grep-like output filter (applies to inline results only, full output goes to log files)
    #[serde(
        default,
        deserialize_with = "option_object_or_json_string",
        alias = "output_filter"
    )]
    output_filter: Option<OutputFilterArgs>,
    /// Execution mode: "sync" (default), "managed", or "detached"
    #[serde(default)]
    mode: RunModeArg,
    /// Shell to wrap the command in. Accepts a bool or a shell name:
    /// - `false` (default): no shell — `command` is the program and `args` its
    ///   arguments (a full command line in `command` is auto-split, quote-aware).
    /// - `true`: platform default — `cmd /C` on Windows, `sh -c` on Unix.
    /// - `"bash"`: `bash -c` (git bash on Windows). USE THIS for unix-style
    ///   pipelines on any OS — `;` separators, pipes, and tools like
    ///   `tail`/`grep`/`sed`. Windows `cmd` does NOT understand `;` and lacks
    ///   those tools, so prefer `"bash"` for such command lines.
    /// - `"pwsh"`: PowerShell (`pwsh -NoProfile -Command`).
    /// - `"cmd"` / `"sh"`: force that specific shell.
    ///
    /// Named shells must be on `PATH`. With `cmd` the line reaches cmd.exe
    /// verbatim (via `raw_arg`), so backslash Windows paths survive intact —
    /// write them as at the prompt, e.g. `type "C:\dir\file"`.
    /// A MULTI-LINE command under `cmd` (newline-separated lines) runs EVERY
    /// line via a temp `.bat`, so it follows BATCH semantics rather than
    /// `cmd /C`: use `%%i` (not `%i`) in `for`, the exit code is that of the
    /// LAST line, and a failing middle line does NOT stop later lines (there is
    /// no implicit `&&`) — chain with `&&` if you need fail-fast.
    #[serde(default)]
    shell: ShellArg,
    /// Stream output to log files (auto-creates them if not provided). Default
    /// true. Streaming and the inline result are INDEPENDENT: stdout/stderr are
    /// always captured and returned inline too. Inline is the full output unless
    /// `stdoutHead`/`stdoutTail`/`outputFilter` trim it; with none of those it is
    /// capped to the last ~200 lines / 16 KB while the complete output stays in
    /// the log file. `stdoutTotalLines` always reports the true length.
    #[serde(default = "default_flex_true", alias = "stream_output")]
    stream_output: FlexBool,
    /// Directory for streamed output files (optional). Defaults to the OS temp
    /// dir (`<temp>/filesystem-mcp`) so auto-created logs never litter the cwd.
    #[serde(alias = "stream_dir")]
    stream_dir: Option<String>,
    /// DEPRECATED: use mode="detached" instead. Kept for backward compat.
    #[serde(default)]
    background: FlexBool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct KillProcessArgs {
    /// Process ID to kill
    pid: RU32,
    /// Force kill (SIGKILL on Unix, /F on Windows)
    #[serde(default)]
    force: FlexBool,
    /// Kill entire process tree (parent + all children)
    #[serde(default)]
    tree: FlexBool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ListProcessesArgs {
    /// Filter by command name (optional)
    filter: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct SearchProcessesArgs {
    /// Regex pattern to match process name (e.g., "chrome", "python.*")
    name_pattern: Option<String>,
    /// Regex pattern to match command line (e.g., "--port=8080", "script\\.py")
    cmdline_pattern: Option<String>,
}

#[cfg(feature = "screenshot-tools")]
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
enum ScreenshotOutputMode {
    #[default]
    File,
    Clipboard,
    Base64,
}

#[cfg(feature = "screenshot-tools")]
#[derive(Debug, Deserialize, JsonSchema)]
struct ListMonitorsArgs {}

#[cfg(feature = "screenshot-tools")]
#[derive(Debug, Deserialize, JsonSchema)]
struct ListWindowsArgs {
    title_filter: Option<String>,
}

#[cfg(feature = "screenshot-tools")]
#[derive(Debug, Deserialize, JsonSchema)]
struct CaptureScreenArgs {
    #[serde(default)]
    monitor_id: FlexU32,
    #[serde(default)]
    output: ScreenshotOutputMode,
    path: Option<String>,
}

#[cfg(feature = "screenshot-tools")]
#[derive(Debug, Deserialize, JsonSchema)]
struct CaptureWindowArgs {
    #[serde(default)]
    window_id: FlexU32,
    title: Option<String>,
    #[serde(default)]
    output: ScreenshotOutputMode,
    path: Option<String>,
}

#[cfg(feature = "screenshot-tools")]
#[derive(Debug, Deserialize, JsonSchema)]
struct CaptureRegionArgs {
    #[serde(default)]
    monitor_id: FlexU32,
    x: RI32,
    y: RI32,
    width: RU32,
    height: RU32,
    #[serde(default)]
    output: ScreenshotOutputMode,
    path: Option<String>,
}

#[cfg(feature = "screenshot-tools")]
#[derive(Debug, Deserialize, JsonSchema)]
struct CopyToClipboardArgs {
    path: String,
}

// ==================== XLSX TOOL ARGS ====================

#[derive(Debug, Deserialize, JsonSchema)]
struct XlsxInfoArgs {
    path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct XlsxSheetsArgs {
    path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct XlsxReadArgs {
    path: String,
    /// Sheet name (default: first sheet)
    sheet: Option<String>,
    /// Treat first row as headers (default: false)
    #[serde(default)]
    headers: FlexBool,
    /// Max rows to return
    #[serde(default)]
    max_rows: FlexU32,
    /// Skip first N data rows
    #[serde(default)]
    offset: FlexU32,
}

// ==================== DOCX TOOL ARGS ====================

#[derive(Debug, Deserialize, JsonSchema)]
struct DocxReadArgs {
    path: String,
    /// Include document structure (paragraphs, tables) instead of plain text
    #[serde(default)]
    include_structure: FlexBool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DocxInfoArgs {
    path: String,
}

// ==================== WAVE2 TOOL ARGS ====================

#[derive(Debug, Deserialize, JsonSchema)]
struct PortUsersArgs {
    /// Port number to check
    port: RU16,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct NetConnectionsArgs {
    /// Filter by process ID (optional)
    #[serde(default)]
    pid: FlexU32,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct PortAvailableArgs {
    /// Port number to check
    port: RU16,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ProcTreeArgs {
    /// Root process ID (optional, shows all if not specified)
    #[serde(default)]
    pid: FlexU32,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ProcEnvArgs {
    /// Process ID
    pid: RU32,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ProcFilesArgs {
    /// Process ID
    pid: RU32,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DiskUsageArgs {
    /// Path to check (optional, shows all disks if not specified)
    path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FileDiffArgs {
    /// First file path
    path1: String,
    /// Second file path
    path2: String,
    /// Context lines around changes (default: 3)
    #[serde(default = "default_context_lines")]
    context: usize,
}

fn default_context_lines() -> usize {
    3
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FileTouchArgs {
    /// File path to touch
    path: String,
    /// Create parent directories if needed
    #[serde(default)]
    create_parents: FlexBool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ClipboardWriteArgs {
    /// Text to write to clipboard
    text: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct EnvGetArgs {
    /// Environment variable name
    name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct EnvSetArgs {
    /// Environment variable name
    name: String,
    /// Value to set
    value: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct EnvRemoveArgs {
    /// Environment variable name to remove
    name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct WhichArgs {
    /// Command name to find (e.g. `cargo`, `naga`). The `name` alias is
    /// accepted too, since the Unix `which <name>` mental model makes it a
    /// natural first guess (bug.md #5).
    #[serde(alias = "name")]
    command: String,
}

#[tool_router]
impl FileSystemServer {
    #[tool(
        name = "read_text_file",
        description = "PREFERRED over built-in Read/cat. Read file with advanced pagination for large files.\n\n\
            **Why use this:** UTF-8 safe, handles large files without token overflow, returns totalLines metadata.\n\n\
            **Pagination options:**\n\
            - `offset` + `limit`: Read N lines starting from line M (1-indexed)\n\
            - `head`: First N lines only\n\
            - `tail`: Last N lines only\n\
            - `max_chars`: Truncate output to N characters (prevents token overflow)\n\n\
            **Line numbers:**\n\
            - `line_numbers`: Prefix output lines with 1-indexed line numbers and include `lines[]` in structured_content\n\n\
            **Examples:**\n\
            - Read lines 100-200: `{offset: 100, limit: 100}`\n\
            - Read first 50 lines: `{head: 50}`\n\
            - Limit output size: `{max_chars: 50000}`\n\
            - Read with line numbers: `{offset: 100, limit: 20, line_numbers: true}`"
    )]
    async fn read_text_file(
        &self,
        Parameters(ReadTextFileArgs {
            path,
            head,
            tail,
            offset,
            limit,
            max_chars,
            line_numbers,
        }): Parameters<ReadTextFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        // Extract Option values from Flex wrappers
        let head = head.get();
        let tail = tail.get();
        let offset = offset.get();
        let limit = limit.get();
        let max_chars = max_chars.get();

        // Validate mutually exclusive options
        let mode_count = [head.is_some(), tail.is_some(), offset.is_some()]
            .iter()
            .filter(|&&x| x)
            .count();
        if mode_count > 1 {
            return Err(McpError::invalid_params(
                "Cannot combine head, tail, and offset - use only one mode",
                None,
            ));
        }

        let path = self.resolve(&path).await?;

        let mut line_records: Option<Vec<serde_json::Value>> = None;
        let mut line_start: Option<usize> = None;
        let mut line_end: Option<usize> = None;
        let mut line_count: Option<usize> = None;

        // Read content based on mode
        let (mut content, total_lines) = if *line_numbers {
            let full = read_text(&path)
                .await
                .map_err(internal_err("Failed to read file"))?;
            let lines: Vec<&str> = full.lines().collect();
            let total = lines.len();

            let (start_idx, end_idx) = if let Some(h) = head {
                (0, (h as usize).min(total))
            } else if let Some(t) = tail {
                let count = t as usize;
                let start = total.saturating_sub(count);
                (start, total)
            } else if offset.is_some() || limit.is_some() {
                let start = offset.map(|o| (o as usize).saturating_sub(1)).unwrap_or(0);
                let count = limit.map(|l| l as usize).unwrap_or(usize::MAX);
                let end = start.saturating_add(count).min(total);
                (start, end)
            } else {
                (0, total)
            };

            let selected = if start_idx >= total {
                &[][..]
            } else {
                &lines[start_idx..end_idx]
            };

            let content = if !selected.is_empty() {
                let end_line = start_idx + selected.len();
                let width = end_line.to_string().len().max(1);
                let mut numbered = Vec::with_capacity(selected.len());
                let mut records = Vec::with_capacity(selected.len());
                for (i, line) in selected.iter().enumerate() {
                    let line_no = start_idx + i + 1;
                    numbered.push(format!("{:>width$} | {}", line_no, line, width = width));
                    records.push(json!({
                        "lineNumber": line_no,
                        "text": line,
                    }));
                }
                let content = numbered.join("\n");
                line_records = Some(records);
                line_start = Some(start_idx + 1);
                line_end = Some(end_line);
                line_count = Some(selected.len());
                content
            } else {
                line_records = Some(Vec::new());
                line_count = Some(0);
                String::new()
            };

            (content, Some(total))
        } else if let Some(h) = head {
            let text = head_lines(&path, h as usize)
                .await
                .map_err(internal_err("Failed to read head"))?;
            (text, None)
        } else if let Some(t) = tail {
            let text = tail_lines(&path, t as usize)
                .await
                .map_err(internal_err("Failed to read tail"))?;
            (text, None)
        } else if offset.is_some() || limit.is_some() {
            // Pagination mode: read full file then slice by lines
            let full = read_text(&path)
                .await
                .map_err(internal_err("Failed to read file"))?;
            let lines: Vec<&str> = full.lines().collect();
            let total = lines.len();

            let start = offset.map(|o| (o as usize).saturating_sub(1)).unwrap_or(0);
            let count = limit.map(|l| l as usize).unwrap_or(usize::MAX);
            let end = start.saturating_add(count).min(total);

            if start >= total {
                (String::new(), Some(total))
            } else {
                (lines[start..end].join("\n"), Some(total))
            }
        } else {
            let text = read_text(&path)
                .await
                .map_err(internal_err("Failed to read file"))?;
            let total = text.lines().count();
            (text, Some(total))
        };

        // Apply max_chars truncation if specified
        let truncated = if let Some(max) = max_chars {
            if content.chars().count() > max {
                let truncated_content: String = content.chars().take(max).collect();
                content = format!(
                    "{}\n\n[truncated at {} chars, total {} chars]",
                    truncated_content,
                    max,
                    content.chars().count()
                );
                true
            } else {
                false
            }
        } else {
            false
        };

        // Build response with metadata
        let mut meta = serde_json::Map::new();
        if let Some(total) = total_lines {
            meta.insert("totalLines".to_string(), json!(total));
        }
        if truncated {
            meta.insert("truncated".to_string(), json!(true));
        }
        if let Some(off) = offset {
            meta.insert("offset".to_string(), json!(off));
        }
        if let Some(lim) = limit {
            meta.insert("limit".to_string(), json!(lim));
        }
        if truncated && *line_numbers {
            meta.insert("linesTruncated".to_string(), json!(true));
            line_records = None;
        }
        if *line_numbers {
            meta.insert("lineNumbers".to_string(), json!(true));
            if let Some(start) = line_start {
                meta.insert("startLine".to_string(), json!(start));
            }
            if let Some(end) = line_end {
                meta.insert("endLine".to_string(), json!(end));
            }
            if let Some(count) = line_count {
                meta.insert("lineCount".to_string(), json!(count));
            }
        }

        let mut structured = serde_json::Map::new();
        structured.insert("content".to_string(), json!(content));
        structured.insert("meta".to_string(), json!(meta));
        if let Some(lines) = line_records {
            structured.insert("lines".to_string(), json!(lines));
        }

        Ok(
            CallToolResult::success(vec![ContentBlock::text(content.clone())])
                .with_structured(serde_json::Value::Object(structured)),
        )
    }

    #[tool(
        name = "read_media_file",
        description = "Read an image or audio file and return base64 data with MIME type."
    )]
    async fn read_media_file(
        &self,
        Parameters(ReadMediaArgs { path }): Parameters<ReadMediaArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&path).await?;
        let (data, mime) = read_media_base64(&path)
            .await
            .map_err(internal_err("Failed to read media file"))?;

        let content = if mime.starts_with("image/") {
            ContentBlock::image(data.clone(), mime.clone())
        } else if mime.starts_with("audio/") {
            // rmcp 2.x flattened Annotated<RawContent> into ContentBlock; annotations are now a
            // plain field, so there is no `.no_annotation()` step any more.
            rmcp::model::ContentBlock::Audio(rmcp::model::AudioContent::new(
                data.clone(),
                mime.clone(),
            ))
        } else {
            ContentBlock::text(format!(
                "Unsupported media type {mime}; returning base64\n{data}"
            ))
        };

        Ok(CallToolResult::success(vec![content]).with_structured(
            json!({ "content": [{ "type": if mime.starts_with("image/") { "image" } else if mime.starts_with("audio/") { "audio" } else { "blob" }, "data": data, "mimeType": mime }]})
        ))
    }

    #[tool(
        name = "read_multiple_files",
        description = "Read multiple files simultaneously; errors on one file do not stop others."
    )]
    async fn read_multiple_files(
        &self,
        Parameters(ReadMultipleArgs { paths }): Parameters<ReadMultipleArgs>,
    ) -> Result<CallToolResult, McpError> {
        if paths.is_empty() {
            return Err(McpError::invalid_params("paths must not be empty", None));
        }
        let tasks = paths.into_iter().map(|p| async move {
            let resolved = self.resolve(&p).await;
            match resolved {
                Ok(path) => match read_text(&path).await {
                    Ok(content) => format!("{}:\n{}", p, content),
                    Err(err) => format!("{}: Error - {}", p, err),
                },
                Err(err) => format!("{}: Error - {}", p, err),
            }
        });
        let joined = join_all(tasks).await.join("\n---\n");
        Ok(
            CallToolResult::success(vec![ContentBlock::text(joined.clone())])
                .with_structured(json!({ "content": joined })),
        )
    }

    #[tool(
        name = "write_file",
        description = "PREFERRED over built-in Write. Create/overwrite via Content Plane.

            content is a ContentRef object (NOT a bare string):
            - {kind:inline, text} max 64KiB UTF-8 (a bare string is tolerated as inline)
            - {kind:base64, data} max 64KiB decoded
            - {kind:path, path} allowlisted file
            - {kind:blob, id} from blob_begin/append/finalize

            Large files: blob_begin -> blob_append chunks -> blob_finalize -> write_file {kind:blob,id}.
            Never python -c for large content. Optional expectSha256."
    )]
    async fn write_file(
        &self,
        Parameters(WriteFileArgs {
            path,
            content,
            expect_sha256,
        }): Parameters<WriteFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        let bytes = self
            .resolve_content_checked(&content, ContentMode::Text, expect_sha256.as_deref())
            .await?;
        info!(target_path = %path, content_len = bytes.len(), "write_file: start");

        let path = self.resolve(&path).await?;
        info!(resolved_path = %path.display(), "write_file: path resolved");

        if let Some(parent) = path.parent() {
            info!(parent = %parent.display(), "write_file: creating parent dirs");
            fs::create_dir_all(parent)
                .await
                .map_err(internal_err("Failed to create parent directories"))?;
        }

        static WRITE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = WRITE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp_name = format!(
            "{}.{}.{}.tmp_mcp_write",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("out"),
            std::process::id(),
            seq
        );
        let tmp_path = path.with_file_name(tmp_name);
        info!(tmp_path = %tmp_path.display(), "write_file: writing temp file");
        fs::write(&tmp_path, &bytes)
            .await
            .map_err(internal_err("Failed to write temp file"))?;

        info!("write_file: renaming temp to target");
        if let Err(e) = fs::rename(&tmp_path, &path).await {
            let _ = fs::remove_file(&tmp_path).await;
            return Err(internal_err("Failed to move temp file into place")(e));
        }

        info!(path = %path.display(), "write_file: success");
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Successfully wrote {} bytes to {}",
            bytes.len(),
            path.display()
        ))])
        .with_structured(json!({
            "path": path.display().to_string(),
            "bytesWritten": bytes.len(),
            "sha256": sha256_hex(&bytes),
        })))
    }

    #[tool(
        name = "blob_begin",
        description = "Open a Content Plane staging session for large payloads.\n\n\
            Returns {sessionId}. Append with blob_append (max 64KiB/chunk), then blob_finalize\n\
            to get {id,sha256,bytes}. Pass {kind:blob,id} to write_file / edit_file / run_command.stdin."
    )]
    async fn blob_begin(&self) -> Result<CallToolResult, McpError> {
        let session_id = self.content_plane.begin().map_err(Self::content_err)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "blob session {session_id}"
        ))])
        .with_structured(json!({ "sessionId": session_id })))
    }

    #[tool(
        name = "blob_append",
        description = "Append a chunk to a blob session (max 64KiB). Provide text OR dataBase64."
    )]
    async fn blob_append(
        &self,
        Parameters(BlobAppendArgs {
            session_id,
            text,
            data_base64,
        }): Parameters<BlobAppendArgs>,
    ) -> Result<CallToolResult, McpError> {
        let chunk = ContentPlane::decode_chunk(text.as_deref(), data_base64.as_deref())
            .map_err(Self::content_err)?;
        self.content_plane
            .append(&session_id, &chunk)
            .map_err(Self::content_err)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "appended {} bytes to session {}",
            chunk.len(),
            session_id
        ))])
        .with_structured(json!({
            "sessionId": session_id,
            "bytesAppended": chunk.len(),
        })))
    }

    #[tool(
        name = "blob_finalize",
        description = "Finalize a blob session into a content-addressed blob id (sha256 hex)."
    )]
    async fn blob_finalize(
        &self,
        Parameters(BlobFinalizeArgs {
            session_id,
            expect_sha256,
        }): Parameters<BlobFinalizeArgs>,
    ) -> Result<CallToolResult, McpError> {
        let fin = self
            .content_plane
            .finalize(&session_id, expect_sha256.as_deref())
            .map_err(Self::content_err)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "blob {} ({} bytes)",
            fin.id, fin.bytes
        ))])
        .with_structured(json!({
            "id": fin.id,
            "bytes": fin.bytes,
            "sha256": fin.sha256,
        })))
    }

    #[tool(
        name = "blob_stat",
        description = "Stat a finalized Content Plane blob by id (sha256 hex)."
    )]
    async fn blob_stat(
        &self,
        Parameters(BlobStatArgs { id }): Parameters<BlobStatArgs>,
    ) -> Result<CallToolResult, McpError> {
        let st = self.content_plane.stat(&id).map_err(Self::content_err)?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "blob {} ({} bytes)",
            st.id, st.bytes
        ))])
        .with_structured(json!({
            "id": st.id,
            "bytes": st.bytes,
            "sha256": st.sha256,
        })))
    }

    #[tool(
        name = "edit_file",
        description = "PREFERRED over built-in Edit/sed. Apply text edits with unified diff.

            Each edit: oldText/newText are UTF-8 strings (preferred for short snippets, including `{`).
            ContentRef objects (inline/base64/path/blob) also work, max 64KiB per side. Large rewrites: write_file + blob.
            Set isRegex=true for patterns, replaceAll=true to replace all, dryRun to preview."
    )]
    async fn edit_file(
        &self,
        Parameters(EditFileArgs {
            path,
            edits,
            dry_run,
        }): Parameters<EditFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&path).await?;
        // Read with round-trip metadata so the write preserves the file's
        // original encoding, BOM, and newline style instead of forcing UTF-8/LF.
        let tf = read_text_meta(&path)
            .await
            .map_err(internal_err("Failed to read file"))?;
        tf.ensure_roundtrippable()
            .map_err(internal_err("Cannot edit file"))?;

        let mut resolved_edits = Vec::with_capacity(edits.len());
        for e in edits {
            let old_ref = e.old_text.into_ref();
            let new_ref = e.new_text.into_ref();
            let old_bytes = self.resolve_content(&old_ref, ContentMode::Text).await?;
            let new_bytes = self.resolve_content(&new_ref, ContentMode::Text).await?;
            let old_text = String::from_utf8(old_bytes)
                .map_err(|err| Self::content_err(ContentError::InvalidUtf8(err.to_string())))?;
            let new_text = String::from_utf8(new_bytes)
                .map_err(|err| Self::content_err(ContentError::InvalidUtf8(err.to_string())))?;
            resolved_edits.push(FileEdit {
                old_text,
                new_text,
                is_regex: *e.is_regex,
                replace_all: *e.replace_all,
            });
        }
        let outcome = apply_edits(&tf.text, &resolved_edits)
            .map_err(internal_err("Failed to apply edits"))?;

        if !*dry_run {
            let bytes = tf
                .encode(&outcome.modified)
                .map_err(internal_err("Failed to encode edited file"))?;
            fs::write(&path, &bytes)
                .await
                .map_err(internal_err("Failed to write edited file"))?;
        }

        Ok(self.diff_response(outcome.diff))
    }

    #[tool(
        name = "create_directory",
        description = "Create new directory (and parents) or ensure it exists."
    )]
    async fn create_directory(
        &self,
        Parameters(CreateDirArgs { path }): Parameters<CreateDirArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&path).await?;
        fs::create_dir_all(&path)
            .await
            .map_err(internal_err("Failed to create directory"))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Successfully created directory {}",
            path.display()
        ))]))
    }

    #[tool(
        name = "list_directory",
        description = "List entries in a directory with [FILE]/[DIR] prefixes."
    )]
    async fn list_directory(
        &self,
        Parameters(ListDirArgs { path }): Parameters<ListDirArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&path).await?;
        let mut dir = fs::read_dir(&path)
            .await
            .map_err(internal_err("Failed to read directory"))?;
        let mut entries = Vec::new();
        while let Some(entry) = dir
            .next_entry()
            .await
            .map_err(internal_err("Failed to iterate directory"))?
        {
            let kind = entry
                .file_type()
                .await
                .map_err(internal_err("stat entry"))?;
            let prefix = if kind.is_dir() { "[DIR]" } else { "[FILE]" };
            entries.push(format!(
                "{} {}",
                prefix,
                entry.file_name().to_string_lossy()
            ));
        }
        entries.sort();
        let listing = entries.join("\n");
        Ok(
            CallToolResult::success(vec![ContentBlock::text(listing.clone())])
                .with_structured(json!({ "entries": entries })),
        )
    }

    #[tool(
        name = "list_directory_with_sizes",
        description = "List directory entries with sizes and summary."
    )]
    async fn list_directory_with_sizes(
        &self,
        Parameters(ListDirWithSizesArgs { path, sort_by }): Parameters<ListDirWithSizesArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&path).await?;
        let mut dir = fs::read_dir(&path)
            .await
            .map_err(internal_err("Failed to read directory"))?;

        let mut entries = Vec::new();
        while let Some(entry) = dir
            .next_entry()
            .await
            .map_err(internal_err("Failed to iterate directory"))?
        {
            let file_type = entry
                .file_type()
                .await
                .map_err(internal_err("stat entry"))?;
            let meta = entry.metadata().await.map_err(internal_err("stat entry"))?;
            entries.push((
                entry.file_name().to_string_lossy().to_string(),
                file_type.is_dir(),
                meta.len(),
            ));
        }

        match sort_by {
            SortBy::Name => entries.sort_by_key(|e| e.0.to_lowercase()),
            SortBy::Size => entries.sort_by_key(|e| std::cmp::Reverse(e.2)),
        }

        let formatted: Vec<String> = entries
            .iter()
            .map(|(name, is_dir, size)| {
                let prefix = if *is_dir { "[DIR]" } else { "[FILE]" };
                let size_str = if *is_dir {
                    "".to_string()
                } else {
                    format::format_size(*size)
                };
                format!("{prefix} {name:<30} {size_str:>10}")
            })
            .collect();

        let total_files = entries.iter().filter(|(_, is_dir, _)| !*is_dir).count();
        let total_dirs = entries.iter().filter(|(_, is_dir, _)| *is_dir).count();
        let total_size: u64 = entries
            .iter()
            .filter(|(_, is_dir, _)| !*is_dir)
            .map(|(_, _, size)| *size)
            .sum();

        let summary = vec![
            String::new(),
            format!("Total: {total_files} files, {total_dirs} directories"),
            format!("Combined size: {}", format::format_size(total_size)),
        ];
        let text_lines: Vec<String> = formatted
            .iter()
            .cloned()
            .chain(summary.clone().into_iter())
            .collect();
        let text = text_lines.join("\n");

        Ok(
            CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
                "entries": entries,
                "totalFiles": total_files,
                "totalDirectories": total_dirs,
                "totalSize": total_size
            })),
        )
    }

    #[tool(
        name = "directory_tree",
        description = "Return recursive JSON tree of a directory; supports exclude patterns."
    )]
    async fn directory_tree(
        &self,
        Parameters(DirectoryTreeArgs {
            path,
            exclude_patterns,
            max_depth,
            show_size,
            show_hash,
        }): Parameters<DirectoryTreeArgs>,
    ) -> Result<CallToolResult, McpError> {
        let root = self.resolve(&path).await?;
        let exclude = search::build_exclude_set(&exclude_patterns)
            .map_err(internal_err("Invalid exclude patterns"))?;

        let opts = TreeOptions {
            max_depth: if max_depth == 0 {
                usize::MAX
            } else {
                max_depth
            },
            show_size: *show_size,
            show_hash: *show_hash,
        };
        let entries = build_tree(&root, &root, &exclude, &opts, 0).await?;
        let json_tree = serde_json::to_string_pretty(&entries)
            .map_err(internal_err("Failed to serialize tree"))?;
        Ok(
            CallToolResult::success(vec![ContentBlock::text(json_tree.clone())])
                .with_structured(json!({ "tree": entries })),
        )
    }

    #[tool(
        name = "move_file",
        description = "Move or rename files/directories; fails if destination exists."
    )]
    async fn move_file(
        &self,
        Parameters(MoveFileArgs {
            source,
            destination,
        }): Parameters<MoveFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        let src = self.resolve(&source).await?;
        let dest = self.resolve(&destination).await?;
        // Documented contract is "fails if destination exists", but fs::rename
        // silently overwrites. Enforce the contract. symlink_metadata so a
        // symlink (even a broken one) at the destination also counts as present.
        if src != dest && fs::symlink_metadata(&dest).await.is_ok() {
            return Err(McpError::invalid_params(
                format!(
                    "Destination already exists: {} (move_file will not overwrite)",
                    dest.display()
                ),
                None,
            ));
        }
        fs::rename(&src, &dest)
            .await
            .map_err(internal_err("Failed to move/rename"))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Moved {} to {}",
            src.display(),
            dest.display()
        ))]))
    }

    #[tool(
        name = "copy_file",
        description = "Copy a file or directory to a destination. Set overwrite to true to replace existing targets."
    )]
    async fn copy_file(
        &self,
        Parameters(CopyFileArgs {
            source,
            destination,
            overwrite,
        }): Parameters<CopyFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        let source = self.resolve(&source).await?;
        let destination = self.resolve(&destination).await?;

        // Copying a path onto itself would, in the overwrite branch below, delete
        // the destination (== source) and then fail the copy — destroying the file.
        if source == destination {
            return Err(McpError::invalid_params(
                "Source and destination are the same path",
                None,
            ));
        }

        let metadata = fs::metadata(&source)
            .await
            .map_err(internal_err("Failed to stat source"))?;

        let dest_exists = fs::symlink_metadata(&destination).await.is_ok();
        if dest_exists && !*overwrite {
            return Err(McpError::invalid_params(
                "Destination exists; set overwrite to true to replace",
                None,
            ));
        }

        if metadata.is_dir() {
            // Directory copy is not staged; remove an existing destination first.
            if dest_exists {
                if destination.is_dir() {
                    fs::remove_dir_all(&destination)
                        .await
                        .map_err(internal_err("Failed to remove destination directory"))?;
                } else {
                    fs::remove_file(&destination)
                        .await
                        .map_err(internal_err("Failed to remove destination file"))?;
                }
            }
            self.copy_dir_recursive(&source, &destination).await?;
        } else {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)
                    .await
                    .map_err(internal_err("Failed to create destination directory"))?;
            }
            // Stage into a temp sibling, then atomically publish, so a failed or
            // partial copy never truncates or deletes a pre-existing destination.
            static COPY_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let seq = COPY_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let tmp_name = format!(
                "{}.{}.{}.tmp_mcp_copy",
                destination
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("out"),
                std::process::id(),
                seq
            );
            let tmp = destination.with_file_name(tmp_name);
            if let Err(e) = fs::copy(&source, &tmp).await {
                let _ = fs::remove_file(&tmp).await;
                return Err(internal_err("Failed to copy file")(e));
            }
            if let Err(e) = fs::rename(&tmp, &destination).await {
                let _ = fs::remove_file(&tmp).await;
                return Err(internal_err("Failed to publish copied file")(e));
            }
        }

        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Copied {} to {}",
            source.display(),
            destination.display()
        ))]))
    }

    #[tool(
        name = "delete_path",
        description = "Delete a file, or delete a directory when recursive=true."
    )]
    async fn delete_path(
        &self,
        Parameters(DeletePathArgs { path, recursive }): Parameters<DeletePathArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&path).await?;
        let metadata = fs::metadata(&path)
            .await
            .map_err(internal_err("Failed to stat path"))?;

        if metadata.is_dir() {
            if !*recursive {
                return Err(McpError::invalid_params(
                    "Refusing to delete directory without recursive=true",
                    None,
                ));
            }
            fs::remove_dir_all(&path)
                .await
                .map_err(internal_err("Failed to delete directory"))?;
        } else {
            fs::remove_file(&path)
                .await
                .map_err(internal_err("Failed to delete file"))?;
        }

        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Deleted {}",
            path.display()
        ))]))
    }

    #[tool(
        name = "search_files",
        description = "PREFERRED over built-in Glob/find. Search paths by glob (not file contents — use grep_files for that).\n\n\
            **Why use this:** Exclusions, structured JSON (path, size, modified unix secs), symlink-safe validation.\n\n\
            **Filters:** fileType (file/dir/symlink/any), minSize/maxSize (bytes), modifiedAfter/modifiedBefore.\n\
            Time filters: RFC3339 (2024-01-01T12:00:00Z) or duration (17m 20s, 17m20s, 2h, 7d) = cutoff at now minus span.\n\n\
            **Workflow examples:**\n\
            - Files touched in the last 17m 20s: {path:\".\", pattern:\"**/*\", fileType:\"file\", modifiedAfter:\"17m 20s\"}\n\
            - Exclude build dirs: excludePatterns:[\"target/**\",\"node_modules/**\"]\n\
            - Older than 7 days: modifiedBefore:\"7d\"\n\
            - Window 1h..10m ago: modifiedAfter:\"1h\", modifiedBefore:\"10m\""
    )]
    async fn search_files(
        &self,
        Parameters(SearchArgs {
            path,
            pattern,
            exclude_patterns,
            file_type,
            min_size,
            max_size,
            modified_after,
            modified_before,
        }): Parameters<SearchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let root = self.resolve(&path).await?;

        // Parse file type filter
        let ft = file_type
            .as_deref()
            .and_then(FileTypeFilter::from_str)
            .unwrap_or_default();

        let modified_after = match modified_after.as_deref() {
            Some(raw) => Some(
                parse_time_filter(raw)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?,
            ),
            None => None,
        };
        let modified_before = match modified_before.as_deref() {
            Some(raw) => Some(
                parse_time_filter(raw)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?,
            ),
            None => None,
        };

        let params = SearchParams {
            root: root.to_string_lossy().to_string(),
            pattern,
            exclude_patterns,
            file_type: ft,
            min_size: min_size.get(),
            max_size: max_size.get(),
            modified_after,
            modified_before,
        };

        let results = search_files_extended(&params, &self.allowed, self.allow_symlink_escape)
            .await
            .map_err(internal_err("Search failed"))?;

        let text = if results.is_empty() {
            "No matches found".to_string()
        } else {
            results
                .iter()
                .map(|r| r.path.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join("\n")
        };

        Ok(CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
            "matches": results.iter().map(|r| json!({
                "path": r.path,
                "isFile": r.is_file,
                "isDir": r.is_dir,
                "isSymlink": r.is_symlink,
                "size": r.size,
                "modified": r.modified.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()),
            })).collect::<Vec<_>>(),
            "count": results.len(),
        })))
    }

    #[tool(
        name = "get_file_info",
        description = "Return metadata for a file or directory (size, times, type, permissions)."
    )]
    async fn get_file_info(
        &self,
        Parameters(FileInfoArgs { path }): Parameters<FileInfoArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&path).await?;
        let meta = fs::metadata(&path)
            .await
            .map_err(internal_err("Failed to stat path"))?;

        let info = json!({
            "path": path.to_string_lossy(),
            "isDirectory": meta.is_dir(),
            "isFile": meta.is_file(),
            "size": meta.len(),
            "created": format_time(meta.created().ok()),
            "modified": format_time(meta.modified().ok()),
            "accessed": format_time(meta.accessed().ok()),
            "permissions": permissions_string(&meta),
        });

        let text = info
            .as_object()
            .map(|o| {
                o.iter()
                    .map(|(k, v)| format!("{k}: {v}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();

        Ok(CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(info))
    }

    #[tool(
        name = "list_allowed_directories",
        description = "List the directories this server is allowed to access."
    )]
    async fn list_allowed_directories(&self) -> Result<CallToolResult, McpError> {
        let dirs = self.allowed.snapshot().await;
        let lines: Vec<String> = dirs
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        let text = if lines.is_empty() {
            "No allowed directories configured".to_string()
        } else {
            format!("Allowed directories:\n{}", lines.join("\n"))
        };
        Ok(
            CallToolResult::success(vec![ContentBlock::text(text.clone())])
                .with_structured(json!({ "directories": lines })),
        )
    }

    #[tool(
        name = "grep_files",
        description = "Search file CONTENTS by regex. Powered by ripgrep's library (grep-regex + grep-searcher + ignore). Use instead of shell grep or built-in Grep.\n\n\
            TWO DISTINCT FIELDS — do not confuse them:\n\
            - `pattern`     : regex matched against file CONTENTS (required)\n\
            - `filePattern` : glob matched against file NAMES/PATHS (optional, e.g. \"*.rs\")\n\n\
            Examples:\n\
            {\"path\": \"src\", \"pattern\": \"catch_unwind\"}\n\
            {\"path\": \"src\", \"pattern\": \"catch_unwind\", \"filePattern\": \"*.rs\"}\n\
            {\"path\": \"src\", \"pattern\": \"TODO\", \"contextBefore\": 2, \"contextAfter\": 2}\n\
            {\"path\": \"src\", \"pattern\": \"foo,\\n\\s*bar\", \"multiline\": true}\n\n\
            Pass `pattern` as a regular JSON string value — do not embed extra quote characters inside the value. \
            Search for the identifier itself, not with surrounding source delimiters \
            (e.g. `spawn_worker`, not `\"spawn_worker\"` or `spawn_worker;`).\n\n\
            Common options:\n\
            - `multiline` (bool): allow `\\n` in pattern and span multiple lines. REQUIRED when matching across line breaks.\n\
            - `fixedStrings` (bool): treat `pattern` as a literal string (no regex parsing). Like `rg -F`.\n\
            - `wholeWord` (bool): require word boundaries on both sides. Like `rg -w`.\n\
            - `caseInsensitive` (bool), `invertMatch` (bool).\n\
            - `contextBefore`/`contextAfter` (int): like `rg -B`/`-A`.\n\
            - `maxMatches` (int, default 100).\n\
            - `maxDepth` (int): cap recursion (0 = unlimited).\n\
            - `maxFilesize` (int bytes): skip huge blobs (0 = no limit).\n\
            - `excludePatterns` (array, e.g. [\"target/**\"]).\n\
            - `outputMode`: `content` (default) | `files_with_matches` | `files_without_match` | `count`.\n\n\
            **Engines:**\n\
            - Default `engine: \"regex\"` uses ripgrep's regex crate — linear time, NO look-around / backreferences. SIMD-accelerated.\n\
            - `engine: \"fancy\"` switches to `fancy_regex` — supports `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`, `\\1` backrefs. Backtracking; slower; can ReDoS on pathological patterns.\n\
            - `encoding`: force a file encoding (e.g. `utf-16`, `windows-1251`); default auto-detects.\n\
            - `heapLimitMb`: cap searcher RAM (multi-line mode safeguard against gigantic single-line files)."
    )]
    async fn grep_files(
        &self,
        Parameters(args): Parameters<GrepFilesArgs>,
        meta: RequestMetaObject,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.ensure_allowed().await?;

        if args.path.trim().is_empty() {
            return Err(McpError::invalid_params(
                "grep_files: missing or empty 'path' (root directory to search). \
                 Accepted keys: path, root, dir, directory. If you sent one of these, \
                 the host may have dropped it from the call — resend with a non-empty value."
                    .to_string(),
                None,
            ));
        }

        // Parse output mode
        let output_mode = match args.output_mode.as_deref() {
            Some("count") | Some("count_only") => grep::GrepOutputMode::CountOnly,
            Some("files_with_matches") | Some("files") => grep::GrepOutputMode::FilesWithMatches,
            Some("files_without_match") => grep::GrepOutputMode::FilesWithoutMatch,
            _ => grep::GrepOutputMode::ContentBlock,
        };

        let engine = match args.engine.as_deref() {
            None | Some("regex") => GrepEngine::Regex,
            Some("fancy") | Some("fancy-regex") => GrepEngine::Fancy,
            Some(other) => {
                return Err(McpError::invalid_params(
                    format!("unknown engine '{other}'; expected 'regex' or 'fancy'"),
                    None,
                ));
            }
        };

        let params = GrepParams {
            root: args.path.clone(),
            pattern: args.pattern.clone(),
            file_pattern: args.file_pattern.clone(),
            exclude_patterns: args.exclude_patterns.clone(),
            case_insensitive: *args.case_insensitive,
            context_before: args.context_before,
            context_after: args.context_after,
            max_matches: args.max_matches,
            invert_match: *args.invert_match,
            output_mode,
            multiline: *args.multiline,
            fixed_strings: *args.fixed_strings,
            whole_word: *args.whole_word,
            max_depth: args.max_depth,
            max_filesize: args.max_filesize,
            encoding: args.encoding.clone(),
            heap_limit_mb: args.heap_limit_mb,
            engine,
        };

        let progress_cb = grep_progress_callback(meta.get_progress_token(), client);
        let fast_result = grep_files_fast(
            params,
            &self.allowed,
            self.allow_symlink_escape,
            progress_cb,
        )
        .await
        .map_err(|e| {
            let details = format!("{:#}", e);
            McpError::internal_error(format!("Grep failed: {}", details), None)
        })?;
        let stats = grep_stats_json(&fast_result.stats);
        let result = fast_result.result;

        // Format results based on output mode
        let (text, structured) = match result {
            grep::GrepResult::Matches(ref matches) => {
                let mut lines = Vec::new();
                for m in matches {
                    let path_str = m.path.to_string_lossy();
                    for (i, line) in m.before_context.iter().enumerate() {
                        let line_no = m.line_number - m.before_context.len() + i;
                        lines.push(format!("{}:{}:  {}", path_str, line_no, line));
                    }
                    lines.push(format!("{}:{}:> {}", path_str, m.line_number, m.line));
                    for (i, line) in m.after_context.iter().enumerate() {
                        let line_no = m.line_number + i + 1;
                        lines.push(format!("{}:{}:  {}", path_str, line_no, line));
                    }
                    if !m.after_context.is_empty() {
                        lines.push("--".to_string());
                    }
                }
                let txt = if matches.is_empty() {
                    format!("No matches for: {}", args.pattern)
                } else {
                    format!("Found {} matches:\n\n{}", matches.len(), lines.join("\n"))
                };
                let s = json!({
                    "matches": matches.iter().map(|m| json!({
                        "path": m.path.to_string_lossy(),
                        "lineNumber": m.line_number,
                        "line": m.line,
                    })).collect::<Vec<_>>(),
                    "totalMatches": matches.len(),
                    "stats": stats,
                });
                (txt, s)
            }
            grep::GrepResult::Counts(ref counts) => {
                let txt = counts
                    .iter()
                    .map(|c| format!("{}: {}", c.path.display(), c.count))
                    .collect::<Vec<_>>()
                    .join("\n");
                let s = json!({
                    "counts": counts.iter().map(|c| json!({
                        "path": c.path.to_string_lossy(),
                        "count": c.count,
                    })).collect::<Vec<_>>(),
                    "stats": stats,
                });
                (txt, s)
            }
            grep::GrepResult::Files(ref files) => {
                let txt = files
                    .iter()
                    .map(|f| f.display().to_string())
                    .collect::<Vec<_>>()
                    .join("\n");
                let s = json!({
                    "files": files.iter().map(|f| f.to_string_lossy()).collect::<Vec<_>>(),
                    "stats": stats,
                });
                (txt, s)
            }
        };

        Ok(CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(structured))
    }

    #[tool(
        name = "grep_context",
        description = "Context-aware grep. Find a pattern only when nearby words/phrases appear within a window.\\n\\n\\
            Use this to reduce noise by requiring context terms near the match.\\n\\n\\
            **Features:**\\n\\
            - Nearby patterns matched by words or characters\\n\\
            - Direction control: before/after/both\\n\\
            - Match mode: any/all\\n\\
            - Same include/exclude, context lines, and output modes as grep_files\\n\\
            - Same `fixedStrings`, `wholeWord`, `maxDepth`, `maxFilesize`, `engine` flags as grep_files (multi-line patterns work natively without a flag here — the matcher reads each file whole).\\n\\n\\
            **Example:**\\n\\
            {\\\"path\\\": \\\".\\\", \\\"pattern\\\": \\\"error\\\", \\\"nearbyPatterns\\\": [\\\"timeout\\\", \\\"retry\\\"], \\\"nearbyWindowWords\\\": 6, \\\"nearbyDirection\\\": \\\"before\\\"}\\n\\n\\
            **Pattern tips:** Do NOT include surrounding quotes, semicolons, or other syntax \\
            delimiters from source code in your pattern. Search for the identifier itself \\
            (e.g. `ext_computation`, not `ext_computation\\\"`)."
    )]
    async fn grep_context(
        &self,
        Parameters(args): Parameters<GrepContextArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.ensure_allowed().await?;

        if args.nearby_patterns.is_empty() {
            return Err(McpError::invalid_params(
                "nearbyPatterns must contain at least one pattern",
                None,
            ));
        }

        if args.nearby_window_words.is_none() && args.nearby_window_chars.is_none() {
            return Err(McpError::invalid_params(
                "Provide nearbyWindowWords and/or nearbyWindowChars",
                None,
            ));
        }

        let output_mode = match args.output_mode.as_deref() {
            Some("count") | Some("count_only") => grep::GrepOutputMode::CountOnly,
            Some("files_with_matches") | Some("files") => grep::GrepOutputMode::FilesWithMatches,
            Some("files_without_match") => grep::GrepOutputMode::FilesWithoutMatch,
            _ => grep::GrepOutputMode::ContentBlock,
        };

        let direction = match args.nearby_direction.as_deref() {
            Some("before") => NearbyDirection::Before,
            Some("after") => NearbyDirection::After,
            _ => NearbyDirection::Both,
        };

        let match_mode = match args.nearby_match_mode.as_deref() {
            Some("all") => NearbyMatchMode::All,
            _ => NearbyMatchMode::Any,
        };

        let pattern = args.pattern.clone();
        let engine = match args.engine.as_deref() {
            None | Some("regex") => GrepEngine::Regex,
            Some("fancy") | Some("fancy-regex") => GrepEngine::Fancy,
            Some(other) => {
                return Err(McpError::invalid_params(
                    format!("unknown engine '{other}'; expected 'regex' or 'fancy'"),
                    None,
                ));
            }
        };

        let params = GrepContextParams {
            root: args.path,
            pattern,
            file_pattern: args.file_pattern,
            exclude_patterns: args.exclude_patterns,
            case_insensitive: *args.case_insensitive,
            context_before: args.context_before,
            context_after: args.context_after,
            max_matches: args.max_matches,
            output_mode,
            nearby_patterns: args.nearby_patterns,
            nearby_is_regex: *args.nearby_is_regex,
            nearby_case_insensitive: *args.nearby_case_insensitive,
            nearby_direction: direction,
            nearby_window_words: args.nearby_window_words.get(),
            nearby_window_chars: args.nearby_window_chars.get(),
            nearby_match_mode: match_mode,
            fixed_strings: *args.fixed_strings,
            whole_word: *args.whole_word,
            max_depth: args.max_depth,
            max_filesize: args.max_filesize,
            engine,
        };

        let result = grep_context_files(params, &self.allowed, self.allow_symlink_escape)
            .await
            .map_err(|e| McpError::internal_error(format!("Grep context failed: {}", e), None))?;

        let (text, structured) = match result {
            grep::GrepResult::Matches(ref matches) => {
                let mut lines = Vec::new();
                for m in matches {
                    let path_str = m.path.to_string_lossy();
                    for (i, line) in m.before_context.iter().enumerate() {
                        let line_no = m.line_number - m.before_context.len() + i;
                        lines.push(format!("{}:{}:  {}", path_str, line_no, line));
                    }
                    lines.push(format!("{}:{}:> {}", path_str, m.line_number, m.line));
                    for (i, line) in m.after_context.iter().enumerate() {
                        let line_no = m.line_number + i + 1;
                        lines.push(format!("{}:{}:  {}", path_str, line_no, line));
                    }
                    if !m.after_context.is_empty() {
                        lines.push("--".to_string());
                    }
                }
                let txt = if matches.is_empty() {
                    format!("No matches for: {}", args.pattern)
                } else {
                    format!(
                        "Found {} matches:\\n\\n{}",
                        matches.len(),
                        lines.join("\\n")
                    )
                };
                let s = json!({
                    "matches": matches.iter().map(|m| json!({
                        "path": m.path.to_string_lossy(),
                        "lineNumber": m.line_number,
                        "line": m.line,
                    })).collect::<Vec<_>>(),
                    "totalMatches": matches.len(),
                });
                (txt, s)
            }
            grep::GrepResult::Counts(ref counts) => {
                let txt = counts
                    .iter()
                    .map(|c| format!("{}: {}", c.path.display(), c.count))
                    .collect::<Vec<_>>()
                    .join("\\n");
                let s = json!({
                    "counts": counts.iter().map(|c| json!({
                        "path": c.path.to_string_lossy(),
                        "count": c.count,
                    })).collect::<Vec<_>>(),
                });
                (txt, s)
            }
            grep::GrepResult::Files(ref files) => {
                let txt = files
                    .iter()
                    .map(|f| f.display().to_string())
                    .collect::<Vec<_>>()
                    .join("\\n");
                let s = json!({
                    "files": files.iter().map(|f| f.to_string_lossy()).collect::<Vec<_>>(),
                });
                (txt, s)
            }
        };

        Ok(CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(structured))
    }

    #[cfg(feature = "http-tools")]
    #[tool(
        name = "http_request",
        description = "HTTP/HTTPS request with method, headers, cookies, query params, and body. Requires allowlisted domains."
    )]
    async fn http_request(
        &self,
        Parameters(args): Parameters<HttpRequestArgs>,
    ) -> Result<CallToolResult, McpError> {
        let _parsed = self.ensure_http_allowed(&args.url)?;

        let mut body_bytes = None;
        if let Some(path) = &args.body_path {
            let resolved = self.resolve(path).await?;
            body_bytes = Some(
                fs::read(&resolved)
                    .await
                    .map_err(internal_err("Failed to read body file"))?,
            );
        }

        let params = HttpRequestParams {
            method: args.method.clone(),
            url: args.url.clone(),
            headers: args.headers.clone(),
            cookies: args.cookies.clone(),
            query: args.query.clone(),
            body: args.body.clone(),
            body_base64: *args.body_base64,
            body_bytes,
            timeout_ms: args.timeout_ms,
            max_bytes: args.max_bytes,
        };

        let client = self.http_client(*args.follow_redirects);
        let resp = http_request(client, params)
            .await
            .map_err(|e| McpError::internal_error(format!("HTTP request failed: {e}"), None))?;

        let accept = args.accept.as_deref().unwrap_or("bytes");
        let (body_text, body_base64, json_value, parse_error) = match accept {
            "text" => (Some(decode_body_text(&resp.body)), None, None, None),
            "json" => match serde_json::from_slice::<Value>(&resp.body) {
                Ok(v) => (None, None, Some(v), None),
                Err(e) => (None, None, None, Some(format!("Invalid JSON: {e}"))),
            },
            _ => (None, Some(to_base64(&resp.body)), None, None),
        };

        let text = format!(
            "HTTP {} {} (truncated: {})",
            resp.status, resp.url, resp.truncated
        );

        let structured = json!({
            "status": resp.status,
            "url": resp.url,
            "headers": resp.headers,
            "contentType": resp.content_type,
            "contentLength": resp.content_length,
            "truncated": resp.truncated,
            "bodyText": body_text,
            "bodyBase64": body_base64,
            "json": json_value,
            "parseError": parse_error,
        });

        Ok(CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(structured))
    }

    #[cfg(feature = "http-tools")]
    #[tool(
        name = "http_request_batch",
        description = "Batch HTTP requests. Each request supports method, headers, cookies, query params, and body. Requires allowlisted domains."
    )]
    async fn http_request_batch(
        &self,
        Parameters(args): Parameters<HttpRequestBatchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut results: Vec<Option<Value>> = vec![None; args.requests.len()];
        let mut batch_follow = Vec::new();
        let mut batch_no_follow = Vec::new();

        for (index, item) in args.requests.into_iter().enumerate() {
            let _parsed = match self.ensure_http_allowed(&item.request.url) {
                Ok(p) => p,
                Err(e) => {
                    results[index] = Some(json!({
                        "id": item.id,
                        "ok": false,
                        "error": e.to_string(),
                    }));
                    continue;
                }
            };

            let mut body_bytes = None;
            if let Some(path) = &item.request.body_path {
                match self.resolve(path).await {
                    Ok(resolved) => match fs::read(&resolved).await {
                        Ok(bytes) => body_bytes = Some(bytes),
                        Err(e) => {
                            results[index] = Some(json!({
                                "id": item.id,
                                "ok": false,
                                "error": format!("Failed to read body file: {e}"),
                            }));
                            continue;
                        }
                    },
                    Err(e) => {
                        results[index] = Some(json!({
                            "id": item.id,
                            "ok": false,
                            "error": e.to_string(),
                        }));
                        continue;
                    }
                }
            }

            let params = HttpRequestParams {
                method: item.request.method.clone(),
                url: item.request.url.clone(),
                headers: item.request.headers.clone(),
                cookies: item.request.cookies.clone(),
                query: item.request.query.clone(),
                body: item.request.body.clone(),
                body_base64: *item.request.body_base64,
                body_bytes,
                timeout_ms: item.request.timeout_ms,
                max_bytes: item.request.max_bytes,
            };

            let request_item = crate::tools::http_tools::HttpRequestItem {
                id: item.id,
                params,
            };

            if *item.request.follow_redirects {
                batch_follow.push((index, request_item));
            } else {
                batch_no_follow.push((index, request_item));
            }
        }

        for (follow, items) in [(true, batch_follow), (false, batch_no_follow)] {
            if items.is_empty() {
                continue;
            }

            let client = self.http_client(follow);
            let (indices, batch_items): (
                Vec<usize>,
                Vec<crate::tools::http_tools::HttpRequestItem>,
            ) = items.into_iter().unzip();
            let batch_results = http_request_batch(client, batch_items).await;

            for (index, result) in indices.into_iter().zip(batch_results) {
                let crate::tools::http_tools::HttpBatchResult {
                    id,
                    ok,
                    response,
                    error,
                } = result;
                let json_result = if let Some(resp) = response {
                    let mut payload = json!({
                        "id": id,
                        "ok": ok,
                        "status": resp.status,
                        "url": resp.url,
                        "headers": resp.headers,
                        "contentType": resp.content_type,
                        "contentLength": resp.content_length,
                        "truncated": resp.truncated,
                        "bodyBase64": to_base64(&resp.body),
                    });
                    if !ok {
                        let err_msg =
                            error.unwrap_or_else(|| format!("HTTP status {}", resp.status));
                        if let Some(map) = payload.as_object_mut() {
                            map.insert("error".to_string(), Value::String(err_msg));
                        }
                    }
                    payload
                } else {
                    json!({ "id": id, "ok": false, "error": error.unwrap_or_else(|| "Missing response".to_string()) })
                };
                results[index] = Some(json_result);
            }
        }

        let results: Vec<Value> = results
            .into_iter()
            .map(|r| r.unwrap_or_else(|| json!({ "ok": false, "error": "Missing result" })))
            .collect();

        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Batch results: {}",
            results.len()
        ))])
        .with_structured(json!({ "results": results })))
    }

    #[cfg(feature = "http-tools")]
    #[tool(
        name = "http_download",
        description = "Download an HTTP/HTTPS resource to a local file path. Requires allowlisted domains."
    )]
    async fn http_download(
        &self,
        Parameters(args): Parameters<HttpDownloadArgs>,
    ) -> Result<CallToolResult, McpError> {
        let _parsed = self.ensure_http_allowed(&args.url)?;

        let params = HttpRequestParams {
            method: "GET".to_string(),
            url: args.url.clone(),
            headers: args.headers.clone(),
            cookies: args.cookies.clone(),
            query: args.query.clone(),
            body: None,
            body_base64: false,
            body_bytes: None,
            timeout_ms: args.timeout_ms,
            max_bytes: args.max_bytes,
        };

        let client = self.http_client(*args.follow_redirects);
        let resp = http_request(client, params)
            .await
            .map_err(|e| McpError::internal_error(format!("HTTP request failed: {e}"), None))?;

        if resp.status >= 400 {
            return Err(McpError::internal_error(
                format!("HTTP status {} for {}", resp.status, resp.url),
                None,
            ));
        }

        // A truncated body means the resource exceeded maxBytes. Writing it would
        // leave a silently-incomplete file on disk under a success response, so
        // refuse instead (BH-17). Nothing has been written yet, so no cleanup.
        if resp.truncated {
            return Err(McpError::internal_error(
                format!(
                    "Download of {} exceeded maxBytes ({}); refusing to write a truncated file. \
                     Raise maxBytes to fetch the full resource.",
                    resp.url, args.max_bytes
                ),
                None,
            ));
        }

        let path = self.resolve(&args.path).await?;
        fs::write(&path, &resp.body)
            .await
            .map_err(internal_err("Failed to write download"))?;

        let text = format!("Downloaded {} bytes to {}", resp.body.len(), path.display());
        Ok(
            CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
                "path": path.to_string_lossy(),
                "bytes": resp.body.len(),
                "status": resp.status,
                "url": resp.url,
                "truncated": resp.truncated,
            })),
        )
    }

    #[cfg(feature = "http-tools")]
    #[tool(
        name = "http_download_batch",
        description = "Batch HTTP downloads to local file paths. Requires allowlisted domains."
    )]
    async fn http_download_batch(
        &self,
        Parameters(args): Parameters<HttpDownloadBatchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut results = Vec::new();
        for item in args.downloads {
            let _parsed = match self.ensure_http_allowed(&item.url) {
                Ok(p) => p,
                Err(e) => {
                    results.push(json!({
                        "url": item.url,
                        "path": item.path,
                        "ok": false,
                        "error": e.to_string(),
                    }));
                    continue;
                }
            };

            let params = HttpRequestParams {
                method: "GET".to_string(),
                url: item.url.clone(),
                headers: item.headers.clone(),
                cookies: item.cookies.clone(),
                query: item.query.clone(),
                body: None,
                body_base64: false,
                body_bytes: None,
                timeout_ms: item.timeout_ms,
                max_bytes: item.max_bytes,
            };

            let client = self.http_client(*item.follow_redirects);
            match http_request(client, params).await {
                Ok(resp) => {
                    if resp.status >= 400 {
                        results.push(json!({
                            "url": item.url,
                            "path": item.path,
                            "ok": false,
                            "status": resp.status,
                            "error": format!("HTTP status {}", resp.status),
                        }));
                        continue;
                    }
                    // Refuse to write a truncated (over-maxBytes) download as success.
                    if resp.truncated {
                        results.push(json!({
                            "url": item.url,
                            "path": item.path,
                            "ok": false,
                            "status": resp.status,
                            "truncated": true,
                            "error": format!(
                                "Download exceeded maxBytes ({}); refusing to write a truncated file",
                                item.max_bytes
                            ),
                        }));
                        continue;
                    }
                    match self.resolve(&item.path).await {
                        Ok(path) => {
                            if let Err(e) = fs::write(&path, &resp.body).await {
                                results.push(json!({
                                    "url": item.url,
                                    "path": item.path,
                                    "ok": false,
                                    "error": format!("Failed to write file: {e}"),
                                }));
                                continue;
                            }
                            results.push(json!({
                                "url": item.url,
                                "path": path.to_string_lossy(),
                                "ok": true,
                                "status": resp.status,
                                "bytes": resp.body.len(),
                                "truncated": resp.truncated,
                            }));
                        }
                        Err(e) => {
                            results.push(json!({
                                "url": item.url,
                                "path": item.path,
                                "ok": false,
                                "error": e.to_string(),
                            }));
                        }
                    }
                }
                Err(e) => {
                    results.push(json!({
                        "url": item.url,
                        "path": item.path,
                        "ok": false,
                        "error": e.to_string(),
                    }));
                }
            }
        }

        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Batch downloads: {}",
            results.len()
        ))])
        .with_structured(json!({ "results": results })))
    }

    #[cfg(feature = "s3-tools")]
    #[tool(
        name = "s3_list_buckets",
        description = "List S3 buckets for the current credentials. Requires allowlisted buckets (use '*' to allow all)."
    )]
    async fn s3_list_buckets(
        &self,
        Parameters(args): Parameters<S3ListBucketsArgs>,
    ) -> Result<CallToolResult, McpError> {
        if self.s3_allowlist_buckets.is_empty() {
            return Err(McpError::invalid_params(
                "S3 allowlist is empty; use FS_MCP_S3_ALLOW_LIST or --s3-allowlist-bucket",
                None,
            ));
        }
        if !self.s3_allowlist_buckets.iter().any(|b| b == "*") {
            return Err(McpError::invalid_params(
                "S3 allowlist must include '*' to list all buckets",
                None,
            ));
        }

        let client = self.s3_client_for(&args.credentials).await?;
        let buckets = list_buckets(&client)
            .await
            .map_err(|e| McpError::internal_error(format!("S3 list buckets failed: {e}"), None))?;

        let text = format!("S3 buckets: {}", buckets.len());
        Ok(
            CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
                "buckets": buckets.iter().map(|b| json!({
                    "name": b.name,
                    "createdAt": b.created_at,
                })).collect::<Vec<_>>(),
            })),
        )
    }

    #[cfg(feature = "s3-tools")]
    #[tool(
        name = "s3_list",
        description = "List S3 objects and common prefixes. Requires allowlisted buckets."
    )]
    async fn s3_list(
        &self,
        Parameters(args): Parameters<S3ListArgs>,
    ) -> Result<CallToolResult, McpError> {
        if !is_bucket_allowed(&args.bucket, &self.s3_allowlist_buckets) {
            return Err(McpError::invalid_params(
                format!("S3 bucket '{}' is not in allowlist", args.bucket),
                None,
            ));
        }

        let client = self.s3_client_for(&args.credentials).await?;
        let params = S3ListParams {
            bucket: args.bucket.clone(),
            prefix: args.prefix.clone(),
            delimiter: args.delimiter.clone(),
            max_keys: args.max_keys.get(),
            continuation_token: args.continuation_token.clone(),
        };
        let result = list_objects(&client, params)
            .await
            .map_err(|e| McpError::internal_error(format!("S3 list failed: {e}"), None))?;

        let text = format!(
            "S3 list: {} objects, {} prefixes",
            result.objects.len(),
            result.prefixes.len()
        );
        Ok(
            CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
                "objects": result.objects.iter().map(|o| json!({
                    "key": o.key,
                    "size": o.size,
                    "eTag": o.e_tag,
                    "lastModified": o.last_modified,
                    "storageClass": o.storage_class,
                })).collect::<Vec<_>>(),
                "prefixes": result.prefixes,
                "isTruncated": result.is_truncated,
                "nextToken": result.next_token,
            })),
        )
    }

    #[cfg(feature = "s3-tools")]
    #[tool(
        name = "s3_stat",
        description = "Fetch S3 object metadata. Requires allowlisted buckets."
    )]
    async fn s3_stat(
        &self,
        Parameters(args): Parameters<S3StatArgs>,
    ) -> Result<CallToolResult, McpError> {
        if !is_bucket_allowed(&args.bucket, &self.s3_allowlist_buckets) {
            return Err(McpError::invalid_params(
                format!("S3 bucket '{}' is not in allowlist", args.bucket),
                None,
            ));
        }

        let client = self.s3_client_for(&args.credentials).await?;
        let result = stat_object(&client, &args.bucket, &args.key)
            .await
            .map_err(|e| McpError::internal_error(format!("S3 stat failed: {e}"), None))?;

        let text = format!("S3 stat: {}/{}", result.bucket, result.key);
        Ok(
            CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
                "bucket": result.bucket,
                "key": result.key,
                "size": result.size,
                "eTag": result.e_tag,
                "contentType": result.content_type,
                "lastModified": result.last_modified,
                "metadata": result.metadata,
            })),
        )
    }

    #[cfg(feature = "s3-tools")]
    #[tool(
        name = "s3_get",
        description = "Get S3 object bytes or write to file. Requires allowlisted buckets."
    )]
    async fn s3_get(
        &self,
        Parameters(args): Parameters<S3GetArgs>,
    ) -> Result<CallToolResult, McpError> {
        if !is_bucket_allowed(&args.bucket, &self.s3_allowlist_buckets) {
            return Err(McpError::invalid_params(
                format!("S3 bucket '{}' is not in allowlist", args.bucket),
                None,
            ));
        }

        let output_path = if let Some(path) = &args.output_path {
            Some(self.resolve(path).await?.to_string_lossy().to_string())
        } else {
            None
        };

        let client = self.s3_client_for(&args.credentials).await?;
        let params = S3GetParams {
            bucket: args.bucket.clone(),
            key: args.key.clone(),
            range: args.range.clone(),
            output_path,
            max_bytes: Some(args.max_bytes),
            accept_text: *args.accept_text,
        };
        let result = get_object(&client, params)
            .await
            .map_err(|e| McpError::internal_error(format!("S3 get failed: {e}"), None))?;

        let text = if let Some(path) = &result.output_path {
            format!("Downloaded to {}", path)
        } else {
            format!("S3 get: {}/{}", result.bucket, result.key)
        };
        Ok(
            CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
                "bucket": result.bucket,
                "key": result.key,
                "size": result.size,
                "contentType": result.content_type,
                "bodyBase64": result.body.as_ref().map(|b| to_base64(b)),
                "text": result.text,
                "outputPath": result.output_path,
                "truncated": result.truncated,
            })),
        )
    }

    #[cfg(feature = "s3-tools")]
    #[tool(
        name = "s3_put",
        description = "Upload data to S3. Supports path or body. Requires allowlisted buckets."
    )]
    async fn s3_put(
        &self,
        Parameters(args): Parameters<S3PutArgs>,
    ) -> Result<CallToolResult, McpError> {
        if !is_bucket_allowed(&args.bucket, &self.s3_allowlist_buckets) {
            return Err(McpError::invalid_params(
                format!("S3 bucket '{}' is not in allowlist", args.bucket),
                None,
            ));
        }

        let path = if let Some(p) = &args.path {
            Some(self.resolve(p).await?.to_string_lossy().to_string())
        } else {
            None
        };

        let client = self.s3_client_for(&args.credentials).await?;
        let params = S3PutParams {
            bucket: args.bucket.clone(),
            key: args.key.clone(),
            path,
            body: args.body.clone(),
            body_base64: *args.body_base64,
            content_type: args.content_type.clone(),
            cache_control: args.cache_control.clone(),
            metadata: args.metadata.clone(),
        };
        put_object(&client, params)
            .await
            .map_err(|e| McpError::internal_error(format!("S3 put failed: {e}"), None))?;

        Ok(CallToolResult::success(vec![ContentBlock::text(
            "S3 put ok",
        )]))
    }

    #[cfg(feature = "s3-tools")]
    #[tool(
        name = "s3_copy",
        description = "Copy S3 object. Requires allowlisted buckets."
    )]
    async fn s3_copy(
        &self,
        Parameters(args): Parameters<S3CopyArgs>,
    ) -> Result<CallToolResult, McpError> {
        if !is_bucket_allowed(&args.source_bucket, &self.s3_allowlist_buckets)
            || !is_bucket_allowed(&args.dest_bucket, &self.s3_allowlist_buckets)
        {
            return Err(McpError::invalid_params(
                "S3 bucket is not in allowlist",
                None,
            ));
        }

        let client = self.s3_client_for(&args.credentials).await?;
        let params = S3CopyParams {
            source_bucket: args.source_bucket.clone(),
            source_key: args.source_key.clone(),
            dest_bucket: args.dest_bucket.clone(),
            dest_key: args.dest_key.clone(),
        };
        copy_object(&client, params)
            .await
            .map_err(|e| McpError::internal_error(format!("S3 copy failed: {e}"), None))?;

        Ok(CallToolResult::success(vec![ContentBlock::text(
            "S3 copy ok",
        )]))
    }

    #[cfg(feature = "s3-tools")]
    #[tool(
        name = "s3_delete",
        description = "Delete S3 object. Requires allowlisted buckets."
    )]
    async fn s3_delete(
        &self,
        Parameters(args): Parameters<S3DeleteArgs>,
    ) -> Result<CallToolResult, McpError> {
        if !is_bucket_allowed(&args.bucket, &self.s3_allowlist_buckets) {
            return Err(McpError::invalid_params(
                format!("S3 bucket '{}' is not in allowlist", args.bucket),
                None,
            ));
        }

        let client = self.s3_client_for(&args.credentials).await?;
        delete_object(
            &client,
            S3DeleteParams {
                bucket: args.bucket,
                key: args.key,
            },
        )
        .await
        .map_err(|e| McpError::internal_error(format!("S3 delete failed: {e}"), None))?;

        Ok(CallToolResult::success(vec![ContentBlock::text(
            "S3 delete ok",
        )]))
    }

    #[cfg(feature = "s3-tools")]
    #[tool(
        name = "s3_delete_batch",
        description = "Delete multiple S3 objects. Requires allowlisted buckets."
    )]
    async fn s3_delete_batch(
        &self,
        Parameters(args): Parameters<S3DeleteBatchArgs>,
    ) -> Result<CallToolResult, McpError> {
        if !is_bucket_allowed(&args.bucket, &self.s3_allowlist_buckets) {
            return Err(McpError::invalid_params(
                format!("S3 bucket '{}' is not in allowlist", args.bucket),
                None,
            ));
        }
        let client = self.s3_client_for(&args.credentials).await?;
        delete_objects(&client, &args.bucket, args.keys)
            .await
            .map_err(|e| McpError::internal_error(format!("S3 delete batch failed: {e}"), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(
            "S3 delete batch ok",
        )]))
    }

    #[cfg(feature = "s3-tools")]
    #[tool(
        name = "s3_presign",
        description = "Generate a presigned S3 URL for GET or PUT. Requires allowlisted buckets."
    )]
    async fn s3_presign(
        &self,
        Parameters(args): Parameters<S3PresignArgs>,
    ) -> Result<CallToolResult, McpError> {
        if !is_bucket_allowed(&args.bucket, &self.s3_allowlist_buckets) {
            return Err(McpError::invalid_params(
                format!("S3 bucket '{}' is not in allowlist", args.bucket),
                None,
            ));
        }
        let client = self.s3_client_for(&args.credentials).await?;
        let url = presign(
            &client,
            S3PresignParams {
                bucket: args.bucket,
                key: args.key,
                method: args.method,
                expires_in_seconds: args.expires_in_seconds,
            },
        )
        .await
        .map_err(|e| McpError::internal_error(format!("S3 presign failed: {e}"), None))?;

        Ok(
            CallToolResult::success(vec![ContentBlock::text(url.clone())])
                .with_structured(json!({ "url": url })),
        )
    }

    #[cfg(feature = "s3-tools")]
    #[tool(
        name = "s3_get_batch",
        description = "Batch S3 get. Requires allowlisted buckets."
    )]
    async fn s3_get_batch(
        &self,
        Parameters(args): Parameters<S3GetBatchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut results = Vec::new();

        for req in args.requests {
            if !is_bucket_allowed(&req.bucket, &self.s3_allowlist_buckets) {
                results.push(json!({
                    "bucket": req.bucket,
                    "key": req.key,
                    "ok": false,
                    "error": "Bucket not in allowlist",
                }));
                continue;
            }

            let client = match self.s3_client_for(&req.credentials).await {
                Ok(client) => client,
                Err(e) => {
                    results.push(json!({
                        "bucket": req.bucket,
                        "key": req.key,
                        "ok": false,
                        "error": e.to_string(),
                    }));
                    continue;
                }
            };

            let output_path = if let Some(path) = &req.output_path {
                match self.resolve(path).await {
                    Ok(resolved) => Some(resolved.to_string_lossy().to_string()),
                    Err(e) => {
                        results.push(json!({
                            "bucket": req.bucket,
                            "key": req.key,
                            "ok": false,
                            "error": e.to_string(),
                        }));
                        continue;
                    }
                }
            } else {
                None
            };

            let params = S3GetParams {
                bucket: req.bucket.clone(),
                key: req.key.clone(),
                range: req.range.clone(),
                output_path,
                max_bytes: Some(req.max_bytes),
                accept_text: *req.accept_text,
            };

            match get_object(&client, params).await {
                Ok(result) => results.push(json!({
                    "bucket": result.bucket,
                    "key": result.key,
                    "ok": true,
                    "size": result.size,
                    "contentType": result.content_type,
                    "bodyBase64": result.body.as_ref().map(|b| to_base64(b)),
                    "text": result.text,
                    "outputPath": result.output_path,
                    "truncated": result.truncated,
                })),
                Err(e) => results.push(json!({
                    "bucket": req.bucket,
                    "key": req.key,
                    "ok": false,
                    "error": e.to_string(),
                })),
            }
        }

        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Batch S3 get: {}",
            results.len()
        ))])
        .with_structured(json!({ "results": results })))
    }

    #[cfg(feature = "s3-tools")]
    #[tool(
        name = "s3_put_batch",
        description = "Batch S3 put. Requires allowlisted buckets."
    )]
    async fn s3_put_batch(
        &self,
        Parameters(args): Parameters<S3PutBatchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut results = Vec::new();

        for req in args.requests {
            if !is_bucket_allowed(&req.bucket, &self.s3_allowlist_buckets) {
                results.push(json!({
                    "bucket": req.bucket,
                    "key": req.key,
                    "ok": false,
                    "error": "Bucket not in allowlist",
                }));
                continue;
            }

            let client = match self.s3_client_for(&req.credentials).await {
                Ok(client) => client,
                Err(e) => {
                    results.push(json!({
                        "bucket": req.bucket,
                        "key": req.key,
                        "ok": false,
                        "error": e.to_string(),
                    }));
                    continue;
                }
            };

            let path = if let Some(p) = &req.path {
                match self.resolve(p).await {
                    Ok(resolved) => Some(resolved.to_string_lossy().to_string()),
                    Err(e) => {
                        results.push(json!({
                            "bucket": req.bucket,
                            "key": req.key,
                            "ok": false,
                            "error": e.to_string(),
                        }));
                        continue;
                    }
                }
            } else {
                None
            };

            let params = S3PutParams {
                bucket: req.bucket.clone(),
                key: req.key.clone(),
                path,
                body: req.body.clone(),
                body_base64: *req.body_base64,
                content_type: req.content_type.clone(),
                cache_control: req.cache_control.clone(),
                metadata: req.metadata.clone(),
            };

            match put_object(&client, params).await {
                Ok(()) => results.push(json!({
                    "bucket": req.bucket,
                    "key": req.key,
                    "ok": true,
                })),
                Err(e) => results.push(json!({
                    "bucket": req.bucket,
                    "key": req.key,
                    "ok": false,
                    "error": e.to_string(),
                })),
            }
        }

        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Batch S3 put: {}",
            results.len()
        ))])
        .with_structured(json!({ "results": results })))
    }

    #[cfg(feature = "s3-tools")]
    #[tool(
        name = "s3_copy_batch",
        description = "Batch S3 copy. Requires allowlisted buckets."
    )]
    async fn s3_copy_batch(
        &self,
        Parameters(args): Parameters<S3CopyBatchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut results = Vec::new();

        for req in args.requests {
            if !is_bucket_allowed(&req.source_bucket, &self.s3_allowlist_buckets)
                || !is_bucket_allowed(&req.dest_bucket, &self.s3_allowlist_buckets)
            {
                results.push(json!({
                    "sourceBucket": req.source_bucket,
                    "destBucket": req.dest_bucket,
                    "key": req.source_key,
                    "ok": false,
                    "error": "Bucket not in allowlist",
                }));
                continue;
            }

            let client = match self.s3_client_for(&req.credentials).await {
                Ok(client) => client,
                Err(e) => {
                    results.push(json!({
                        "sourceBucket": req.source_bucket,
                        "destBucket": req.dest_bucket,
                        "key": req.source_key,
                        "ok": false,
                        "error": e.to_string(),
                    }));
                    continue;
                }
            };

            let params = S3CopyParams {
                source_bucket: req.source_bucket.clone(),
                source_key: req.source_key.clone(),
                dest_bucket: req.dest_bucket.clone(),
                dest_key: req.dest_key.clone(),
            };

            match copy_object(&client, params).await {
                Ok(()) => results.push(json!({
                    "sourceBucket": req.source_bucket,
                    "destBucket": req.dest_bucket,
                    "key": req.source_key,
                    "ok": true,
                })),
                Err(e) => results.push(json!({
                    "sourceBucket": req.source_bucket,
                    "destBucket": req.dest_bucket,
                    "key": req.source_key,
                    "ok": false,
                    "error": e.to_string(),
                })),
            }
        }

        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Batch S3 copy: {}",
            results.len()
        ))])
        .with_structured(json!({ "results": results })))
    }

    #[tool(
        name = "edit_lines",
        description = "Edit file by LINE NUMBERS (precise, surgical edits). Use when you know EXACT line numbers to modify. Operations: replace (change line(s)), insert_before/insert_after (add new lines), delete (remove line(s)). Supports single lines or ranges (startLine-endLine). Returns unified diff. Use this for: fixing specific lines, adding imports at known positions, removing exact lines. Different from edit_file which uses search/replace text matching. Line numbers are 1-indexed."
    )]
    async fn edit_lines(
        &self,
        Parameters(args): Parameters<EditLinesArgs>,
    ) -> Result<CallToolResult, McpError> {
        // Validate line numbers (1-indexed)
        for (idx, edit) in args.edits.iter().enumerate() {
            if edit.line == 0 {
                return Err(McpError::invalid_params(
                    format!("Edit {}: line number must be >= 1 (1-indexed)", idx),
                    None,
                ));
            }
            if let Some(end) = edit.end_line.get() {
                if end == 0 {
                    return Err(McpError::invalid_params(
                        format!("Edit {}: end_line must be >= 1 (1-indexed)", idx),
                        None,
                    ));
                }
                if end < edit.line {
                    return Err(McpError::invalid_params(
                        format!(
                            "Edit {}: invalid range - end_line {} is before line {}",
                            idx, end, edit.line
                        ),
                        None,
                    ));
                }
            }
        }

        let path = self.resolve(&args.path).await?;
        let tf = read_text_meta(&path)
            .await
            .map_err(internal_err("Failed to read file"))?;
        tf.ensure_roundtrippable()
            .map_err(internal_err("Cannot edit file"))?;
        let original = tf.text.clone();

        // Convert JSON operations to internal LineEdit format
        let edits: Vec<LineEdit> = args
            .edits
            .into_iter()
            .map(|e| {
                let operation = match e.operation {
                    LineEditOperation::Replace => LineOperation::Replace,
                    LineEditOperation::InsertBefore => LineOperation::InsertBefore,
                    LineEditOperation::InsertAfter => LineOperation::InsertAfter,
                    LineEditOperation::Delete => LineOperation::Delete,
                };
                LineEdit {
                    start_line: e.line,
                    end_line: e.end_line.get(),
                    operation,
                    text: e.text,
                }
            })
            .collect();

        let (modified, diff) = apply_line_edits(&original, &edits)
            .map_err(|e| McpError::internal_error(format!("Line edit failed: {}", e), None))?;

        if !*args.dry_run {
            let bytes = tf
                .encode(&modified)
                .map_err(internal_err("Failed to encode edited file"))?;
            fs::write(&path, &bytes)
                .await
                .map_err(internal_err("Failed to write file"))?;
        }

        let message = if *args.dry_run {
            format!("Dry run - changes NOT applied to {}", args.path)
        } else {
            format!("Successfully edited {} lines in {}", edits.len(), args.path)
        };

        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "{}\n\nDiff:\n{}",
            message, diff
        ))])
        .with_structured(json!({
            "message": message,
            "diff": diff,
            "editsApplied": edits.len(),
            "dryRun": args.dry_run,
        })))
    }

    #[tool(
        name = "bulk_edits",
        description = "Apply the SAME set of edits to MANY files at once (mass search/replace). Select files by glob (e.g. `**/*.rs`), then apply ordered edits to each.\n\n\
Return shape (compact by design — designed for codebase-wide migrations of thousands of files):\n  - `scannedFiles`: total files visited.\n  - `modified`: count of files that changed.\n  - `errors`: count of files that errored.\n  - `modifiedFiles`: array of paths that changed (fast for follow-up tooling).\n  - `results`: per-file entries ONLY for modified files (each with truncated diff).\n  - `errorResults`: per-file entries ONLY for errored files.\n  - `diffsTruncated`: true if any diff or trailing diff was clipped (logs still contain everything).\n  Unchanged files DO NOT appear in `results` — they are reflected in `scannedFiles - modified - errors`.\n\n\
Each edit supports:\n  - `oldText`, `newText` (strings).\n  - `isRegex` (bool): use regex (supports `$1`/`$2` capture groups).\n  - `replaceAll` (bool): replace all occurrences instead of just the first.\n\n\
Semantics: all edits in a single call are evaluated against a FROZEN SNAPSHOT of each file. Overlapping match spans from different edits are resolved by `longest span wins; on a tie the earlier edit wins`. This prevents cascading duplicates when one `oldText` is a substring of another (the classic indent-overlap trap).\n\n\
Bulk options:\n  - `dryRun` (bool): preview only.\n  - `failOnNoMatch` (bool): if true, files where any edit has zero matches error out; default false. Aggregates ALL no-match edits into a single error message.\n  - `engine` (string): `regex` (default, linear-time, no look-around) | `fancy` (supports `(?=...)`, `(?!...)`, `(?<=...)`, `(?<!...)`, backreferences; backtracking, may be slower).\n\n\
Migration-safety output:\n  - Top-level `editsSummary[]` reports per-edit totals across ALL scanned files (`totalMatches`, `totalApplied`, `filesWithMatches`). Spot silent no-op edits in batches of thousands of files.\n  - Each `results[]` entry also includes `matchesPerEdit[]` and `appliedPerEdit[]` for that file.\n\n\
EXAMPLES:\n  1. Literal replace all occurrences:\n     {\"oldText\": \"use crate::foo\", \"newText\": \"use crate::bar::foo\", \"replaceAll\": true}\n  2. Regex with capture groups (rename imports):\n     {\"oldText\": \"use crate::(cache_man|event_bus|workers)\", \"newText\": \"use crate::core::$1\", \"isRegex\": true, \"replaceAll\": true}\n  3. Rename function across codebase:\n     {\"oldText\": \"old_function_name\", \"newText\": \"new_function_name\", \"replaceAll\": true}"
    )]
    async fn bulk_edits(
        &self,
        Parameters(args): Parameters<BulkEditsArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.ensure_allowed().await?;

        // Resolve ContentRefs then convert to FileEdit format
        let mut edits = Vec::with_capacity(args.edits.len());
        for e in args.edits {
            let old_ref = e.old_text.into_ref();
            let new_ref = e.new_text.into_ref();
            let old_bytes = self.resolve_content(&old_ref, ContentMode::Text).await?;
            let new_bytes = self.resolve_content(&new_ref, ContentMode::Text).await?;
            let old_text = String::from_utf8(old_bytes)
                .map_err(|err| Self::content_err(ContentError::InvalidUtf8(err.to_string())))?;
            let new_text = String::from_utf8(new_bytes)
                .map_err(|err| Self::content_err(ContentError::InvalidUtf8(err.to_string())))?;
            edits.push(FileEdit {
                old_text,
                new_text,
                is_regex: *e.is_regex,
                replace_all: *e.replace_all,
            });
        }

        let engine = match args.engine.as_deref() {
            None | Some("regex") => EditEngine::Regex,
            Some("fancy") | Some("fancy-regex") => EditEngine::Fancy,
            Some(other) => {
                return Err(McpError::invalid_params(
                    format!("unknown engine '{other}'; expected 'regex' or 'fancy'"),
                    None,
                ));
            }
        };

        let results = bulk_edit_files(
            &args.path,
            &args.file_pattern,
            &args.exclude_patterns,
            &edits,
            *args.dry_run,
            *args.fail_on_no_match,
            engine,
            &self.allowed,
            self.allow_symlink_escape,
        )
        .await
        .map_err(|e| McpError::internal_error(format!("Bulk edit failed: {}", e), None))?;

        // Count results.
        let scanned_files = results.len();
        let modified_count = results.iter().filter(|r| r.modified).count();
        let error_count = results.iter().filter(|r| r.error.is_some()).count();

        // Hard cap per-file diff size so the structured payload never overruns
        // MCP transport limits when many files are edited (bug.md BUG #4).
        const PER_DIFF_MAX_CHARS: usize = 4_000;
        const TOTAL_STRUCTURED_MAX_CHARS: usize = 200_000;

        let truncate_diff = |diff: &str| -> (String, bool) {
            if diff.chars().count() <= PER_DIFF_MAX_CHARS {
                (diff.to_string(), false)
            } else {
                let head: String = diff.chars().take(PER_DIFF_MAX_CHARS).collect();
                (format!("{head}\n... [diff truncated]"), true)
            }
        };

        let mut modified_files: Vec<&BulkEditResult> =
            results.iter().filter(|r| r.modified).collect();
        let error_results: Vec<&BulkEditResult> =
            results.iter().filter(|r| r.error.is_some()).collect();

        // Text view: brief, only changed files + errors.
        let mut lines = Vec::new();
        if *args.dry_run {
            lines.push("DRY RUN - Changes NOT applied".to_string());
        }
        lines.push(format!(
            "Scanned {} files: {} modified, {} errors",
            scanned_files, modified_count, error_count
        ));
        lines.push(String::new());
        for result in &error_results {
            lines.push(format!(
                "❌ {}: {}",
                result.path.display(),
                result.error.as_deref().unwrap_or("")
            ));
        }
        for result in &modified_files {
            lines.push(format!("✓ {} - MODIFIED", result.path.display()));
            if let Some(diff) = &result.diff {
                let (clipped, _) = truncate_diff(diff);
                lines.push(clipped);
                lines.push(String::new());
            }
        }

        let text = lines.join("\n");

        // Structured payload: skip unchanged files entirely; truncate diffs;
        // stop emitting diffs once total payload approaches cap.
        // Aggregate per-edit match/apply counts across ALL files (so users can
        // quickly see if any edit silently produced zero changes — critical
        // for migration safety).
        let edit_count = edits.len();
        let mut total_matches_per_edit = vec![0usize; edit_count];
        let mut total_applied_per_edit = vec![0usize; edit_count];
        let mut files_with_matches_per_edit = vec![0usize; edit_count];
        for r in &results {
            for (i, &n) in r.matches_per_edit.iter().enumerate() {
                if i < edit_count {
                    total_matches_per_edit[i] += n;
                    if n > 0 {
                        files_with_matches_per_edit[i] += 1;
                    }
                }
            }
            for (i, &n) in r.applied_per_edit.iter().enumerate() {
                if i < edit_count {
                    total_applied_per_edit[i] += n;
                }
            }
        }

        let mut total_chars = 0usize;
        let mut any_diff_dropped = false;
        modified_files.sort_by(|a, b| a.path.cmp(&b.path));
        let results_json: Vec<_> = modified_files
            .iter()
            .map(|r| {
                let diff_field = match r.diff.as_deref() {
                    Some(d) if total_chars < TOTAL_STRUCTURED_MAX_CHARS => {
                        let (clipped, truncated) = truncate_diff(d);
                        total_chars += clipped.chars().count();
                        if truncated {
                            any_diff_dropped = true;
                        }
                        Some(clipped)
                    }
                    Some(_) => {
                        any_diff_dropped = true;
                        None
                    }
                    None => None,
                };
                json!({
                    "path": r.path.to_string_lossy(),
                    "modified": true,
                    "diff": diff_field,
                    "appliedPerEdit": r.applied_per_edit,
                    "matchesPerEdit": r.matches_per_edit,
                })
            })
            .collect();
        let errors_json: Vec<_> = error_results
            .iter()
            .map(|r| {
                json!({
                    "path": r.path.to_string_lossy(),
                    "error": r.error,
                })
            })
            .collect();
        let modified_paths: Vec<String> = modified_files
            .iter()
            .map(|r| r.path.to_string_lossy().into_owned())
            .collect();

        // Per-edit summary across all files — makes it trivial to spot silent
        // no-op edits in a migration batch.
        let edits_summary: Vec<_> = (0..edit_count)
            .map(|i| {
                json!({
                    "index": i,
                    "totalMatches": total_matches_per_edit[i],
                    "totalApplied": total_applied_per_edit[i],
                    "filesWithMatches": files_with_matches_per_edit[i],
                })
            })
            .collect();

        let structured = json!({
            "scannedFiles": scanned_files,
            "modified": modified_count,
            "errors": error_count,
            "dryRun": args.dry_run,
            "engine": match engine { EditEngine::Regex => "regex", EditEngine::Fancy => "fancy" },
            "modifiedFiles": modified_paths,
            "results": results_json,
            "errorResults": errors_json,
            "diffsTruncated": any_diff_dropped,
            "editsSummary": edits_summary,
        });

        Ok(CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(structured))
    }

    // ========================================================================
    // Extract tools - cut content and return it
    // ========================================================================

    #[tool(
        name = "extract_lines",
        description = "Extract (cut) lines from a text file by line numbers. Removes lines from file unless dryRun=true.

PARAMETERS:
- path: File path
- line: Start line (1-indexed, so first line is 1)
- endLine: End line inclusive (optional, defaults to same as 'line' for single line)
- dryRun: If true, only preview - don't modify file
- returnExtracted: If true, include extracted text in response (default: false to save tokens)

EXAMPLES:
- Delete line 5: {path: 'file.txt', line: 5}
- Delete lines 10-20: {path: 'file.txt', line: 10, endLine: 20}
- Preview deletion: {path: 'file.txt', line: 5, dryRun: true}
- Get deleted content: {path: 'file.txt', line: 5, returnExtracted: true}

USE CASES: Remove imports, delete code blocks, cut sections to paste elsewhere."
    )]
    async fn extract_lines(
        &self,
        Parameters(args): Parameters<ExtractLinesArgs>,
    ) -> Result<CallToolResult, McpError> {
        // Validate line numbers (1-indexed)
        if args.line == 0 {
            return Err(McpError::invalid_params(
                "Line number must be >= 1 (1-indexed)",
                None,
            ));
        }
        if let Some(end) = args.end_line.get() {
            if end == 0 {
                return Err(McpError::invalid_params(
                    "End line number must be >= 1 (1-indexed)",
                    None,
                ));
            }
            if end < args.line {
                return Err(McpError::invalid_params(
                    format!(
                        "Invalid range: end line {} is before start line {}",
                        end, args.line
                    ),
                    None,
                ));
            }
        }

        let path = self.resolve(&args.path).await?;
        let tf = read_text_meta(&path)
            .await
            .map_err(internal_err("Failed to read file"))?;
        tf.ensure_roundtrippable()
            .map_err(internal_err("Cannot edit file"))?;
        let content = &tf.text;

        // Track if original content ends with newline
        let had_trailing_newline = content.ends_with('\n');

        let lines: Vec<&str> = content.lines().collect();
        let start_idx = args.line - 1;
        let end_idx = args.end_line.unwrap_or(args.line) - 1;

        // Validate line numbers
        if start_idx >= lines.len() {
            return Err(McpError::invalid_params(
                format!(
                    "Line {} is out of range (file has {} lines)",
                    args.line,
                    lines.len()
                ),
                None,
            ));
        }
        // Clamp end to file length - return what's available
        let end_idx = end_idx.min(lines.len() - 1);
        if start_idx > end_idx {
            return Err(McpError::invalid_params(
                format!(
                    "Invalid range: start line {} is after end line {}",
                    args.line,
                    end_idx + 1
                ),
                None,
            ));
        }

        // Extract the lines
        let extracted: Vec<&str> = lines[start_idx..=end_idx].to_vec();
        let extracted_text = extracted.join("\n");
        let line_count = extracted.len();

        if !*args.dry_run {
            // Build new content without extracted lines
            let mut remaining: Vec<&str> = Vec::with_capacity(lines.len() - line_count);
            remaining.extend_from_slice(&lines[..start_idx]);
            if end_idx + 1 < lines.len() {
                remaining.extend_from_slice(&lines[end_idx + 1..]);
            }
            let mut new_content = remaining.join("\n");

            // Preserve trailing newline if original had one
            if had_trailing_newline && !new_content.is_empty() {
                new_content.push('\n');
            }

            let bytes = tf
                .encode(&new_content)
                .map_err(internal_err("Failed to encode edited file"))?;
            fs::write(&path, &bytes)
                .await
                .map_err(internal_err("Failed to write file"))?;
        }

        let message = if *args.dry_run {
            format!(
                "Dry run - would extract {} line(s) {}-{} from {}",
                line_count,
                args.line,
                end_idx + 1,
                args.path
            )
        } else {
            format!(
                "Extracted {} line(s) {}-{} from {}",
                line_count,
                args.line,
                end_idx + 1,
                args.path
            )
        };

        // Build response - only include extracted content if requested
        let text_response = if *args.return_extracted {
            format!("{}\n\nExtracted content:\n{}", message, extracted_text)
        } else {
            message.clone()
        };

        let mut structured = json!({
            "message": message,
            "lineCount": line_count,
            "startLine": args.line,
            "endLine": end_idx + 1,
            "dryRun": *args.dry_run,
        });
        if *args.return_extracted {
            structured["extracted"] = json!(extracted_text);
        }

        Ok(
            CallToolResult::success(vec![ContentBlock::text(text_response)])
                .with_structured(structured),
        )
    }

    #[tool(
        name = "extract_symbols",
        description = "Extract (cut) characters from a file by position. Removes chars from file unless dryRun=true.

PARAMETERS:
- path: File path
- start: Start position (0-indexed Unicode chars, not bytes)
- end: End position exclusive (optional) - use EITHER end OR length
- length: Number of chars to extract (optional) - use EITHER end OR length
- dryRun: If true, only preview - don't modify file
- returnExtracted: If true, include extracted text in response (default: false to save tokens)

EXAMPLES:
- First 10 chars: {path: 'file.txt', start: 0, length: 10}
- Chars 100-199: {path: 'file.txt', start: 100, end: 200}
- Preview cut: {path: 'file.txt', start: 50, length: 25, dryRun: true}
- Get cut content: {path: 'file.txt', start: 0, length: 100, returnExtracted: true}

USE CASES: Remove headers, cut text blocks, extract specific character ranges.
Note: Uses Unicode chars (safe for multibyte), not raw bytes. If range exceeds file, returns available content."
    )]
    async fn extract_symbols(
        &self,
        Parameters(args): Parameters<ExtractSymbolsArgs>,
    ) -> Result<CallToolResult, McpError> {
        // Validate args
        if args.end.is_some() && args.length.is_some() {
            return Err(McpError::invalid_params(
                "Specify either 'end' or 'length', not both",
                None,
            ));
        }
        if args.end.is_none() && args.length.is_none() {
            return Err(McpError::invalid_params(
                "Must specify either 'end' or 'length'",
                None,
            ));
        }

        let path = self.resolve(&args.path).await?;
        let tf = read_text_meta(&path)
            .await
            .map_err(internal_err("Failed to read file"))?;
        tf.ensure_roundtrippable()
            .map_err(internal_err("Cannot edit file"))?;
        let content = &tf.text;

        // Work with Unicode characters
        let chars: Vec<char> = content.chars().collect();
        let char_count = chars.len();

        // Clamp start to content length
        let start = args.start.min(char_count);

        // Calculate end position
        let end = if let Some(e) = args.end.get() {
            e.min(char_count)
        } else if let Some(len) = args.length.get() {
            (start + len).min(char_count)
        } else {
            unreachable!()
        };

        if start >= end {
            // Nothing to extract
            return Ok(CallToolResult::success(vec![ContentBlock::text(
                "Nothing to extract (empty range)",
            )])
            .with_structured(json!({
                "charCount": 0,
                "start": start,
                "end": end,
                "dryRun": args.dry_run,
            })));
        }

        // Extract characters
        let extracted: String = chars[start..end].iter().collect();

        if !*args.dry_run {
            // Build new content without extracted chars
            let mut remaining = String::with_capacity(content.len() - extracted.len());
            remaining.extend(chars[..start].iter());
            remaining.extend(chars[end..].iter());

            let bytes = tf
                .encode(&remaining)
                .map_err(internal_err("Failed to encode edited file"))?;
            fs::write(&path, &bytes)
                .await
                .map_err(internal_err("Failed to write file"))?;
        }

        let message = if *args.dry_run {
            format!(
                "Dry run - would extract {} characters (positions {}-{}) from {}",
                end - start,
                start,
                end,
                args.path
            )
        } else {
            format!(
                "Extracted {} characters (positions {}-{}) from {}",
                end - start,
                start,
                end,
                args.path
            )
        };

        // Build response - only include extracted content if requested
        let text_response = if *args.return_extracted {
            format!("{}\n\nExtracted content:\n{}", message, extracted)
        } else {
            message.clone()
        };

        let mut structured = json!({
            "message": message,
            "charCount": end - start,
            "start": start,
            "end": end,
            "dryRun": *args.dry_run,
        });
        if *args.return_extracted {
            structured["extracted"] = json!(extracted);
        }

        Ok(
            CallToolResult::success(vec![ContentBlock::text(text_response)])
                .with_structured(structured),
        )
    }

    // ========================================================================
    // Binary tools - read/write/edit binary files
    // ========================================================================

    #[tool(
        name = "read_binary",
        description = "Read bytes from a binary file. Returns base64-encoded data.

PARAMETERS:
- path: File path
- offset: Start position in bytes (0-indexed)
- length: Number of bytes to read

EXAMPLES:
- Read 100 bytes from start: {path: 'file.bin', offset: 0, length: 100}
- Read 1KB at position 512: {path: 'file.bin', offset: 512, length: 1024}

USE CASES: Read binary headers, extract sections of images/executables, inspect binary data."
    )]
    async fn read_binary(
        &self,
        Parameters(args): Parameters<ReadBinaryArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;

        let data = read_bytes(&path, *args.offset, *args.length)
            .await
            .map_err(|e| McpError::internal_error(format!("Failed to read binary: {}", e), None))?;

        let base64_data = to_base64(&data);

        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Read {} bytes from {} at offset {}\n\nBase64:\n{}",
            data.len(),
            args.path,
            args.offset,
            base64_data
        ))])
        .with_structured(json!({
            "data": base64_data,
            "bytesRead": data.len(),
            "offset": args.offset,
            "path": args.path,
        })))
    }

    #[tool(
        name = "write_binary",
        description = "Write bytes to a binary file via Content Plane.

            data is a ContentRef (binary mode): inline/base64/path/blob. Prefer base64 or blob.
            PARAMETERS: path, offset, data (ContentRef), mode replace|insert."
    )]
    async fn write_binary(
        &self,
        Parameters(args): Parameters<WriteBinaryArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;

        let data = self
            .resolve_content(&args.data, ContentMode::Binary)
            .await?;

        let insert = matches!(args.mode, WriteBinaryMode::Insert);

        write_bytes(&path, *args.offset, &data, insert)
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to write binary: {}", e), None)
            })?;

        let mode_str = if insert { "inserted" } else { "replaced" };
        let message = format!(
            "Successfully {} {} bytes at offset {} in {}",
            mode_str,
            data.len(),
            args.offset,
            args.path
        );

        Ok(
            CallToolResult::success(vec![ContentBlock::text(&message)]).with_structured(json!({
                "message": message,
                "bytesWritten": data.len(),
                "offset": args.offset,
                "mode": if insert { "insert" } else { "replace" },
                "path": args.path,
            })),
        )
    }

    #[tool(
        name = "extract_binary",
        description = "Extract (cut) bytes from a binary file. Removes bytes and returns base64-encoded data.

PARAMETERS:
- path: File path
- offset: Start position in bytes (0-indexed)
- length: Number of bytes to extract
- dryRun: If true, only preview - don't modify file

EXAMPLES:
- Cut first 256 bytes: {path: 'file.bin', offset: 0, length: 256}
- Preview cut: {path: 'file.bin', offset: 1024, length: 512, dryRun: true}

USE CASES: Remove binary sections, cut data to relocate, strip headers from files."
    )]
    async fn extract_binary(
        &self,
        Parameters(args): Parameters<ExtractBinaryArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;

        let data = if *args.dry_run {
            // Just read without removing
            read_bytes(&path, *args.offset, *args.length)
                .await
                .map_err(|e| {
                    McpError::internal_error(format!("Failed to read binary: {}", e), None)
                })?
        } else {
            extract_bytes(&path, *args.offset, *args.length)
                .await
                .map_err(|e| {
                    McpError::internal_error(format!("Failed to extract binary: {}", e), None)
                })?
        };

        let base64_data = to_base64(&data);

        let message = if *args.dry_run {
            format!(
                "Dry run - would extract {} bytes at offset {} from {}",
                data.len(),
                args.offset,
                args.path
            )
        } else {
            format!(
                "Extracted {} bytes at offset {} from {}",
                data.len(),
                args.offset,
                args.path
            )
        };

        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "{}\n\nBase64:\n{}",
            message, base64_data
        ))])
        .with_structured(json!({
            "message": message,
            "data": base64_data,
            "bytesExtracted": data.len(),
            "offset": args.offset,
            "dryRun": args.dry_run,
            "path": args.path,
        })))
    }

    #[tool(
        name = "patch_binary",
        description = "Find and replace binary patterns in a file. Both patterns must be base64-encoded.

PARAMETERS:
- path: File path
- find: Base64-encoded pattern to find
- replace: Base64-encoded replacement pattern
- all: If true, replace all occurrences (default: first only)

EXAMPLES:
- Replace first match: {path: 'file.bin', find: 'SGVsbG8=', replace: 'V29ybGQ='}
- Replace all matches: {path: 'file.bin', find: 'AAA=', replace: 'QkJC', all: true}

USE CASES: Patch executables, fix binary data, search-replace in non-text files."
    )]
    async fn patch_binary(
        &self,
        Parameters(args): Parameters<PatchBinaryArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;

        let find_data = from_base64(&args.find).map_err(|e| {
            McpError::invalid_params(format!("Invalid base64 in 'find': {}", e), None)
        })?;
        let replace_data = from_base64(&args.replace).map_err(|e| {
            McpError::invalid_params(format!("Invalid base64 in 'replace': {}", e), None)
        })?;

        let count = patch_bytes(&path, &find_data, &replace_data, *args.all)
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to patch binary: {}", e), None)
            })?;

        let message = if count == 0 {
            format!("Pattern not found in {}", args.path)
        } else {
            format!("Replaced {} occurrence(s) in {}", count, args.path)
        };

        Ok(
            CallToolResult::success(vec![ContentBlock::text(&message)]).with_structured(json!({
                "message": message,
                "replacements": count,
                "replaceAll": args.all,
                "path": args.path,
            })),
        )
    }

    // ========================================================================
    // NEW TOOLS: Hashing, Comparison, Watch, JSON, PDF, Archives, Stats
    // ========================================================================

    #[tool(
        name = "file_hash",
        description = "Compute hash of a file or file region.\n\nAlgorithms: md5, sha1, sha256 (default), sha512, xxh64, murmur3, spooky.\n\nOptional offset/length for partial hashing (e.g., hash first 1KB: offset=0, length=1024).\n\nEXAMPLES:\n- Hash entire file: {path: 'file.bin'}\n- Hash with MD5: {path: 'file.bin', algorithm: 'md5'}\n- Hash first 1KB: {path: 'file.bin', offset: 0, length: 1024}\n- Hash from position 512: {path: 'file.bin', offset: 512}"
    )]
    async fn file_hash(
        &self,
        Parameters(args): Parameters<FileHashArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;
        let algo = hash::HashAlgorithm::from_str(args.algorithm.as_deref().unwrap_or("sha256"))
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let result = hash::hash_file_range(&path, algo, args.offset.get(), args.length.get())
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "{}: {}",
            args.path, result.hash
        ))])
        .with_structured(json!({
            "path": args.path,
            "algorithm": args.algorithm.as_deref().unwrap_or("sha256"),
            "hash": result.hash,
            "size": result.size,
            "offset": args.offset.unwrap_or(0),
            "length": args.length,
        })))
    }

    #[tool(
        name = "file_hash_multiple",
        description = "Compute hashes of multiple files.\n\nAlgorithms: md5, sha1, sha256 (default), sha512, xxh64, murmur3, spooky.\n\nReturns all_match=true if all hashes identical. Each result has error field for failures."
    )]
    async fn file_hash_multiple(
        &self,
        Parameters(args): Parameters<FileHashMultipleArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut paths = Vec::new();
        for p in &args.paths {
            paths.push(self.resolve(p).await?);
        }

        let algo = hash::HashAlgorithm::from_str(args.algorithm.as_deref().unwrap_or("sha256"))
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let path_refs: Vec<&std::path::Path> = paths.iter().map(|p| p.as_path()).collect();
        let result = hash::hash_files_multiple(&path_refs, algo).await;

        let text = result
            .results
            .iter()
            .map(|r| format!("{}: {}", r.path, r.hash))
            .collect::<Vec<_>>()
            .join("\n");

        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "{}\n\nAll match: {}",
            text, result.all_match
        ))])
        .with_structured(json!({
            "results": result.results.iter().map(|r| json!({
                "path": r.path,
                "hash": r.hash,
                "size": r.size,
                "error": r.error,
            })).collect::<Vec<_>>(),
            "allMatch": result.all_match,
        })))
    }

    #[tool(
        name = "compare_files",
        description = "Binary comparison of two files. Returns diff samples (hex bytes), match percentage, hash values, and empty-range flags."
    )]
    async fn compare_files(
        &self,
        Parameters(args): Parameters<CompareFilesArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path1 = self.resolve(&args.path1).await?;
        let path2 = self.resolve(&args.path2).await?;

        let params = compare::CompareParams {
            offset1: args.offset1,
            offset2: args.offset2,
            length: if args.length == 0 {
                None
            } else {
                Some(args.length)
            },
            max_diffs: args.max_diffs,
            context_bytes: args.context_bytes,
        };

        let result = compare::compare_files(&path1, &path2, params)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let status = if result.identical {
            "IDENTICAL"
        } else {
            "DIFFERENT"
        };
        let text = format!(
            "{} vs {}\nStatus: {}\nSize: {} vs {} ({:+})\nMatch: {:.2}%",
            args.path1,
            args.path2,
            status,
            result.size1,
            result.size2,
            result.size_diff,
            result.match_percentage
        );

        Ok(
            CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
                "identical": result.identical,
                "size1": result.size1,
                "size2": result.size2,
                "sizeDiff": result.size_diff,
                "hash1": result.hash1,
                "hash2": result.hash2,
                "firstDiffOffset": result.first_diff_offset,
                "totalDiffRegions": result.total_diff_regions,
                "totalDiffBytes": result.total_diff_bytes,
                "matchPercentage": result.match_percentage,
                "file1Empty": result.file1_empty,
                "file2Empty": result.file2_empty,
                "diffSamples": result.diff_samples.iter().map(|s| json!({
                    "offset": s.offset,
                    "length": s.length,
                    "bytes1Hex": s.bytes1_hex,
                    "bytes2Hex": s.bytes2_hex,
                })).collect::<Vec<_>>(),
            })),
        )
    }

    #[tool(
        name = "compare_directories",
        description = "Compare two directories. Returns files only in first, only in second, different files, and any errors encountered."
    )]
    async fn compare_directories(
        &self,
        Parameters(args): Parameters<CompareDirsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path1 = self.resolve(&args.path1).await?;
        let path2 = self.resolve(&args.path2).await?;

        let params = compare::DirCompareParams {
            recursive: *args.recursive,
            compare_content: *args.compare_content,
            ignore_patterns: args.ignore_patterns.clone(),
        };

        let result = compare::compare_directories(&path1, &path2, params)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let status = if result.identical {
            "IDENTICAL"
        } else {
            "DIFFERENT"
        };
        let text = format!(
            "{}\nOnly in {}: {}\nOnly in {}: {}\nDifferent: {}\nSame: {}",
            status,
            args.path1,
            result.only_in_first.len(),
            args.path2,
            result.only_in_second.len(),
            result.different.len(),
            result.same_count
        );

        Ok(
            CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
                "identical": result.identical,
                "onlyInFirst": result.only_in_first,
                "onlyInSecond": result.only_in_second,
                "different": result.different.iter().map(|d| json!({
                    "path": d.path,
                    "size1": d.size1,
                    "size2": d.size2,
                    "hash1": d.hash1,
                    "hash2": d.hash2,
                })).collect::<Vec<_>>(),
                "sameCount": result.same_count,
                "diffCount": result.diff_count,
                "errors": result.errors,
            })),
        )
    }

    #[tool(
        name = "tail_file",
        description = "Read last N lines/bytes of a file. Supports follow mode for logs."
    )]
    async fn tail_file(
        &self,
        Parameters(args): Parameters<TailFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;

        let params = watch::TailParams {
            lines: args.lines,
            bytes: args.bytes.map(|b| b as u64),
            follow: *args.follow,
            timeout_ms: args.timeout_ms,
        };

        let result = watch::tail_file(&path, params)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        // In follow mode the appended content is the whole point of the call;
        // surface it (and its line count) instead of silently discarding it.
        Ok(
            CallToolResult::success(vec![ContentBlock::text(&result.content)]).with_structured(
                json!({
                    "content": result.content,
                    "linesReturned": result.lines_returned,
                    "fileSize": result.file_size,
                    "truncated": result.truncated,
                    "followContent": result.follow_content,
                    "followLines": result.follow_lines,
                }),
            ),
        )
    }

    #[tool(
        name = "watch_file",
        description = "Wait for file changes (modify, create, delete). Returns event type, elapsed time, new size, and timedOut flag."
    )]
    async fn watch_file(
        &self,
        Parameters(args): Parameters<WatchFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;

        let events: Vec<watch::WatchEvent> = args
            .events
            .iter()
            .filter_map(|e| watch::WatchEvent::from_str(e).ok())
            .collect();

        let result = watch::watch_file(&path, args.timeout_ms, &events)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let text = if result.changed {
            format!(
                "File changed: {:?} after {}ms",
                result.event, result.elapsed_ms
            )
        } else {
            "No changes detected (timeout)".to_string()
        };

        Ok(
            CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
                "changed": result.changed,
                "event": result.event,
                "newSize": result.new_size,
                "elapsedMs": result.elapsed_ms,
                "timedOut": result.timed_out,
            })),
        )
    }

    #[tool(
        name = "read_json",
        description = "Read JSON file with optional JSONPath query. Returns result, totalKeys (objects), arrayLength (arrays), and parse errors."
    )]
    async fn read_json(
        &self,
        Parameters(args): Parameters<ReadJsonArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;

        let result = json_reader::read_json(&path, args.query.as_deref(), *args.pretty)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let text = if let Some(ref err) = result.parse_error {
            format!(
                "JSON parse error at line {:?}, col {:?}: {}\nContext: {:?}",
                err.line, err.column, err.message, err.context
            )
        } else {
            result.pretty.clone()
        };

        let mut r = CallToolResult::success(vec![ContentBlock::text(text)]);
        r.structured_content = Some(json!({
            "result": result.result,
            "queryMatched": result.query_matched,
            "parseError": result.parse_error.as_ref().map(|e| json!({
                "message": e.message,
                "line": e.line,
                "column": e.column,
            })),
            "totalKeys": result.total_keys,
            "arrayLength": result.array_length,
        }));
        r.is_error = Some(result.parse_error.is_some());
        Ok(r)
    }

    #[tool(
        name = "read_pdf",
        description = "Extract text from PDF. Default normalize=true collapses ZWSP/spaced glyphs. Returns quality.score, quality.warnings, suspiciousTokens when encoding maps look broken — do not treat low-score text as source of truth. Optional includeRaw for unnormalized extract."
    )]
    async fn read_pdf(
        &self,
        Parameters(args): Parameters<ReadPdfArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;

        let result = pdf_reader::read_pdf(
            &path,
            args.pages.as_deref(),
            args.max_chars,
            pdf_reader::ReadPdfOptions {
                normalize: *args.normalize,
                include_raw: *args.include_raw,
            },
        )
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut structured = json!({
            "text": result.text,
            "pagesCount": result.pages_count,
            "pagesExtracted": result.pages_extracted,
            "truncated": result.truncated,
            "charCount": result.char_count,
            "normalized": result.normalized,
            "quality": {
                "score": result.quality.score,
                "warnings": result.quality.warnings,
                "zeroWidthChars": result.quality.zero_width_chars,
                "singleLetterTokenRatio": result.quality.single_letter_token_ratio,
                "suspiciousTokenRatio": result.quality.suspicious_token_ratio,
                "suspiciousTokens": result.quality.suspicious_tokens,
            },
        });
        if let Some(raw) = result.raw_text {
            structured["rawText"] = json!(raw);
        }

        Ok(
            CallToolResult::success(vec![ContentBlock::text(&result.text)])
                .with_structured(structured),
        )
    }

    #[tool(
        name = "extract_archive",
        description = "Extract archive (zip, tar, tar.gz) to destination."
    )]
    async fn extract_archive(
        &self,
        Parameters(args): Parameters<ExtractArchiveArgs>,
    ) -> Result<CallToolResult, McpError> {
        let archive_path = self.resolve(&args.path).await?;
        let dest_path = self.resolve(&args.destination).await?;

        let format = if let Some(ref f) = args.format {
            Some(
                archive::ArchiveFormat::from_str(f)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?,
            )
        } else {
            None
        };

        let files_filter = if args.files.is_empty() {
            None
        } else {
            Some(args.files.as_slice())
        };

        let result = archive::extract_archive(&archive_path, &dest_path, format, files_filter)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let text = format!(
            "Extracted {} files ({} dirs) to {}. Total: {} bytes",
            result.files_extracted, result.dirs_created, args.destination, result.total_bytes
        );

        Ok(
            CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
                "filesExtracted": result.files_extracted,
                "dirsCreated": result.dirs_created,
                "files": result.files,
                "totalBytes": result.total_bytes,
            })),
        )
    }

    #[tool(
        name = "create_archive",
        description = "Create archive (zip, tar, tar.gz) from files/directories."
    )]
    async fn create_archive(
        &self,
        Parameters(args): Parameters<CreateArchiveArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut paths = Vec::new();
        for p in &args.paths {
            paths.push(self.resolve(p).await?);
        }
        let dest_path = self.resolve(&args.destination).await?;

        let format = if let Some(ref f) = args.format {
            Some(
                archive::ArchiveFormat::from_str(f)
                    .map_err(|e| McpError::invalid_params(e.to_string(), None))?,
            )
        } else {
            None
        };

        let result = archive::create_archive(&paths, &dest_path, format)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let text = format!(
            "Created archive with {} files. Size: {} bytes",
            result.files_added, result.archive_size
        );

        Ok(
            CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
                "filesAdded": result.files_added,
                "archiveSize": result.archive_size,
                "archivePath": result.archive_path,
            })),
        )
    }

    #[tool(
        name = "file_stats",
        description = "Get statistics for file/directory: total files, size, breakdown by extension, largest files."
    )]
    async fn file_stats(
        &self,
        Parameters(args): Parameters<FileStatsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;

        let result = stats::file_stats(&path, *args.recursive, 10)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let text = format!(
            "Files: {}, Dirs: {}, Size: {}",
            result.total_files, result.total_dirs, result.total_size_human
        );

        Ok(
            CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
                "totalFiles": result.total_files,
                "totalDirs": result.total_dirs,
                "totalSize": result.total_size,
                "totalSizeHuman": result.total_size_human,
                "byExtension": result.by_extension.iter().map(|(k, v)| {
                    (k.clone(), json!({ "count": v.count, "size": v.size }))
                }).collect::<std::collections::HashMap<_, _>>(),
                "largestFiles": result.largest_files.iter().map(|f| json!({
                    "path": f.path,
                    "size": f.size,
                })).collect::<Vec<_>>(),
            })),
        )
    }

    #[tool(
        name = "find_duplicates",
        description = "Find duplicate files by content hash. Returns groups of duplicates and wasted space."
    )]
    async fn find_duplicates(
        &self,
        Parameters(args): Parameters<FindDuplicatesArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;

        let result = duplicates::find_duplicates(&path, args.min_size.get(), *args.by_content)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let text = format!(
            "Found {} duplicate groups ({} files). Wasted space: {}",
            result.duplicate_groups.len(),
            result.duplicate_files,
            result.wasted_space_human
        );

        Ok(
            CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
                "duplicateGroups": result.duplicate_groups.iter().map(|g| json!({
                    "hash": g.hash,
                    "size": g.size,
                    "files": g.files,
                })).collect::<Vec<_>>(),
                "totalWastedSpace": result.total_wasted_space,
                "wastedSpaceHuman": result.wasted_space_human,
                "filesScanned": result.files_scanned,
                "duplicateFiles": result.duplicate_files,
            })),
        )
    }

    // === Process Management Tools ===

    #[tool(
        name = "run_command",
        description = "Execute a command with full process lifecycle control.\n\n\
            CROSS-PLATFORM: Windows, macOS, Linux. Handles long-running builds, background servers, \n\
            and quick commands. Sends progress heartbeat to prevent MCP client timeouts.\n\n\
            **Execution modes (mode):**\n\
            - sync (default): Wait for completion. Heartbeat every ~30s prevents timeout.\n\
            - managed: Wait for completion. Progress includes output snippets every ~10s.\n\
            - detached: Return immediately with PID. Use tail_file on log files for output.\n\n\
            **Output control:**\n\
            - streamOutput=true (default): full output goes to log files AND is returned inline.\n\
            - Default inline = last ~200 lines / 16 KB; full output stays in the file; stdoutTotalLines = true count.\n\
            - stdoutHead/stderrHead: Return first N lines inline.\n\
            - stdoutTail/stderrTail: Return last N lines inline.\n\
            - outputFilter: Grep-like filtering (include/exclude regex, context lines).\n\
            - Head+filter+tail can combine: first 5 lines + errors from middle + last 5 lines.\n\
            - Full output always goes to log files regardless of inline filtering.\n\
            - captureTruncated=true -> inline output is incomplete (a child kept the pipe open); read the log file.\n\n\
            **Output filter example:**\n\
            {outputFilter: {include: [\"error\", \"warning\"], exclude: [\"note:\"], context: 3, maxLines: 50}}\n\n\
            **Key features:**\n\
            - shell: false(default)=no shell (command auto-split into program+args); true=platform shell (cmd /C Win, sh -c Unix); 'bash'=bash -c (git bash on Win); 'pwsh'=PowerShell; 'cmd'/'sh'=force one.\n\
            - Unix-style pipelines on Windows: cmd does NOT support ';' and lacks tail/grep/sed — use shell:'bash' for those command lines.\n\
            - Multi-line cmd (newline-separated, shell:'cmd' or true/default on Windows) runs ALL lines via a temp .bat = BATCH semantics: %%i (not %i) in for, exit code = LAST line, a failing middle line does NOT stop the rest (use && for fail-fast).\n\
            - WINDOWS PATHS in `command`: JSON eats single backslashes (`\\r`/`\\t` become control chars). Double them (`\"C:\\\\dir\\\\file\"`) or use forward slashes; in shell mode the decoded line reaches cmd.exe verbatim.\n\
            - env/envPrepend/envAppend: Set, prepend, or append env vars.\n\
            - stdin: ContentRef for command stdin (inline/base64/path/blob).\n\
            - $VAR GOTCHA: the MCP client may DELETE `$NAME` tokens from `command`/`args` before the shell runs (every `$var` -> empty, even defined ones like $HOME); silent, no error. For scripts that need shell variables, pass them via `stdin` ContentRef (NOT stripped) or write a script file and run it (`bash x.sh` / `pwsh -NoProfile -File x.ps1`) — stdin ContentRef and file contents reach the program verbatim.\n\
            - cwd: optional working directory. Pass an absolute path with forward slashes as a plain JSON string value (e.g. `\"cwd\": \"C:/projects/repo\"`). Do NOT embed extra quote characters inside the path value itself.\n\
            - timeoutMs: Kill command (and all children) after N ms.\n\
            - Process tree kill: On timeout/cancel, kills all child processes too.\n\
            - MCP cancellation: If client cancels, process tree is killed immediately.\n\n\
            **Examples:**\n\
            - Quick: {command: 'git', args: ['status']}\n\
            - Long build: {command: 'cargo', args: ['build', '--release'], timeoutMs: 1200000}\n\
            - With filter: {command: 'cargo', args: ['build'], outputFilter: {include: ['error\\[', 'warning\\['], context: 2}}\n\
            - Shell pipes (unix dialect, any OS): {command: 'cat file.txt | grep error | head -20', shell: 'bash'}\n\
            - Background server: {command: 'npm', args: ['start'], mode: 'detached'}\n\
            - Managed build: {command: 'cargo', args: ['build'], mode: 'managed', timeoutMs: 600000}\n\
            - Stdin pipe: {command: 'python', args: ['script.py'], stdin: {kind:'inline', text:'input data'}}\n\n\
            **Output tips:** Prefer machine-readable formats: cargo build --message-format=json, \n\
            cargo test -- --format=terse, npm --json, pylint --output-format=json."
    )]
    async fn run_command(
        &self,
        Parameters(args): Parameters<RunCommandArgs>,
        meta: RequestMetaObject,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        // Auto-split a full command line accidentally passed via `command`.
        //
        // Agents frequently pass an entire command line as `command`
        // (e.g. "cargo test -p foo --release") while leaving `args` empty and
        // `shell` unset. Without a shell, `command` is taken as the literal
        // program name, so `Command::new` looks for an executable whose name
        // contains spaces and fails with a cryptic "Failed to spawn". When
        // `args` is empty and no shell is requested, `command` is parsed as a
        // command line (quote-aware, backslashes preserved): the first token is
        // the program, the rest its arguments. Deterministic, no filesystem
        // probing — a program path containing spaces must be quoted, as in any
        // shell. Explicit `args`, or any shell, leave `command` exactly as given.
        // See `fsmcp_bug.md` #2.
        let (command, run_args): (String, Vec<String>) =
            if args.args.is_empty() && *args.shell == ShellKind::None {
                let mut toks = split_command_line(&args.command).into_iter();
                match toks.next() {
                    Some(prog) => (prog, toks.collect()),
                    // Empty / whitespace-only command: keep the raw string so the
                    // spawn failure surfaces the original input unchanged.
                    None => (args.command.clone(), Vec::new()),
                }
            } else {
                (args.command.clone(), args.args.clone())
            };
        let args_refs: Vec<&str> = run_args.iter().map(|s| s.as_str()).collect();

        // Non-fatal hint for the silent-pipe footgun.
        //
        // When a whole command line is handed in via `command` with no explicit
        // `args` and no shell, a top-level operator (`|`, `;`, `&&`, `>`, …) was
        // split into a literal argv token, not interpreted — so the command
        // quietly does the wrong thing and returns a confusing exit code. We do
        // NOT reject (literal operators are valid argv for some programs); we
        // only attach an advisory so the caller knows to pass `shell:"bash"`.
        let pipe_hint: Option<String> = if args.args.is_empty() && *args.shell == ShellKind::None {
            top_level_shell_meta(&args.command).map(|op| {
                format!(
                    "command contains an unquoted shell operator '{op}' but shell is off, \
                         so it was passed as a literal argument and NOT interpreted. For \
                         pipelines/redirection pass shell:\"bash\" (works on Windows/macOS/Linux) \
                         or shell:true; quote the operator to silence this."
                )
            })
        } else {
            None
        };

        // Determine effective mode (backward compat: background=true -> detached)
        let mode = if *args.background {
            process::RunMode::Detached
        } else {
            match args.mode {
                RunModeArg::Sync => process::RunMode::Sync,
                RunModeArg::Managed => process::RunMode::Managed,
                RunModeArg::Detached => process::RunMode::Detached,
            }
        };

        // Prepare output log files
        let mut stdout_file = args.stdout_file.clone();
        let mut stderr_file = args.stderr_file.clone();
        let use_file_streaming =
            *args.stream_output || stdout_file.is_some() || stderr_file.is_some();
        if use_file_streaming && (stdout_file.is_none() || stderr_file.is_none()) {
            let (stream_stdout, stream_stderr) = prepare_stream_paths(&args).await?;
            stdout_file = stdout_file.or(Some(stream_stdout));
            stderr_file = stderr_file.or(Some(stream_stderr));
        }

        // Build output filter from args
        let output_filter = if let Some(ref filter_args) = args.output_filter {
            let context = filter_args.context.get().unwrap_or(0);
            // Reject invalid regexes instead of silently dropping them, which
            // turned an outputFilter into a no-op (fail-open) and returned the
            // whole output the caller was trying to narrow.
            let include = filter_args
                .include
                .iter()
                .map(|p| regex::Regex::new(p))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| {
                    McpError::invalid_params(
                        format!("Invalid outputFilter include regex: {e}"),
                        None,
                    )
                })?;
            let exclude = filter_args
                .exclude
                .iter()
                .map(|p| regex::Regex::new(p))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| {
                    McpError::invalid_params(
                        format!("Invalid outputFilter exclude regex: {e}"),
                        None,
                    )
                })?;
            Some(process::OutputFilter {
                include,
                exclude,
                context_before: filter_args.context_before.get().unwrap_or(context),
                context_after: filter_args.context_after.get().unwrap_or(context),
                max_lines: filter_args.max_lines.get(),
            })
        } else {
            None
        };

        let params = process::RunParams {
            cwd: args.cwd,
            env: args.env,
            clear_env: *args.clear_env,
            env_prepend: args.env_prepend,
            env_append: args.env_append,
            timeout_ms: args.timeout_ms.get(),
            kill_after_ms: args.kill_after_ms.get(),
            stdout_file: stdout_file.clone(),
            stderr_file: stderr_file.clone(),
            stdin_bytes: match args.stdin.as_ref() {
                Some(content) => Some(self.resolve_content(content, ContentMode::Text).await?),
                None => None,
            },
            stdout_head: args.stdout_head.get(),
            stdout_tail: args.stdout_tail.get(),
            stderr_head: args.stderr_head.get(),
            stderr_tail: args.stderr_tail.get(),
            output_filter,
            mode,
            shell: *args.shell,
            // Capture and file-streaming are independent (see stream_output
            // docs): always capture for the inline result; the log file is
            // teed in parallel when use_file_streaming set the paths above.
            capture_output: Some(true),
        };

        // Extract progress token from client request meta
        let progress_token = meta.get_progress_token();

        // Build progress callback that sends MCP progress notifications
        let progress_cb: Option<process::ProgressCallback> = if let Some(token) = progress_token {
            let peer = client.clone();
            let is_managed = mode == process::RunMode::Managed;
            let progress_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1));
            Some(Box::new(move |elapsed_ms: u64, new_lines: &[String]| {
                let peer = peer.clone();
                let token = token.clone();
                let counter = progress_counter.clone();
                let msg = if is_managed && !new_lines.is_empty() {
                    // In managed mode, include output snippet in progress message
                    let snippet: String = new_lines
                        .iter()
                        .rev()
                        .take(20)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n");
                    format!("Running ({}ms)...\n{}", elapsed_ms, snippet)
                } else {
                    format!("Running ({}ms)...", elapsed_ms)
                };
                let seq = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Box::pin(async move {
                    let param = ProgressNotificationParam::new(token, seq as f64).with_message(msg);
                    let _ = peer.notify_progress(param).await;
                })
            }))
        } else {
            None
        };

        // Build cancellation token from MCP context
        let cancel = tokio_util::sync::CancellationToken::new();
        // (rmcp does not currently expose ct on tool calls, so we don't wire it yet)

        // A genuine launch failure (program not found, `cd`/builtin spawned
        // without a shell, …) is a real tool-level error. When a top-level shell
        // operator was detected (`pipe_hint`) it is the likely cause — e.g.
        // `cd x && pwsh ...` fails to spawn `cd` — so fold the advisory into the
        // error message instead of dropping it on this path. See BUG3.md #2.
        let result = match process::run_command(
            &command,
            &args_refs,
            params,
            Some(&self.process_manager),
            Some(cancel),
            progress_cb,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                let mut msg = e.to_string();
                if let Some(hint) = &pipe_hint {
                    msg.push_str(&format!("\n\u{26a0} hint: {hint}"));
                }
                return Err(McpError::internal_error(msg, None));
            }
        };

        // Format human-readable status
        let status = if result.background {
            format!("Started in background (PID: {})", result.pid.unwrap_or(0))
        } else if result.cancelled {
            format!("Cancelled after {}ms", result.duration_ms)
        } else if result.timed_out {
            format!("Killed after {}ms (timeout)", result.duration_ms)
        } else {
            format!(
                "Completed in {}ms (exit code: {:?})",
                result.duration_ms, result.exit_code
            )
        };

        let mut text_parts = vec![status];
        if let Some(hint) = &pipe_hint {
            text_parts.push(format!("\n⚠ hint: {hint}"));
        }
        if let Some(path) = &stdout_file {
            text_parts.push(format!("\nstdout log: {path}"));
        }
        if let Some(path) = &stderr_file {
            text_parts.push(format!("\nstderr log: {path}"));
        }
        if use_file_streaming {
            text_parts
                .push("\nUse tail_file/read_text_file on these paths for full output.".to_string());
        }
        if result.capture_truncated {
            text_parts.push(
                "\n⚠ output capture incomplete (a child process may still hold the pipe open) — read the stdout log for the full output.".to_string(),
            );
        }
        if !result.stdout.is_empty() {
            text_parts.push(format!(
                "\n--- stdout ({} lines total) ---\n{}",
                result.stdout_total_lines, result.stdout
            ));
        }
        if !result.stderr.is_empty() {
            text_parts.push(format!(
                "\n--- stderr ({} lines total) ---\n{}",
                result.stderr_total_lines, result.stderr
            ));
        }

        let mut r = CallToolResult::success(vec![ContentBlock::text(text_parts.join(""))]);
        r.structured_content = Some(json!({
            "exitCode": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "pid": result.pid,
            "killed": result.killed,
            "timedOut": result.timed_out,
            "cancelled": result.cancelled,
            "durationMs": result.duration_ms,
            "background": result.background,
            "startedAt": result.started_at,
            "finishedAt": result.finished_at,
            "stdoutFile": stdout_file,
            "stderrFile": stderr_file,
            "stdoutTotalLines": result.stdout_total_lines,
            "stderrTotalLines": result.stderr_total_lines,
            "captureTruncated": result.capture_truncated,
            "hint": pipe_hint,
        }));
        // is_error means the TOOL failed, not that the command reported failure.
        // run_command's job is to launch the command and report its result; a
        // launched process that exits non-zero is a successful tool call whose
        // data happens to be a non-zero code. Many tools use non-zero as
        // information, not error: `grep`/`grep -c` (1 = no match), `diff`
        // (1 = differs), `test`. Flagging those as tool failures fires spurious
        // PostToolUse failure hooks. So is_error is true ONLY when the command
        // could not run to normal completion — killed by timeout/watchdog or
        // cancelled. A launch failure is already a separate Err path above. The
        // exit code itself is always surfaced in the text + structuredContent.
        // See BUG3.md #3.
        r.is_error = Some(result.killed || result.timed_out || result.cancelled);
        Ok(r)
    }

    #[tool(
        name = "kill_process",
        description = "Kill a running process by PID.\n\n\
            CROSS-PLATFORM: Works on Windows, macOS and Linux.\n\n\
            **Parameters:**\n\
            - pid: Process ID to kill\n\
            - force: Force kill (SIGKILL on Unix, TerminateProcess on Windows)\n\
            - tree: Kill entire process tree (parent + all child processes)\n\n\
            **Examples:**\n\
            - Graceful: {pid: 12345}\n\
            - Force kill: {pid: 12345, force: true}\n\
            - Kill tree: {pid: 12345, force: true, tree: true}"
    )]
    async fn kill_process(
        &self,
        Parameters(args): Parameters<KillProcessArgs>,
    ) -> Result<CallToolResult, McpError> {
        let (success, killed_count) = if *args.tree {
            let count = process::kill_process_tree(*args.pid, *args.force)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            (count > 0, count)
        } else {
            let ok = process::kill_process(*args.pid, *args.force)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            (ok, if ok { 1u32 } else { 0 })
        };

        // Only stop tracking the process if the kill actually succeeded.
        // Unconditional unregister hid a still-running process from the manager
        // when the kill failed (e.g. Windows force:false is a no-op) — an
        // invisible orphan.
        if success {
            self.process_manager.unregister(*args.pid).await;
        }

        let text = if *args.tree {
            if success {
                format!(
                    "Killed {} processes in tree rooted at PID {}",
                    killed_count, args.pid
                )
            } else {
                format!("No processes found in tree for PID {}", args.pid)
            }
        } else if success {
            format!("Process {} killed successfully", args.pid)
        } else {
            format!("Failed to kill process {} (may not exist)", args.pid)
        };

        let mut r = CallToolResult::success(vec![ContentBlock::text(text)]);
        r.structured_content = Some(json!({
            "pid": args.pid,
            "success": success,
            "killedCount": killed_count,
            "tree": *args.tree,
        }));
        r.is_error = Some(!success);
        Ok(r)
    }

    #[tool(
        name = "list_processes",
        description = "List background processes started by this server.\n\n\
            Returns processes that were started with run_command(mode: 'detached') and are still tracked.\n\
            Note: This only lists processes started by THIS server session, not all system processes.\n\n\
            **Parameters:**\n\
            - filter: Optional filter by command name"
    )]
    async fn list_processes(
        &self,
        Parameters(args): Parameters<ListProcessesArgs>,
    ) -> Result<CallToolResult, McpError> {
        let processes = self.process_manager.list().await;

        let filtered: Vec<_> = if let Some(ref filter) = args.filter {
            processes
                .into_iter()
                .filter(|p| p.command.contains(filter))
                .collect()
        } else {
            processes
        };

        let text = if filtered.is_empty() {
            "No background processes tracked".to_string()
        } else {
            filtered
                .iter()
                .map(|p| {
                    format!(
                        "PID {}: {} {} (running for {}s)",
                        p.pid,
                        p.command,
                        p.args.join(" "),
                        p.started_at.elapsed().as_secs()
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        };

        Ok(
            CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
                "processes": filtered.iter().map(|p| json!({
                    "pid": p.pid,
                    "command": p.command,
                    "args": p.args,
                    "cwd": p.cwd,
                    "runningForSecs": p.started_at.elapsed().as_secs(),
                })).collect::<Vec<_>>(),
                "count": filtered.len(),
            })),
        )
    }

    #[tool(
        name = "search_processes",
        description = "Search for running processes by name or command line pattern.\n\n\
            CROSS-PLATFORM: Works on Windows, macOS, and Linux.\n\n\
            **Parameters:**\n\
            - name_pattern: Regex to match process name (e.g., 'chrome', 'python.*')\n\
            - cmdline_pattern: Regex to match full command line (e.g., '--port=8080')\n\
            - include_window_title: Include window titles (Windows only, slower)\n\n\
            **Examples:**\n\
            - Find Chrome: {name_pattern: 'chrome'}\n\
            - Find by port: {cmdline_pattern: '--port=3000'}\n\
            - Find Python scripts: {name_pattern: 'python', cmdline_pattern: 'script\\\\.py'}\n\n\
            **Note:** At least one of name_pattern or cmdline_pattern must be provided."
    )]
    async fn search_processes(
        &self,
        Parameters(args): Parameters<SearchProcessesArgs>,
    ) -> Result<CallToolResult, McpError> {
        if args.name_pattern.is_none() && args.cmdline_pattern.is_none() {
            return Err(McpError::invalid_params(
                "At least one of name_pattern or cmdline_pattern must be provided",
                None,
            ));
        }

        let results = process::search_processes(
            args.name_pattern.as_deref(),
            args.cmdline_pattern.as_deref(),
        )
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let text = if results.is_empty() {
            "No matching processes found".to_string()
        } else {
            results
                .iter()
                .map(|p| {
                    let cmdline = p.command_line.as_deref().unwrap_or("");
                    format!(
                        "PID {}: {} ({:.1}% CPU, {} MB) - {}",
                        p.pid,
                        p.name,
                        p.cpu_percent,
                        p.memory_bytes / 1024 / 1024,
                        cmdline
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        };

        Ok(
            CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!({
                "processes": results,
                "count": results.len(),
            })),
        )
    }

    // === Screenshot Tools ===

    #[cfg(feature = "screenshot-tools")]
    #[tool(
        name = "screenshot_list_monitors",
        description = "List all monitors with IDs and dimensions"
    )]
    async fn list_monitors(
        &self,
        Parameters(_args): Parameters<ListMonitorsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let monitors = screenshot::list_monitors()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let payload = json!({ "monitors": monitors });
        let text =
            serde_json::to_string_pretty(&payload).unwrap_or_else(|_| format!("{:?}", payload));
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(payload))
    }

    #[cfg(feature = "screenshot-tools")]
    #[tool(
        name = "screenshot_list_windows",
        description = "List all visible windows. Optional title_filter."
    )]
    async fn list_windows(
        &self,
        Parameters(args): Parameters<ListWindowsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut windows = screenshot::list_windows()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        if let Some(filter) = &args.title_filter {
            let lower = filter.to_lowercase();
            windows.retain(|w| w.title.to_lowercase().contains(&lower));
        }
        let payload = json!({ "windows": windows });
        let text =
            serde_json::to_string_pretty(&payload).unwrap_or_else(|_| format!("{:?}", payload));
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(payload))
    }

    #[cfg(feature = "screenshot-tools")]
    #[tool(
        name = "screenshot_capture_screen",
        description = "Capture monitor. Args: monitor_id, output (file/clipboard/base64), path"
    )]
    async fn capture_screen(
        &self,
        Parameters(args): Parameters<CaptureScreenArgs>,
    ) -> Result<CallToolResult, McpError> {
        let image = screenshot::capture_monitor(args.monitor_id.get())
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        self.handle_screenshot_output(&image, args.output, args.path.as_deref())
            .await
    }

    #[cfg(feature = "screenshot-tools")]
    #[tool(
        name = "screenshot_capture_window",
        description = "Capture window by window_id or title"
    )]
    async fn capture_window(
        &self,
        Parameters(args): Parameters<CaptureWindowArgs>,
    ) -> Result<CallToolResult, McpError> {
        let image = match (args.window_id.get(), &args.title) {
            (Some(id), _) => screenshot::capture_window_by_id(id),
            (None, Some(title)) => screenshot::capture_window_by_title(title),
            _ => {
                return Err(McpError::invalid_params(
                    "window_id or title required",
                    None,
                ));
            }
        }
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        self.handle_screenshot_output(&image, args.output, args.path.as_deref())
            .await
    }

    #[cfg(feature = "screenshot-tools")]
    #[tool(
        name = "screenshot_capture_region",
        description = "Capture region. Args: x, y, width, height, monitor_id, output, path"
    )]
    async fn capture_region(
        &self,
        Parameters(args): Parameters<CaptureRegionArgs>,
    ) -> Result<CallToolResult, McpError> {
        let image = screenshot::capture_region(
            args.monitor_id.get(),
            *args.x,
            *args.y,
            *args.width,
            *args.height,
        )
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        self.handle_screenshot_output(&image, args.output, args.path.as_deref())
            .await
    }

    #[cfg(feature = "screenshot-tools")]
    #[tool(
        name = "screenshot_copy_to_clipboard",
        description = "Copy image file to clipboard"
    )]
    async fn copy_to_clipboard(
        &self,
        Parameters(args): Parameters<CopyToClipboardArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;
        screenshot::copy_file(&path).map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Copied to clipboard: {}",
            path.display()
        ))])
        .with_structured(json!({ "path": path.display().to_string() })))
    }

    // ==================== THINKING TOOLS ====================

    #[tool(
        name = "seq_think",
        description = "Sequential thinking for structured problem-solving. USE WITH SCOPED MEMORY TOOLS.\n\n\
            Helps analyze problems through a flexible thinking process that can adapt and evolve.\n\
            Each thought can build on, question, or revise previous insights.\n\n\
            RECOMMENDED WORKFLOW:\n\
            1. Use seq_think to break down task into numbered steps\n\
            2. Recall context with mem_get_summary (default workspace level), then focused mem_search if needed\n\
            3. Load exact records with mem_get by item UUID\n\
            4. Save or revise the plan with mem_put or mem_update using explicit scope + actor context\n\
            5. Connect related records with mem_link when useful\n\n\
            When to use:\n\
            - Breaking down complex problems into steps\n\
            - Planning and design with room for revision\n\
            - Analysis that might need course correction\n\
            - Multi-step solutions requiring context\n\n\
            EXAMPLE:\n\
            seq_think({thought: 'Step 1: Read config files', thoughtNumber: 1, totalThoughts: 5, nextThoughtNeeded: true})\n\
            seq_think({thought: 'Step 2: Parse schema', thoughtNumber: 2, ...})\n\
            Then save with mem_put: workspaceId, actorId, item{ itemType: task, content: ... }.\n\n\
            Parameters:\n\
            - thought: Current thinking step content\n\
            - nextThoughtNeeded: Whether another step is needed\n\
            - thoughtNumber: Current number (1-based)\n\
            - totalThoughts: Estimated total (adjustable)\n\
            - isRevision: If revising previous thinking\n\
            - revisesThought: Which thought being reconsidered\n\
            - branchFromThought: Branching point number\n\
            - branchId: Branch identifier\n\
            - needsMoreThoughts: If more needed beyond estimate"
    )]
    async fn seq_think(
        &self,
        Parameters(input): Parameters<ThoughtInput>,
    ) -> Result<CallToolResult, McpError> {
        let output = self.thinking_state.process(input);
        let text = serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string());
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!(output)))
    }

    // ==================== MEMORY TOOLS ====================

    fn require_memory_v2(&self) -> Result<&SqliteMemoryStore, McpError> {
        self.memory_store
            .as_ref()
            .map(|m| m.as_ref())
            .ok_or_else(|| McpError::internal_error("Memory v2 store not initialized", None))
    }

    #[tool(
        name = "mem_put",
        description = "Create a scoped memory item.\n\n\
            Required: workspaceId, actorId, item (object).\n\
            item.itemType: fact | episode | task | decision | artifact | summary.\n\
            item.content: plain string (facts) or JSON object/array.\n\
            Optional: tenantId, appId (default \"default\"), topicId, sessionId, runId, actorType (default agent).\n\n\
            Example: {\"workspaceId\":\"vfx-rs\",\"actorId\":\"cursor\",\"item\":{\"itemType\":\"task\",\"content\":{\"status\":\"open\"}}}"
    )]
    async fn mem_put(
        &self,
        Parameters(args): Parameters<MemPutArgs>,
    ) -> Result<CallToolResult, McpError> {
        mem_put(self.require_memory_v2()?, args).await
    }

    #[tool(
        name = "mem_update",
        description = "Update a scoped memory item by UUID. Required: workspaceId, actorId, id, item (same shape as mem_put)."
    )]
    async fn mem_update(
        &self,
        Parameters(args): Parameters<MemUpdateArgs>,
    ) -> Result<CallToolResult, McpError> {
        mem_update(self.require_memory_v2()?, args).await
    }

    #[tool(
        name = "mem_link",
        description = "Link two memory items. Required: workspaceId, actorId, relation { fromItemId, toItemId, relationType }."
    )]
    async fn mem_link(
        &self,
        Parameters(args): Parameters<MemLinkArgs>,
    ) -> Result<CallToolResult, McpError> {
        mem_link(self.require_memory_v2()?, args).await
    }

    #[tool(
        name = "mem_search",
        description = "Search scoped memory. Required: workspaceId, actorId, query. Optional: itemTypes[], tags[], visibility[], limit (default 20)."
    )]
    async fn mem_search(
        &self,
        Parameters(args): Parameters<MemSearchArgs>,
    ) -> Result<CallToolResult, McpError> {
        mem_search(self.require_memory_v2()?, args).await
    }

    #[tool(
        name = "mem_get",
        description = "Load memory items by UUID. Required: workspaceId, actorId, ids (UUID strings)."
    )]
    async fn mem_get(
        &self,
        Parameters(args): Parameters<MemGetArgs>,
    ) -> Result<CallToolResult, McpError> {
        mem_get(self.require_memory_v2()?, args).await
    }

    #[tool(
        name = "mem_get_summary",
        description = "Load latest summary item for scope. Required: workspaceId, actorId. Optional: level (workspace|topic|session|run, default workspace). topic/session/run require matching topicId/sessionId/runId."
    )]
    async fn mem_get_summary(
        &self,
        Parameters(args): Parameters<MemGetSummaryArgs>,
    ) -> Result<CallToolResult, McpError> {
        mem_get_summary(self.require_memory_v2()?, args).await
    }

    // ==================== XLSX TOOLS ====================

    #[tool(
        name = "xlsx_info",
        description = "Get XLSX workbook metadata.\n\n\
            Returns sheet names and dimensions."
    )]
    async fn xlsx_info(
        &self,
        Parameters(args): Parameters<XlsxInfoArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;
        let info = crate::tools::xlsx::xlsx_info(&path)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&info).unwrap_or_default(),
        )])
        .with_structured(info))
    }

    #[tool(
        name = "xlsx_sheets",
        description = "List sheet names in XLSX workbook."
    )]
    async fn xlsx_sheets(
        &self,
        Parameters(args): Parameters<XlsxSheetsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;
        let sheets = crate::tools::xlsx::xlsx_sheets(&path)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(
            CallToolResult::success(vec![ContentBlock::text(sheets.join(", "))])
                .with_structured(json!({"sheets": sheets})),
        )
    }

    #[tool(
        name = "xlsx_read",
        description = "Read XLSX sheet data as JSON.\n\n\
            Args: path, sheet (optional), headers (bool), max_rows, offset.\n\
            With headers=true, returns array of objects using first row as keys."
    )]
    async fn xlsx_read(
        &self,
        Parameters(args): Parameters<XlsxReadArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;
        let data = crate::tools::xlsx::xlsx_read(
            &path,
            args.sheet.as_deref(),
            *args.headers,
            args.max_rows.get(),
            args.offset.get(),
        )
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let summary = format!(
            "Read {} rows from sheet '{}'",
            data.get("returned").and_then(|v| v.as_u64()).unwrap_or(0),
            data.get("sheet").and_then(|v| v.as_str()).unwrap_or("?")
        );
        Ok(CallToolResult::success(vec![ContentBlock::text(&summary)]).with_structured(data))
    }

    // ==================== DOCX TOOLS ====================

    #[tool(
        name = "docx_read",
        description = "Read DOCX document content.\n\n\
            Args: path, include_structure (bool).\n\
            With include_structure=false (default): returns plain text.\n\
            With include_structure=true: returns paragraphs and tables as JSON."
    )]
    async fn docx_read(
        &self,
        Parameters(args): Parameters<DocxReadArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;
        let data = crate::tools::docx::docx_read(&path, *args.include_structure)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let summary = if *args.include_structure {
            format!(
                "Read {} paragraphs, {} tables",
                data.get("paragraph_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                data.get("table_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            )
        } else {
            format!(
                "Extracted {} characters",
                data.get("length").and_then(|v| v.as_u64()).unwrap_or(0)
            )
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(&summary)]).with_structured(data))
    }

    #[tool(
        name = "docx_info",
        description = "Get DOCX document metadata.\n\n\
            Returns paragraph count, table count, total characters."
    )]
    async fn docx_info(
        &self,
        Parameters(args): Parameters<DocxInfoArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;
        let info = crate::tools::docx::docx_info(&path)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&info).unwrap_or_default(),
        )])
        .with_structured(info))
    }

    // ==================== LLM TOOLS ====================

    #[tool(
        name = "ai_messages",
        description = "Claude Messages API-compatible conversation tool.\n\n\
            Supports tools, tool_choice, and streaming via progress notifications.\n\
            Request: { model, max_tokens, messages:[{role, content}], system?, tools?, stream? }.\n\
            Response: Anthropic-style message with content blocks and stop_reason."
    )]
    async fn ai_messages(
        &self,
        Parameters(request): Parameters<tools::llm::model::MessagesRequest>,
        meta: RequestMetaObject,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let llm = self.require_llm()?;
        let provider = llm.state().config.primary_provider();
        llm.messages_for_provider(&provider, request, meta, client)
            .await
    }

    #[tool(
        name = "ai_messages_gemini",
        description = "Claude Messages API-compatible conversation tool backed by Gemini."
    )]
    async fn ai_messages_gemini(
        &self,
        Parameters(request): Parameters<tools::llm::model::MessagesRequest>,
        meta: RequestMetaObject,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let llm = self.require_llm()?;
        llm.messages_for_provider("gemini", request, meta, client)
            .await
    }

    #[tool(
        name = "ai_messages_openai",
        description = "Claude Messages API-compatible conversation tool backed by OpenAI."
    )]
    async fn ai_messages_openai(
        &self,
        Parameters(request): Parameters<tools::llm::model::MessagesRequest>,
        meta: RequestMetaObject,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let llm = self.require_llm()?;
        llm.messages_for_provider("openai", request, meta, client)
            .await
    }

    #[tool(
        name = "ai_messages_cerebras",
        description = "Claude Messages API-compatible conversation tool backed by Cerebras."
    )]
    async fn ai_messages_cerebras(
        &self,
        Parameters(request): Parameters<tools::llm::model::MessagesRequest>,
        meta: RequestMetaObject,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let llm = self.require_llm()?;
        llm.messages_for_provider("cerebras", request, meta, client)
            .await
    }

    #[tool(
        name = "ai_count_tokens",
        description = "Claude Messages API-compatible token counting.\n\n\
            Returns input_tokens based on provider usage."
    )]
    async fn ai_count_tokens(
        &self,
        Parameters(request): Parameters<tools::llm::model::TokenCountRequest>,
    ) -> Result<CallToolResult, McpError> {
        let llm = self.require_llm()?;
        let provider = llm.state().config.primary_provider();
        llm.count_tokens_for_provider(&provider, request).await
    }

    #[tool(
        name = "ai_count_tokens_gemini",
        description = "Token counting backed by Gemini."
    )]
    async fn ai_count_tokens_gemini(
        &self,
        Parameters(request): Parameters<tools::llm::model::TokenCountRequest>,
    ) -> Result<CallToolResult, McpError> {
        let llm = self.require_llm()?;
        llm.count_tokens_for_provider("gemini", request).await
    }

    #[tool(
        name = "ai_count_tokens_openai",
        description = "Token counting backed by OpenAI."
    )]
    async fn ai_count_tokens_openai(
        &self,
        Parameters(request): Parameters<tools::llm::model::TokenCountRequest>,
    ) -> Result<CallToolResult, McpError> {
        let llm = self.require_llm()?;
        llm.count_tokens_for_provider("openai", request).await
    }

    #[tool(
        name = "ai_count_tokens_cerebras",
        description = "Token counting backed by Cerebras."
    )]
    async fn ai_count_tokens_cerebras(
        &self,
        Parameters(request): Parameters<tools::llm::model::TokenCountRequest>,
    ) -> Result<CallToolResult, McpError> {
        let llm = self.require_llm()?;
        llm.count_tokens_for_provider("cerebras", request).await
    }

    // ==================== WAVE2 TOOLS ====================

    #[tool(
        name = "port_users",
        description = "Find processes using a specific port.\n\n\
            Returns list of processes with PID, name, protocol, and connection state."
    )]
    async fn port_users(
        &self,
        Parameters(args): Parameters<PortUsersArgs>,
    ) -> Result<CallToolResult, McpError> {
        let users = tools::wave2::net::port_users(*args.port)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let count = users.len();
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "{} process(es) using port {}",
            count, args.port
        ))])
        .with_structured(json!({"port": args.port, "count": count, "processes": users})))
    }

    #[tool(
        name = "net_connections",
        description = "List network connections.\n\n\
            Optionally filter by process ID. Shows protocol, addresses, ports, and state."
    )]
    async fn net_connections(
        &self,
        Parameters(args): Parameters<NetConnectionsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let conns = tools::wave2::net::net_connections(args.pid.get())
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let count = conns.len();
        let summary = match args.pid.get() {
            Some(pid) => format!("{} connection(s) for PID {}", count, pid),
            None => format!("{} total connection(s)", count),
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(&summary)])
            .with_structured(json!({"count": count, "connections": conns})))
    }

    #[tool(
        name = "port_available",
        description = "Check if a port is available (not in use)."
    )]
    async fn port_available(
        &self,
        Parameters(args): Parameters<PortAvailableArgs>,
    ) -> Result<CallToolResult, McpError> {
        let available = tools::wave2::net::port_available(*args.port);
        let msg = if available {
            format!("Port {} is available", args.port)
        } else {
            format!("Port {} is in use", args.port)
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(&msg)])
            .with_structured(json!({"port": args.port, "available": available})))
    }

    #[tool(
        name = "proc_tree",
        description = "Get process tree with parent-child relationships.\n\n\
            Shows PID, name, CPU%, memory, and children for each process."
    )]
    async fn proc_tree(
        &self,
        Parameters(args): Parameters<ProcTreeArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tree = tools::wave2::proc::proc_tree(args.pid.get())
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let summary = match args.pid.get() {
            Some(pid) => format!("Process tree for PID {}", pid),
            None => "Full process tree".to_string(),
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(&summary)]).with_structured(tree))
    }

    #[tool(
        name = "proc_env",
        description = "Get environment variables of a process."
    )]
    async fn proc_env(
        &self,
        Parameters(args): Parameters<ProcEnvArgs>,
    ) -> Result<CallToolResult, McpError> {
        let env = tools::wave2::proc::proc_env(*args.pid)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let count = env.get("env_count").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "{} environment variables for PID {}",
            count, args.pid
        ))])
        .with_structured(env))
    }

    #[tool(
        name = "proc_files",
        description = "Get open files of a process.\n\n\
            Full support on Linux/macOS. Limited info on Windows."
    )]
    async fn proc_files(
        &self,
        Parameters(args): Parameters<ProcFilesArgs>,
    ) -> Result<CallToolResult, McpError> {
        let files = tools::wave2::proc::proc_files(*args.pid)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let count = files
            .get("file_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "{} open file(s) for PID {}",
            count, args.pid
        ))])
        .with_structured(files))
    }

    #[tool(
        name = "disk_usage",
        description = "Get disk usage information.\n\n\
            Shows total, used, available space for a path or all disks."
    )]
    async fn disk_usage(
        &self,
        Parameters(args): Parameters<DiskUsageArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = args.path.as_ref().map(std::path::Path::new);
        let usage = tools::wave2::sys::disk_usage(path)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let summary = match &args.path {
            Some(p) => format!("Disk usage for {}", p),
            None => "All disks".to_string(),
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(&summary)]).with_structured(usage))
    }

    #[tool(
        name = "sys_info",
        description = "Get system information.\n\n\
            Returns CPU, memory, swap, uptime, OS info, and load average."
    )]
    async fn sys_info(&self) -> Result<CallToolResult, McpError> {
        let info = tools::wave2::sys::sys_info();
        let hostname = info
            .get("hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "System info for {}",
            hostname
        ))])
        .with_structured(info))
    }

    #[tool(
        name = "file_diff",
        description = "Compare two files and show differences.\n\n\
            Returns unified diff with additions, deletions, and context."
    )]
    async fn file_diff(
        &self,
        Parameters(args): Parameters<FileDiffArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path1 = self.resolve(&args.path1).await?;
        let path2 = self.resolve(&args.path2).await?;
        let diff = tools::wave2::file::file_diff(&path1, &path2, args.context)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let identical = diff
            .get("identical")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let adds = diff.get("additions").and_then(|v| v.as_u64()).unwrap_or(0);
        let dels = diff.get("deletions").and_then(|v| v.as_u64()).unwrap_or(0);
        let summary = if identical {
            "Files are identical".to_string()
        } else {
            format!("+{} -{} lines", adds, dels)
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(&summary)]).with_structured(diff))
    }

    #[tool(
        name = "file_touch",
        description = "Create file or update its timestamp (like touch command)."
    )]
    async fn file_touch(
        &self,
        Parameters(args): Parameters<FileTouchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;
        let result = tools::wave2::file::file_touch(&path, *args.create_parents)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let created = result
            .get("created")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let summary = if created {
            "File created"
        } else {
            "Timestamp updated"
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(summary)]).with_structured(result))
    }

    #[tool(
        name = "clipboard_read",
        description = "Read text from system clipboard."
    )]
    async fn clipboard_read(&self) -> Result<CallToolResult, McpError> {
        let text = tools::wave2::util::clipboard_read()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let len = text.len();
        Ok(CallToolResult::success(vec![ContentBlock::text(&text)])
            .with_structured(json!({"text": text, "length": len})))
    }

    #[tool(
        name = "clipboard_write",
        description = "Write text to system clipboard."
    )]
    async fn clipboard_write(
        &self,
        Parameters(args): Parameters<ClipboardWriteArgs>,
    ) -> Result<CallToolResult, McpError> {
        tools::wave2::util::clipboard_write(&args.text)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Wrote {} characters to clipboard",
            args.text.len()
        ))])
        .with_structured(json!({"success": true, "length": args.text.len()})))
    }

    #[tool(name = "env_get", description = "Get environment variable value.")]
    async fn env_get(
        &self,
        Parameters(args): Parameters<EnvGetArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::wave2::util::env_get(&args.name) {
            Some(value) => Ok(CallToolResult::success(vec![ContentBlock::text(&value)])
                .with_structured(json!({"name": args.name, "value": value, "found": true}))),
            None => Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                "Environment variable '{}' not found",
                args.name
            ))])
            .with_structured(json!({"name": args.name, "found": false}))),
        }
    }

    #[tool(
        name = "env_set",
        description = "Set environment variable (current process only)."
    )]
    async fn env_set(
        &self,
        Parameters(args): Parameters<EnvSetArgs>,
    ) -> Result<CallToolResult, McpError> {
        tools::wave2::util::env_set(&args.name, &args.value);
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "Set {}={}",
            args.name, args.value
        ))])
        .with_structured(json!({"name": args.name, "value": args.value, "success": true})))
    }

    /// Remove an environment variable (current process only)
    #[tool(name = "env_remove")]
    async fn env_remove(
        &self,
        Parameters(args): Parameters<EnvRemoveArgs>,
    ) -> Result<CallToolResult, McpError> {
        tools::wave2::util::env_remove(&args.name);
        Ok(
            CallToolResult::success(vec![ContentBlock::text(format!("Removed {}", args.name))])
                .with_structured(json!({"name": args.name, "success": true})),
        )
    }

    #[tool(name = "env_list", description = "List all environment variables.")]
    async fn env_list(&self) -> Result<CallToolResult, McpError> {
        let list = tools::wave2::util::env_list();
        let count = list.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "{} environment variables",
            count
        ))])
        .with_structured(list))
    }

    #[tool(
        name = "which",
        description = "Find executable in PATH (like 'which' command)."
    )]
    async fn which(
        &self,
        Parameters(args): Parameters<WhichArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::wave2::util::which(&args.command) {
            Ok(result) => {
                let path = result.get("path").and_then(|v| v.as_str()).unwrap_or("");
                Ok(CallToolResult::success(vec![ContentBlock::text(path)]).with_structured(result))
            }
            Err(e) => Ok(
                CallToolResult::success(vec![ContentBlock::text(e.to_string())]).with_structured(
                    json!({"command": args.command, "found": false, "error": e.to_string()}),
                ),
            ),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for FileSystemServer {
    fn get_info(&self) -> ServerInfo {
        self.server_info()
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let ctx = rmcp::handler::server::tool::ToolCallContext::new(self, request, context);
        let response = self.tool_router.call(ctx).await?;
        Ok(if self.session_footer {
            match response {
                CallToolResponse::Complete(result) => {
                    CallToolResponse::Complete(agent_policy::stamp_tool_result(result))
                }
                other => other,
            }
        } else {
            response
        })
    }

    // NOTE: We don't override initialize() - let rmcp SDK handle the handshake protocol.
    // The default implementation will use get_info() to build the response.
    // Root fetching happens via on_roots_list_changed notification handler.

    async fn on_roots_list_changed(
        &self,
        context: rmcp::service::NotificationContext<rmcp::RoleServer>,
    ) {
        if let Err(err) = self.refresh_roots(&context.peer).await {
            warn!("Failed to refresh roots on list_changed: {}", err);
        }
    }
}

/// Run server in stdio mode (default)
async fn run_stdio_mode(server: FileSystemServer) -> Result<(), Box<dyn std::error::Error>> {
    let transport = stdio();
    let svc = server.serve(transport).await?;
    svc.waiting().await?;
    Ok(())
}

/// Run server in streamable HTTP mode
async fn run_stream_mode(
    server: FileSystemServer,
    bind: &str,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    use rmcp::transport::StreamableHttpService;
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;

    let addr = format!("{}:{}", bind, port);
    tracing::info!("Starting MCP HTTP server on http://{}/mcp", addr);

    // Create service with session management
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    // Build router with MCP endpoint and health check
    let router = axum::Router::new()
        .nest_service("/mcp", service)
        .route("/health", axum::routing::get(|| async { "OK" }));

    let tcp_listener = tokio::net::TcpListener::bind(&addr).await?;

    // Start server with graceful shutdown
    axum::serve(tcp_listener, router)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
        })
        .await?;

    Ok(())
}

/// Install panic hook that writes to file (stderr breaks stdio MCP transport)
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|panic_info| {
        let panic_log = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("filesystem-mcp-rs")
            .join("panic.log");

        // Ensure directory exists
        if let Some(parent) = panic_log.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let timestamp = humantime::format_rfc3339(std::time::SystemTime::now());
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        let message = panic_info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| {
                panic_info
                    .payload()
                    .downcast_ref::<String>()
                    .map(|s| s.as_str())
            })
            .unwrap_or("unknown panic");

        let backtrace = std::backtrace::Backtrace::force_capture();

        let log_entry = format!(
            "\n=== PANIC at {} ===\nLocation: {}\nMessage: {}\nBacktrace:\n{}\n",
            timestamp, location, message, backtrace
        );

        // Append to panic log file
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&panic_log)
        {
            use std::io::Write;
            let _ = file.write_all(log_entry.as_bytes());
        }
    }));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install panic hook FIRST - writes to file since stderr breaks stdio MCP
    install_panic_hook();

    let top = TopCli::parse();

    // Setup subcommands never start the server: they only touch agent configs.
    if let Some(cmd) = top.setup {
        let cmd = setup::with_default_dirs(cmd);
        match mcp_setup::cli::run(&cmd, &setup::host_spec()?) {
            // A broken or unreachable client is already spelled out in the table; exit non-zero
            // rather than printing an error line over it.
            Ok(outcome) => std::process::exit(outcome.exit_code()),
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(1);
            }
        }
    }

    let args = top.server;

    // Computer-control bootstrap: DPI first (clicks/captures misalign without it),
    // then the process-global arm gate.
    #[cfg(any(feature = "ctl-input", feature = "ctl-uia", feature = "ctl-ocr"))]
    if let Err(e) = crate::tools::computer::ensure_dpi_aware() {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
    #[cfg(any(feature = "ctl-input", feature = "ctl-uia"))]
    crate::tools::computer::safety::init_gate(
        crate::tools::computer::safety::resolve_ops_per_min(args.ctl_ops_per_min),
    );

    // Handle --list-features
    if args.list_features {
        print_features();
        return Ok(());
    }

    // Determine transport mode
    let mode = if args.stream_mode {
        TransportMode::Stream
    } else {
        TransportMode::Stdio
    };

    // Initialize logging based on mode
    // CRITICAL: stdio mode MUST NOT log to stderr by default!
    // Any stderr output during handshake causes "connection closed" in MCP clients
    init_logging(mode, args.log)?;

    // Create server instance
    let allowed = AllowedDirs::new(args.allowed_dirs);
    let mut server = FileSystemServer::new(allowed);
    server.allow_symlink_escape = args.allow_symlink_escape;
    server.session_footer = !args.no_session_footer;
    #[cfg(feature = "http-tools")]
    {
        let mut allowlist = args.http_allowlist_domains;
        allowlist.extend(parse_allowlist_env("FS_MCP_HTTP_ALLOW_LIST"));
        server.http_allowlist_domains = allowlist;
    }
    #[cfg(feature = "s3-tools")]
    {
        let mut allowlist = args.s3_allowlist_buckets;
        allowlist.extend(parse_allowlist_env("FS_MCP_S3_ALLOW_LIST"));
        server.s3_allowlist_buckets = allowlist;
    }
    {
        let access_mode = args
            .memory_access_mode
            .clone()
            .or_else(|| std::env::var("FS_MCP_MEMORY_ACCESS_MODE").ok())
            .map(|value| {
                value.parse::<V2MemoryAccessMode>().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid memory access mode '{value}': {e}"),
                    )
                })
            })
            .transpose()?
            .unwrap_or_default();
        let db_path = args
            .memory_db
            .or_else(|| std::env::var("FS_MCP_MEMORY_DB").ok().map(PathBuf::from))
            .unwrap_or_else(|| {
                let mut path = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
                path.push("filesystem-mcp-rs");
                path.push("memory2.db");
                path
            });
        info!("Memory v2 access mode: {}", access_mode);
        match SqliteMemoryStore::new(db_path, access_mode) {
            Ok(store) => server.memory_store = Some(Arc::new(store)),
            Err(e) => warn!("Failed to initialize memory v2 store: {}", e),
        }
    }

    // Initialize LLM server (if API keys are available)
    {
        match tools::llm::build_state().await {
            Ok(state) => {
                let llm = tools::llm::LlmMcpServer::new(state);
                info!(
                    "LLM server initialized with providers: {:?}",
                    llm.available_providers()
                );
                server.llm_server = Some(llm);
            }
            Err(e) => info!("LLM server not initialized: {}", e),
        }
    }

    // Run in selected mode
    match mode {
        TransportMode::Stdio => run_stdio_mode(server).await,
        TransportMode::Stream => run_stream_mode(server, &args.bind, args.port).await,
    }
}

// init_tracing removed - see main() comment about why we can't use stderr logging

fn internal_err<T: ToString>(message: &'static str) -> impl FnOnce(T) -> McpError + Clone {
    move |err| {
        let details = err.to_string();
        McpError::internal_error(
            format!("{}: {}", message, details),
            Some(json!({ "error": details })),
        )
    }
}

fn grep_stats_json(stats: &GrepStats) -> Value {
    json!({
        "elapsedMs": stats.elapsed_ms,
        "visitedEntries": stats.visited_entries,
        "visitedDirs": stats.visited_dirs,
        "filesSeen": stats.files_seen,
        "filesSearched": stats.files_searched,
        "bytesSearched": stats.bytes_searched,
        "matchesFound": stats.matches_found,
        "skippedBinary": stats.skipped_binary,
        "skippedUnreadable": stats.skipped_unreadable,
        "threads": stats.threads,
        "stoppedReason": stats.stopped_reason,
    })
}

fn grep_progress_callback(
    progress_token: Option<rmcp::model::ProgressToken>,
    client: Peer<RoleServer>,
) -> Option<ProgressCallback> {
    progress_token.map(|token| {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ProgressSnapshot>();
        let counter = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let notify_counter = counter.clone();
        tokio::spawn(async move {
            while let Some(snapshot) = rx.recv().await {
                let seq = notify_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let message = grep_progress_message(&snapshot);
                let _ = client
                    .notify_progress(
                        ProgressNotificationParam::new(token.clone(), seq as f64)
                            .with_message(message),
                    )
                    .await;
            }
        });

        Arc::new(move |snapshot: ProgressSnapshot| {
            let _ = tx.send(snapshot);
        }) as ProgressCallback
    })
}

fn grep_progress_message(snapshot: &ProgressSnapshot) -> String {
    let stats = &snapshot.stats;
    let current = snapshot
        .current_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<starting>".to_string());
    let stopped = stats
        .stopped_reason
        .as_ref()
        .map(|reason| format!(", stoppingReason={reason}"))
        .unwrap_or_default();
    format!(
        "grep_files: {}ms elapsed, visited {} entries, searched {} files / {} bytes, found {} matches, current={}{}",
        stats.elapsed_ms,
        stats.visited_entries,
        stats.files_searched,
        stats.bytes_searched,
        stats.matches_found,
        current,
        stopped
    )
}

fn print_features() {
    println!("filesystem-mcp-rs v{}", env!("CARGO_PKG_VERSION"));
    println!("Enabled features:");

    #[cfg(feature = "http-tools")]
    println!("  + http-tools");
    #[cfg(not(feature = "http-tools"))]
    println!("  - http-tools");

    #[cfg(feature = "s3-tools")]
    println!("  + s3-tools");
    #[cfg(not(feature = "s3-tools"))]
    println!("  - s3-tools");

    #[cfg(feature = "screenshot-tools")]
    println!("  + screenshot-tools");
    #[cfg(not(feature = "screenshot-tools"))]
    println!("  - screenshot-tools");

    println!("  + thinking-tools (always on)");
    println!("  + memory-v2-tools (always on)");
    println!("  + xlsx-tools (always on)");
    println!("  + docx-tools (always on)");
    println!("  + llm-tools (always on, needs API keys)");
    println!(
        "  + wave2-tools (always on) - port_users, net_connections, proc_tree, disk_usage, etc."
    );
}

fn parse_allowlist_env(var_name: &str) -> Vec<String> {
    let Ok(value) = env::var(var_name) else {
        return Vec::new();
    };
    value
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn service_error(message: &'static str, error: ServiceError) -> McpError {
    let details = error.to_string();
    McpError::internal_error(
        format!("{}: {}", message, details),
        Some(json!({ "error": details })),
    )
}

fn parse_root_uri(uri: &str) -> Option<PathBuf> {
    if let Ok(url) = url::Url::parse(uri)
        && url.scheme() == "file"
    {
        return url.to_file_path().ok();
    }
    Some(PathBuf::from(uri))
}

fn format_time(time: Option<SystemTime>) -> Option<String> {
    time.and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| {
            let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(d.as_secs());
            humantime::format_rfc3339(ts).to_string()
        })
}

fn parse_time_filter(raw: &str) -> anyhow::Result<SystemTime> {
    if let Ok(ts) = humantime::parse_rfc3339(raw) {
        return Ok(ts);
    }
    if let Ok(duration) = humantime::parse_duration(raw) {
        return SystemTime::now()
            .checked_sub(duration)
            .ok_or_else(|| anyhow::anyhow!("Time filter underflow"));
    }
    anyhow::bail!(
        "Invalid time filter '{raw}'. Expected RFC3339 or duration like '17m 20s' or '7d'"
    )
}

async fn prepare_stream_paths(args: &RunCommandArgs) -> Result<(String, String), McpError> {
    // Auto-generated stream logs always go to the OS temp dir (cross-platform:
    // %TEMP% on Windows, $TMPDIR or /tmp on Unix) so they never litter the
    // working directory. Callers wanting them elsewhere set `stream_dir` explicitly.
    let dir = if let Some(ref dir) = args.stream_dir {
        PathBuf::from(dir)
    } else {
        env::temp_dir().join("filesystem-mcp")
    };

    fs::create_dir_all(&dir)
        .await
        .map_err(internal_err("Failed to create stream output directory"))?;

    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let base = format!("run_command_{ts}");
    let stdout = dir.join(format!("{base}_stdout.log"));
    let stderr = dir.join(format!("{base}_stderr.log"));

    Ok((
        stdout.to_string_lossy().to_string(),
        stderr.to_string_lossy().to_string(),
    ))
}

fn permissions_string(meta: &Metadata) -> String {
    #[cfg(unix)]
    {
        format!("{:o}", meta.permissions().mode())
    }
    #[cfg(not(unix))]
    {
        format!("{:?}", meta.permissions())
    }
}

/// Options for directory tree building
struct TreeOptions {
    max_depth: usize,
    show_size: bool,
    show_hash: bool,
}

#[async_recursion]
async fn build_tree(
    root: &Path,
    current: &Path,
    exclude: &globset::GlobSet,
    opts: &TreeOptions,
    depth: usize,
) -> Result<Vec<TreeEntry>, McpError> {
    let mut dir = fs::read_dir(current)
        .await
        .map_err(internal_err("Failed to read directory"))?;
    let mut children = Vec::new();
    while let Some(entry) = dir
        .next_entry()
        .await
        .map_err(internal_err("Failed to iterate directory"))?
    {
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(&path);
        let rel_str = rel.to_string_lossy();
        if exclude.is_match(&*rel_str) {
            continue;
        }

        let file_type = entry
            .file_type()
            .await
            .map_err(internal_err("stat entry"))?;
        let is_dir = file_type.is_dir();

        if is_dir {
            // Check depth limit before recursing
            let kids = if depth < opts.max_depth {
                Some(build_tree(root, &path, exclude, opts, depth + 1).await?)
            } else {
                None // At max depth, don't include children
            };

            children.push(TreeEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                kind: "directory".to_string(),
                children: kids,
                size: None,
                size_human: None,
                hash: None,
            });
        } else {
            // Get metadata for size
            let (size, size_human) = if opts.show_size {
                if let Ok(meta) = entry.metadata().await {
                    let s = meta.len();
                    (Some(s), Some(format::format_size(s)))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            // Get hash if requested
            let file_hash = if opts.show_hash {
                hash::hash_file(&path, hash::HashAlgorithm::Sha256)
                    .await
                    .ok()
                    .map(|r| r.hash)
            } else {
                None
            };

            children.push(TreeEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                kind: "file".to_string(),
                children: None,
                size,
                size_human,
                hash: file_hash,
            });
        }
    }
    Ok(children)
}

trait WithStructured {
    fn with_structured(self, value: serde_json::Value) -> Self;
}

impl WithStructured for CallToolResult {
    fn with_structured(mut self, value: serde_json::Value) -> Self {
        self.structured_content = Some(value);
        self
    }
}
