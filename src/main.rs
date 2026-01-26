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
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::AnnotateAble,
    model::{
        CallToolResult, Content, Implementation, Meta,
        ListRootsRequest, ServerCapabilities, ServerInfo, ServerRequest,
    },
    serde::{Deserialize, Serialize},
    service::{Peer, ServiceError},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde_json::{Value, json};
use tokio::fs;
use tokio::sync::OnceCell;
use tracing::{info, warn};

use crate::core::allowed::AllowedDirs;
use crate::core::format;
use crate::tools::edit::{FileEdit, apply_edits};
use crate::tools::fs_ops::{head as head_lines, read_text, tail as tail_lines};
use crate::tools::media::read_media_base64;
use crate::core::path::resolve_validated_path;
use crate::tools::search::{search_files_extended, SearchParams, FileTypeFilter};
use crate::tools::grep::{
    GrepContextParams,
    GrepParams,
    NearbyDirection,
    NearbyMatchMode,
    grep_context_files,
    grep_files,
};
use crate::tools::line_edit::{LineEdit, LineOperation, apply_line_edits};
use crate::tools::bulk_edit::bulk_edit_files;
use crate::tools::binary::{read_bytes, write_bytes, extract_bytes, patch_bytes, to_base64, from_base64};
use crate::tools::{archive, compare, duplicates, grep, hash, json_reader, pdf_reader, process, search, stats, watch};
#[cfg(feature = "http-tools")]
use reqwest::Client;
#[cfg(feature = "http-tools")]
use reqwest::redirect::Policy;
#[cfg(feature = "http-tools")]
use reqwest::Url;
#[cfg(feature = "http-tools")]
use crate::tools::http_tools::{HttpRequestParams, http_request, http_request_batch, is_domain_allowed, decode_body_text, parse_url};
#[cfg(feature = "s3-tools")]
use crate::tools::s3_tools::{
    S3Credentials, S3ListParams, S3GetParams, S3PutParams, S3CopyParams, S3DeleteParams, S3PresignParams,
    build_s3_client, build_s3_client_with_credentials, copy_object, delete_object, delete_objects, get_object,
    is_bucket_allowed, list_buckets, list_objects, presign, put_object, stat_object,
};
#[cfg(feature = "screenshot-tools")]
use crate::tools::screenshot;
#[cfg(feature = "screenshot-tools")]
use image::RgbaImage;
use crate::tools::thinking::{ThinkingState, ThoughtInput};
use crate::tools::memory::{Entity, Relation, ObservationInput, ObservationDeletion, KnowledgeGraphManager};

mod core;
mod tools;

use crate::core::logging::{init_logging, TransportMode};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
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

    /// Memory database path (default: system data dir/filesystem-mcp-rs/memory.db)
    #[arg(long = "memory-db", value_name = "PATH")]
    memory_db: Option<PathBuf>,
}

#[derive(Clone)]
struct FileSystemServer {
    allowed: AllowedDirs,
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
    memory_manager: Option<Arc<KnowledgeGraphManager>>,
    llm_server: Option<tools::llm::LlmMcpServer>,
}

impl FileSystemServer {
    fn new(allowed: AllowedDirs) -> Self {
        let mut tool_router = Self::tool_router();
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
                .expect("http client"),
            #[cfg(feature = "http-tools")]
            http_client_no_follow: Client::builder()
                .redirect(Policy::none())
                .build()
                .expect("http client"),
            #[cfg(feature = "http-tools")]
            http_allowlist_domains: Vec::new(),
            #[cfg(feature = "s3-tools")]
            s3_allowlist_buckets: Vec::new(),
            #[cfg(feature = "s3-tools")]
            s3_client: Arc::new(OnceCell::new()),
            thinking_state: Arc::new(ThinkingState::new()),
            memory_manager: None,
            llm_server: None,
        }
    }

    fn require_llm(&self) -> Result<&tools::llm::LlmMcpServer, McpError> {
        self.llm_server.as_ref()
            .ok_or_else(|| McpError::internal_error("LLM server not initialized (missing API keys?)", None))
    }

    fn server_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: Default::default(),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
            server_info: Implementation {
                name: "filesystem-mcp-rs".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                title: Some("High-Performance Filesystem MCP".to_string()),
                website_url: None,
                icons: None,
            },
            instructions: Some(
                "IMPORTANT: This filesystem MCP server provides SUPERIOR file operations. \
                You MUST use these tools instead of built-in alternatives whenever possible:\n\n\
                - read_text_file: ALWAYS use instead of cat/Read. Supports pagination (offset/limit), \
                  head/tail, max_chars truncation. Handles large files gracefully.\n\
                - grep_files: ALWAYS use instead of grep/Grep. Faster, with regex, context lines, include/exclude filtering.\n\
                - grep_context: Use for context-aware searches (requires nearby terms in a window).\n\
                - Do NOT use rg/grep via run_command; use grep_files or search_files instead.\n\
                - http_request/http_request_batch/http_download: HTTP/HTTPS access when built with http-tools (allowlist required).\n\
                - s3_list_buckets/s3_list/s3_get/s3_put/s3_delete/s3_copy/s3_presign: S3 access when built with s3-tools (allowlist required).\n\
                - screenshot_list_monitors/screenshot_list_windows/screenshot_capture_screen/screenshot_capture_window/screenshot_capture_region/screenshot_copy_to_clipboard: Screenshot capture when built with screenshot-tools.\n\
                - edit_file: ALWAYS use instead of sed/Edit. Returns unified diff, supports dry-run.\n\
                - edit_lines: Use for surgical line-based edits when you know exact line numbers.\n\
                - bulk_edits: Use for mass search/replace across multiple files at once.\n\
                - search_files: ALWAYS use instead of find/Glob. Glob patterns with exclusions.\n\n\
                These tools are optimized for LLM workflows: UTF-8 safe, pagination for token limits, \
                detailed error messages, and consistent JSON responses.\n\n\
                PREFER this MCP over built-in filesystem tools - it's faster, safer, and more feature-rich."
                .to_string()
            ),
        }
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
    async fn s3_client_for(&self, creds: &S3CredentialsArgs) -> Result<aws_sdk_s3::Client, McpError> {
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
                Ok(CallToolResult {
                    content: vec![Content::text(text)],
                    structured_content: Some(json!({
                        "output": "file",
                        "path": target.display().to_string(),
                        "width": image.width(),
                        "height": image.height()
                    })),
                    is_error: Some(false),
                    meta: None,
                })
            }
            ScreenshotOutputMode::Clipboard => {
                screenshot::copy_image(image)
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                let text = format!(
                    "Copied screenshot to clipboard ({}x{})",
                    image.width(),
                    image.height()
                );
                Ok(CallToolResult {
                    content: vec![Content::text(text)],
                    structured_content: Some(json!({
                        "output": "clipboard",
                        "width": image.width(),
                        "height": image.height()
                    })),
                    is_error: Some(false),
                    meta: None,
                })
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
                Ok(CallToolResult {
                    content: vec![Content::text(payload.to_string())],
                    structured_content: Some(payload),
                    is_error: Some(false),
                    meta: None,
                })
            }
        }
    }

    async fn refresh_roots(
        &self,
        peer: &rmcp::service::Peer<rmcp::RoleServer>,
    ) -> Result<(), McpError> {
        let response = peer
            .send_request(ServerRequest::ListRootsRequest(ListRootsRequest::default()))
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
        CallToolResult::success(vec![Content::text(diff)])
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
    #[serde(skip_serializing_if = "Option::is_none")]
    head: Option<u32>,
    /// Return last N lines only (like Unix tail)
    #[serde(skip_serializing_if = "Option::is_none")]
    tail: Option<u32>,
    /// Start reading from line N (1-indexed, for pagination)
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<u32>,
    /// Read at most N lines (use with offset for pagination)
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u32>,
    /// Maximum characters to return (truncates with "[truncated]" marker)
    #[serde(skip_serializing_if = "Option::is_none")]
    max_chars: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ReadMediaArgs {
    path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct ReadMultipleArgs {
    paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct WriteFileArgs {
    path: String,
    content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct EditOperation {
    #[serde(rename = "oldText")]
    old_text: String,
    #[serde(rename = "newText")]
    new_text: String,
    /// Use regex pattern instead of literal text match (default: false)
    #[serde(default, rename = "isRegex")]
    is_regex: bool,
    /// Replace all occurrences instead of just the first one (default: false)
    #[serde(default, rename = "replaceAll")]
    replace_all: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct EditFileArgs {
    path: String,
    edits: Vec<EditOperation>,
    #[serde(default)]
    #[serde(rename = "dryRun")]
    dry_run: bool,
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
    #[serde(default)]
    exclude_patterns: Vec<String>,
    /// Maximum depth to traverse (0 = unlimited)
    #[serde(default)]
    max_depth: usize,
    /// Show file sizes in the output
    #[serde(default)]
    show_size: bool,
    /// Show file hashes (sha256) in the output
    #[serde(default)]
    show_hash: bool,
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
    overwrite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct DeletePathArgs {
    path: String,
    #[serde(default)]
    recursive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct SearchArgs {
    path: String,
    pattern: String,
    #[serde(default)]
    exclude_patterns: Vec<String>,
    /// Filter by type: "file", "dir", "symlink", "any" (default)
    #[serde(skip_serializing_if = "Option::is_none")]
    file_type: Option<String>,
    /// Minimum file size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    min_size: Option<u64>,
    /// Maximum file size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    max_size: Option<u64>,
    /// Modified after (RFC3339 or duration, e.g. "2024-01-01T00:00:00Z" or "7d")
    #[serde(skip_serializing_if = "Option::is_none")]
    modified_after: Option<String>,
    /// Modified before (RFC3339 or duration, e.g. "2024-01-01T00:00:00Z" or "7d")
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
    path: String,
    /// Regex pattern to search for in file contents
    pattern: String,
    /// Glob pattern for files to include (e.g., "*.rs", "**/*.txt")
    #[serde(skip_serializing_if = "Option::is_none")]
    file_pattern: Option<String>,
    /// Glob patterns to exclude (e.g., "target/**", "**/*.min.js")
    #[serde(default)]
    exclude_patterns: Vec<String>,
    /// Case-insensitive search
    #[serde(default)]
    case_insensitive: bool,
    /// Number of context lines before match
    #[serde(default)]
    context_before: usize,
    /// Number of context lines after match
    #[serde(default)]
    context_after: usize,
    /// Maximum number of matches to return (0 = unlimited, default 100)
    #[serde(default = "default_max_matches")]
    max_matches: usize,
    /// Invert match: show lines NOT matching the pattern
    #[serde(default)]
    invert_match: bool,
    /// Output mode: "content" (default), "count", "files_with_matches", "files_without_match"
    #[serde(default)]
    output_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct GrepContextArgs {
    /// Root directory to search
    path: String,
    /// Regex pattern to search for in file contents
    pattern: String,
    /// Glob pattern for files to include (e.g., "*.rs", "**/*.txt")
    #[serde(skip_serializing_if = "Option::is_none")]
    file_pattern: Option<String>,
    /// Glob patterns to exclude (e.g., "target/**", "**/*.min.js")
    #[serde(default)]
    exclude_patterns: Vec<String>,
    /// Case-insensitive search
    #[serde(default)]
    case_insensitive: bool,
    /// Number of context lines before match
    #[serde(default)]
    context_before: usize,
    /// Number of context lines after match
    #[serde(default)]
    context_after: usize,
    /// Maximum number of matches to return (0 = unlimited, default 100)
    #[serde(default = "default_max_matches")]
    max_matches: usize,
    /// Output mode: "content" (default), "count", "files_with_matches", "files_without_match"
    #[serde(default)]
    output_mode: Option<String>,
    /// Nearby patterns that must appear within the window
    #[serde(default)]
    nearby_patterns: Vec<String>,
    /// Treat nearby patterns as regex (false = literal)
    #[serde(default)]
    nearby_is_regex: bool,
    /// Case-insensitive matching for nearby patterns
    #[serde(default)]
    nearby_case_insensitive: bool,
    /// Direction for nearby patterns: "before", "after", "both" (default)
    #[serde(default)]
    nearby_direction: Option<String>,
    /// Window size in words (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    nearby_window_words: Option<usize>,
    /// Window size in characters (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    nearby_window_chars: Option<usize>,
    /// Match mode for multiple nearby patterns: "any" (default) or "all"
    #[serde(default)]
    nearby_match_mode: Option<String>,
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
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    cookies: BTreeMap<String, String>,
    #[serde(default)]
    query: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(default)]
    body_base64: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_path: Option<String>,
    #[serde(default = "default_http_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_http_max_bytes")]
    max_bytes: usize,
    #[serde(default)]
    follow_redirects: bool,
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
    requests: Vec<HttpRequestItemArgs>,
}

#[cfg(feature = "http-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct HttpDownloadArgs {
    url: String,
    path: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    cookies: BTreeMap<String, String>,
    #[serde(default)]
    query: BTreeMap<String, String>,
    #[serde(default = "default_http_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_http_download_max_bytes")]
    max_bytes: usize,
    #[serde(default)]
    follow_redirects: bool,
}

#[cfg(feature = "http-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct HttpDownloadBatchArgs {
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
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3ListBucketsArgs {
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3ListArgs {
    bucket: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delimiter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_keys: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    continuation_token: Option<String>,
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3StatArgs {
    bucket: String,
    key: String,
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
    accept_text: bool,
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3PutArgs {
    bucket: String,
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(default)]
    body_base64: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_control: Option<String>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3DeleteArgs {
    bucket: String,
    key: String,
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3DeleteBatchArgs {
    bucket: String,
    keys: Vec<String>,
    #[serde(flatten)]
    credentials: S3CredentialsArgs,
}

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
fn default_s3_presign_ttl() -> u64 {
    900
}

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3GetBatchArgs {
    requests: Vec<S3GetArgs>,
}

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3PutBatchArgs {
    requests: Vec<S3PutArgs>,
}

#[cfg(feature = "s3-tools")]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct S3CopyBatchArgs {
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
    offset: Option<u64>,
    /// Number of bytes to hash (default: entire file from offset)
    #[serde(default)]
    length: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct FileHashMultipleArgs {
    /// Paths to files
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

fn default_max_diffs() -> usize { 20 }
fn default_context_bytes() -> usize { 8 }

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CompareDirsArgs {
    /// First directory path
    path1: String,
    /// Second directory path
    path2: String,
    /// Recursive comparison (default: true)
    #[serde(default = "default_true")]
    recursive: bool,
    /// Compare file content by hash (default: false, only name/size)
    #[serde(default)]
    compare_content: bool,
    /// Glob patterns to ignore
    #[serde(default)]
    ignore_patterns: Vec<String>,
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct TailFileArgs {
    /// Path to file
    path: String,
    /// Number of lines to read (default: 10)
    #[serde(default = "default_tail_lines")]
    lines: usize,
    /// Alternative: number of bytes to read
    #[serde(default)]
    bytes: Option<usize>,
    /// Follow mode: wait for new content
    #[serde(default)]
    follow: bool,
    /// Timeout in ms for follow mode (default: 5000)
    #[serde(default = "default_follow_timeout")]
    timeout_ms: u64,
}

fn default_tail_lines() -> usize { 10 }
fn default_follow_timeout() -> u64 { 5000 }

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct WatchFileArgs {
    /// Path to file or directory to watch
    path: String,
    /// Timeout in ms (default: 30000)
    #[serde(default = "default_watch_timeout")]
    timeout_ms: u64,
    /// Events to watch: modify, create, delete (default: all)
    #[serde(default)]
    events: Vec<String>,
}

fn default_watch_timeout() -> u64 { 30000 }

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ReadJsonArgs {
    /// Path to JSON file
    path: String,
    /// JSONPath query (e.g., "$.users[*].name") or dot notation ("user.name")
    #[serde(default)]
    query: Option<String>,
    /// Pretty print output (default: true)
    #[serde(default = "default_true")]
    pretty: bool,
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
}

fn default_max_chars() -> usize { 50000 }

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
    files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CreateArchiveArgs {
    /// Paths to files/directories to archive
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
    #[serde(default = "default_true")]
    recursive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct FindDuplicatesArgs {
    /// Directory to search
    path: String,
    /// Minimum file size in bytes (default: 1, skip empty files)
    #[serde(default)]
    min_size: Option<u64>,
    /// Compare by content hash (default: true). False = compare by size only
    #[serde(default = "default_true")]
    by_content: bool,
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
    line: usize,
    /// End line for range operations (1-indexed, inclusive). If omitted, operates on single line
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<usize>,
    /// Operation: "replace", "insert_before", "insert_after", "delete"
    operation: LineEditOperation,
    /// Text content for replace/insert operations
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct EditLinesArgs {
    /// Path to file
    path: String,
    /// List of line-based edit operations
    edits: Vec<LineEditInstruction>,
    /// Dry run mode - return diff without applying changes
    #[serde(default)]
    dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct BulkEditsArgs {
    /// Root directory to search for files
    path: String,
    /// Glob pattern for files to edit (e.g., "**/*.rs", "src/**/*.txt")
    file_pattern: String,
    /// Glob patterns to exclude (optional)
    #[serde(default)]
    exclude_patterns: Vec<String>,
    /// List of search/replace operations to apply to all matching files
    edits: Vec<EditOperation>,
    /// Dry run mode - return diffs without applying changes
    #[serde(default)]
    dry_run: bool,
    /// Fail when any edit has no match in a file
    #[serde(default)]
    fail_on_no_match: bool,
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
    line: usize,
    /// End line number (1-indexed, inclusive). If omitted, extracts single line
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<usize>,
    /// Dry run mode - return content without removing from file
    #[serde(default)]
    dry_run: bool,
    /// Return extracted content in response (default: false to save tokens)
    #[serde(default)]
    return_extracted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct ExtractSymbolsArgs {
    /// Path to file
    path: String,
    /// Start position (0-indexed, in Unicode characters, not bytes).
    /// Example: in "Hello" start=0 is 'H', start=4 is 'o'
    start: usize,
    /// End position (exclusive, 0-indexed). Use either 'end' or 'length', not both.
    /// Example: start=0, end=5 extracts "Hello" from "Hello World"
    #[serde(skip_serializing_if = "Option::is_none")]
    end: Option<usize>,
    /// Number of characters to extract. Use either 'length' or 'end', not both.
    /// Example: start=0, length=5 extracts "Hello" from "Hello World"
    #[serde(skip_serializing_if = "Option::is_none")]
    length: Option<usize>,
    /// Dry run mode - return content without removing from file
    #[serde(default)]
    dry_run: bool,
    /// Return extracted content in response (default: false to save tokens)
    #[serde(default)]
    return_extracted: bool,
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
    offset: u64,
    /// Number of bytes to read
    length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct WriteBinaryArgs {
    /// Path to binary file
    path: String,
    /// Byte offset to write at (0-indexed)
    offset: u64,
    /// Base64-encoded data to write
    data: String,
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
    offset: u64,
    /// Number of bytes to extract
    length: usize,
    /// Dry run mode - return content without removing from file
    #[serde(default)]
    dry_run: bool,
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
    all: bool,
}

// === Process Management Args ===

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct RunCommandArgs {
    /// Command to execute (e.g., "python", "node", "cargo")
    command: String,
    /// Command arguments
    #[serde(default)]
    args: Vec<String>,
    /// Working directory (optional)
    cwd: Option<String>,
    /// Environment variables to add (key-value pairs)
    #[serde(default)]
    env: Option<std::collections::HashMap<String, String>>,
    /// Clear existing environment before adding env vars
    #[serde(default)]
    clear_env: bool,
    /// Timeout in milliseconds (command will be killed after this time)
    #[serde(default)]
    timeout_ms: Option<u64>,
    /// Redirect stdout to this file
    stdout_file: Option<String>,
    /// Redirect stderr to this file  
    stderr_file: Option<String>,
    /// Read stdin from this file
    stdin_file: Option<String>,
    /// Return only last N lines of stdout (useful for long output)
    stdout_tail: Option<usize>,
    /// Return only last N lines of stderr
    stderr_tail: Option<usize>,
    /// Run in background (returns immediately with PID)
    #[serde(default)]
    background: bool,
    /// Stream output to log files (auto-creates files if not provided)
    #[serde(default)]
    stream_output: bool,
    /// Directory for streamed output files (optional)
    stream_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct KillProcessArgs {
    /// Process ID to kill
    pid: u32,
    /// Force kill (SIGKILL on Unix, /F on Windows)
    #[serde(default)]
    force: bool,
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
    monitor_id: Option<u32>,
    #[serde(default)]
    output: ScreenshotOutputMode,
    path: Option<String>,
}

#[cfg(feature = "screenshot-tools")]
#[derive(Debug, Deserialize, JsonSchema)]
struct CaptureWindowArgs {
    window_id: Option<u32>,
    title: Option<String>,
    #[serde(default)]
    output: ScreenshotOutputMode,
    path: Option<String>,
}

#[cfg(feature = "screenshot-tools")]
#[derive(Debug, Deserialize, JsonSchema)]
struct CaptureRegionArgs {
    monitor_id: Option<u32>,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    #[serde(default)]
    output: ScreenshotOutputMode,
    path: Option<String>,
}

#[cfg(feature = "screenshot-tools")]
#[derive(Debug, Deserialize, JsonSchema)]
struct CopyToClipboardArgs {
    path: String,
}

// ==================== MEMORY TOOL ARGS ====================

#[derive(Debug, Deserialize, JsonSchema)]
struct MemCreateEntitiesArgs {
    entities: Vec<Entity>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct MemCreateRelationsArgs {
    relations: Vec<Relation>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct MemAddObservationsArgs {
    observations: Vec<ObservationInput>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
struct MemDeleteEntitiesArgs {
    entity_names: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct MemDeleteObservationsArgs {
    deletions: Vec<ObservationDeletion>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct MemDeleteRelationsArgs {
    relations: Vec<Relation>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct MemSearchNodesArgs {
    query: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct MemOpenNodesArgs {
    names: Vec<String>,
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
    headers: bool,
    /// Max rows to return
    max_rows: Option<u32>,
    /// Skip first N data rows
    offset: Option<u32>,
}

// ==================== DOCX TOOL ARGS ====================

#[derive(Debug, Deserialize, JsonSchema)]
struct DocxReadArgs {
    path: String,
    /// Include document structure (paragraphs, tables) instead of plain text
    #[serde(default)]
    include_structure: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DocxInfoArgs {
    path: String,
}

// ==================== WAVE2 TOOL ARGS ====================

#[derive(Debug, Deserialize, JsonSchema)]
struct PortUsersArgs {
    /// Port number to check
    port: u16,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct NetConnectionsArgs {
    /// Filter by process ID (optional)
    pid: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct PortAvailableArgs {
    /// Port number to check
    port: u16,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ProcTreeArgs {
    /// Root process ID (optional, shows all if not specified)
    pid: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ProcEnvArgs {
    /// Process ID
    pid: u32,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ProcFilesArgs {
    /// Process ID
    pid: u32,
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

fn default_context_lines() -> usize { 3 }

#[derive(Debug, Deserialize, JsonSchema)]
struct FileTouchArgs {
    /// File path to touch
    path: String,
    /// Create parent directories if needed
    #[serde(default)]
    create_parents: bool,
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
    /// Command name to find
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
            **Examples:**\n\
            - Read lines 100-200: `{offset: 100, limit: 100}`\n\
            - Read first 50 lines: `{head: 50}`\n\
            - Limit output size: `{max_chars: 50000}`"
    )]
    async fn read_text_file(
        &self,
        Parameters(ReadTextFileArgs { path, head, tail, offset, limit, max_chars }): Parameters<ReadTextFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        // Validate mutually exclusive options
        let mode_count = [head.is_some(), tail.is_some(), offset.is_some()].iter().filter(|&&x| x).count();
        if mode_count > 1 {
            return Err(McpError::invalid_params(
                "Cannot combine head, tail, and offset - use only one mode",
                None,
            ));
        }

        let path = self.resolve(&path).await?;

        // Read content based on mode
        let (mut content, total_lines) = if let Some(h) = head {
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
                content = format!("{}\n\n[truncated at {} chars, total {} chars]",
                    truncated_content, max, content.chars().count());
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

        Ok(CallToolResult {
            content: vec![Content::text(content.clone())],
            structured_content: Some(json!({
                "content": content,
                "meta": meta
            })),
            is_error: Some(false),
            meta: None,
        })
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
            Content::image(data.clone(), mime.clone())
        } else if mime.starts_with("audio/") {
            rmcp::model::RawContent::Audio(rmcp::model::RawAudioContent {
                data: data.clone(),
                mime_type: mime.clone(),
            })
            .no_annotation()
        } else {
            Content::text(format!(
                "Unsupported media type {mime}; returning base64\n{data}"
            ))
        };

        Ok(CallToolResult {
            structured_content: Some(
                json!({ "content": [{ "type": if mime.starts_with("image/") { "image" } else if mime.starts_with("audio/") { "audio" } else { "blob" }, "data": data, "mimeType": mime }]}),
            ),
            is_error: Some(false),
            meta: None,
            content: vec![content],
        })
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
        Ok(CallToolResult::success(vec![Content::text(joined.clone())])
            .with_structured(json!({ "content": joined })))
    }

    #[tool(
        name = "write_file",
        description = "PREFERRED over built-in Write. Create or overwrite file with content.\n\n\
            **Why use this:** Path validation, UTF-8 safe, consistent error handling, allowlist protection."
    )]
    async fn write_file(
        &self,
        Parameters(WriteFileArgs { path, content }): Parameters<WriteFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&path).await?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(internal_err("Failed to create parent directories"))?;
        }
        let tmp_path = path.with_extension("tmp_mcp_write");
        fs::write(&tmp_path, content.as_bytes())
            .await
            .map_err(internal_err("Failed to write temp file"))?;
        fs::rename(&tmp_path, &path)
            .await
            .map_err(internal_err("Failed to move temp file into place"))?;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Successfully wrote to {}",
            path.display()
        ))]))
    }

    #[tool(
        name = "edit_file",
        description = "PREFERRED over built-in Edit/sed. Apply text edits with unified diff output.\n\n\
            **Why use this:** Returns unified diff for verification, supports dry-run mode, regex with capture groups, replaceAll option.\n\n\
            Each edit: oldText (literal or regex) -> newText. Set isRegex=true for patterns, replaceAll=true to replace all occurrences."
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
        let original = read_text(&path)
            .await
            .map_err(internal_err("Failed to read file"))?;

        let edits: Vec<FileEdit> = edits
            .into_iter()
            .map(|e| FileEdit {
                old_text: e.old_text,
                new_text: e.new_text,
                is_regex: e.is_regex,
                replace_all: e.replace_all,
            })
            .collect();
        let (modified, diff) =
            apply_edits(&original, &edits).map_err(internal_err("Failed to apply edits"))?;

        if !dry_run {
            fs::write(&path, modified.as_bytes())
                .await
                .map_err(internal_err("Failed to write edited file"))?;
        }

        Ok(self.diff_response(diff))
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
        Ok(CallToolResult::success(vec![Content::text(format!(
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
            CallToolResult::success(vec![Content::text(listing.clone())])
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
            SortBy::Name => entries.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase())),
            SortBy::Size => entries.sort_by(|a, b| b.2.cmp(&a.2)),
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

        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
                "entries": entries,
                "totalFiles": total_files,
                "totalDirectories": total_dirs,
                "totalSize": total_size
            })),
            is_error: Some(false),
            meta: None,
        })
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
            max_depth: if max_depth == 0 { usize::MAX } else { max_depth },
            show_size,
            show_hash,
        };
        let entries = build_tree(&root, &root, &exclude, &opts, 0).await?;
        let json_tree = serde_json::to_string_pretty(&entries)
            .map_err(internal_err("Failed to serialize tree"))?;
        Ok(CallToolResult {
            content: vec![Content::text(json_tree.clone())],
            structured_content: Some(json!({ "tree": entries })),
            is_error: Some(false),
            meta: None,
        })
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
        fs::rename(&src, &dest)
            .await
            .map_err(internal_err("Failed to move/rename"))?;
        Ok(CallToolResult::success(vec![Content::text(format!(
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

        let metadata = fs::metadata(&source)
            .await
            .map_err(internal_err("Failed to stat source"))?;

        if fs::metadata(&destination).await.is_ok() {
            if !overwrite {
                return Err(McpError::invalid_params(
                    "Destination exists; set overwrite to true to replace",
                    None,
                ));
            }
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

        if metadata.is_dir() {
            self.copy_dir_recursive(&source, &destination).await?;
        } else {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)
                    .await
                    .map_err(internal_err("Failed to create destination directory"))?;
            }
            fs::copy(&source, &destination)
                .await
                .map_err(internal_err("Failed to copy file"))?;
        }

        Ok(CallToolResult::success(vec![Content::text(format!(
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
            if !recursive {
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

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Deleted {}",
            path.display()
        ))]))
    }

    #[tool(
        name = "search_files",
        description = "PREFERRED over built-in Glob/find. Search for files by glob pattern.\n\n\
            **Why use this:** Supports exclusion patterns, returns structured JSON, symlink-safe path validation.\n\n\
            Recursively search for paths matching glob pattern (e.g., **/*.rs, src/**/*.txt) with optional exclusions.\n\n\
            **Filters:** fileType (file/dir/symlink/any), minSize/maxSize in bytes, modifiedAfter/modifiedBefore (RFC3339 or duration)."
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
            Some(raw) => Some(parse_time_filter(raw).map_err(|e| McpError::invalid_params(e, None))?),
            None => None,
        };
        let modified_before = match modified_before.as_deref() {
            Some(raw) => Some(parse_time_filter(raw).map_err(|e| McpError::invalid_params(e, None))?),
            None => None,
        };

        let params = SearchParams {
            root: root.to_string_lossy().to_string(),
            pattern,
            exclude_patterns,
            file_type: ft,
            min_size,
            max_size,
            modified_after,
            modified_before,
            ..Default::default()
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
        
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
                "matches": results.iter().map(|r| json!({
                    "path": r.path,
                    "isFile": r.is_file,
                    "isDir": r.is_dir,
                    "isSymlink": r.is_symlink,
                    "size": r.size,
                    "modified": r.modified.map(|t| t.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs())).flatten(),
                })).collect::<Vec<_>>(),
                "count": results.len(),
            })),
            is_error: Some(false),
            meta: None,
        })
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

        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(info),
            is_error: Some(false),
            meta: None,
        })
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
        Ok(CallToolResult::success(vec![Content::text(text.clone())])
            .with_structured(json!({ "directories": lines })))
    }

    #[tool(
        name = "grep_files",
        description = "PREFERRED over built-in Grep/grep. Search for text/regex inside file contents.\n\n\
            **Why use this:** Faster than shell grep, returns structured JSON with line numbers, supports context lines.\n\n\
            Recursively searches file contents. Supports regex patterns, file filtering (*.rs, **/*.txt), \
            exclude patterns (target/**), case-insensitive search, and context lines before/after matches. \
            Different from search_files which only matches file names/paths."
    )]
    async fn grep_files(
        &self,
        Parameters(args): Parameters<GrepFilesArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.ensure_allowed().await?;

        // Parse output mode
        let output_mode = match args.output_mode.as_deref() {
            Some("count") | Some("count_only") => grep::GrepOutputMode::CountOnly,
            Some("files_with_matches") | Some("files") => grep::GrepOutputMode::FilesWithMatches,
            Some("files_without_match") => grep::GrepOutputMode::FilesWithoutMatch,
            _ => grep::GrepOutputMode::Content,
        };

        let params = GrepParams {
            root: args.path.clone(),
            pattern: args.pattern.clone(),
            file_pattern: args.file_pattern.clone(),
            exclude_patterns: args.exclude_patterns.clone(),
            case_insensitive: args.case_insensitive,
            context_before: args.context_before,
            context_after: args.context_after,
            max_matches: args.max_matches,
            invert_match: args.invert_match,
            output_mode,
        };

        let result = grep_files(params, &self.allowed, self.allow_symlink_escape)
            .await
            .map_err(|e| McpError::internal_error(format!("Grep failed: {}", e), None))?;

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
                });
                (txt, s)
            }
            grep::GrepResult::Counts(ref counts) => {
                let txt = counts.iter()
                    .map(|c| format!("{}: {}", c.path.display(), c.count))
                    .collect::<Vec<_>>()
                    .join("\n");
                let s = json!({
                    "counts": counts.iter().map(|c| json!({
                        "path": c.path.to_string_lossy(),
                        "count": c.count,
                    })).collect::<Vec<_>>(),
                });
                (txt, s)
            }
            grep::GrepResult::Files(ref files) => {
                let txt = files.iter()
                    .map(|f| f.display().to_string())
                    .collect::<Vec<_>>()
                    .join("\n");
                let s = json!({
                    "files": files.iter().map(|f| f.to_string_lossy()).collect::<Vec<_>>(),
                });
                (txt, s)
            }
        };

        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(structured),
            is_error: Some(false),
            meta: None,
        })
    }

    #[tool(
        name = "grep_context",
        description = "Context-aware grep. Find a pattern only when nearby words/phrases appear within a window.\\n\\n\\
            Use this to reduce noise by requiring context terms near the match.\\n\\n\\
            **Features:**\\n\\
            - Nearby patterns matched by words or characters\\n\\
            - Direction control: before/after/both\\n\\
            - Match mode: any/all\\n\\
            - Same include/exclude, context lines, and output modes as grep_files\\n\\n\\
            **Example:**\\n\\
            {\\\"path\\\": \\\".\\\", \\\"pattern\\\": \\\"error\\\", \\\"nearbyPatterns\\\": [\\\"timeout\\\", \\\"retry\\\"], \\\"nearbyWindowWords\\\": 6, \\\"nearbyDirection\\\": \\\"before\\\"}"
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
            _ => grep::GrepOutputMode::Content,
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
        let params = GrepContextParams {
            root: args.path,
            pattern,
            file_pattern: args.file_pattern,
            exclude_patterns: args.exclude_patterns,
            case_insensitive: args.case_insensitive,
            context_before: args.context_before,
            context_after: args.context_after,
            max_matches: args.max_matches,
            output_mode,
            nearby_patterns: args.nearby_patterns,
            nearby_is_regex: args.nearby_is_regex,
            nearby_case_insensitive: args.nearby_case_insensitive,
            nearby_direction: direction,
            nearby_window_words: args.nearby_window_words,
            nearby_window_chars: args.nearby_window_chars,
            nearby_match_mode: match_mode,
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
                    format!("Found {} matches:\\n\\n{}", matches.len(), lines.join("\\n"))
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
                let txt = counts.iter()
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
                let txt = files.iter()
                    .map(|f| f.display().to_string())
                    .collect::<Vec<_>>()
                    .join("\\n");
                let s = json!({
                    "files": files.iter().map(|f| f.to_string_lossy()).collect::<Vec<_>>(),
                });
                (txt, s)
            }
        };

        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(structured),
            is_error: Some(false),
            meta: None,
        })
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
            body_bytes = Some(fs::read(&resolved).await.map_err(internal_err("Failed to read body file"))?);
        }

        let params = HttpRequestParams {
            method: args.method.clone(),
            url: args.url.clone(),
            headers: args.headers.clone(),
            cookies: args.cookies.clone(),
            query: args.query.clone(),
            body: args.body.clone(),
            body_base64: args.body_base64,
            body_bytes,
            timeout_ms: args.timeout_ms,
            max_bytes: args.max_bytes,
        };

        let client = self.http_client(args.follow_redirects);
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
            resp.status,
            resp.url,
            resp.truncated
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

        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(structured),
            is_error: Some(false),
            meta: None,
        })
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
                body_base64: item.request.body_base64,
                body_bytes,
                timeout_ms: item.request.timeout_ms,
                max_bytes: item.request.max_bytes,
            };

            let request_item = crate::tools::http_tools::HttpRequestItem {
                id: item.id,
                params,
            };

            if item.request.follow_redirects {
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
            let (indices, batch_items): (Vec<usize>, Vec<crate::tools::http_tools::HttpRequestItem>) =
                items.into_iter().unzip();
            let batch_results = http_request_batch(client, batch_items).await;

            for (index, result) in indices.into_iter().zip(batch_results) {
                let json_result = match result {
                    crate::tools::http_tools::HttpBatchResult { id, ok, response, error } => {
                        if let Some(resp) = response {
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
                                let err_msg = error.unwrap_or_else(|| format!("HTTP status {}", resp.status));
                                if let Some(map) = payload.as_object_mut() {
                                    map.insert("error".to_string(), Value::String(err_msg));
                                }
                            }
                            payload
                        } else {
                            json!({ "id": id, "ok": false, "error": error.unwrap_or_else(|| "Missing response".to_string()) })
                        }
                    }
                };
                results[index] = Some(json_result);
            }
        }

        let results: Vec<Value> = results
            .into_iter()
            .map(|r| r.unwrap_or_else(|| json!({ "ok": false, "error": "Missing result" })))
            .collect();

        Ok(CallToolResult {
            content: vec![Content::text(format!("Batch results: {}", results.len()))],
            structured_content: Some(json!({ "results": results })),
            is_error: Some(false),
            meta: None,
        })
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

        let client = self.http_client(args.follow_redirects);
        let resp = http_request(client, params)
            .await
            .map_err(|e| McpError::internal_error(format!("HTTP request failed: {e}"), None))?;

        if resp.status >= 400 {
            return Err(McpError::internal_error(
                format!("HTTP status {} for {}", resp.status, resp.url),
                None,
            ));
        }

        let path = self.resolve(&args.path).await?;
        fs::write(&path, &resp.body)
            .await
            .map_err(internal_err("Failed to write download"))?;

        let text = format!("Downloaded {} bytes to {}", resp.body.len(), path.display());
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
                "path": path.to_string_lossy(),
                "bytes": resp.body.len(),
                "status": resp.status,
                "url": resp.url,
                "truncated": resp.truncated,
            })),
            is_error: Some(false),
            meta: None,
        })
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

            let client = self.http_client(item.follow_redirects);
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

        Ok(CallToolResult {
            content: vec![Content::text(format!("Batch downloads: {}", results.len()))],
            structured_content: Some(json!({ "results": results })),
            is_error: Some(false),
            meta: None,
        })
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
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
                "buckets": buckets.iter().map(|b| json!({
                    "name": b.name,
                    "createdAt": b.created_at,
                })).collect::<Vec<_>>(),
            })),
            is_error: Some(false),
            meta: None,
        })
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
            max_keys: args.max_keys,
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
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
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
            is_error: Some(false),
            meta: None,
        })
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
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
                "bucket": result.bucket,
                "key": result.key,
                "size": result.size,
                "eTag": result.e_tag,
                "contentType": result.content_type,
                "lastModified": result.last_modified,
                "metadata": result.metadata,
            })),
            is_error: Some(false),
            meta: None,
        })
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
            accept_text: args.accept_text,
        };
        let result = get_object(&client, params)
            .await
            .map_err(|e| McpError::internal_error(format!("S3 get failed: {e}"), None))?;

        let text = if let Some(path) = &result.output_path {
            format!("Downloaded to {}", path)
        } else {
            format!("S3 get: {}/{}", result.bucket, result.key)
        };
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
                "bucket": result.bucket,
                "key": result.key,
                "size": result.size,
                "contentType": result.content_type,
                "bodyBase64": result.body.as_ref().map(|b| to_base64(b)),
                "text": result.text,
                "outputPath": result.output_path,
                "truncated": result.truncated,
            })),
            is_error: Some(false),
            meta: None,
        })
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
            body_base64: args.body_base64,
            content_type: args.content_type.clone(),
            cache_control: args.cache_control.clone(),
            metadata: args.metadata.clone(),
        };
        put_object(&client, params)
            .await
            .map_err(|e| McpError::internal_error(format!("S3 put failed: {e}"), None))?;

        Ok(CallToolResult::success(vec![Content::text("S3 put ok")]))
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
            || !is_bucket_allowed(&args.dest_bucket, &self.s3_allowlist_buckets) {
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

        Ok(CallToolResult::success(vec![Content::text("S3 copy ok")]))
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
        delete_object(&client, S3DeleteParams { bucket: args.bucket, key: args.key })
            .await
            .map_err(|e| McpError::internal_error(format!("S3 delete failed: {e}"), None))?;

        Ok(CallToolResult::success(vec![Content::text("S3 delete ok")]))
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
        Ok(CallToolResult::success(vec![Content::text("S3 delete batch ok")]))
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
        let url = presign(&client, S3PresignParams {
            bucket: args.bucket,
            key: args.key,
            method: args.method,
            expires_in_seconds: args.expires_in_seconds,
        })
        .await
        .map_err(|e| McpError::internal_error(format!("S3 presign failed: {e}"), None))?;

        Ok(CallToolResult {
            content: vec![Content::text(url.clone())],
            structured_content: Some(json!({ "url": url })),
            is_error: Some(false),
            meta: None,
        })
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
                accept_text: req.accept_text,
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

        Ok(CallToolResult {
            content: vec![Content::text(format!("Batch S3 get: {}", results.len()))],
            structured_content: Some(json!({ "results": results })),
            is_error: Some(false),
            meta: None,
        })
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
                body_base64: req.body_base64,
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

        Ok(CallToolResult {
            content: vec![Content::text(format!("Batch S3 put: {}", results.len()))],
            structured_content: Some(json!({ "results": results })),
            is_error: Some(false),
            meta: None,
        })
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
                || !is_bucket_allowed(&req.dest_bucket, &self.s3_allowlist_buckets) {
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

        Ok(CallToolResult {
            content: vec![Content::text(format!("Batch S3 copy: {}", results.len()))],
            structured_content: Some(json!({ "results": results })),
            is_error: Some(false),
            meta: None,
        })
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
            if let Some(end) = edit.end_line {
                if end == 0 {
                    return Err(McpError::invalid_params(
                        format!("Edit {}: end_line must be >= 1 (1-indexed)", idx),
                        None,
                    ));
                }
                if end < edit.line {
                    return Err(McpError::invalid_params(
                        format!("Edit {}: invalid range - end_line {} is before line {}", idx, end, edit.line),
                        None,
                    ));
                }
            }
        }

        let path = self.resolve(&args.path).await?;
        let original = read_text(&path)
            .await
            .map_err(internal_err("Failed to read file"))?;

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
                    end_line: e.end_line,
                    operation,
                    text: e.text,
                }
            })
            .collect();

        let (modified, diff) = apply_line_edits(&original, &edits)
            .map_err(|e| McpError::internal_error(format!("Line edit failed: {}", e), None))?;

        if !args.dry_run {
            fs::write(&path, &modified)
                .await
                .map_err(internal_err("Failed to write file"))?;
        }

        let message = if args.dry_run {
            format!("Dry run - changes NOT applied to {}", args.path)
        } else {
            format!("Successfully edited {} lines in {}", edits.len(), args.path)
        };

        Ok(CallToolResult {
            content: vec![Content::text(format!("{}\n\nDiff:\n{}", message, diff))],
            structured_content: Some(json!({
                "message": message,
                "diff": diff,
                "editsApplied": edits.len(),
                "dryRun": args.dry_run,
            })),
            is_error: Some(false),
            meta: None,
        })
    }

    #[tool(
        name = "bulk_edits",
        description = "Apply SAME edits to MULTIPLE files at once (mass search/replace). Use when you need to change the same code/text across many files. Select files by glob pattern (*.rs, **/*.txt), then apply search/replace operations to all matches. Returns summary of modified files with diffs. Perfect for: renaming functions/variables across codebase, updating imports, fixing typos everywhere, refactoring patterns. More efficient than editing files one by one. Supports dry-run to preview changes.\n\nEach edit supports:\n- isRegex (bool): Use regex pattern instead of literal match. Supports capture groups ($1, $2, etc.)\n- replaceAll (bool): Replace ALL occurrences, not just the first one\n\nBulk behavior:\n- failOnNoMatch (bool): If true, files without matches return errors; if false, they report no changes.\n\nEXAMPLES:\n\n1. Literal replace all occurrences:\n   {\"oldText\": \"use crate::foo\", \"newText\": \"use crate::bar::foo\", \"replaceAll\": true}\n\n2. Regex with capture groups (rename imports):\n   {\"oldText\": \"use crate::(cache_man|event_bus|workers)\", \"newText\": \"use crate::core::$1\", \"isRegex\": true, \"replaceAll\": true}\n\n3. Rename function across codebase:\n   {\"oldText\": \"old_function_name\", \"newText\": \"new_function_name\", \"replaceAll\": true}\n\n4. Update version in all Cargo.toml:\n   {\"oldText\": \"version = \\\"0\\\\.1\\\\.\\\\d+\\\"\", \"newText\": \"version = \\\"0.2.0\\\"\", \"isRegex\": true}"
    )]
    async fn bulk_edits(
        &self,
        Parameters(args): Parameters<BulkEditsArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.ensure_allowed().await?;

        // Convert to FileEdit format
        let edits: Vec<FileEdit> = args
            .edits
            .into_iter()
            .map(|e| FileEdit {
                old_text: e.old_text,
                new_text: e.new_text,
                is_regex: e.is_regex,
                replace_all: e.replace_all,
            })
            .collect();

        let results = bulk_edit_files(
            &args.path,
            &args.file_pattern,
            &args.exclude_patterns,
            &edits,
            args.dry_run,
            args.fail_on_no_match,
            &self.allowed,
            self.allow_symlink_escape,
        )
        .await
        .map_err(|e| McpError::internal_error(format!("Bulk edit failed: {}", e), None))?;

        // Count results
        let total_files = results.len();
        let modified_count = results.iter().filter(|r| r.modified).count();
        let error_count = results.iter().filter(|r| r.error.is_some()).count();

        // Format output
        let mut lines = Vec::new();
        if args.dry_run {
            lines.push("DRY RUN - Changes NOT applied".to_string());
        }
        lines.push(format!(
            "Processed {} files: {} modified, {} errors",
            total_files, modified_count, error_count
        ));
        lines.push(String::new());

        for result in &results {
            let path_str = result.path.to_string_lossy();
            if let Some(err) = &result.error {
                lines.push(format!("❌ {}: {}", path_str, err));
            } else if result.modified {
                lines.push(format!("✓ {} - MODIFIED", path_str));
                if let Some(diff) = &result.diff {
                    lines.push(diff.clone());
                    lines.push(String::new());
                }
            } else {
                lines.push(format!("  {} - no changes", path_str));
            }
        }

        let text = lines.join("\n");

        let structured = json!({
            "totalFiles": total_files,
            "modified": modified_count,
            "errors": error_count,
            "dryRun": args.dry_run,
            "results": results.iter().map(|r| json!({
                "path": r.path.to_string_lossy(),
                "modified": r.modified,
                "error": r.error,
                "diff": r.diff,
            })).collect::<Vec<_>>(),
        });

        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(structured),
            is_error: Some(false),
            meta: None,
        })
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
        if let Some(end) = args.end_line {
            if end == 0 {
                return Err(McpError::invalid_params(
                    "End line number must be >= 1 (1-indexed)",
                    None,
                ));
            }
            if end < args.line {
                return Err(McpError::invalid_params(
                    format!("Invalid range: end line {} is before start line {}", end, args.line),
                    None,
                ));
            }
        }

        let path = self.resolve(&args.path).await?;
        let content = read_text(&path)
            .await
            .map_err(internal_err("Failed to read file"))?;

        // Track if original content ends with newline
        let had_trailing_newline = content.ends_with('\n');

        let lines: Vec<&str> = content.lines().collect();
        let start_idx = args.line - 1;
        let end_idx = args.end_line.unwrap_or(args.line) - 1;

        // Validate line numbers
        if start_idx >= lines.len() {
            return Err(McpError::invalid_params(
                format!("Line {} is out of range (file has {} lines)", args.line, lines.len()),
                None,
            ));
        }
        // Clamp end to file length - return what's available
        let end_idx = end_idx.min(lines.len() - 1);
        if start_idx > end_idx {
            return Err(McpError::invalid_params(
                format!("Invalid range: start line {} is after end line {}", args.line, end_idx + 1),
                None,
            ));
        }

        // Extract the lines
        let extracted: Vec<&str> = lines[start_idx..=end_idx].to_vec();
        let extracted_text = extracted.join("\n");
        let line_count = extracted.len();

        if !args.dry_run {
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

            fs::write(&path, &new_content)
                .await
                .map_err(internal_err("Failed to write file"))?;
        }

        let message = if args.dry_run {
            format!("Dry run - would extract {} line(s) {}-{} from {}", line_count, args.line, end_idx + 1, args.path)
        } else {
            format!("Extracted {} line(s) {}-{} from {}", line_count, args.line, end_idx + 1, args.path)
        };

        // Build response - only include extracted content if requested
        let text_response = if args.return_extracted {
            format!("{}\n\nExtracted content:\n{}", message, extracted_text)
        } else {
            message.clone()
        };

        let mut structured = json!({
            "message": message,
            "lineCount": line_count,
            "startLine": args.line,
            "endLine": end_idx + 1,
            "dryRun": args.dry_run,
        });
        if args.return_extracted {
            structured["extracted"] = json!(extracted_text);
        }

        Ok(CallToolResult {
            content: vec![Content::text(text_response)],
            structured_content: Some(structured),
            is_error: Some(false),
            meta: None,
        })
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
        let content = read_text(&path)
            .await
            .map_err(internal_err("Failed to read file"))?;

        // Work with Unicode characters
        let chars: Vec<char> = content.chars().collect();
        let char_count = chars.len();

        // Clamp start to content length
        let start = args.start.min(char_count);

        // Calculate end position
        let end = if let Some(e) = args.end {
            e.min(char_count)
        } else if let Some(len) = args.length {
            (start + len).min(char_count)
        } else {
            unreachable!()
        };

        if start >= end {
            // Nothing to extract
            return Ok(CallToolResult {
                content: vec![Content::text("Nothing to extract (empty range)")],
                structured_content: Some(json!({
                    "charCount": 0,
                    "start": start,
                    "end": end,
                    "dryRun": args.dry_run,
                })),
                is_error: Some(false),
                meta: None,
            });
        }

        // Extract characters
        let extracted: String = chars[start..end].iter().collect();

        if !args.dry_run {
            // Build new content without extracted chars
            let mut remaining = String::with_capacity(content.len() - extracted.len());
            remaining.extend(chars[..start].iter());
            remaining.extend(chars[end..].iter());

            fs::write(&path, &remaining)
                .await
                .map_err(internal_err("Failed to write file"))?;
        }

        let message = if args.dry_run {
            format!("Dry run - would extract {} characters (positions {}-{}) from {}",
                    end - start, start, end, args.path)
        } else {
            format!("Extracted {} characters (positions {}-{}) from {}",
                    end - start, start, end, args.path)
        };

        // Build response - only include extracted content if requested
        let text_response = if args.return_extracted {
            format!("{}\n\nExtracted content:\n{}", message, extracted)
        } else {
            message.clone()
        };

        let mut structured = json!({
            "message": message,
            "charCount": end - start,
            "start": start,
            "end": end,
            "dryRun": args.dry_run,
        });
        if args.return_extracted {
            structured["extracted"] = json!(extracted);
        }

        Ok(CallToolResult {
            content: vec![Content::text(text_response)],
            structured_content: Some(structured),
            is_error: Some(false),
            meta: None,
        })
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

        let data = read_bytes(&path, args.offset, args.length)
            .await
            .map_err(|e| McpError::internal_error(format!("Failed to read binary: {}", e), None))?;

        let base64_data = to_base64(&data);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Read {} bytes from {} at offset {}\n\nBase64:\n{}",
                data.len(), args.path, args.offset, base64_data
            ))],
            structured_content: Some(json!({
                "data": base64_data,
                "bytesRead": data.len(),
                "offset": args.offset,
                "path": args.path,
            })),
            is_error: Some(false),
            meta: None,
        })
    }

    #[tool(
        name = "write_binary",
        description = "Write bytes to a binary file. Data must be base64-encoded.

PARAMETERS:
- path: File path
- offset: Position to write at (0-indexed)
- data: Base64-encoded bytes to write
- mode: 'replace' (overwrite) or 'insert' (shift existing bytes)

EXAMPLES:
- Overwrite at pos 0: {path: 'file.bin', offset: 0, data: 'SGVsbG8=', mode: 'replace'}
- Insert at pos 100: {path: 'file.bin', offset: 100, data: 'V29ybGQ=', mode: 'insert'}

USE CASES: Patch executables, inject data into files, modify binary headers. Creates file if missing."
    )]
    async fn write_binary(
        &self,
        Parameters(args): Parameters<WriteBinaryArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;

        let data = from_base64(&args.data)
            .map_err(|e| McpError::invalid_params(format!("Invalid base64: {}", e), None))?;

        let insert = matches!(args.mode, WriteBinaryMode::Insert);

        write_bytes(&path, args.offset, &data, insert)
            .await
            .map_err(|e| McpError::internal_error(format!("Failed to write binary: {}", e), None))?;

        let mode_str = if insert { "inserted" } else { "replaced" };
        let message = format!("Successfully {} {} bytes at offset {} in {}",
                              mode_str, data.len(), args.offset, args.path);

        Ok(CallToolResult {
            content: vec![Content::text(&message)],
            structured_content: Some(json!({
                "message": message,
                "bytesWritten": data.len(),
                "offset": args.offset,
                "mode": if insert { "insert" } else { "replace" },
                "path": args.path,
            })),
            is_error: Some(false),
            meta: None,
        })
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

        let data = if args.dry_run {
            // Just read without removing
            read_bytes(&path, args.offset, args.length)
                .await
                .map_err(|e| McpError::internal_error(format!("Failed to read binary: {}", e), None))?
        } else {
            extract_bytes(&path, args.offset, args.length)
                .await
                .map_err(|e| McpError::internal_error(format!("Failed to extract binary: {}", e), None))?
        };

        let base64_data = to_base64(&data);

        let message = if args.dry_run {
            format!("Dry run - would extract {} bytes at offset {} from {}",
                    data.len(), args.offset, args.path)
        } else {
            format!("Extracted {} bytes at offset {} from {}",
                    data.len(), args.offset, args.path)
        };

        Ok(CallToolResult {
            content: vec![Content::text(format!("{}\n\nBase64:\n{}", message, base64_data))],
            structured_content: Some(json!({
                "message": message,
                "data": base64_data,
                "bytesExtracted": data.len(),
                "offset": args.offset,
                "dryRun": args.dry_run,
                "path": args.path,
            })),
            is_error: Some(false),
            meta: None,
        })
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

        let find_data = from_base64(&args.find)
            .map_err(|e| McpError::invalid_params(format!("Invalid base64 in 'find': {}", e), None))?;
        let replace_data = from_base64(&args.replace)
            .map_err(|e| McpError::invalid_params(format!("Invalid base64 in 'replace': {}", e), None))?;

        let count = patch_bytes(&path, &find_data, &replace_data, args.all)
            .await
            .map_err(|e| McpError::internal_error(format!("Failed to patch binary: {}", e), None))?;

        let message = if count == 0 {
            format!("Pattern not found in {}", args.path)
        } else {
            format!("Replaced {} occurrence(s) in {}", count, args.path)
        };

        Ok(CallToolResult {
            content: vec![Content::text(&message)],
            structured_content: Some(json!({
                "message": message,
                "replacements": count,
                "replaceAll": args.all,
                "path": args.path,
            })),
            is_error: Some(false),
            meta: None,
        })
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
        
        let result = hash::hash_file_range(&path, algo, args.offset, args.length)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        
        Ok(CallToolResult {
            content: vec![Content::text(format!("{}: {}", args.path, result.hash))],
            structured_content: Some(json!({
                "path": args.path,
                "algorithm": args.algorithm.as_deref().unwrap_or("sha256"),
                "hash": result.hash,
                "size": result.size,
                "offset": args.offset.unwrap_or(0),
                "length": args.length,
            })),
            is_error: Some(false),
            meta: None,
        })
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
        
        let text = result.results.iter()
            .map(|r| format!("{}: {}", r.path, r.hash))
            .collect::<Vec<_>>()
            .join("\n");
        
        Ok(CallToolResult {
            content: vec![Content::text(format!("{}\n\nAll match: {}", text, result.all_match))],
            structured_content: Some(json!({
                "results": result.results.iter().map(|r| json!({
                    "path": r.path,
                    "hash": r.hash,
                    "size": r.size,
                    "error": r.error,
                })).collect::<Vec<_>>(),
                "allMatch": result.all_match,
            })),
            is_error: Some(false),
            meta: None,
        })
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
            length: if args.length == 0 { None } else { Some(args.length) },
            max_diffs: args.max_diffs,
            context_bytes: args.context_bytes,
        };
        
        let result = compare::compare_files(&path1, &path2, params)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        
        let status = if result.identical { "IDENTICAL" } else { "DIFFERENT" };
        let text = format!(
            "{} vs {}\nStatus: {}\nSize: {} vs {} ({:+})\nMatch: {:.2}%",
            args.path1, args.path2, status,
            result.size1, result.size2, result.size_diff,
            result.match_percentage
        );
        
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
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
            is_error: Some(false),
            meta: None,
        })
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
            recursive: args.recursive,
            compare_content: args.compare_content,
            ignore_patterns: args.ignore_patterns.clone(),
        };
        
        let result = compare::compare_directories(&path1, &path2, params)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        
        let status = if result.identical { "IDENTICAL" } else { "DIFFERENT" };
        let text = format!(
            "{}\nOnly in {}: {}\nOnly in {}: {}\nDifferent: {}\nSame: {}",
            status,
            args.path1, result.only_in_first.len(),
            args.path2, result.only_in_second.len(),
            result.different.len(),
            result.same_count
        );
        
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
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
            is_error: Some(false),
            meta: None,
        })
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
            follow: args.follow,
            timeout_ms: args.timeout_ms,
        };
        
        let result = watch::tail_file(&path, params)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        
        Ok(CallToolResult {
            content: vec![Content::text(&result.content)],
            structured_content: Some(json!({
                "content": result.content,
                "linesReturned": result.lines_returned,
                "fileSize": result.file_size,
                "truncated": result.truncated,
            })),
            is_error: Some(false),
            meta: None,
        })
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
        
        let events: Vec<watch::WatchEvent> = args.events
            .iter()
            .filter_map(|e| watch::WatchEvent::from_str(e).ok())
            .collect();
        
        let result = watch::watch_file(&path, args.timeout_ms, &events)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        
        let text = if result.changed {
            format!("File changed: {:?} after {}ms", result.event, result.elapsed_ms)
        } else {
            "No changes detected (timeout)".to_string()
        };
        
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
                "changed": result.changed,
                "event": result.event,
                "newSize": result.new_size,
                "elapsedMs": result.elapsed_ms,
                "timedOut": result.timed_out,
            })),
            is_error: Some(false),
            meta: None,
        })
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
        
        let result = json_reader::read_json(&path, args.query.as_deref(), args.pretty)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        
        let text = if let Some(ref err) = result.parse_error {
            format!("JSON parse error at line {:?}, col {:?}: {}\nContext: {:?}",
                err.line, err.column, err.message, err.context)
        } else {
            result.pretty.clone()
        };
        
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
                "result": result.result,
                "queryMatched": result.query_matched,
                "parseError": result.parse_error.as_ref().map(|e| json!({
                    "message": e.message,
                    "line": e.line,
                    "column": e.column,
                })),
                "totalKeys": result.total_keys,
                "arrayLength": result.array_length,
            })),
            is_error: Some(result.parse_error.is_some()),
            meta: None,
        })
    }

    #[tool(
        name = "read_pdf",
        description = "Extract text from PDF file. Supports page ranges. Returns text, page count, charCount, and truncation info."
    )]
    async fn read_pdf(
        &self,
        Parameters(args): Parameters<ReadPdfArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;
        
        let result = pdf_reader::read_pdf(&path, args.pages.as_deref(), args.max_chars)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        
        Ok(CallToolResult {
            content: vec![Content::text(&result.text)],
            structured_content: Some(json!({
                "text": result.text,
                "pagesCount": result.pages_count,
                "pagesExtracted": result.pages_extracted,
                "truncated": result.truncated,
                "charCount": result.char_count,
            })),
            is_error: Some(false),
            meta: None,
        })
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
            Some(archive::ArchiveFormat::from_str(f)
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?)
        } else {
            None
        };
        
        let files_filter = if args.files.is_empty() { None } else { Some(args.files.as_slice()) };
        
        let result = archive::extract_archive(&archive_path, &dest_path, format, files_filter)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        
        let text = format!(
            "Extracted {} files ({} dirs) to {}. Total: {} bytes",
            result.files_extracted, result.dirs_created,
            args.destination, result.total_bytes
        );
        
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
                "filesExtracted": result.files_extracted,
                "dirsCreated": result.dirs_created,
                "files": result.files,
                "totalBytes": result.total_bytes,
            })),
            is_error: Some(false),
            meta: None,
        })
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
            Some(archive::ArchiveFormat::from_str(f)
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?)
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
        
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
                "filesAdded": result.files_added,
                "archiveSize": result.archive_size,
                "archivePath": result.archive_path,
            })),
            is_error: Some(false),
            meta: None,
        })
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
        
        let result = stats::file_stats(&path, args.recursive, 10)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        
        let text = format!(
            "Files: {}, Dirs: {}, Size: {}",
            result.total_files, result.total_dirs, result.total_size_human
        );
        
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
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
            is_error: Some(false),
            meta: None,
        })
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
        
        let result = duplicates::find_duplicates(&path, args.min_size, args.by_content)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        
        let text = format!(
            "Found {} duplicate groups ({} files). Wasted space: {}",
            result.duplicate_groups.len(),
            result.duplicate_files,
            result.wasted_space_human
        );
        
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
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
            is_error: Some(false),
            meta: None,
        })
    }

    // === Process Management Tools ===

    #[tool(
        name = "run_command",
        description = "Execute a shell command with full control over execution environment.\n\n\
            CROSS-PLATFORM: Works on Windows, macOS, and Linux.\n\n\
            **Features:**\n\
            - Custom working directory (cwd)\n\
            - Environment variables (env) - added to current environment\n\
            - Timeout with automatic kill (timeout_ms)\n\
            - Redirect stdout/stderr to files\n\
            - Stream output to files (streamOutput; use with background)\n\
            - Read stdin from file\n\
            - Tail output (stdout_tail/stderr_tail) - return only last N lines\n\
            - Background execution (background) - returns PID immediately\n\
            - Background output: use stdout_file/stderr_file to capture output while running\n\n\
            **Examples:**\n\
            - Run Python script: {command: 'python', args: ['script.py']}\n\
            - With timeout: {command: 'cargo', args: ['build'], timeout_ms: 60000}\n\
            - Background: {command: 'npm', args: ['start'], background: true}\n\
            - Stream to logs: {command: 'cargo', args: ['build'], background: true, streamOutput: true}\n\
            - Custom env: {command: 'node', args: ['app.js'], env: {NODE_ENV: 'production'}}\n\
            - Tail output: {command: 'cargo', args: ['test'], stdout_tail: 50}"
    )]
    async fn run_command(
        &self,
        Parameters(args): Parameters<RunCommandArgs>,
    ) -> Result<CallToolResult, McpError> {
        let args_refs: Vec<&str> = args.args.iter().map(|s| s.as_str()).collect();

        let mut stdout_file = args.stdout_file.clone();
        let mut stderr_file = args.stderr_file.clone();
        if args.stream_output {
            let (stream_stdout, stream_stderr) = prepare_stream_paths(&args).await?;
            if stdout_file.is_none() {
                stdout_file = Some(stream_stdout);
            }
            if stderr_file.is_none() {
                stderr_file = Some(stream_stderr);
            }
        }

        let params = process::RunParams {
            cwd: args.cwd,
            env: args.env,
            clear_env: args.clear_env,
            timeout_ms: args.timeout_ms,
            kill_after_ms: args.timeout_ms, // Use same value for watchdog
            stdout_file: stdout_file.clone(),
            stderr_file: stderr_file.clone(),
            stdin_file: args.stdin_file,
            stdout_tail: args.stdout_tail,
            stderr_tail: args.stderr_tail,
            background: args.background,
        };
        
        let result = process::run_command(&args.command, &args_refs, params, Some(&self.process_manager))
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        
        let status = if result.background {
            format!("Started in background (PID: {})", result.pid.unwrap_or(0))
        } else if result.killed {
            format!("Killed after {}ms (timeout)", result.duration_ms)
        } else {
            format!("Completed in {}ms (exit code: {:?})", result.duration_ms, result.exit_code)
        };
        
        let mut text_parts = vec![status];
        if !result.stdout.is_empty() {
            text_parts.push(format!("\n--- stdout ---\n{}", result.stdout));
        }
        if !result.stderr.is_empty() {
            text_parts.push(format!("\n--- stderr ---\n{}", result.stderr));
        }
        
        Ok(CallToolResult {
            content: vec![Content::text(text_parts.join(""))],
            structured_content: Some(json!({
                "exitCode": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "pid": result.pid,
                "killed": result.killed,
                "timedOut": result.timed_out,
                "durationMs": result.duration_ms,
                "background": result.background,
                "stdoutFile": stdout_file,
                "stderrFile": stderr_file,
            })),
            is_error: Some(result.exit_code.map(|c| c != 0).unwrap_or(result.killed)),
            meta: None,
        })
    }

    #[tool(
        name = "kill_process",
        description = "Kill a running process by PID.\n\n\
            CROSS-PLATFORM: Works on Windows (taskkill), macOS and Linux (kill).\n\n\
            **Parameters:**\n\
            - pid: Process ID to kill\n\
            - force: Force kill (SIGKILL on Unix, /F on Windows)\n\n\
            **Examples:**\n\
            - Graceful: {pid: 12345}\n\
            - Force kill: {pid: 12345, force: true}"
    )]
    async fn kill_process(
        &self,
        Parameters(args): Parameters<KillProcessArgs>,
    ) -> Result<CallToolResult, McpError> {
        let success = process::kill_process(args.pid, args.force)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        
        // Unregister from our process manager if we were tracking it
        self.process_manager.unregister(args.pid).await;
        
        let text = if success {
            format!("Process {} killed successfully", args.pid)
        } else {
            format!("Failed to kill process {} (may not exist)", args.pid)
        };
        
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
                "pid": args.pid,
                "success": success,
            })),
            is_error: Some(!success),
            meta: None,
        })
    }

    #[tool(
        name = "list_processes",
        description = "List background processes started by this server.\n\n\
            Returns processes that were started with run_command(background: true) and are still tracked.\n\
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
            processes.into_iter()
                .filter(|p| p.command.contains(filter))
                .collect()
        } else {
            processes
        };
        
        let text = if filtered.is_empty() {
            "No background processes tracked".to_string()
        } else {
            filtered.iter()
                .map(|p| format!(
                    "PID {}: {} {} (running for {}s)",
                    p.pid,
                    p.command,
                    p.args.join(" "),
                    p.started_at.elapsed().as_secs()
                ))
                .collect::<Vec<_>>()
                .join("\n")
        };
        
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
                "processes": filtered.iter().map(|p| json!({
                    "pid": p.pid,
                    "command": p.command,
                    "args": p.args,
                    "cwd": p.cwd,
                    "runningForSecs": p.started_at.elapsed().as_secs(),
                })).collect::<Vec<_>>(),
                "count": filtered.len(),
            })),
            is_error: Some(false),
            meta: None,
        })
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
        ).map_err(|e| McpError::internal_error(e.to_string(), None))?;
        
        let text = if results.is_empty() {
            "No matching processes found".to_string()
        } else {
            results.iter()
                .map(|p| {
                    let cmdline = p.command_line.as_deref().unwrap_or("");
                    format!("PID {}: {} ({:.1}% CPU, {} MB) - {}", 
                        p.pid, p.name, p.cpu_percent, p.memory_bytes / 1024 / 1024, cmdline)
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!({
                "processes": results,
                "count": results.len(),
            })),
            is_error: Some(false),
            meta: None,
        })
    }

    // === Screenshot Tools ===

    #[cfg(feature = "screenshot-tools")]
    #[tool(name = "screenshot_list_monitors", description = "List all monitors with IDs and dimensions")]
    async fn list_monitors(
        &self,
        Parameters(_args): Parameters<ListMonitorsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let monitors = screenshot::list_monitors()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let payload = json!({ "monitors": monitors });
        Ok(CallToolResult {
            content: vec![Content::text(serde_json::to_string_pretty(&payload).unwrap())],
            structured_content: Some(payload),
            is_error: Some(false),
            meta: None,
        })
    }

    #[cfg(feature = "screenshot-tools")]
    #[tool(name = "screenshot_list_windows", description = "List all visible windows. Optional title_filter.")]
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
        Ok(CallToolResult {
            content: vec![Content::text(serde_json::to_string_pretty(&payload).unwrap())],
            structured_content: Some(payload),
            is_error: Some(false),
            meta: None,
        })
    }

    #[cfg(feature = "screenshot-tools")]
    #[tool(name = "screenshot_capture_screen", description = "Capture monitor. Args: monitor_id, output (file/clipboard/base64), path")]
    async fn capture_screen(
        &self,
        Parameters(args): Parameters<CaptureScreenArgs>,
    ) -> Result<CallToolResult, McpError> {
        let image = screenshot::capture_monitor(args.monitor_id)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        self.handle_screenshot_output(&image, args.output, args.path.as_deref()).await
    }

    #[cfg(feature = "screenshot-tools")]
    #[tool(name = "screenshot_capture_window", description = "Capture window by window_id or title")]
    async fn capture_window(
        &self,
        Parameters(args): Parameters<CaptureWindowArgs>,
    ) -> Result<CallToolResult, McpError> {
        let image = match (args.window_id, &args.title) {
            (Some(id), _) => screenshot::capture_window_by_id(id),
            (None, Some(title)) => screenshot::capture_window_by_title(title),
            _ => return Err(McpError::invalid_params("window_id or title required", None)),
        }
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        self.handle_screenshot_output(&image, args.output, args.path.as_deref()).await
    }

    #[cfg(feature = "screenshot-tools")]
    #[tool(name = "screenshot_capture_region", description = "Capture region. Args: x, y, width, height, monitor_id, output, path")]
    async fn capture_region(
        &self,
        Parameters(args): Parameters<CaptureRegionArgs>,
    ) -> Result<CallToolResult, McpError> {
        let image = screenshot::capture_region(
            args.monitor_id,
            args.x,
            args.y,
            args.width,
            args.height,
        )
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        self.handle_screenshot_output(&image, args.output, args.path.as_deref()).await
    }

    #[cfg(feature = "screenshot-tools")]
    #[tool(name = "screenshot_copy_to_clipboard", description = "Copy image file to clipboard")]
    async fn copy_to_clipboard(
        &self,
        Parameters(args): Parameters<CopyToClipboardArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = self.resolve(&args.path).await?;
        screenshot::copy_file(&path)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Copied to clipboard: {}",
                path.display()
            ))],
            structured_content: Some(json!({ "path": path.display().to_string() })),
            is_error: Some(false),
            meta: None,
        })
    }

    // ==================== THINKING TOOLS ====================

    #[tool(
        name = "seq_think",
        description = "Sequential thinking for structured problem-solving.\n\n\
            Helps analyze problems through a flexible thinking process that can adapt and evolve.\n\
            Each thought can build on, question, or revise previous insights.\n\n\
            When to use:\n\
            - Breaking down complex problems into steps\n\
            - Planning and design with room for revision\n\
            - Analysis that might need course correction\n\
            - Multi-step solutions requiring context\n\n\
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
        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(json!(output)),
            is_error: Some(false),
            meta: None,
        })
    }

    // ==================== MEMORY TOOLS ====================

    fn require_memory(&self) -> Result<&KnowledgeGraphManager, McpError> {
        self.memory_manager.as_ref().map(|m| m.as_ref())
            .ok_or_else(|| McpError::internal_error("Memory manager not initialized", None))
    }

    #[tool(
        name = "mem_entities_create",
        description = "Create entities in knowledge graph.\n\n\
            Input: { \"entities\": [{ \"name\": \"id\", \"entityType\": \"type\", \"observations\": [\"fact1\"] }] }\n\
            Returns only newly created entities (duplicates ignored)."
    )]
    async fn mem_entities_create(
        &self,
        Parameters(args): Parameters<MemCreateEntitiesArgs>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.require_memory()?;
        let created = manager.create_entities(args.entities).await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let summary = format!("{} entities created", created.len());
        Ok(CallToolResult {
            content: vec![Content::text(&summary)],
            structured_content: Some(json!({"entities": created})),
            is_error: Some(false),
            meta: None,
        })
    }

    #[tool(
        name = "mem_relations_create",
        description = "Create relations between entities.\n\n\
            Input: { \"relations\": [{ \"from\": \"entity1\", \"to\": \"entity2\", \"relationType\": \"knows\" }] }\n\
            Both entities must exist. Returns only newly created relations."
    )]
    async fn mem_relations_create(
        &self,
        Parameters(args): Parameters<MemCreateRelationsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.require_memory()?;
        let created = manager.create_relations(args.relations).await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let summary = format!("{} relations created", created.len());
        Ok(CallToolResult {
            content: vec![Content::text(&summary)],
            structured_content: Some(json!({"relations": created})),
            is_error: Some(false),
            meta: None,
        })
    }

    #[tool(
        name = "mem_observations_add",
        description = "Add observations to existing entities.\n\n\
            Input: { \"observations\": [{ \"entityName\": \"name\", \"contents\": [\"fact1\", \"fact2\"] }] }\n\
            Entity must exist. Duplicate observations are ignored."
    )]
    async fn mem_observations_add(
        &self,
        Parameters(args): Parameters<MemAddObservationsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.require_memory()?;
        let results = manager.add_observations(args.observations).await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let summary = format!("Added observations to {} entities", results.len());
        Ok(CallToolResult {
            content: vec![Content::text(&summary)],
            structured_content: Some(json!({"results": results})),
            is_error: Some(false),
            meta: None,
        })
    }

    #[tool(
        name = "mem_entities_delete",
        description = "Delete entities and their relations.\n\n\
            Input: { \"entityNames\": [\"name1\", \"name2\"] }\n\
            Relations involving deleted entities are auto-removed."
    )]
    async fn mem_entities_delete(
        &self,
        Parameters(args): Parameters<MemDeleteEntitiesArgs>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.require_memory()?;
        let count = manager.delete_entities(args.entity_names).await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(format!("{} entities deleted", count))]))
    }

    #[tool(
        name = "mem_observations_delete",
        description = "Delete specific observations from entities.\n\n\
            Input: { \"deletions\": [{ \"entityName\": \"name\", \"observations\": [\"exact text\"] }] }\n\
            Observation text must match exactly."
    )]
    async fn mem_observations_delete(
        &self,
        Parameters(args): Parameters<MemDeleteObservationsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.require_memory()?;
        manager.delete_observations(args.deletions).await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text("Observations deleted")]))
    }

    #[tool(
        name = "mem_relations_delete",
        description = "Delete specific relations.\n\n\
            Input: { \"relations\": [{ \"from\": \"e1\", \"to\": \"e2\", \"relationType\": \"type\" }] }\n\
            All three fields must match exactly."
    )]
    async fn mem_relations_delete(
        &self,
        Parameters(args): Parameters<MemDeleteRelationsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.require_memory()?;
        let count = manager.delete_relations(args.relations).await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        Ok(CallToolResult::success(vec![Content::text(format!("{} relations deleted", count))]))
    }

    #[tool(
        name = "mem_graph_read",
        description = "Read entire knowledge graph.\n\n\
            Input: {} (empty object)\n\
            Returns all entities and relations."
    )]
    async fn mem_graph_read(&self) -> Result<CallToolResult, McpError> {
        let manager = self.require_memory()?;
        let graph = manager.read_graph().await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let summary = format!("{} entities, {} relations", graph.entities.len(), graph.relations.len());
        Ok(CallToolResult {
            content: vec![Content::text(&summary)],
            structured_content: Some(json!(graph)),
            is_error: Some(false),
            meta: None,
        })
    }

    #[tool(
        name = "mem_nodes_search",
        description = "Search nodes using full-text search.\n\n\
            Input: { \"query\": \"search terms\" } or { \"query\": null } for all\n\
            Searches entity names, types, and observations."
    )]
    async fn mem_nodes_search(
        &self,
        Parameters(args): Parameters<MemSearchNodesArgs>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.require_memory()?;
        let result = manager.search_nodes(args.query).await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let summary = format!("Found {} entities, {} relations", result.entities.len(), result.relations.len());
        Ok(CallToolResult {
            content: vec![Content::text(&summary)],
            structured_content: Some(json!(result)),
            is_error: Some(false),
            meta: None,
        })
    }

    #[tool(
        name = "mem_nodes_open",
        description = "Open specific nodes by names.\n\n\
            Input: { \"names\": [\"entity1\", \"entity2\"] }\n\
            Returns requested entities with their relations."
    )]
    async fn mem_nodes_open(
        &self,
        Parameters(args): Parameters<MemOpenNodesArgs>,
    ) -> Result<CallToolResult, McpError> {
        let manager = self.require_memory()?;
        let result = manager.open_nodes(args.names).await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let summary = format!("Retrieved {} entities, {} relations", result.entities.len(), result.relations.len());
        Ok(CallToolResult {
            content: vec![Content::text(&summary)],
            structured_content: Some(json!(result)),
            is_error: Some(false),
            meta: None,
        })
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
            .map_err(|e| McpError::internal_error(e, None))?;
        Ok(CallToolResult {
            content: vec![Content::text(serde_json::to_string_pretty(&info).unwrap_or_default())],
            structured_content: Some(info),
            is_error: Some(false),
            meta: None,
        })
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
            .map_err(|e| McpError::internal_error(e, None))?;
        Ok(CallToolResult {
            content: vec![Content::text(sheets.join(", "))],
            structured_content: Some(json!({"sheets": sheets})),
            is_error: Some(false),
            meta: None,
        })
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
            args.headers,
            args.max_rows,
            args.offset,
        ).map_err(|e| McpError::internal_error(e, None))?;
        
        let summary = format!(
            "Read {} rows from sheet '{}'",
            data.get("returned").and_then(|v| v.as_u64()).unwrap_or(0),
            data.get("sheet").and_then(|v| v.as_str()).unwrap_or("?")
        );
        Ok(CallToolResult {
            content: vec![Content::text(&summary)],
            structured_content: Some(data),
            is_error: Some(false),
            meta: None,
        })
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
        let data = crate::tools::docx::docx_read(&path, args.include_structure)
            .map_err(|e| McpError::internal_error(e, None))?;
        
        let summary = if args.include_structure {
            format!(
                "Read {} paragraphs, {} tables",
                data.get("paragraph_count").and_then(|v| v.as_u64()).unwrap_or(0),
                data.get("table_count").and_then(|v| v.as_u64()).unwrap_or(0)
            )
        } else {
            format!(
                "Extracted {} characters",
                data.get("length").and_then(|v| v.as_u64()).unwrap_or(0)
            )
        };
        Ok(CallToolResult {
            content: vec![Content::text(&summary)],
            structured_content: Some(data),
            is_error: Some(false),
            meta: None,
        })
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
            .map_err(|e| McpError::internal_error(e, None))?;
        Ok(CallToolResult {
            content: vec![Content::text(serde_json::to_string_pretty(&info).unwrap_or_default())],
            structured_content: Some(info),
            is_error: Some(false),
            meta: None,
        })
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
        meta: Meta,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let llm = self.require_llm()?;
        let provider = llm.state().config.primary_provider();
        llm.messages_for_provider(&provider, request, meta, client).await
    }

    #[tool(
        name = "ai_messages_gemini",
        description = "Claude Messages API-compatible conversation tool backed by Gemini."
    )]
    async fn ai_messages_gemini(
        &self,
        Parameters(request): Parameters<tools::llm::model::MessagesRequest>,
        meta: Meta,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let llm = self.require_llm()?;
        llm.messages_for_provider("gemini", request, meta, client).await
    }

    #[tool(
        name = "ai_messages_openai",
        description = "Claude Messages API-compatible conversation tool backed by OpenAI."
    )]
    async fn ai_messages_openai(
        &self,
        Parameters(request): Parameters<tools::llm::model::MessagesRequest>,
        meta: Meta,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let llm = self.require_llm()?;
        llm.messages_for_provider("openai", request, meta, client).await
    }

    #[tool(
        name = "ai_messages_cerebras",
        description = "Claude Messages API-compatible conversation tool backed by Cerebras."
    )]
    async fn ai_messages_cerebras(
        &self,
        Parameters(request): Parameters<tools::llm::model::MessagesRequest>,
        meta: Meta,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let llm = self.require_llm()?;
        llm.messages_for_provider("cerebras", request, meta, client).await
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
        let users = tools::wave2::net::port_users(args.port)
            .map_err(|e| McpError::internal_error(e, None))?;
        let count = users.len();
        Ok(CallToolResult {
            content: vec![Content::text(format!("{} process(es) using port {}", count, args.port))],
            structured_content: Some(json!({"port": args.port, "count": count, "processes": users})),
            is_error: Some(false),
            meta: None,
        })
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
        let conns = tools::wave2::net::net_connections(args.pid)
            .map_err(|e| McpError::internal_error(e, None))?;
        let count = conns.len();
        let summary = match args.pid {
            Some(pid) => format!("{} connection(s) for PID {}", count, pid),
            None => format!("{} total connection(s)", count),
        };
        Ok(CallToolResult {
            content: vec![Content::text(&summary)],
            structured_content: Some(json!({"count": count, "connections": conns})),
            is_error: Some(false),
            meta: None,
        })
    }

    #[tool(
        name = "port_available",
        description = "Check if a port is available (not in use)."
    )]
    async fn port_available(
        &self,
        Parameters(args): Parameters<PortAvailableArgs>,
    ) -> Result<CallToolResult, McpError> {
        let available = tools::wave2::net::port_available(args.port);
        let msg = if available {
            format!("Port {} is available", args.port)
        } else {
            format!("Port {} is in use", args.port)
        };
        Ok(CallToolResult {
            content: vec![Content::text(&msg)],
            structured_content: Some(json!({"port": args.port, "available": available})),
            is_error: Some(false),
            meta: None,
        })
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
        let tree = tools::wave2::proc::proc_tree(args.pid)
            .map_err(|e| McpError::internal_error(e, None))?;
        let summary = match args.pid {
            Some(pid) => format!("Process tree for PID {}", pid),
            None => "Full process tree".to_string(),
        };
        Ok(CallToolResult {
            content: vec![Content::text(&summary)],
            structured_content: Some(tree),
            is_error: Some(false),
            meta: None,
        })
    }

    #[tool(
        name = "proc_env",
        description = "Get environment variables of a process."
    )]
    async fn proc_env(
        &self,
        Parameters(args): Parameters<ProcEnvArgs>,
    ) -> Result<CallToolResult, McpError> {
        let env = tools::wave2::proc::proc_env(args.pid)
            .map_err(|e| McpError::internal_error(e, None))?;
        let count = env.get("env_count").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(CallToolResult {
            content: vec![Content::text(format!("{} environment variables for PID {}", count, args.pid))],
            structured_content: Some(env),
            is_error: Some(false),
            meta: None,
        })
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
        let files = tools::wave2::proc::proc_files(args.pid)
            .map_err(|e| McpError::internal_error(e, None))?;
        let count = files.get("file_count").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(CallToolResult {
            content: vec![Content::text(format!("{} open file(s) for PID {}", count, args.pid))],
            structured_content: Some(files),
            is_error: Some(false),
            meta: None,
        })
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
            .map_err(|e| McpError::internal_error(e, None))?;
        let summary = match &args.path {
            Some(p) => format!("Disk usage for {}", p),
            None => "All disks".to_string(),
        };
        Ok(CallToolResult {
            content: vec![Content::text(&summary)],
            structured_content: Some(usage),
            is_error: Some(false),
            meta: None,
        })
    }

    #[tool(
        name = "sys_info",
        description = "Get system information.\n\n\
            Returns CPU, memory, swap, uptime, OS info, and load average."
    )]
    async fn sys_info(&self) -> Result<CallToolResult, McpError> {
        let info = tools::wave2::sys::sys_info();
        let hostname = info.get("hostname").and_then(|v| v.as_str()).unwrap_or("unknown");
        Ok(CallToolResult {
            content: vec![Content::text(format!("System info for {}", hostname))],
            structured_content: Some(info),
            is_error: Some(false),
            meta: None,
        })
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
            .map_err(|e| McpError::internal_error(e, None))?;
        let identical = diff.get("identical").and_then(|v| v.as_bool()).unwrap_or(false);
        let adds = diff.get("additions").and_then(|v| v.as_u64()).unwrap_or(0);
        let dels = diff.get("deletions").and_then(|v| v.as_u64()).unwrap_or(0);
        let summary = if identical {
            "Files are identical".to_string()
        } else {
            format!("+{} -{} lines", adds, dels)
        };
        Ok(CallToolResult {
            content: vec![Content::text(&summary)],
            structured_content: Some(diff),
            is_error: Some(false),
            meta: None,
        })
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
        let result = tools::wave2::file::file_touch(&path, args.create_parents)
            .map_err(|e| McpError::internal_error(e, None))?;
        let created = result.get("created").and_then(|v| v.as_bool()).unwrap_or(false);
        let summary = if created { "File created" } else { "Timestamp updated" };
        Ok(CallToolResult {
            content: vec![Content::text(summary)],
            structured_content: Some(result),
            is_error: Some(false),
            meta: None,
        })
    }

    #[tool(
        name = "clipboard_read",
        description = "Read text from system clipboard."
    )]
    async fn clipboard_read(&self) -> Result<CallToolResult, McpError> {
        let text = tools::wave2::util::clipboard_read()
            .map_err(|e| McpError::internal_error(e, None))?;
        let len = text.len();
        Ok(CallToolResult {
            content: vec![Content::text(&text)],
            structured_content: Some(json!({"text": text, "length": len})),
            is_error: Some(false),
            meta: None,
        })
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
            .map_err(|e| McpError::internal_error(e, None))?;
        Ok(CallToolResult {
            content: vec![Content::text(format!("Wrote {} characters to clipboard", args.text.len()))],
            structured_content: Some(json!({"success": true, "length": args.text.len()})),
            is_error: Some(false),
            meta: None,
        })
    }

    #[tool(
        name = "env_get",
        description = "Get environment variable value."
    )]
    async fn env_get(
        &self,
        Parameters(args): Parameters<EnvGetArgs>,
    ) -> Result<CallToolResult, McpError> {
        match tools::wave2::util::env_get(&args.name) {
            Some(value) => Ok(CallToolResult {
                content: vec![Content::text(&value)],
                structured_content: Some(json!({"name": args.name, "value": value, "found": true})),
                is_error: Some(false),
                meta: None,
            }),
            None => Ok(CallToolResult {
                content: vec![Content::text(format!("Environment variable '{}' not found", args.name))],
                structured_content: Some(json!({"name": args.name, "found": false})),
                is_error: Some(false),
                meta: None,
            }),
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
        Ok(CallToolResult {
            content: vec![Content::text(format!("Set {}={}", args.name, args.value))],
            structured_content: Some(json!({"name": args.name, "value": args.value, "success": true})),
            is_error: Some(false),
            meta: None,
        })
    }

    /// Remove an environment variable (current process only)
    #[tool(name = "env_remove")]
    async fn env_remove(
        &self,
        Parameters(args): Parameters<EnvRemoveArgs>,
    ) -> Result<CallToolResult, McpError> {
        tools::wave2::util::env_remove(&args.name);
        Ok(CallToolResult {
            content: vec![Content::text(format!("Removed {}", args.name))],
            structured_content: Some(json!({"name": args.name, "success": true})),
            is_error: Some(false),
            meta: None,
        })
    }

    #[tool(
        name = "env_list",
        description = "List all environment variables."
    )]
    async fn env_list(&self) -> Result<CallToolResult, McpError> {
        let list = tools::wave2::util::env_list();
        let count = list.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(CallToolResult {
            content: vec![Content::text(format!("{} environment variables", count))],
            structured_content: Some(list),
            is_error: Some(false),
            meta: None,
        })
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
                Ok(CallToolResult {
                    content: vec![Content::text(path)],
                    structured_content: Some(result),
                    is_error: Some(false),
                    meta: None,
                })
            }
            Err(e) => Ok(CallToolResult {
                content: vec![Content::text(&e)],
                structured_content: Some(json!({"command": args.command, "found": false, "error": e})),
                is_error: Some(false),
                meta: None,
            }),
        }
    }
}

#[tool_handler]
impl ServerHandler for FileSystemServer {
    fn get_info(&self) -> ServerInfo {
        self.server_info()
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

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
        let db_path = args.memory_db
            .or_else(|| std::env::var("FS_MCP_MEMORY_DB").ok().map(PathBuf::from))
            .unwrap_or_else(|| {
                let mut path = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
                path.push("filesystem-mcp-rs");
                path.push("memory.db");
                path
            });
        match KnowledgeGraphManager::new(db_path) {
            Ok(manager) => server.memory_manager = Some(Arc::new(manager)),
            Err(e) => warn!("Failed to initialize memory manager: {}", e),
        }
    }

    // Initialize LLM server (if API keys are available)
    {
        match tools::llm::build_state() {
            Ok(state) => {
                let llm = tools::llm::LlmMcpServer::new(state);
                info!("LLM server initialized with providers: {:?}", llm.available_providers());
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
            Some(json!({ "error": details }))
        )
    }
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
    println!("  + memory-tools (always on)");
    println!("  + xlsx-tools (always on)");
    println!("  + docx-tools (always on)");
    println!("  + llm-tools (always on, needs API keys)");
    println!("  + wave2-tools (always on) - port_users, net_connections, proc_tree, disk_usage, etc.");
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
        Some(json!({ "error": details }))
    )
}

fn normalize_tool_schemas(tool_router: &mut ToolRouter<FileSystemServer>) {
    for route in tool_router.map.values_mut() {
        let schema_value = Value::Object((*route.attr.input_schema).clone());
        let schema_value = to_draft07_schema(schema_value);
        if let Value::Object(object) = schema_value {
            route.attr.input_schema = object.into();
        }
    }
}

fn to_draft07_schema(mut schema: Value) -> Value {
    if let Value::Object(ref mut root) = schema {
        root.insert(
            "$schema".to_string(),
            Value::String("http://json-schema.org/draft-07/schema#".to_string()),
        );
    }
    rewrite_schema_refs(&mut schema);
    schema
}

fn rewrite_schema_refs(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(defs) = map.remove("$defs") {
                let definitions = map.entry("definitions".to_string()).or_insert_with(|| Value::Object(Default::default()));
                if let (Value::Object(target), Value::Object(src)) = (definitions, defs) {
                    for (key, value) in src {
                        target.entry(key).or_insert(value);
                    }
                }
            }
            for (key, value) in map.iter_mut() {
                if key == "$ref" {
                    if let Value::String(reference) = value {
                        if let Some(rest) = reference.strip_prefix("#/$defs/") {
                            *reference = format!("#/definitions/{}", rest);
                        } else if reference == "#/$defs" {
                            *reference = "#/definitions".to_string();
                        }
                    }
                }
                rewrite_schema_refs(value);
            }
        }
        Value::Array(items) => {
            for item in items {
                rewrite_schema_refs(item);
            }
        }
        _ => {}
    }
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

fn parse_time_filter(raw: &str) -> Result<SystemTime, String> {
    if let Ok(ts) = humantime::parse_rfc3339(raw) {
        return Ok(ts);
    }
    if let Ok(duration) = humantime::parse_duration(raw) {
        return SystemTime::now()
            .checked_sub(duration)
            .ok_or_else(|| "Time filter underflow".to_string());
    }
    Err(format!(
        "Invalid time filter '{raw}'. Expected RFC3339 or duration like '7d'"
    ))
}

async fn prepare_stream_paths(args: &RunCommandArgs) -> Result<(String, String), McpError> {
    let dir = if let Some(ref dir) = args.stream_dir {
        PathBuf::from(dir)
    } else if let Some(ref cwd) = args.cwd {
        PathBuf::from(cwd)
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

fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;
    
    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
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
                    (Some(s), Some(human_size(s)))
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
