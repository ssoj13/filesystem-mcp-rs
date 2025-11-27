use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use async_recursion::async_recursion;
use clap::Parser;
use futures::future::join_all;
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::AnnotateAble,
    model::{
        CallToolResult, Content, Implementation,
        ListRootsRequest, ServerCapabilities, ServerInfo, ServerRequest,
    },
    serde::{Deserialize, Serialize},
    service::ServiceError,
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde_json::json;
use tokio::fs;
use tracing::warn;

use crate::allowed::AllowedDirs;
use crate::edit::{FileEdit, apply_edits};
use crate::fs_ops::{head as head_lines, read_text, tail as tail_lines};
use crate::media::read_media_base64;
use crate::path::resolve_validated_path;
use crate::search::search_paths;
use crate::grep::{GrepParams, grep_files};
use crate::line_edit::{LineEdit, LineOperation, apply_line_edits};
use crate::bulk_edit::bulk_edit_files;

mod allowed;
mod diff;
mod edit;
mod format;
mod fs_ops;
mod logging;
mod media;
mod mime;
mod path;
mod roots;
mod search;
mod grep;
mod line_edit;
mod bulk_edit;

use logging::{init_logging, TransportMode};

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
}

#[derive(Clone)]
struct FileSystemServer {
    allowed: AllowedDirs,
    tool_router: ToolRouter<Self>,
    allow_symlink_escape: bool,
}

impl FileSystemServer {
    fn new(allowed: AllowedDirs) -> Self {
        Self {
            allowed,
            tool_router: Self::tool_router(),
            allow_symlink_escape: false,
        }
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
                title: None,
                website_url: None,
                icons: None,
            },
            instructions: None,
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
                McpError::internal_error(
                    "Path validation failed",
                    Some(json!({ "error": e.to_string() })),
                )
            })
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
                    "Unexpected response to roots/list",
                    Some(json!({ "response": other })),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    head: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tail: Option<u32>,
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
}

fn default_max_matches() -> usize {
    100
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
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct TreeEntry {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    children: Option<Vec<TreeEntry>>,
}

#[tool_router]
impl FileSystemServer {
    #[tool(
        name = "read_text_file",
        description = "Read the complete contents of a file as text. Use head/tail to slice lines."
    )]
    async fn read_text_file(
        &self,
        Parameters(ReadTextFileArgs { path, head, tail }): Parameters<ReadTextFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        if head.is_some() && tail.is_some() {
            return Err(McpError::invalid_params(
                "Cannot specify both head and tail",
                None,
            ));
        }

        let path = self.resolve(&path).await?;
        let content = match (head, tail) {
            (Some(h), _) => head_lines(&path, h as usize)
                .await
                .map_err(internal_err("Failed to read head"))?,
            (_, Some(t)) => tail_lines(&path, t as usize)
                .await
                .map_err(internal_err("Failed to read tail"))?,
            _ => read_text(&path)
                .await
                .map_err(internal_err("Failed to read file"))?,
        };

        Ok(CallToolResult {
            content: vec![Content::text(content.clone())],
            structured_content: Some(json!({ "content": content })),
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
        description = "Create new file or overwrite existing file with provided content."
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
        description = "Apply text edits to a file and return a unified diff; supports dry run."
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
        }): Parameters<DirectoryTreeArgs>,
    ) -> Result<CallToolResult, McpError> {
        let root = self.resolve(&path).await?;
        let exclude = search::build_exclude_set(&exclude_patterns)
            .map_err(internal_err("Invalid exclude patterns"))?;

        let entries = build_tree(&root, &root, &exclude).await?;
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
        description = "Recursively search for paths matching glob pattern with optional exclusions."
    )]
    async fn search_files(
        &self,
        Parameters(SearchArgs {
            path,
            pattern,
            exclude_patterns,
        }): Parameters<SearchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let root = self.resolve(&path).await?;
        let results = search_paths(
            root.to_string_lossy().as_ref(),
            &pattern,
            &exclude_patterns,
            &self.allowed,
            self.allow_symlink_escape,
        )
        .await
        .map_err(internal_err("Search failed"))?;

        let text = if results.is_empty() {
            "No matches found".to_string()
        } else {
            results
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join("\n")
        };
        Ok(CallToolResult::success(vec![Content::text(text.clone())])
            .with_structured(json!({ "matches": results })))
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
            .unwrap_or_else(String::new);

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
        description = "Search for text/regex pattern INSIDE file contents (like grep/ripgrep). Use when you need to find specific code, text, or patterns within files. Recursively searches through file contents and returns matching lines with context. Supports regex patterns, file filtering (*.rs, **/*.txt), case-insensitive search, and context lines. Different from search_files which only matches file names/paths."
    )]
    async fn grep_files(
        &self,
        Parameters(args): Parameters<GrepFilesArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.ensure_allowed().await?;

        let params = GrepParams {
            root: args.path.clone(),
            pattern: args.pattern.clone(),
            file_pattern: args.file_pattern.clone(),
            case_insensitive: args.case_insensitive,
            context_before: args.context_before,
            context_after: args.context_after,
            max_matches: args.max_matches,
        };

        let matches = grep_files(params, &self.allowed, self.allow_symlink_escape)
            .await
            .map_err(|e| McpError::internal_error(format!("Grep failed: {}", e), None))?;

        // Format results
        let mut lines = Vec::new();
        for m in &matches {
            let path_str = m.path.to_string_lossy();
            
            // Add before context
            for (i, line) in m.before_context.iter().enumerate() {
                let line_no = m.line_number - m.before_context.len() + i;
                lines.push(format!("{}:{}:  {}", path_str, line_no, line));
            }
            
            // Add match line
            lines.push(format!("{}:{}:> {}", path_str, m.line_number, m.line));
            
            // Add after context
            for (i, line) in m.after_context.iter().enumerate() {
                let line_no = m.line_number + i + 1;
                lines.push(format!("{}:{}:  {}", path_str, line_no, line));
            }
            
            if !m.after_context.is_empty() {
                lines.push("--".to_string());
            }
        }

        let text = if matches.is_empty() {
            format!("No matches found for pattern: {}", args.pattern)
        } else {
            format!(
                "Found {} matches for pattern '{}' in {}:\n\n{}",
                matches.len(),
                args.pattern,
                args.path,
                lines.join("\n")
            )
        };

        let structured = json!({
            "matches": matches.iter().map(|m| json!({
                "path": m.path.to_string_lossy(),
                "lineNumber": m.line_number,
                "line": m.line,
                "beforeContext": m.before_context,
                "afterContext": m.after_context,
            })).collect::<Vec<_>>(),
            "totalMatches": matches.len(),
            "pattern": args.pattern,
            "searchPath": args.path,
        });

        Ok(CallToolResult {
            content: vec![Content::text(text)],
            structured_content: Some(structured),
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
        description = "Apply SAME edits to MULTIPLE files at once (mass search/replace). Use when you need to change the same code/text across many files. Select files by glob pattern (*.rs, **/*.txt), then apply search/replace operations to all matches. Returns summary of modified files with diffs. Perfect for: renaming functions/variables across codebase, updating imports, fixing typos everywhere, refactoring patterns. More efficient than editing files one by one. Supports dry-run to preview changes."
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
            })
            .collect();

        let results = bulk_edit_files(
            &args.path,
            &args.file_pattern,
            &args.exclude_patterns,
            &edits,
            args.dry_run,
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
            lines.push(format!("DRY RUN - Changes NOT applied"));
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
}

#[tool_handler]
impl ServerHandler for FileSystemServer {
    fn get_info(&self) -> ServerInfo {
        self.server_info()
    }

    // NOTE: We don't override initialize() - let rmcp SDK handle the handshake protocol.
    // The default implementation will use get_info() to build the response.
    // Root fetching happens via on_roots_list_changed notification handler.

    fn on_roots_list_changed(
        &self,
        context: rmcp::service::NotificationContext<rmcp::RoleServer>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        async move {
            if let Err(err) = self.refresh_roots(&context.peer).await {
                warn!("Failed to refresh roots on list_changed: {}", err);
            }
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

    // Run in selected mode
    match mode {
        TransportMode::Stdio => run_stdio_mode(server).await,
        TransportMode::Stream => run_stream_mode(server, &args.bind, args.port).await,
    }
}

// init_tracing removed - see main() comment about why we can't use stderr logging

fn internal_err<T: ToString>(message: &'static str) -> impl FnOnce(T) -> McpError + Clone {
    move |err| McpError::internal_error(message, Some(json!({ "error": err.to_string() })))
}

fn service_error(message: &'static str, error: ServiceError) -> McpError {
    McpError::internal_error(message, Some(json!({ "error": error.to_string() })))
}

fn parse_root_uri(uri: &str) -> Option<PathBuf> {
    if let Ok(url) = url::Url::parse(uri) {
        if url.scheme() == "file" {
            return url.to_file_path().ok();
        }
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

#[async_recursion]
async fn build_tree(
    root: &Path,
    current: &Path,
    exclude: &globset::GlobSet,
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
        if exclude.is_match(rel_str.as_ref()) {
            continue;
        }
        let is_dir = entry
            .file_type()
            .await
            .map_err(internal_err("stat entry"))?
            .is_dir();
        if is_dir {
            let kids = build_tree(root, &path, exclude).await?;
            children.push(TreeEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                kind: "directory".to_string(),
                children: Some(kids),
            });
        } else {
            children.push(TreeEntry {
                name: entry.file_name().to_string_lossy().to_string(),
                kind: "file".to_string(),
                children: None,
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
