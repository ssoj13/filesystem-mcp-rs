use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(unix)]
use std::os::unix::fs::symlink;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::json;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, Mutex};
use uuid::Uuid;

/// Spawn the filesystem MCP server binary with given args.
async fn spawn_server(args: &[&str]) -> Result<ServerHandle> {
    let mut cmd = Command::new(assert_cmd());
    cmd.args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());

    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take().unwrap();
    let mut stdin = child.stdin.take().unwrap();

    let (tx_out, mut rx_out) = mpsc::channel::<serde_json::Value>(32);
    let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

    // Writer task
    tokio::spawn(async move {
        while let Some(msg) = rx_out.recv().await {
            if let Ok(line) = serde_json::to_string(&msg) {
                let _ = stdin.write_all(line.as_bytes()).await;
                let _ = stdin.write_all(b"\n").await;
                let _ = stdin.flush().await;
            }
        }
    });

    // Reader task
    {
        let pending = pending.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line)
                    && let Some(id) = v.get("id").and_then(|x| x.as_str())
                    && let Some(waiter) = pending.lock().await.remove(id)
                {
                    let _ = waiter.send(v);
                }
                // Notifications without id are ignored
            }
        });
    }

    Ok(ServerHandle {
        child,
        tx_out,
        pending,
    })
}

type PendingMap = Arc<Mutex<HashMap<String, oneshot::Sender<serde_json::Value>>>>;

struct ServerHandle {
    child: Child,
    tx_out: mpsc::Sender<serde_json::Value>,
    pending: PendingMap,
}

impl ServerHandle {
    async fn request(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id.clone(), tx);
        self.tx_out
            .send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .await?;
        let resp = rx.await?;
        Ok(resp)
    }

    async fn call_tool(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.request(
            "tools/call",
            json!({
                "name": name,
                "arguments": arguments
            }),
        )
        .await
    }

    async fn notify(&self, method: &str, params: serde_json::Value) -> Result<()> {
        self.tx_out
            .send(json!({"jsonrpc":"2.0","method":method,"params":params}))
            .await?;
        Ok(())
    }

    async fn kill(mut self) {
        let _ = self.child.kill().await;
    }
}

fn assert_cmd() -> PathBuf {
    // target/debug/filesystem-mcp-rs
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // deps
    path.pop(); // debug or release
    path.push("filesystem-mcp-rs");
    if cfg!(windows) {
        path.set_extension("exe");
    }
    path
}

async fn start_server_with_args(root: &Path, extra: &[&str]) -> Result<ServerHandle> {
    let mut args: Vec<&str> = extra.to_vec();
    args.push(root.to_str().unwrap());
    let srv = spawn_server(&args).await?;
    let _ = srv
        .request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1" }
            }),
        )
        .await?;
    srv.notify("notifications/initialized", json!({})).await?;
    Ok(srv)
}

async fn start_server(root: &Path) -> Result<ServerHandle> {
    start_server_with_args(root, &[]).await
}

fn assert_ok(res: &serde_json::Value) {
    assert!(!res["result"]["is_error"].as_bool().unwrap_or(false));
}

fn assert_err(res: &serde_json::Value) {
    if let Some(err) = res.get("error") {
        assert!(err.is_object());
        return;
    }
    assert!(res["result"]["is_error"].as_bool().unwrap_or(false));
}

#[tokio::test]
async fn tools_list_includes_all_tools() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;

    let tools = srv.request("tools/list", json!({})).await?;
    let names: Vec<_> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t.get("name").and_then(|v| v.as_str()))
        .collect();
    for required in [
        "write_file",
        "read_text_file",
        "read_media_file",
        "read_multiple_files",
        "edit_file",
        "create_directory",
        "list_directory",
        "list_directory_with_sizes",
        "get_file_info",
        "move_file",
        "copy_file",
        "delete_path",
        "search_files",
        "directory_tree",
        "list_allowed_directories",
    ] {
        assert!(names.contains(&required));
    }

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn write_and_read_text_full_head_tail() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file_path = tmp.path().join("hello.txt");

    srv.call_tool(
        "write_file",
        json!({ "path": &file_path, "content": "one\ntwo\nthree" }),
    )
    .await?;

    let full = srv
        .call_tool("read_text_file", json!({ "path": &file_path }))
        .await?;
    assert_eq!(
        full["result"]["content"][0]["text"].as_str().unwrap_or(""),
        "one\ntwo\nthree"
    );

    let head = srv
        .call_tool("read_text_file", json!({ "path": &file_path, "head": 1 }))
        .await?;
    assert!(head["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("")
        .starts_with("one"));

    let tail = srv
        .call_tool("read_text_file", json!({ "path": &file_path, "tail": 1 }))
        .await?;
    assert!(tail["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("")
        .contains("three"));

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn create_directory_creates_nested_folders() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let new_dir = tmp.path().join("a").join("b");

    let res = srv
        .call_tool("create_directory", json!({ "path": &new_dir }))
        .await?;
    assert_ok(&res);
    assert!(new_dir.exists());

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn edit_file_dry_run_and_apply() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file_path = tmp.path().join("file.txt");
    std::fs::write(&file_path, "a\nb\nc\n")?;

    let dry = srv
        .call_tool(
            "edit_file",
            json!({
                "path": &file_path,
                "dryRun": true,
                "edits": [{ "oldText": "b", "newText": "B" }]
            }),
        )
        .await?;
    assert_ok(&dry);

    let applied = srv
        .call_tool(
            "edit_file",
            json!({
                "path": &file_path,
                "dryRun": false,
                "edits": [{ "oldText": "c", "newText": "C" }]
            }),
        )
        .await?;
    assert_ok(&applied);

    let full = srv
        .call_tool("read_text_file", json!({ "path": &file_path }))
        .await?;
    let text = full["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(text.contains("C"));

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn read_multiple_files_reports_missing() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let ok = tmp.path().join("ok.txt");
    std::fs::write(&ok, "hi")?;

    let res = srv
        .call_tool(
            "read_multiple_files",
            json!({ "paths": [ &ok, tmp.path().join("missing.txt") ] }),
        )
        .await?;
    let texts: Vec<_> = res["result"]["content"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c.get("text").and_then(|t| t.as_str()))
        .collect();
    assert!(texts.iter().any(|t| t.contains("hi")));
    assert!(texts.iter().any(|t| t.contains("missing.txt")));

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn move_file_moves_and_preserves_content() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let src = tmp.path().join("src.txt");
    let dst = tmp.path().join("dst.txt");
    std::fs::write(&src, "content")?;

    let res = srv
        .call_tool("move_file", json!({ "source": &src, "destination": &dst }))
        .await?;
    assert_ok(&res);
    assert!(!src.exists());
    assert_eq!(std::fs::read_to_string(&dst)?, "content");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn copy_file_copies_and_allows_overwrite() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let src = tmp.path().join("src.txt");
    let dst = tmp.path().join("nested").join("dst.txt");
    std::fs::write(&src, "copy-me")?;

    let res = srv
        .call_tool(
            "copy_file",
            json!({ "source": &src, "destination": &dst, "overwrite": false }),
        )
        .await?;
    assert_ok(&res);
    assert_eq!(std::fs::read_to_string(&dst)?, "copy-me");
    assert_eq!(std::fs::read_to_string(&src)?, "copy-me");

    // overwrite
    std::fs::write(&src, "new")?;
    let res_overwrite = srv
        .call_tool(
            "copy_file",
            json!({ "source": &src, "destination": &dst, "overwrite": true }),
        )
        .await?;
    assert_ok(&res_overwrite);
    assert_eq!(std::fs::read_to_string(&dst)?, "new");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn copy_directory_recursively() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let src_dir = tmp.path().join("srcdir");
    let sub = src_dir.join("sub");
    std::fs::create_dir_all(&sub)?;
    std::fs::write(src_dir.join("a.txt"), "A")?;
    std::fs::write(sub.join("b.txt"), "B")?;

    let dst_dir = tmp.path().join("destdir");
    let res = srv
        .call_tool(
            "copy_file",
            json!({ "source": &src_dir, "destination": &dst_dir, "overwrite": false }),
        )
        .await?;
    assert_ok(&res);
    assert_eq!(std::fs::read_to_string(dst_dir.join("a.txt"))?, "A");
    assert_eq!(std::fs::read_to_string(dst_dir.join("sub").join("b.txt"))?, "B");

    // overwrite directory
    std::fs::write(src_dir.join("a.txt"), "A2")?;
    let res_overwrite = srv
        .call_tool(
            "copy_file",
            json!({ "source": &src_dir, "destination": &dst_dir, "overwrite": true }),
        )
        .await?;
    assert_ok(&res_overwrite);
    assert_eq!(std::fs::read_to_string(dst_dir.join("a.txt"))?, "A2");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn copy_file_without_overwrite_errors() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let src = tmp.path().join("src.txt");
    let dst = tmp.path().join("dst.txt");
    std::fs::write(&src, "one")?;
    std::fs::write(&dst, "two")?;

    let res = srv
        .call_tool(
            "copy_file",
            json!({ "source": &src, "destination": &dst, "overwrite": false }),
        )
        .await?;
    assert_err(&res);

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn delete_directory_without_recursive_errors() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let dir = tmp.path().join("dir");
    std::fs::create_dir_all(&dir)?;

    let res = srv
        .call_tool("delete_path", json!({ "path": &dir, "recursive": false }))
        .await?;
    assert_err(&res);
    assert!(dir.exists());

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn operations_outside_allowed_are_rejected() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let outside = tmp.path().parent().unwrap().join("outside.txt");

    let res = srv
        .call_tool(
            "write_file",
            json!({ "path": outside.to_string_lossy(), "content": "x" }),
        )
        .await?;
    assert_err(&res);

    srv.kill().await;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_escape_allowed_when_flag_set() -> Result<()> {
    let tmp = TempDir::new()?;
    let outside = tmp.path().parent().unwrap().join("outside_target.txt");
    std::fs::write(&outside, "outside")?;
    let link = tmp.path().join("link.txt");
    symlink(&outside, &link)?;

    let srv = start_server_with_args(tmp.path(), &["--allow_symlink_escape"]).await?;
    let res = srv
        .call_tool("read_text_file", json!({ "path": &link }))
        .await?;
    assert_eq!(
        res["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or(""),
        "outside"
    );

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn delete_path_removes_files_and_directories() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("deleteme.txt");
    std::fs::write(&file, "gone")?;

    let res_file = srv
        .call_tool("delete_path", json!({ "path": &file, "recursive": false }))
        .await?;
    assert_ok(&res_file);
    assert!(!file.exists());

    let dir = tmp.path().join("dir");
    let nested = dir.join("inner.txt");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(&nested, "x")?;

    let res_dir = srv
        .call_tool("delete_path", json!({ "path": &dir, "recursive": true }))
        .await?;
    assert_ok(&res_dir);
    assert!(!dir.exists());

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn list_directory_lists_entries() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let dir = tmp.path().join("dir");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("a.txt"), "a")?;
    std::fs::write(dir.join("b.txt"), "b")?;

    let res = srv
        .call_tool(
            "list_directory",
            json!({ "path": &dir, "sortBy": "name" }),
        )
        .await?;
    let text = res["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(text.contains("a.txt"));
    assert!(text.contains("b.txt"));

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn list_directory_with_sizes_reports_file_sizes() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let dir = tmp.path().join("dir");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("a.txt"), "12345")?;

    let res = srv
        .call_tool(
            "list_directory_with_sizes",
            json!({ "path": &dir, "sortBy": "name" }),
        )
        .await?;
    let text = res["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(text.contains("a.txt"));
    assert!(text.contains("5 B"));

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn get_file_info_reports_metadata() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("info.txt");
    std::fs::write(&file, "info")?;

    let res = srv
        .call_tool("get_file_info", json!({ "path": &file }))
        .await?;
    let text = res["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(text.contains("info.txt"));
    assert!(text.contains("File"));

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn directory_tree_respects_exclude_patterns() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let include_dir = tmp.path().join("keep");
    let exclude_dir = tmp.path().join("exclude");
    std::fs::create_dir_all(&include_dir)?;
    std::fs::create_dir_all(&exclude_dir)?;
    std::fs::write(include_dir.join("a.txt"), "ok")?;
    std::fs::write(exclude_dir.join("b.txt"), "skip")?;

    let res = srv
        .call_tool(
            "directory_tree",
            json!({ "path": tmp.path(), "excludePatterns": ["exclude/**"] }),
        )
        .await?;
    let text = res["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(text.contains("a.txt"));
    assert!(!text.contains("b.txt"));

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn search_files_matches_patterns() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    std::fs::write(tmp.path().join("match.txt"), "x")?;
    std::fs::write(tmp.path().join("other.bin"), "y")?;

    let res = srv
        .call_tool(
            "search_files",
            json!({ "path": tmp.path(), "pattern": "**/*.txt", "excludePatterns": [] }),
        )
        .await?;
    let text = res["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(text.contains("match.txt"));
    assert!(!text.contains("other.bin"));

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn read_media_file_returns_mime_and_base64() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let png_bytes = STANDARD
        .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII=")?
        ;
    let img_path = tmp.path().join("img.png");
    std::fs::write(&img_path, &png_bytes)?;

    let res = srv
        .call_tool("read_media_file", json!({ "path": &img_path }))
        .await?;
    let mime = res["result"]["content"][0]["mimeType"]
        .as_str()
        .unwrap_or("");
    assert_eq!(mime, "image/png");
    let data = res["result"]["content"][0]["data"]
        .as_str()
        .unwrap_or("");
    assert!(!data.is_empty());

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn list_allowed_directories_includes_root() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;

    let res = srv.call_tool("list_allowed_directories", json!({})).await?;
    let text = res["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(text.contains(tmp.path().to_str().unwrap()));

    srv.kill().await;
    Ok(())
}

// ============================================================================
// Extract tools tests
// ============================================================================

#[tokio::test]
async fn extract_lines_removes_and_returns_lines() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("lines.txt");
    std::fs::write(&file, "line1\nline2\nline3\nline4\nline5")?;

    // Extract lines 2-3 with returnExtracted to get content
    let res = srv
        .call_tool(
            "extract_lines",
            json!({ "path": &file, "line": 2, "endLine": 3, "returnExtracted": true }),
        )
        .await?;
    assert_ok(&res);

    // Check extracted content
    let extracted = res["result"]["structuredContent"]["extracted"]
        .as_str()
        .unwrap_or("");
    assert_eq!(extracted, "line2\nline3");

    // Check file was modified
    let remaining = std::fs::read_to_string(&file)?;
    assert_eq!(remaining, "line1\nline4\nline5");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn extract_lines_dry_run_does_not_modify() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("lines.txt");
    std::fs::write(&file, "line1\nline2\nline3")?;

    let res = srv
        .call_tool(
            "extract_lines",
            json!({ "path": &file, "line": 2, "dryRun": true }),
        )
        .await?;
    assert_ok(&res);

    // File should be unchanged
    let content = std::fs::read_to_string(&file)?;
    assert_eq!(content, "line1\nline2\nline3");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn extract_lines_single_line() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("lines.txt");
    std::fs::write(&file, "a\nb\nc")?;

    let res = srv
        .call_tool("extract_lines", json!({ "path": &file, "line": 2, "returnExtracted": true }))
        .await?;
    assert_ok(&res);

    let extracted = res["result"]["structuredContent"]["extracted"]
        .as_str()
        .unwrap_or("");
    assert_eq!(extracted, "b");

    let remaining = std::fs::read_to_string(&file)?;
    assert_eq!(remaining, "a\nc");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn extract_symbols_with_length() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("text.txt");
    std::fs::write(&file, "Hello, World!")?;

    // Extract "Hello" (first 5 chars) with returnExtracted
    let res = srv
        .call_tool(
            "extract_symbols",
            json!({ "path": &file, "start": 0, "length": 5, "returnExtracted": true }),
        )
        .await?;
    assert_ok(&res);

    let extracted = res["result"]["structuredContent"]["extracted"]
        .as_str()
        .unwrap_or("");
    assert_eq!(extracted, "Hello");

    let remaining = std::fs::read_to_string(&file)?;
    assert_eq!(remaining, ", World!");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn extract_symbols_with_end() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("text.txt");
    std::fs::write(&file, "Hello, World!")?;

    // Extract ", World" (positions 5-12) with returnExtracted
    let res = srv
        .call_tool(
            "extract_symbols",
            json!({ "path": &file, "start": 5, "end": 12, "returnExtracted": true }),
        )
        .await?;
    assert_ok(&res);

    let extracted = res["result"]["structuredContent"]["extracted"]
        .as_str()
        .unwrap_or("");
    assert_eq!(extracted, ", World");

    let remaining = std::fs::read_to_string(&file)?;
    assert_eq!(remaining, "Hello!");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn extract_symbols_unicode() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("unicode.txt");
    std::fs::write(&file, "Hello")?;

    // Extract first 2 chars with returnExtracted
    let res = srv
        .call_tool(
            "extract_symbols",
            json!({ "path": &file, "start": 0, "length": 2, "returnExtracted": true }),
        )
        .await?;
    assert_ok(&res);

    let extracted = res["result"]["structuredContent"]["extracted"]
        .as_str()
        .unwrap_or("");
    assert_eq!(extracted, "He");

    let remaining = std::fs::read_to_string(&file)?;
    assert_eq!(remaining, "llo");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn extract_symbols_dry_run() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("text.txt");
    std::fs::write(&file, "Hello")?;

    let res = srv
        .call_tool(
            "extract_symbols",
            json!({ "path": &file, "start": 0, "length": 3, "dryRun": true }),
        )
        .await?;
    assert_ok(&res);

    // File unchanged
    let content = std::fs::read_to_string(&file)?;
    assert_eq!(content, "Hello");

    srv.kill().await;
    Ok(())
}

// ============================================================================
// Binary tools tests
// ============================================================================

#[tokio::test]
async fn read_binary_returns_base64() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("data.bin");
    std::fs::write(&file, b"Hello, World!")?;

    let res = srv
        .call_tool(
            "read_binary",
            json!({ "path": &file, "offset": 7, "length": 5 }),
        )
        .await?;
    assert_ok(&res);

    let data = res["result"]["structuredContent"]["data"]
        .as_str()
        .unwrap_or("");
    // "World" in base64
    let decoded = STANDARD.decode(data)?;
    assert_eq!(decoded, b"World");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn write_binary_replace_mode() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("data.bin");
    std::fs::write(&file, b"Hello, World!")?;

    // Replace "World" with "Rust!"
    let data = STANDARD.encode(b"Rust!");
    let res = srv
        .call_tool(
            "write_binary",
            json!({ "path": &file, "offset": 7, "data": data, "mode": "replace" }),
        )
        .await?;
    assert_ok(&res);

    let content = std::fs::read(&file)?;
    assert_eq!(content, b"Hello, Rust!!");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn write_binary_insert_mode() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("data.bin");
    std::fs::write(&file, b"Hello World!")?;

    // Insert "," at position 5
    let data = STANDARD.encode(b",");
    let res = srv
        .call_tool(
            "write_binary",
            json!({ "path": &file, "offset": 5, "data": data, "mode": "insert" }),
        )
        .await?;
    assert_ok(&res);

    let content = std::fs::read(&file)?;
    assert_eq!(content, b"Hello, World!");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn extract_binary_removes_and_returns() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("data.bin");
    std::fs::write(&file, b"Hello, World!")?;

    // Extract ", " (2 bytes at offset 5)
    let res = srv
        .call_tool(
            "extract_binary",
            json!({ "path": &file, "offset": 5, "length": 2 }),
        )
        .await?;
    assert_ok(&res);

    let data = res["result"]["structuredContent"]["data"]
        .as_str()
        .unwrap_or("");
    let decoded = STANDARD.decode(data)?;
    assert_eq!(decoded, b", ");

    let remaining = std::fs::read(&file)?;
    assert_eq!(remaining, b"HelloWorld!");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn extract_binary_dry_run() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("data.bin");
    std::fs::write(&file, b"Hello")?;

    let res = srv
        .call_tool(
            "extract_binary",
            json!({ "path": &file, "offset": 0, "length": 2, "dryRun": true }),
        )
        .await?;
    assert_ok(&res);

    // File unchanged
    let content = std::fs::read(&file)?;
    assert_eq!(content, b"Hello");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn patch_binary_single_replacement() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("data.bin");
    std::fs::write(&file, b"foo bar foo baz")?;

    let find = STANDARD.encode(b"foo");
    let replace = STANDARD.encode(b"qux");

    let res = srv
        .call_tool(
            "patch_binary",
            json!({ "path": &file, "find": find, "replace": replace, "all": false }),
        )
        .await?;
    assert_ok(&res);

    let count = res["result"]["structuredContent"]["replacements"]
        .as_i64()
        .unwrap_or(0);
    assert_eq!(count, 1);

    let content = std::fs::read(&file)?;
    assert_eq!(content, b"qux bar foo baz");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn patch_binary_all_replacements() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("data.bin");
    std::fs::write(&file, b"foo bar foo baz foo")?;

    let find = STANDARD.encode(b"foo");
    let replace = STANDARD.encode(b"X");

    let res = srv
        .call_tool(
            "patch_binary",
            json!({ "path": &file, "find": find, "replace": replace, "all": true }),
        )
        .await?;
    assert_ok(&res);

    let count = res["result"]["structuredContent"]["replacements"]
        .as_i64()
        .unwrap_or(0);
    assert_eq!(count, 3);

    let content = std::fs::read(&file)?;
    assert_eq!(content, b"X bar X baz X");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn patch_binary_not_found() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("data.bin");
    std::fs::write(&file, b"hello world")?;

    let find = STANDARD.encode(b"notfound");
    let replace = STANDARD.encode(b"x");

    let res = srv
        .call_tool(
            "patch_binary",
            json!({ "path": &file, "find": find, "replace": replace }),
        )
        .await?;
    assert_ok(&res);

    let count = res["result"]["structuredContent"]["replacements"]
        .as_i64()
        .unwrap_or(-1);
    assert_eq!(count, 0);

    // File unchanged
    let content = std::fs::read(&file)?;
    assert_eq!(content, b"hello world");

    srv.kill().await;
    Ok(())
}
