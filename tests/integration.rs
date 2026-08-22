use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, mpsc, oneshot};
use uuid::Uuid;

fn content_inline(s: &str) -> serde_json::Value {
    json!({ "kind": "inline", "text": s })
}

fn content_blob(id: &str) -> serde_json::Value {
    json!({ "kind": "blob", "id": id })
}

fn content_path(path: &Path) -> serde_json::Value {
    json!({ "kind": "path", "path": path })
}

fn content_base64(bytes: &[u8]) -> serde_json::Value {
    json!({ "kind": "base64", "data": STANDARD.encode(bytes) })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let dig = Sha256::digest(bytes);
    dig.iter().map(|b| format!("{b:02x}")).collect()
}

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
    start_server_with_args(root, &["--no-session-footer"]).await
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

/// Helper: get all tools from tools/list as a map name → description.
async fn list_tool_descriptions(srv: &ServerHandle) -> serde_json::Map<String, serde_json::Value> {
    let resp = srv.request("tools/list", json!({})).await.unwrap();
    resp["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| {
            let name = t["name"].as_str()?.to_string();
            let desc = t["description"].clone();
            Some((name, desc))
        })
        .collect()
}

/// Regression: cwd example must show plain quotes, not backslash-escaped quotes.
/// Before the fix the description contained `\"C:/projects/repo\"` which confused
/// LLMs into generating `"cwd": C:/path` (unquoted, invalid JSON).
#[tokio::test]
async fn run_command_cwd_description_uses_plain_quotes() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let tools = list_tool_descriptions(&srv).await;
    let desc = tools["run_command"].as_str().unwrap_or("");

    // Must have a clean example — plain quotes, no leading backslash
    assert!(
        desc.contains("\"C:/projects/repo\""),
        "run_command cwd example must use plain quotes; got desc snippet: {:?}",
        &desc[desc.find("cwd").unwrap_or(0)..]
            .chars()
            .take(120)
            .collect::<String>()
    );
    // Must NOT have backslash before the C: path (the old broken form)
    assert!(
        !desc.contains("\\\"C:/"),
        "run_command cwd example must not contain backslash-quote before Windows path"
    );

    srv.kill().await;
    Ok(())
}

/// Regression: grep_files description must clearly separate `pattern` (content regex)
/// from `filePattern` (file-name glob) so LLMs don't pass bare globs in the wrong field.
#[tokio::test]
async fn grep_files_description_separates_pattern_from_file_pattern() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let tools = list_tool_descriptions(&srv).await;
    let desc = tools["grep_files"].as_str().unwrap_or("");

    // Must call out both fields by name
    assert!(
        desc.contains("pattern"),
        "grep_files desc must mention 'pattern'"
    );
    assert!(
        desc.contains("filePattern"),
        "grep_files desc must mention 'filePattern'"
    );
    // Must warn that pattern is a quoted string, not a bare glob
    assert!(
        desc.contains("quoted") || desc.contains("JSON string"),
        "grep_files desc must warn that pattern is a quoted string"
    );
    // Must contain a concrete usage example
    assert!(
        desc.contains("catch_unwind") || (desc.contains("pattern") && desc.contains("\":")),
        "grep_files desc must contain a usage example"
    );

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
        json!({ "path": &file_path, "content": content_inline("one\ntwo\nthree") }),
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
    assert!(
        head["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .starts_with("one")
    );

    let tail = srv
        .call_tool("read_text_file", json!({ "path": &file_path, "tail": 1 }))
        .await?;
    assert!(
        tail["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains("three")
    );

    // Test offset/limit pagination
    let offset_res = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "offset": 2, "limit": 1 }),
        )
        .await?;
    assert_eq!(
        offset_res["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or(""),
        "two"
    );

    // Test max_chars truncation
    let truncated = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "max_chars": 5 }),
        )
        .await?;
    let text = truncated["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(text.starts_with("one\nt"));
    assert!(text.contains("[truncated"));

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn read_text_file_pagination_utf8() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file_path = tmp.path().join("utf8.txt");

    // Create file with UTF-8 content
    srv.call_tool(
        "write_file",
        json!({ "path": &file_path, "content": content_inline("Erste\nZweite\nDritte") }),
    )
    .await?;

    // Test that offset/limit work with UTF-8
    let res = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "offset": 2, "limit": 1 }),
        )
        .await?;
    assert_eq!(
        res["result"]["content"][0]["text"].as_str().unwrap_or(""),
        "Zweite"
    );

    // Test max_chars with UTF-8 (should not panic on multi-byte boundary)
    let truncated = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "max_chars": 8 }),
        )
        .await?;
    let text = truncated["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    // Should cleanly truncate at char boundary
    assert!(text.starts_with("Erste\nZw"));

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn read_text_file_pagination_full_coverage() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file_path = tmp.path().join("lines.txt");

    // Create file with 10 lines
    let content = (1..=10)
        .map(|i| format!("line{}", i))
        .collect::<Vec<_>>()
        .join("\n");
    srv.call_tool(
        "write_file",
        json!({ "path": &file_path, "content": content_inline(&content) }),
    )
    .await?;

    // Page 1: lines 1-3
    let page1 = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "offset": 1, "limit": 3 }),
        )
        .await?;
    assert_eq!(
        page1["result"]["content"][0]["text"].as_str().unwrap_or(""),
        "line1\nline2\nline3"
    );

    // Page 2: lines 4-6
    let page2 = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "offset": 4, "limit": 3 }),
        )
        .await?;
    assert_eq!(
        page2["result"]["content"][0]["text"].as_str().unwrap_or(""),
        "line4\nline5\nline6"
    );

    // Page 3: lines 7-9
    let page3 = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "offset": 7, "limit": 3 }),
        )
        .await?;
    assert_eq!(
        page3["result"]["content"][0]["text"].as_str().unwrap_or(""),
        "line7\nline8\nline9"
    );

    // Page 4: line 10 only (partial page)
    let page4 = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "offset": 10, "limit": 3 }),
        )
        .await?;
    assert_eq!(
        page4["result"]["content"][0]["text"].as_str().unwrap_or(""),
        "line10"
    );

    // Beyond file: empty result
    let beyond = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "offset": 100, "limit": 3 }),
        )
        .await?;
    assert_eq!(
        beyond["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or(""),
        ""
    );

    // Only limit (no offset) - first N lines
    let first5 = srv
        .call_tool("read_text_file", json!({ "path": &file_path, "limit": 5 }))
        .await?;
    assert_eq!(
        first5["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or(""),
        "line1\nline2\nline3\nline4\nline5"
    );

    // Only offset (no limit) - from line N to end
    let from8 = srv
        .call_tool("read_text_file", json!({ "path": &file_path, "offset": 8 }))
        .await?;
    assert_eq!(
        from8["result"]["content"][0]["text"].as_str().unwrap_or(""),
        "line8\nline9\nline10"
    );

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn read_text_file_line_numbers_offset_limit() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file_path = tmp.path().join("lines_ln.txt");

    srv.call_tool(
        "write_file",
        json!({ "path": &file_path, "content": content_inline("a\nb\nc\nd") }),
    )
    .await?;

    let res = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "offset": 2, "limit": 2, "line_numbers": true }),
        )
        .await?;

    let text = res["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert_eq!(text, "2 | b\n3 | c");

    let meta = &res["result"]["structuredContent"]["meta"];
    assert_eq!(meta["lineNumbers"], true);
    assert_eq!(meta["startLine"], 2);
    assert_eq!(meta["endLine"], 3);
    assert_eq!(meta["lineCount"], 2);
    assert_eq!(meta["totalLines"], 4);

    let lines = res["result"]["structuredContent"]["lines"]
        .as_array()
        .unwrap();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["lineNumber"], 2);
    assert_eq!(lines[0]["text"], "b");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn read_text_file_line_numbers_tail() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file_path = tmp.path().join("lines_tail.txt");

    let content = (1..=12)
        .map(|i| format!("line{}", i))
        .collect::<Vec<_>>()
        .join("\n");
    srv.call_tool(
        "write_file",
        json!({ "path": &file_path, "content": content_inline(&content) }),
    )
    .await?;

    let res = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "tail": 3, "line_numbers": true }),
        )
        .await?;

    let text = res["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert_eq!(text, "10 | line10\n11 | line11\n12 | line12");

    let meta = &res["result"]["structuredContent"]["meta"];
    assert_eq!(meta["startLine"], 10);
    assert_eq!(meta["endLine"], 12);
    assert_eq!(meta["lineCount"], 3);
    assert_eq!(meta["totalLines"], 12);

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn read_text_file_pagination_edge_cases() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file_path = tmp.path().join("edge.txt");

    // Single line file
    srv.call_tool(
        "write_file",
        json!({ "path": &file_path, "content": content_inline("only one line") }),
    )
    .await?;

    // offset=1 should return that line
    let res = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "offset": 1, "limit": 10 }),
        )
        .await?;
    assert_eq!(
        res["result"]["content"][0]["text"].as_str().unwrap_or(""),
        "only one line"
    );

    // offset=2 should return empty
    let res2 = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "offset": 2, "limit": 10 }),
        )
        .await?;
    assert_eq!(
        res2["result"]["content"][0]["text"].as_str().unwrap_or(""),
        ""
    );

    // Empty file
    let empty_path = tmp.path().join("empty.txt");
    srv.call_tool(
        "write_file",
        json!({ "path": &empty_path, "content": content_inline("") }),
    )
    .await?;

    let empty_res = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &empty_path, "offset": 1, "limit": 10 }),
        )
        .await?;
    assert_eq!(
        empty_res["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or(""),
        ""
    );

    // limit=0 should return empty
    let zero_limit = srv
        .call_tool("read_text_file", json!({ "path": &file_path, "limit": 0 }))
        .await?;
    assert_eq!(
        zero_limit["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or(""),
        ""
    );

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn read_text_file_max_chars_variations() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file_path = tmp.path().join("chars.txt");

    // 100 chars content
    let content = "a".repeat(100);
    srv.call_tool(
        "write_file",
        json!({ "path": &file_path, "content": content_inline(&content) }),
    )
    .await?;

    // max_chars smaller than content
    let truncated = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "max_chars": 50 }),
        )
        .await?;
    let text = truncated["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(text.starts_with(&"a".repeat(50)));
    assert!(text.contains("[truncated"));

    // max_chars larger than content - no truncation
    let not_truncated = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "max_chars": 200 }),
        )
        .await?;
    let text2 = not_truncated["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert_eq!(text2, &content);
    assert!(!text2.contains("[truncated"));

    // max_chars with pagination combined
    let combined = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "offset": 1, "limit": 1, "max_chars": 20 }),
        )
        .await?;
    let text3 = combined["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(text3.starts_with(&"a".repeat(20)));
    assert!(text3.contains("[truncated"));

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn read_text_file_mutually_exclusive_modes() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file_path = tmp.path().join("modes.txt");

    srv.call_tool(
        "write_file",
        json!({ "path": &file_path, "content": content_inline("line1\nline2\nline3") }),
    )
    .await?;

    // head + tail = error
    let res1 = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "head": 1, "tail": 1 }),
        )
        .await?;
    assert_err(&res1);

    // head + offset = error
    let res2 = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "head": 1, "offset": 1 }),
        )
        .await?;
    assert_err(&res2);

    // tail + offset = error
    let res3 = srv
        .call_tool(
            "read_text_file",
            json!({ "path": &file_path, "tail": 1, "offset": 1 }),
        )
        .await?;
    assert_err(&res3);

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
                "edits": [{ "oldText": content_inline("b"), "newText": content_inline("B") }]
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
                "edits": [{ "oldText": content_inline("c"), "newText": content_inline("C") }]
            }),
        )
        .await?;
    assert_ok(&applied);

    let full = srv
        .call_tool("read_text_file", json!({ "path": &file_path }))
        .await?;
    let text = full["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(text.contains("C"));

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn edit_file_json_string_edits() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file_path = tmp.path().join("file_json.txt");
    std::fs::write(&file_path, "a\nb\nc\n")?;

    let res = srv
        .call_tool(
            "edit_file",
            json!({
                "path": &file_path,
                "edits": [r#"{"oldText":{"kind":"inline","text":"b"},"newText":{"kind":"inline","text":"B"}}"#]
            }),
        )
        .await?;
    assert_ok(&res);

    let full = srv
        .call_tool("read_text_file", json!({ "path": &file_path }))
        .await?;
    let text = full["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(text.contains("B"));

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn edit_lines_json_string_edits() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file_path = tmp.path().join("lines_json.txt");
    std::fs::write(&file_path, "a\nb\nc\n")?;

    let res = srv
        .call_tool(
            "edit_lines",
            json!({
                "path": &file_path,
                "edits": [r#"{"line":2,"operation":"replace","text":"B"}"#]
            }),
        )
        .await?;
    assert_ok(&res);

    let full = srv
        .call_tool("read_text_file", json!({ "path": &file_path }))
        .await?;
    let text = full["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(text.contains("B"));

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn edit_file_bare_strings_with_braces_and_two_edits() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file_path = tmp.path().join("braces.rs");
    std::fs::write(&file_path, "use crate::foo;\nlet x = 1;\n")?;

    let res = srv
        .call_tool(
            "edit_file",
            json!({
                "path": &file_path,
                "edits": [
                    { "oldText": "use crate::foo;", "newText": "use crate::foo::{Bar};" },
                    { "oldText": "let x = 1;", "newText": "let x = 2;" }
                ]
            }),
        )
        .await?;
    assert_ok(&res);

    let full = srv
        .call_tool("read_text_file", json!({ "path": &file_path }))
        .await?;
    let text = full["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(text.contains("use crate::foo::{Bar};"), "{text}");
    assert!(text.contains("let x = 2;"), "{text}");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn bulk_edits_json_string_edits() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file_a = tmp.path().join("a.txt");
    let file_b = tmp.path().join("b.txt");
    std::fs::write(&file_a, "foo\n")?;
    std::fs::write(&file_b, "foo\n")?;

    let res = srv
        .call_tool(
            "bulk_edits",
            json!({
                "path": tmp.path(),
                "filePattern": "**/*.txt",
                "edits": [r#"{"oldText":{"kind":"inline","text":"foo"},"newText":{"kind":"inline","text":"bar"},"replaceAll":true}"#]
            }),
        )
        .await?;
    assert_ok(&res);

    let full = srv
        .call_tool("read_text_file", json!({ "path": &file_a }))
        .await?;
    let text = full["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(text.contains("bar"));

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
    assert_eq!(
        std::fs::read_to_string(dst_dir.join("sub").join("b.txt"))?,
        "B"
    );

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

// BH-08: move_file documents "fails if destination exists"; it must not
// silently overwrite (fs::rename would).
#[tokio::test]
async fn move_file_refuses_existing_destination() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let src = tmp.path().join("src.txt");
    let dst = tmp.path().join("dst.txt");
    std::fs::write(&src, "from-src")?;
    std::fs::write(&dst, "keep-me")?;

    let res = srv
        .call_tool("move_file", json!({ "source": &src, "destination": &dst }))
        .await?;
    assert_err(&res);
    // Destination untouched, source intact.
    assert_eq!(std::fs::read_to_string(&dst)?, "keep-me");
    assert!(src.exists());

    srv.kill().await;
    Ok(())
}

// BH-08: copying a file onto itself must not delete it.
#[tokio::test]
async fn copy_file_rejects_self_copy() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file = tmp.path().join("data.txt");
    std::fs::write(&file, "precious")?;

    let res = srv
        .call_tool(
            "copy_file",
            json!({ "source": &file, "destination": &file, "overwrite": true }),
        )
        .await?;
    assert_err(&res);
    // The file must still be there with its content intact.
    assert_eq!(std::fs::read_to_string(&file)?, "precious");

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
            json!({ "path": outside.to_string_lossy(), "content": content_inline("x") }),
        )
        .await?;
    assert_err(&res);

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn grep_files_outside_allowed_reports_access_denied() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let outside = tmp.path().parent().unwrap().join("outside-grep");
    std::fs::create_dir_all(&outside)?;

    let res = srv
        .call_tool(
            "grep_files",
            json!({ "path": outside.to_string_lossy(), "pattern": "needle" }),
        )
        .await?;
    assert_err(&res);
    let msg = res["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("Access denied"),
        "grep_files should preserve access-denied details, got: {msg}"
    );

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn grep_files_max_matches_is_global_result_limit() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    for i in 0..10 {
        std::fs::write(tmp.path().join(format!("file-{i}.txt")), "needle\nneedle\n")?;
    }

    let res = srv
        .call_tool(
            "grep_files",
            json!({ "path": tmp.path(), "pattern": "needle", "maxMatches": 3 }),
        )
        .await?;
    assert_ok(&res);
    let total = res["result"]["structuredContent"]["totalMatches"]
        .as_u64()
        .unwrap_or(0);
    assert_eq!(
        total, 3,
        "grep_files must cap total returned matches globally"
    );

    srv.kill().await;
    Ok(())
}

// BH-09: clients (mirroring the built-in Grep tool) send `glob` and
// `head_limit`; these must alias to filePattern/maxMatches, not be silently
// dropped (which widened the search to every file and ignored the cap).
#[tokio::test]
async fn grep_files_accepts_glob_and_head_limit_aliases() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    std::fs::write(tmp.path().join("keep.rs"), "needle here\n")?;
    std::fs::write(tmp.path().join("skip.txt"), "needle here\n")?;

    // `glob` must restrict the search to *.rs only.
    let res = srv
        .call_tool(
            "grep_files",
            json!({ "path": tmp.path(), "pattern": "needle", "glob": "*.rs" }),
        )
        .await?;
    assert_ok(&res);
    let text = serde_json::to_string(&res["result"]).unwrap_or_default();
    assert!(
        text.contains("keep.rs"),
        "glob alias must include keep.rs: {text}"
    );
    assert!(
        !text.contains("skip.txt"),
        "glob alias must exclude skip.txt (was the filter silently dropped?): {text}"
    );

    // `head_limit` must cap results like maxMatches.
    for i in 0..10 {
        std::fs::write(tmp.path().join(format!("n-{i}.rs")), "needle\nneedle\n")?;
    }
    let res2 = srv
        .call_tool(
            "grep_files",
            json!({ "path": tmp.path(), "pattern": "needle", "glob": "*.rs", "head_limit": 2 }),
        )
        .await?;
    assert_ok(&res2);
    let total = res2["result"]["structuredContent"]["totalMatches"]
        .as_u64()
        .unwrap_or(0);
    assert_eq!(total, 2, "head_limit alias must cap total matches");

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

    let srv = start_server_with_args(tmp.path(), &["--allow-symlink-escape"]).await?;
    let res = srv
        .call_tool("read_text_file", json!({ "path": &link }))
        .await?;
    assert_eq!(
        res["result"]["content"][0]["text"].as_str().unwrap_or(""),
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
        .call_tool("list_directory", json!({ "path": &dir, "sortBy": "name" }))
        .await?;
    let text = res["result"]["content"][0]["text"].as_str().unwrap_or("");
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
    let text = res["result"]["content"][0]["text"].as_str().unwrap_or("");
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
    let text = res["result"]["content"][0]["text"].as_str().unwrap_or("");
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
    let text = res["result"]["content"][0]["text"].as_str().unwrap_or("");
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
    let text = res["result"]["content"][0]["text"].as_str().unwrap_or("");
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
    let data = res["result"]["content"][0]["data"].as_str().unwrap_or("");
    assert!(!data.is_empty());

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn list_allowed_directories_includes_root() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;

    let res = srv.call_tool("list_allowed_directories", json!({})).await?;
    let text = res["result"]["content"][0]["text"].as_str().unwrap_or("");
    // Server canonicalizes paths (on Windows adds \\?\ prefix), so compare canonicalized
    let canonical = std::fs::canonicalize(tmp.path())?;
    assert!(text.contains(canonical.to_str().unwrap()));

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
        .call_tool(
            "extract_lines",
            json!({ "path": &file, "line": 2, "returnExtracted": true }),
        )
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
            json!({ "path": &file, "offset": 7, "data": {"kind":"base64","data": data}, "mode": "replace" }),
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
            json!({ "path": &file, "offset": 5, "data": {"kind":"base64","data": data}, "mode": "insert" }),
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

#[tokio::test]
async fn session_footer_appended_by_default() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server_with_args(tmp.path(), &[]).await?;
    let file_path = tmp.path().join("footer_probe.txt");

    srv.call_tool(
        "write_file",
        json!({ "path": &file_path, "content": content_inline("probe") }),
    )
    .await?;

    let res = srv
        .call_tool("read_text_file", json!({ "path": &file_path }))
        .await?;
    let text = res["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(text.starts_with("probe"));
    assert!(
        text.contains("[MCP session lock]"),
        "expected session footer in tool text, got: {text}"
    );
    assert_eq!(res["result"]["structuredContent"]["_mcpSessionLock"], true);

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn run_command_accepts_llm_json_shapes() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;

    let minimal = srv
        .call_tool(
            "run_command",
            json!({ "command": "cargo", "args": ["--version"] }),
        )
        .await?;
    assert_ok(&minimal);
    let out = minimal["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(
        out.contains("Completed") || out.contains("exit code"),
        "expected run_command status in text, got: {out}"
    );
    assert_eq!(
        minimal["result"]["structuredContent"]["exitCode"].as_i64(),
        Some(0)
    );

    let stringified_args = srv
        .call_tool(
            "run_command",
            json!({
                "command": "cargo",
                "args": "[\"--version\"]"
            }),
        )
        .await?;
    assert_ok(&stringified_args);

    let snake_case = srv
        .call_tool(
            "run_command",
            json!({
                "command": "cargo",
                "args": ["--version"],
                "stream_output": "true",
                "timeout_ms": 120000
            }),
        )
        .await?;
    assert_ok(&snake_case);

    let cwd_forward = tmp.path().to_string_lossy().replace('\\', "/");
    let with_cwd = srv
        .call_tool(
            "run_command",
            json!({
                "command": "cargo",
                "args": ["--version"],
                "cwd": cwd_forward
            }),
        )
        .await?;
    assert_ok(&with_cwd);

    srv.kill().await;
    Ok(())
}

/// BUG3.md #3: a launched process that exits non-zero is NOT a tool failure.
/// Tools like `grep`/`diff`/`test` use a non-zero exit as information, so the
/// MCP result must stay `is_error == false` while still reporting the code in
/// `structuredContent.exitCode`. Regression guard against re-flagging clean
/// non-zero exits (which fires spurious PostToolUse failure hooks).
#[tokio::test]
async fn run_command_nonzero_exit_is_not_tool_error() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;

    // `cargo <bogus-subcommand>` launches cleanly and exits non-zero.
    let res = srv
        .call_tool(
            "run_command",
            json!({ "command": "cargo", "args": ["this-subcommand-does-not-exist-xyz"] }),
        )
        .await?;

    // Tool call succeeded (no JSON-RPC error, is_error == false) ...
    assert_ok(&res);
    // ... but the command's own exit code is surfaced and is non-zero.
    let code = res["result"]["structuredContent"]["exitCode"].as_i64();
    assert!(
        matches!(code, Some(c) if c != 0),
        "expected a non-zero exit code in structuredContent, got: {code:?}"
    );

    srv.kill().await;
    Ok(())
}

/// BUG3.md #2: a compound command led by a shell builtin (`cd x && ...`) run
/// with shell off fails to spawn the builtin. The error must carry the
/// shell-operator advisory so the caller learns to pass `shell:"bash"`, instead
/// of a bare "Failed to spawn command: cd".
#[tokio::test]
async fn run_command_spawn_failure_includes_operator_hint() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;

    let res = srv
        .call_tool(
            "run_command",
            json!({ "command": "cd nonexistent_dir_xyz && echo hi" }),
        )
        .await?;

    // Spawning the `cd` builtin fails -> a real tool-level error.
    assert_err(&res);
    let msg = res["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("shell") && msg.contains("hint"),
        "spawn-failure error should include the shell-operator hint, got: {msg}"
    );

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn content_plane_blob_write_cyrillic() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file_path = tmp.path().join("cyr.txt");

    let begin = srv.call_tool("blob_begin", json!({})).await?;
    assert_ok(&begin);
    let session_id = begin["result"]["structuredContent"]["sessionId"]
        .as_str()
        .unwrap()
        .to_string();

    let chunk = "\u{0440}\u{0430}\u{0432}\u{043d}\u{0438}\u{043d}\u{0430}\nline2\n";
    assert_eq!(&chunk.as_bytes()[..2], &[0xd1, 0x80]);
    let append = srv
        .call_tool(
            "blob_append",
            json!({ "sessionId": &session_id, "text": chunk }),
        )
        .await?;
    assert_ok(&append);

    let fin = srv
        .call_tool("blob_finalize", json!({ "sessionId": &session_id }))
        .await?;
    assert_ok(&fin);
    let blob_id = fin["result"]["structuredContent"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let write = srv
        .call_tool(
            "write_file",
            json!({ "path": &file_path, "content": content_blob(&blob_id) }),
        )
        .await?;
    assert_ok(&write);

    let text = std::fs::read_to_string(&file_path)?;
    assert_eq!(text, chunk);

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn content_plane_inline_too_large() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let file_path = tmp.path().join("big.txt");
    let big = "x".repeat(8 * 1024 + 1);

    let res = srv
        .call_tool(
            "write_file",
            json!({ "path": &file_path, "content": content_inline(&big) }),
        )
        .await?;
    assert_err(&res);
    let msg = res["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("inline_too_large"),
        "expected inline_too_large, got: {msg}"
    );

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn content_plane_run_command_stdin_inline() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;

    #[cfg(windows)]
    let args = json!({
        "command": "cmd",
        "args": ["/C", "findstr ."],
        "stdin": { "kind": "inline", "text": "hello-stdin" }
    });
    #[cfg(unix)]
    let args = json!({
        "command": "cat",
        "args": [],
        "stdin": { "kind": "inline", "text": "hello-stdin" }
    });

    let res = srv.call_tool("run_command", args).await?;
    assert_ok(&res);
    let stdout = res["result"]["structuredContent"]["stdout"]
        .as_str()
        .unwrap_or("");
    assert!(
        stdout.contains("hello-stdin"),
        "stdout missing stdin payload: {stdout}"
    );

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn content_plane_path_ref_write() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let src = tmp.path().join("src.txt");
    let dst = tmp.path().join("dst.txt");
    std::fs::write(&src, b"from-path-ref\n")?;

    let res = srv
        .call_tool(
            "write_file",
            json!({ "path": &dst, "content": content_path(&src) }),
        )
        .await?;
    assert_ok(&res);
    assert_eq!(std::fs::read_to_string(&dst)?, "from-path-ref\n");

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn content_plane_expect_sha256_ok_and_mismatch() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let path = tmp.path().join("hashed.txt");
    let body = b"expect-sha-body";
    let good = sha256_hex(body);

    let ok = srv
        .call_tool(
            "write_file",
            json!({
                "path": &path,
                "content": content_inline(std::str::from_utf8(body)?),
                "expectSha256": &good,
            }),
        )
        .await?;
    assert_ok(&ok);
    assert_eq!(std::fs::read(&path)?, body);

    let bad = srv
        .call_tool(
            "write_file",
            json!({
                "path": &path,
                "content": content_inline("other"),
                "expectSha256": &good,
            }),
        )
        .await?;
    assert_err(&bad);
    let msg = format!("{bad}");
    assert!(
        msg.contains("hash_mismatch"),
        "expected hash_mismatch, got: {msg}"
    );

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn content_plane_nul_rejected_in_text_mode() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;
    let path = tmp.path().join("nul.txt");
    let payload = b"hello\0world";

    let res = srv
        .call_tool(
            "write_file",
            json!({ "path": &path, "content": content_base64(payload) }),
        )
        .await?;
    assert_err(&res);
    let msg = format!("{res}");
    assert!(
        msg.contains("nul_in_text"),
        "expected nul_in_text, got: {msg}"
    );

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn content_plane_blob_stat() -> Result<()> {
    let tmp = TempDir::new()?;
    let srv = start_server(tmp.path()).await?;

    let begin = srv.call_tool("blob_begin", json!({})).await?;
    assert_ok(&begin);
    let session_id = begin["result"]["structuredContent"]["sessionId"]
        .as_str()
        .unwrap()
        .to_string();

    let chunk = "stat-me";
    let append = srv
        .call_tool(
            "blob_append",
            json!({ "sessionId": &session_id, "text": chunk }),
        )
        .await?;
    assert_ok(&append);

    let fin = srv
        .call_tool("blob_finalize", json!({ "sessionId": &session_id }))
        .await?;
    assert_ok(&fin);
    let blob_id = fin["result"]["structuredContent"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let expected_sha = sha256_hex(chunk.as_bytes());
    assert_eq!(blob_id, expected_sha);

    let st = srv
        .call_tool("blob_stat", json!({ "id": &blob_id }))
        .await?;
    assert_ok(&st);
    let sc = &st["result"]["structuredContent"];
    assert_eq!(sc["bytes"].as_u64().unwrap(), chunk.len() as u64);
    assert_eq!(sc["sha256"].as_str().unwrap(), expected_sha);

    let missing = srv
        .call_tool(
            "blob_stat",
            json!({ "id": "0000000000000000000000000000000000000000000000000000000000000000" }),
        )
        .await?;
    assert_err(&missing);

    srv.kill().await;
    Ok(())
}

#[tokio::test]
async fn read_pdf_cryptomatte_quality_contract() -> Result<()> {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cryptomatte_specification.pdf");
    if !fixture.is_file() {
        eprintln!("skip: missing fixture {}", fixture.display());
        return Ok(());
    }
    let tmp = TempDir::new()?;
    let local = tmp.path().join("cryptomatte_specification.pdf");
    std::fs::copy(&fixture, &local)?;
    let srv = start_server(tmp.path()).await?;

    let res = srv
        .call_tool(
            "read_pdf",
            json!({
                "path": &local,
                "maxChars": 80000,
                "normalize": true,
                "includeRaw": true,
            }),
        )
        .await?;
    assert_ok(&res);
    let sc = &res["result"]["structuredContent"];
    let text = sc["text"].as_str().unwrap_or("");
    assert!(
        text.contains("Table of Contents"),
        "normalized TOC missing: {:?}",
        text.chars().take(160).collect::<String>()
    );
    assert!(!text.contains("Ta ble"));
    let score = sc["quality"]["score"].as_f64().unwrap_or(1.0);
    assert!(score < 0.85, "expected degraded score, got {score}");
    let warnings = sc["quality"]["warnings"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        warnings.iter().any(|w| {
            matches!(
                w.as_str(),
                Some("extraction_quality_degraded")
                    | Some("suspicious_encoding_tokens")
                    | Some("zero_width_chars_present")
            )
        }),
        "expected quality warnings, got {warnings:?}"
    );

    srv.kill().await;
    Ok(())
}
