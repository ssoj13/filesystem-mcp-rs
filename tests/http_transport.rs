//! Integration tests for HTTP streamable transport mode

use serial_test::serial;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

/// Drop guard to ensure child process is killed even on panic.
///
/// It also owns the child's private state root: that directory has to outlive the process
/// writing into it, and must not outlive the test.
struct ChildGuard {
    child: tokio::process::Child,
    _state: TempDir,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // Try to kill synchronously - best effort
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let pid = self.child.id();
            if let Some(pid) = pid {
                let _ = std::process::Command::new("taskkill")
                    .args(["/F", "/T", "/PID", &pid.to_string()])
                    .creation_flags(0x08000000) // CREATE_NO_WINDOW
                    .output();
            }
        }
        #[cfg(not(windows))]
        {
            let _ = self.child.start_kill();
        }
    }
}

/// Spawn the server binary with a state root of its own.
///
/// Without the override the child resolves the real `~/.filesystem-mcp-rs/` and every test run
/// leaves per-process log files there. `FS_MCP_STATE_DIR` must be absolute — the resolver
/// rejects a relative value at startup — which a `TempDir` path always is.
fn spawn_server(args: &[&str]) -> ChildGuard {
    let state = TempDir::new().expect("Failed to create state dir");
    let child = tokio::process::Command::new(get_binary_path())
        .args(args)
        .env("FS_MCP_STATE_DIR", state.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start server");
    ChildGuard {
        child,
        _state: state,
    }
}

/// Get path to the built binary
fn get_binary_path() -> PathBuf {
    // When running tests, the binary is in target-test/debug/ or target/debug/
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // Try target-test first (used when running with --target-dir)
    let test_binary = manifest_dir.join("target-test/debug/filesystem-mcp-rs");
    if test_binary.exists() || test_binary.with_extension("exe").exists() {
        #[cfg(windows)]
        return test_binary.with_extension("exe");
        #[cfg(not(windows))]
        return test_binary;
    }

    // Fall back to regular target
    let binary = manifest_dir.join("target/debug/filesystem-mcp-rs");
    #[cfg(windows)]
    return binary.with_extension("exe");
    #[cfg(not(windows))]
    return binary;
}

/// Helper function to find an available port
async fn find_available_port() -> u16 {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Wait for server to be ready by polling the health endpoint
async fn wait_for_server(bind: &str, port: u16, max_attempts: u32) -> Result<(), String> {
    let client = reqwest::Client::new();
    let health_url = format!("http://{}:{}/health", bind, port);

    for attempt in 1..=max_attempts {
        tokio::time::sleep(Duration::from_millis(500)).await;

        match client.get(&health_url).send().await {
            Ok(response) if response.status().is_success() => {
                return Ok(());
            }
            _ => {
                if attempt < max_attempts {
                    continue;
                }
            }
        }
    }

    Err(format!(
        "Server did not start after {} attempts",
        max_attempts
    ))
}

/// Test that HTTP server starts and health endpoint responds
#[tokio::test]
#[serial]
async fn test_http_server_health_check() {
    let port = find_available_port().await;
    let bind = "127.0.0.1";

    let _guard = spawn_server(&["-s", "-b", bind, "-p", &port.to_string()]);

    // Wait for server to be ready (poll up to 20 times = 10 seconds)
    wait_for_server(bind, port, 20)
        .await
        .expect("Server failed to start");

    // Test health endpoint
    let client = reqwest::Client::new();
    let health_url = format!("http://{}:{}/health", bind, port);

    let response = client
        .get(&health_url)
        .send()
        .await
        .expect("Failed to connect to health endpoint");

    assert_eq!(response.status(), 200);
    let body = response.text().await.expect("Failed to read response body");
    assert_eq!(body, "OK");
}

/// Test that MCP endpoint is accessible
#[tokio::test]
#[serial]
async fn test_mcp_endpoint_accessible() {
    let port = find_available_port().await;
    let bind = "127.0.0.1";

    let _guard = spawn_server(&["-s", "-b", bind, "-p", &port.to_string()]);

    // Wait for server to be ready
    wait_for_server(bind, port, 20)
        .await
        .expect("Server failed to start");

    // Test MCP endpoint existence (it should respond, even if we don't send proper MCP request)
    let client = reqwest::Client::new();
    let mcp_url = format!("http://{}:{}/mcp", bind, port);

    // GET request to MCP endpoint (SSE endpoint should be accessible)
    let response = client
        .get(&mcp_url)
        .send()
        .await
        .expect("Failed to connect to MCP endpoint");

    // The endpoint should be accessible (status might be 200 or other, but not connection refused)
    assert!(response.status().is_success() || response.status().is_client_error());
}

/// One MCP session over HTTP: initialize, then a `agent_ls` call. Returns the address it was given.
#[cfg(feature = "chat-tools")]
async fn chat_address_of_new_session(client: &reqwest::Client, url: &str) -> String {
    const ACCEPT: &str = "application/json, text/event-stream";
    let init = client
        .post(url)
        .header("Accept", ACCEPT)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "http-test", "version": "1"}
            }
        }))
        .send()
        .await
        .expect("initialize");
    let session = init
        .headers()
        .get("mcp-session-id")
        .expect("session id")
        .to_str()
        .expect("session id text")
        .to_owned();
    init.text().await.expect("initialize body");
    client
        .post(url)
        .header("Accept", ACCEPT)
        .header("mcp-session-id", &session)
        .json(&serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .send()
        .await
        .expect("initialized");
    let body = client
        .post(url)
        .header("Accept", ACCEPT)
        .header("mcp-session-id", &session)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "agent_ls", "arguments": {}}
        }))
        .send()
        .await
        .expect("tools/call")
        .text()
        .await
        .expect("tools/call body");
    let data = body
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .find(|data| data.contains("\"id\":2"))
        .unwrap_or_else(|| panic!("no response in {body}"));
    let value: serde_json::Value = serde_json::from_str(data).expect("response json");
    value["result"]["structuredContent"]["you"]
        .as_str()
        .unwrap_or_else(|| panic!("no address in {value}"))
        .to_owned()
}

/// This process is one agent in the chat however many sessions it serves. A stateless client gets a
/// new service per request, so giving each session its own subscriber would make one per call.
#[cfg(feature = "chat-tools")]
#[tokio::test]
#[serial]
async fn every_http_session_is_the_same_agent_in_the_chat() {
    let port = find_available_port().await;
    let bind = "127.0.0.1";
    let _guard = spawn_server(&["-s", "-b", bind, "-p", &port.to_string()]);
    wait_for_server(bind, port, 20)
        .await
        .expect("Server failed to start");
    let client = reqwest::Client::new();
    let url = format!("http://{bind}:{port}/mcp");
    let first = chat_address_of_new_session(&client, &url).await;
    let second = chat_address_of_new_session(&client, &url).await;
    assert_eq!(first, second);
}

/// Test server on custom port
#[tokio::test]
#[serial]
async fn test_custom_port_and_bind() {
    let port = find_available_port().await;
    let bind = "127.0.0.1";

    let _guard = spawn_server(&["-s", "-b", bind, "-p", &port.to_string()]);

    // Wait for server to be ready
    wait_for_server(bind, port, 20)
        .await
        .expect("Server failed to start");

    let client = reqwest::Client::new();
    let health_url = format!("http://{}:{}/health", bind, port);

    let response = client
        .get(&health_url)
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .expect("Failed to connect");

    assert_eq!(response.status(), 200);
}

/// Test that server with logging enabled starts correctly
#[tokio::test]
#[serial]
async fn test_server_with_logging() {
    let port = find_available_port().await;
    let bind = "127.0.0.1";
    // The log goes into a directory of our own, like the state root does: an absolute `-l` under
    // a `TempDir` cannot leave a stray file in the checkout when the assertions below fail, which
    // a relative path resolved against `CARGO_MANIFEST_DIR` did.
    let log_dir = TempDir::new().expect("Failed to create log dir");
    let log_path = log_dir.path().join(format!("test-http-{}.log", port));
    let log_file = log_path.to_string_lossy().into_owned();

    let _guard = spawn_server(&["-s", "-b", bind, "-p", &port.to_string(), "-l", &log_file]);

    // Wait for server to be ready
    wait_for_server(bind, port, 20)
        .await
        .expect("Server failed to start");

    let client = reqwest::Client::new();
    let health_url = format!("http://{}:{}/health", bind, port);

    let response = client
        .get(&health_url)
        .send()
        .await
        .expect("Failed to connect");

    assert_eq!(response.status(), 200);

    // Check that log file was created. `log_dir` is dropped at the end of the test, taking the
    // file with it whether or not this assertion holds.
    assert!(log_path.exists(), "Log file should be created");
}
