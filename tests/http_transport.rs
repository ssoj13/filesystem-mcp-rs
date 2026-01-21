//! Integration tests for HTTP streamable transport mode

use std::path::PathBuf;
use std::time::Duration;
use serial_test::serial;

/// Drop guard to ensure child process is killed even on panic
struct ChildGuard(tokio::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // Try to kill synchronously - best effort
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let pid = self.0.id();
            if let Some(pid) = pid {
                let _ = std::process::Command::new("taskkill")
                    .args(["/F", "/T", "/PID", &pid.to_string()])
                    .creation_flags(0x08000000) // CREATE_NO_WINDOW
                    .output();
            }
        }
        #[cfg(not(windows))]
        {
            let _ = self.0.start_kill();
        }
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

    Err(format!("Server did not start after {} attempts", max_attempts))
}

/// Test that HTTP server starts and health endpoint responds
#[tokio::test]
#[serial]
async fn test_http_server_health_check() {
    let port = find_available_port().await;
    let bind = "127.0.0.1";

    let binary = get_binary_path();
    let _guard = ChildGuard(tokio::process::Command::new(&binary)
        .args(["-s", "-b", bind, "-p", &port.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start server"));

    // Wait for server to be ready (poll up to 20 times = 10 seconds)
    wait_for_server(bind, port, 20)
        .await
        .expect("Server failed to start");

    // Test health endpoint
    let client = reqwest::Client::new();
    let health_url = format!("http://{}:{}/health", bind, port);

    let response = client.get(&health_url)
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

    let binary = get_binary_path();
    let _guard = ChildGuard(tokio::process::Command::new(&binary)
        .args(["-s", "-b", bind, "-p", &port.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start server"));

    // Wait for server to be ready
    wait_for_server(bind, port, 20)
        .await
        .expect("Server failed to start");

    // Test MCP endpoint existence (it should respond, even if we don't send proper MCP request)
    let client = reqwest::Client::new();
    let mcp_url = format!("http://{}:{}/mcp", bind, port);

    // GET request to MCP endpoint (SSE endpoint should be accessible)
    let response = client.get(&mcp_url)
        .send()
        .await
        .expect("Failed to connect to MCP endpoint");

    // The endpoint should be accessible (status might be 200 or other, but not connection refused)
    assert!(response.status().is_success() || response.status().is_client_error());
}

/// Test server on custom port
#[tokio::test]
#[serial]
async fn test_custom_port_and_bind() {
    let port = find_available_port().await;
    let bind = "127.0.0.1";

    let binary = get_binary_path();
    let _guard = ChildGuard(tokio::process::Command::new(&binary)
        .args(["-s", "-b", bind, "-p", &port.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start server"));

    // Wait for server to be ready
    wait_for_server(bind, port, 20)
        .await
        .expect("Server failed to start");

    let client = reqwest::Client::new();
    let health_url = format!("http://{}:{}/health", bind, port);

    let response = client.get(&health_url)
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
    let log_file = format!("test-http-{}.log", port);

    let binary = get_binary_path();
    let _guard = ChildGuard(tokio::process::Command::new(&binary)
        .args(["-s", "-b", bind, "-p", &port.to_string(), "-l", &log_file])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start server"));

    // Wait for server to be ready
    wait_for_server(bind, port, 20)
        .await
        .expect("Server failed to start");

    let client = reqwest::Client::new();
    let health_url = format!("http://{}:{}/health", bind, port);

    let response = client.get(&health_url)
        .send()
        .await
        .expect("Failed to connect");

    assert_eq!(response.status(), 200);

    // Check that log file was created
    let log_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(&log_file);
    assert!(log_path.exists(), "Log file should be created");

    // Clean up log file (guard will kill the server)
    let _ = std::fs::remove_file(&log_path);
}
