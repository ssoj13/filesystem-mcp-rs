//! Integration tests for HTTP streamable transport mode

use std::path::PathBuf;
use std::time::Duration;

/// Helper function to find an available port
async fn find_available_port() -> u16 {
    // Use a random port in the ephemeral range
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
async fn test_http_server_health_check() {
    let port = find_available_port().await;
    let bind = "127.0.0.1";

    let mut child = tokio::process::Command::new("cargo")
        .args(["run", "--", "-s", "-b", bind, "-p", &port.to_string()])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start server");

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

    // Cleanup
    child.kill().await.expect("Failed to kill server");
}

/// Test that MCP endpoint is accessible
#[tokio::test]
async fn test_mcp_endpoint_accessible() {
    let port = find_available_port().await;
    let bind = "127.0.0.1";

    let mut child = tokio::process::Command::new("cargo")
        .args(["run", "--", "-s", "-b", bind, "-p", &port.to_string()])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start server");

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

    // Cleanup
    child.kill().await.expect("Failed to kill server");
}

/// Test server on custom port
#[tokio::test]
async fn test_custom_port_and_bind() {
    let port = find_available_port().await;
    let bind = "127.0.0.1";

    let mut child = tokio::process::Command::new("cargo")
        .args(["run", "--", "-s", "-b", bind, "-p", &port.to_string()])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start server");

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

    // Cleanup
    child.kill().await.expect("Failed to kill server");
}

/// Test that server with logging enabled starts correctly
#[tokio::test]
async fn test_server_with_logging() {
    let port = find_available_port().await;
    let bind = "127.0.0.1";
    let log_file = format!("test-http-{}.log", port);

    let mut child = tokio::process::Command::new("cargo")
        .args(["run", "--", "-s", "-b", bind, "-p", &port.to_string(), "-l", &log_file])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start server");

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

    // Cleanup
    child.kill().await.expect("Failed to kill server");
    let _ = std::fs::remove_file(&log_path); // Clean up log file
}
