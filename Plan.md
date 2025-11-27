# Implementation Plan: Dual-Mode Transport for filesystem-mcp-rs

## Overview

Add support for two transport modes to filesystem-mcp-rs MCP server:
- **stdio mode** (default): Local CLI integration
- **streamable HTTP mode**: Remote web/API access

## Goals

1. Maintain backward compatibility with existing stdio usage
2. Enable remote access via HTTP with proper session management
3. Implement correct logging strategy per transport mode
4. Provide intuitive CLI interface with help flags

## Transport Modes

### stdio Mode (Default)
- **Use case**: Local MCP clients (Claude Desktop, Cursor, etc.)
- **Logging**: NO stderr output by default (prevents connection issues)
- **Activation**: Default behavior when no `-s` flag
- **Log options**:
  - `--log`: Enable file logging to `filesystem-mcp-rs.log`
  - `--log-file <name>`: Custom log file name

**Critical Note**: stdio transport MUST NOT write to stderr during handshake. Any stderr output causes "connection closed" in MCP clients (see main.rs:1221-1225).

### Streamable HTTP Mode
- **Use case**: Remote access, web integrations, cloud deployments
- **Logging**: Normal console (stderr) and file logging enabled
- **Activation**: `-s` or `--stream` flag
- **Configuration**:
  - `--bind <addr>`: Bind address (default: `127.0.0.1`)
  - `--port <port>`: HTTP port (default: `8000`)
  - `--log`: Enable file logging alongside console
  - `--log-file <name>`: Custom log file name

**Default endpoint**: `http://127.0.0.1:8000/mcp`

## CLI Interface

### Flags Summary

```
Usage: filesystem-mcp-rs [OPTIONS] [DIRS...]

Arguments:
  [DIRS...]  Allowed directories (fallback if client doesn't support roots)

Options:
      --allow-symlink-escape  Allow symlinks outside allowed dirs
  -s, --stream                Enable streamable HTTP mode (default: stdio)
  -p, --port <PORT>           HTTP port for stream mode [default: 8000]
  -b, --bind <ADDR>           Bind address for stream mode [default: 127.0.0.1]
  -l, --log [<FILE>]          Enable file logging. Optionally specify log file name [default: filesystem-mcp-rs.log]
  -h, --help                  Print help
  -V, --version               Print version
```

### Usage Examples

```bash
# stdio mode (default) - no logging
filesystem-mcp-rs /path/to/allowed/dir

# stdio mode with file logging (default: filesystem-mcp-rs.log)
filesystem-mcp-rs -l /path/to/allowed/dir

# stdio mode with custom log file
filesystem-mcp-rs -l custom.log /path/to/allowed/dir

# Stream mode on default port (localhost:8000)
filesystem-mcp-rs -s

# Stream mode on custom port
filesystem-mcp-rs -s -p 9000

# Stream mode accessible from network (short flags)
filesystem-mcp-rs -s -b 0.0.0.0 -p 8000

# Stream mode with file logging (default filename)
filesystem-mcp-rs -s -l

# Stream mode with custom log file
filesystem-mcp-rs -s -l myserver.log
```

## Implementation Phases

### Phase 1: Project Structure (30-40 min)

**1.1. Update Cargo.toml**

Add dependencies:
```toml
[dependencies]
# Existing dependencies...
axum = "0.7"
tower = "0.5"
tower-http = { version = "0.5", features = ["cors", "trace"] }
tokio-util = "0.7"
```

Update rmcp features (verify available features):
```toml
rmcp = { version = "0.9.0", features = [
  "transport-io",
  "server",
  "macros",
  "transport-streamable-http"  # or similar HTTP transport feature
] }
```

**1.2. Extend Args struct**

File: `src/main.rs`

```rust
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Allowed directories (fallback if client does not support roots)
    #[arg(value_name = "DIR", num_args = 0..)]
    allowed_dirs: Vec<PathBuf>,

    /// Allow symlinks to point outside the allowed directories
    #[arg(long, default_value_t = false)]
    allow_symlink_escape: bool,

    /// Enable streamable HTTP mode (default: stdio)
    #[arg(short = 's', long = "stream")]
    stream_mode: bool,

    /// HTTP port for stream mode
    #[arg(short = 'p', long, default_value = "8000")]
    port: u16,

    /// Bind address for stream mode
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

    /// Enable file logging
    #[arg(short = 'l', long)]
    log: bool,

    /// Custom log file name
    #[arg(long)]
    log_file: Option<String>,
}
```

### Phase 2: Logging System (20-30 min)

**2.1. Create src/logging.rs**

```rust
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    Stdio,
    Stream,
}

pub fn init_logging(
    mode: TransportMode,
    log_enabled: bool,
    log_file: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        TransportMode::Stdio => {
            // stdio: NEVER log to stderr unless --log is explicitly enabled
            if log_enabled {
                init_file_logging(log_file)?;
            }
            // Otherwise: no logging initialization at all
        }
        TransportMode::Stream => {
            // stream: Always log to stderr, optionally to file
            if log_enabled {
                init_dual_logging(log_file)?;
            } else {
                init_console_logging()?;
            }
        }
    }
    Ok(())
}

fn init_console_logging() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();
    Ok(())
}

fn init_file_logging(log_file: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let filename = log_file.unwrap_or_else(|| "filesystem-mcp-rs.log".to_string());
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&filename)?;

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(fmt::layer().with_writer(file).with_ansi(false))
        .init();
    Ok(())
}

fn init_dual_logging(log_file: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let filename = log_file.unwrap_or_else(|| "filesystem-mcp-rs.log".to_string());
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&filename)?;

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(fmt::layer().with_writer(file).with_ansi(false))
        .init();
    Ok(())
}
```

**2.2. Add module to main.rs**

```rust
mod logging;
use logging::{init_logging, TransportMode};
```

### Phase 3: Streamable HTTP Transport (1-1.5 hours)

**3.1. Implement HTTP server function**

Add to `src/main.rs`:

```rust
use axum::{Router, routing::get};
use rmcp::transport::streamable_http::{StreamableHttpService, LocalSessionManager};

async fn run_stream_mode(
    server: FileSystemServer,
    bind: &str,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create streamable HTTP service with session management
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    // Build router with MCP endpoint
    let app = Router::new()
        .nest_service("/mcp", service)
        .route("/health", get(|| async { "OK" })); // Optional health check

    let addr = format!("{}:{}", bind, port);
    tracing::info!("Starting MCP HTTP server on http://{}/mcp", addr);

    // Start server
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn run_stdio_mode(
    server: FileSystemServer,
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = stdio();
    let svc = server.serve(transport).await?;
    svc.waiting().await?;
    Ok(())
}
```

### Phase 4: Main Function Integration (20-30 min)

**4.1. Refactor main()**

```rust
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
    init_logging(mode, args.log, args.log_file.clone())?;

    // Create server instance
    let allowed = AllowedDirs::new(args.allowed_dirs);
    let mut server = FileSystemServer::new(allowed);
    server.allow_symlink_escape = args.allow_symlink_escape;

    // Run in selected mode
    match mode {
        TransportMode::Stdio => {
            run_stdio_mode(server).await
        }
        TransportMode::Stream => {
            run_stream_mode(server, &args.bind, args.port).await
        }
    }
}
```

### Phase 5: Testing & Documentation (30-40 min)

**5.1. Testing Checklist**

- [ ] stdio mode works without any stderr output
- [ ] stdio mode with `--log` creates log file
- [ ] stream mode starts HTTP server on correct address/port
- [ ] stream mode logs to console by default
- [ ] stream mode with `--log` creates log file + console
- [ ] Help flags work: `-h`, `--help`
- [ ] Version flag works: `-V`, `--version`
- [ ] MCP client can connect to stdio mode
- [ ] MCP client can connect to stream mode via HTTP
- [ ] Session management works correctly in stream mode

**5.2. Update README.md**

Add section on transport modes with examples (see CLI Interface section above).

**5.3. Create CHANGELOG.md entry**

```markdown
## [Unreleased]

### Added
- Streamable HTTP transport mode for remote access
- Dual-mode operation: stdio (default) and stream modes
- Configurable logging per transport mode
- HTTP server with session management
- Health check endpoint at /health
- CLI flags: --stream, --port, --bind, --log, --log-file

### Changed
- Logging disabled by default in stdio mode (prevents connection issues)
- Main function refactored to support multiple transport modes
```

### Phase 6: Optional Enhancements (20-30 min)

**6.1. Graceful Shutdown**

Add Ctrl+C handler:

```rust
use tokio::signal;

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received");
}

// In run_stream_mode:
axum::serve(listener, app)
    .with_graceful_shutdown(shutdown_signal())
    .await?;
```

**6.2. Enhanced Health Check**

```rust
use serde_json::json;

async fn health_check() -> axum::Json<serde_json::Value> {
    axum::Json(json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "mode": "streamable-http"
    }))
}

// In router:
.route("/health", get(health_check))
```

## TLS/HTTPS Support (Future Enhancement)

### Certificate Sources

**Development:**
- **Self-signed certificates**: Generate with `openssl` or `mkcert`
- **mkcert** (recommended): Creates locally-trusted certificates
  ```bash
  mkcert -install
  mkcert localhost 127.0.0.1 ::1
  # Creates: localhost+2.pem, localhost+2-key.pem
  ```

**Production:**
- **Let's Encrypt**: Free automated certificates (requires domain)
- **Commercial CAs**: DigiCert, GlobalSign, Sectigo
- **Cloud providers**: AWS ACM, Azure Key Vault, GCP Certificate Manager
- **Internal PKI**: Company-managed certificate authority

### TLS Implementation Complexity

**Difficulty**: Medium (additional 1-2 hours)

**Required Dependencies:**
```toml
axum-server = { version = "0.7", features = ["tls-rustls"] }
rustls = "0.23"
rustls-pemfile = "2.0"
tokio-rustls = "0.26"
```

**Additional CLI Args:**
```rust
#[arg(long, requires = "key_file")]
cert_file: Option<PathBuf>,

#[arg(long, requires = "cert_file")]
key_file: Option<PathBuf>,
```

**Implementation:**
```rust
use axum_server::tls_rustls::RustlsConfig;

async fn run_stream_mode_tls(
    server: FileSystemServer,
    bind: &str,
    port: u16,
    cert_path: PathBuf,
    key_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = RustlsConfig::from_pem_file(cert_path, key_path).await?;

    let app = /* same as before */;
    let addr = format!("{}:{}", bind, port);

    tracing::info!("Starting HTTPS server on https://{}/mcp", addr);

    axum_server::bind_rustls(addr.parse()?, config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
```

**Total additions**: ~100 lines of code

### Decision: TLS Later

We'll implement TLS in a separate phase because:
1. HTTP is sufficient for localhost development/testing
2. Production deployments often use reverse proxy (nginx, Caddy) for TLS
3. Adds complexity without immediate value for local use case
4. Can be added later without breaking existing functionality

## Time Estimates

| Phase | Minimum | With Testing | With Polish |
|-------|---------|--------------|-------------|
| Phase 1: Structure | 30 min | 40 min | 40 min |
| Phase 2: Logging | 20 min | 30 min | 30 min |
| Phase 3: HTTP Transport | 60 min | 80 min | 90 min |
| Phase 4: Integration | 20 min | 30 min | 30 min |
| Phase 5: Testing & Docs | - | 40 min | 60 min |
| Phase 6: Enhancements | - | - | 30 min |
| **Total** | **2.2 hrs** | **3.7 hrs** | **4.7 hrs** |

## Success Criteria

- [x] Plan documented and approved
- [x] Backward compatibility maintained (stdio mode unchanged)
- [x] No stderr output in stdio mode by default
- [x] HTTP server starts and accepts MCP connections
- [x] Logging works correctly in both modes
- [x] Help and version flags work
- [x] README updated with usage examples
- [x] All tests pass (29 tests: 10 unit + 19 integration)
- [x] No compiler warnings

## References

- [Shuttle.dev Stream MCP Article](https://www.shuttle.dev/blog/2025/10/29/stream-http-mcp)
- [MCP Specification](https://modelcontextprotocol.io/spec)
- [rmcp SDK Documentation](https://docs.rs/rmcp)
- [Axum Web Framework](https://docs.rs/axum)

## Notes

- Critical: stdio transport must never write to stderr during handshake
- Default bind address 127.0.0.1 provides security by default
- Health check endpoint optional but useful for monitoring
- TLS support deferred to separate implementation
- Consider adding metrics/telemetry in future enhancement
