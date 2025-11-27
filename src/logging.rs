use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Transport mode for MCP server
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// stdio transport (default) - for local MCP clients
    Stdio,
    /// Streamable HTTP transport - for remote/web access
    Stream,
}

/// Initialize logging based on transport mode
///
/// # stdio mode
/// - NO stderr output by default (prevents connection issues with MCP clients)
/// - File logging only when log_file is Some
///
/// # Stream mode
/// - Normal console (stderr) logging enabled
/// - File logging when log_file is Some (in addition to console)
pub fn init_logging(
    mode: TransportMode,
    log_file: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        TransportMode::Stdio => {
            // CRITICAL: stdio NEVER logs to stderr unless --log is explicitly enabled
            // Any stderr output during handshake causes "connection closed" in MCP clients
            if let Some(filename) = log_file {
                init_file_logging(filename)?;
            }
            // Otherwise: no logging initialization at all
        }
        TransportMode::Stream => {
            // Stream: Always log to stderr, optionally to file
            if let Some(filename) = log_file {
                init_dual_logging(filename)?;
            } else {
                init_console_logging()?;
            }
        }
    }
    Ok(())
}

/// Console-only logging (stderr)
fn init_console_logging() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(fmt::layer().with_writer(std::io::stderr))
        .init();
    Ok(())
}

/// File-only logging
fn init_file_logging(filename: String) -> Result<(), Box<dyn std::error::Error>> {
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

/// Dual logging: both console (stderr) and file
fn init_dual_logging(filename: String) -> Result<(), Box<dyn std::error::Error>> {
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
