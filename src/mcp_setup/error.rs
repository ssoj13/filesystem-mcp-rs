//! Error types for setup operations.

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SetupError {
    #[error("invalid home directory")]
    InvalidHome,

    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("settings file is not valid JSON: {path}")]
    InvalidJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("settings root must be a JSON object: {path}")]
    ExpectedJsonObject { path: PathBuf },

    #[error(
        "refusing to overwrite MCP server {key:?}: already present with a different install_id (expected {expected:?}, found {found:?})"
    )]
    McpKeyConflict {
        key: String,
        expected: Option<String>,
        found: Option<String>,
    },

    #[error(
        "refusing to remove MCP server {key:?}: entry is not managed by this installer (missing or mismatched {install_id_key})"
    )]
    NotOurInstall {
        key: String,
        install_id_key: &'static str,
    },

    #[error("manifest is inconsistent with settings.json: {0}")]
    ManifestConflict(String),

    #[error("unknown client {0:?} (see `--client` help for the supported list)")]
    UnknownClient(String),

    #[error("{client} does not appear to be installed ({hint})")]
    HostNotDetected { client: &'static str, hint: String },

    #[error("Codex: {detail}")]
    CodexConfigFailed { detail: String },

    #[error("invalid project root: {path} ({reason})")]
    InvalidProjectRoot { path: PathBuf, reason: String },

    #[error("{client} does not support {scope} scope")]
    UnsupportedScope {
        client: &'static str,
        scope: &'static str,
    },

    #[error("invalid MCP setup bundle: {0}")]
    InvalidBundle(String),
}

impl SetupError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, SetupError>;
