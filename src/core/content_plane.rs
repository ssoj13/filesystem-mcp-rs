//! Content Plane — single source of truth for tool payload ingress.
//!
//! Control-plane JSON carries a small [`ContentRef`]; bytes live inline (hard
//! size cap), on an allowlisted path, or in a process-local blob session.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Hard max for `inline` / `base64` ContentRef payloads (bytes after decode).
pub const INLINE_MAX_BYTES: usize = 8 * 1024;

/// Hard max per `blob_append` chunk.
pub const CHUNK_MAX_BYTES: usize = 8 * 1024;

/// How resolved bytes will be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentMode {
    /// Reject embedded NUL bytes (text files / stdin scripts).
    Text,
    /// Allow any byte sequence.
    Binary,
}

/// Tagged content reference — object only (no bare-string dual form).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ContentRef {
    /// UTF-8 text, max [`INLINE_MAX_BYTES`].
    Inline { text: String },
    /// Base64-encoded bytes, decoded size max [`INLINE_MAX_BYTES`].
    Base64 { data: String },
    /// Allowlisted filesystem path (resolved by the caller).
    Path { path: String },
    /// Finalized content-addressed blob id (sha256 hex).
    Blob { id: String },
}

#[derive(Debug, Error)]
pub enum ContentError {
    #[error(
        "inline_too_large: {got} bytes exceeds limit of {limit}; stage with blob_begin/blob_append/blob_finalize and pass {{kind:blob,id}}"
    )]
    InlineTooLarge { got: usize, limit: usize },
    #[error("chunk_too_large: {got} bytes exceeds chunk limit of {limit}")]
    ChunkTooLarge { got: usize, limit: usize },
    #[error("blob_not_found: {id}")]
    BlobNotFound { id: String },
    #[error("session_not_found: {id}")]
    SessionNotFound { id: String },
    #[error("hash_mismatch: expected {expected}, got {got}")]
    HashMismatch { expected: String, got: String },
    #[error("nul_in_text: unexpected NUL byte at offset {offset}")]
    NulInText { offset: usize },
    #[error("invalid_base64: {0}")]
    InvalidBase64(String),
    #[error("invalid_utf8: {0}")]
    InvalidUtf8(String),
    #[error("io: {0}")]
    Io(String),
}

impl ContentError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InlineTooLarge { .. } => "inline_too_large",
            Self::ChunkTooLarge { .. } => "chunk_too_large",
            Self::BlobNotFound { .. } => "blob_not_found",
            Self::SessionNotFound { .. } => "session_not_found",
            Self::HashMismatch { .. } => "hash_mismatch",
            Self::NulInText { .. } => "nul_in_text",
            Self::InvalidBase64(_) => "invalid_base64",
            Self::InvalidUtf8(_) => "invalid_utf8",
            Self::Io(_) => "io",
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "code": self.code(),
            "message": self.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct FinalizeResult {
    pub id: String,
    pub bytes: usize,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct BlobStat {
    pub id: String,
    pub bytes: usize,
    pub sha256: String,
}

struct OpenSession {
    path: PathBuf,
    hasher: Sha256,
    bytes: u64,
}

/// Process-local content-addressed blob store + open append sessions.
#[derive(Clone)]
pub struct ContentPlane {
    root: PathBuf,
    sessions: Arc<Mutex<HashMap<String, OpenSession>>>,
    seq: Arc<AtomicU64>,
}

impl ContentPlane {
    pub fn new() -> std::io::Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "filesystem-mcp-rs-blobs-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(root.join("sessions"))?;
        std::fs::create_dir_all(root.join("blobs"))?;
        Ok(Self {
            root,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            seq: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn begin(&self) -> Result<String, ContentError> {
        let id = Uuid::new_v4().to_string();
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let path = self
            .root
            .join("sessions")
            .join(format!("{id}-{seq}.part"));
        std::fs::File::create(&path).map_err(|e| ContentError::Io(e.to_string()))?;
        let mut guard = self
            .sessions
            .lock()
            .map_err(|e| ContentError::Io(e.to_string()))?;
        guard.insert(
            id.clone(),
            OpenSession {
                path,
                hasher: Sha256::new(),
                bytes: 0,
            },
        );
        Ok(id)
    }

    pub fn append(&self, session_id: &str, data: &[u8]) -> Result<(), ContentError> {
        if data.len() > CHUNK_MAX_BYTES {
            return Err(ContentError::ChunkTooLarge {
                got: data.len(),
                limit: CHUNK_MAX_BYTES,
            });
        }
        let mut guard = self
            .sessions
            .lock()
            .map_err(|e| ContentError::Io(e.to_string()))?;
        let session = guard
            .get_mut(session_id)
            .ok_or_else(|| ContentError::SessionNotFound {
                id: session_id.to_string(),
            })?;
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&session.path)
            .map_err(|e| ContentError::Io(e.to_string()))?;
        f.write_all(data)
            .map_err(|e| ContentError::Io(e.to_string()))?;
        session.hasher.update(data);
        session.bytes += data.len() as u64;
        Ok(())
    }

    pub fn finalize(
        &self,
        session_id: &str,
        expect_sha256: Option<&str>,
    ) -> Result<FinalizeResult, ContentError> {
        let mut guard = self
            .sessions
            .lock()
            .map_err(|e| ContentError::Io(e.to_string()))?;
        let session = guard
            .remove(session_id)
            .ok_or_else(|| ContentError::SessionNotFound {
                id: session_id.to_string(),
            })?;
        let digest = session.hasher.finalize();
        let sha256 = hex_encode(&digest);
        if let Some(expected) = expect_sha256
            && !expected.eq_ignore_ascii_case(&sha256)
        {
            let _ = std::fs::remove_file(&session.path);
            return Err(ContentError::HashMismatch {
                expected: expected.to_string(),
                got: sha256,
            });
        }
        let dest = self.root.join("blobs").join(&sha256);
        if dest.exists() {
            let _ = std::fs::remove_file(&session.path);
        } else {
            std::fs::rename(&session.path, &dest).map_err(|e| ContentError::Io(e.to_string()))?;
        }
        Ok(FinalizeResult {
            id: sha256.clone(),
            bytes: session.bytes as usize,
            sha256,
        })
    }

    pub fn stat(&self, id: &str) -> Result<BlobStat, ContentError> {
        let path = self.blob_path(id)?;
        let meta = std::fs::metadata(&path).map_err(|_| ContentError::BlobNotFound {
            id: id.to_string(),
        })?;
        Ok(BlobStat {
            id: id.to_lowercase(),
            bytes: meta.len() as usize,
            sha256: id.to_lowercase(),
        })
    }

    pub fn read_blob(&self, id: &str) -> Result<Vec<u8>, ContentError> {
        let path = self.blob_path(id)?;
        std::fs::read(&path).map_err(|_| ContentError::BlobNotFound {
            id: id.to_string(),
        })
    }

    fn blob_path(&self, id: &str) -> Result<PathBuf, ContentError> {
        let id = id.to_lowercase();
        if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ContentError::BlobNotFound { id });
        }
        let path = self.root.join("blobs").join(&id);
        if !path.is_file() {
            return Err(ContentError::BlobNotFound { id });
        }
        Ok(path)
    }

    /// Resolve a ContentRef to bytes.
    pub async fn resolve<F, Fut>(
        &self,
        content: &ContentRef,
        mode: ContentMode,
        load_path: F,
    ) -> Result<Vec<u8>, ContentError>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<u8>, ContentError>>,
    {
        let bytes = match content {
            ContentRef::Inline { text } => {
                let b = text.as_bytes().to_vec();
                enforce_inline_limit(b.len())?;
                b
            }
            ContentRef::Base64 { data } => {
                let b = BASE64
                    .decode(data.trim())
                    .map_err(|e| ContentError::InvalidBase64(e.to_string()))?;
                enforce_inline_limit(b.len())?;
                b
            }
            ContentRef::Path { path } => load_path(path.clone()).await?,
            ContentRef::Blob { id } => self.read_blob(id)?,
        };
        check_mode(&bytes, mode)?;
        Ok(bytes)
    }

    /// Decode a blob_append payload (text XOR base64).
    pub fn decode_chunk(
        text: Option<&str>,
        data_base64: Option<&str>,
    ) -> Result<Vec<u8>, ContentError> {
        match (text, data_base64) {
            (Some(t), None) => {
                let b = t.as_bytes().to_vec();
                if b.len() > CHUNK_MAX_BYTES {
                    return Err(ContentError::ChunkTooLarge {
                        got: b.len(),
                        limit: CHUNK_MAX_BYTES,
                    });
                }
                Ok(b)
            }
            (None, Some(d)) => {
                let b = BASE64
                    .decode(d.trim())
                    .map_err(|e| ContentError::InvalidBase64(e.to_string()))?;
                if b.len() > CHUNK_MAX_BYTES {
                    return Err(ContentError::ChunkTooLarge {
                        got: b.len(),
                        limit: CHUNK_MAX_BYTES,
                    });
                }
                Ok(b)
            }
            (Some(_), Some(_)) => Err(ContentError::Io(
                "provide either text or dataBase64, not both".into(),
            )),
            (None, None) => Err(ContentError::Io(
                "blob_append requires text or dataBase64".into(),
            )),
        }
    }
}

impl Default for ContentPlane {
    fn default() -> Self {
        Self::new().expect("failed to create content plane temp dir")
    }
}

fn enforce_inline_limit(len: usize) -> Result<(), ContentError> {
    if len > INLINE_MAX_BYTES {
        Err(ContentError::InlineTooLarge {
            got: len,
            limit: INLINE_MAX_BYTES,
        })
    } else {
        Ok(())
    }
}

pub fn check_mode(bytes: &[u8], mode: ContentMode) -> Result<(), ContentError> {
    if mode == ContentMode::Text
        && let Some(offset) = bytes.iter().position(|&b| b == 0)
    {
        return Err(ContentError::NulInText { offset });
    }
    if mode == ContentMode::Text {
        std::str::from_utf8(bytes).map_err(|e| ContentError::InvalidUtf8(e.to_string()))?;
    }
    Ok(())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn inline_limit_rejects() {
        let plane = ContentPlane::new().unwrap();
        let big = "x".repeat(INLINE_MAX_BYTES + 1);
        let r = ContentRef::Inline { text: big };
        let err = rt()
            .block_on(plane.resolve(&r, ContentMode::Text, |_| async { Ok(vec![]) }))
            .unwrap_err();
        assert_eq!(err.code(), "inline_too_large");
    }

    #[test]
    fn nul_rejected_in_text_mode() {
        let plane = ContentPlane::new().unwrap();
        let r = ContentRef::Inline {
            text: "a\0b".into(),
        };
        let err = rt()
            .block_on(plane.resolve(&r, ContentMode::Text, |_| async { Ok(vec![]) }))
            .unwrap_err();
        assert_eq!(err.code(), "nul_in_text");
    }

    #[test]
    fn blob_round_trip_cyrillic() {
        let plane = ContentPlane::new().unwrap();
        let sid = plane.begin().unwrap();
        let chunk = "\u{0440}\u{0430}\u{0432}\u{043d}\u{0438}\u{043d}\u{0430}\nline2\n".as_bytes();
        assert_eq!(&chunk[..2], &[0xd1, 0x80]);
        plane.append(&sid, chunk).unwrap();
        let fin = plane.finalize(&sid, None).unwrap();
        assert_eq!(fin.sha256, sha256_hex(chunk));
        let got = plane.read_blob(&fin.id).unwrap();
        assert_eq!(got, chunk);
        let st = plane.stat(&fin.id).unwrap();
        assert_eq!(st.bytes, chunk.len());
    }

    #[test]
    fn hash_mismatch_on_finalize() {
        let plane = ContentPlane::new().unwrap();
        let sid = plane.begin().unwrap();
        plane.append(&sid, b"hello").unwrap();
        let err = plane.finalize(&sid, Some("deadbeef")).unwrap_err();
        assert_eq!(err.code(), "hash_mismatch");
    }

    #[test]
    fn chunk_too_large() {
        let plane = ContentPlane::new().unwrap();
        let sid = plane.begin().unwrap();
        let big = vec![0u8; CHUNK_MAX_BYTES + 1];
        let err = plane.append(&sid, &big).unwrap_err();
        assert_eq!(err.code(), "chunk_too_large");
    }

    #[test]
    fn content_ref_json_shape() {
        let v = serde_json::json!({"kind": "inline", "text": "hi"});
        let r: ContentRef = serde_json::from_value(v).unwrap();
        match r {
            ContentRef::Inline { text } => assert_eq!(text, "hi"),
            _ => panic!("expected inline"),
        }
        let v = serde_json::json!({"kind": "blob", "id": "abc"});
        let r: ContentRef = serde_json::from_value(v).unwrap();
        match r {
            ContentRef::Blob { id } => assert_eq!(id, "abc"),
            _ => panic!("expected blob"),
        }
    }
}
