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
use schemars::{JsonSchema, Schema, json_schema};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Hard max for `inline` / `base64` ContentRef payloads (bytes after decode).
/// Max inline content carried in a single tool argument (write_file content,
/// edit snippets, stdin). 64 KiB keeps single-argument payloads bounded (no
/// megabyte smuggling) while not forcing blob staging for ordinary sources —
/// the old 8 KiB tripped real files (BUG.md follow-up, 2026-08-29).
pub const INLINE_MAX_BYTES: usize = 64 * 1024;

/// Hard max per `blob_append` chunk (kept equal to [`INLINE_MAX_BYTES`] so
/// staging large files needs the same number of calls as inline would).
pub const CHUNK_MAX_BYTES: usize = 64 * 1024;

/// How resolved bytes will be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentMode {
    /// Reject embedded NUL bytes (text files / stdin scripts).
    Text,
    /// Allow any byte sequence.
    Binary,
}

/// Tagged content reference — canonical form is an object; a bare string is
/// tolerated as inline text (BUG.md fix 1: hosts that double-encode the
/// argument would otherwise die at deserialization).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
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

/// Object-shape mirror used by the tolerant [`ContentRef`] deserializer.
/// A separate type avoids recursion: the public enum's custom Deserialize
/// dispatches on the incoming JSON shape, then delegates here for objects.
#[derive(serde::Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum ContentRefObject {
    Inline { text: String },
    Base64 { data: String },
    Path { path: String },
    Blob { id: String },
}

impl From<ContentRefObject> for ContentRef {
    fn from(o: ContentRefObject) -> Self {
        match o {
            ContentRefObject::Inline { text } => Self::Inline { text },
            ContentRefObject::Base64 { data } => Self::Base64 { data },
            ContentRefObject::Path { path } => Self::Path { path },
            ContentRefObject::Blob { id } => Self::Blob { id },
        }
    }
}

impl<'de> Deserialize<'de> for ContentRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        Self::tolerant_from_value(value).map_err(DeError::custom)
    }
}

impl ContentRef {
    /// Tolerant parse (BUG.md): canonical object OR string forms.
    ///
    /// - object → canonical tagged parse (unknown fields ignored, as before)
    /// - string starting with `{` → must parse as a JSON object holding a
    ///   ContentRef (double-encoded form); failures are LOUD with line/column
    ///   from serde_json (BUG.md fix 2) — a mangled encoding must not silently
    ///   become file content
    /// - any other string → inline text
    pub fn tolerant_from_value(value: serde_json::Value) -> Result<Self, String> {
        match value {
            serde_json::Value::Object(_) => {
                let o = ContentRefObject::deserialize(value)
                    .map_err(|e| format!("content: invalid ContentRef object: {e}"))?;
                Ok(o.into())
            }
            serde_json::Value::String(s) => Self::tolerant_from_str(&s),
            other => Err(format!(
                "content: expected object {{kind:inline|base64|path|blob}} or string, got {}",
                json_type_name(&other)
            )),
        }
    }

    /// String-form tolerance: unwrap a double-encoded ContentRef, else inline.
    pub fn tolerant_from_str(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.starts_with('{') {
            // Looks like a (possibly double-encoded) ContentRef. serde_json's
            // error carries "at line L column C" — the actionable detail the
            // old opaque message lacked.
            let parsed: serde_json::Value = serde_json::from_str(trimmed)
                .map_err(|e| format!("content: string looks like a JSON object but failed to parse: {e} (fix escaping or stage via blob)"))?;
            let o = ContentRefObject::deserialize(parsed)
                .map_err(|e| format!("content: string holds JSON but not a ContentRef object: {e}"))?;
            return Ok(o.into());
        }
        Ok(ContentRef::Inline { text: s.to_string() })
    }
}

fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
        serde_json::Value::String(_) => "string",
    }
}

/// Search/replace snippet for `edit_file` / `bulk_edits`.
///
/// [`ContentRef`] stays object-only so `write_file` / `stdin` cannot smuggle a
/// megabyte through tool-argument JSON. Edit snippets are different: hosts
/// (Grok) drop nested `{kind:inline,text}` objects — especially when `text`
/// contains `{` — and the call dies as `missing field newText`. A bare string
/// is the natural form for a 40-byte Rust replace and survives that parser.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum TextOrRef {
    Text(String),
    Ref(ContentRef),
}

impl TextOrRef {
    /// Owned [`ContentRef`] for the resolve path.
    pub fn into_ref(self) -> ContentRef {
        match self {
            Self::Text(text) => ContentRef::Inline { text },
            Self::Ref(r) => r,
        }
    }
}

impl<'de> Deserialize<'de> for TextOrRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(text) => Ok(Self::Text(text)),
            other => {
                let r = ContentRef::deserialize(other).map_err(DeError::custom)?;
                Ok(Self::Ref(r))
            }
        }
    }
}

impl JsonSchema for TextOrRef {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("TextOrRef")
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed(concat!(module_path!(), "::TextOrRef"))
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> Schema {
        let content = ContentRef::json_schema(generator);
        json_schema!({
            "anyOf": [
                {
                    "type": "string",
                    "description": "UTF-8 search/replace text. Prefer this for short snippets (including `{` in Rust)."
                },
                content
            ]
        })
    }
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
        let root =
            std::env::temp_dir().join(format!("filesystem-mcp-rs-blobs-{}", std::process::id()));
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
        let path = self.root.join("sessions").join(format!("{id}-{seq}.part"));
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
        let meta = std::fs::metadata(&path)
            .map_err(|_| ContentError::BlobNotFound { id: id.to_string() })?;
        Ok(BlobStat {
            id: id.to_lowercase(),
            bytes: meta.len() as usize,
            sha256: id.to_lowercase(),
        })
    }

    pub fn read_blob(&self, id: &str) -> Result<Vec<u8>, ContentError> {
        let path = self.blob_path(id)?;
        std::fs::read(&path).map_err(|_| ContentError::BlobNotFound { id: id.to_string() })
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

    /// BUG.md fix 1: bare string → inline text.
    #[test]
    fn tolerant_bare_string_is_inline() {
        let r: ContentRef = serde_json::from_str("\"plain text content\"").unwrap();
        assert_eq!(r, ContentRef::Inline { text: "plain text content".into() });
    }

    /// BUG.md fix 1: double-encoded ContentRef object is unwrapped.
    #[test]
    fn tolerant_double_encoded_object() {
        let inner = serde_json::json!({ "kind": "inline", "text": "hi" });
        let wire = serde_json::Value::String(inner.to_string());
        let r: ContentRef = serde_json::from_value(wire).unwrap();
        assert_eq!(r, ContentRef::Inline { text: "hi".into() });
    }

    /// BUG.md fix 1: canonical object form unchanged.
    #[test]
    fn tolerant_object_passthrough() {
        let r: ContentRef =
            serde_json::from_str("{\"kind\":\"blob\",\"id\":\"abc\"}").unwrap();
        assert_eq!(r, ContentRef::Blob { id: "abc".into() });
    }

    /// BUG.md fix 2: malformed `{`-string fails LOUDLY with serde line/column.
    #[test]
    fn tolerant_mangled_object_is_loud() {
        let err = ContentRef::tolerant_from_str("{kind: inline").unwrap_err();
        assert!(err.contains("line"), "error must carry line/column: {err}");
    }

    /// Non-string non-object shapes stay a clear error.
    #[test]
    fn tolerant_rejects_other_shapes() {
        assert!(ContentRef::tolerant_from_value(serde_json::json!(42)).is_err());
        assert!(ContentRef::tolerant_from_value(serde_json::json!(null)).is_err());
    }

    /// A JSON object that is NOT a ContentRef fails with a field-level error.
    #[test]
    fn tolerant_wrong_object_shape_is_loud() {
        let err = ContentRef::tolerant_from_value(serde_json::json!({ "kind": "inline" }))
            .unwrap_err();
        assert!(err.contains("text"), "error must name the missing field: {err}");
    }

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

    #[test]
    fn text_or_ref_accepts_string_with_braces() {
        let r: TextOrRef = serde_json::from_value(serde_json::json!("use foo::{Bar};")).unwrap();
        match r.into_ref() {
            ContentRef::Inline { text } => assert_eq!(text, "use foo::{Bar};"),
            _ => panic!("expected inline"),
        }
    }

    #[test]
    fn text_or_ref_accepts_content_ref_object() {
        let r: TextOrRef = serde_json::from_value(serde_json::json!({
            "kind": "inline",
            "text": "hi"
        }))
        .unwrap();
        match r {
            TextOrRef::Ref(ContentRef::Inline { text }) => assert_eq!(text, "hi"),
            _ => panic!("expected ref"),
        }
    }
}
