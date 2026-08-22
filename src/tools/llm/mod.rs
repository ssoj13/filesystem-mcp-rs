pub mod config;
pub mod error;
pub mod model;

// Re-exports for integration
pub mod model_mapping;
pub mod providers;
pub mod transform;

use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context, Result, bail};
use futures::StreamExt;
use reqwest::Client;
use reqwest::header::HeaderName;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, ContentBlock, Implementation, ProgressNotificationParam, RequestMetaObject,
        ServerCapabilities, ServerInfo,
    },
    service::Peer,
    tool, tool_handler, tool_router,
};
use serde_json::{Value, json};
use tracing::{debug, info, warn};
use uuid::Uuid;

use self::config::load_config;
use self::error::classify_provider_error;
use self::model::{
    MessagesRequest, MessagesResponse, ResponseContentBlock, TokenCountRequest, TokenCountResponse,
    Usage,
};
use self::model_mapping::ModelManager;
use self::providers::{known_providers, provider_by_name};
use self::transform::{
    convert_anthropic_to_openai, convert_openai_to_anthropic, map_finish_reason,
};
use crate::core::schema::normalize_tool_schemas;

#[derive(Clone)]
pub struct AppState {
    pub config: config::Config,
    pub model_manager: ModelManager,
    pub client: Client,
    pub dialog_log_file: Option<String>,
    pub available_providers: std::collections::HashSet<String>,
}

#[derive(Clone)]
pub struct LlmMcpServer {
    state: AppState,
    /// Must be used for dispatch (`#[tool_handler(router = self.tool_router)]`) so `filter_provider_tools`
    /// and `normalize_tool_schemas` from `LlmMcpServer::new()` apply to `list_tools` / `call_tool`.
    tool_router: ToolRouter<Self>,
}

impl LlmMcpServer {
    pub fn new(state: AppState) -> Self {
        let mut tool_router = Self::tool_router();
        filter_provider_tools(&mut tool_router, &state);
        normalize_tool_schemas(&mut tool_router);
        Self { state, tool_router }
    }

    pub fn available_providers(&self) -> &std::collections::HashSet<String> {
        &self.state.available_providers
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    fn server_info(&self) -> ServerInfo {
        let mut impl_info = Implementation::default();
        impl_info.name = "llm-mcp-rs".to_string();
        impl_info.version = env!("CARGO_PKG_VERSION").to_string();
        impl_info.title = Some("LLM MCP Bridge".to_string());

        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = impl_info;
        info.instructions = Some(
            "Claude Messages API-compatible tools.\n\
            Use `messages` for chat; `count_tokens` for input token estimates.\n\
            Provider-specific tools (if available): `messages_gemini`, `messages_cerebras`, `messages_openai`, `count_tokens_gemini`, `count_tokens_cerebras`, `count_tokens_openai`.\n\
            Request: { model, max_tokens, messages:[{role, content}], system?, tools?, tool_choice?, stream? }.\n\
            Response: Anthropic-style message with `content` blocks and `stop_reason`.\n\
            Tool use: send `tools` with JSON Schema; model returns `tool_use` blocks. You then send `tool_result` in a user message.\n\
            Streaming: `stream=true` + progress token ⇒ events via `notifications/progress` (JSON strings).\n\
            Minimal: model=\"gemini-3-pro-preview\", max_tokens=256, messages=[{role:\"user\", content:\"Hello\"}].\n\
            Tool roundtrip: assistant → {type:\"tool_use\", name, id, input}; client → user message with {type:\"tool_result\", tool_use_id, content}."
                .to_string(),
        );
        info
    }

    fn auth_header_for(&self, provider: &str) -> Result<(HeaderName, String), McpError> {
        let key = self
            .state
            .config
            .effective_api_key_for(provider)
            .ok_or_else(|| McpError::invalid_params("Missing API key", None))?;
        let header = HeaderName::from_bytes(self.state.config.provider_api_key_header.as_bytes())
            .map_err(|e| {
            McpError::invalid_params(
                format!("Invalid LLM_MCP_PROVIDER_API_KEY_HEADER: {e}"),
                None,
            )
        })?;
        let value = format!("{}{}", self.state.config.provider_api_key_prefix, key);
        Ok((header, value))
    }
}

#[tool_router]
impl LlmMcpServer {
    #[tool(
        name = "ai_messages",
        description = "Claude Messages API-compatible conversation tool. Supports tools, tool_choice, and streaming via progress notifications."
    )]
    async fn messages(
        &self,
        Parameters(request): Parameters<MessagesRequest>,
        meta: RequestMetaObject,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let provider = self.state.config.primary_provider();
        self.messages_for_provider(&provider, request, meta, client)
            .await
    }

    #[tool(
        name = "ai_messages_gemini",
        description = "Claude Messages API-compatible conversation tool backed by Gemini."
    )]
    async fn messages_gemini(
        &self,
        Parameters(request): Parameters<MessagesRequest>,
        meta: RequestMetaObject,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.messages_for_provider("gemini", request, meta, client)
            .await
    }

    #[tool(
        name = "ai_messages_cerebras",
        description = "Claude Messages API-compatible conversation tool backed by Cerebras."
    )]
    async fn messages_cerebras(
        &self,
        Parameters(request): Parameters<MessagesRequest>,
        meta: RequestMetaObject,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.messages_for_provider("cerebras", request, meta, client)
            .await
    }

    #[tool(
        name = "ai_messages_openai",
        description = "Claude Messages API-compatible conversation tool backed by OpenAI."
    )]
    async fn messages_openai(
        &self,
        Parameters(request): Parameters<MessagesRequest>,
        meta: RequestMetaObject,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.messages_for_provider("openai", request, meta, client)
            .await
    }

    pub async fn messages_for_provider(
        &self,
        provider: &str,
        mut request: MessagesRequest,
        meta: RequestMetaObject,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let original_model = request.model.clone();
        let (mapped, _) = self.state.model_manager.validate_and_map_model(
            &request.model,
            provider,
            self.state.config.model_mapping_mode,
        );
        request.model = mapped.clone();
        debug!(
            "model mapping provider={} original={} mapped={}",
            provider, original_model, mapped
        );

        if request.stream.unwrap_or(false) && self.state.config.emergency_disable_streaming {
            warn!("Streaming disabled via LLM_MCP_EMERGENCY_DISABLE_STREAMING");
            request.stream = Some(false);
        }
        if request.stream.unwrap_or(false) && self.state.config.force_disable_streaming {
            info!("Streaming disabled via LLM_MCP_FORCE_DISABLE_STREAMING");
            request.stream = Some(false);
        }

        let mut body = convert_anthropic_to_openai(&request, &self.state.config);
        if let Some(adapter) = provider_by_name(provider) {
            adapter.prepare_request_body(&mut body);
        }
        body["stream"] = json!(request.stream.unwrap_or(false));

        let stream_requested = request.stream.unwrap_or(false);
        let progress_token = meta.get_progress_token();

        if stream_requested && progress_token.is_some() {
            match self
                .stream_with_retries(
                    &body,
                    &original_model,
                    &request.model,
                    progress_token,
                    &client,
                    provider,
                )
                .await
            {
                Ok(response) => {
                    let structured = serde_json::to_value(&response).unwrap_or(json!({}));
                    log_dialog(&self.state.dialog_log_file, &request, &response);
                    return Ok(CallToolResult::success(vec![ContentBlock::text("ok")])
                        .with_structured(structured));
                }
                Err(err) => {
                    warn!("Streaming failed, falling back to non-streaming: {}", err);
                    body["stream"] = json!(false);
                }
            }
        } else if stream_requested {
            warn!(
                "Streaming requested but no progress token provided; falling back to non-streaming"
            );
            body["stream"] = json!(false);
        }

        let response = match post_with_retries(
            &self.state.client,
            &self.state.config,
            &body,
            self.state.config.max_retries,
            self.state.config.retry_backoff_ms,
            self.auth_header_for(provider)?,
            provider,
        )
        .await
        {
            Ok(resp) => resp,
            Err(err) => {
                let msg = classify_provider_error(&err.to_string());
                return Err(McpError::internal_error(msg, None));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            let msg = classify_provider_error(&text);
            return Err(McpError::internal_error(
                format!("Upstream error {status}: {msg}"),
                None,
            ));
        }

        let mut response_json = match response.json::<Value>().await {
            Ok(val) => val,
            Err(err) => {
                let msg = classify_provider_error(&err.to_string());
                return Err(McpError::internal_error(msg, None));
            }
        };
        if let Some(adapter) = provider_by_name(provider) {
            adapter.postprocess_response(&mut response_json);
        }

        let mut anthropic_response = convert_openai_to_anthropic(&response_json, &original_model);
        anthropic_response.metadata = Some(json!({ "actual_model": request.model }));
        log_dialog(&self.state.dialog_log_file, &request, &anthropic_response);
        Ok(CallToolResult::success(vec![ContentBlock::text("ok")])
            .with_structured(serde_json::to_value(&anthropic_response).unwrap_or(json!({}))))
    }

    #[tool(
        name = "ai_count_tokens",
        description = "Claude Messages API-compatible token counting. Returns input_tokens based on provider usage."
    )]
    async fn count_tokens(
        &self,
        Parameters(request): Parameters<TokenCountRequest>,
    ) -> Result<CallToolResult, McpError> {
        let provider = self.state.config.primary_provider();
        self.count_tokens_for_provider(&provider, request).await
    }

    #[tool(
        name = "ai_count_tokens_gemini",
        description = "Claude Messages API-compatible token counting backed by Gemini."
    )]
    async fn count_tokens_gemini(
        &self,
        Parameters(request): Parameters<TokenCountRequest>,
    ) -> Result<CallToolResult, McpError> {
        self.count_tokens_for_provider("gemini", request).await
    }

    #[tool(
        name = "ai_count_tokens_cerebras",
        description = "Claude Messages API-compatible token counting backed by Cerebras."
    )]
    async fn count_tokens_cerebras(
        &self,
        Parameters(request): Parameters<TokenCountRequest>,
    ) -> Result<CallToolResult, McpError> {
        self.count_tokens_for_provider("cerebras", request).await
    }

    #[tool(
        name = "ai_count_tokens_openai",
        description = "Claude Messages API-compatible token counting backed by OpenAI."
    )]
    async fn count_tokens_openai(
        &self,
        Parameters(request): Parameters<TokenCountRequest>,
    ) -> Result<CallToolResult, McpError> {
        self.count_tokens_for_provider("openai", request).await
    }

    pub async fn count_tokens_for_provider(
        &self,
        provider: &str,
        mut request: TokenCountRequest,
    ) -> Result<CallToolResult, McpError> {
        let original_model = request.model.clone();
        let (mapped, _) = self.state.model_manager.validate_and_map_model(
            &request.model,
            provider,
            self.state.config.model_mapping_mode,
        );
        request.model = mapped.clone();
        debug!(
            "model mapping provider={} original={} mapped={}",
            provider, original_model, mapped
        );

        let messages_request = MessagesRequest {
            model: request.model.clone(),
            max_tokens: self.state.config.max_tokens_limit,
            messages: request.messages.clone(),
            system: request.system.clone(),
            stop_sequences: None,
            stream: Some(false),
            temperature: None,
            top_p: None,
            top_k: None,
            metadata: None,
            tools: request.tools.clone(),
            tool_choice: request.tool_choice.clone(),
            thinking: request.thinking.clone(),
        };

        let mut body = convert_anthropic_to_openai(&messages_request, &self.state.config);
        if let Some(adapter) = provider_by_name(provider) {
            adapter.prepare_request_body(&mut body);
        }

        let response = match post_with_retries(
            &self.state.client,
            &self.state.config,
            &body,
            self.state.config.max_retries,
            self.state.config.retry_backoff_ms,
            self.auth_header_for(provider)?,
            provider,
        )
        .await
        {
            Ok(resp) => resp,
            Err(err) => {
                let msg = classify_provider_error(&err.to_string());
                return Err(McpError::internal_error(msg, None));
            }
        };

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            let msg = classify_provider_error(&text);
            return Err(McpError::internal_error(
                format!("Upstream error {status}: {msg}"),
                None,
            ));
        }

        let response_json = match response.json::<Value>().await {
            Ok(val) => val,
            Err(err) => {
                let msg = classify_provider_error(&err.to_string());
                return Err(McpError::internal_error(msg, None));
            }
        };

        let input_tokens = response_json
            .get("usage")
            .and_then(|u| u.get("prompt_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32;

        let result = TokenCountResponse {
            input_tokens,
            model: request.model.clone(),
        };
        Ok(CallToolResult::success(vec![ContentBlock::text("ok")])
            .with_structured(serde_json::to_value(result).unwrap_or(json!({}))))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for LlmMcpServer {
    fn get_info(&self) -> ServerInfo {
        self.server_info()
    }
}

fn log_dialog(
    _dialog_log_file: &Option<String>,
    _request: &MessagesRequest,
    _response: &MessagesResponse,
) {
    // Dialog logging disabled in embedded mode
}

impl LlmMcpServer {
    async fn stream_with_retries(
        &self,
        body: &Value,
        original_model: &str,
        mapped_model: &str,
        progress_token: Option<rmcp::model::ProgressToken>,
        client: &Peer<RoleServer>,
        provider: &str,
    ) -> Result<MessagesResponse> {
        let mut attempts = 0;
        while attempts <= self.state.config.max_streaming_retries {
            match self
                .stream_once(
                    body,
                    original_model,
                    mapped_model,
                    progress_token.clone(),
                    client,
                    provider,
                )
                .await
            {
                Ok(response) => return Ok(response),
                Err(err) => {
                    attempts += 1;
                    if attempts > self.state.config.max_streaming_retries {
                        return Err(err);
                    }
                    tokio::time::sleep(Duration::from_millis(
                        self.state.config.streaming_retry_backoff_ms,
                    ))
                    .await;
                }
            }
        }
        bail!("Streaming retries exhausted")
    }

    async fn stream_once(
        &self,
        body: &Value,
        original_model: &str,
        mapped_model: &str,
        progress_token: Option<rmcp::model::ProgressToken>,
        client: &Peer<RoleServer>,
        provider: &str,
    ) -> Result<MessagesResponse> {
        let (header, value) = self
            .auth_header_for(provider)
            .map_err(|e| anyhow::anyhow!("{}", e.message))?;
        let endpoint = self.state.config.effective_endpoint_for(provider);

        let response = self
            .state
            .client
            .post(&endpoint)
            .header(header, value)
            .json(body)
            .send()
            .await
            .context("Failed to send streaming request")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            bail!("Upstream error {status}: {text}");
        }

        let stream = response.bytes_stream();

        let message_id = format!("msg_{}", Uuid::new_v4().simple());
        let mut progress_count: f64 = 0.0;

        progress_count += 1.0;
        notify_progress(
            client,
            &progress_token,
            progress_count,
            json!({
                "type": "message_start",
                "message": {
                    "id": message_id,
                    "type": "message",
                    "role": "assistant",
                    "model": original_model,
                    "metadata": {"actual_model": mapped_model},
                    "content": [],
                    "stop_reason": null,
                    "stop_sequence": null,
                    "usage": {"input_tokens": 0, "output_tokens": 0}
                }
            }),
        )
        .await;
        progress_count += 1.0;
        notify_progress(
            client,
            &progress_token,
            progress_count,
            json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""}
            }),
        )
        .await;
        progress_count += 1.0;
        notify_progress(
            client,
            &progress_token,
            progress_count,
            json!({"type": "ping"}),
        )
        .await;

        // BH-16: parse frames from a byte accumulator (see `SseStreamParser`)
        // so split-UTF-8 codepoints, `\r\n\r\n` framing, and index-keyed
        // tool-call deltas are all handled correctly. The parser is pure and
        // unit-tested; here we drive it and turn its events into progress
        // notifications.
        let mut parser = SseStreamParser::new();

        futures::pin_mut!(stream);
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("Stream chunk error")?;
            for event in parser.push_bytes(&chunk)? {
                match event {
                    SseEvent::Text(text) => {
                        progress_count += 1.0;
                        notify_progress(
                            client,
                            &progress_token,
                            progress_count,
                            json!({
                                "type": "content_block_delta",
                                "index": 0,
                                "delta": {"type": "text_delta", "text": text}
                            }),
                        )
                        .await;
                    }
                    SseEvent::ToolStart {
                        block_index,
                        id,
                        name,
                    } => {
                        progress_count += 1.0;
                        notify_progress(client, &progress_token, progress_count, json!({
                            "type": "content_block_start",
                            "index": block_index,
                            "content_block": {"type": "tool_use", "id": id, "name": name, "input": {}}
                        }))
                        .await;
                    }
                    SseEvent::ToolArgs {
                        block_index,
                        partial,
                    } => {
                        progress_count += 1.0;
                        notify_progress(
                            client,
                            &progress_token,
                            progress_count,
                            json!({
                                "type": "content_block_delta",
                                "index": block_index,
                                "delta": {"type": "input_json_delta", "partial_json": partial}
                            }),
                        )
                        .await;
                    }
                }
            }
        }

        let ParsedStream {
            text: text_accum,
            stop_reason: final_stop,
            tool_calls,
        } = parser.finish()?;

        progress_count += 1.0;
        notify_progress(
            client,
            &progress_token,
            progress_count,
            json!({"type": "content_block_stop", "index": 0}),
        )
        .await;
        for tc in &tool_calls {
            progress_count += 1.0;
            notify_progress(
                client,
                &progress_token,
                progress_count,
                json!({"type": "content_block_stop", "index": tc.block_index}),
            )
            .await;
        }
        progress_count += 1.0;
        notify_progress(
            client,
            &progress_token,
            progress_count,
            json!({
                "type": "message_delta",
                "delta": {"stop_reason": final_stop, "stop_sequence": null},
                "usage": {"input_tokens": 0, "output_tokens": 0}
            }),
        )
        .await;
        progress_count += 1.0;
        notify_progress(
            client,
            &progress_token,
            progress_count,
            json!({"type": "message_stop"}),
        )
        .await;

        let mut content_blocks = Vec::new();
        if !text_accum.trim().is_empty() {
            content_blocks.push(ResponseContentBlock::Text { text: text_accum });
        }

        // `tool_calls` is already ordered by content-block index (order of
        // appearance) and each `input` has been parsed/validated by `finish`.
        for tc in tool_calls {
            content_blocks.push(ResponseContentBlock::ToolUse {
                id: tc.id,
                name: tc.name,
                input: tc.input,
            });
        }

        Ok(MessagesResponse {
            id: message_id,
            model: original_model.to_string(),
            role: "assistant".to_string(),
            content: content_blocks,
            message_type: "message".to_string(),
            stop_reason: Some(final_stop),
            stop_sequence: None,
            usage: Usage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
            },
            metadata: Some(json!({ "actual_model": mapped_model })),
        })
    }
}

/// A semantic event produced while parsing an OpenAI-compatible SSE stream.
///
/// The parser is deliberately free of I/O and progress-notification concerns:
/// `stream_once` translates these events into MCP progress notifications, while
/// unit tests assert on them directly.
#[derive(Debug, Clone, PartialEq)]
enum SseEvent {
    /// A chunk of assistant text (`delta.content`).
    Text(String),
    /// First sighting of the tool call at some OpenAI `index`. `block_index`
    /// is the Anthropic content-block index we advertise downstream (the text
    /// block occupies index 0, so tool blocks start at 1).
    ToolStart {
        block_index: usize,
        id: String,
        name: String,
    },
    /// A fragment of a tool call's `arguments` JSON string.
    ToolArgs { block_index: usize, partial: String },
}

/// Per-tool-call accumulation state, keyed by the OpenAI
/// `delta.tool_calls[].index`. That field is REQUIRED on every delta, whereas
/// `id`/`name` arrive only on the first delta of each call — so keying by
/// `index` (BH-16) is what lets later argument fragments land on the right
/// call instead of being dropped.
struct ToolCallAcc {
    /// Anthropic content-block index we advertise (assigned on first sighting).
    block_index: usize,
    id: String,
    name: String,
    args: String,
}

/// A fully assembled tool call, ready to emit as a `tool_use` content block.
#[derive(Debug)]
struct ParsedToolCall {
    block_index: usize,
    id: String,
    name: String,
    input: Value,
}

/// The final assembled result of a streamed chat-completion.
#[derive(Debug)]
struct ParsedStream {
    text: String,
    stop_reason: String,
    /// Ordered by content-block index (order of appearance).
    tool_calls: Vec<ParsedToolCall>,
}

/// Incremental parser for an OpenAI-compatible `/chat/completions` SSE stream.
///
/// Fixes several silent-data-loss defects (BH-16):
/// - Raw bytes are buffered and only decoded once a *complete* SSE frame is
///   available, so a multibyte UTF-8 codepoint split across two network chunks
///   is never turned into U+FFFD.
/// - Frames are split on both `\n\n` and `\r\n\r\n` delimiters.
/// - Streamed tool-call deltas are keyed by the REQUIRED `index` field, not the
///   optional `id`, so argument fragments in later deltas are not dropped.
/// - Malformed `data:` frames surface a real error instead of being skipped,
///   and non-empty tool arguments that fail to parse error out rather than
///   silently collapsing to `{}`.
#[derive(Default)]
struct SseStreamParser {
    /// Raw, not-yet-framed bytes carried across chunks.
    buf: Vec<u8>,
    text: String,
    /// Tool calls keyed by OpenAI delta index (BTreeMap keeps a stable order).
    tools: BTreeMap<u64, ToolCallAcc>,
    /// Next Anthropic content-block index to assign (text block occupies 0).
    next_block_index: usize,
    stop_reason: Option<String>,
}

impl SseStreamParser {
    fn new() -> Self {
        SseStreamParser {
            next_block_index: 1,
            ..Default::default()
        }
    }

    /// Feed one network chunk of raw bytes, returning the semantic events that
    /// became complete within it (in order). Errors on malformed frames.
    fn push_bytes(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>> {
        self.buf.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some((end, delim_len)) = next_frame_boundary(&self.buf) {
            let frame: Vec<u8> = self.buf.drain(..end + delim_len).collect();
            // `frame[..end]` is a complete SSE event; because we only cut on a
            // full delimiter, no multibyte codepoint is ever split here.
            let frame = std::str::from_utf8(&frame[..end])
                .context("SSE frame contained invalid UTF-8")?
                .to_string();
            self.consume_frame(&frame, &mut events)?;
        }
        Ok(events)
    }

    /// Parse one complete SSE frame (already delimited and UTF-8 decoded).
    fn consume_frame(&mut self, frame: &str, events: &mut Vec<SseEvent>) -> Result<()> {
        for line in frame.lines() {
            let line = line.trim();
            if !line.starts_with("data:") {
                // SSE comments (`:`), `event:` lines and blank keep-alives.
                continue;
            }
            let data = line.trim_start_matches("data:").trim();
            if data == "[DONE]" {
                break;
            }
            if data.is_empty() {
                // Genuinely-empty keep-alive `data:` line.
                continue;
            }
            let parsed: Value = serde_json::from_str(data)
                .with_context(|| format!("Malformed SSE JSON frame: {data}"))?;
            self.consume_json(&parsed, events);
        }
        Ok(())
    }

    /// Fold one parsed `chat.completion.chunk` object into the running state.
    fn consume_json(&mut self, parsed: &Value, events: &mut Vec<SseEvent>) {
        let Some(choice) = parsed
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
        else {
            return;
        };
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            self.stop_reason = Some(map_finish_reason(Some(reason)));
        }
        let Some(delta) = choice.get("delta") else {
            return;
        };
        if let Some(text) = delta.get("content").and_then(Value::as_str)
            && !text.is_empty()
        {
            self.text.push_str(text);
            events.push(SseEvent::Text(text.to_string()));
        }
        if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
            for tc in tool_calls {
                self.consume_tool_delta(tc, events);
            }
        }
    }

    /// Fold a single `delta.tool_calls[]` fragment into the per-index state.
    fn consume_tool_delta(&mut self, tc: &Value, events: &mut Vec<SseEvent>) {
        // `index` is REQUIRED per the chat.completion.chunk schema. Fall back
        // to 0 only if a non-compliant provider omits it, so a lone call still
        // assembles rather than being dropped.
        let index = tc.get("index").and_then(Value::as_u64).unwrap_or(0);
        let id = tc.get("id").and_then(Value::as_str).unwrap_or("");
        let name = tc
            .get("function")
            .and_then(|f| f.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("");

        if let Some(entry) = self.tools.get_mut(&index) {
            // `id`/`name` may only appear on the first delta; fill if missing.
            if entry.id.is_empty() && !id.is_empty() {
                entry.id = id.to_string();
            }
            if entry.name.is_empty() && !name.is_empty() {
                entry.name = name.to_string();
            }
        } else {
            let block_index = self.next_block_index;
            self.next_block_index += 1;
            self.tools.insert(
                index,
                ToolCallAcc {
                    block_index,
                    id: id.to_string(),
                    name: name.to_string(),
                    args: String::new(),
                },
            );
            events.push(SseEvent::ToolStart {
                block_index,
                id: id.to_string(),
                name: name.to_string(),
            });
        }

        if let Some(args) = tc
            .get("function")
            .and_then(|f| f.get("arguments"))
            .and_then(Value::as_str)
            && !args.is_empty()
        {
            let entry = self.tools.get_mut(&index).expect("inserted above");
            entry.args.push_str(args);
            events.push(SseEvent::ToolArgs {
                block_index: entry.block_index,
                partial: args.to_string(),
            });
        }
    }

    /// Assemble the final response. Errors if any tool call accumulated
    /// non-empty `arguments` that fail to parse as JSON (BH-16: previously such
    /// corruption was silently masked as `{}`).
    fn finish(self) -> Result<ParsedStream> {
        let mut accs: Vec<ToolCallAcc> = self.tools.into_values().collect();
        accs.sort_by_key(|a| a.block_index);

        let mut tool_calls = Vec::with_capacity(accs.len());
        for acc in accs {
            let trimmed = acc.args.trim();
            let input = if trimmed.is_empty() {
                // A tool with no arguments legitimately streams nothing.
                json!({})
            } else {
                serde_json::from_str(trimmed).with_context(|| {
                    format!(
                        "Tool call `{}` produced unparseable streamed arguments: {}",
                        acc.name, acc.args
                    )
                })?
            };
            tool_calls.push(ParsedToolCall {
                block_index: acc.block_index,
                id: acc.id,
                name: acc.name,
                input,
            });
        }

        Ok(ParsedStream {
            text: self.text,
            stop_reason: self.stop_reason.unwrap_or_else(|| "end_turn".to_string()),
            tool_calls,
        })
    }
}

/// Find the end of the first complete SSE frame in `buf`, returning
/// `(frame_end, delimiter_len)` where the frame body is `buf[..frame_end]` and
/// the next frame starts at `frame_end + delimiter_len`. Recognises both the
/// `\n\n` and `\r\n\r\n` event delimiters, choosing whichever occurs first.
fn next_frame_boundary(buf: &[u8]) -> Option<(usize, usize)> {
    let lf = find_subslice(buf, b"\n\n");
    let crlf = find_subslice(buf, b"\r\n\r\n");
    match (lf, crlf) {
        // On a tie prefer the longer CRLF delimiter so we don't leave a stray
        // `\r\n` at the head of the next frame.
        (Some(l), Some(c)) => {
            if c <= l {
                Some((c, 4))
            } else {
                Some((l, 2))
            }
        }
        (Some(l), None) => Some((l, 2)),
        (None, Some(c)) => Some((c, 4)),
        (None, None) => None,
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn notify_progress(
    client: &Peer<RoleServer>,
    token: &Option<rmcp::model::ProgressToken>,
    progress: f64,
    message: Value,
) {
    if let Some(progress_token) = token.clone() {
        let _ = client
            .notify_progress(
                ProgressNotificationParam::new(progress_token, progress)
                    .with_message(message.to_string()),
            )
            .await;
    }
}

async fn post_with_retries(
    client: &Client,
    config: &config::Config,
    body: &Value,
    max_retries: u32,
    retry_backoff_ms: u64,
    (header, value): (HeaderName, String),
    provider: &str,
) -> Result<reqwest::Response> {
    let endpoint = config.effective_endpoint_for(provider);
    let mut attempt = 0;
    loop {
        let result = client
            .post(&endpoint)
            .header(header.clone(), value.clone())
            .json(body)
            .send()
            .await;

        match result {
            Ok(resp) => {
                if resp.status().is_server_error() && attempt < max_retries {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(retry_backoff_ms)).await;
                    continue;
                }
                return Ok(resp);
            }
            Err(err) => {
                if attempt < max_retries {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(retry_backoff_ms)).await;
                    continue;
                }
                return Err(err.into());
            }
        }
    }
}

fn filter_provider_tools(tool_router: &mut ToolRouter<LlmMcpServer>, state: &AppState) {
    let configured_set: Option<std::collections::HashSet<_>> = if state.config.providers.is_empty()
    {
        None
    } else {
        Some(
            state
                .config
                .providers
                .iter()
                .map(|p| p.to_lowercase())
                .collect(),
        )
    };

    for provider in known_providers() {
        let name = provider.name().to_lowercase();
        let allowed = configured_set
            .as_ref()
            .map(|set| set.contains(&name))
            .unwrap_or(true);
        let enabled = allowed
            && state.available_providers.contains(provider.name())
            && provider_by_name(provider.name()).is_some();
        if !enabled {
            for tool in provider.tool_names() {
                tool_router.remove_route(&tool);
            }
        }
    }
}

trait WithStructured {
    fn with_structured(self, value: serde_json::Value) -> Self;
}

impl WithStructured for CallToolResult {
    fn with_structured(mut self, value: serde_json::Value) -> Self {
        self.structured_content = Some(value);
        self
    }
}

pub async fn build_state() -> Result<AppState> {
    build_state_with_options(None, None, false).await
}

pub async fn build_state_with_options(
    timeout_seconds: Option<u64>,
    dialog_log_file: Option<String>,
    log_init: bool,
) -> Result<AppState> {
    let mut config = load_config().context("Failed to load config")?;
    if let Some(timeout) = timeout_seconds {
        config.request_timeout = timeout;
    }

    for provider in known_providers() {
        provider.detect_env(&mut config);
    }

    if let Err(err) = config.validate()
        && log_init
    {
        warn!("startup config validation warning: {}", err);
    }

    let model_manager = ModelManager::new(&config);
    let client = Client::builder()
        .timeout(Duration::from_secs(config.request_timeout))
        .build()
        .context("Failed to build HTTP client")?;

    let available_providers = probe_available_providers(&client, &config, log_init).await;
    if log_init {
        log_init_summary(&config, &available_providers);
    }

    Ok(AppState {
        config,
        model_manager,
        client,
        dialog_log_file,
        available_providers,
    })
}

async fn probe_available_providers(
    client: &Client,
    config: &config::Config,
    log_init: bool,
) -> std::collections::HashSet<String> {
    let candidates = config.configured_providers();
    let mut available = std::collections::HashSet::new();
    for provider in candidates {
        if !config.is_provider_available(&provider) {
            if log_init {
                info!("probe: provider={provider} skipped (missing api key or endpoint)");
            }
            continue;
        }
        if let Some(spec) = self::providers::probe_spec(&provider, config) {
            if log_init {
                info!("probe: checking provider={provider}");
            }
            match probe_provider_access(client, config, &provider, spec).await {
                Ok(()) => {
                    if log_init {
                        info!("probe: provider={provider} ok");
                    }
                    available.insert(provider);
                }
                Err(err) => {
                    if log_init {
                        warn!("probe: provider={provider} failed: {err}");
                    }
                }
            }
        } else if log_init {
            warn!("probe: provider={provider} has no probe spec");
        }
    }
    available
}

async fn probe_provider_access(
    client: &Client,
    config: &config::Config,
    provider: &str,
    spec: self::providers::ProviderProbe,
) -> Result<()> {
    let (header, value) = {
        let key = config
            .effective_api_key_for(provider)
            .context("Missing API key")?;
        let header = HeaderName::from_bytes(config.provider_api_key_header.as_bytes())
            .context("Invalid header")?;
        let value = format!("{}{}", config.provider_api_key_prefix, key);
        (header, value)
    };

    match spec {
        self::providers::ProviderProbe::ModelsList { endpoint } => {
            let response = client
                .get(endpoint)
                .header(header, value)
                .send()
                .await
                .context("Probe request failed")?;
            if response.status().is_success() {
                Ok(())
            } else {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                bail!("probe failed: {status} {text}")
            }
        }
        self::providers::ProviderProbe::ChatCompletions { endpoint, model } => {
            let body = json!({
                "model": model,
                "messages": [{"role": "user", "content": "ping"}],
                "max_tokens": 1,
                "stream": false
            });
            let response = client
                .post(endpoint)
                .header(header, value)
                .json(&body)
                .send()
                .await
                .context("Probe request failed")?;
            if response.status().is_success() {
                Ok(())
            } else {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                bail!("probe failed: {status} {text}")
            }
        }
    }
}

fn log_init_summary(
    config: &config::Config,
    available_providers: &std::collections::HashSet<String>,
) {
    let configured = config.configured_providers();
    let mut available: Vec<String> = available_providers.iter().cloned().collect();
    available.sort();
    let configured_label = if configured.is_empty() {
        "<empty>".to_string()
    } else {
        configured.join(", ")
    };
    let available_label = if available.is_empty() {
        "<none>".to_string()
    } else {
        available.join(", ")
    };
    let tools = build_available_tools(config, available_providers);
    let tools_label = if tools.is_empty() {
        "<none>".to_string()
    } else {
        tools.join(", ")
    };
    info!(
        "init: primary_provider={} providers=[{}] available=[{}] available_count={} tools=[{}] model_mapping={} big_model={} small_model={}",
        config.primary_provider(),
        configured_label,
        available_label,
        available.len(),
        tools_label,
        config.model_mapping_mode.as_str(),
        config.big_model,
        config.small_model
    );
}

fn build_available_tools(
    config: &config::Config,
    available_providers: &std::collections::HashSet<String>,
) -> Vec<String> {
    let mut tools = vec!["messages".to_string(), "count_tokens".to_string()];
    let allowed_set: Option<std::collections::HashSet<_>> = if config.providers.is_empty() {
        None
    } else {
        Some(config.providers.iter().map(|p| p.to_lowercase()).collect())
    };
    for provider in known_providers() {
        let name = provider.name().to_lowercase();
        let allowed = allowed_set
            .as_ref()
            .map(|set| set.contains(&name))
            .unwrap_or(true);
        if allowed && available_providers.contains(provider.name()) {
            tools.extend(provider.tool_names());
        }
    }
    tools
}

#[cfg(test)]
mod sse_parser_tests {
    //! BH-16 regression tests for the streaming SSE parser. These feed
    //! hand-crafted byte-chunk boundaries directly into `SseStreamParser`,
    //! exercising the exact frame/accumulation path the live HTTP stream uses.
    use super::*;

    /// Drive the parser over a sequence of raw byte chunks and return the
    /// assembled result.
    fn run(chunks: &[&[u8]]) -> ParsedStream {
        let mut parser = SseStreamParser::new();
        for chunk in chunks {
            parser.push_bytes(chunk).expect("chunk parsed cleanly");
        }
        parser.finish().expect("stream assembled cleanly")
    }

    /// (a) Argument fragments assemble across multiple deltas where only the
    /// first carries `id`/`name` and later deltas carry only `index` + a
    /// fragment. The final arguments JSON must be complete, not `{}`.
    #[test]
    fn tool_args_assemble_across_deltas_with_id_only_first() {
        let frames = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"{\\\"ci\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"ty\\\": \\\"Paris\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"}\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        let out = run(&[frames.as_bytes()]);
        assert_eq!(out.tool_calls.len(), 1);
        let tc = &out.tool_calls[0];
        assert_eq!(tc.id, "call_1");
        assert_eq!(tc.name, "get_weather");
        assert_eq!(tc.input, json!({"city": "Paris"}));
        assert_ne!(tc.input, json!({}));
    }

    /// (b) Two parallel tool calls (index 0 and index 1) interleaved across
    /// deltas must both assemble correctly without collision.
    #[test]
    fn parallel_tool_calls_do_not_collide() {
        let frames = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_a\",\"function\":{\"name\":\"alpha\",\"arguments\":\"{\\\"x\\\":\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"call_b\",\"function\":{\"name\":\"beta\",\"arguments\":\"{\\\"y\\\":\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"1}\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":1,\"function\":{\"arguments\":\"2}\"}}]}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let out = run(&[frames.as_bytes()]);
        assert_eq!(out.tool_calls.len(), 2);
        assert_eq!(out.tool_calls[0].id, "call_a");
        assert_eq!(out.tool_calls[0].name, "alpha");
        assert_eq!(out.tool_calls[0].input, json!({"x": 1}));
        assert_eq!(out.tool_calls[1].id, "call_b");
        assert_eq!(out.tool_calls[1].name, "beta");
        assert_eq!(out.tool_calls[1].input, json!({"y": 2}));
    }

    /// (c) A multibyte UTF-8 codepoint split across two byte chunks must decode
    /// correctly with no U+FFFD replacement characters.
    #[test]
    fn split_utf8_codepoint_across_chunks_is_not_corrupted() {
        // Cyrillic и is D0 B8; the emoji \u{1F600} is F0 9F 98 80.
        let full = "data: {\"choices\":[{\"delta\":{\"content\":\"\u{0438}\u{1F600}\"}}]}\n\n";
        let bytes = full.as_bytes();
        // Split in the middle of the Cyrillic byte pair (right after D0).
        let split_at = bytes
            .windows(2)
            .position(|w| w == [0xD0, 0xB8])
            .expect("cyrillic present")
            + 1;
        let (a, b) = bytes.split_at(split_at);
        let out = run(&[a, b]);
        assert_eq!(out.text, "\u{0438}\u{1F600}");
        assert!(!out.text.contains('\u{FFFD}'));
    }

    /// The emoji case, split inside the 4-byte sequence across three chunks.
    #[test]
    fn split_emoji_across_multiple_chunks() {
        let full = "data: {\"choices\":[{\"delta\":{\"content\":\"a\u{1F600}b\"}}]}\n\n";
        let bytes = full.as_bytes();
        let emoji_pos = bytes
            .windows(4)
            .position(|w| w == [0xF0, 0x9F, 0x98, 0x80])
            .expect("emoji present");
        let c1 = &bytes[..emoji_pos + 1];
        let c2 = &bytes[emoji_pos + 1..emoji_pos + 3];
        let c3 = &bytes[emoji_pos + 3..];
        let out = run(&[c1, c2, c3]);
        assert_eq!(out.text, "a\u{1F600}b");
    }

    /// Framing must handle `\r\n\r\n` (CRLF) event delimiters, not just `\n\n`.
    #[test]
    fn crlf_frame_delimiters_are_split() {
        let frames = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hello \"}}]}\r\n\r\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"world\"}}]}\r\n\r\n",
            "data: [DONE]\r\n\r\n",
        );
        let out = run(&[frames.as_bytes()]);
        assert_eq!(out.text, "Hello world");
    }

    /// A frame boundary split across two chunks still assembles a whole frame.
    #[test]
    fn frame_split_across_chunk_boundary() {
        let full = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
        let bytes = full.as_bytes();
        let (a, b) = bytes.split_at(bytes.len() - 1); // split inside the "\n\n"
        let out = run(&[a, b]);
        assert_eq!(out.text, "hi");
    }

    /// (d) Non-empty tool arguments that fail to parse as JSON must surface a
    /// real error instead of silently collapsing to `{}`.
    #[test]
    fn unparseable_tool_arguments_error_out() {
        let frames = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c\",\"function\":{\"name\":\"f\",\"arguments\":\"{not valid\"}}]}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let mut parser = SseStreamParser::new();
        parser.push_bytes(frames.as_bytes()).expect("frames parse");
        let err = parser.finish().expect_err("must reject bad tool args");
        assert!(
            err.to_string().contains("unparseable"),
            "unexpected error: {err}"
        );
    }

    /// A malformed `data:` JSON frame (not `[DONE]`, not empty) must error.
    #[test]
    fn malformed_data_frame_errors() {
        let mut parser = SseStreamParser::new();
        let err = parser
            .push_bytes(b"data: {this is not json}\n\n")
            .expect_err("malformed frame must error");
        assert!(
            err.to_string().contains("Malformed SSE JSON"),
            "unexpected error: {err}"
        );
    }

    /// A tool with genuinely no arguments assembles as an empty object, not an
    /// error.
    #[test]
    fn tool_with_no_arguments_is_empty_object() {
        let frames = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c\",\"function\":{\"name\":\"ping\"}}]}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let out = run(&[frames.as_bytes()]);
        assert_eq!(out.tool_calls.len(), 1);
        assert_eq!(out.tool_calls[0].input, json!({}));
    }

    /// Keep-alive comment lines and empty `data:` lines are skipped silently.
    #[test]
    fn keepalive_lines_are_ignored() {
        let frames = concat!(
            ": keep-alive comment\n\n",
            "data: \n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let out = run(&[frames.as_bytes()]);
        assert_eq!(out.text, "ok");
    }

    /// The emitted events carry the right content-block indices: text stays on
    /// index 0, tool calls start at 1, and argument fragments follow.
    #[test]
    fn events_carry_expected_block_indices() {
        let mut parser = SseStreamParser::new();
        let mut events = Vec::new();
        let frames = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c\",\"function\":{\"name\":\"f\",\"arguments\":\"{}\"}}]}}]}\n\n",
        );
        events.extend(parser.push_bytes(frames.as_bytes()).expect("parses"));
        assert_eq!(events[0], SseEvent::Text("hi".to_string()));
        assert_eq!(
            events[1],
            SseEvent::ToolStart {
                block_index: 1,
                id: "c".to_string(),
                name: "f".to_string(),
            }
        );
        assert_eq!(
            events[2],
            SseEvent::ToolArgs {
                block_index: 1,
                partial: "{}".to_string(),
            }
        );
    }
}
