pub mod config;
pub mod error;
pub mod model;

// Re-exports for integration
pub use config::Config;
pub mod model_mapping;
pub mod providers;
pub mod transform;

use std::{collections::HashMap, time::Duration};

use futures_util::StreamExt;
use reqwest::header::HeaderName;
use reqwest::Client;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Content, Implementation, Meta, ProgressNotificationParam,
        ServerCapabilities, ServerInfo,
    },
    service::Peer,
    tool, tool_handler, tool_router,
};
use serde_json::{json, Value};
use tracing::{debug, info, warn};
use uuid::Uuid;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use self::config::load_config;
use self::error::classify_provider_error;
use self::model::{
    ContentBlock, Message, MessageContent, MessagesRequest, MessagesResponse, ResponseContentBlock,
    TokenCountRequest, TokenCountResponse, Usage,
};
use self::model_mapping::ModelManager;
use self::providers::{known_providers, provider_by_name};
use self::transform::{
    convert_anthropic_to_openai, convert_openai_to_anthropic, map_finish_reason,
    parse_tool_result_content,
};

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
        ServerInfo {
            protocol_version: Default::default(),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "llm-mcp-rs".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                title: Some("LLM MCP Bridge".to_string()),
                website_url: None,
                icons: None,
            },
            instructions: Some(
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
            ),
        }
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
        meta: Meta,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let provider = self.state.config.primary_provider();
        self.messages_for_provider(&provider, request, meta, client).await
    }

    #[tool(
        name = "ai_messages_gemini",
        description = "Claude Messages API-compatible conversation tool backed by Gemini."
    )]
    async fn messages_gemini(
        &self,
        Parameters(request): Parameters<MessagesRequest>,
        meta: Meta,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.messages_for_provider("gemini", request, meta, client).await
    }

    #[tool(
        name = "ai_messages_cerebras",
        description = "Claude Messages API-compatible conversation tool backed by Cerebras."
    )]
    async fn messages_cerebras(
        &self,
        Parameters(request): Parameters<MessagesRequest>,
        meta: Meta,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.messages_for_provider("cerebras", request, meta, client).await
    }

    #[tool(
        name = "ai_messages_openai",
        description = "Claude Messages API-compatible conversation tool backed by OpenAI."
    )]
    async fn messages_openai(
        &self,
        Parameters(request): Parameters<MessagesRequest>,
        meta: Meta,
        client: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        self.messages_for_provider("openai", request, meta, client).await
    }

    pub async fn messages_for_provider(
        &self,
        provider: &str,
        mut request: MessagesRequest,
        meta: Meta,
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
                    return Ok(CallToolResult::success(vec![Content::text("ok")])
                        .with_structured(structured));
                }
                Err(err) => {
                    warn!("Streaming failed, falling back to non-streaming: {}", err);
                    body["stream"] = json!(false);
                }
            }
        } else if stream_requested {
            warn!("Streaming requested but no progress token provided; falling back to non-streaming");
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
                let msg = classify_provider_error(&err);
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
        Ok(CallToolResult::success(vec![Content::text("ok")])
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
                let msg = classify_provider_error(&err);
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
        Ok(CallToolResult::success(vec![Content::text("ok")])
            .with_structured(serde_json::to_value(result).unwrap_or(json!({}))))
    }
}

#[tool_handler]
impl ServerHandler for LlmMcpServer {
    fn get_info(&self) -> ServerInfo {
        self.server_info()
    }
}

fn render_message_content(message: &Message) -> String {
    match &message.content {
        MessageContent::Text(text) => text.trim().to_string(),
        MessageContent::Blocks(blocks) => {
            let mut parts = Vec::new();
            for block in blocks {
                match block {
                    ContentBlock::Text { text } => {
                        if !text.trim().is_empty() {
                            parts.push(text.trim().to_string());
                        }
                    }
                    ContentBlock::Image { .. } => parts.push("[image]".to_string()),
                    ContentBlock::ToolUse { name, input, .. } => {
                        parts.push(format!("[tool_use {}]: {}", name, input));
                    }
                    ContentBlock::ToolResult { tool_use_id, content } => {
                        let parsed = parse_tool_result_content(content);
                        parts.push(format!("[tool_result {}]: {}", tool_use_id, parsed));
                    }
                }
            }
            parts.join("\n")
        }
    }
}

fn render_response_content(response: &MessagesResponse) -> String {
    let mut parts = Vec::new();
    for block in &response.content {
        match block {
            ResponseContentBlock::Text { text } => {
                if !text.trim().is_empty() {
                    parts.push(text.trim().to_string());
                }
            }
            ResponseContentBlock::ToolUse { name, input, .. } => {
                parts.push(format!("[tool_use {}]: {}", name, input));
            }
        }
    }
    parts.join("\n")
}

fn log_dialog(dialog_log_file: &Option<String>, request: &MessagesRequest, response: &MessagesResponse) {
    let Some(filename) = dialog_log_file.as_ref() else {
        return;
    };
    let mut user_parts = Vec::new();
    for message in &request.messages {
        if message.role == "user" {
            let rendered = render_message_content(message);
            if !rendered.is_empty() {
                user_parts.push(rendered);
            }
        }
    }
    let user_text = if user_parts.is_empty() {
        "<empty>".to_string()
    } else {
        user_parts.join("\n\n")
    };

    let assistant_text = {
        let rendered = render_response_content(response);
        if rendered.is_empty() {
            "<empty>".to_string()
        } else {
            rendered
        }
    };

    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

    let entry = format!(
        "[{timestamp}] model: {model}\nuser:\n{user}\nassistant:\n{assistant}\n----",
        timestamp = timestamp,
        model = response.model,
        user = user_text,
        assistant = assistant_text
    );

    // Dialog logging disabled in embedded mode
    let _ = (entry, filename);
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
    ) -> Result<MessagesResponse, String> {
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
        Err("Streaming retries exhausted".to_string())
    }

    async fn stream_once(
        &self,
        body: &Value,
        original_model: &str,
        mapped_model: &str,
        progress_token: Option<rmcp::model::ProgressToken>,
        client: &Peer<RoleServer>,
        provider: &str,
    ) -> Result<MessagesResponse, String> {
        let (header, value) = self.auth_header_for(provider).map_err(|e| e.to_string())?;
        let endpoint = self.state.config.effective_endpoint_for(provider);

        let response = self
            .state
            .client
            .post(&endpoint)
            .header(header, value)
            .json(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(format!("Upstream error {status}: {text}"));
        }

        let stream = response.bytes_stream();

        let message_id = format!("msg_{}", Uuid::new_v4().simple());
        let mut progress_count: f64 = 0.0;

        progress_count += 1.0;
        notify_progress(client, &progress_token, progress_count, json!({
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
        }))
        .await;
        progress_count += 1.0;
        notify_progress(client, &progress_token, progress_count, json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""}
        }))
        .await;
        progress_count += 1.0;
        notify_progress(client, &progress_token, progress_count, json!({"type": "ping"}))
        .await;

        let mut buffer = String::new();
        let mut tool_indices: HashMap<String, usize> = HashMap::new();
        let mut tool_args: HashMap<String, String> = HashMap::new();
        let mut tool_names: HashMap<String, String> = HashMap::new();
        let mut next_tool_index: usize = 1;
        let mut final_stop = "end_turn".to_string();
        let mut text_accum = String::new();

        futures_util::pin_mut!(stream);
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(err) => return Err(err.to_string()),
            };
            buffer.push_str(&String::from_utf8_lossy(&chunk));

            while let Some(pos) = buffer.find("\n\n") {
                let raw = buffer[..pos].to_string();
                buffer = buffer[pos + 2..].to_string();
                for line in raw.lines() {
                    let line = line.trim();
                    if !line.starts_with("data:") {
                        continue;
                    }
                    let data = line.trim_start_matches("data:").trim();
                    if data == "[DONE]" {
                        break;
                    }
                    let parsed: Value = match serde_json::from_str(data) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let choice = parsed
                        .get("choices")
                        .and_then(Value::as_array)
                        .and_then(|c| c.first());
                    if let Some(choice) = choice {
                        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                            final_stop = map_finish_reason(Some(reason));
                        }
                        if let Some(delta) = choice.get("delta") {
                            if let Some(text) = delta.get("content").and_then(Value::as_str) {
                                if !text.is_empty() {
                                    text_accum.push_str(text);
                                    progress_count += 1.0;
                                    notify_progress(client, &progress_token, progress_count, json!({
                                        "type": "content_block_delta",
                                        "index": 0,
                                        "delta": {"type": "text_delta", "text": text}
                                    }))
                                    .await;
                                }
                            }
                            if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
                                for tc in tool_calls {
                                    let id = tc.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                                    let name = tc
                                        .get("function")
                                        .and_then(|f| f.get("name"))
                                        .and_then(Value::as_str)
                                        .unwrap_or("")
                                        .to_string();
                                    if !id.is_empty() && !tool_indices.contains_key(&id) {
                                        let index = next_tool_index;
                                        next_tool_index += 1;
                                        tool_indices.insert(id.clone(), index);
                                        tool_names.insert(id.clone(), name.clone());
                                        progress_count += 1.0;
                                        notify_progress(client, &progress_token, progress_count, json!({
                                            "type": "content_block_start",
                                            "index": index,
                                            "content_block": {"type": "tool_use", "id": id, "name": name, "input": {}}
                                        }))
                                        .await;
                                    }
                                    if let Some(args) = tc
                                        .get("function")
                                        .and_then(|f| f.get("arguments"))
                                        .and_then(Value::as_str)
                                    {
                                        if let Some(index) = tool_indices.get(&id) {
                                            let entry = tool_args.entry(id.clone()).or_default();
                                            entry.push_str(args);
                                            progress_count += 1.0;
                                            notify_progress(client, &progress_token, progress_count, json!({
                                                "type": "content_block_delta",
                                                "index": index,
                                                "delta": {"type": "input_json_delta", "partial_json": args}
                                            }))
                                            .await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        progress_count += 1.0;
        notify_progress(client, &progress_token, progress_count, json!({"type": "content_block_stop", "index": 0})).await;
        for index in tool_indices.values() {
            progress_count += 1.0;
            notify_progress(client, &progress_token, progress_count, json!({"type": "content_block_stop", "index": index})).await;
        }
        progress_count += 1.0;
        notify_progress(client, &progress_token, progress_count, json!({
            "type": "message_delta",
            "delta": {"stop_reason": final_stop, "stop_sequence": null},
            "usage": {"input_tokens": 0, "output_tokens": 0}
        }))
        .await;
        progress_count += 1.0;
        notify_progress(client, &progress_token, progress_count, json!({"type": "message_stop"})).await;

        let mut content_blocks = Vec::new();
        if !text_accum.trim().is_empty() {
            content_blocks.push(ResponseContentBlock::Text { text: text_accum });
        }

        let mut ordered_tool_calls: Vec<(usize, String)> = tool_indices
            .iter()
            .map(|(id, index)| (*index, id.clone()))
            .collect();
        ordered_tool_calls.sort_by_key(|(index, _)| *index);

        for (_, id) in ordered_tool_calls {
            let name = tool_names.get(&id).cloned().unwrap_or_default();
            let args = tool_args.get(&id).cloned().unwrap_or_else(|| "{}".to_string());
            let input = serde_json::from_str(&args).unwrap_or(json!({}));
            content_blocks.push(ResponseContentBlock::ToolUse { id, name, input });
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

async fn notify_progress(
    client: &Peer<RoleServer>,
    token: &Option<rmcp::model::ProgressToken>,
    progress: f64,
    message: Value,
) {
    if let Some(progress_token) = token.clone() {
        let _ = client
            .notify_progress(ProgressNotificationParam {
                progress_token,
                progress,
                total: None,
                message: Some(message.to_string()),
            })
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
) -> Result<reqwest::Response, String> {
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
                return Err(err.to_string());
            }
        }
    }
}

fn filter_provider_tools(tool_router: &mut ToolRouter<LlmMcpServer>, state: &AppState) {
    let configured_set: Option<std::collections::HashSet<_>> = if state.config.providers.is_empty() {
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

fn normalize_tool_schemas(tool_router: &mut ToolRouter<LlmMcpServer>) {
    for route in tool_router.map.values_mut() {
        let schema_value = Value::Object((*route.attr.input_schema).clone());
        let schema_value = to_draft07_schema(schema_value);
        if let Value::Object(object) = schema_value {
            route.attr.input_schema = object.into();
        }
    }
}

fn to_draft07_schema(mut schema: Value) -> Value {
    if let Value::Object(ref mut root) = schema {
        root.insert(
            "$schema".to_string(),
            Value::String("http://json-schema.org/draft-07/schema#".to_string()),
        );
    }
    rewrite_schema_refs(&mut schema);
    schema
}

fn rewrite_schema_refs(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(defs) = map.remove("$defs") {
                let definitions = map
                    .entry("definitions".to_string())
                    .or_insert_with(|| Value::Object(Default::default()));
                if let (Value::Object(target), Value::Object(src)) = (definitions, defs) {
                    for (key, value) in src {
                        target.entry(key).or_insert(value);
                    }
                }
            }
            for (key, value) in map.iter_mut() {
                if key == "$ref" {
                    if let Value::String(reference) = value {
                        if let Some(rest) = reference.strip_prefix("#/$defs/") {
                            *reference = format!("#/definitions/{}", rest);
                        } else if reference == "#/$defs" {
                            *reference = "#/definitions".to_string();
                        }
                    }
                }
                rewrite_schema_refs(value);
            }
        }
        Value::Array(items) => {
            for item in items {
                rewrite_schema_refs(item);
            }
        }
        _ => {}
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

pub fn build_state() -> Result<AppState, String> {
    let handle = tokio::runtime::Handle::current();
    handle.block_on(build_state_with_options(None, None, false))
}

pub fn build_state_with_overrides(timeout_seconds: Option<u64>) -> Result<AppState, String> {
    let handle = tokio::runtime::Handle::current();
    handle.block_on(build_state_with_options(timeout_seconds, None, false))
}

pub async fn build_state_with_options(
    timeout_seconds: Option<u64>,
    dialog_log_file: Option<String>,
    log_init: bool,
) -> Result<AppState, String> {
    let mut config = load_config().map_err(|e| format!("Config error: {e}"))?;
    if let Some(timeout) = timeout_seconds {
        config.request_timeout = timeout;
    }

    for provider in known_providers() {
        provider.detect_env(&mut config);
    }

    if let Err(err) = config.validate() {
        if log_init {
            warn!("startup config validation warning: {}", err);
        }
    }

    let model_manager = ModelManager::new(&config);
    let client = Client::builder()
        .timeout(Duration::from_secs(config.request_timeout))
        .build()
        .map_err(|e| e.to_string())?;

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
) -> Result<(), String> {
    let (header, value) = {
        let key = config
            .effective_api_key_for(provider)
            .ok_or_else(|| "missing api key".to_string())?;
        let header = HeaderName::from_bytes(config.provider_api_key_header.as_bytes())
            .map_err(|e| format!("invalid header: {e}"))?;
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
                .map_err(|e| e.to_string())?;
            if response.status().is_success() {
                Ok(())
            } else {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                Err(format!("probe failed: {status} {text}"))
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
                .map_err(|e| e.to_string())?;
            if response.status().is_success() {
                Ok(())
            } else {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                Err(format!("probe failed: {status} {text}"))
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
        Some(
            config
                .providers
                .iter()
                .map(|p| p.to_lowercase())
                .collect(),
        )
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
