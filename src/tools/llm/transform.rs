use serde_json::{json, Value};
use uuid::Uuid;

use super::config::Config;
use super::model::{
    ContentBlock, MessageContent, MessagesRequest, MessagesResponse, ResponseContentBlock,
    SystemContent, Tool, Usage,
};

pub fn parse_tool_result_content(content: &Value) -> String {
    if content.is_null() {
        return "No content provided".to_string();
    }
    if let Some(s) = content.as_str() {
        return s.to_string();
    }
    if let Some(items) = content.as_array() {
        let mut parts = Vec::new();
        for item in items {
            if let Some(obj) = item.as_object() {
                if obj.get("type").and_then(Value::as_str) == Some("text") {
                    if let Some(text) = obj.get("text").and_then(Value::as_str) {
                        parts.push(text.to_string());
                        continue;
                    }
                }
                if let Some(text) = obj.get("text").and_then(Value::as_str) {
                    parts.push(text.to_string());
                } else {
                    parts.push(item.to_string());
                }
            } else if let Some(text) = item.as_str() {
                parts.push(text.to_string());
            } else {
                parts.push(item.to_string());
            }
        }
        return parts.join("\n").trim().to_string();
    }
    if content.is_object() {
        if content.get("type").and_then(Value::as_str) == Some("text") {
            if let Some(text) = content.get("text").and_then(Value::as_str) {
                return text.to_string();
            }
        }
        return content.to_string();
    }
    content.to_string()
}

pub fn clean_gemini_schema(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("additionalProperties");
            map.remove("default");
            if map.get("type").and_then(Value::as_str) == Some("string") {
                if let Some(format) = map.get("format").and_then(Value::as_str) {
                    let allowed = ["enum", "date-time"];
                    if !allowed.contains(&format) {
                        map.remove("format");
                    }
                }
            }
            for (_, v) in map.iter_mut() {
                clean_gemini_schema(v);
            }
        }
        Value::Array(items) => {
            for item in items {
                clean_gemini_schema(item);
            }
        }
        _ => {}
    }
}

fn system_text(system: &SystemContent) -> String {
    match system {
        SystemContent::Text(text) => text.clone(),
        SystemContent::Blocks(blocks) => blocks
            .iter()
            .filter(|b| b.block_type == "text")
            .map(|b| b.text.clone())
            .collect::<Vec<_>>()
            .join("\n\n"),
    }
}

pub fn convert_anthropic_to_openai(req: &MessagesRequest, config: &Config) -> Value {
    let mut messages: Vec<Value> = Vec::new();

    if let Some(system) = &req.system {
        let system_text = system_text(system);
        if !system_text.trim().is_empty() {
            messages.push(json!({"role": "system", "content": system_text.trim()}));
        }
    }

    for msg in &req.messages {
        match &msg.content {
            MessageContent::Text(text) => {
                messages.push(json!({"role": msg.role, "content": text}));
            }
            MessageContent::Blocks(blocks) => {
                let mut text_parts = Vec::new();
                let mut image_parts = Vec::new();
                let mut tool_calls = Vec::new();
                let mut pending_tool_messages = Vec::new();

                for block in blocks {
                    match block {
                        ContentBlock::Text { text } => text_parts.push(text.clone()),
                        ContentBlock::Image { source } => {
                            if source.get("type").and_then(Value::as_str) == Some("base64") {
                                if let (Some(media_type), Some(data)) = (
                                    source.get("media_type").and_then(Value::as_str),
                                    source.get("data").and_then(Value::as_str),
                                ) {
                                    image_parts.push(json!({
                                        "type": "image_url",
                                        "image_url": {"url": format!("data:{};base64,{}", media_type, data)}
                                    }));
                                }
                            }
                        }
                        ContentBlock::ToolUse { id, name, input } if msg.role == "assistant" => {
                            tool_calls.push(json!({
                                "id": id,
                                "type": "function",
                                "function": {"name": name, "arguments": serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string())}
                            }));
                        }
                        ContentBlock::ToolResult { tool_use_id, content } if msg.role == "user" => {
                            if !text_parts.is_empty() || !image_parts.is_empty() {
                                let mut content_parts = Vec::new();
                                let text_content = text_parts.join("").trim().to_string();
                                if !text_content.is_empty() {
                                    content_parts.push(json!({"type": "text", "text": text_content}));
                                }
                                content_parts.extend(image_parts.clone());
                                if content_parts.len() == 1 && content_parts[0].get("type") == Some(&Value::String("text".to_string())) {
                                    messages.push(json!({"role": "user", "content": content_parts[0]["text"]}));
                                } else if !content_parts.is_empty() {
                                    messages.push(json!({"role": "user", "content": content_parts}));
                                }
                                text_parts.clear();
                                image_parts.clear();
                            }

                            let parsed = parse_tool_result_content(content);
                            pending_tool_messages.push(json!({
                                "role": "tool",
                                "tool_call_id": tool_use_id,
                                "content": parsed
                            }));
                        }
                        _ => {}
                    }
                }

                if msg.role == "user" {
                    if !text_parts.is_empty() || !image_parts.is_empty() {
                        let mut content_parts = Vec::new();
                        let text_content = text_parts.join("").trim().to_string();
                        if !text_content.is_empty() {
                            content_parts.push(json!({"type": "text", "text": text_content}));
                        }
                        content_parts.extend(image_parts.clone());
                        if content_parts.len() == 1 && content_parts[0].get("type") == Some(&Value::String("text".to_string())) {
                            messages.push(json!({"role": "user", "content": content_parts[0]["text"]}));
                        } else if !content_parts.is_empty() {
                            messages.push(json!({"role": "user", "content": content_parts}));
                        }
                    }
                    for tool_msg in pending_tool_messages {
                        messages.push(tool_msg);
                    }
                } else if msg.role == "assistant" {
                    let mut assistant_msg = json!({"role": "assistant"});
                    let mut content_parts = Vec::new();
                    let text_content = text_parts.join("").trim().to_string();
                    if !text_content.is_empty() {
                        content_parts.push(json!({"type": "text", "text": text_content}));
                    }
                    content_parts.extend(image_parts.clone());
                    if !content_parts.is_empty() {
                        assistant_msg["content"] = if content_parts.len() == 1 && content_parts[0].get("type") == Some(&Value::String("text".to_string()))
                        {
                            content_parts[0]["text"].clone()
                        } else {
                            Value::Array(content_parts)
                        };
                    } else {
                        assistant_msg["content"] = Value::Null;
                    }
                    if !tool_calls.is_empty() {
                        assistant_msg["tool_calls"] = Value::Array(tool_calls);
                    }
                    if assistant_msg.get("content").and_then(Value::as_str).is_some()
                        || assistant_msg.get("tool_calls").is_some()
                    {
                        messages.push(assistant_msg);
                    }
                }
            }
        }
    }

    let mut body = json!({
        "model": req.model,
        "messages": messages,
        "max_tokens": req.max_tokens.min(config.max_tokens_limit),
        "stream": req.stream.unwrap_or(false),
    });

    if let Some(temp) = req.temperature {
        body["temperature"] = json!(temp);
    }
    if let Some(stop) = &req.stop_sequences {
        body["stop"] = json!(stop);
    }
    if let Some(top_p) = req.top_p {
        body["top_p"] = json!(top_p);
    }
    if let Some(top_k) = req.top_k {
        body["top_k"] = json!(top_k);
    }
    if let Some(meta) = &req.metadata {
        if let Some(user_id) = meta.get("user_id").and_then(Value::as_str) {
            body["user"] = json!(user_id);
        }
    }

    if let Some(tools) = &req.tools {
        let mut converted = Vec::new();
        for Tool { name, description, input_schema } in tools {
            if name.trim().is_empty() {
                continue;
            }
            let mut schema = input_schema.clone();
            clean_gemini_schema(&mut schema);
            converted.push(json!({
                "type": "function",
                "function": {
                    "name": name,
                    "description": description.clone().unwrap_or_default(),
                    "parameters": schema
                }
            }));
        }
        if !converted.is_empty() {
            body["tools"] = Value::Array(converted);
        }
    }

    if let Some(tool_choice) = &req.tool_choice {
        let choice_type = tool_choice.get("type").and_then(Value::as_str).unwrap_or("auto");
        if choice_type == "tool" {
            if let Some(name) = tool_choice.get("name").and_then(Value::as_str) {
                body["tool_choice"] = json!({"type": "function", "function": {"name": name}});
            } else {
                body["tool_choice"] = json!("auto");
            }
        } else {
            body["tool_choice"] = json!("auto");
        }
    }

    body
}

pub fn map_finish_reason(reason: Option<&str>) -> String {
    match reason.unwrap_or("stop") {
        "length" => "max_tokens".to_string(),
        "tool_calls" => "tool_use".to_string(),
        "stop" => "end_turn".to_string(),
        _ => "end_turn".to_string(),
    }
}

pub fn convert_openai_to_anthropic(response: &Value, original_model: &str) -> MessagesResponse {
    let response_id = response
        .get("id")
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("msg_{}", Uuid::new_v4()));

    let mut content_blocks = Vec::new();
    let mut finish_reason = "end_turn".to_string();
    let mut prompt_tokens = 0u32;
    let mut completion_tokens = 0u32;

    if let Some(choices) = response.get("choices").and_then(Value::as_array) {
        if let Some(choice) = choices.first() {
            finish_reason = map_finish_reason(choice.get("finish_reason").and_then(Value::as_str));
            if let Some(message) = choice.get("message") {
                if let Some(content) = message.get("content") {
                    if let Some(text) = content.as_str() {
                        if !text.is_empty() {
                            content_blocks.push(ResponseContentBlock::Text { text: text.to_string() });
                        }
                    }
                }
                if let Some(tool_calls) = message.get("tool_calls").and_then(Value::as_array) {
                    for call in tool_calls {
                        let id = call.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                        let name = call
                            .get("function")
                            .and_then(|f| f.get("name"))
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        let args = call
                            .get("function")
                            .and_then(|f| f.get("arguments"))
                            .and_then(Value::as_str)
                            .unwrap_or("{}");
                        let input = serde_json::from_str(args).unwrap_or_else(|_| json!({}));
                        content_blocks.push(ResponseContentBlock::ToolUse { id, name, input });
                    }
                }
            }
        }
    }

    if let Some(usage) = response.get("usage") {
        prompt_tokens = usage.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(0) as u32;
        completion_tokens = usage.get("completion_tokens").and_then(Value::as_u64).unwrap_or(0) as u32;
    }

    MessagesResponse {
        id: response_id,
        model: original_model.to_string(),
        role: "assistant".to_string(),
        content: content_blocks,
        message_type: "message".to_string(),
        stop_reason: Some(finish_reason),
        stop_sequence: None,
        usage: Usage {
            input_tokens: prompt_tokens,
            output_tokens: completion_tokens,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        },
        metadata: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tool_result_handles_text() {
        let value = json!({"type": "text", "text": "hello"});
        assert_eq!(parse_tool_result_content(&value), "hello");
    }

    #[test]
    fn parse_tool_result_handles_array() {
        let value = json!([
            {"type": "text", "text": "first"},
            {"text": "second"}
        ]);
        assert_eq!(parse_tool_result_content(&value), "first\nsecond");
    }

    #[test]
    fn clean_schema_removes_unsupported_fields() {
        let mut schema = json!({
            "type": "object",
            "additionalProperties": true,
            "properties": {
                "url": {"type": "string", "format": "uri"},
                "name": {"type": "string", "format": "enum"}
            },
            "default": {}
        });
        clean_gemini_schema(&mut schema);
        assert!(schema.get("additionalProperties").is_none());
        assert!(schema.get("default").is_none());
        let url = &schema["properties"]["url"];
        assert!(url.get("format").is_none());
        let name = &schema["properties"]["name"];
        assert_eq!(name.get("format").and_then(Value::as_str), Some("enum"));
    }

    #[test]
    fn convert_openai_to_anthropic_handles_tool_calls() {
        let response = json!({
            "id": "resp_1",
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "function": {
                                    "name": "do_work",
                                    "arguments": "{\"x\":1}"
                                }
                            }
                        ]
                    }
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5}
        });

        let result = convert_openai_to_anthropic(&response, "gemini-3-pro-preview");
        assert_eq!(result.model, "gemini-3-pro-preview");
        assert_eq!(result.usage.input_tokens, 10);
        assert_eq!(result.usage.output_tokens, 5);
        assert!(matches!(result.content[0], ResponseContentBlock::ToolUse { .. }));
    }
}
