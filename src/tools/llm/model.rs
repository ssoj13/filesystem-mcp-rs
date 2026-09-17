use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Open-object stand-in for a request whose canonical schema another tool
/// already publishes.
///
/// The provider-pinned `ai_messages_*` / `ai_count_tokens_*` tools take exactly
/// the body their unpinned sibling takes, but MCP has no way to share one schema
/// between tools: declaring the real type on all four ships the same ~2.4 KB of
/// JSON Schema four times in every `tools/list`, which every session pays for
/// before its first request. The pinned variants therefore publish an open
/// object and are validated against the real type on arrival — the shape is
/// described once and still enforced everywhere.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PinnedRequest(pub serde_json::Map<String, Value>);

impl PinnedRequest {
    /// Validate the body against the canonical request type. `canonical` names
    /// the sibling tool whose schema documents the shape, so a rejected call
    /// says where to look.
    pub fn parse<T: serde::de::DeserializeOwned>(self, canonical: &str) -> Result<T, String> {
        serde_json::from_value(Value::Object(self.0)).map_err(|e| {
            format!("{e} — this tool takes the same request body as `{canonical}`, whose schema describes it")
        })
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
#[serde(tag = "type")]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image")]
    Image {
        #[serde(deserialize_with = "crate::core::serde::json_value_or_string")]
        source: Value,
    },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        #[serde(deserialize_with = "crate::core::serde::json_value_or_string")]
        input: Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        #[serde(deserialize_with = "crate::core::serde::json_value_or_string")]
        content: Value,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
#[serde(untagged)]
pub enum SystemContent {
    Text(String),
    Blocks(Vec<SystemTextBlock>),
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct SystemTextBlock {
    #[serde(rename = "type")]
    pub block_type: String,
    pub text: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct Message {
    pub role: String,
    pub content: MessageContent,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct Tool {
    pub name: String,
    pub description: Option<String>,
    #[serde(deserialize_with = "crate::core::serde::json_value_or_string")]
    pub input_schema: Value,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct ThinkingConfig {
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct MessagesRequest {
    pub model: String,
    pub max_tokens: u32,
    #[serde(deserialize_with = "deserialize_messages")]
    pub messages: Vec<Message>,
    #[serde(default)]
    pub system: Option<SystemContent>,
    #[serde(default)]
    pub stop_sequences: Option<Vec<String>>,
    #[serde(default)]
    pub stream: Option<bool>,
    #[serde(default)]
    pub temperature: Option<f32>,
    #[serde(default)]
    pub top_p: Option<f32>,
    #[serde(default)]
    pub top_k: Option<u32>,
    #[serde(
        default,
        deserialize_with = "crate::core::serde::option_json_value_or_string"
    )]
    pub metadata: Option<Value>,
    #[serde(default, deserialize_with = "crate::core::serde::option_vec_or_string")]
    pub tools: Option<Vec<Tool>>,
    #[serde(
        default,
        deserialize_with = "crate::core::serde::option_json_value_or_string"
    )]
    pub tool_choice: Option<Value>,
    #[serde(default)]
    pub thinking: Option<ThinkingConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct TokenCountRequest {
    pub model: String,
    #[serde(deserialize_with = "deserialize_messages")]
    pub messages: Vec<Message>,
    #[serde(default)]
    pub system: Option<SystemContent>,
    #[serde(default, deserialize_with = "crate::core::serde::option_vec_or_string")]
    pub tools: Option<Vec<Tool>>,
    #[serde(default)]
    pub thinking: Option<ThinkingConfig>,
    #[serde(
        default,
        deserialize_with = "crate::core::serde::option_json_value_or_string"
    )]
    pub tool_choice: Option<Value>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TokenCountResponse {
    pub input_tokens: u32,
    pub model: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_creation_input_tokens: u32,
    pub cache_read_input_tokens: u32,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(tag = "type")]
pub enum ResponseContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MessagesResponse {
    pub id: String,
    pub model: String,
    pub role: String,
    pub content: Vec<ResponseContentBlock>,
    #[serde(rename = "type")]
    pub message_type: String,
    pub stop_reason: Option<String>,
    pub stop_sequence: Option<String>,
    pub usage: Usage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

fn deserialize_messages<'de, D>(deserializer: D) -> Result<Vec<Message>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::String(text) => Ok(vec![Message {
            role: "user".to_string(),
            content: MessageContent::Text(text),
        }]),
        Value::Array(_) => serde_json::from_value(value).map_err(serde::de::Error::custom),
        _ => Err(serde::de::Error::custom(
            "messages must be an array of messages or a string",
        )),
    }
}
