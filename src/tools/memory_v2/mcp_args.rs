//! Strict MCP argument types for memory v2 tools (`inputSchema` matches `Deserialize`).

use crate::WithStructured;
use rmcp::ErrorData as McpError;
use rmcp::model::{CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::SqliteMemoryStore;
use super::types::{
    ActorContext, ActorType, GetRequest, GetSummaryRequest, LinkRequest, MemoryItemInput,
    MemoryItemType, MemoryRelationInput, PutRequest, ScopeRef, SearchRequest, SummaryRef,
    UpdateRequest, Visibility,
};

pub fn invalid_params(msg: impl Into<String>) -> McpError {
    McpError::invalid_params(msg.into(), None)
}

fn default_tenant_id() -> String {
    "default".to_string()
}

fn default_app_id() -> String {
    "default".to_string()
}

fn default_actor_type() -> ActorType {
    ActorType::Agent
}

fn default_visibility() -> Visibility {
    Visibility::Workspace
}

/// Workspace + actor fields shared by all `mem_*` tools (flattened in each tool schema).
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemContextArgs {
    /// Workspace / project identifier (required).
    pub workspace_id: String,
    #[serde(default = "default_tenant_id")]
    pub tenant_id: String,
    #[serde(default = "default_app_id")]
    pub app_id: String,
    #[serde(default)]
    pub topic_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    /// Actor performing the operation (required).
    pub actor_id: String,
    #[serde(default = "default_actor_type")]
    pub actor_type: ActorType,
    #[serde(default)]
    pub tenant_user_id: Option<String>,
    #[serde(default)]
    pub host_user: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub impersonated_user_id: Option<String>,
}

impl MemContextArgs {
    pub fn validate(&self) -> Result<(), String> {
        if self.workspace_id.trim().is_empty() {
            return Err("workspaceId must not be empty".to_string());
        }
        if self.actor_id.trim().is_empty() {
            return Err("actorId must not be empty".to_string());
        }
        Ok(())
    }

    pub fn into_parts(self) -> Result<(ScopeRef, ActorContext), String> {
        self.validate()?;
        Ok((
            ScopeRef {
                tenant_id: self.tenant_id,
                app_id: self.app_id,
                workspace_id: self.workspace_id,
                topic_id: self.topic_id,
                session_id: self.session_id,
                run_id: self.run_id,
            },
            ActorContext {
                actor_id: self.actor_id,
                actor_type: self.actor_type,
                tenant_user_id: self.tenant_user_id,
                host_user: self.host_user,
                environment: self.environment,
                impersonated_user_id: self.impersonated_user_id,
            },
        ))
    }
}

/// Plain string fact or structured JSON object/array.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum MemContent {
    Text(String),
    Json(Value),
}

impl MemContent {
    pub fn into_json(self) -> Value {
        match self {
            MemContent::Text(s) => Value::String(s),
            MemContent::Json(v) => v,
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemItemArgs {
    pub item_type: MemoryItemType,
    pub content: MemContent,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub summary_text: Option<String>,
    #[serde(default = "default_visibility")]
    pub visibility: Visibility,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub owner_actor_id: Option<String>,
    #[serde(default)]
    pub source_kind: Option<String>,
    #[serde(default)]
    pub source_ref: Option<String>,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub supersedes_id: Option<String>,
}

impl MemItemArgs {
    pub fn into_memory_item_input(self) -> MemoryItemInput {
        MemoryItemInput {
            item_type: self.item_type,
            title: self.title,
            summary_text: self.summary_text,
            content_json: self.content.into_json(),
            visibility: self.visibility,
            status: self.status,
            tags: self.tags,
            owner_actor_id: self.owner_actor_id,
            source_kind: self.source_kind,
            source_ref: self.source_ref,
            confidence: self.confidence,
            expires_at: self.expires_at,
            supersedes_id: self.supersedes_id,
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemRelationArgs {
    pub from_item_id: String,
    pub to_item_id: String,
    pub relation_type: String,
}

impl MemRelationArgs {
    pub fn into_relation_input(self) -> Result<MemoryRelationInput, String> {
        let relation_type = self.relation_type.trim().to_string();
        if relation_type.is_empty() {
            return Err("relationType must not be empty".to_string());
        }
        Ok(MemoryRelationInput {
            from_item_id: Uuid::parse_str(self.from_item_id.trim())
                .map_err(|e| format!("Invalid fromItemId UUID: {e}"))?,
            to_item_id: Uuid::parse_str(self.to_item_id.trim())
                .map_err(|e| format!("Invalid toItemId UUID: {e}"))?,
            relation_type,
        })
    }
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SummaryLevelArg {
    #[default]
    Workspace,
    Topic,
    Session,
    Run,
}

impl SummaryLevelArg {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Topic => "topic",
            Self::Session => "session",
            Self::Run => "run",
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemPutArgs {
    #[serde(flatten)]
    pub context: MemContextArgs,
    pub item: MemItemArgs,
}

impl MemPutArgs {
    pub fn into_put_request(self) -> Result<PutRequest, String> {
        let (scope, actor) = self.context.into_parts()?;
        Ok(PutRequest {
            scope,
            actor,
            item: self.item.into_memory_item_input(),
        })
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemUpdateArgs {
    #[serde(flatten)]
    pub context: MemContextArgs,
    pub id: String,
    pub item: MemItemArgs,
}

impl MemUpdateArgs {
    pub fn into_update_request(self) -> Result<UpdateRequest, String> {
        let (scope, actor) = self.context.into_parts()?;
        Ok(UpdateRequest {
            scope,
            actor,
            id: Uuid::parse_str(self.id.trim()).map_err(|e| format!("Invalid id UUID: {e}"))?,
            item: self.item.into_memory_item_input(),
        })
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemLinkArgs {
    #[serde(flatten)]
    pub context: MemContextArgs,
    pub relation: MemRelationArgs,
}

impl MemLinkArgs {
    pub fn into_link_request(self) -> Result<LinkRequest, String> {
        let (scope, actor) = self.context.into_parts()?;
        Ok(LinkRequest {
            scope,
            actor,
            relation: self.relation.into_relation_input()?,
        })
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemSearchArgs {
    #[serde(flatten)]
    pub context: MemContextArgs,
    pub query: String,
    #[serde(default)]
    pub item_types: Vec<MemoryItemType>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub visibility: Vec<Visibility>,
    #[serde(default)]
    pub limit: Option<u32>,
}

impl MemSearchArgs {
    pub fn into_search_request(self) -> Result<SearchRequest, String> {
        if self.query.trim().is_empty() {
            return Err("query must not be empty".to_string());
        }
        let (scope, actor) = self.context.into_parts()?;
        Ok(SearchRequest {
            scope,
            actor,
            query: self.query,
            item_types: self.item_types,
            tags: self.tags,
            visibility: self.visibility,
            limit: self.limit.unwrap_or(20) as usize,
        })
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemGetArgs {
    #[serde(flatten)]
    pub context: MemContextArgs,
    pub ids: Vec<String>,
}

impl MemGetArgs {
    pub fn into_get_request(self) -> Result<GetRequest, String> {
        if self.ids.is_empty() {
            return Err("ids must not be empty".to_string());
        }
        let ids = self
            .ids
            .iter()
            .map(|value| {
                Uuid::parse_str(value.trim()).map_err(|e| format!("Invalid ids[] UUID: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (scope, actor) = self.context.into_parts()?;
        Ok(GetRequest { scope, actor, ids })
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemGetSummaryArgs {
    #[serde(flatten)]
    pub context: MemContextArgs,
    #[serde(default)]
    pub level: SummaryLevelArg,
}

impl MemGetSummaryArgs {
    pub fn into_get_summary_request(self) -> Result<GetSummaryRequest, String> {
        let (scope, actor) = self.context.into_parts()?;
        validate_summary_level_scope(self.level, &scope)?;
        Ok(GetSummaryRequest {
            summary: SummaryRef {
                level: self.level.as_str().to_string(),
                scope,
            },
            actor,
        })
    }
}

fn validate_summary_level_scope(level: SummaryLevelArg, scope: &ScopeRef) -> Result<(), String> {
    let missing = |field: &str, level_name: &str| {
        format!("Summary level '{level_name}' requires {field} in scope")
    };
    match level {
        SummaryLevelArg::Run => {
            if scope
                .run_id
                .as_ref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(missing("runId", "run"));
            }
        }
        SummaryLevelArg::Session => {
            if scope
                .session_id
                .as_ref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(missing("sessionId", "session"));
            }
        }
        SummaryLevelArg::Topic => {
            if scope
                .topic_id
                .as_ref()
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(missing("topicId", "topic"));
            }
        }
        SummaryLevelArg::Workspace => {}
    }
    Ok(())
}

pub async fn mem_put(
    store: &SqliteMemoryStore,
    args: MemPutArgs,
) -> Result<CallToolResult, McpError> {
    let request = args.into_put_request().map_err(invalid_params)?;
    let result = store
        .put(request)
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(format!(
        "Created memory item {}",
        result.id
    ))])
    .with_structured(json!(result)))
}

pub async fn mem_update(
    store: &SqliteMemoryStore,
    args: MemUpdateArgs,
) -> Result<CallToolResult, McpError> {
    let request = args.into_update_request().map_err(invalid_params)?;
    let result = store
        .update(request)
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(format!(
        "Updated memory item {}",
        result.id
    ))])
    .with_structured(json!(result)))
}

pub async fn mem_link(
    store: &SqliteMemoryStore,
    args: MemLinkArgs,
) -> Result<CallToolResult, McpError> {
    let request = args.into_link_request().map_err(invalid_params)?;
    let result = store
        .link(request)
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(format!(
        "Created memory relation {}",
        result.id
    ))])
    .with_structured(json!(result)))
}

pub async fn mem_search(
    store: &SqliteMemoryStore,
    args: MemSearchArgs,
) -> Result<CallToolResult, McpError> {
    let request = args.into_search_request().map_err(invalid_params)?;
    let result = store
        .search(request)
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(format!(
        "Found {} items",
        result.items.len()
    ))])
    .with_structured(json!(result)))
}

pub async fn mem_get(
    store: &SqliteMemoryStore,
    args: MemGetArgs,
) -> Result<CallToolResult, McpError> {
    let request = args.into_get_request().map_err(invalid_params)?;
    let result = store
        .get(request)
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(format!(
        "Retrieved {} items",
        result.items.len()
    ))])
    .with_structured(json!(result)))
}

pub async fn mem_get_summary(
    store: &SqliteMemoryStore,
    args: MemGetSummaryArgs,
) -> Result<CallToolResult, McpError> {
    let request = args.into_get_summary_request().map_err(invalid_params)?;
    let result = store
        .get_summary(request)
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    let text = match &result.item {
        Some(item) => format!("Loaded summary {}", item.id),
        None => "No summary found".to_string(),
    };
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]).with_structured(json!(result)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_mem_put_deserializes() {
        let json = r#"{
            "workspaceId": "vfx-rs",
            "actorId": "cursor",
            "item": {
                "itemType": "task",
                "content": { "status": "open" }
            }
        }"#;
        let args: MemPutArgs = serde_json::from_str(json).expect("deserialize");
        assert_eq!(args.context.workspace_id, "vfx-rs");
        assert_eq!(args.item.item_type, MemoryItemType::Task);
        let req = args.into_put_request().expect("into request");
        assert_eq!(req.scope.workspace_id, "vfx-rs");
        assert_eq!(req.actor.actor_id, "cursor");
    }

    #[test]
    fn fact_with_plain_string_content() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "item": { "itemType": "fact", "content": "remember this" }
        }"#;
        let args: MemPutArgs = serde_json::from_str(json).unwrap();
        let req = args.into_put_request().unwrap();
        assert_eq!(req.item.content_json, Value::String("remember this".into()));
    }

    #[test]
    fn missing_workspace_id_fails_validation() {
        let json = r#"{
            "workspaceId": "  ",
            "actorId": "a",
            "item": { "itemType": "fact", "content": "x" }
        }"#;
        let args: MemPutArgs = serde_json::from_str(json).unwrap();
        assert!(args.into_put_request().is_err());
    }

    #[test]
    fn unknown_field_on_item_rejected() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "item": { "itemType": "fact", "content": "x", "extra": true }
        }"#;
        let err = serde_json::from_str::<MemPutArgs>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn stringified_item_object_rejected() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "item": "{\"itemType\":\"fact\",\"content\":\"x\"}"
        }"#;
        assert!(serde_json::from_str::<MemPutArgs>(json).is_err());
    }

    #[test]
    fn mem_put_schema_lists_flat_required_fields() {
        let schema = schemars::schema_for!(MemPutArgs);
        let value = serde_json::to_value(&schema).expect("schema json");
        let required = value["required"].as_array().expect("required array");
        let names: Vec<_> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(names.contains(&"workspaceId"));
        assert!(names.contains(&"actorId"));
        assert!(names.contains(&"item"));
        assert!(!names.contains(&"scope"));
        let item = &value["properties"]["item"];
        assert!(item.get("oneOf").is_none(), "item must be object only");
    }

    // --- Realistic MCP / LLM edge cases (strict contract) ---

    #[test]
    fn empty_arguments_rejected() {
        let err = serde_json::from_str::<MemPutArgs>("{}").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("workspaceId") || msg.contains("item"),
            "empty payload must fail required fields, got {msg}"
        );
    }

    /// Pre-0.2 clients sent `"scope": "my-project"` instead of `workspaceId`.
    #[test]
    fn legacy_scope_shortcut_rejected() {
        let json = r#"{
            "scope": "vfx-rs",
            "actorId": "cursor",
            "item": { "itemType": "fact", "content": "x" }
        }"#;
        let err = serde_json::from_str::<MemPutArgs>(json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("scope") || msg.contains("workspaceId"),
            "legacy scope shortcut must not deserialize, got {msg}"
        );
    }

    #[test]
    fn legacy_actor_shortcut_rejected() {
        let json = r#"{
            "workspaceId": "ws",
            "actor": "claude",
            "item": { "itemType": "fact", "content": "x" }
        }"#;
        let err = serde_json::from_str::<MemPutArgs>(json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("actor") || msg.contains("actorId"),
            "legacy actor shortcut must not deserialize, got {msg}"
        );
    }

    #[test]
    fn legacy_scope_with_workspace_id_still_rejects_unknown_scope() {
        let json = r#"{
            "workspaceId": "vfx-rs",
            "scope": "vfx-rs",
            "actorId": "cursor",
            "item": { "itemType": "fact", "content": "x" }
        }"#;
        let err = serde_json::from_str::<MemPutArgs>(json).unwrap_err();
        assert!(err.to_string().contains("scope"));
    }

    #[test]
    fn missing_item_rejected() {
        let json = r#"{ "workspaceId": "ws", "actorId": "a" }"#;
        let err = serde_json::from_str::<MemPutArgs>(json).unwrap_err();
        assert!(err.to_string().contains("item"));
    }

    #[test]
    fn whitespace_actor_id_rejected_on_validate() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "   ",
            "item": { "itemType": "fact", "content": "x" }
        }"#;
        let args: MemPutArgs = serde_json::from_str(json).unwrap();
        let err = args.into_put_request().unwrap_err();
        assert!(err.contains("actorId"));
    }

    #[test]
    fn invalid_item_type_rejected() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "item": { "itemType": "not_a_type", "content": "x" }
        }"#;
        assert!(serde_json::from_str::<MemPutArgs>(json).is_err());
    }

    #[test]
    fn pascal_case_item_type_rejected() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "item": { "itemType": "Task", "content": {} }
        }"#;
        assert!(serde_json::from_str::<MemPutArgs>(json).is_err());
    }

    #[test]
    fn content_json_array_accepted() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "item": { "itemType": "artifact", "content": [1, 2, 3] }
        }"#;
        let args: MemPutArgs = serde_json::from_str(json).unwrap();
        let req = args.into_put_request().unwrap();
        assert!(req.item.content_json.is_array());
    }

    /// LLM sometimes sends JSON-looking text as a string; we store it as plain text (not parsed).
    #[test]
    fn stringified_json_content_stays_string_not_object() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "item": { "itemType": "task", "content": "{\"status\":\"open\"}" }
        }"#;
        let args: MemPutArgs = serde_json::from_str(json).unwrap();
        let req = args.into_put_request().unwrap();
        assert!(req.item.content_json.is_string());
        assert!(req.item.content_json.as_str().unwrap().contains("status"));
    }

    #[test]
    fn tags_must_be_array_not_stringified_json() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "item": {
                "itemType": "fact",
                "content": "x",
                "tags": "[\"vfx-rs\"]"
            }
        }"#;
        assert!(serde_json::from_str::<MemPutArgs>(json).is_err());
    }

    #[test]
    fn optional_scope_boundaries_round_trip() {
        let json = r#"{
            "workspaceId": "vfx-rs",
            "tenantId": "org",
            "appId": "app",
            "topicId": "pt-debug",
            "sessionId": "sess-1",
            "runId": "run-9",
            "actorId": "cursor",
            "actorType": "agent",
            "item": { "itemType": "task", "content": { "note": 1 } }
        }"#;
        let args: MemPutArgs = serde_json::from_str(json).unwrap();
        let req = args.into_put_request().unwrap();
        assert_eq!(req.scope.tenant_id, "org");
        assert_eq!(req.scope.topic_id.as_deref(), Some("pt-debug"));
        assert_eq!(req.scope.session_id.as_deref(), Some("sess-1"));
        assert_eq!(req.actor.actor_type, ActorType::Agent);
    }

    #[test]
    fn mem_search_empty_query_rejected() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "query": ""
        }"#;
        let args: MemSearchArgs = serde_json::from_str(json).unwrap();
        let err = args.into_search_request().unwrap_err();
        assert!(err.contains("query"));
    }

    #[test]
    fn mem_search_whitespace_query_rejected() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "query": "   \n\t"
        }"#;
        let args: MemSearchArgs = serde_json::from_str(json).unwrap();
        assert!(args.into_search_request().is_err());
    }

    #[test]
    fn mem_get_empty_ids_rejected() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "ids": []
        }"#;
        let args: MemGetArgs = serde_json::from_str(json).unwrap();
        let err = args.into_get_request().unwrap_err();
        assert!(err.contains("ids"));
    }

    #[test]
    fn mem_get_invalid_uuid_rejected() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "ids": ["not-a-uuid"]
        }"#;
        let args: MemGetArgs = serde_json::from_str(json).unwrap();
        let err = args.into_get_request().unwrap_err();
        assert!(err.contains("UUID"));
    }

    #[test]
    fn mem_get_ids_must_be_array() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "ids": "550e8400-e29b-41d4-a716-446655440000"
        }"#;
        assert!(serde_json::from_str::<MemGetArgs>(json).is_err());
    }

    #[test]
    fn mem_update_invalid_id_uuid_rejected() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "id": "bad-id",
            "item": { "itemType": "fact", "content": "y" }
        }"#;
        let args: MemUpdateArgs = serde_json::from_str(json).unwrap();
        let err = args.into_update_request().unwrap_err();
        assert!(err.contains("UUID"));
    }

    #[test]
    fn mem_link_empty_relation_type_rejected() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "relation": {
                "fromItemId": "550e8400-e29b-41d4-a716-446655440000",
                "toItemId": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                "relationType": "   "
            }
        }"#;
        let args: MemLinkArgs = serde_json::from_str(json).unwrap();
        let err = args.into_link_request().unwrap_err();
        assert!(err.contains("relationType"));
    }

    #[test]
    fn mem_link_invalid_from_item_id_rejected() {
        let json = r#"{
            "workspaceId": "ws",
            "actorId": "a",
            "relation": {
                "fromItemId": "nope",
                "toItemId": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                "relationType": "relates_to"
            }
        }"#;
        let args: MemLinkArgs = serde_json::from_str(json).unwrap();
        let err = args.into_link_request().unwrap_err();
        assert!(err.contains("fromItemId"));
    }

    #[test]
    fn mem_get_summary_defaults_to_workspace_level() {
        let json = r#"{ "workspaceId": "ws", "actorId": "a" }"#;
        let args: MemGetSummaryArgs = serde_json::from_str(json).unwrap();
        let req = args.into_get_summary_request().unwrap();
        assert_eq!(req.summary.level, "workspace");
    }

    #[test]
    fn mem_get_summary_topic_without_topic_id_rejected() {
        let json = r#"{ "workspaceId": "ws", "actorId": "a", "level": "topic" }"#;
        let args: MemGetSummaryArgs = serde_json::from_str(json).unwrap();
        let err = args.into_get_summary_request().unwrap_err();
        assert!(err.contains("topicId"));
    }

    #[test]
    fn mem_get_summary_session_without_session_id_rejected() {
        let json = r#"{ "workspaceId": "ws", "actorId": "a", "level": "session" }"#;
        let args: MemGetSummaryArgs = serde_json::from_str(json).unwrap();
        let err = args.into_get_summary_request().unwrap_err();
        assert!(err.contains("sessionId"));
    }

    #[test]
    fn strict_draft07_schema_for_mem_put_has_no_item_string_coercion() {
        use crate::core::schema::to_draft07_schema_strict;

        let schema = schemars::schema_for!(MemPutArgs);
        let mut value = serde_json::to_value(&schema).expect("schema");
        value = to_draft07_schema_strict(value);
        let item = &value["properties"]["item"];
        assert!(
            item.get("oneOf").is_none(),
            "mem_put item must not offer object-or-string coercion: {item}"
        );
    }
}
