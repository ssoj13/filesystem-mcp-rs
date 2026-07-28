use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    HumanUser,
    ServiceUser,
    Agent,
    LlmProvider,
    System,
}

impl ActorType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HumanUser => "human_user",
            Self::ServiceUser => "service_user",
            Self::Agent => "agent",
            Self::LlmProvider => "llm_provider",
            Self::System => "system",
        }
    }
}

impl fmt::Display for ActorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ActorType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "human_user" => Ok(Self::HumanUser),
            "service_user" => Ok(Self::ServiceUser),
            "agent" => Ok(Self::Agent),
            "llm_provider" => Ok(Self::LlmProvider),
            "system" => Ok(Self::System),
            _ => Err(format!("unsupported actor type: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryItemType {
    Fact,
    Episode,
    Task,
    Decision,
    Artifact,
    Summary,
}

impl MemoryItemType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fact => "fact",
            Self::Episode => "episode",
            Self::Task => "task",
            Self::Decision => "decision",
            Self::Artifact => "artifact",
            Self::Summary => "summary",
        }
    }
}

impl fmt::Display for MemoryItemType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MemoryItemType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "fact" => Ok(Self::Fact),
            "episode" => Ok(Self::Episode),
            "task" => Ok(Self::Task),
            "decision" => Ok(Self::Decision),
            "artifact" => Ok(Self::Artifact),
            "summary" => Ok(Self::Summary),
            _ => Err(format!("unsupported memory item type: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Private,
    Session,
    Topic,
    Workspace,
    App,
    Tenant,
    PublicRead,
}

impl Visibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Session => "session",
            Self::Topic => "topic",
            Self::Workspace => "workspace",
            Self::App => "app",
            Self::Tenant => "tenant",
            Self::PublicRead => "public_read",
        }
    }
}

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Visibility {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "private" => Ok(Self::Private),
            "session" => Ok(Self::Session),
            "topic" => Ok(Self::Topic),
            "workspace" => Ok(Self::Workspace),
            "app" => Ok(Self::App),
            "tenant" => Ok(Self::Tenant),
            "public_read" => Ok(Self::PublicRead),
            _ => Err(format!("unsupported visibility: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAccessMode {
    AllowAll,
    #[default]
    EnforcePrivateOnly,
    EnforceVisibility,
}

impl MemoryAccessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllowAll => "allow_all",
            Self::EnforcePrivateOnly => "enforce_private_only",
            Self::EnforceVisibility => "enforce_visibility",
        }
    }
}

impl fmt::Display for MemoryAccessMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MemoryAccessMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "allow_all" => Ok(Self::AllowAll),
            "enforce_private_only" => Ok(Self::EnforcePrivateOnly),
            "enforce_visibility" => Ok(Self::EnforceVisibility),
            _ => Err(format!("unsupported memory access mode: {s}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScopeRef {
    pub tenant_id: String,
    pub app_id: String,
    pub workspace_id: String,
    pub topic_id: Option<String>,
    pub session_id: Option<String>,
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ActorContext {
    pub actor_id: String,
    pub actor_type: ActorType,
    pub tenant_user_id: Option<String>,
    pub host_user: Option<String>,
    pub environment: Option<String>,
    pub impersonated_user_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryItem {
    pub id: Uuid,
    pub scope: ScopeRef,
    pub item_type: MemoryItemType,
    pub title: Option<String>,
    pub summary_text: Option<String>,
    pub content_json: Value,
    pub visibility: Visibility,
    pub status: String,
    pub tags: Vec<String>,
    pub created_by_actor_id: String,
    pub owner_actor_id: Option<String>,
    pub source_kind: Option<String>,
    pub source_ref: Option<String>,
    pub confidence: Option<f32>,
    pub expires_at: Option<String>,
    pub supersedes_id: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryItemInput {
    pub item_type: MemoryItemType,
    pub title: Option<String>,
    pub summary_text: Option<String>,
    pub content_json: Value,
    pub visibility: Visibility,
    pub status: Option<String>,
    pub tags: Vec<String>,
    pub owner_actor_id: Option<String>,
    pub source_kind: Option<String>,
    pub source_ref: Option<String>,
    pub confidence: Option<f32>,
    pub expires_at: Option<String>,
    pub supersedes_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryRelation {
    pub id: Uuid,
    pub scope: ScopeRef,
    pub from_item_id: Uuid,
    pub to_item_id: Uuid,
    pub relation_type: String,
    pub created_by_actor_id: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryRelationInput {
    pub from_item_id: Uuid,
    pub to_item_id: Uuid,
    pub relation_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SummaryRef {
    pub level: String,
    pub scope: ScopeRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SearchRequest {
    pub scope: ScopeRef,
    pub actor: ActorContext,
    pub query: String,
    pub item_types: Vec<MemoryItemType>,
    pub tags: Vec<String>,
    pub visibility: Vec<Visibility>,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SearchResponse {
    pub items: Vec<MemoryItem>,
    pub relations: Vec<MemoryRelation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GetRequest {
    pub scope: ScopeRef,
    pub actor: ActorContext,
    pub ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GetResponse {
    pub items: Vec<MemoryItem>,
    pub relations: Vec<MemoryRelation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PutRequest {
    pub scope: ScopeRef,
    pub actor: ActorContext,
    pub item: MemoryItemInput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PutResponse {
    pub id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRequest {
    pub scope: ScopeRef,
    pub actor: ActorContext,
    pub id: Uuid,
    pub item: MemoryItemInput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateResponse {
    pub id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LinkRequest {
    pub scope: ScopeRef,
    pub actor: ActorContext,
    pub relation: MemoryRelationInput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LinkResponse {
    pub id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GetSummaryRequest {
    pub summary: SummaryRef,
    pub actor: ActorContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GetSummaryResponse {
    pub item: Option<MemoryItem>,
}

#[cfg(test)]
mod tests {
    use super::{ActorContext, ActorType, MemoryAccessMode, MemoryItemType, ScopeRef, Visibility};

    #[test]
    fn scope_ref_preserves_optional_boundaries() {
        let scope = ScopeRef {
            tenant_id: "test-tenant".to_string(),
            app_id: "test-app".to_string(),
            workspace_id: "test-workspace".to_string(),
            topic_id: None,
            session_id: None,
            run_id: None,
        };

        assert!(scope.topic_id.is_none());
        assert!(scope.session_id.is_none());
        assert!(scope.run_id.is_none());
    }

    #[test]
    fn actor_and_visibility_enums_cover_v2_defaults() {
        let actor = ActorContext {
            actor_id: "test-actor".to_string(),
            actor_type: ActorType::Agent,
            tenant_user_id: Some("user_joss".to_string()),
            host_user: Some("joss1".to_string()),
            environment: Some("local".to_string()),
            impersonated_user_id: None,
        };

        assert_eq!(actor.actor_type, ActorType::Agent);
        assert_eq!(MemoryItemType::Summary, MemoryItemType::Summary);
        assert_eq!(Visibility::Workspace, Visibility::Workspace);
        assert_eq!(
            "allow_all".parse::<MemoryAccessMode>().expect("mode"),
            MemoryAccessMode::AllowAll
        );
        assert_eq!(
            "enforce_private_only"
                .parse::<MemoryAccessMode>()
                .expect("mode"),
            MemoryAccessMode::EnforcePrivateOnly
        );
    }
}
