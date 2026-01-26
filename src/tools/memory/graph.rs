//! Knowledge graph data structures.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Entity in the knowledge graph
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Entity {
    /// Unique name of the entity (serves as ID)
    pub name: String,

    /// Type of entity (person, organization, concept, etc.)
    #[serde(rename = "entityType")]
    pub entity_type: String,

    /// Array of observations (facts) about the entity
    pub observations: Vec<String>,
}

/// Relation between two entities
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Relation {
    /// Source entity name
    pub from: String,

    /// Target entity name
    pub to: String,

    /// Type of relation (works_at, knows, related_to, etc.)
    #[serde(rename = "relationType")]
    pub relation_type: String,
}

/// Complete knowledge graph
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KnowledgeGraph {
    pub entities: Vec<Entity>,
    pub relations: Vec<Relation>,
}

/// Input for adding observations to an entity
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ObservationInput {
    #[serde(rename = "entityName")]
    pub entity_name: String,
    pub contents: Vec<String>,
}

/// Result of adding observations
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ObservationResult {
    #[serde(rename = "entityName")]
    pub entity_name: String,
    #[serde(rename = "addedObservations")]
    pub added_observations: Vec<String>,
}

/// Input for deleting observations from an entity
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ObservationDeletion {
    #[serde(rename = "entityName")]
    pub entity_name: String,
    pub observations: Vec<String>,
}
