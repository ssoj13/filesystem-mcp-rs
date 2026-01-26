//! Memory tools for knowledge graph management.
//!
//! Provides tools for creating, querying, and managing entities and relations
//! in a persistent SQLite-backed knowledge graph.

pub mod graph;
pub mod manager;
pub mod storage;

pub use graph::{Entity, ObservationDeletion, ObservationInput, Relation};
pub use manager::KnowledgeGraphManager;
