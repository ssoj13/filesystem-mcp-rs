//! Async manager for knowledge graph operations.

use super::graph::{
    Entity, KnowledgeGraph, ObservationDeletion, ObservationInput, ObservationResult, Relation,
};
use super::storage::Database;
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;

/// Manager for knowledge graph operations.
/// Provides async API wrapping SQLite database with proper blocking isolation.
pub struct KnowledgeGraphManager {
    db: Arc<Database>,
}

impl KnowledgeGraphManager {
    /// Create new manager with database at given path
    pub fn new(db_path: PathBuf) -> Result<Self> {
        let db = Database::open(&db_path)?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Create entities (returns only newly created entities)
    pub async fn create_entities(&self, entities: Vec<Entity>) -> Result<Vec<Entity>> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || db.create_entities(&entities))
            .await
            .context("Task panicked")?
    }

    /// Create relations (returns only newly created relations)
    pub async fn create_relations(&self, relations: Vec<Relation>) -> Result<Vec<Relation>> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || db.create_relations(&relations))
            .await
            .context("Task panicked")?
    }

    /// Add observations to multiple entities (batch operation)
    pub async fn add_observations(
        &self,
        inputs: Vec<ObservationInput>,
    ) -> Result<Vec<ObservationResult>> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || db.add_observations(&inputs))
            .await
            .context("Task panicked")?
    }

    /// Delete entities (cascade deletes relations via FOREIGN KEY)
    pub async fn delete_entities(&self, names: Vec<String>) -> Result<usize> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || db.delete_entities(&names))
            .await
            .context("Task panicked")?
    }

    /// Delete observations from multiple entities (batch operation)
    pub async fn delete_observations(&self, deletions: Vec<ObservationDeletion>) -> Result<()> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || db.delete_observations(&deletions))
            .await
            .context("Task panicked")?
    }

    /// Delete relations
    pub async fn delete_relations(&self, relations: Vec<Relation>) -> Result<usize> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || db.delete_relations(&relations))
            .await
            .context("Task panicked")?
    }

    /// Read entire knowledge graph
    pub async fn read_graph(&self) -> Result<KnowledgeGraph> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || db.read_graph())
            .await
            .context("Task panicked")?
    }

    /// Search nodes using FTS5 full-text search
    pub async fn search_nodes(&self, query: Option<String>) -> Result<KnowledgeGraph> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || db.search_nodes(query.as_deref()))
            .await
            .context("Task panicked")?
    }

    /// Open specific nodes by names
    pub async fn open_nodes(&self, names: Vec<String>) -> Result<KnowledgeGraph> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || db.open_nodes(&names))
            .await
            .context("Task panicked")?
    }
}
