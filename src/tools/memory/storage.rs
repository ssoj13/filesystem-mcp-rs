//! SQLite storage backend for knowledge graph.

use super::graph::{
    Entity, KnowledgeGraph, ObservationDeletion, ObservationInput, ObservationResult, Relation,
};
use anyhow::{bail, Context, Result};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashSet;
use std::path::Path;

// Validation constants
const MAX_NAME_LENGTH: usize = 256;
const MAX_TYPE_LENGTH: usize = 128;
const MAX_OBSERVATION_LENGTH: usize = 4096;

/// Connection customizer to set PRAGMAs on every new connection
#[derive(Debug)]
struct SqliteCustomizer;

impl r2d2::CustomizeConnection<Connection, rusqlite::Error> for SqliteCustomizer {
    fn on_acquire(&self, conn: &mut Connection) -> std::result::Result<(), rusqlite::Error> {
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        Ok(())
    }
}

fn validate_name(name: &str, field: &str) -> Result<()> {
    if name.is_empty() {
        bail!("{} cannot be empty", field);
    }
    if name.len() > MAX_NAME_LENGTH {
        bail!("{} too long (max {} chars)", field, MAX_NAME_LENGTH);
    }
    if name.chars().any(|c| c.is_control() || c == '\0') {
        bail!("{} contains invalid characters", field);
    }
    Ok(())
}

fn validate_type(type_str: &str, field: &str) -> Result<()> {
    if type_str.is_empty() {
        bail!("{} cannot be empty", field);
    }
    if type_str.len() > MAX_TYPE_LENGTH {
        bail!("{} too long (max {} chars)", field, MAX_TYPE_LENGTH);
    }
    if !type_str
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':')
    {
        bail!(
            "{} contains invalid characters (only alphanumeric, -, _, ., : allowed)",
            field
        );
    }
    Ok(())
}

fn validate_observation(obs: &str) -> Result<()> {
    if obs.len() > MAX_OBSERVATION_LENGTH {
        bail!("Observation too long (max {} chars)", MAX_OBSERVATION_LENGTH);
    }
    if obs.contains('\0') {
        bail!("Observation contains null bytes");
    }
    Ok(())
}

fn build_placeholders(count: usize, offset: usize) -> String {
    (offset..offset + count)
        .map(|i| format!("?{}", i))
        .collect::<Vec<_>>()
        .join(", ")
}

fn sanitize_fts5_query(query: &str) -> String {
    query
        .split_whitespace()
        .map(|term| {
            let stripped = term.trim_matches('"');
            let escaped = stripped.replace('"', "\"\"");
            format!("\"{}\"", escaped)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn validate_db_path(path: &Path) -> Result<()> {
    if let Some(ext) = path.extension() {
        if ext != "db" {
            bail!("Invalid database file extension (must be .db)");
        }
    } else {
        bail!("Database path must have .db extension");
    }
    Ok(())
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS entities (
    name TEXT PRIMARY KEY NOT NULL,
    entity_type TEXT NOT NULL,
    observations TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS relations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_entity TEXT NOT NULL,
    to_entity TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    UNIQUE(from_entity, to_entity, relation_type),
    FOREIGN KEY(from_entity) REFERENCES entities(name) ON DELETE CASCADE,
    FOREIGN KEY(to_entity) REFERENCES entities(name) ON DELETE CASCADE
) STRICT;

CREATE INDEX IF NOT EXISTS idx_entity_type ON entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_from ON relations(from_entity);
CREATE INDEX IF NOT EXISTS idx_to ON relations(to_entity);
CREATE INDEX IF NOT EXISTS idx_relation_type ON relations(relation_type);
CREATE INDEX IF NOT EXISTS idx_relations_from_type ON relations(from_entity, relation_type);
CREATE INDEX IF NOT EXISTS idx_relations_to_type ON relations(to_entity, relation_type);

CREATE VIRTUAL TABLE IF NOT EXISTS entities_fts USING fts5(
    name, entity_type, observations,
    content='entities', content_rowid='rowid'
);

CREATE TRIGGER IF NOT EXISTS entities_ai AFTER INSERT ON entities BEGIN
    INSERT INTO entities_fts(rowid, name, entity_type, observations)
    VALUES (new.rowid, new.name, new.entity_type, new.observations);
END;

CREATE TRIGGER IF NOT EXISTS entities_ad AFTER DELETE ON entities BEGIN
    INSERT INTO entities_fts(entities_fts, rowid, name, entity_type, observations)
    VALUES ('delete', old.rowid, old.name, old.entity_type, old.observations);
END;

CREATE TRIGGER IF NOT EXISTS entities_au AFTER UPDATE ON entities BEGIN
    INSERT INTO entities_fts(entities_fts, rowid, name, entity_type, observations)
    VALUES ('delete', old.rowid, old.name, old.entity_type, old.observations);
    INSERT INTO entities_fts(rowid, name, entity_type, observations)
    VALUES (new.rowid, new.name, new.entity_type, new.observations);
END;
"#;

pub struct Database {
    pool: Pool<SqliteConnectionManager>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        validate_db_path(path)?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder()
            .max_size(15)
            .connection_customizer(Box::new(SqliteCustomizer))
            .build(manager)
            .context("Failed to create connection pool")?;

        {
            let conn = pool.get().context("Failed to get connection from pool")?;
            conn.execute_batch("PRAGMA journal_mode = WAL;")?;
            conn.execute_batch(SCHEMA)?;
        }

        Ok(Self { pool })
    }

    pub fn create_entities(&self, entities: &[Entity]) -> Result<Vec<Entity>> {
        if entities.is_empty() {
            return Ok(Vec::new());
        }

        for entity in entities {
            validate_name(&entity.name, "Entity name")?;
            validate_type(&entity.entity_type, "Entity type")?;
            for obs in &entity.observations {
                validate_observation(obs)?;
            }
        }

        let conn = self.pool.get().context("Failed to get database connection")?;
        let tx = conn.unchecked_transaction().context("Failed to start transaction")?;
        let mut new_entities = Vec::new();

        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR IGNORE INTO entities (name, entity_type, observations) VALUES (?1, ?2, ?3)"
            )?;

            for entity in entities {
                let obs_json = serde_json::to_string(&entity.observations)?;
                let rows_affected = stmt.execute(params![&entity.name, &entity.entity_type, &obs_json])?;
                if rows_affected > 0 {
                    new_entities.push(entity.clone());
                }
            }
        }

        tx.commit()?;
        Ok(new_entities)
    }

    pub fn create_relations(&self, relations: &[Relation]) -> Result<Vec<Relation>> {
        if relations.is_empty() {
            return Ok(Vec::new());
        }

        for rel in relations {
            validate_name(&rel.from, "From entity")?;
            validate_name(&rel.to, "To entity")?;
            validate_type(&rel.relation_type, "Relation type")?;
        }

        let conn = self.pool.get().context("Failed to get database connection")?;
        let tx = conn.unchecked_transaction().context("Failed to start transaction")?;
        let mut new_relations = Vec::new();

        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR IGNORE INTO relations (from_entity, to_entity, relation_type) VALUES (?1, ?2, ?3)"
            )?;

            for rel in relations {
                match stmt.execute(params![&rel.from, &rel.to, &rel.relation_type]) {
                    Ok(rows_affected) => {
                        if rows_affected > 0 {
                            new_relations.push(rel.clone());
                        }
                    }
                    Err(rusqlite::Error::SqliteFailure(err, _)) => {
                        if err.code == rusqlite::ErrorCode::ConstraintViolation {
                            bail!(
                                "Cannot create relation '{}' -> '{}': one or both entities do not exist",
                                rel.from, rel.to
                            );
                        }
                        return Err(err.into());
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }

        tx.commit()?;
        Ok(new_relations)
    }

    pub fn add_observations(&self, inputs: &[ObservationInput]) -> Result<Vec<ObservationResult>> {
        for input in inputs {
            validate_name(&input.entity_name, "Entity name")?;
            for obs in &input.contents {
                validate_observation(obs)?;
            }
        }

        let conn = self.pool.get().context("Failed to get database connection")?;
        let tx = conn.unchecked_transaction()?;
        let mut results = Vec::new();

        for input in inputs {
            let current: Option<String> = tx
                .query_row(
                    "SELECT observations FROM entities WHERE name = ?1",
                    params![&input.entity_name],
                    |row| row.get(0),
                )
                .optional()?;

            let current = current.with_context(|| {
                format!("Entity '{}' does not exist", input.entity_name)
            })?;

            let mut observations: Vec<String> = serde_json::from_str(&current)?;
            let mut added = Vec::new();

            for obs in &input.contents {
                if !observations.contains(obs) {
                    observations.push(obs.clone());
                    added.push(obs.clone());
                }
            }

            if !added.is_empty() {
                let obs_json = serde_json::to_string(&observations)?;
                tx.execute(
                    "UPDATE entities SET observations = ?1 WHERE name = ?2",
                    params![&obs_json, &input.entity_name],
                )?;
            }

            results.push(ObservationResult {
                entity_name: input.entity_name.clone(),
                added_observations: added,
            });
        }

        tx.commit()?;
        Ok(results)
    }

    pub fn delete_entities(&self, names: &[String]) -> Result<usize> {
        if names.is_empty() {
            return Ok(0);
        }

        for name in names {
            validate_name(name, "Entity name")?;
        }

        let conn = self.pool.get().context("Failed to get database connection")?;
        let tx = conn.unchecked_transaction()?;

        let placeholders = build_placeholders(names.len(), 1);
        let query = format!("DELETE FROM entities WHERE name IN ({})", placeholders);
        let params: Vec<&dyn rusqlite::ToSql> = names.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

        let count = tx.execute(&query, params.as_slice())?;
        tx.commit()?;
        Ok(count)
    }

    pub fn delete_observations(&self, deletions: &[ObservationDeletion]) -> Result<()> {
        for deletion in deletions {
            validate_name(&deletion.entity_name, "Entity name")?;
        }

        let conn = self.pool.get().context("Failed to get database connection")?;
        let tx = conn.unchecked_transaction()?;

        for deletion in deletions {
            let current: Option<String> = tx
                .query_row(
                    "SELECT observations FROM entities WHERE name = ?1",
                    params![&deletion.entity_name],
                    |row| row.get(0),
                )
                .optional()?;

            let current = current.with_context(|| {
                format!("Entity '{}' does not exist", deletion.entity_name)
            })?;

            let mut observations: Vec<String> = serde_json::from_str(&current)?;
            observations.retain(|obs| !deletion.observations.contains(obs));

            let obs_json = serde_json::to_string(&observations)?;
            tx.execute(
                "UPDATE entities SET observations = ?1 WHERE name = ?2",
                params![&obs_json, &deletion.entity_name],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn delete_relations(&self, relations: &[Relation]) -> Result<usize> {
        if relations.is_empty() {
            return Ok(0);
        }

        for rel in relations {
            validate_name(&rel.from, "From entity")?;
            validate_name(&rel.to, "To entity")?;
            validate_type(&rel.relation_type, "Relation type")?;
        }

        let conn = self.pool.get().context("Failed to get database connection")?;
        let tx = conn.unchecked_transaction()?;
        let mut count = 0;

        {
            let mut stmt = tx.prepare_cached(
                "DELETE FROM relations WHERE from_entity = ?1 AND to_entity = ?2 AND relation_type = ?3"
            )?;

            for rel in relations {
                count += stmt.execute(params![&rel.from, &rel.to, &rel.relation_type])?;
            }
        }

        tx.commit()?;
        Ok(count)
    }

    pub fn read_graph(&self) -> Result<KnowledgeGraph> {
        let conn = self.pool.get().context("Failed to get database connection")?;
        let entities = self.read_all_entities(&conn)?;
        let relations = self.read_all_relations(&conn)?;
        Ok(KnowledgeGraph { entities, relations })
    }

    fn read_all_entities(&self, conn: &Connection) -> Result<Vec<Entity>> {
        let mut stmt = conn.prepare("SELECT name, entity_type, observations FROM entities")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;

        let mut entities = Vec::new();
        for row in rows {
            let (name, entity_type, obs_json) = row?;
            let observations: Vec<String> = serde_json::from_str(&obs_json)?;
            entities.push(Entity { name, entity_type, observations });
        }
        Ok(entities)
    }

    fn read_all_relations(&self, conn: &Connection) -> Result<Vec<Relation>> {
        let mut stmt = conn.prepare("SELECT from_entity, to_entity, relation_type FROM relations")?;
        let rows = stmt.query_map([], |row| {
            Ok(Relation {
                from: row.get(0)?,
                to: row.get(1)?,
                relation_type: row.get(2)?,
            })
        })?;

        let mut relations = Vec::new();
        for row in rows {
            relations.push(row?);
        }
        Ok(relations)
    }

    pub fn search_nodes(&self, query: Option<&str>) -> Result<KnowledgeGraph> {
        let trimmed = query.map(|q| q.trim()).unwrap_or("");
        if trimmed.is_empty() {
            return self.read_graph();
        }

        let conn = self.pool.get().context("Failed to get database connection")?;
        let safe_query = sanitize_fts5_query(trimmed);
        let entities = self.search_entities_fts(&conn, &safe_query)?;
        let relations = self.get_relations_between(&conn, &entities)?;
        Ok(KnowledgeGraph { entities, relations })
    }

    fn search_entities_fts(&self, conn: &Connection, fts_query: &str) -> Result<Vec<Entity>> {
        let mut stmt = conn.prepare(
            "SELECT e.name, e.entity_type, e.observations
             FROM entities e
             INNER JOIN entities_fts fts ON e.rowid = fts.rowid
             WHERE entities_fts MATCH ?1"
        )?;

        let rows = stmt.query_map(params![fts_query], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;

        let mut entities = Vec::new();
        for row in rows {
            let (name, entity_type, obs_json) = row?;
            let observations: Vec<String> = serde_json::from_str(&obs_json)?;
            entities.push(Entity { name, entity_type, observations });
        }
        Ok(entities)
    }

    fn get_relations_between(&self, conn: &Connection, entities: &[Entity]) -> Result<Vec<Relation>> {
        if entities.is_empty() {
            return Ok(Vec::new());
        }

        let entity_names: HashSet<_> = entities.iter().map(|e| &e.name).collect();
        let placeholders_from = build_placeholders(entity_names.len(), 1);
        let placeholders_to = build_placeholders(entity_names.len(), entity_names.len() + 1);

        let query = format!(
            "SELECT from_entity, to_entity, relation_type FROM relations
             WHERE from_entity IN ({}) AND to_entity IN ({})",
            placeholders_from, placeholders_to
        );

        let mut params: Vec<&dyn rusqlite::ToSql> = Vec::new();
        for name in &entity_names {
            params.push(*name);
        }
        for name in &entity_names {
            params.push(*name);
        }

        let mut stmt = conn.prepare(&query)?;
        let rows = stmt.query_map(params.as_slice(), |row| {
            Ok(Relation {
                from: row.get(0)?,
                to: row.get(1)?,
                relation_type: row.get(2)?,
            })
        })?;

        let mut relations = Vec::new();
        for row in rows {
            relations.push(row?);
        }
        Ok(relations)
    }

    pub fn open_nodes(&self, names: &[String]) -> Result<KnowledgeGraph> {
        if names.is_empty() {
            return Ok(KnowledgeGraph::default());
        }

        for name in names {
            validate_name(name, "Entity name")?;
        }

        let conn = self.pool.get().context("Failed to get database connection")?;
        let entities = self.read_entities_by_names(&conn, names)?;
        let relations = self.get_relations_between(&conn, &entities)?;
        Ok(KnowledgeGraph { entities, relations })
    }

    fn read_entities_by_names(&self, conn: &Connection, names: &[String]) -> Result<Vec<Entity>> {
        let placeholders = build_placeholders(names.len(), 1);
        let query = format!(
            "SELECT name, entity_type, observations FROM entities WHERE name IN ({})",
            placeholders
        );

        let params: Vec<&dyn rusqlite::ToSql> = names.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let mut stmt = conn.prepare(&query)?;
        let rows = stmt.query_map(params.as_slice(), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;

        let mut entities = Vec::new();
        for row in rows {
            let (name, entity_type, obs_json) = row?;
            let observations: Vec<String> = serde_json::from_str(&obs_json)?;
            entities.push(Entity { name, entity_type, observations });
        }
        Ok(entities)
    }
}
