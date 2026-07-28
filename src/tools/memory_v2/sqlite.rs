use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use r2d2::Pool;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::task;
use uuid::Uuid;

use super::types::{
    ActorContext, ActorType, GetRequest, GetResponse, GetSummaryRequest, GetSummaryResponse,
    LinkRequest, LinkResponse, MemoryAccessMode, MemoryItem, MemoryItemInput, MemoryItemType,
    MemoryRelation, PutRequest, PutResponse, ScopeRef, SearchRequest, SearchResponse,
    UpdateRequest, UpdateResponse, Visibility,
};

const ITEM_COLS: &str = "id, tenant_id, app_id, workspace_id, topic_id, session_id, run_id, item_type, title, summary_text, content_json, visibility, status, tags_json, created_by_actor_id, owner_actor_id, source_kind, source_ref, confidence, expires_at, supersedes_id, created_at, updated_at, deleted_at";

const SCOPE_WHERE: &str = "tenant_id = ?1 AND app_id = ?2 AND workspace_id = ?3 AND (?4 IS NULL OR topic_id = ?4) AND (?5 IS NULL OR session_id = ?5) AND (?6 IS NULL OR run_id = ?6) AND deleted_at IS NULL";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS memory_items (
    id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL,
    app_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    topic_id TEXT,
    session_id TEXT,
    run_id TEXT,
    item_type TEXT NOT NULL,
    title TEXT,
    summary_text TEXT,
    content_json TEXT NOT NULL,
    visibility TEXT NOT NULL,
    status TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    created_by_actor_id TEXT NOT NULL,
    owner_actor_id TEXT,
    source_kind TEXT,
    source_ref TEXT,
    confidence REAL,
    expires_at TEXT,
    supersedes_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS idx_memory_items_scope
    ON memory_items(tenant_id, app_id, workspace_id);
CREATE INDEX IF NOT EXISTS idx_memory_items_topic
    ON memory_items(topic_id);
CREATE INDEX IF NOT EXISTS idx_memory_items_type
    ON memory_items(item_type);
CREATE INDEX IF NOT EXISTS idx_memory_items_created_at
    ON memory_items(created_at DESC);

CREATE TABLE IF NOT EXISTS memory_relations (
    id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL,
    app_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    topic_id TEXT,
    session_id TEXT,
    run_id TEXT,
    from_item_id TEXT NOT NULL,
    to_item_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    created_by_actor_id TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS idx_memory_relations_scope
    ON memory_relations(tenant_id, app_id, workspace_id);
CREATE INDEX IF NOT EXISTS idx_memory_relations_from
    ON memory_relations(from_item_id);
CREATE INDEX IF NOT EXISTS idx_memory_relations_to
    ON memory_relations(to_item_id);
"#;

#[derive(Debug)]
struct SqliteCustomizer;

impl r2d2::CustomizeConnection<Connection, rusqlite::Error> for SqliteCustomizer {
    fn on_acquire(&self, conn: &mut Connection) -> std::result::Result<(), rusqlite::Error> {
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        Ok(())
    }
}

/// Minimal r2d2 connection manager for a file-backed rusqlite database.
///
/// Replaces the `r2d2_sqlite` crate, whose sole purpose was this `ManageConnection`
/// impl (~15 lines). Inlining it drops the dependency and, more importantly, the
/// `rusqlite` version ceiling it imposed: `r2d2_sqlite` lagged at `rusqlite ^0.39`,
/// which clashed with our direct `rusqlite 0.40` (two `libsqlite3-sys` versions,
/// both linking the native `sqlite3` library — a hard resolver error). `r2d2`
/// itself is generic over the connection type, so the pool and `SqliteCustomizer`
/// are unaffected.
#[derive(Debug)]
struct SqliteManager {
    path: PathBuf,
}

impl r2d2::ManageConnection for SqliteManager {
    type Connection = Connection;
    type Error = rusqlite::Error;

    fn connect(&self) -> std::result::Result<Connection, rusqlite::Error> {
        Connection::open(&self.path)
    }

    fn is_valid(&self, conn: &mut Connection) -> std::result::Result<(), rusqlite::Error> {
        conn.execute_batch("SELECT 1")
    }

    fn has_broken(&self, _conn: &mut Connection) -> bool {
        false
    }
}

pub struct SqliteMemoryStore {
    db: Arc<Database>,
    access_mode: MemoryAccessMode,
}

impl SqliteMemoryStore {
    pub fn new(db_path: PathBuf, access_mode: MemoryAccessMode) -> Result<Self> {
        Ok(Self {
            db: Arc::new(Database::open(&db_path)?),
            access_mode,
        })
    }

    pub async fn search(&self, req: SearchRequest) -> Result<SearchResponse> {
        let db = self.db.clone();
        let access_mode = self.access_mode;
        task::spawn_blocking(move || db.search(req, access_mode))
            .await
            .context("Task panicked")?
    }

    pub async fn get(&self, req: GetRequest) -> Result<GetResponse> {
        let db = self.db.clone();
        let access_mode = self.access_mode;
        task::spawn_blocking(move || db.get(req, access_mode))
            .await
            .context("Task panicked")?
    }

    pub async fn put(&self, req: PutRequest) -> Result<PutResponse> {
        let db = self.db.clone();
        task::spawn_blocking(move || db.put(req))
            .await
            .context("Task panicked")?
    }

    pub async fn update(&self, req: UpdateRequest) -> Result<UpdateResponse> {
        let db = self.db.clone();
        let access_mode = self.access_mode;
        task::spawn_blocking(move || db.update(req, access_mode))
            .await
            .context("Task panicked")?
    }

    pub async fn link(&self, req: LinkRequest) -> Result<LinkResponse> {
        let db = self.db.clone();
        let access_mode = self.access_mode;
        task::spawn_blocking(move || db.link(req, access_mode))
            .await
            .context("Task panicked")?
    }

    pub async fn get_summary(&self, req: GetSummaryRequest) -> Result<GetSummaryResponse> {
        let db = self.db.clone();
        let access_mode = self.access_mode;
        task::spawn_blocking(move || db.get_summary(req, access_mode))
            .await
            .context("Task panicked")?
    }
}

struct Database {
    pool: Pool<SqliteManager>,
}

impl Database {
    fn open(path: &Path) -> Result<Self> {
        validate_db_path(path)?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let manager = SqliteManager {
            path: path.to_path_buf(),
        };
        let pool = Pool::builder()
            .max_size(8)
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

    fn search(&self, req: SearchRequest, access_mode: MemoryAccessMode) -> Result<SearchResponse> {
        let query = req.query.trim();
        if query.is_empty() {
            bail!("Search query cannot be empty");
        }

        let conn = self
            .pool
            .get()
            .context("Failed to get database connection")?;
        let like = format!("%{}%", query.to_ascii_lowercase());
        let limit = req.limit.clamp(1, 100);

        // The item-type / visibility / tag / access filters run in Rust
        // (`matches_filters`), but SQLite applies `LIMIT` *before* those filters
        // ever run. Binding `LIMIT ?8` straight onto the raw scope+LIKE match lets
        // the newest N rows monopolize the limit even when every one of them is
        // filtered out in Rust (e.g. private to another actor), which hid the
        // authorized older rows entirely (BH-20: a search that should return 10
        // returned 0). We instead page through the scope+LIKE matches newest-first,
        // apply `matches_filters` per page, and stop once we have `limit` authorized
        // items or the store is exhausted. `id` is the ORDER BY tie-breaker so
        // `(created_at, id)` is a total order and OFFSET paging can neither skip nor
        // duplicate rows that share a `created_at`.
        let sql = format!(
            "SELECT {ITEM_COLS} FROM memory_items WHERE {SCOPE_WHERE}
               AND lower(coalesce(title, '') || ' ' || coalesce(summary_text, '') || ' ' || content_json) LIKE ?7
             ORDER BY created_at DESC, id DESC LIMIT ?8 OFFSET ?9"
        );
        let mut stmt = conn.prepare(&sql)?;

        // Over-fetch a few multiples of `limit` per round-trip so a page still
        // yields enough authorized rows when most are filtered out, while keeping
        // the batch bounded.
        let batch_size = limit.saturating_mul(4).clamp(32, 512) as i64;

        let mut items: Vec<MemoryItem> = Vec::new();
        let mut offset: i64 = 0;
        'paging: loop {
            let rows = stmt.query_map(
                params![
                    &req.scope.tenant_id,
                    &req.scope.app_id,
                    &req.scope.workspace_id,
                    req.scope.topic_id.as_deref(),
                    req.scope.session_id.as_deref(),
                    req.scope.run_id.as_deref(),
                    &like,
                    batch_size,
                    offset,
                ],
                read_item_row,
            )?;

            let mut fetched = 0usize;
            for row in rows {
                fetched += 1;
                let item = row?;
                if matches_filters(
                    &item,
                    &req.actor,
                    &req.scope,
                    access_mode,
                    &req.item_types,
                    &req.visibility,
                    &req.tags,
                ) {
                    items.push(item);
                    if items.len() >= limit {
                        break 'paging;
                    }
                }
            }

            // A short page means the scope+LIKE matches are exhausted.
            if fetched < batch_size as usize {
                break 'paging;
            }
            offset += batch_size;
        }

        Ok(SearchResponse {
            relations: load_relations_for_items(
                &conn,
                &req.scope,
                items.iter().map(|item| item.id),
            )?,
            items,
        })
    }

    fn get(&self, req: GetRequest, access_mode: MemoryAccessMode) -> Result<GetResponse> {
        let conn = self
            .pool
            .get()
            .context("Failed to get database connection")?;
        let mut items = Vec::new();
        let sql = format!("SELECT {ITEM_COLS} FROM memory_items WHERE {SCOPE_WHERE} AND id = ?7");
        let mut stmt = conn.prepare(&sql)?;

        for id in req.ids {
            let item = stmt
                .query_row(
                    params![
                        &req.scope.tenant_id,
                        &req.scope.app_id,
                        &req.scope.workspace_id,
                        req.scope.topic_id.as_deref(),
                        req.scope.session_id.as_deref(),
                        req.scope.run_id.as_deref(),
                        id.to_string(),
                    ],
                    read_item_row,
                )
                .optional()?;

            if let Some(item) =
                item.filter(|item| can_read_item(item, &req.actor, &req.scope, access_mode))
            {
                items.push(item);
            }
        }

        Ok(GetResponse {
            relations: load_relations_for_items(
                &conn,
                &req.scope,
                items.iter().map(|item| item.id),
            )?,
            items,
        })
    }

    fn put(&self, req: PutRequest) -> Result<PutResponse> {
        let conn = self
            .pool
            .get()
            .context("Failed to get database connection")?;
        let now = now_rfc3339()?;
        let id = Uuid::new_v4();
        let item: MemoryItemInput = req.item;
        validate_scope_for_visibility(&req.scope, &item.visibility)?;

        conn.execute(
            "INSERT INTO memory_items (
                id, tenant_id, app_id, workspace_id, topic_id, session_id, run_id, item_type,
                title, summary_text, content_json, visibility, status, tags_json,
                created_by_actor_id, owner_actor_id, source_kind, source_ref, confidence,
                expires_at, supersedes_id, created_at, updated_at, deleted_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17, ?18, ?19,
                ?20, ?21, ?22, ?23, NULL
            )",
            params![
                id.to_string(),
                &req.scope.tenant_id,
                &req.scope.app_id,
                &req.scope.workspace_id,
                req.scope.topic_id.as_deref(),
                req.scope.session_id.as_deref(),
                req.scope.run_id.as_deref(),
                item.item_type.to_string(),
                item.title,
                item.summary_text,
                serde_json::to_string(&item.content_json)?,
                item.visibility.to_string(),
                item.status.unwrap_or_else(|| "active".to_string()),
                serde_json::to_string(&item.tags)?,
                &req.actor.actor_id,
                item.owner_actor_id.as_deref(),
                item.source_kind,
                item.source_ref,
                item.confidence,
                item.expires_at,
                item.supersedes_id.as_deref(),
                now,
                now,
            ],
        )?;

        Ok(PutResponse { id })
    }

    fn update(&self, req: UpdateRequest, access_mode: MemoryAccessMode) -> Result<UpdateResponse> {
        let conn = self
            .pool
            .get()
            .context("Failed to get database connection")?;
        let existing = read_item_by_id(&conn, &req.scope, req.id)?
            .ok_or_else(|| anyhow::anyhow!("Memory item {} not found in scope", req.id))?;
        if !can_write_item(&existing, &req.actor, access_mode) {
            bail!("Actor is not allowed to update memory item {}", req.id);
        }

        let item = req.item;
        // Mirror put()'s invariant: an update must not move an item to a (scope,
        // visibility) pair that `enforce_visibility` can never satisfy (BH-21). The
        // item is not relocated, so validate the new visibility against its stored
        // scope; e.g. switching to session visibility while the item's scope has no
        // session_id would render it permanently unreadable.
        validate_scope_for_visibility(&existing.scope, &item.visibility)?;
        let now = now_rfc3339()?;
        let updated = conn.execute(
            "UPDATE memory_items
             SET item_type = ?1,
                 title = ?2,
                 summary_text = ?3,
                 content_json = ?4,
                 visibility = ?5,
                 status = ?6,
                 tags_json = ?7,
                 owner_actor_id = ?8,
                 source_kind = ?9,
                 source_ref = ?10,
                 confidence = ?11,
                 expires_at = ?12,
                 supersedes_id = ?13,
                 updated_at = ?14
             WHERE id = ?15
               AND tenant_id = ?16
               AND app_id = ?17
               AND workspace_id = ?18
               AND (?19 IS NULL OR topic_id = ?19)
               AND (?20 IS NULL OR session_id = ?20)
               AND (?21 IS NULL OR run_id = ?21)
               AND deleted_at IS NULL",
            params![
                item.item_type.to_string(),
                item.title,
                item.summary_text,
                serde_json::to_string(&item.content_json)?,
                item.visibility.to_string(),
                item.status.unwrap_or_else(|| existing.status.clone()),
                serde_json::to_string(&item.tags)?,
                item.owner_actor_id.as_deref(),
                item.source_kind,
                item.source_ref,
                item.confidence,
                item.expires_at,
                item.supersedes_id.as_deref(),
                now,
                req.id.to_string(),
                &req.scope.tenant_id,
                &req.scope.app_id,
                &req.scope.workspace_id,
                req.scope.topic_id.as_deref(),
                req.scope.session_id.as_deref(),
                req.scope.run_id.as_deref(),
            ],
        )?;
        if updated == 0 {
            bail!("Memory item {} was not updated", req.id);
        }

        Ok(UpdateResponse { id: req.id })
    }

    fn link(&self, req: LinkRequest, access_mode: MemoryAccessMode) -> Result<LinkResponse> {
        let conn = self
            .pool
            .get()
            .context("Failed to get database connection")?;
        let relation = req.relation;
        let from_item =
            read_item_by_id(&conn, &req.scope, relation.from_item_id)?.ok_or_else(|| {
                anyhow::anyhow!("fromItemId {} not found in scope", relation.from_item_id)
            })?;
        let to_item =
            read_item_by_id(&conn, &req.scope, relation.to_item_id)?.ok_or_else(|| {
                anyhow::anyhow!("toItemId {} not found in scope", relation.to_item_id)
            })?;
        if !can_write_item(&from_item, &req.actor, access_mode)
            || !can_write_item(&to_item, &req.actor, access_mode)
        {
            bail!("Actor is not allowed to link the requested memory items");
        }

        let id = Uuid::new_v4();
        let now = now_rfc3339()?;
        conn.execute(
            "INSERT INTO memory_relations (
                id, tenant_id, app_id, workspace_id, topic_id, session_id, run_id,
                from_item_id, to_item_id, relation_type, created_by_actor_id, created_at
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                ?8, ?9, ?10, ?11, ?12
             )",
            params![
                id.to_string(),
                &req.scope.tenant_id,
                &req.scope.app_id,
                &req.scope.workspace_id,
                req.scope.topic_id.as_deref(),
                req.scope.session_id.as_deref(),
                req.scope.run_id.as_deref(),
                relation.from_item_id.to_string(),
                relation.to_item_id.to_string(),
                relation.relation_type,
                &req.actor.actor_id,
                now,
            ],
        )?;

        Ok(LinkResponse { id })
    }

    fn get_summary(
        &self,
        req: GetSummaryRequest,
        access_mode: MemoryAccessMode,
    ) -> Result<GetSummaryResponse> {
        let scope = normalize_summary_scope(&req.summary.level, &req.summary.scope)?;
        let conn = self
            .pool
            .get()
            .context("Failed to get database connection")?;
        let sql = format!(
            "SELECT {ITEM_COLS} FROM memory_items WHERE {SCOPE_WHERE}
               AND item_type = 'summary' ORDER BY created_at DESC LIMIT 1"
        );
        let mut stmt = conn.prepare(&sql)?;
        let item = stmt
            .query_row(
                params![
                    &scope.tenant_id,
                    &scope.app_id,
                    &scope.workspace_id,
                    scope.topic_id.as_deref(),
                    scope.session_id.as_deref(),
                    scope.run_id.as_deref(),
                ],
                read_item_row,
            )
            .optional()?;

        Ok(GetSummaryResponse {
            item: item.filter(|item| can_read_item(item, &req.actor, &scope, access_mode)),
        })
    }
}

fn validate_db_path(path: &Path) -> Result<()> {
    if path.extension().is_some_and(|ext| ext == "db") {
        return Ok(());
    }
    bail!("Database path must have .db extension")
}

fn now_rfc3339() -> Result<String> {
    Ok(OffsetDateTime::now_utc().format(&Rfc3339)?)
}

fn normalize_summary_scope(level: &str, scope: &ScopeRef) -> Result<ScopeRef> {
    let normalized = level.trim().to_ascii_lowercase();
    let normalized = if normalized.is_empty() {
        "topic".to_string()
    } else {
        normalized
    };

    match normalized.as_str() {
        "run" => {
            require_scope_id(&scope.run_id, "run", "run_id")?;
            Ok(scope.clone())
        }
        "session" => {
            require_scope_id(&scope.session_id, "session", "session_id")?;
            let mut s = scope.clone();
            s.run_id = None;
            Ok(s)
        }
        "topic" => {
            require_scope_id(&scope.topic_id, "topic", "topic_id")?;
            let mut s = scope.clone();
            s.session_id = None;
            s.run_id = None;
            Ok(s)
        }
        "workspace" => {
            let mut s = scope.clone();
            s.topic_id = None;
            s.session_id = None;
            s.run_id = None;
            Ok(s)
        }
        _ => bail!("Unsupported summary level: {normalized}"),
    }
}

fn require_scope_id(id: &Option<String>, level: &str, field_name: &str) -> Result<()> {
    if id.is_some() {
        return Ok(());
    }
    bail!("Summary level '{level}' requires scope.{field_name}")
}

fn validate_scope_for_visibility(scope: &ScopeRef, visibility: &Visibility) -> Result<()> {
    match visibility {
        Visibility::Session if scope.session_id.is_none() => {
            bail!("Visibility 'session' requires scope.session_id")
        }
        Visibility::Topic if scope.topic_id.is_none() => {
            bail!("Visibility 'topic' requires scope.topic_id")
        }
        _ => Ok(()),
    }
}

fn read_item_by_id(conn: &Connection, scope: &ScopeRef, id: Uuid) -> Result<Option<MemoryItem>> {
    let sql = format!("SELECT {ITEM_COLS} FROM memory_items WHERE {SCOPE_WHERE} AND id = ?7");
    let mut stmt = conn.prepare(&sql)?;
    stmt.query_row(
        params![
            &scope.tenant_id,
            &scope.app_id,
            &scope.workspace_id,
            scope.topic_id.as_deref(),
            scope.session_id.as_deref(),
            scope.run_id.as_deref(),
            id.to_string(),
        ],
        read_item_row,
    )
    .optional()
    .map_err(Into::into)
}

fn load_relations_for_items<I>(
    conn: &Connection,
    scope: &ScopeRef,
    item_ids: I,
) -> Result<Vec<MemoryRelation>>
where
    I: IntoIterator<Item = Uuid>,
{
    let visible_item_ids: HashSet<Uuid> = item_ids.into_iter().collect();
    if visible_item_ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut relations = Vec::new();
    let mut seen = HashSet::new();
    let mut stmt = conn.prepare(
        "SELECT id, tenant_id, app_id, workspace_id, topic_id, session_id, run_id,
                from_item_id, to_item_id, relation_type, created_by_actor_id, created_at
         FROM memory_relations
         WHERE tenant_id = ?1
           AND app_id = ?2
           AND workspace_id = ?3
           AND (?4 IS NULL OR topic_id = ?4)
           AND (?5 IS NULL OR session_id = ?5)
           AND (?6 IS NULL OR run_id = ?6)
           AND (from_item_id = ?7 OR to_item_id = ?7)",
    )?;

    for item_id in &visible_item_ids {
        let rows = stmt.query_map(
            params![
                &scope.tenant_id,
                &scope.app_id,
                &scope.workspace_id,
                scope.topic_id.as_deref(),
                scope.session_id.as_deref(),
                scope.run_id.as_deref(),
                item_id.to_string(),
            ],
            read_relation_row,
        )?;
        for row in rows {
            let relation = row?;
            let relation_is_visible = visible_item_ids.contains(&relation.from_item_id)
                && visible_item_ids.contains(&relation.to_item_id);
            if relation_is_visible && seen.insert(relation.id) {
                relations.push(relation);
            }
        }
    }

    Ok(relations)
}

fn read_item_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryItem> {
    Ok(MemoryItem {
        id: parse_uuid(row.get::<_, String>(0)?)?,
        scope: ScopeRef {
            tenant_id: row.get::<_, String>(1)?,
            app_id: row.get::<_, String>(2)?,
            workspace_id: row.get::<_, String>(3)?,
            topic_id: row.get::<_, Option<String>>(4)?,
            session_id: row.get::<_, Option<String>>(5)?,
            run_id: row.get::<_, Option<String>>(6)?,
        },
        item_type: row
            .get::<_, String>(7)?
            .parse::<MemoryItemType>()
            .map_err(to_from_sql_error_message)?,
        title: row.get(8)?,
        summary_text: row.get(9)?,
        content_json: serde_json::from_str::<Value>(&row.get::<_, String>(10)?)
            .map_err(to_from_sql_error)?,
        visibility: row
            .get::<_, String>(11)?
            .parse::<Visibility>()
            .map_err(to_from_sql_error_message)?,
        status: row.get(12)?,
        tags: serde_json::from_str(&row.get::<_, String>(13)?).map_err(to_from_sql_error)?,
        created_by_actor_id: row.get::<_, String>(14)?,
        owner_actor_id: row.get::<_, Option<String>>(15)?,
        source_kind: row.get(16)?,
        source_ref: row.get(17)?,
        confidence: row.get(18)?,
        expires_at: row.get(19)?,
        supersedes_id: row.get::<_, Option<String>>(20)?,
        created_at: row.get(21)?,
        updated_at: row.get(22)?,
        deleted_at: row.get(23)?,
    })
}

fn read_relation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryRelation> {
    Ok(MemoryRelation {
        id: parse_uuid(row.get::<_, String>(0)?)?,
        scope: ScopeRef {
            tenant_id: row.get::<_, String>(1)?,
            app_id: row.get::<_, String>(2)?,
            workspace_id: row.get::<_, String>(3)?,
            topic_id: row.get::<_, Option<String>>(4)?,
            session_id: row.get::<_, Option<String>>(5)?,
            run_id: row.get::<_, Option<String>>(6)?,
        },
        from_item_id: parse_uuid(row.get::<_, String>(7)?)?,
        to_item_id: parse_uuid(row.get::<_, String>(8)?)?,
        relation_type: row.get(9)?,
        created_by_actor_id: row.get::<_, String>(10)?,
        created_at: row.get(11)?,
    })
}

fn parse_uuid(value: String) -> rusqlite::Result<Uuid> {
    value.parse::<Uuid>().map_err(to_from_sql_error)
}

fn to_from_sql_error<E: std::error::Error + Send + Sync + 'static>(err: E) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
}

fn to_from_sql_error_message(err: String) -> rusqlite::Error {
    to_from_sql_error(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

fn matches_filters(
    item: &MemoryItem,
    actor: &ActorContext,
    scope: &ScopeRef,
    access_mode: MemoryAccessMode,
    item_types: &[MemoryItemType],
    visibility: &[Visibility],
    tags: &[String],
) -> bool {
    if !can_read_item(item, actor, scope, access_mode) {
        return false;
    }
    if !item_types.is_empty() && !item_types.contains(&item.item_type) {
        return false;
    }
    if !visibility.is_empty() && !visibility.contains(&item.visibility) {
        return false;
    }
    if !tags.is_empty() && !tags.iter().all(|tag| item.tags.contains(tag)) {
        return false;
    }
    true
}

fn can_read_item(
    item: &MemoryItem,
    actor: &ActorContext,
    request_scope: &ScopeRef,
    access_mode: MemoryAccessMode,
) -> bool {
    match access_mode {
        MemoryAccessMode::AllowAll => true,
        MemoryAccessMode::EnforcePrivateOnly => {
            item.visibility != Visibility::Private || has_item_control(item, actor)
        }
        MemoryAccessMode::EnforceVisibility => {
            if has_item_control(item, actor) {
                return true;
            }

            match item.visibility {
                Visibility::Private => false,
                Visibility::Session => {
                    item.scope.session_id.is_some()
                        && request_scope.session_id == item.scope.session_id
                }
                Visibility::Topic => {
                    item.scope.topic_id.is_some() && request_scope.topic_id == item.scope.topic_id
                }
                Visibility::Workspace => request_scope.workspace_id == item.scope.workspace_id,
                Visibility::App => request_scope.app_id == item.scope.app_id,
                Visibility::Tenant => request_scope.tenant_id == item.scope.tenant_id,
                Visibility::PublicRead => true,
            }
        }
    }
}

fn can_write_item(item: &MemoryItem, actor: &ActorContext, access_mode: MemoryAccessMode) -> bool {
    match access_mode {
        MemoryAccessMode::AllowAll => true,
        MemoryAccessMode::EnforcePrivateOnly => {
            item.visibility != Visibility::Private || has_item_control(item, actor)
        }
        MemoryAccessMode::EnforceVisibility => has_item_control(item, actor),
    }
}

fn has_item_control(item: &MemoryItem, actor: &ActorContext) -> bool {
    item.created_by_actor_id == actor.actor_id
        || item.owner_actor_id.as_deref() == Some(actor.actor_id.as_str())
        || actor.actor_type == ActorType::System
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::SqliteMemoryStore;
    use crate::tools::memory_v2::types::{
        ActorContext, ActorType, GetRequest, GetSummaryRequest, LinkRequest, MemoryAccessMode,
        MemoryItemInput, MemoryItemType, MemoryRelationInput, PutRequest, ScopeRef, SearchRequest,
        SummaryRef, UpdateRequest, Visibility,
    };

    fn scope() -> ScopeRef {
        ScopeRef {
            tenant_id: "test-tenant".to_string(),
            app_id: "test-app".to_string(),
            workspace_id: "test-workspace".to_string(),
            topic_id: Some("test-topic".to_string()),
            session_id: Some("test-session".to_string()),
            run_id: None,
        }
    }

    fn actor() -> ActorContext {
        ActorContext {
            actor_id: "test-actor".to_string(),
            actor_type: ActorType::Agent,
            tenant_user_id: Some("user_joss".to_string()),
            host_user: Some("joss1".to_string()),
            environment: Some("local".to_string()),
            impersonated_user_id: None,
        }
    }

    fn other_actor() -> ActorContext {
        ActorContext {
            actor_id: "other-actor".to_string(),
            actor_type: ActorType::Agent,
            tenant_user_id: Some("user_other".to_string()),
            host_user: Some("other1".to_string()),
            environment: Some("local".to_string()),
            impersonated_user_id: None,
        }
    }

    #[tokio::test]
    async fn put_search_and_get_round_trip() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("memory2.db");
        let store = SqliteMemoryStore::new(path, MemoryAccessMode::AllowAll).expect("store");
        let scope = scope();
        let actor = actor();

        let put = store
            .put(PutRequest {
                scope: scope.clone(),
                actor: actor.clone(),
                item: MemoryItemInput {
                    item_type: MemoryItemType::Decision,
                    title: Some("Deprecate full graph reads".to_string()),
                    summary_text: Some("Switch to scoped retrieval".to_string()),
                    content_json: serde_json::json!({
                        "summary": "read-all is forbidden",
                        "rationale": "scoped memory only"
                    }),
                    visibility: Visibility::Workspace,
                    status: Some("active".to_string()),
                    tags: vec!["memory".to_string(), "v2".to_string()],
                    owner_actor_id: None,
                    source_kind: Some("test".to_string()),
                    source_ref: None,
                    confidence: Some(0.9),
                    expires_at: None,
                    supersedes_id: None,
                },
            })
            .await
            .expect("put");

        let search = store
            .search(SearchRequest {
                scope: scope.clone(),
                actor: actor.clone(),
                query: "scoped retrieval".to_string(),
                item_types: vec![MemoryItemType::Decision],
                tags: vec!["memory".to_string()],
                visibility: vec![Visibility::Workspace],
                limit: 10,
            })
            .await
            .expect("search");
        assert_eq!(search.items.len(), 1);
        assert_eq!(search.items[0].id, put.id);

        let get = store
            .get(GetRequest {
                scope,
                actor,
                ids: vec![put.id],
            })
            .await
            .expect("get");
        assert_eq!(get.items.len(), 1);
        assert_eq!(
            get.items[0].title.as_deref(),
            Some("Deprecate full graph reads")
        );
    }

    #[tokio::test]
    async fn update_and_link_round_trip() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("memory2.db");
        let store = SqliteMemoryStore::new(path, MemoryAccessMode::AllowAll).expect("store");
        let scope = scope();
        let actor = actor();

        let first = store
            .put(PutRequest {
                scope: scope.clone(),
                actor: actor.clone(),
                item: MemoryItemInput {
                    item_type: MemoryItemType::Task,
                    title: Some("Original task".to_string()),
                    summary_text: None,
                    content_json: serde_json::json!({ "step": 1 }),
                    visibility: Visibility::Workspace,
                    status: Some("active".to_string()),
                    tags: vec!["memory".to_string()],
                    owner_actor_id: None,
                    source_kind: None,
                    source_ref: None,
                    confidence: None,
                    expires_at: None,
                    supersedes_id: None,
                },
            })
            .await
            .expect("put first");
        let second = store
            .put(PutRequest {
                scope: scope.clone(),
                actor: actor.clone(),
                item: MemoryItemInput {
                    item_type: MemoryItemType::Decision,
                    title: Some("Decision".to_string()),
                    summary_text: None,
                    content_json: serde_json::json!({ "status": "accepted" }),
                    visibility: Visibility::Workspace,
                    status: Some("active".to_string()),
                    tags: vec!["memory".to_string()],
                    owner_actor_id: None,
                    source_kind: None,
                    source_ref: None,
                    confidence: None,
                    expires_at: None,
                    supersedes_id: None,
                },
            })
            .await
            .expect("put second");

        store
            .update(UpdateRequest {
                scope: scope.clone(),
                actor: actor.clone(),
                id: first.id,
                item: MemoryItemInput {
                    item_type: MemoryItemType::Task,
                    title: Some("Updated task".to_string()),
                    summary_text: Some("Scope-safe update".to_string()),
                    content_json: serde_json::json!({ "step": 2 }),
                    visibility: Visibility::Workspace,
                    status: Some("done".to_string()),
                    tags: vec!["memory".to_string(), "updated".to_string()],
                    owner_actor_id: None,
                    source_kind: Some("test".to_string()),
                    source_ref: None,
                    confidence: Some(1.0),
                    expires_at: None,
                    supersedes_id: None,
                },
            })
            .await
            .expect("update");

        store
            .link(LinkRequest {
                scope: scope.clone(),
                actor: actor.clone(),
                relation: MemoryRelationInput {
                    from_item_id: first.id,
                    to_item_id: second.id,
                    relation_type: "depends_on".to_string(),
                },
            })
            .await
            .expect("link");

        let get = store
            .get(GetRequest {
                scope,
                actor,
                ids: vec![first.id, second.id],
            })
            .await
            .expect("get");
        assert_eq!(get.items.len(), 2);
        assert_eq!(get.relations.len(), 1);
        assert_eq!(get.relations[0].relation_type, "depends_on");
        assert!(
            get.items
                .iter()
                .any(|item| item.title.as_deref() == Some("Updated task"))
        );
    }

    #[tokio::test]
    async fn enforce_visibility_hides_private_items_from_other_actors() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("memory2.db");
        let store =
            SqliteMemoryStore::new(path, MemoryAccessMode::EnforceVisibility).expect("store");
        let scope = scope();
        let actor = actor();
        let outsider = other_actor();

        let put = store
            .put(PutRequest {
                scope: scope.clone(),
                actor: actor.clone(),
                item: MemoryItemInput {
                    item_type: MemoryItemType::Fact,
                    title: Some("Private note".to_string()),
                    summary_text: None,
                    content_json: serde_json::json!({ "value": 1 }),
                    visibility: Visibility::Private,
                    status: Some("active".to_string()),
                    tags: vec![],
                    owner_actor_id: None,
                    source_kind: None,
                    source_ref: None,
                    confidence: None,
                    expires_at: None,
                    supersedes_id: None,
                },
            })
            .await
            .expect("put");

        let get = store
            .get(GetRequest {
                scope,
                actor: outsider,
                ids: vec![put.id],
            })
            .await
            .expect("get");
        assert!(get.items.is_empty());
    }

    #[tokio::test]
    async fn enforce_visibility_hides_relations_to_private_items() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("memory2.db");
        let store =
            SqliteMemoryStore::new(path, MemoryAccessMode::EnforceVisibility).expect("store");
        let scope = scope();
        let actor = actor();
        let outsider = other_actor();

        let visible = store
            .put(PutRequest {
                scope: scope.clone(),
                actor: actor.clone(),
                item: MemoryItemInput {
                    item_type: MemoryItemType::Task,
                    title: Some("Visible task".to_string()),
                    summary_text: None,
                    content_json: serde_json::json!({ "kind": "visible" }),
                    visibility: Visibility::Workspace,
                    status: Some("active".to_string()),
                    tags: vec!["memory".to_string()],
                    owner_actor_id: None,
                    source_kind: None,
                    source_ref: None,
                    confidence: None,
                    expires_at: None,
                    supersedes_id: None,
                },
            })
            .await
            .expect("put visible");
        let sibling = store
            .put(PutRequest {
                scope: scope.clone(),
                actor: actor.clone(),
                item: MemoryItemInput {
                    item_type: MemoryItemType::Decision,
                    title: Some("Visible sibling".to_string()),
                    summary_text: None,
                    content_json: serde_json::json!({ "kind": "sibling" }),
                    visibility: Visibility::Workspace,
                    status: Some("active".to_string()),
                    tags: vec!["memory".to_string()],
                    owner_actor_id: None,
                    source_kind: None,
                    source_ref: None,
                    confidence: None,
                    expires_at: None,
                    supersedes_id: None,
                },
            })
            .await
            .expect("put sibling");
        let hidden = store
            .put(PutRequest {
                scope: scope.clone(),
                actor: actor.clone(),
                item: MemoryItemInput {
                    item_type: MemoryItemType::Fact,
                    title: Some("Hidden private note".to_string()),
                    summary_text: None,
                    content_json: serde_json::json!({ "kind": "private" }),
                    visibility: Visibility::Private,
                    status: Some("active".to_string()),
                    tags: vec!["memory".to_string()],
                    owner_actor_id: None,
                    source_kind: None,
                    source_ref: None,
                    confidence: None,
                    expires_at: None,
                    supersedes_id: None,
                },
            })
            .await
            .expect("put hidden");

        store
            .link(LinkRequest {
                scope: scope.clone(),
                actor: actor.clone(),
                relation: MemoryRelationInput {
                    from_item_id: visible.id,
                    to_item_id: sibling.id,
                    relation_type: "depends_on".to_string(),
                },
            })
            .await
            .expect("link visible sibling");
        store
            .link(LinkRequest {
                scope: scope.clone(),
                actor: actor.clone(),
                relation: MemoryRelationInput {
                    from_item_id: visible.id,
                    to_item_id: hidden.id,
                    relation_type: "references".to_string(),
                },
            })
            .await
            .expect("link visible hidden");

        let search = store
            .search(SearchRequest {
                scope: scope.clone(),
                actor: outsider.clone(),
                query: "visible".to_string(),
                item_types: vec![],
                tags: vec![],
                visibility: vec![],
                limit: 10,
            })
            .await
            .expect("search");
        assert_eq!(search.items.len(), 2);
        assert_eq!(search.relations.len(), 1);
        assert_eq!(search.relations[0].from_item_id, visible.id);
        assert_eq!(search.relations[0].to_item_id, sibling.id);

        let get = store
            .get(GetRequest {
                scope,
                actor: outsider,
                ids: vec![visible.id, sibling.id, hidden.id],
            })
            .await
            .expect("get");
        assert_eq!(get.items.len(), 2);
        assert_eq!(get.relations.len(), 1);
        assert_eq!(get.relations[0].from_item_id, visible.id);
        assert_eq!(get.relations[0].to_item_id, sibling.id);
    }

    #[tokio::test]
    async fn enforce_private_only_keeps_workspace_items_shared() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("memory2.db");
        let store =
            SqliteMemoryStore::new(path, MemoryAccessMode::EnforcePrivateOnly).expect("store");
        let scope = scope();
        let actor = actor();
        let outsider = other_actor();

        let put = store
            .put(PutRequest {
                scope: scope.clone(),
                actor,
                item: MemoryItemInput {
                    item_type: MemoryItemType::Fact,
                    title: Some("Shared workspace fact".to_string()),
                    summary_text: None,
                    content_json: serde_json::json!({ "value": 2 }),
                    visibility: Visibility::Workspace,
                    status: Some("active".to_string()),
                    tags: vec![],
                    owner_actor_id: None,
                    source_kind: None,
                    source_ref: None,
                    confidence: None,
                    expires_at: None,
                    supersedes_id: None,
                },
            })
            .await
            .expect("put");

        let get = store
            .get(GetRequest {
                scope,
                actor: outsider,
                ids: vec![put.id],
            })
            .await
            .expect("get");
        assert_eq!(get.items.len(), 1);
    }

    #[tokio::test]
    async fn get_summary_requires_requested_scope_level_ids() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("memory2.db");
        let store = SqliteMemoryStore::new(path, MemoryAccessMode::AllowAll).expect("store");
        let actor = actor();
        let workspace_scope = ScopeRef {
            tenant_id: "sum-tenant".to_string(),
            app_id: "sum-app".to_string(),
            workspace_id: "sum-workspace".to_string(),
            topic_id: None,
            session_id: None,
            run_id: None,
        };
        let topic_scope = ScopeRef {
            tenant_id: workspace_scope.tenant_id.clone(),
            app_id: workspace_scope.app_id.clone(),
            workspace_id: workspace_scope.workspace_id.clone(),
            topic_id: Some("sum-topic".to_string()),
            session_id: None,
            run_id: None,
        };
        let session_scope = ScopeRef {
            tenant_id: workspace_scope.tenant_id.clone(),
            app_id: workspace_scope.app_id.clone(),
            workspace_id: workspace_scope.workspace_id.clone(),
            topic_id: topic_scope.topic_id.clone(),
            session_id: Some("sum-session".to_string()),
            run_id: None,
        };

        let topic_err = store
            .get_summary(GetSummaryRequest {
                summary: SummaryRef {
                    level: "topic".to_string(),
                    scope: workspace_scope.clone(),
                },
                actor: actor.clone(),
            })
            .await
            .expect_err("topic scope should require topic_id");
        assert!(
            topic_err
                .to_string()
                .contains("Summary level 'topic' requires scope.topic_id")
        );

        let session_err = store
            .get_summary(GetSummaryRequest {
                summary: SummaryRef {
                    level: "session".to_string(),
                    scope: topic_scope,
                },
                actor: actor.clone(),
            })
            .await
            .expect_err("session scope should require session_id");
        assert!(
            session_err
                .to_string()
                .contains("Summary level 'session' requires scope.session_id")
        );

        let run_err = store
            .get_summary(GetSummaryRequest {
                summary: SummaryRef {
                    level: "run".to_string(),
                    scope: session_scope,
                },
                actor,
            })
            .await
            .expect_err("run scope should require run_id");
        assert!(
            run_err
                .to_string()
                .contains("Summary level 'run' requires scope.run_id")
        );
    }

    #[tokio::test]
    async fn get_summary_workspace_round_trip() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("memory2.db");
        let store = SqliteMemoryStore::new(path, MemoryAccessMode::AllowAll).expect("store");
        let actor = actor();
        let scope = ScopeRef {
            tenant_id: "default".to_string(),
            app_id: "default".to_string(),
            workspace_id: "vfx-rs".to_string(),
            topic_id: None,
            session_id: None,
            run_id: None,
        };

        store
            .put(PutRequest {
                scope: scope.clone(),
                actor: actor.clone(),
                item: MemoryItemInput {
                    item_type: MemoryItemType::Summary,
                    title: Some("vfx-rs context".into()),
                    summary_text: Some("workspace summary smoke".into()),
                    content_json: serde_json::json!({"focus": "Path Tracer"}),
                    visibility: Visibility::Workspace,
                    status: None,
                    tags: vec![],
                    owner_actor_id: None,
                    source_kind: None,
                    source_ref: None,
                    confidence: None,
                    expires_at: None,
                    supersedes_id: None,
                },
            })
            .await
            .expect("put summary");

        let loaded = store
            .get_summary(GetSummaryRequest {
                summary: SummaryRef {
                    level: "workspace".to_string(),
                    scope: scope.clone(),
                },
                actor: actor.clone(),
            })
            .await
            .expect("get summary");
        let item = loaded.item.expect("summary item");
        assert_eq!(item.item_type, MemoryItemType::Summary);
        assert_eq!(item.title.as_deref(), Some("vfx-rs context"));
    }

    /// Builds a searchable item whose serialized content carries a shared token,
    /// so a single query LIKE-matches every item regardless of title/visibility.
    fn item_with(title: &str, visibility: Visibility) -> MemoryItemInput {
        MemoryItemInput {
            item_type: MemoryItemType::Fact,
            title: Some(title.to_string()),
            summary_text: None,
            content_json: serde_json::json!({ "token": "sharedneedle" }),
            visibility,
            status: Some("active".to_string()),
            tags: vec![],
            owner_actor_id: None,
            source_kind: None,
            source_ref: None,
            confidence: None,
            expires_at: None,
            supersedes_id: None,
        }
    }

    /// BH-20: the SQL `LIMIT` must apply to already-authorized rows. With the 20
    /// newest matches private to another actor and 10 older workspace-visible ones,
    /// a search by an outsider must still return the 10 authorized items — the
    /// pre-fix code applied `LIMIT 10` to the raw match set (all private) and
    /// returned 0.
    #[tokio::test]
    async fn search_returns_authorized_items_hidden_behind_the_limit() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("memory2.db");
        let store =
            SqliteMemoryStore::new(path, MemoryAccessMode::EnforceVisibility).expect("store");
        let scope = scope();
        let author = actor();
        let outsider = other_actor();

        // 10 older workspace-visible items (readable by any actor in the workspace).
        for i in 0..10 {
            store
                .put(PutRequest {
                    scope: scope.clone(),
                    actor: author.clone(),
                    item: item_with(&format!("workspace visible {i}"), Visibility::Workspace),
                })
                .await
                .expect("put workspace item");
        }

        // Guarantee the private batch sorts strictly newer than the workspace batch
        // so it would monopolize a naive SQL LIMIT (created_at is wall-clock).
        std::thread::sleep(std::time::Duration::from_millis(50));

        // 20 newest items private to the author -> invisible to the outsider.
        for i in 0..20 {
            store
                .put(PutRequest {
                    scope: scope.clone(),
                    actor: author.clone(),
                    item: item_with(&format!("private secret {i}"), Visibility::Private),
                })
                .await
                .expect("put private item");
        }

        let search = store
            .search(SearchRequest {
                scope: scope.clone(),
                actor: outsider,
                query: "sharedneedle".to_string(),
                item_types: vec![],
                tags: vec![],
                visibility: vec![],
                limit: 10,
            })
            .await
            .expect("search");

        assert_eq!(
            search.items.len(),
            10,
            "all authorized workspace items must survive the limit"
        );
        assert!(
            search
                .items
                .iter()
                .all(|item| item.visibility == Visibility::Workspace),
            "only workspace-visible items should be returned to the outsider"
        );
    }

    /// BH-21: update() must enforce the same (scope, visibility) invariant as put().
    /// Moving a workspace item to session visibility while the scope has no
    /// session_id would make it permanently unreadable, so it must be rejected —
    /// and put() rejects the identical pair, proving parity.
    #[tokio::test]
    async fn update_rejects_illegal_scope_visibility_pair() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("memory2.db");
        let store = SqliteMemoryStore::new(path, MemoryAccessMode::AllowAll).expect("store");
        let actor = actor();
        // Scope without a session id: session-visibility items are illegal here.
        let scope = ScopeRef {
            tenant_id: "test-tenant".to_string(),
            app_id: "test-app".to_string(),
            workspace_id: "test-workspace".to_string(),
            topic_id: Some("test-topic".to_string()),
            session_id: None,
            run_id: None,
        };

        let put = store
            .put(PutRequest {
                scope: scope.clone(),
                actor: actor.clone(),
                item: item_with("workspace item", Visibility::Workspace),
            })
            .await
            .expect("put workspace item");

        let err = store
            .update(UpdateRequest {
                scope: scope.clone(),
                actor: actor.clone(),
                id: put.id,
                item: item_with("now session-scoped", Visibility::Session),
            })
            .await
            .expect_err("update to session visibility must be rejected");
        assert!(
            err.to_string()
                .contains("Visibility 'session' requires scope.session_id"),
            "unexpected error: {err}"
        );

        // The identical (scope, visibility) pair is likewise rejected by put().
        let put_err = store
            .put(PutRequest {
                scope,
                actor,
                item: item_with("illegal session item", Visibility::Session),
            })
            .await
            .expect_err("put with session visibility must be rejected");
        assert!(
            put_err
                .to_string()
                .contains("Visibility 'session' requires scope.session_id"),
            "unexpected error: {put_err}"
        );
    }
}
