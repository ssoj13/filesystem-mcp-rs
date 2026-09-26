//! Read-only SQL over the index, for questions a name search cannot answer: the largest files
//! under a folder, totals per extension, folders that hold two particular entries.
//!
//! The caller never sees the tables. Two temporary views expose the published entries of every
//! root, already limited to the directories the caller may read, and an authorizer refuses
//! anything else: writes, pragmas, other tables, functions that can allocate without bound.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use regex::Regex;
use rusqlite::functions::FunctionFlags;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, ErrorCode};

use super::*;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// What `locate_sql` tells the caller about the views and how to use them.
pub const SQL_GUIDE: &str = r"fs_entries: one row per indexed file, directory or symlink (the latest published scan of each root)
  path            full path, verbatim form: \\?\C:\dir\file
  name            last component
  dir             parent path (computed, not indexed)
  ext             lowercase extension without the dot; '' for directories and files without one
  kind            'file' | 'dir' | 'symlink'
  size            a file's own bytes; a directory's total beneath it (when the scan has totalled it)
  files, dirs     directories only: how many files and directories lie beneath
  modified        unix seconds
  depth           number of separators in path
fs_roots: path, state, last_verified (unix seconds), last_error

Functions: fs_ext(name); `text REGEXP pattern` (Rust regex); SQLite's GLOB, LIKE, lower, instr, substr, strftime(..., 'unixepoch'), CTEs and window functions. One SELECT only.

A subtree of P is  path >= 'P\' AND path < 'P]'  (']' follows '\'), which uses the primary key; filters on dir, ext and depth scan the subtree. Directory rows carry subtree totals, so SUM(size) over everything double counts: add kind='file'. The index is as fresh as fs_roots.last_verified.

Examples:
-- the 20 largest files under a folder
SELECT path,size FROM fs_entries WHERE kind='file' AND path>='\\?\C:\Temp\' AND path<'\\?\C:\Temp]' ORDER BY size DESC LIMIT 20
-- what takes the space: the children of a folder
SELECT name,size,files FROM fs_entries WHERE path>='\\?\C:\Users\me\' AND path<'\\?\C:\Users\me]' AND dir='\\?\C:\Users\me' ORDER BY size DESC LIMIT 20
-- size per extension
SELECT ext,count(*) n,sum(size) bytes FROM fs_entries WHERE kind='file' GROUP BY ext ORDER BY bytes DESC LIMIT 20
-- folders holding both Assets and ProjectSettings
SELECT a.dir FROM fs_entries a WHERE a.name='Assets' AND a.kind='dir' AND EXISTS (SELECT 1 FROM fs_entries b WHERE b.path=a.dir||'\ProjectSettings')
-- node_modules folders not nested in another one, biggest first
SELECT path,size FROM fs_entries WHERE name='node_modules' AND kind='dir' AND instr(path,'\node_modules\')=0 ORDER BY size DESC
-- files untouched for a year
SELECT path,size FROM fs_entries WHERE kind='file' AND modified < strftime('%s','now','-1 year') ORDER BY size DESC LIMIT 50";

#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

pub struct SqlQuery<'a> {
    pub sql: &'a str,
    /// Directories the caller may read; a row outside all of them is not visible. Empty: none.
    pub allowed: &'a [PathBuf],
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootInfo {
    pub path: PathBuf,
    pub state: String,
    pub last_verified: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Debug)]
pub struct SqlOutcome {
    pub columns: Vec<String>,
    /// Rows handed to the callback.
    pub rows: u64,
    /// The callback stopped the query before its last row.
    pub stopped: bool,
    pub elapsed_ms: u64,
    /// The scans the answer rests on.
    pub roots: Vec<RootInfo>,
}

impl Indexer {
    /// Run one read-only SELECT and hand each row to `on_row(columns, values)`, which returns
    /// whether to go on. Rows are streamed: nothing here holds the whole result.
    pub fn query_each(
        &self,
        query: &SqlQuery<'_>,
        mut on_row: impl FnMut(&[String], &[SqlValue]) -> Result<bool>,
    ) -> Result<SqlOutcome> {
        let started = Instant::now();
        let conn = connect(&self.db_path)?;
        let (roots, published) = published_roots(&conn)?;
        install_views(&conn, query.allowed, &published)?;
        // Views exist; from here on the connection can only read them. The index is far
        // bigger than SQLite's default cache and a scan over it is one long sweep: map the file
        // and keep a sizeable cache so the sweep is not a page-by-page read.
        conn.execute_batch(
            "PRAGMA query_only=ON; PRAGMA cache_size=-262144; PRAGMA mmap_size=17179869184;",
        )?;
        conn.authorizer(Some(authorize))?;
        let deadline = started + query.timeout;
        conn.progress_handler(1_000, Some(move || Instant::now() >= deadline))?;

        let mut stmt = conn
            .prepare(query.sql)
            .map_err(|error| explain(error, query))?;
        if !stmt.readonly() {
            bail!("only a read-only SELECT is allowed");
        }
        let columns: Vec<String> = stmt.column_names().into_iter().map(str::to_owned).collect();
        let mut rows = stmt.query([]).map_err(|error| explain(error, query))?;
        let mut values = Vec::with_capacity(columns.len());
        let mut count = 0u64;
        let mut stopped = false;
        loop {
            let row = match rows.next() {
                Ok(Some(row)) => row,
                Ok(None) => break,
                Err(error) => return Err(explain(error, query)),
            };
            values.clear();
            for index in 0..columns.len() {
                values.push(to_value(row.get_ref(index)?));
            }
            count += 1;
            if !on_row(&columns, &values)? {
                stopped = true;
                break;
            }
        }
        Ok(SqlOutcome {
            columns,
            rows: count,
            stopped,
            elapsed_ms: started.elapsed().as_millis() as u64,
            roots,
        })
    }
}

fn to_value(value: ValueRef<'_>) -> SqlValue {
    match value {
        ValueRef::Null => SqlValue::Null,
        ValueRef::Integer(number) => SqlValue::Int(number),
        ValueRef::Real(number) => SqlValue::Real(number),
        ValueRef::Text(text) => SqlValue::Text(String::from_utf8_lossy(text).into_owned()),
        ValueRef::Blob(bytes) => SqlValue::Blob(bytes.to_vec()),
    }
}

/// A timeout and a refused statement are the caller's to fix: say which, in words.
fn explain(error: rusqlite::Error, query: &SqlQuery<'_>) -> anyhow::Error {
    match error.sqlite_error_code() {
        Some(ErrorCode::OperationInterrupted) => anyhow!(
            "the query ran past its time limit of {} ms and was stopped; narrow it with a path range (path >= 'P\\' AND path < 'P]') or raise timeoutMs",
            query.timeout.as_millis()
        ),
        Some(ErrorCode::AuthorizationForStatementDenied) => anyhow!(
            "not allowed: only SELECT over the views fs_entries and fs_roots (help:true describes them)"
        ),
        _ => anyhow!("{error}"),
    }
}

/// Which rows of `entries` and `dir_stats` a root's answer rests on.
struct PublishedRoot {
    id: i64,
    generation: i64,
    attempt: i64,
}

fn published_roots(conn: &Connection) -> Result<(Vec<RootInfo>, Vec<PublishedRoot>)> {
    let mut stmt = conn.prepare(
        "SELECT path,state,last_verified,last_error,id,active_generation,published_attempt
         FROM roots WHERE active_generation>0 AND covered_by IS NULL ORDER BY path",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                RootInfo {
                    path: PathBuf::from(row.get::<_, String>(0)?),
                    state: row.get(1)?,
                    last_verified: row.get(2)?,
                    last_error: row.get(3)?,
                },
                PublishedRoot {
                    id: row.get(4)?,
                    generation: row.get(5)?,
                    attempt: row.get(6)?,
                },
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows.into_iter().unzip())
}

/// Everything except the views, and the columns and functions they need, is refused.
fn authorize(ctx: AuthContext<'_>) -> Authorization {
    let ours = |name: &str| matches!(name, "fs_entries" | "fs_roots");
    match ctx.action {
        AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
        // Functions that can allocate an arbitrary amount from one call.
        AuthAction::Function {
            function_name: "zeroblob" | "randomblob" | "load_extension" | "readfile" | "writefile",
        } => Authorization::Deny,
        AuthAction::Function { .. } => Authorization::Allow,
        // Reading a view is the caller's; reading the tables behind it is the view's own. A
        // read with no database behind it is one of the query's own CTEs or subqueries.
        AuthAction::Read { table_name, .. }
            if ours(table_name)
                || ctx.accessor.is_some_and(ours)
                || ctx.database_name.is_none() =>
        {
            Authorization::Allow
        }
        _ => Authorization::Deny,
    }
}

fn install_views(
    conn: &Connection,
    allowed: &[PathBuf],
    published: &[PublishedRoot],
) -> Result<()> {
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
    conn.create_scalar_function("fs_ext", 1, flags, |ctx| {
        Ok(match ctx.get_raw(0) {
            ValueRef::Text(bytes) => std::str::from_utf8(bytes).ok().map(extension),
            _ => None,
        })
    })?;
    conn.create_scalar_function("regexp", 2, flags, |ctx| {
        let text = match ctx.get_raw(1) {
            ValueRef::Text(bytes) => match std::str::from_utf8(bytes) {
                Ok(text) => text,
                Err(_) => return Ok(false),
            },
            _ => return Ok(false),
        };
        let pattern: Arc<Regex> = ctx.get_or_create_aux(0, |value| -> Result<Regex, BoxError> {
            Ok(Regex::new(value.as_str()?)?)
        })?;
        Ok(pattern.is_match(text))
    })?;
    // One arm per root, with its generation written in as a constant. Joined through `roots`
    // instead, SQLite reads the generation as a range and sweeps every index it owns rather
    // than seeking a name or a path, which turned seconds into minutes on a real index.
    let visible = visible(allowed)?;
    let arms: Vec<String> = published
        .iter()
        .map(|root| {
            format!(
                "SELECT e.path AS path, e.name AS name,
                        substr(e.path,1,length(e.path)-length(e.name)-1) AS dir,
                        CASE e.kind WHEN 'dir' THEN '' ELSE fs_ext(e.name) END AS ext,
                        e.kind AS kind,
                        COALESCE(d.bytes,e.size) AS size,
                        d.files AS files, d.dirs AS dirs,
                        e.modified AS modified,
                        length(e.path)-length(replace(e.path,'\\','')) AS depth
                 FROM entries e
                 LEFT JOIN dir_stats d
                   ON e.kind='dir' AND d.root_id={id} AND d.generation={attempt}
                  AND d.path=e.path
                 WHERE e.root_id={id} AND e.generation={generation} AND ({visible})",
                id = root.id,
                attempt = root.attempt,
                generation = root.generation,
            )
        })
        .collect();
    let body = if arms.is_empty() {
        "SELECT '' AS path, '' AS name, '' AS dir, '' AS ext, '' AS kind, 0 AS size,
                0 AS files, 0 AS dirs, 0 AS modified, 0 AS depth WHERE 0"
            .to_owned()
    } else {
        arms.join(" UNION ALL ")
    };
    conn.execute_batch(&format!(
        "CREATE TEMP VIEW fs_entries AS {body};
         CREATE TEMP VIEW fs_roots AS
         SELECT path,state,last_verified,last_error FROM roots
         WHERE active_generation>0 AND covered_by IS NULL;"
    ))?;
    Ok(())
}

/// SQL over `e.path` that is true for the allowed directories and everything beneath them.
fn visible(allowed: &[PathBuf]) -> Result<String> {
    if allowed.is_empty() {
        return Ok("0".into());
    }
    let literal = |text: &str| format!("'{}'", text.replace('\'', "''"));
    let mut terms = Vec::new();
    for dir in allowed {
        let text = path_text(dir)?;
        let bare = text.trim_end_matches(std::path::MAIN_SEPARATOR);
        // Descendants are `bare\...`; `]` is the character after the separator.
        terms.push(format!(
            "e.path={eq} OR (e.path>={lo} AND e.path<{hi})",
            eq = literal(text),
            lo = literal(&format!("{bare}{}", std::path::MAIN_SEPARATOR)),
            hi = literal(&format!("{bare}]")),
        ));
    }
    Ok(terms.join(" OR "))
}

/// Lowercase extension without the dot; empty when there is none.
fn extension(name: &str) -> String {
    Path::new(name)
        .extension()
        .map(|part| part.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}
