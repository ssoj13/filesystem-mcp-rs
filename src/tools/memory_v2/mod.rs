//! Scoped memory v2 domain model.
//!
//! This module provides the scoped memory system used by the MCP server.

pub mod mcp_args;
pub mod sqlite;
pub mod types;

pub use mcp_args::{
    MemGetArgs, MemGetSummaryArgs, MemLinkArgs, MemPutArgs, MemSearchArgs, MemUpdateArgs, mem_get,
    mem_get_summary, mem_link, mem_put, mem_search, mem_update,
};
pub use sqlite::SqliteMemoryStore;
pub use types::MemoryAccessMode;
