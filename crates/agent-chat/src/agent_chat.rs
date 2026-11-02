//! Live chat between agents on one machine, independent of any MCP framework.
//!
//! `store` is `chat.db`, the only channel between processes. `session` is one agent's view of it
//! and turns unread messages into text. `wait` is the blocking wait behind the `chat-wait` command,
//! which an agent keeps running in the background so that a new message wakes it while it is idle.
//! `address` is the `project:topic:name:parent` scheme.
//!
//! Used by filesystem-mcp-rs, whose `src/tools/chat.rs` exposes this as `chat_*` tools and puts
//! delivered text on tool results. The reasoning is in
//! `docs/superpowers/specs/2026-10-31-agent-chat-design.md`.

pub mod address;
pub mod session;
pub mod store;
pub mod wait;
