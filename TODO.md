# TODO: Integration Plan

## Overview

Integrate 3 MCP servers + 2 document readers as optional Cargo features into filesystem-mcp-rs.

**Target:** Single binary with feature flags.

---

## Phase 1: Memory Tools (`memory-tools` feature)

### Source: `C:\projects\projects.rust\_mcp\memory-mcp-rs`

### Files to copy:
- `src/graph.rs` → `src/tools/memory/graph.rs`
- `src/storage.rs` → `src/tools/memory/storage.rs`
- `src/manager.rs` → `src/tools/memory/manager.rs`
- Create `src/tools/memory/mod.rs`

### Dependencies to add (conditional):
```toml
[dependencies]
rusqlite = { version = "0.37", features = ["bundled"], optional = true }
r2d2 = { version = "0.8", optional = true }
r2d2_sqlite = { version = "0.31", optional = true }
dirs = { version = "6.0", optional = true }

[features]
memory-tools = ["dep:rusqlite", "dep:r2d2", "dep:r2d2_sqlite", "dep:dirs"]
```

### Tools (9) with prefix `mem_`:
| Original | New Name |
|----------|----------|
| create_entities | mem_entities_create |
| create_relations | mem_relations_create |
| add_observations | mem_observations_add |
| delete_entities | mem_entities_delete |
| delete_observations | mem_observations_delete |
| delete_relations | mem_relations_delete |
| read_graph | mem_graph_read |
| search_nodes | mem_nodes_search |
| open_nodes | mem_nodes_open |

### CLI args:
- `--memory-db <PATH>` - database path (default: system data dir)

---

## Phase 2: Sequential Thinking (`thinking-tools` feature)

### Source: `C:\projects\projects.rust\_mcp\seq-thinking-rs`

### Files to copy:
- `src/thinking.rs` → `src/tools/thinking/thinking.rs`
- Create `src/tools/thinking/mod.rs`

### Dependencies: None extra (uses only std + serde)

### Tools (1):
| Original | New Name |
|----------|----------|
| sequentialthinking | seq_think |

### Feature:
```toml
[features]
thinking-tools = []
```

---

## Phase 3: LLM Tools (`llm-tools` feature)

### Source: `C:\projects\projects.rust\_mcp\llm-mcp-rs`

### Files to copy:
- `src/config.rs` → `src/tools/llm/config.rs`
- `src/error.rs` → `src/tools/llm/error.rs`
- `src/model.rs` → `src/tools/llm/model.rs`
- `src/model_mapping.rs` → `src/tools/llm/model_mapping.rs`
- `src/transform.rs` → `src/tools/llm/transform.rs`
- `src/providers/*.rs` → `src/tools/llm/providers/`
- Create `src/tools/llm/mod.rs`

### Dependencies to add (conditional):
```toml
[dependencies]
dotenvy = { version = "0.15", optional = true }
futures-util = { version = "0.3", optional = true }
thiserror = { version = "2.0", optional = true }
time = { version = "0.3", features = ["formatting"], optional = true }
toml = { version = "0.9", optional = true }
uuid = { version = "1.19", features = ["v4"], optional = true }

[features]
llm-tools = ["dep:dotenvy", "dep:futures-util", "dep:thiserror", "dep:time", "dep:toml", "dep:uuid"]
```

Note: `reqwest` already present in filesystem-mcp-rs.

### Tools (8) with prefix `ai_`:
| Original | New Name |
|----------|----------|
| messages | ai_chat |
| messages_gemini | ai_chat_gemini |
| messages_cerebras | ai_chat_cerebras |
| messages_openai | ai_chat_openai |
| count_tokens | ai_tokens |
| count_tokens_gemini | ai_tokens_gemini |
| count_tokens_cerebras | ai_tokens_cerebras |
| count_tokens_openai | ai_tokens_openai |

### CLI args:
- `--llm-config <PATH>` - config file path
- Env vars: `LLM_MCP_*` (existing from llm-mcp-rs)

---

## Phase 4: XLSX Reader (`xlsx-tools` feature)

### New files:
- `src/tools/xlsx.rs`

### Dependencies:
```toml
[dependencies]
calamine = { version = "0.26", optional = true }

[features]
xlsx-tools = ["dep:calamine"]
```

### Tools (2-3):
| Name | Description |
|------|-------------|
| xlsx_read | Read entire sheet or range as JSON |
| xlsx_sheets | List sheet names |
| xlsx_info | Get workbook metadata (sheets, dimensions) |

### Args schema:
```rust
struct XlsxReadArgs {
    path: String,
    sheet: Option<String>,      // sheet name or index
    range: Option<String>,      // e.g. "A1:D10"
    headers: Option<bool>,      // treat first row as headers
    max_rows: Option<u32>,      // limit rows
}
```

---

## Phase 5: DOCX Reader (`docx-tools` feature)

### New files:
- `src/tools/docx.rs`

### Dependencies:
```toml
[dependencies]
docx-rs = { version = "0.4", optional = true }
# or
zip = "7.1"  # already present, can parse docx manually
quick-xml = { version = "0.37", optional = true }
```

### Tools (2):
| Name | Description |
|------|-------------|
| docx_read | Extract text content from docx |
| docx_info | Get document metadata (author, pages, etc) |

### Args schema:
```rust
struct DocxReadArgs {
    path: String,
    include_headers: Option<bool>,
    include_footers: Option<bool>,
    max_chars: Option<u32>,
}
```

---

## Implementation Order

1. [x] **thinking-tools** - DONE (always on)
2. [x] **memory-tools** - DONE (always on)
3. [ ] **xlsx-tools** (single crate)
4. [ ] **docx-tools** (single crate)
5. [ ] **llm-tools** (most complex, many files)

---

## Architecture Changes

### main.rs modifications:
1. Add conditional `mod tools::memory/thinking/llm/xlsx/docx`
2. Add conditional fields to `FileSystemServer` struct
3. Add tools to `tool_router` conditionally
4. Add CLI args for each feature
5. Update `server_info()` instructions

### Cargo.toml:
```toml
[features]
default = ["http-tools", "s3-tools", "screenshot-tools"]
full = ["default", "memory-tools", "thinking-tools", "llm-tools", "xlsx-tools", "docx-tools"]
memory-tools = [...]
thinking-tools = []
llm-tools = [...]
xlsx-tools = ["dep:calamine"]
docx-tools = ["dep:quick-xml"]
```

---

## Testing Checklist

- [ ] Build with no features: `cargo build --no-default-features`
- [ ] Build with each feature individually
- [ ] Build with `--all-features`
- [ ] Test each tool group via MCP client
- [ ] Verify no feature leaks (code from disabled features not compiled)

---

## Notes

- All tools must use `#[cfg(feature = "xxx")]` guards
- Prefix tool descriptions with feature info for clarity
- Consider adding `--list-features` CLI flag to show enabled features
