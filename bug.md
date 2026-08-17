# BUG — filesystem-mcp-rs from playa G4 editor port (2026-08-15)

Session: Grok + filesystem MCP session lock, repo `cglibs/playa` branch `playa3`.
Format matches `BUG2.md` / `BUG3.md`.

**This is filesystem-mcp-rs**, not GitNexus / Telegram / Chrome. The host error is always:

```
Failed to call <tool>: failed to deserialize parameters: missing field `<name>`
```

The field **was in the tool call**. The server never ran the tool body. Serde rejected the args object because the host (or the ContentRef schema) dropped a required key first.

---

## BUG-001: `edit_file` — `missing field newText` (regression of BUG3-002)

- **Status:** fixed (TextOrRef dual form + grep path aliases)
- **Tool:** `edit_file`
- **When:** 2026-08-15, playa `node_graph.rs` port
- **Server:** `filesystem` / `filesystem-mcp-rs` (same binary; dual-registered)

### What happened

`EditOperation` is:

```rust
// src/main.rs ~689
old_text: ContentRef,  // rename = "oldText"
new_text: ContentRef,  // rename = "newText"
```

`ContentRef` is an internally tagged enum, **object only** — no bare-string dual form (`content_plane.rs` line 34–46). Schema `oneOf` + `required: [oldText, newText]`.

The agent sent valid ContentRefs:

```json
{
  "path": ".../node_graph.rs",
  "edits": [{
    "oldText": {"kind": "inline", "text": "..."},
    "newText": {"kind": "inline", "text": "use nodes_core::{NodeLibrary, NodeType};"}
  }]
}
```

The wrapper failed **before** `edit_file` ran:

```
Failed to call edit_file: failed to deserialize parameters: missing field `newText`
```

Not `invalid type: string, expected internally tagged enum`. The key `newText` is **absent** from the JSON that reached serde.

### Repro matrix (this session, same file)

| Call | `newText.text` contains | Result |
|------|-------------------------|--------|
| 1 edit, no `{` | `let id = c.tracks...` | **ok** |
| 1 edit, no `{` | `NodeType::name(t.as_ref())` | **ok** |
| 1 edit, `{` in Rust | `use nodes_core::{NodeLibrary, NodeType};` | **missing newText** |
| 1 edit, `{` at start of rust use block | `use nodes_core::{` multiline | **missing newText** |
| 1 edit, `::` path in newText | `nodes_core::NodeType::name(...)` | **missing newText** (once) |
| **2 edits in one call** | anything | **always missing newText** |
| `edit_lines` (plain `text` string, no ContentRef) | `{` fine | **always ok** |

`edit_lines` on the same path with `{` in `text` succeeded immediately after `edit_file` failed.

### Why this is a server contract bug, not just a host glitch

BUG3-002 was “`Failed to parse arguments string as JSON object`” on large `oldText`/`newText` **strings**. The Content Plane fix made those fields **objects**. That trades one host-parse failure for another:

1. Hosts (Grok tool-call JSON/XML) already struggle to emit nested objects inside arrays.
2. When `newText.text` contains `{`, a sloppy host parser treats it as a new object and **drops or truncates** the field instead of leaving a string.
3. Schema `required: [newText]` + ContentRef `oneOf` means a half-parsed object fails closed as `missing field newText` — the agent gets no hint that ContentRef is the problem.
4. `vec_or_string` on `edits` can peel a JSON string into items (`serde.rs` `decode_value`). A ContentRef `{kind:inline,text:"...{...}"}` embedded in a string is easy to split wrong. A **bare string** `newText` is not.
5. `bulk_edits` description **still documents strings** (`src/main.rs` ~4613): `oldText`/`newText` (strings). `edit_file` description forbids them. Two tools, two contracts.

### Expected

- `oldText` / `newText` accept **either** a ContentRef object **or** a UTF-8 string (dual form). Same LLM-tolerant pattern as `vec_or_string` / `FlexBool`.
- Two edits in one call must not drop `newText` on the second item.
- If `newText` is missing, the error must name the edit index and say: host dropped a ContentRef; send a string or a blob id.
- `edit_file` and `bulk_edits` docs must agree.

### Workaround that worked today

- One edit per call, avoid `{` in the replacement, **or** use `edit_lines` (string `text`).
- Large rewrites: `blob_begin` → `blob_append` → `blob_finalize` → `write_file` `{kind:blob,id}` (this path is fine).

### Suggested fix

```rust
#[serde(untagged)]
enum EditText {
    Ref(ContentRef),
    Inline(String),
}
```

on `EditOperation.old_text` / `new_text`. Keep ContentRef for blobs. Do **not** require objects for a 40-byte Rust replace.

Add a unit test: `edits` array of two items, `newText` as a bare string containing `{` and `::`.

---

## BUG-002: `grep_files` — intermittent `missing field path`

- **Status:** fixed (path default + root/dir aliases; empty path is invalid_params)
- **Tool:** `grep_files`
- **When:** 2026-08-15, same session

Call included `path`, `pattern`, and `filePattern`. Wrapper:

```
Failed to call grep_files: failed to deserialize parameters: missing field `path`
```

`GrepFilesArgs.path` is a required `String` with **no alias** (`src/main.rs` ~815). `file_pattern` has aliases (`glob`, `include`, `file_pattern`) but **not** `filePattern` on the serde field (only JsonSchema camelCase). Extra keys are ignored; they should not delete `path`.

Seen twice: once in a parallel batch with `read_text_file` / `run_command`, once earlier in the playa session.

### Expected

- Accept `filePattern` as a serde alias (host schema already uses camelCase).
- If `path` is missing, error text should dump the keys that **did** arrive (`pattern`, `filePattern`, …) so it is obvious whether the host stripped `path` or the agent used `root`/`dir`.
- Alias `root` / `dir` → `path` (GrepParams internally already calls it `root`).

---

## Not a server bug (for the record)

- `run_command` `outputFilter.include: ["error["]` — invalid regex (unclosed class). Server message is correct.
- First `cargo test` kill after 182s — host timeout, `vfx-io` rustc died mid-compile. Retry succeeded.

---

## Impact

Blocked a Scene→editor port: `edit_file` could not apply a 3-line Rust fix that contained `{`. The agent had to fall back to `edit_lines`. Multi-edit batches are unusable on this host.
