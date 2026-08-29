# Bug: `write_file` rejects calls whose `content` needs JSON escaping

**Found:** 2026-08-21, during a Claude Code session using this MCP server against an unrelated
project (`bootstrap105`). Reported by the operator, written up by the agent that hit it.

## Symptom

Calling `mcp__filesystem__write_file` to create a new Python file (~40 lines: a module docstring
with `"""`, single and double quotes, backslash path separators, multi-line function bodies) failed
repeatedly with:

```
InputValidationError: mcp__filesystem__write_file was called with input that could not be parsed
as JSON.
You sent (first 200 of 1479 bytes): {"path": "D:\\_rez_install\\bootstrap105\\...\\deploy_config.py",
"content": #!/usr/bin/env python3
"""Deploy this leaf's main.py to the file REZ_CONFIG_FILE names ...
Common causes: unescaped backslashes in file paths (use / or \\), unescaped control characters, or
truncated output. Retry with valid JSON.
```

The call was retried **five times in a row**, byte-for-byte the same malformed payload each time,
before falling back to a different (non-MCP, built-in) file-write tool — which succeeded first try
with identical content, and broke this session's "MCP-only file ops" convention in the process.

## Root cause (confirmed while writing this report)

**Caller-side, not a server defect** — reproduced live a second time, this time trying to write
*this very file*, whose content is Markdown containing backtick+quote sequences (`` `write_file` ``,
literal `"..."` in the symptom section) and a fenced code block. Same error, same signature: the
tool call's `content` parameter was being sent as **raw, unescaped text appended directly after
`"content": ` with no surrounding quotes and no internal `"`/newline escaping** — not a valid JSON
string value at all, just literal bytes.

This points at the calling agent's tool-invocation path: something in how the harness/agent
constructed the outer JSON envelope for this call substituted the `content` argument in *before*
JSON-string-encoding it, rather than serializing it as a proper escaped JSON string. Two open
questions for whoever owns the MCP-side transport:

1. Is there a code path in the client/host (not this repo) that string-templates tool-call JSON
   instead of using a real JSON serializer for large/multi-line string parameters? If so, this is
   not actually a `filesystem-mcp-rs` bug — it's upstream, and this repo is just the tool that
   surfaces the resulting parse failure.
2. **Regardless of where the bad JSON originates**, `write_file`'s error message could be more
   actionable: it currently prints the first 200 raw bytes of whatever it received and a generic
   "Common causes" list, but does not say *where* in the payload parsing failed (byte offset, line,
   or which JSON parse error was raised — e.g. serde_json's `Error::line()`/`Error::column()`).
   Surfacing the underlying parser's exact position would have made it obvious after the *first*
   failure that `content` had no opening quote, instead of costing five identical retries.

## Suggested follow-up (not fixed by this report — flagging only)

- Add the underlying JSON parse error's line/column (or byte offset) to `InputValidationError`'s
  message for every MCP tool that accepts free-form string content, not just `write_file`.
- If this server has any control over how the host packages large multi-line string arguments
  before they reach it, double-check that path doesn't string-template instead of JSON-encoding —
  but this is speculative from the caller side and needs confirming against the actual host/client
  code, which is outside this repo.

## RESOLVED server-side (2026-08-29) — tolerant ContentRef + actionable errors

Two variants hit in production sessions since the original report:

- **Variant A (unreachable server-side):** the harness substitutes the `content` argument as raw
  unescaped text into the outer JSON envelope — the transport fails before the server sees anything.
  Unfixable here; retry-identical-payload or use the built-in Write tool.
- **Variant B (fixed):** `content` arrives as a bare string — either plain text, or a JSON-encoded
  string of the ContentRef object (`"{\"kind\":\"inline\",...}"`). Both previously died with the
  opaque `expected internally tagged enum ContentRef`.

Server changes (`core/content_plane.rs`):

1. **Tolerant `ContentRef` deserialization** — a bare string is accepted as inline text; a
   `{`-prefixed string is parsed as a (double-encoded) ContentRef object and unwrapped. Canonical
   object form unchanged. Cost: writing literal content that starts with `{` and happens to be a
   valid ContentRef object requires the canonical object form.
2. **Actionable errors with line/column** — a `{`-prefixed string that fails JSON parse surfaces
   serde_json's `at line L column C` (the old message had none); wrong object shapes name the
   missing field (`content: invalid ContentRef object: missing field \`text\``); non-string
   non-object shapes report the actual JSON type.
3. **Inline limit raised 8 → 64 KiB** (`INLINE_MAX_BYTES`, `CHUNK_MAX_BYTES`): real files
   (PLAN2.md, 8.4 KB) tripped the old limit and forced blob staging for no safety gain.

Note: the `InputValidationError ... You sent (first 200 of ...)` header quoted above is emitted by
the calling host (Claude Code), not this server — its formatting is upstream and out of scope.
