# BUG2 — third-party / external issues with filesystem-mcp-rs

Log of problems found while using MCP from other projects (not bugs in the consumer code).

---

## BUG2-001: `read_pdf` — broken / unreadable text extraction

- **When:** 2026-08-10
- **From:** `C:\projects\projects.rust.cg\cglibs\cryptomatte-rs`
- **Tool:** `read_pdf`
- **File:** Cryptomatte Specification v1.2.0 PDF (~225862 bytes)
  - fixture: `tests/fixtures/cryptomatte_specification.pdf`
  - source: `https://raw.githubusercontent.com/Psyop/Cryptomatte/master/specification/cryptomatte_specification.pdf`

### Symptoms

1. Extra spaces / ZWSP between letters (`Ta ble o f C o n ten ts`, U+200B)
2. Broken glyph/encoding maps (`lqh]fe]` instead of layer names)
3. Uneven quality across the document

### Status

**fixed (contract)** — `read_pdf` now:

- **`normalize` (default true):** treats ZWSP runs as word separators and joins short glyph fragments (`Table of Contents`)
- **`quality` structured fields:** `score`, `warnings`, `suspiciousTokens`, ratios — agents must not treat low-score text as source of truth
- **`includeRaw`:** optional unnormalized extract

Broken ToUnicode maps (`lqh]fe]`) cannot be reconstructed by post-processing; they are reported via `suspicious_encoding_tokens` / `extraction_quality_degraded`. Replacing `pdf-extract` with a heavier crate (e.g. `pdf_oxide`) was rejected due to build size (~1GB artifacts).
