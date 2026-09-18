# Tool surface style — what an MCP tool says, and how much

This file is the contract for every `#[tool]` in this crate. It exists because the tool list is
not documentation: it is a prompt. Every character of it is loaded into the model's context in
every session, before a single request, and it competes for attention with the user's actual task.

Measured on 2026-09-17 (132 tools, real `tools/list` over a real handshake):

| | chars | share |
|---|---|---|
| whole `tools/list` payload | 156,260 | ≈ 39k tokens |
| descriptions | 31,092 | 20% |
| JSON schemas | 117,118 | 75% |
| top 15 tools | 62,000 | 40% |
| median tool | 708 | — |

The weight is not spread evenly and the cure is not a general diet: most tools are already lean.

## The rule

**Say only what the caller cannot infer from the tool's name, the parameter names and their
types.** Everything else is noise that makes the signal harder to find.

Keep, always — these are the facts that cause wrong calls when missing:

- **Units and their boundaries.** `FS_MCP_TMP_KEEP_HOURS` is hours; `maxSize` is bytes while the
  budget the caller is thinking in is usually MiB.
- **Conventions that invert the obvious reading.** `0 = never sweep` (not "sweep everything now"),
  blank = unset (not the empty string), a relative `FS_MCP_STATE_DIR` is rejected.
- **Precedence** when more than one input can set the same thing: flag > env > default.
- **Platform traps** the caller cannot see: `cmd.exe` understands neither `;` nor `grep`;
  `shell:"bash"` on Windows needs git-bash and refuses the WSL launcher.
- **Where output lands**, when it is not the return value: a path, a state directory, a log file.
- **The shape of large payloads**: a ContentRef, not a megabyte of JSON.
- **What the tool destroys or overwrites**, always, in the first sentence.

Cut, always:

- Restatements of the type system ("`path` is a string with the path").
- Examples that only re-spell the schema. One example earns its place when it shows a
  non-obvious *combination*, never when it shows the obvious call.
- Prose that belongs in the README: rationale, history, comparisons with other tools.
- Repeated boilerplate across sibling tools. If four tools share a schema, share it in code.
- Anything already said by the parameter's own `description` — say it once, in the schema.

## Budgets

These are limits, not targets: a 200-char description for a tool that needs 200 chars is correct.

- Tool description: **≤ 600 chars**. Past that, the tool is either doing too much or explaining
  what it does not need to.
- Description + schema per tool: **≤ 2,000 chars**. The exceptions are listed in
  `src/core/tool_surface_guard.rs`, each with a ceiling and the reason it carries. There are
  fifteen, not the five this document first guessed, and the difference is instructive: only ~28k
  of the 101k schema payload is prose. The rest is JSON Schema *structure*, so most exceptions are
  not tools that over-explain but tools whose **type** is large — `mem_update` is a 102-char
  description beside 2,238 chars of schema carrying no descriptions at all. Bringing those under
  budget means fewer parameters, which is a design decision, not a wording one.
- No two tools may ship byte-identical schemas. Share the type instead — and where MCP forces the
  repetition on the wire (it cannot `$ref` across tools), have the pinned variants take an open
  object validated against the canonical type on arrival, as `ai_messages_*` does. The guard judges
  this by what the copies cost, `schema_len × (tools - 1)` against the same 2,000: eight of this
  server's tools take no parameters at all and a bare `{path}` is shared by eight more, where there
  is nothing to factor out and the letter of the rule would only produce an allowlist that rots.

## Error messages

An error is also a prompt, and the model acts on it. Three parts, in order:

1. **What was refused**, naming the offending value.
2. **Why**, in one clause.
3. **What to do instead**, concretely.

> `FS_MCP_STATE_DIR must be an absolute path, got "state"` — refused, value named, rule stated.
> `"logs" was refused as a lease name` — refused and named, but the caller is left guessing; add
> the rule and the fix.

Never return a bare `io::Error` where the caller cannot tell which path failed: name the path.

## Enforcement

`src/core/tool_surface_guard.rs` checks all three budgets **and one rule about truth** against the
real router — the one `tools/list` serves, built by `FileSystemServer::build_tool_router` with
schemas already normalized — the same way `paths_are_centralized` checks where state may live. A
rule this file states but the guard cannot see is a rule that will decay, so either make it
checkable or accept that it is advice and mark it as such.

**Every parameter a description names must exist.** Size rules cannot see this, and it is the worse
failure: a verbose description wastes context, a lying one wastes the caller's reasoning and then
fails silently, because an unknown key is simply ignored. `search_processes` documented an
`include_window_title` knob that does not exist and nothing noticed until someone read the text
against the type. The guard now scans the tool description and every property description, and a
backtick-quoted token that **reads as a parameter** must be a property of that tool's schema, the
name of another tool, or listed in `NOT_A_PARAMETER` under a category with its reason.

**A description that lists a property's options must list all of them.** Enum drift — a variant
added to the type while the prose listing the old set stays behind — is the failure most likely to
recur, and `wait` had it: three `kind` values documented where the code accepts four. Mentioning no
variants is fine, and mentioning exactly one is fine (that is an example); two is where the text
starts claiming to be the options. A variant counts as listed only when the text *offers* it —
backtick-quoted, or adjacent to a `|` — so "(default)" as English prose is not read as the
`"default"` variant.

The reach is small and worth knowing rather than assuming: of **525 top-level properties, 20 carry
a schema enum** and the rule guards **16**. Four are skipped because a variant is under four
characters and cannot be told from ordinary English (`run`, `sh`, `cmd`, `out`, `min`).

**An option list in prose is a smell: give the parameter a type instead.** Six properties used to
document their options only in a sentence, typed as bare `String` and resolved by a `match` in the
handler — `wait.kind` was one, and it was the one that drifted. They are now real enums, and the
surface has **no prose-only option lists left**. Type the next one at review time: the options land
in the schema where a model reads them rather than in prose it must trust, an unknown value is
refused at deserialization naming the accepted set instead of falling through a handler arm, and
the parameter comes under this rule for free.

"Reads as a parameter" is deliberately narrow: lowercase first character, `[A-Za-z0-9_]` only, and
compound — an interior capital or an underscore. That admits `filePattern` and `context_after` while
rejecting shell names (`bash`), env keys (`FS_MCP_STATE_DIR`, which starts uppercase), file names
and paths (a `.` or `/` disqualifies) and anything with a space. A lie about a single-word parameter
slips through; that is the price of a check with no false alarms, and a check that cries wolf is one
the next person deletes under time pressure.

The error-message shape above is **advice**: it is a judgement about prose that no assertion can
make. Every message touched since this document was written follows it.

Every allowlist entry carries a ceiling, so "exempt" never means "unbounded", and an entry whose
tool has come back under the ordinary budget fails the test by name rather than lingering. The
guard was verified by padding a description past 600, adding an unneeded allowlist entry, and
restoring one duplicated schema: each reddened with the offending tool and number named.
