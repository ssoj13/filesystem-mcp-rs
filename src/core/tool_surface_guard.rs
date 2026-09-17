//! Enforces the budgets in `docs/TOOL_STYLE.md` against the real tool surface.
//!
//! The tool list is not documentation, it is a prompt: every character of it is loaded into the
//! model's context in every session, before a single request, and it competes for attention with
//! the user's actual task. That makes its size a property of the build, and a property nobody
//! checks decays within two waves — `paths_guard` exists for the same reason, and this repo has
//! the scars that prompted both.
//!
//! Three rules, all from `docs/TOOL_STYLE.md`:
//!
//! 1. a tool description is at most [`MAX_DESCRIPTION`] chars;
//! 2. description + JSON schema is at most [`MAX_TOOL`] chars;
//! 3. no two tools ship byte-identical schemas.
//!
//! **Rule 3 is enforced by what the repetition costs, not by its letter.** Taken literally it is
//! unenforceable: MCP cannot `$ref` a schema across tools, so two tools that genuinely take the
//! same input must repeat it on the wire, and eight of this server's tools take no parameters at
//! all — their schemas are identical because there is nothing in them. Five of the eight
//! duplicate groups here are a bare `{path}` or an empty object, where nothing can be factored
//! out and an allowlist entry would only rot. So the guard measures the duplication itself,
//! `schema_len * (tools_sharing_it - 1)`, and fails when that exceeds [`MAX_TOOL`] — when the
//! copies alone cost more than a whole tool's budget. The threshold is the doc's own number
//! rather than an invented one, and it catches exactly what the rule was written for: the four
//! `ai_messages*` tools wasted 7,425 chars and `ai_count_tokens*` another 6,045, while `{path}`
//! repeated across eight tools costs 903 and stays quiet.
//!
//! Rules 1 and 2 have an allowlist, and every allowlist entry carries a **ceiling** plus the
//! reason it earns one. The ceiling is what makes an exemption safe: an allowlisted tool that grows past it
//! fails, so "exempt" never means "unbounded". Staleness fails too — an entry whose tool has come
//! back under the ordinary budget, or a duplicate group that is no longer duplicated, is reported
//! as removable rather than left to accumulate. That is the half of an allowlist people forget,
//! and it is the half that keeps the list honest.
//!
//! **What the exemptions actually say.** `docs/TOOL_STYLE.md` guessed five; there are fifteen,
//! and the reason is worth writing down because it changes what to do about them. Measured over a
//! real handshake, the schema half of `tools/list` is ~101k chars of which only ~28k is prose:
//! the rest is JSON Schema *structure* — `type`, `required`, `$ref`, `properties`, `anyOf`,
//! `definitions` — with no text to cut. So most entries below are not tools that over-explain;
//! they are tools whose *type* is large. `mem_update` is the clearest case: a 102-char
//! description and 2,238 chars of schema carrying no descriptions at all. Cutting those needs
//! fewer parameters, not fewer words, which is a design change and not a documentation one.
//!
//! Sizes are measured the way the wire measures them: the router this test builds is the router
//! `tools/list` serves ([`FileSystemServer::build_tool_router`], schemas already normalized), and
//! the schema is serialized compactly. Numbers here are therefore bytes of UTF-8, which run a
//! little above a char count wherever a description uses an em dash.
//!
//! The module is test-only and compiles out of release builds.

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::FileSystemServer;

    /// Longest tool description. Past this a tool is either doing too much or explaining what it
    /// does not need to.
    const MAX_DESCRIPTION: usize = 600;

    /// Longest description + schema for one tool.
    const MAX_TOOL: usize = 2_000;

    /// Descriptions allowed past [`MAX_DESCRIPTION`]: `(tool, ceiling, reason)`.
    const LONG_DESCRIPTION_ALLOWED: &[(&str, usize, &str)] = &[
        // The only tool whose facts are genuinely cross-field: how the inline result relates to
        // the log files, that a timeout kills the tree rather than the child, that multi-line cmd
        // silently becomes batch semantics, and why a leftover $NAME is refused. None of those
        // belong to a single parameter, so none of them can move into the schema.
        (
            "run_command",
            1_000,
            "cross-field facts with no single owner",
        ),
    ];

    /// Tools allowed past [`MAX_TOOL`]: `(tool, ceiling, reason)`.
    ///
    /// Ceilings are the measured size rounded up to the next 100, so an ordinary rewording does
    /// not trip the guard while real growth does. A tool that drops back under [`MAX_TOOL`] must
    /// be removed from this list — the test says so by name.
    const OVER_BUDGET_ALLOWED: &[(&str, usize, &str)] = &[
        // Twenty-six parameters, six shared $defs. The surface is the price of one tool that
        // replaces a shell; splitting it would duplicate the process-lifecycle machinery.
        ("run_command", 8_600, "26 parameters + 6 shared definitions"),
        // Eight nearby* parameters on top of the full grep_files option set; the pairing IS the
        // tool. Its description is already 418 chars.
        ("grep_context", 3_900, "grep options + 8 nearby* parameters"),
        // Shape, Pt, RectArgs, CapTarget and CursorSize, all of them the caller's vocabulary.
        (
            "annotate",
            3_800,
            "five geometry definitions, all caller-facing",
        ),
        // EditOperation + ContentRef + FlexBool, times the bulk options.
        (
            "bulk_edits",
            3_700,
            "EditOperation and ContentRef definitions",
        ),
        // Nineteen parameters, each a documented ripgrep flag with a unit or a 0-convention.
        (
            "grep_files",
            3_600,
            "19 ripgrep options, each carrying a convention",
        ),
        // Four condition kinds in one tool, so it carries CapTarget, WinQuery and ColorWaitArgs.
        // Splitting it into four tools costs more than it saves.
        (
            "wait",
            3_300,
            "four condition kinds, three shared definitions",
        ),
        // The Anthropic Messages request: messages, content blocks, tools, thinking. The shape is
        // not ours to trim, and it is published exactly once (the pinned provider variants take
        // an open object and validate against this type).
        ("ai_messages", 2_800, "Anthropic Messages request shape"),
        ("ai_count_tokens", 2_200, "Anthropic Messages request shape"),
        // EditOperation + ContentRef again, for a single file.
        (
            "edit_file",
            2_500,
            "EditOperation and ContentRef definitions",
        ),
        // Scope (6 fields) + actor (6) + item (13), and the schema carries almost no prose: 216
        // and 102 chars of description respectively. Under budget needs fewer fields, not fewer
        // words.
        ("mem_put", 2_500, "scope + actor + item, ~all structure"),
        ("mem_update", 2_400, "scope + actor + item, ~all structure"),
        // CapTarget's six wire forms, in tools whose own descriptions are 125-258 chars.
        ("find_image", 2_400, "CapTarget's six wire forms"),
        ("ocr", 2_200, "CapTarget's six wire forms"),
        ("capture", 2_100, "CapTarget's six wire forms"),
        // Line-range editing with ContentRef payloads.
        ("edit_lines", 2_100, "ContentRef payloads per edit"),
    ];

    /// The tool surface as `tools/list` serves it: name -> (description, compact schema).
    fn tool_surface() -> BTreeMap<String, (String, String)> {
        FileSystemServer::build_tool_router()
            .map
            .iter()
            .map(|(name, route)| {
                let description = route.attr.description.as_deref().unwrap_or("").to_string();
                let schema = serde_json::to_string(&*route.attr.input_schema)
                    .unwrap_or_else(|e| panic!("{name}: schema is not serializable: {e}"));
                (name.to_string(), (description, schema))
            })
            .collect()
    }

    /// Look an allowlist entry up by tool name.
    fn allowed_ceiling(list: &[(&str, usize, &str)], name: &str) -> Option<usize> {
        list.iter()
            .find(|(tool, _, _)| *tool == name)
            .map(|(_, ceiling, _)| *ceiling)
    }

    /// Rule 1: a description says what the caller cannot infer, and no more.
    #[test]
    fn tool_descriptions_stay_within_budget() {
        let mut offenders = Vec::new();
        for (name, (description, _)) in tool_surface() {
            let len = description.len();
            match allowed_ceiling(LONG_DESCRIPTION_ALLOWED, &name) {
                Some(ceiling) if len > ceiling => offenders.push(format!(
                    "{name}: description {len} > its allowlisted ceiling {ceiling}"
                )),
                Some(_) if len <= MAX_DESCRIPTION => offenders.push(format!(
                    "{name}: description {len} is within {MAX_DESCRIPTION} again — drop it from \
                     LONG_DESCRIPTION_ALLOWED"
                )),
                Some(_) => {}
                None if len > MAX_DESCRIPTION => {
                    offenders.push(format!("{name}: description {len} > {MAX_DESCRIPTION}"))
                }
                None => {}
            }
        }
        assert!(
            offenders.is_empty(),
            "docs/TOOL_STYLE.md: a tool description says only what the caller cannot infer from \
             the tool's name, the parameter names and their types. Cut restatements of the type \
             system, examples that re-spell the schema, and anything a parameter's own \
             description already says. A tool that genuinely earns more goes in \
             LONG_DESCRIPTION_ALLOWED with a ceiling and a reason.\noffenders: {offenders:#?}"
        );
    }

    /// Rule 2: description + schema, which is what a session actually pays for.
    #[test]
    fn tool_surface_stays_within_budget() {
        let mut offenders = Vec::new();
        for (name, (description, schema)) in tool_surface() {
            let total = description.len() + schema.len();
            match allowed_ceiling(OVER_BUDGET_ALLOWED, &name) {
                Some(ceiling) if total > ceiling => offenders.push(format!(
                    "{name}: {total} chars (description {}, schema {}) > its allowlisted ceiling \
                     {ceiling}",
                    description.len(),
                    schema.len()
                )),
                Some(_) if total <= MAX_TOOL => offenders.push(format!(
                    "{name}: {total} chars is within {MAX_TOOL} again — drop it from \
                     OVER_BUDGET_ALLOWED"
                )),
                Some(_) => {}
                None if total > MAX_TOOL => offenders.push(format!(
                    "{name}: {total} chars (description {}, schema {}) > {MAX_TOOL}",
                    description.len(),
                    schema.len()
                )),
                None => {}
            }
        }
        assert!(
            offenders.is_empty(),
            "docs/TOOL_STYLE.md: description + schema is at most {MAX_TOOL} chars per tool. If \
             the weight is prose, cut it; if it is schema, the tool has too many parameters and \
             that is a design question, not a wording one. A tool that genuinely earns more goes \
             in OVER_BUDGET_ALLOWED with a ceiling and a reason.\noffenders: {offenders:#?}"
        );
    }

    /// Rule 3: shipping the same schema twice is paying for it twice. Judged by what the copies
    /// cost — see the module doc for why the letter of the rule is not the enforceable form.
    #[test]
    fn no_two_tools_ship_costly_identical_schemas() {
        let mut by_schema: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, (_, schema)) in tool_surface() {
            by_schema.entry(schema).or_default().push(name);
        }

        let mut offenders = Vec::new();
        for (schema, names) in &by_schema {
            // The first copy is the schema those tools need; every further copy is pure waste.
            let wasted = schema.len() * names.len().saturating_sub(1);
            if wasted > MAX_TOOL {
                offenders.push(format!(
                    "{names:?}: {} tools ship a byte-identical {}-char schema, wasting {wasted} \
                     chars of every session's context",
                    names.len(),
                    schema.len()
                ));
            }
        }

        assert!(
            offenders.is_empty(),
            "docs/TOOL_STYLE.md: no two tools may ship byte-identical schemas, and MCP cannot \
             $ref one across tools. Where the repetition is large, have the pinned variants take \
             an open object and validate it against the canonical type on arrival — as the \
             ai_messages_* / ai_count_tokens_* tools do — so the shape is published once, by the \
             tool it belongs to.\noffenders: {offenders:#?}"
        );
    }
}
