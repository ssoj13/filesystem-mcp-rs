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
//! 3. no two tools ship byte-identical schemas;
//! 4. every parameter a description names actually exists;
//! 5. a description that lists a property's options lists all of them.
//!
//! Rule 4 checks **truth**, where the first three check size, and it is here because reading the
//! text against the types found three defects the size rules were blind to: `search_processes`
//! documented an `include_window_title` knob that does not exist, `wait` listed three `kind`
//! values where the code accepts four, and `grep_files` never mentioned that its walk honours
//! `.gitignore`. A description that promises a parameter the code lacks is worse than a verbose
//! one — a verbose description wastes context, a lying one wastes the caller's reasoning and then
//! fails silently, because an unknown key is simply ignored.
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

    /// Shortest enum variant rule 5 will look for in prose.
    ///
    /// Below this a variant cannot be told from ordinary English by any textual match: `run`,
    /// `sh` and `cmd` occur constantly in descriptions that are not offering them as options.
    /// Enums with a short variant are skipped whole rather than waived per tool.
    const MIN_VARIANT_LEN: usize = 4;

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
        // Splitting it into four tools costs more than it saves. Grew ~310 when `kind` became a
        // real enum: the four options moved out of prose into the schema, which is where a model
        // can act on them instead of trusting a sentence. A good trade, and the guard made it a
        // decision rather than a drift.
        (
            "wait",
            3_700,
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

    /// Identifiers a description may quote although they are not parameters of that tool.
    ///
    /// Each entry is a **category** with the reason it is one, never a per-tool waiver: a waiver
    /// list grows one tool at a time until it means nothing, which is exactly how the rule this
    /// guard replaces would die. Both categories below are global — a token listed here is
    /// explained for every tool — and that is the deliberate trade-off: none of these names is a
    /// knob anywhere in this server, so a per-tool list would buy precision nobody needs at the
    /// price of a list that rots. Every token must be quoted by some description or the test says
    /// to delete it.
    const NOT_A_PARAMETER: &[(&str, &[&str])] = &[
        (
            "fields of the tool's JSON RESULT: a description legitimately says what comes back, \
             and the caller cannot pass them",
            &["diffsTruncated", "errorResults", "totalLines"],
        ),
        (
            "serde aliases: keys the deserializer accepts but the schema does not advertise, so \
             documenting them is true even though they are not properties",
            &["workingDir", "working_dir", "working_directory", "end_line"],
        ),
    ];

    /// Every `\u{60}`-quoted span in `text`.
    fn quoted_spans(text: &str) -> Vec<&str> {
        text.split('`').skip(1).step_by(2).collect()
    }

    /// Does `token` read as a parameter name rather than as prose?
    ///
    /// Deliberately narrow, because a check that cries wolf gets deleted by the next person under
    /// time pressure. A claim must start lowercase, contain nothing but `[A-Za-z0-9_]`, and be
    /// **compound** — carry an interior capital or an underscore. That admits `filePattern` and
    /// `context_after` while rejecting every shape a description quotes for other reasons: prose
    /// and shell names (`bash`, `pwsh`, `cmd`), env keys (`FS_MCP_STATE_DIR`, which starts
    /// uppercase), paths and file names (a `.` or `/` disqualifies), expressions and enum values
    /// written with punctuation, and anything containing a space. The cost of the narrowness is
    /// that a lie about a single-word parameter slips through; the benefit is a check with no
    /// false alarms, which is the only kind that survives.
    fn reads_as_parameter(token: &str) -> bool {
        let mut chars = token.chars();
        match chars.next() {
            Some(c) if c.is_ascii_lowercase() => {}
            _ => return false,
        }
        if !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
        token.chars().any(|c| c.is_ascii_uppercase() || c == '_')
    }

    /// Every property name anywhere in a schema, including nested `definitions` — `oldText` is a
    /// knob of `bulk_edits` even though it belongs to the `EditOperation` definition.
    fn property_names(schema: &serde_json::Value, out: &mut std::collections::BTreeSet<String>) {
        match schema {
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::Object(props)) = map.get("properties") {
                    out.extend(props.keys().cloned());
                }
                for value in map.values() {
                    property_names(value, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    property_names(item, out);
                }
            }
            _ => {}
        }
    }

    /// Every `description` string inside a schema, so a lying property doc is caught too.
    fn nested_descriptions(schema: &serde_json::Value, out: &mut Vec<String>) {
        match schema {
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::String(text)) = map.get("description") {
                    out.push(text.clone());
                }
                for value in map.values() {
                    nested_descriptions(value, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    nested_descriptions(item, out);
                }
            }
            _ => {}
        }
    }

    /// The string variants a property schema allows, following one `$ref` into `definitions`.
    ///
    /// schemars renders a plain unit enum as `"enum": [...]` and a documented one as a `oneOf`
    /// of `const` branches, so both shapes are read.
    fn enum_variants(
        node: &serde_json::Value,
        defs: &serde_json::Value,
        depth: usize,
    ) -> Vec<String> {
        let Some(map) = node.as_object() else {
            return Vec::new();
        };
        if depth > 4 {
            return Vec::new();
        }
        if let Some(values) = map.get("enum").and_then(|v| v.as_array()) {
            return values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
        }
        if let Some(reference) = map.get("$ref").and_then(|v| v.as_str())
            && let Some(name) = reference.strip_prefix("#/definitions/")
            && let Some(target) = defs.get(name)
        {
            return enum_variants(target, defs, depth + 1);
        }
        for key in ["oneOf", "anyOf", "allOf"] {
            let Some(branches) = map.get(key).and_then(|v| v.as_array()) else {
                continue;
            };
            let consts: Vec<String> = branches
                .iter()
                .filter_map(|b| b.get("const").and_then(|c| c.as_str()).map(str::to_string))
                .collect();
            if !consts.is_empty() && consts.len() == branches.len() {
                return consts;
            }
        }
        Vec::new()
    }

    /// Identifiers the text presents as an OPTION, not merely as a word it contains.
    ///
    /// Two forms count: a backtick-quoted span that is the variant (bare or in JSON/shell
    /// quotes), and a word adjacent to a `|`. English prose like "(default)" matches neither,
    /// which is what stops `default` in `false` (default) being read as the `"default"` variant.
    fn offered_options(text: &str) -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        for span in quoted_spans(text) {
            out.insert(span.trim().trim_matches(['"', '\'']).to_string());
        }
        let parts: Vec<&str> = text.split('|').collect();
        for pair in parts.windows(2) {
            if let Some(left) = edge_ident(pair[0], true) {
                out.insert(left);
            }
            if let Some(right) = edge_ident(pair[1], false) {
                out.insert(right);
            }
        }
        out
    }

    /// The identifier at one end of a string, skipping quotes and spaces: `trailing` takes the
    /// word before a `|`, otherwise the word after it. `mode replace|insert` therefore yields
    /// `replace` and `insert`, not the whole phrase before the bar.
    fn edge_ident(text: &str, trailing: bool) -> Option<String> {
        let skip = |c: &char| c.is_whitespace() || *c == '"' || *c == '\'';
        let keep = |c: &char| c.is_ascii_alphanumeric() || *c == '_';
        let word: String = if trailing {
            let rev: String = text
                .chars()
                .rev()
                .skip_while(skip)
                .take_while(keep)
                .collect();
            rev.chars().rev().collect()
        } else {
            text.chars().skip_while(skip).take_while(keep).collect()
        };
        (!word.is_empty()).then_some(word)
    }

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

    /// Rule 5: a description that lists a property's options must list all of them.
    ///
    /// The failure this catches is drift: a variant is added to the type and the prose listing
    /// the old set stays behind. Mentioning none of the variants is fine — plenty of properties
    /// rightly do not enumerate — and mentioning exactly one is fine too, because one is an
    /// example rather than a list. Two is where the text starts claiming to be the options.
    ///
    /// No allowlist, deliberately. The only exclusion is [`MIN_VARIANT_LEN`], stated as a
    /// property of the matching rather than of any tool: a variant under four characters cannot
    /// be told from ordinary English, so those enums are skipped whole.
    #[test]
    fn descriptions_list_all_of_a_property_options_or_none() {
        let mut offenders = Vec::new();
        let mut in_reach = 0usize;

        for (name, (tool_description, schema)) in &tool_surface() {
            let Ok(schema) = serde_json::from_str::<serde_json::Value>(schema) else {
                continue; // rule 4 already reports a schema that will not parse back
            };
            let defs = schema
                .get("definitions")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) else {
                continue;
            };

            for (property, property_schema) in properties {
                let variants = enum_variants(property_schema, &defs, 0);
                if variants.len() < 2 || variants.iter().any(|v| v.len() < MIN_VARIANT_LEN) {
                    continue;
                }
                in_reach += 1;

                let text = format!(
                    "{}\n{tool_description}",
                    property_schema
                        .get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or_default()
                );
                let offered = offered_options(&text);
                let listed: Vec<&String> =
                    variants.iter().filter(|v| offered.contains(*v)).collect();
                if listed.len() >= 2 && listed.len() < variants.len() {
                    let missing: Vec<&String> =
                        variants.iter().filter(|v| !offered.contains(*v)).collect();
                    offenders.push(format!(
                        "{name}.{property}: lists {listed:?} but the type also accepts {missing:?}"
                    ));
                }
            }
        }

        assert!(
            in_reach > 0,
            "rule 5 reached no property at all — the variant extraction has stopped matching the \
             schemas it is meant to read, so this test is passing vacuously"
        );
        assert!(
            offenders.is_empty(),
            "docs/TOOL_STYLE.md: a description that lists a property's options must list all of \
             them. A partial list is how enum drift reads to a caller: the missing variants look \
             unsupported, so nobody uses them and nobody reports it. Add the variants, or drop the \
             list entirely and let the schema carry the options.\noffenders: {offenders:#?}"
        );
    }

    /// Rule 4: a description may not name a parameter the tool does not accept.
    ///
    /// Scans the tool description AND every property description, since a property doc lies just
    /// as readily. A quoted token that reads as a parameter must be a property of that tool's
    /// schema, the name of another tool, or listed in [`NOT_A_PARAMETER`].
    #[test]
    fn descriptions_name_only_parameters_that_exist() {
        use std::collections::{BTreeMap, BTreeSet};

        let surface = tool_surface();
        let tool_names: BTreeSet<&str> = surface.keys().map(String::as_str).collect();
        let explained: BTreeMap<&str, &str> = NOT_A_PARAMETER
            .iter()
            .flat_map(|(reason, tokens)| tokens.iter().map(move |t| (*t, *reason)))
            .collect();

        let mut offenders = Vec::new();
        let mut used: BTreeSet<&str> = BTreeSet::new();

        for (name, (description, schema)) in &surface {
            let schema: serde_json::Value = match serde_json::from_str(schema) {
                Ok(value) => value,
                Err(e) => {
                    offenders.push(format!("{name}: schema did not parse back: {e}"));
                    continue;
                }
            };
            let mut properties = BTreeSet::new();
            property_names(&schema, &mut properties);
            let mut texts = vec![description.clone()];
            nested_descriptions(&schema, &mut texts);

            for text in &texts {
                for token in quoted_spans(text) {
                    if !reads_as_parameter(token)
                        || properties.contains(token)
                        || tool_names.contains(token)
                    {
                        continue;
                    }
                    match explained.get_key_value(token) {
                        Some((listed, _)) => {
                            used.insert(listed);
                        }
                        None => offenders.push(format!(
                            "{name}: names `{token}`, which is not one of its parameters"
                        )),
                    }
                }
            }
        }

        // Staleness, as everywhere else here: a token nothing quotes any more is a line nobody
        // will delete unless the test asks for it.
        for (_, tokens) in NOT_A_PARAMETER {
            for token in *tokens {
                if !used.contains(token) {
                    offenders.push(format!(
                        "`{token}` is no longer quoted by any description — drop it from \
                         NOT_A_PARAMETER"
                    ));
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "docs/TOOL_STYLE.md: a description must not promise a parameter the tool does not \
             accept. An unknown key is silently ignored, so the caller is misled and then gets no \
             error to learn from. Either the parameter is missing from the code or the sentence is \
             wrong — fix whichever is actually broken. If the identifier is not a parameter at all, \
             it belongs in a NOT_A_PARAMETER category, with the reason that category \
             exists.\noffenders: {offenders:#?}"
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
