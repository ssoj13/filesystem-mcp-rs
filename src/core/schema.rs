//! Tool-schema post-processing: what this server changes about the schemas rmcp generates, and
//! why each change is still justified.
//!
//! Two things happen here, and **only** these two. Everything else is served exactly as schemars
//! produced it, in JSON Schema 2020-12 — `$defs` and `#/$defs/...` refs included.
//!
//! 1. `$schema` is stripped (see below).
//! 2. Non-`mem_*` tools get LLM-tolerance hints: a property typed `object`/`array` becomes a
//!    `oneOf` of that schema or a JSON string, because models emit stringified JSON and the
//!    server accepts both. `mem_*` tools are exempt — their contract is `inputSchema` ==
//!    `Deserialize`, with no coercion — which is the only reason the strict/non-strict split
//!    exists.
//!
//! **The draft-07 rewrite is gone (2026-09-17).** This module used to turn `$defs` into
//! `definitions` and repoint every `$ref`, claiming that is "the shape MCP clients expect".
//! Checked, and the claim does not survive: MCP 2025-06-18 (Server Features / Tools) says only
//! "JSON Schema defining expected parameters" and names no dialect; rmcp reads neither spelling
//! anywhere; and rmcp generates tool schemas with `SchemaSettings::draft2020_12()` under the
//! comment "explicitly to align json schema version to official specifications", citing
//! modelcontextprotocol PR #655 (`rmcp-3.1.3/src/handler/server/common.rs`). So 2020-12 with
//! `$defs` is what the ecosystem's own alignment produces and what every unmodified rmcp server —
//! and every pydantic-based server in the official Python SDK — already puts on the wire.
//! Rewriting it was a local deviation from the one shape all clients must already handle.
//!
//! `$schema` is deliberately **stripped**, and this is the note that should stop anyone re-adding
//! it. **Checked against the specification on 2026-09-17** (MCP 2025-06-18, Server Features /
//! Tools): `inputSchema` is described only as "JSON Schema defining expected parameters",
//! `$schema` appears nowhere in the requirements, and every example in that section ships a bare
//! `{"type": "object", "properties": {...}, "required": [...]}`. Nothing in rmcp 3.1.4 reads it
//! either: its only `$schema` handling is in `model::elicitation_schema` (a different MCP
//! feature), where the field is optional, skipped when absent, and covered by a test asserting no
//! key is emitted without a dialect. rmcp generates with
//! `SchemaSettings::draft2020_12()`, so every tool schema arrives declaring
//! `https://json-schema.org/draft/2020-12/schema`; this code used to overwrite that with the
//! draft-07 URL "for MCP compatibility" — a claim the spec does not support and no client was
//! ever found to need. That comment is how the key survived this long, which is why this one is
//! dated and cites what was read. The key goes entirely: spec-shaped, and ~7.4k chars off every
//! session's context before a single request, for no information the caller can use
//! (`docs/TOOL_STYLE.md`). The body left behind is plain 2020-12, so nothing now contradicts the
//! declaration that was dropped.

use rmcp::handler::server::router::tool::ToolRouter;
use serde_json::Value;

/// Memory tools use a strict contract (`inputSchema` == `Deserialize`); no object/string coercion.
pub fn is_strict_memory_tool(name: &str) -> bool {
    name.starts_with("mem_")
}

/// Post-process every tool schema in a router. Works with any server type T.
pub fn normalize_tool_schemas<T>(tool_router: &mut ToolRouter<T>) {
    for (name, route) in tool_router.map.iter_mut() {
        let schema_value = Value::Object((*route.attr.input_schema).clone());
        let schema_value = if is_strict_memory_tool(name) {
            served_schema_strict(schema_value)
        } else {
            served_schema(schema_value)
        };
        if let Value::Object(object) = schema_value {
            route.attr.input_schema = object.into();
        }
    }
}

/// The schema as served: rmcp's 2020-12 output minus `$schema`, plus coercion hints.
pub fn served_schema(mut schema: Value) -> Value {
    strip_schema_keyword(&mut schema);
    apply_llm_coercion_hints(&mut schema);
    schema
}

/// The schema as served for strict `mem_*` tools: `$schema` stripped, nothing else touched.
pub fn served_schema_strict(mut schema: Value) -> Value {
    strip_schema_keyword(&mut schema);
    schema
}

/// Drop rmcp's 2020-12 declaration rather than restating it: see the module doc.
fn strip_schema_keyword(schema: &mut Value) {
    if let Value::Object(root) = schema {
        root.remove("$schema");
    }
}

/// Document LLM-tolerant coercion in tool input schemas (object/array OR JSON string).
fn apply_llm_coercion_hints(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(props) = map.get_mut("properties")
                && let Value::Object(props_map) = props
            {
                for prop in props_map.values_mut() {
                    patch_coercible_property_schema(prop);
                    apply_llm_coercion_hints(prop);
                }
            }
            if let Some(items) = map.get_mut("items") {
                apply_llm_coercion_hints(items);
            }
            // Everything else, `$defs` included, is plain recursion: only
            // `properties` and `items` need the special handling above.
            for (key, child) in map.iter_mut() {
                if key != "properties" && key != "items" {
                    apply_llm_coercion_hints(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                apply_llm_coercion_hints(item);
            }
        }
        _ => {}
    }
}

fn patch_coercible_property_schema(prop: &mut Value) {
    let Value::Object(map) = prop else {
        return;
    };
    if map.contains_key("oneOf") || map.contains_key("$ref") {
        return;
    }
    let Some(Value::String(ty)) = map.get("type") else {
        return;
    };
    if ty == "object" {
        let object_branch = Value::Object(map.clone());
        *prop = serde_json::json!({
            "oneOf": [
                object_branch,
                {
                    "type": "string",
                    "description": "JSON object as a string (LLM-tolerant; server accepts both)."
                }
            ]
        });
    } else if ty == "array" {
        let array_branch = Value::Object(map.clone());
        *prop = serde_json::json!({
            "oneOf": [
                array_branch,
                {
                    "type": "string",
                    "description": "JSON array as a string (LLM-tolerant; server accepts both)."
                }
            ]
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A served schema declares no `$schema`: MCP never asks for one, and 132 copies of the
    /// declaration cost ~7.4k chars of every session's context for no information. The input
    /// carries rmcp's real 2020-12 declaration, because stripping is the point — an earlier
    /// version of this test passed while the key was merely being overwritten.
    #[test]
    fn test_served_schema_strips_the_schema_keyword() {
        let rmcp_shaped = || {
            json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object"
            })
        };
        assert!(
            served_schema(rmcp_shaped()).get("$schema").is_none(),
            "served schemas must not declare $schema"
        );
        assert!(
            served_schema_strict(rmcp_shaped()).get("$schema").is_none(),
            "the strict mem_* path must strip it too"
        );
    }

    /// 2020-12 `$defs` and its refs are served untouched: that is what rmcp
    /// generates on purpose (see the module doc) and what clients already get
    /// from every other rmcp- and pydantic-based MCP server.
    #[test]
    fn test_defs_and_refs_are_served_unchanged() {
        let nested = || {
            json!({
                "type": "object",
                "$defs": { "MyType": {"type": "string"} },
                "properties": {
                    "field": {"$ref": "#/$defs/MyType"}
                }
            })
        };
        for served in [served_schema(nested()), served_schema_strict(nested())] {
            assert!(served.get("definitions").is_none(), "no draft-07 rewrite");
            assert_eq!(served["$defs"]["MyType"]["type"], "string");
            assert_eq!(served["properties"]["field"]["$ref"], "#/$defs/MyType");
        }
    }

    #[test]
    fn test_strict_memory_tool_name() {
        assert!(is_strict_memory_tool("mem_put"));
        assert!(is_strict_memory_tool("mem_search"));
        assert!(!is_strict_memory_tool("write_file"));
    }

    #[test]
    fn test_mem_put_normalized_schema_strict() {
        use crate::tools::memory_v2::MemPutArgs;

        let schema = schemars::schema_for!(MemPutArgs);
        let mut value = serde_json::to_value(&schema).expect("schema");
        value = served_schema_strict(value);
        assert!(
            value["properties"]["item"].get("oneOf").is_none(),
            "normalized mem_put must not coerce item to string"
        );
        assert!(
            value["properties"]["workspaceId"].get("oneOf").is_none(),
            "workspaceId must stay a plain string"
        );
    }

    #[test]
    fn test_strict_schema_skips_coercion() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "item": { "type": "object" }
            }
        });
        strip_schema_keyword(&mut schema);
        assert!(schema["properties"]["item"].get("oneOf").is_none());
        apply_llm_coercion_hints(&mut schema);
        assert!(schema["properties"]["item"]["oneOf"].is_array());
    }

    #[test]
    fn test_object_property_gets_string_alternative() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "item": { "type": "object" }
            }
        });
        apply_llm_coercion_hints(&mut schema);
        assert!(schema["properties"]["item"]["oneOf"].is_array());
    }

    /// A nested type inside `$defs` still gets the coercion hints on the
    /// non-strict path — removing the rewrite must not stop the recursion.
    #[test]
    fn test_coercion_hints_reach_defs() {
        let served = served_schema(json!({
            "type": "object",
            "$defs": {
                "Nested": {
                    "type": "object",
                    "properties": { "payload": { "type": "object" } }
                }
            }
        }));
        assert!(served["$defs"]["Nested"]["properties"]["payload"]["oneOf"].is_array());
    }
}
