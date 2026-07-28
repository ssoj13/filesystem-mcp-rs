//! JSON Schema conversion utilities.
//!
//! Converts schemars 2020-12 schemas to Draft-07 for MCP compatibility.

use rmcp::handler::server::router::tool::ToolRouter;
use serde_json::Value;

/// Normalize all tool schemas in a router to Draft-07 format.
///
/// This function works with any server type T.
/// Memory tools use a strict contract (`inputSchema` == `Deserialize`); no object/string coercion.
pub fn is_strict_memory_tool(name: &str) -> bool {
    name.starts_with("mem_")
}

pub fn normalize_tool_schemas<T>(tool_router: &mut ToolRouter<T>) {
    for (name, route) in tool_router.map.iter_mut() {
        let schema_value = Value::Object((*route.attr.input_schema).clone());
        let schema_value = if is_strict_memory_tool(name) {
            to_draft07_schema_strict(schema_value)
        } else {
            to_draft07_schema(schema_value)
        };
        if let Value::Object(object) = schema_value {
            route.attr.input_schema = object.into();
        }
    }
}

/// Convert a JSON Schema from 2020-12 format to Draft-07.
pub fn to_draft07_schema(mut schema: Value) -> Value {
    prepare_draft07(&mut schema);
    apply_llm_coercion_hints(&mut schema);
    schema
}

/// Draft-07 + ref rewrite only (used for strict `mem_*` tools).
pub fn to_draft07_schema_strict(mut schema: Value) -> Value {
    prepare_draft07(&mut schema);
    schema
}

fn prepare_draft07(schema: &mut Value) {
    if let Value::Object(root) = schema {
        root.insert(
            "$schema".to_string(),
            Value::String("http://json-schema.org/draft-07/schema#".to_string()),
        );
    }
    rewrite_schema_refs(schema);
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
            if let Some(defs) = map.get_mut("definitions") {
                apply_llm_coercion_hints(defs);
            }
            for (key, child) in map.iter_mut() {
                if key != "properties" && key != "items" && key != "definitions" {
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

/// Rewrite $defs to definitions and update $ref pointers.
pub fn rewrite_schema_refs(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(defs) = map.remove("$defs") {
                let definitions = map
                    .entry("definitions".to_string())
                    .or_insert_with(|| Value::Object(Default::default()));
                if let (Value::Object(target), Value::Object(src)) = (definitions, defs) {
                    for (key, value) in src {
                        target.entry(key).or_insert(value);
                    }
                }
            }
            for (key, value) in map.iter_mut() {
                if key == "$ref"
                    && let Value::String(reference) = value
                {
                    if let Some(rest) = reference.strip_prefix("#/$defs/") {
                        *reference = format!("#/definitions/{}", rest);
                    } else if reference == "#/$defs" {
                        *reference = "#/definitions".to_string();
                    }
                }
                rewrite_schema_refs(value);
            }
        }
        Value::Array(items) => {
            for item in items {
                rewrite_schema_refs(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_to_draft07_adds_schema() {
        let input = json!({
            "type": "object"
        });
        let output = to_draft07_schema(input);
        assert_eq!(output["$schema"], "http://json-schema.org/draft-07/schema#");
    }

    #[test]
    fn test_rewrite_defs_to_definitions() {
        let mut schema = json!({
            "$defs": {
                "MyType": {"type": "string"}
            },
            "properties": {
                "field": {"$ref": "#/$defs/MyType"}
            }
        });
        rewrite_schema_refs(&mut schema);

        assert!(schema.get("$defs").is_none());
        assert!(schema.get("definitions").is_some());
        assert_eq!(
            schema["properties"]["field"]["$ref"],
            "#/definitions/MyType"
        );
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
        value = to_draft07_schema_strict(value);
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
        prepare_draft07(&mut schema);
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

    #[test]
    fn test_preserves_existing_definitions() {
        let mut schema = json!({
            "definitions": {
                "Existing": {"type": "number"}
            },
            "$defs": {
                "New": {"type": "string"}
            }
        });
        rewrite_schema_refs(&mut schema);

        assert_eq!(schema["definitions"]["Existing"]["type"], "number");
        assert_eq!(schema["definitions"]["New"]["type"], "string");
    }
}
