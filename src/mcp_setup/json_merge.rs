//! JSON primitives shared by every JSON-config client: reading the root object, locating the
//! (possibly nested) servers map, building an entry in the client's dialect, and merging safely.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::mcp_setup::error::{Result, SetupError};
use crate::mcp_setup::types::{INSTALL_ID_ENV_KEY, StdioMcpEntry};

/// How a client spells a stdio server entry. All variants carry `env`, which is where the
/// install-id marker lives — without it we could not tell our entries from hand-written ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryStyle {
    /// `{ "command": "exe", "args": [...], "env": {...} }` — Claude, Cursor, Qwen, Gemini, …
    Plain,
    /// `{ "type": "stdio", "command": "exe", "args": [...], "env": {...} }` — VS Code, Zed-style.
    TypedStdio,
    /// `{ "type": "local", "command": ["exe", "arg"], "env": {...} }` — OpenCode.
    LocalCommandArray,
    /// `{ "source": "custom", "command": "exe", "args": [...], "env": {...} }` — Zed.
    ZedCustom,
}

impl EntryStyle {
    pub fn build(self, stdio: &StdioMcpEntry, install_id: &str) -> Value {
        let mut env: BTreeMap<String, Value> = stdio
            .env
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        env.insert(
            INSTALL_ID_ENV_KEY.to_string(),
            Value::String(install_id.to_string()),
        );
        let env = Value::Object(env.into_iter().collect());

        let mut o = Map::new();
        match self {
            Self::LocalCommandArray => {
                let mut cmd = vec![Value::String(stdio.command.clone())];
                cmd.extend(stdio.args.iter().cloned().map(Value::String));
                o.insert("type".to_string(), Value::String("local".to_string()));
                o.insert("command".to_string(), Value::Array(cmd));
            }
            Self::Plain | Self::TypedStdio | Self::ZedCustom => {
                match self {
                    Self::TypedStdio => {
                        o.insert("type".to_string(), Value::String("stdio".to_string()));
                    }
                    Self::ZedCustom => {
                        o.insert("source".to_string(), Value::String("custom".to_string()));
                    }
                    _ => {}
                }
                o.insert("command".to_string(), Value::String(stdio.command.clone()));
                if !stdio.args.is_empty() {
                    o.insert(
                        "args".to_string(),
                        Value::Array(stdio.args.iter().cloned().map(Value::String).collect()),
                    );
                }
            }
        }
        o.insert("env".to_string(), env);
        Value::Object(o)
    }
}

/// The servers map, e.g. `["mcpServers"]` or `["mcp", "servers"]` (VS Code user settings).
pub fn servers_at<'a>(root: &'a Map<String, Value>, path: &[&str]) -> Option<&'a Map<String, Value>> {
    let mut cur = root;
    for (i, key) in path.iter().enumerate() {
        let next = cur.get(*key)?.as_object()?;
        if i == path.len() - 1 {
            return Some(next);
        }
        cur = next;
    }
    None
}

pub fn mcp_install_id_from_value(v: &Value) -> Option<String> {
    v.as_object()?
        .get("env")?
        .as_object()?
        .get(INSTALL_ID_ENV_KEY)?
        .as_str()
        .map(ToString::to_string)
}

/// The command, whether the client stores it as a string or as an argv array.
pub fn mcp_command_from_value(v: &Value) -> Option<&str> {
    match v.as_object()?.get("command")? {
        Value::String(s) => Some(s),
        Value::Array(parts) => parts.first()?.as_str(),
        _ => None,
    }
}

fn command_basename(command: &str) -> &str {
    command
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(command)
}

fn commands_match(expected: &str, actual: &str) -> bool {
    if expected.trim().is_empty() || actual.trim().is_empty() {
        return false;
    }
    command_basename(expected).eq_ignore_ascii_case(command_basename(actual))
}

/// Find the same binary registered by hand under a key we do not manage, so `status` can say
/// "you already wired this up yourself" instead of "not installed".
pub fn find_custom_mcp_server_key(
    root: &Map<String, Value>,
    parent_path: &[&str],
    managed_key: &str,
    expected_command: &str,
) -> Option<String> {
    servers_at(root, parent_path)?
        .iter()
        .find(|(key, value)| {
            key.as_str() != managed_key
                && mcp_install_id_from_value(value).is_none()
                && mcp_command_from_value(value)
                    .map(|c| commands_match(expected_command, c))
                    .unwrap_or(false)
        })
        .map(|(key, _)| key.clone())
}

/// An install id is `<server_key>:<version>`. Ownership is decided by the **server key**, not the
/// whole id: otherwise a version bump would leave behind an entry we could neither overwrite on
/// upgrade nor delete on uninstall, because the recorded id no longer matches.
pub fn is_ours(install_id: &str, server_key: &str) -> bool {
    install_id == server_key
        || install_id
            .split_once(':')
            .is_some_and(|(owner, _)| owner == server_key)
}

/// We only ever overwrite an entry that is already ours. Anything else is a conflict for the user
/// to resolve — silently clobbering a hand-written entry would be theft.
pub fn ensure_key_available_for_apply(
    root: &Map<String, Value>,
    parent_path: &[&str],
    key: &str,
    server_key: &str,
    desired_install_id: &str,
) -> Result<()> {
    let Some(servers) = servers_at(root, parent_path) else {
        return Ok(());
    };
    let Some(existing) = servers.get(key) else {
        return Ok(());
    };
    match mcp_install_id_from_value(existing) {
        Some(id) if is_ours(&id, server_key) => Ok(()),
        found => Err(SetupError::McpKeyConflict {
            key: key.to_string(),
            expected: Some(desired_install_id.to_string()),
            found,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stdio() -> StdioMcpEntry {
        StdioMcpEntry {
            command: "/bin/srv".to_string(),
            args: vec!["--flag".to_string()],
            env: BTreeMap::from([("A".to_string(), "1".to_string())]),
        }
    }

    #[test]
    fn entry_styles_carry_install_id_and_client_dialect() {
        let plain = EntryStyle::Plain.build(&stdio(), "id1");
        assert_eq!(plain["command"], "/bin/srv");
        assert_eq!(plain["args"][0], "--flag");
        assert_eq!(plain["env"][INSTALL_ID_ENV_KEY], "id1");
        assert!(plain.get("type").is_none());

        let typed = EntryStyle::TypedStdio.build(&stdio(), "id1");
        assert_eq!(typed["type"], "stdio");

        let local = EntryStyle::LocalCommandArray.build(&stdio(), "id1");
        assert_eq!(local["type"], "local");
        assert_eq!(local["command"][0], "/bin/srv");
        assert_eq!(local["command"][1], "--flag");
        assert_eq!(local["env"][INSTALL_ID_ENV_KEY], "id1");
    }

    /// The servers map may sit one level down (VS Code user settings: `mcp` → `servers`).
    #[test]
    fn nested_parent_path_is_walked() {
        let root = serde_json::json!({"mcp": {"servers": {"srv": {"env": {INSTALL_ID_ENV_KEY: "id1"}}}}});
        let root = root.as_object().unwrap().clone();
        let path = ["mcp", "servers"];
        assert!(servers_at(&root, &path).unwrap().contains_key("srv"));
        assert_eq!(
            mcp_install_id_from_value(servers_at(&root, &path).unwrap().get("srv").unwrap())
                .as_deref(),
            Some("id1")
        );
        assert!(servers_at(&root, &["nope"]).is_none());
    }

    fn root_with(key: &str, entry: Value) -> Map<String, Value> {
        serde_json::json!({"mcpServers": {key: entry}})
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn apply_refuses_to_clobber_foreign_entry() {
        let root = root_with("srv", serde_json::json!({"command": "x"}));
        let err = ensure_key_available_for_apply(&root, &["mcpServers"], "srv", "srv", "srv:1.0")
            .unwrap_err();
        assert!(matches!(err, SetupError::McpKeyConflict { .. }));
    }

    #[test]
    fn our_own_entry_from_an_older_version_is_still_ours() {
        assert!(is_ours("srv:0.9.0", "srv"));
        assert!(is_ours("srv", "srv"));
        assert!(!is_ours("other:1.0", "srv"));
        assert!(!is_ours("srv-extra:1.0", "srv"));

        let root = root_with("srv", EntryStyle::Plain.build(&stdio(), "srv:0.9.0"));
        // Upgrading from 0.9.0 to 1.0.0 must be allowed to overwrite our own entry.
        ensure_key_available_for_apply(&root, &["mcpServers"], "srv", "srv", "srv:1.0.0").unwrap();
    }

    #[test]
    fn custom_key_detected_by_command_basename() {
        let root = root_with("handwritten", serde_json::json!({"command": "/opt/bin/srv"}));
        assert_eq!(
            find_custom_mcp_server_key(&root, &["mcpServers"], "srv", "C:\\tools\\SRV").as_deref(),
            Some("handwritten")
        );
    }
}
