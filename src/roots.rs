#![allow(dead_code)]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Root {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListRootsResult {
    pub roots: Vec<Root>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_list_roots() {
        let json = r#"{"roots":[{"uri":"file:///tmp","name":"tmp"}]}"#;
        let parsed: ListRootsResult = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.roots.len(), 1);
        assert_eq!(parsed.roots[0].uri, "file:///tmp");
        assert_eq!(parsed.roots[0].name.as_deref(), Some("tmp"));
    }
}
