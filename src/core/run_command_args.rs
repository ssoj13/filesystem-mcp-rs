//! `run_command` MCP argument deserialization tests (mirrors `RunCommandArgs` in main).

#[cfg(test)]
mod tests {
    use crate::core::serde::{
        FlexBool, FlexU64, FlexUsize, ShellArg, ShellKind, default_flex_true,
        option_object_or_json_string, vec_or_string,
    };
    use serde::Deserialize;
    use serde_json::json;

    // Fixture is used only to assert that the JSON schema deserializes; fields
    // are not introspected, so suppress dead-code lint.
    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RunCommandArgsFixture {
        command: String,
        #[serde(default, deserialize_with = "vec_or_string")]
        args: Vec<String>,
        #[serde(
            alias = "working_directory",
            alias = "workingDir",
            alias = "working_dir",
            alias = "workdir",
            alias = "dir"
        )]
        cwd: Option<String>,
        #[serde(default, deserialize_with = "option_object_or_json_string")]
        env: Option<std::collections::HashMap<String, String>>,
        #[serde(default, alias = "clear_env")]
        clear_env: FlexBool,
        #[serde(default, deserialize_with = "option_object_or_json_string", alias = "env_prepend")]
        env_prepend: Option<std::collections::HashMap<String, String>>,
        #[serde(default, deserialize_with = "option_object_or_json_string", alias = "env_append")]
        env_append: Option<std::collections::HashMap<String, String>>,
        #[serde(default, alias = "timeout_ms")]
        timeout_ms: FlexU64,
        #[serde(default, alias = "kill_after_ms")]
        kill_after_ms: FlexU64,
        #[serde(alias = "stdout_file")]
        stdout_file: Option<String>,
        #[serde(alias = "stderr_file")]
        stderr_file: Option<String>,
        #[serde(alias = "stdin_file")]
        stdin_file: Option<String>,
        #[serde(alias = "stdin_data")]
        stdin_data: Option<String>,
        #[serde(default, alias = "stdout_head")]
        stdout_head: FlexUsize,
        #[serde(default, alias = "stdout_tail")]
        stdout_tail: FlexUsize,
        #[serde(default, alias = "stderr_head")]
        stderr_head: FlexUsize,
        #[serde(default, alias = "stderr_tail")]
        stderr_tail: FlexUsize,
        #[serde(default = "default_flex_true", alias = "stream_output")]
        stream_output: FlexBool,
        #[serde(alias = "stream_dir")]
        stream_dir: Option<String>,
        #[serde(default)]
        shell: ShellArg,
        #[serde(default)]
        background: FlexBool,
        // These two were previously missing from the fixture, so the tests never
        // exercised the two fields with the most fragile wire contract:
        // outputFilter (object OR stringified-JSON) and mode (closed enum).
        // Keep in sync with RunCommandArgs in main.rs.
        #[serde(default, deserialize_with = "option_object_or_json_string", alias = "output_filter")]
        output_filter: Option<serde_json::Value>,
        #[serde(default)]
        mode: Option<String>,
    }

    #[test]
    fn minimal_camel_case() {
        let args: RunCommandArgsFixture =
            serde_json::from_value(json!({ "command": "cargo", "args": ["check"] })).unwrap();
        assert_eq!(args.command, "cargo");
        assert_eq!(args.args, vec!["check"]);
    }

    #[test]
    fn stringified_args_array() {
        let args: RunCommandArgsFixture = serde_json::from_value(json!({
            "command": "cargo",
            "args": "[\"check\", \"--workspace\"]"
        }))
        .unwrap();
        assert_eq!(args.args, vec!["check", "--workspace"]);
    }

    #[test]
    fn snake_case_optional_fields() {
        let args: RunCommandArgsFixture = serde_json::from_value(json!({
            "command": "cargo",
            "args": ["check"],
            "stream_output": "true",
            "timeout_ms": "60000",
            "clear_env": false
        }))
        .unwrap();
        assert!(*args.stream_output);
        assert_eq!(args.timeout_ms.get(), Some(60_000));
        assert!(!*args.clear_env);
    }

    #[test]
    fn cwd_must_be_json_string() {
        let args: RunCommandArgsFixture = serde_json::from_value(json!({
            "command": "cargo",
            "args": [],
            "cwd": "C:/projects/demo"
        }))
        .unwrap();
        assert_eq!(args.cwd.as_deref(), Some("C:/projects/demo"));
    }

    #[test]
    fn cwd_accepts_common_aliases() {
        // LLM-tolerant: a caller guessing any of these synonyms still sets cwd,
        // instead of having the key silently dropped (which left the child in
        // the server's primary dir — see FILESYSTEM_REPORT.md).
        for key in ["working_directory", "workingDir", "working_dir", "workdir", "dir"] {
            let args: RunCommandArgsFixture = serde_json::from_value(json!({
                "command": "cargo",
                "args": [],
                key: "C:/projects/demo"
            }))
            .unwrap_or_else(|e| panic!("alias {key} failed: {e}"));
            assert_eq!(args.cwd.as_deref(), Some("C:/projects/demo"), "alias {key}");
        }
    }

    #[test]
    fn flex_bool_on_shell_and_background() {
        let args: RunCommandArgsFixture = serde_json::from_value(json!({
            "command": "cmd",
            "args": [],
            "shell": "1",
            "background": "false"
        }))
        .unwrap();
        assert_eq!(*args.shell, ShellKind::Default);
        assert!(!*args.background);
    }

    #[test]
    fn shell_accepts_named_shell() {
        let args: RunCommandArgsFixture =
            serde_json::from_value(json!({ "command": "echo", "args": [], "shell": "bash" }))
                .unwrap();
        assert_eq!(*args.shell, ShellKind::Bash);
    }

    #[test]
    fn default_stream_output_true() {
        let args: RunCommandArgsFixture =
            serde_json::from_value(json!({ "command": "echo", "args": ["hi"] })).unwrap();
        assert!(*args.stream_output);
    }

    #[test]
    fn output_filter_accepts_object_and_stringified_json() {
        let obj: RunCommandArgsFixture = serde_json::from_value(json!({
            "command": "cargo", "args": [],
            "outputFilter": { "include": ["error"] }
        }))
        .unwrap();
        assert!(obj.output_filter.is_some());

        let stringified: RunCommandArgsFixture = serde_json::from_value(json!({
            "command": "cargo", "args": [],
            "outputFilter": "{\"include\":[\"error\"]}"
        }))
        .unwrap();
        assert!(stringified.output_filter.is_some());
    }

    #[test]
    fn mode_field_is_accepted() {
        let args: RunCommandArgsFixture = serde_json::from_value(json!({
            "command": "cargo", "args": [], "mode": "managed"
        }))
        .unwrap();
        assert_eq!(args.mode.as_deref(), Some("managed"));
    }
}
