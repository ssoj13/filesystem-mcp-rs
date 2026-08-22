//! Serde helpers for flexible deserialization.
//!
//! LLMs often send numeric values as strings. These helpers accept both.

use schemars::{JsonSchema, Schema, json_schema};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer};
use std::fmt::Display;
use std::str::FromStr;

// ========== FlexBool: bool that accepts "true"/"false"/"1"/"0"/1/0 ==========

/// Bool wrapper that accepts: true/false, "true"/"false", "1"/"0", 1/0.
/// Defaults to `false`. Derefs to `bool` for transparent usage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlexBool(pub bool);

/// Default value for fields that should default to `true`.
pub fn default_flex_true() -> FlexBool {
    FlexBool(true)
}

impl<'de> Deserialize<'de> for FlexBool {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum BoolOrStr {
            Bool(bool),
            Num(u8),
            Str(String),
        }

        match BoolOrStr::deserialize(deserializer)? {
            BoolOrStr::Bool(b) => Ok(FlexBool(b)),
            BoolOrStr::Num(n) => Ok(FlexBool(n != 0)),
            BoolOrStr::Str(s) => match s.as_str() {
                "true" | "1" => Ok(FlexBool(true)),
                "false" | "0" => Ok(FlexBool(false)),
                other => Err(serde::de::Error::custom(format!(
                    "invalid bool string: \"{other}\", expected true/false/1/0"
                ))),
            },
        }
    }
}

impl serde::Serialize for FlexBool {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bool(self.0)
    }
}

impl JsonSchema for FlexBool {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("FlexBool")
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed(concat!(module_path!(), "::FlexBool"))
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> Schema {
        json_schema!({
            "anyOf": [
                {"type": "boolean"},
                {"type": "string", "pattern": "^(true|false|1|0)$"}
            ]
        })
    }
}

impl std::ops::Deref for FlexBool {
    type Target = bool;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for FlexBool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<FlexBool> for bool {
    fn from(v: FlexBool) -> Self {
        v.0
    }
}

impl From<bool> for FlexBool {
    fn from(v: bool) -> Self {
        FlexBool(v)
    }
}

// ========== ShellKind / ShellArg: which shell wraps a command ==========

/// Which shell `run_command` should wrap a command in.
///
/// Platform-independent: `Default` is resolved to the platform shell (cmd.exe
/// on Windows, sh on Unix) at spawn time by `tools::process`. `None` means
/// spawn the program directly without any shell.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ShellKind {
    /// No shell — spawn the program directly.
    #[default]
    None,
    /// Platform default: cmd.exe on Windows, sh on Unix.
    Default,
    /// Windows `cmd /C`.
    Cmd,
    /// POSIX `sh -c`.
    Sh,
    /// `bash -c` (git bash on Windows). The cross-platform unix dialect:
    /// enables `;`, pipes, and tools like tail/grep/sed on every OS.
    Bash,
    /// PowerShell `pwsh -NoProfile -Command`.
    Pwsh,
}

/// `shell` argument wrapper with tolerant deserialization, mirroring
/// [`FlexBool`]. Accepts a JSON bool (`true` = platform default shell,
/// `false` = no shell), the numeric/string forms `1`/`0`/`"true"`/`"false"`,
/// and shell names `"cmd"`/`"sh"`/`"bash"`/`"pwsh"`/`"powershell"`/`"default"`/
/// `"none"`. This keeps existing `shell: true|false` callers working while
/// adding named shells. Derefs to [`ShellKind`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShellArg(pub ShellKind);

impl<'de> Deserialize<'de> for ShellArg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum BoolNumOrStr {
            Bool(bool),
            Num(u8),
            Str(String),
        }

        let kind = match BoolNumOrStr::deserialize(deserializer)? {
            BoolNumOrStr::Bool(true) => ShellKind::Default,
            BoolNumOrStr::Bool(false) => ShellKind::None,
            BoolNumOrStr::Num(n) => {
                if n != 0 {
                    ShellKind::Default
                } else {
                    ShellKind::None
                }
            }
            BoolNumOrStr::Str(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "on" | "default" => ShellKind::Default,
                "false" | "0" | "no" | "off" | "none" | "" => ShellKind::None,
                "cmd" => ShellKind::Cmd,
                "sh" => ShellKind::Sh,
                "bash" => ShellKind::Bash,
                "pwsh" | "powershell" | "ps" => ShellKind::Pwsh,
                other => {
                    return Err(serde::de::Error::custom(format!(
                        "invalid shell: \"{other}\", expected a bool or one of \
                         default/cmd/sh/bash/pwsh/none"
                    )));
                }
            },
        };
        Ok(ShellArg(kind))
    }
}

impl serde::Serialize for ShellArg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let name = match self.0 {
            ShellKind::None => "none",
            ShellKind::Default => "default",
            ShellKind::Cmd => "cmd",
            ShellKind::Sh => "sh",
            ShellKind::Bash => "bash",
            ShellKind::Pwsh => "pwsh",
        };
        serializer.serialize_str(name)
    }
}

impl JsonSchema for ShellArg {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("ShellArg")
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed(concat!(module_path!(), "::ShellArg"))
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> Schema {
        json_schema!({
            "anyOf": [
                {"type": "boolean"},
                {"type": "string", "enum": [
                    "default", "cmd", "sh", "bash", "pwsh", "powershell", "none",
                    "true", "false"
                ]}
            ]
        })
    }
}

impl std::ops::Deref for ShellArg {
    type Target = ShellKind;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ========== Optional Flex types (Option<T> from number or string) ==========

macro_rules! flex_optional {
    ($name:ident, $inner:ty, $schema:expr) => {
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct $name(pub Option<$inner>);

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                option_number_or_string(deserializer).map($name)
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                match self.0 {
                    Some(v) => serializer.serialize_some(&v),
                    None => serializer.serialize_none(),
                }
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed(stringify!($name))
            }

            fn schema_id() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed(concat!(module_path!(), "::", stringify!($name)))
            }

            fn json_schema(_gen: &mut schemars::SchemaGenerator) -> Schema {
                $schema
            }
        }

        impl $name {
            pub fn get(self) -> Option<$inner> {
                self.0
            }
            pub fn is_some(&self) -> bool {
                self.0.is_some()
            }
            pub fn is_none(&self) -> bool {
                self.0.is_none()
            }
            pub fn map<U, F: FnOnce($inner) -> U>(self, f: F) -> Option<U> {
                self.0.map(f)
            }
            pub fn unwrap_or(self, default: $inner) -> $inner {
                self.0.unwrap_or(default)
            }
        }

        impl From<$name> for Option<$inner> {
            fn from(v: $name) -> Self {
                v.0
            }
        }
    };
}

flex_optional!(
    FlexU32,
    u32,
    json_schema!({
        "anyOf": [
            {"type": "integer", "minimum": 0},
            {"type": "string", "pattern": "^[0-9]+$"}
        ],
        "nullable": true
    })
);

flex_optional!(
    FlexUsize,
    usize,
    json_schema!({
        "anyOf": [
            {"type": "integer", "minimum": 0},
            {"type": "string", "pattern": "^[0-9]+$"}
        ],
        "nullable": true
    })
);

flex_optional!(
    FlexU64,
    u64,
    json_schema!({
        "anyOf": [
            {"type": "integer", "minimum": 0},
            {"type": "string", "pattern": "^[0-9]+$"}
        ],
        "nullable": true
    })
);

flex_optional!(
    FlexI32,
    i32,
    json_schema!({
        "anyOf": [
            {"type": "integer"},
            {"type": "string", "pattern": "^-?[0-9]+$"}
        ],
        "nullable": true
    })
);

// ========== Required Flex types (non-Option) ==========

macro_rules! flex_required {
    ($name:ident, $inner:ty, $schema:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(pub $inner);

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                number_or_string(deserializer).map($name)
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed(stringify!($name))
            }

            fn schema_id() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed(concat!(module_path!(), "::", stringify!($name)))
            }

            fn json_schema(_gen: &mut schemars::SchemaGenerator) -> Schema {
                $schema
            }
        }

        impl $name {
            pub fn get(self) -> $inner {
                self.0
            }
        }

        impl From<$name> for $inner {
            fn from(v: $name) -> Self {
                v.0
            }
        }

        impl std::ops::Deref for $name {
            type Target = $inner;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

flex_required!(
    RU16,
    u16,
    json_schema!({
        "anyOf": [
            {"type": "integer", "minimum": 0},
            {"type": "string", "pattern": "^[0-9]+$"}
        ]
    })
);

flex_required!(
    RU32,
    u32,
    json_schema!({
        "anyOf": [
            {"type": "integer", "minimum": 0},
            {"type": "string", "pattern": "^[0-9]+$"}
        ]
    })
);

flex_required!(
    RU64,
    u64,
    json_schema!({
        "anyOf": [
            {"type": "integer", "minimum": 0},
            {"type": "string", "pattern": "^[0-9]+$"}
        ]
    })
);

flex_required!(
    RUsize,
    usize,
    json_schema!({
        "anyOf": [
            {"type": "integer", "minimum": 0},
            {"type": "string", "pattern": "^[0-9]+$"}
        ]
    })
);

flex_required!(
    RI32,
    i32,
    json_schema!({
        "anyOf": [
            {"type": "integer"},
            {"type": "string", "pattern": "^-?[0-9]+$"}
        ]
    })
);

// ========== Serde deserialize helpers ==========

/// Deserialize a value that can be either a number or a string containing a number.
pub fn number_or_string<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr + Deserialize<'de>,
    T::Err: Display,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNum<T> {
        Num(T),
        Str(String),
    }

    match StringOrNum::<T>::deserialize(deserializer)? {
        StringOrNum::Num(n) => Ok(n),
        StringOrNum::Str(s) => s.parse().map_err(serde::de::Error::custom),
    }
}

/// Deserialize an optional value that can be number, string, or null.
pub fn option_number_or_string<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr + Deserialize<'de>,
    T::Err: Display,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrNum<T> {
        Num(T),
        Str(String),
        Null,
    }

    match Option::<StringOrNum<T>>::deserialize(deserializer)? {
        Some(StringOrNum::Num(n)) => Ok(Some(n)),
        Some(StringOrNum::Str(s)) if s.is_empty() => Ok(None),
        Some(StringOrNum::Str(s)) => s.parse().map(Some).map_err(serde::de::Error::custom),
        Some(StringOrNum::Null) | None => Ok(None),
    }
}

// ========== JSON string peeling (shared by vec / object / map helpers) ==========

fn parse_json_if_likely(input: &str) -> Option<serde_json::Value> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let first = trimmed.as_bytes()[0];
    if first == b'{' || first == b'[' {
        return serde_json::from_str::<serde_json::Value>(trimmed).ok();
    }
    None
}

/// Parse JSON from a string, unwrapping up to 3 layers of JSON string encoding.
/// LLMs sometimes double-serialize nested MCP tool arguments.
pub fn parse_json_from_string(input: &str) -> Option<serde_json::Value> {
    let mut current = input.trim().to_string();
    for _ in 0..3 {
        if let Some(parsed) = parse_json_if_likely(&current) {
            return Some(parsed);
        }
        let unescaped = match serde_json::from_str::<String>(&format!("\"{}\"", current)) {
            Ok(value) => value,
            Err(_) => break,
        };
        if unescaped == current {
            break;
        }
        current = unescaped;
    }
    None
}

fn decode_value<T>(value: serde_json::Value) -> Result<T, serde_json::Error>
where
    T: serde::de::DeserializeOwned,
{
    match value {
        serde_json::Value::String(s) => {
            if let Some(parsed) = parse_json_from_string(&s)
                && let Ok(decoded) = serde_json::from_value(parsed)
            {
                return Ok(decoded);
            }
            serde_json::from_value(serde_json::Value::String(s))
        }
        other => serde_json::from_value(other),
    }
}

fn object_or_json_string_from_value<T>(value: serde_json::Value) -> Result<T, serde_json::Error>
where
    T: serde::de::DeserializeOwned,
{
    match value {
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return Err(DeError::custom("expected JSON object, got empty string"));
            }
            let parsed = parse_json_from_string(trimmed).ok_or_else(|| {
                DeError::custom(format!(
                    "expected JSON object string, got invalid JSON: {trimmed}"
                ))
            })?;
            decode_value(parsed)
        }
        other => decode_value(other),
    }
}

/// Deserialize a struct from a JSON object or a JSON string containing that object.
pub fn object_or_json_string<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    object_or_json_string_from_value(value).map_err(serde::de::Error::custom)
}

/// Like [`object_or_json_string`] for `Option<T>` (null stays None).
pub fn option_object_or_json_string<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) if s.trim().is_empty() => Ok(None),
        other => object_or_json_string_from_value(other)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

/// Deserialize a map from a JSON object or a JSON string containing that object.
pub fn map_or_json_string<'de, D, M>(deserializer: D) -> Result<M, D::Error>
where
    D: Deserializer<'de>,
    M: serde::de::DeserializeOwned,
{
    object_or_json_string(deserializer)
}

fn vec_or_string_from_value<T>(value: serde_json::Value) -> Result<Vec<T>, serde_json::Error>
where
    T: serde::de::DeserializeOwned,
{
    fn decode_item<T>(value: serde_json::Value) -> Result<T, serde_json::Error>
    where
        T: serde::de::DeserializeOwned,
    {
        decode_value(value)
    }

    match value {
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(decode_item(item)?);
            }
            Ok(out)
        }
        serde_json::Value::String(s) => {
            if let Some(parsed) = parse_json_from_string(&s) {
                return vec_or_string_from_value(parsed);
            }
            Ok(vec![decode_item(serde_json::Value::String(s))?])
        }
        other => Ok(vec![decode_item(other)?]),
    }
}

/// Deserialize [`serde_json::Value`] from any JSON value, or peel JSON embedded in a string.
///
/// Plain text facts stay as `Value::String`. LLM double-encoding of structured `content`
/// (`"{\"key\":1}"`) is parsed into object/array when valid JSON.
pub fn json_value_or_string<'de, D>(deserializer: D) -> Result<serde_json::Value, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(coerce_json_value_leaf(value))
}

fn coerce_json_value_leaf(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            if let Some(parsed) = parse_json_from_string(&s) {
                coerce_json_value_leaf(parsed)
            } else {
                serde_json::Value::String(s)
            }
        }
        other => other,
    }
}

/// Like [`json_value_or_string`] for `Option<serde_json::Value>`.
pub fn option_json_value_or_string<'de, D>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Null => Ok(None),
        other => Ok(Some(coerce_json_value_leaf(other))),
    }
}

/// Merge a nested `credentials` object (or JSON string) into top-level keys for flattened S3 args.
#[cfg(feature = "s3-tools")]
pub fn hoist_s3_credentials_blob(map: &mut serde_json::Map<String, serde_json::Value>) {
    let Some(cred) = map.remove("credentials") else {
        return;
    };
    let parsed = match cred {
        serde_json::Value::String(s) => parse_json_from_string(&s),
        serde_json::Value::Object(_) => Some(cred),
        _ => None,
    };
    if let Some(serde_json::Value::Object(inner)) = parsed {
        for (k, v) in inner {
            map.entry(k).or_insert(v);
        }
    }
}

/// Deserialize S3 tool args: hoists optional `credentials` blob, then deserializes `T`.
#[cfg(feature = "s3-tools")]
pub fn deserialize_s3_args<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let mut value = serde_json::Value::deserialize(deserializer)?;
    if let serde_json::Value::Object(ref mut map) = value {
        hoist_s3_credentials_blob(map);
    }
    serde_json::from_value(value).map_err(serde::de::Error::custom)
}

/// Like [`vec_or_string`] for `Option<Vec<T>>` (null stays None).
pub fn option_vec_or_string<'de, D, T>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Null => Ok(None),
        other => vec_or_string_from_value(other)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

// ========== FlexVec: Vec that can be deserialized from array OR JSON string ==========

/// Deserialize Vec<T> from a JSON array or a JSON string.
/// Accepts arrays that contain JSON-encoded items and single-item values.
/// LLMs sometimes double-serialize arrays or elements as strings.
pub fn vec_or_string<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    vec_or_string_from_value(value).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize, Debug, PartialEq)]
    struct TestStruct {
        #[serde(deserialize_with = "option_number_or_string", default)]
        value: Option<u32>,
    }

    #[test]
    fn test_number() {
        let json = r#"{"value": 42}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.value, Some(42));
    }

    #[test]
    fn test_string() {
        let json = r#"{"value": "42"}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.value, Some(42));
    }

    #[test]
    fn test_null() {
        let json = r#"{"value": null}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.value, None);
    }

    #[test]
    fn test_missing() {
        let json = r#"{}"#;
        let result: TestStruct = serde_json::from_str(json).unwrap();
        assert_eq!(result.value, None);
    }

    // ========== FlexBool tests ==========

    #[derive(Deserialize, Debug, PartialEq)]
    struct TestBool {
        #[serde(default)]
        flag: FlexBool,
    }

    #[test]
    fn test_flex_bool_true() {
        let r: TestBool = serde_json::from_str(r#"{"flag": true}"#).unwrap();
        assert!(r.flag.0);
    }

    #[test]
    fn test_flex_bool_false() {
        let r: TestBool = serde_json::from_str(r#"{"flag": false}"#).unwrap();
        assert!(!r.flag.0);
    }

    #[test]
    fn test_flex_bool_string_true() {
        let r: TestBool = serde_json::from_str(r#"{"flag": "true"}"#).unwrap();
        assert!(r.flag.0);
    }

    #[test]
    fn test_flex_bool_string_false() {
        let r: TestBool = serde_json::from_str(r#"{"flag": "false"}"#).unwrap();
        assert!(!r.flag.0);
    }

    #[test]
    fn test_flex_bool_string_1() {
        let r: TestBool = serde_json::from_str(r#"{"flag": "1"}"#).unwrap();
        assert!(r.flag.0);
    }

    #[test]
    fn test_flex_bool_string_0() {
        let r: TestBool = serde_json::from_str(r#"{"flag": "0"}"#).unwrap();
        assert!(!r.flag.0);
    }

    #[test]
    fn test_flex_bool_int_1() {
        let r: TestBool = serde_json::from_str(r#"{"flag": 1}"#).unwrap();
        assert!(r.flag.0);
    }

    #[test]
    fn test_flex_bool_int_0() {
        let r: TestBool = serde_json::from_str(r#"{"flag": 0}"#).unwrap();
        assert!(!r.flag.0);
    }

    #[test]
    fn test_flex_bool_missing_defaults_false() {
        let r: TestBool = serde_json::from_str(r#"{}"#).unwrap();
        assert!(!r.flag.0);
    }

    #[test]
    fn test_flex_bool_deref() {
        let fb = FlexBool(true);
        assert!(*fb);
        let fb2 = FlexBool(false);
        assert!(!*fb2);
    }

    // ========== FlexVec tests ==========

    #[derive(Deserialize, Debug, PartialEq)]
    struct TestItem {
        name: String,
        value: u32,
    }

    #[derive(Deserialize, Debug, PartialEq)]
    struct TestVecItems {
        #[serde(deserialize_with = "vec_or_string")]
        items: Vec<TestItem>,
    }

    #[derive(Deserialize, Debug, PartialEq)]
    struct TestVecStrings {
        #[serde(deserialize_with = "vec_or_string")]
        items: Vec<String>,
    }

    #[test]
    fn test_vec_or_string_array_of_objects() {
        let json = r#"{"items":[{"name":"a","value":1},{"name":"b","value":2}]}"#;
        let result: TestVecItems = serde_json::from_str(json).unwrap();
        assert_eq!(
            result.items,
            vec![
                TestItem {
                    name: "a".to_string(),
                    value: 1
                },
                TestItem {
                    name: "b".to_string(),
                    value: 2
                }
            ]
        );
    }

    #[test]
    fn test_vec_or_string_array_of_stringified_objects() {
        let json = r#"{"items":["{\"name\":\"a\",\"value\":1}","{\"name\":\"b\",\"value\":2}"]}"#;
        let result: TestVecItems = serde_json::from_str(json).unwrap();
        assert_eq!(
            result.items,
            vec![
                TestItem {
                    name: "a".to_string(),
                    value: 1
                },
                TestItem {
                    name: "b".to_string(),
                    value: 2
                }
            ]
        );
    }

    #[test]
    fn test_vec_or_string_stringified_array_of_stringified_objects() {
        let json = r#"{"items":"[\"{\\\"name\\\":\\\"a\\\",\\\"value\\\":1}\",\"{\\\"name\\\":\\\"b\\\",\\\"value\\\":2}\"]"}"#;
        let result: TestVecItems = serde_json::from_str(json).unwrap();
        assert_eq!(
            result.items,
            vec![
                TestItem {
                    name: "a".to_string(),
                    value: 1
                },
                TestItem {
                    name: "b".to_string(),
                    value: 2
                }
            ]
        );
    }

    #[test]
    fn test_vec_or_string_single_object_string() {
        let json = r#"{"items":"{\"name\":\"solo\",\"value\":3}"}"#;
        let result: TestVecItems = serde_json::from_str(json).unwrap();
        assert_eq!(
            result.items,
            vec![TestItem {
                name: "solo".to_string(),
                value: 3
            }]
        );
    }

    #[test]
    fn test_vec_or_string_single_plain_string() {
        let json = r#"{"items":"alpha"}"#;
        let result: TestVecStrings = serde_json::from_str(json).unwrap();
        assert_eq!(result.items, vec!["alpha".to_string()]);
    }

    #[derive(Deserialize, Debug, PartialEq)]
    struct TestObjectField {
        #[serde(deserialize_with = "object_or_json_string")]
        item: TestItem,
    }

    #[test]
    fn test_object_or_json_string_object() {
        let json = r#"{"item":{"name":"a","value":1}}"#;
        let result: TestObjectField = serde_json::from_str(json).unwrap();
        assert_eq!(
            result.item,
            TestItem {
                name: "a".to_string(),
                value: 1
            }
        );
    }

    #[test]
    fn test_object_or_json_string_stringified_object() {
        let json = r#"{"item":"{\"name\":\"a\",\"value\":1}"}"#;
        let result: TestObjectField = serde_json::from_str(json).unwrap();
        assert_eq!(
            result.item,
            TestItem {
                name: "a".to_string(),
                value: 1
            }
        );
    }

    #[derive(Deserialize, Debug, PartialEq)]
    struct TestOptionalObject {
        #[serde(default, deserialize_with = "option_object_or_json_string")]
        filter: Option<TestItem>,
    }

    #[test]
    fn test_option_object_or_json_string_null() {
        let json = r#"{"filter":null}"#;
        let result: TestOptionalObject = serde_json::from_str(json).unwrap();
        assert_eq!(result.filter, None);
    }

    #[test]
    fn test_option_object_or_json_string_string() {
        let json = r#"{"filter":"{\"name\":\"f\",\"value\":9}"}"#;
        let result: TestOptionalObject = serde_json::from_str(json).unwrap();
        assert_eq!(
            result.filter,
            Some(TestItem {
                name: "f".to_string(),
                value: 9
            })
        );
    }

    #[derive(Deserialize, Debug, PartialEq, Eq)]
    struct TestMapField {
        #[serde(default, deserialize_with = "map_or_json_string")]
        meta: std::collections::BTreeMap<String, String>,
    }

    #[test]
    fn test_map_or_json_string_object() {
        let json = r#"{"meta":{"k":"v"}}"#;
        let result: TestMapField = serde_json::from_str(json).unwrap();
        let mut expected = std::collections::BTreeMap::new();
        expected.insert("k".to_string(), "v".to_string());
        assert_eq!(result.meta, expected);
    }

    #[test]
    fn test_map_or_json_string_string() {
        let json = r#"{"meta":"{\"k\":\"v\"}"}"#;
        let result: TestMapField = serde_json::from_str(json).unwrap();
        let mut expected = std::collections::BTreeMap::new();
        expected.insert("k".to_string(), "v".to_string());
        assert_eq!(result.meta, expected);
    }

    #[cfg(feature = "s3-tools")]
    #[test]
    fn test_hoist_s3_credentials_blob() {
        let mut map = serde_json::Map::new();
        map.insert("bucket".into(), serde_json::json!("b"));
        map.insert(
            "credentials".into(),
            serde_json::json!({"accessKeyId": "AKIA", "region": "eu-west-1"}),
        );
        hoist_s3_credentials_blob(&mut map);
        assert!(!map.contains_key("credentials"));
        assert_eq!(map["accessKeyId"], "AKIA");
        assert_eq!(map["region"], "eu-west-1");
    }
}
