//! Serde helpers for flexible deserialization.
//!
//! LLMs often send numeric values as strings. These helpers accept both.

use serde::{Deserialize, Deserializer};
use std::fmt::Display;
use std::str::FromStr;

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
}
