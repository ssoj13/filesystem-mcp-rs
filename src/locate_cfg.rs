//! The locate worker's settings, read from the registered locate keys.
//!
//! `filesystem-locate` reads no environment itself; it takes an [`IndexerConfig`]. This is the one
//! place that turns the registered keys into one, so a blank or unparsable value can never reach
//! the worker as an empty path or a zero batch.

use filesystem_locate::IndexerConfig;
use tracing::warn;

use crate::env_spec;

const BATCH: &str = "FS_MCP_LOCATE_SCAN_BATCH";
const REST: &str = "FS_MCP_LOCATE_WRITE_REST";
const PAUSE_MAX: &str = "FS_MCP_LOCATE_WRITE_PAUSE_MAX_MS";
const EXCLUDE: &str = "FS_MCP_LOCATE_EXCLUDE";

/// The worker's settings for this process.
pub fn indexer_config() -> IndexerConfig {
    from_lookup(env_spec::get)
}

/// [`indexer_config`] over any source of values, so the rules are testable without touching the
/// process environment. A key with no value takes the default the registry advertises.
fn from_lookup(get: impl Fn(&str) -> Option<String>) -> IndexerConfig {
    let value = |key: &'static str| get(key).or_else(|| registered_default(key));
    let number = |key: &'static str, min: u64, max: u64| -> u64 {
        let default = registered_default(key).and_then(|text| text.parse().ok());
        let parsed = value(key).and_then(|text| text.parse::<u64>().ok());
        match (parsed, default) {
            (Some(parsed), _) => parsed.clamp(min, max),
            (None, Some(default)) => {
                warn!("{key} is not a number; using the default {default}");
                default
            }
            (None, None) => min,
        }
    };
    let exclude = match value(EXCLUDE).map(|text| serde_json::from_str::<Vec<String>>(&text)) {
        Some(Ok(paths)) => paths,
        Some(Err(error)) => {
            warn!("{EXCLUDE} is not a JSON array of paths ({error}); using the default list");
            registered_default(EXCLUDE)
                .and_then(|text| serde_json::from_str(&text).ok())
                .unwrap_or_default()
        }
        None => Vec::new(),
    };
    IndexerConfig {
        scan_batch: number(BATCH, 200, 20_000) as usize,
        write_rest: number(REST, 0, 8) as u32,
        write_pause_max: std::time::Duration::from_millis(number(PAUSE_MAX, 10, 30_000)),
        ..IndexerConfig::default()
    }
    .with_exclude(exclude)
}

fn registered_default(key: &str) -> Option<String> {
    env_spec::vars()
        .into_iter()
        .find(|var| var.key == key)
        .map(|var| var.default.to_owned())
        .filter(|default| !default.is_empty())
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use super::*;

    fn with(pairs: &[(&str, &str)]) -> IndexerConfig {
        from_lookup(|key| {
            pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    #[test]
    fn shipped_defaults_match_what_the_crate_uses_when_nothing_is_set() {
        let shipped = with(&[]);
        let crate_default = IndexerConfig::default();
        assert_eq!(shipped.scan_batch, crate_default.scan_batch);
        assert_eq!(shipped.write_rest, crate_default.write_rest);
        assert_eq!(shipped.write_pause_max, crate_default.write_pause_max);
        assert_eq!(shipped.scan_batch, 2_000);
        assert_eq!(shipped.write_rest, 2);
        assert_eq!(shipped.write_pause_max, Duration::from_millis(2_000));
    }

    #[cfg(windows)]
    #[test]
    fn by_default_the_component_store_and_container_layers_are_skipped() {
        let shipped = with(&[]);
        for skipped in [
            r"C:\Windows\WinSxS\amd64_x\y.dll",
            r"C:\ProgramData\Microsoft\Windows\Containers\Layers\a",
            r"C:\System Volume Information\x",
        ] {
            assert!(shipped.is_excluded(Path::new(skipped)), "{skipped}");
        }
        assert!(!shipped.is_excluded(Path::new(r"C:\Windows\System32\kernel32.dll")));
        assert!(!shipped.is_excluded(Path::new(r"C:\Users\me\file.txt")));
    }

    #[test]
    fn numbers_are_clamped_into_their_safe_range() {
        let low = with(&[(BATCH, "5"), (REST, "0"), (PAUSE_MAX, "1")]);
        assert_eq!(low.scan_batch, 200);
        assert_eq!(low.write_rest, 0, "0 is a real setting: floor only");
        assert_eq!(low.write_pause_max, Duration::from_millis(10));
        let high = with(&[(BATCH, "999999"), (REST, "99"), (PAUSE_MAX, "999999")]);
        assert_eq!(high.scan_batch, 20_000);
        assert_eq!(high.write_rest, 8);
        assert_eq!(high.write_pause_max, Duration::from_millis(30_000));
        let exact = with(&[(BATCH, "5000"), (REST, "3"), (PAUSE_MAX, "750")]);
        assert_eq!(
            (exact.scan_batch, exact.write_rest, exact.write_pause_max),
            (5_000, 3, Duration::from_millis(750))
        );
    }

    #[test]
    fn an_unparsable_number_falls_back_to_the_default_instead_of_failing() {
        let config = with(&[(BATCH, "lots"), (REST, "-1"), (PAUSE_MAX, "")]);
        assert_eq!(config.scan_batch, 2_000);
        assert_eq!(config.write_rest, 2);
        assert_eq!(config.write_pause_max, Duration::from_millis(2_000));
    }

    #[test]
    fn exclude_is_a_json_array_and_it_replaces_the_default_list() {
        let sep = std::path::MAIN_SEPARATOR;
        let mine = format!("{sep}data{sep}cache");
        let config = with(&[(EXCLUDE, &serde_json::to_string(&[&mine]).unwrap())]);
        assert!(config.is_excluded(Path::new(&format!("{mine}{sep}a.bin"))));
        assert!(!config.is_excluded(Path::new(&format!("{sep}data{sep}keep"))));
        // An empty array is how the shipped list is switched off.
        let none = with(&[(EXCLUDE, "[]")]);
        #[cfg(windows)]
        assert!(!none.is_excluded(Path::new(r"C:\Windows\WinSxS\x")));
        assert!(!none.is_excluded(Path::new(&mine)));
    }

    #[cfg(windows)]
    #[test]
    fn a_malformed_exclude_keeps_the_default_list_rather_than_scanning_everything() {
        let config = with(&[(EXCLUDE, r"C:\Windows\WinSxS")]);
        assert!(config.is_excluded(Path::new(r"C:\Windows\WinSxS\x")));
        assert!(config.is_excluded(Path::new(r"C:\ProgramData\Microsoft\Windows\Containers\x")));
    }
}
