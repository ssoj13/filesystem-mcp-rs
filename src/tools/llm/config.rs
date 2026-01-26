use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelMappingMode {
    Auto,
    Passthrough,
    Off,
}

impl ModelMappingMode {
    pub fn from_str(value: &str) -> Self {
        match value.trim().to_lowercase().as_str() {
            "passthrough" => Self::Passthrough,
            "off" | "disabled" | "none" => Self::Off,
            _ => Self::Auto,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Passthrough => "passthrough",
            Self::Off => "off",
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub provider: String,
    pub providers: Vec<String>,
    pub provider_endpoint: Option<String>,
    pub provider_api_key: Option<String>,
    pub provider_api_key_header: String,
    pub provider_api_key_prefix: String,

    pub gemini_api_key: String,
    pub cerebras_api_key: String,
    pub openai_api_key: String,
    pub big_model: String,
    pub small_model: String,
    pub max_tokens_limit: u32,
    pub request_timeout: u64,
    pub max_retries: u32,
    pub max_streaming_retries: u32,
    pub retry_backoff_ms: u64,
    pub streaming_retry_backoff_ms: u64,
    pub force_disable_streaming: bool,
    pub emergency_disable_streaming: bool,
    pub model_mapping_mode: ModelMappingMode,
}

impl Config {
    pub fn defaults() -> Self {
        Self {
            provider: "gemini".to_string(),
            providers: Vec::new(),
            provider_endpoint: None,
            provider_api_key: None,
            provider_api_key_header: "Authorization".to_string(),
            provider_api_key_prefix: "Bearer ".to_string(),

            gemini_api_key: String::new(),
            cerebras_api_key: String::new(),
            openai_api_key: String::new(),
            big_model: "gemini-3-pro-preview".to_string(),
            small_model: "gemini-3-flash-preview".to_string(),
            max_tokens_limit: 65535,
            request_timeout: 90,
            max_retries: 2,
            max_streaming_retries: 12,
            retry_backoff_ms: 200,
            streaming_retry_backoff_ms: 200,
            force_disable_streaming: false,
            emergency_disable_streaming: false,
            model_mapping_mode: ModelMappingMode::Auto,
        }
    }

    pub fn apply_env_overrides(&mut self) {
        if let Ok(value) = std::env::var("LLM_MCP_PROVIDERS") {
            let parsed = parse_providers(&value);
            if !parsed.is_empty() {
                self.providers = parsed.clone();
                self.provider = parsed[0].clone();
            }
        }
        if let Ok(value) = std::env::var("LLM_MCP_PROVIDER") {
            if !value.trim().is_empty() {
                self.provider = value;
            }
        }
        if let Ok(value) = std::env::var("LLM_MCP_PROVIDER_ENDPOINT") {
            if !value.trim().is_empty() {
                self.provider_endpoint = Some(value);
            }
        }
        if let Ok(value) = std::env::var("LLM_MCP_PROVIDER_API_KEY") {
            if !value.trim().is_empty() {
                self.provider_api_key = Some(value);
            }
        }
        if let Ok(value) = std::env::var("LLM_MCP_PROVIDER_API_KEY_HEADER") {
            if !value.trim().is_empty() {
                self.provider_api_key_header = value;
            }
        }
        if let Ok(value) = std::env::var("LLM_MCP_PROVIDER_API_KEY_PREFIX") {
            self.provider_api_key_prefix = value;
        }
        if let Ok(value) = std::env::var("LLM_MCP_MODEL_MAPPING") {
            self.model_mapping_mode = ModelMappingMode::from_str(&value);
        }
        if let Ok(value) = std::env::var("LLM_MCP_OPENAI_API_KEY") {
            if !value.trim().is_empty() {
                self.openai_api_key = value;
            }
        }
        if self.openai_api_key.trim().is_empty() {
            if let Ok(value) = std::env::var("OPENAI_API_KEY") {
                if !value.trim().is_empty() {
                    self.openai_api_key = value;
                }
            }
        }

        if let Ok(value) = std::env::var("LLM_MCP_BIG_MODEL") {
            self.big_model = value;
        }
        if let Ok(value) = std::env::var("LLM_MCP_SMALL_MODEL") {
            self.small_model = value;
        }
        if let Ok(value) = std::env::var("LLM_MCP_MAX_TOKENS_LIMIT") {
            if let Ok(parsed) = value.parse() {
                self.max_tokens_limit = parsed;
            }
        }
        if let Ok(value) = std::env::var("LLM_MCP_REQUEST_TIMEOUT") {
            if let Ok(parsed) = value.parse() {
                self.request_timeout = parsed;
            }
        }
        if let Ok(value) = std::env::var("LLM_MCP_MAX_RETRIES") {
            if let Ok(parsed) = value.parse() {
                self.max_retries = parsed;
            }
        }
        if let Ok(value) = std::env::var("LLM_MCP_MAX_STREAMING_RETRIES") {
            if let Ok(parsed) = value.parse() {
                self.max_streaming_retries = parsed;
            }
        }
        if let Ok(value) = std::env::var("LLM_MCP_RETRY_BACKOFF_MS") {
            if let Ok(parsed) = value.parse() {
                self.retry_backoff_ms = parsed;
            }
        }
        if let Ok(value) = std::env::var("LLM_MCP_STREAMING_RETRY_BACKOFF_MS") {
            if let Ok(parsed) = value.parse() {
                self.streaming_retry_backoff_ms = parsed;
            }
        }
        if let Ok(value) = std::env::var("LLM_MCP_FORCE_DISABLE_STREAMING") {
            self.force_disable_streaming = value == "true";
        }
        if let Ok(value) = std::env::var("LLM_MCP_EMERGENCY_DISABLE_STREAMING") {
            self.emergency_disable_streaming = value == "true";
        }
    }

    fn apply_toml_overrides(&mut self, config: ConfigToml) {
        if let Some(value) = config.providers {
            let parsed = parse_providers_value(&value);
            if !parsed.is_empty() {
                self.providers = parsed.clone();
                self.provider = parsed[0].clone();
            }
        }
        if let Some(value) = config.provider {
            self.provider = value;
        }
        if let Some(value) = config.provider_endpoint {
            self.provider_endpoint = Some(value);
        }
        if let Some(value) = config.provider_api_key {
            self.provider_api_key = Some(value);
        }
        if let Some(value) = config.provider_api_key_header {
            self.provider_api_key_header = value;
        }
        if let Some(value) = config.provider_api_key_prefix {
            self.provider_api_key_prefix = value;
        }
        if let Some(value) = config.model_mapping {
            self.model_mapping_mode = ModelMappingMode::from_str(&value);
        }

        if let Some(value) = config.gemini_api_key {
            self.gemini_api_key = value;
        }
        if let Some(value) = config.cerebras_api_key {
            self.cerebras_api_key = value;
        }
        if let Some(value) = config.openai_api_key {
            self.openai_api_key = value;
        }
        if let Some(value) = config.big_model {
            self.big_model = value;
        }
        if let Some(value) = config.small_model {
            self.small_model = value;
        }
        if let Some(value) = config.max_tokens_limit {
            self.max_tokens_limit = value;
        }
        if let Some(value) = config.request_timeout {
            self.request_timeout = value;
        }
        if let Some(value) = config.max_retries {
            self.max_retries = value;
        }
        if let Some(value) = config.max_streaming_retries {
            self.max_streaming_retries = value;
        }
        if let Some(value) = config.retry_backoff_ms {
            self.retry_backoff_ms = value;
        }
        if let Some(value) = config.streaming_retry_backoff_ms {
            self.streaming_retry_backoff_ms = value;
        }
        if let Some(value) = config.force_disable_streaming {
            self.force_disable_streaming = value;
        }
        if let Some(value) = config.emergency_disable_streaming {
            self.emergency_disable_streaming = value;
        }
    }

    pub fn effective_api_key_for(&self, provider: &str) -> Option<String> {
        if provider.eq_ignore_ascii_case(&self.provider) {
            if let Some(key) = &self.provider_api_key {
                if !key.trim().is_empty() {
                    return Some(key.clone());
                }
            }
        }
        if provider.eq_ignore_ascii_case("gemini") && !self.gemini_api_key.trim().is_empty() {
            return Some(self.gemini_api_key.clone());
        }
        if provider.eq_ignore_ascii_case("cerebras") && !self.cerebras_api_key.trim().is_empty() {
            return Some(self.cerebras_api_key.clone());
        }
        if provider.eq_ignore_ascii_case("openai") && !self.openai_api_key.trim().is_empty() {
            return Some(self.openai_api_key.clone());
        }
        None
    }

    pub fn effective_endpoint_for(&self, provider: &str) -> String {
        if provider.eq_ignore_ascii_case(&self.provider) {
            if let Some(endpoint) = &self.provider_endpoint {
                if !endpoint.trim().is_empty() {
                    return endpoint.clone();
                }
            }
        }
        if provider.eq_ignore_ascii_case("gemini") {
            return "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions".to_string();
        }
        if provider.eq_ignore_ascii_case("cerebras") {
            return "https://api.cerebras.ai/v1/chat/completions".to_string();
        }
        if provider.eq_ignore_ascii_case("openai") {
            return "https://api.openai.com/v1/chat/completions".to_string();
        }
        String::new()
    }

    pub fn primary_provider(&self) -> String {
        if let Some(first) = self.providers.first() {
            if !first.trim().is_empty() {
                return first.clone();
            }
        }
        let auto = self.auto_providers();
        if let Some(first) = auto.first() {
            return first.clone();
        }
        self.provider.clone()
    }

    pub fn configured_providers(&self) -> Vec<String> {
        if !self.providers.is_empty() {
            return self.providers.clone();
        }
        let auto = self.auto_providers();
        if !auto.is_empty() {
            return auto;
        }
        vec![self.provider.clone()]
    }

    fn auto_providers(&self) -> Vec<String> {
        let mut providers = Vec::new();
        if !self.gemini_api_key.trim().is_empty() {
            providers.push("gemini".to_string());
        }
        if !self.cerebras_api_key.trim().is_empty() {
            providers.push("cerebras".to_string());
        }
        if !self.openai_api_key.trim().is_empty() {
            providers.push("openai".to_string());
        }
        if let Some(key) = &self.provider_api_key {
            if !key.trim().is_empty() && !self.provider.trim().is_empty() {
                if !providers.iter().any(|p| p.eq_ignore_ascii_case(&self.provider)) {
                    providers.push(self.provider.clone());
                }
            }
        }
        providers
    }

    pub fn is_provider_available(&self, provider: &str) -> bool {
        let endpoint = self.effective_endpoint_for(provider);
        !endpoint.trim().is_empty() && self.effective_api_key_for(provider).is_some()
    }

    pub fn validate(&self) -> Result<(), String> {
        let provider = self.primary_provider();
        if self.effective_endpoint_for(&provider).trim().is_empty() {
            return Err("LLM_MCP_PROVIDER_ENDPOINT is required for non-gemini providers".to_string());
        }
        if self.effective_api_key_for(&provider).is_none() {
            return Err(format!(
                "Missing API key for provider {provider}: set LLM_MCP_PROVIDER_API_KEY or provider-specific API key"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct ConfigToml {
    #[serde(rename = "LLM_MCP_PROVIDERS")]
    providers: Option<toml::Value>,
    #[serde(rename = "LLM_MCP_PROVIDER")]
    provider: Option<String>,
    #[serde(rename = "LLM_MCP_PROVIDER_ENDPOINT")]
    provider_endpoint: Option<String>,
    #[serde(rename = "LLM_MCP_PROVIDER_API_KEY")]
    provider_api_key: Option<String>,
    #[serde(rename = "LLM_MCP_PROVIDER_API_KEY_HEADER")]
    provider_api_key_header: Option<String>,
    #[serde(rename = "LLM_MCP_PROVIDER_API_KEY_PREFIX")]
    provider_api_key_prefix: Option<String>,
    #[serde(rename = "LLM_MCP_MODEL_MAPPING")]
    model_mapping: Option<String>,

    #[serde(rename = "LLM_MCP_GEMINI_API_KEY")]
    gemini_api_key: Option<String>,
    #[serde(rename = "LLM_MCP_CEREBRAS_API_KEY")]
    cerebras_api_key: Option<String>,
    #[serde(rename = "LLM_MCP_OPENAI_API_KEY")]
    openai_api_key: Option<String>,
    #[serde(rename = "LLM_MCP_BIG_MODEL")]
    big_model: Option<String>,
    #[serde(rename = "LLM_MCP_SMALL_MODEL")]
    small_model: Option<String>,
    #[serde(rename = "LLM_MCP_MAX_TOKENS_LIMIT")]
    max_tokens_limit: Option<u32>,
    #[serde(rename = "LLM_MCP_REQUEST_TIMEOUT")]
    request_timeout: Option<u64>,
    #[serde(rename = "LLM_MCP_MAX_RETRIES")]
    max_retries: Option<u32>,
    #[serde(rename = "LLM_MCP_MAX_STREAMING_RETRIES")]
    max_streaming_retries: Option<u32>,
    #[serde(rename = "LLM_MCP_RETRY_BACKOFF_MS")]
    retry_backoff_ms: Option<u64>,
    #[serde(rename = "LLM_MCP_STREAMING_RETRY_BACKOFF_MS")]
    streaming_retry_backoff_ms: Option<u64>,
    #[serde(rename = "LLM_MCP_FORCE_DISABLE_STREAMING")]
    force_disable_streaming: Option<bool>,
    #[serde(rename = "LLM_MCP_EMERGENCY_DISABLE_STREAMING")]
    emergency_disable_streaming: Option<bool>,
}

pub fn config_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("Failed to locate binary path: {}", e))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "Failed to resolve binary directory".to_string())?;
    let stem = exe
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "Failed to determine binary name".to_string())?;
    Ok(dir.join(format!("{}.toml", stem)))
}

enum ConfigReadOutcome {
    Parsed(ConfigToml, HashSet<String>),
    MissingOrEmpty,
    Invalid,
}

fn read_config_file(path: &Path) -> Result<ConfigReadOutcome, String> {
    if !path.exists() {
        debug!("config: no file at {}", path.display());
        return Ok(ConfigReadOutcome::MissingOrEmpty);
    }
    debug!("config: reading {}", path.display());
    let content = fs::read_to_string(path).map_err(|e| format!("Failed to read config: {}", e))?;
    if content.trim().is_empty() {
        debug!("config: file {} is empty", path.display());
        return Ok(ConfigReadOutcome::MissingOrEmpty);
    }
    let value: toml::Value = match toml::from_str(&content) {
        Ok(value) => value,
        Err(err) => {
            warn!("Invalid config TOML at {}: {}", path.display(), err);
            return Ok(ConfigReadOutcome::Invalid);
        }
    };
    debug!("config: parsed {}", path.display());
    let keys = value
        .as_table()
        .map(|table| table.keys().cloned().collect::<HashSet<_>>())
        .unwrap_or_default();
    let parsed: ConfigToml = match toml::from_str(&content) {
        Ok(parsed) => parsed,
        Err(err) => {
            warn!("Invalid config TOML at {}: {}", path.display(), err);
            return Ok(ConfigReadOutcome::Invalid);
        }
    };
    debug!("config: extracted {} keys", keys.len());
    Ok(ConfigReadOutcome::Parsed(parsed, keys))
}

fn parse_providers(raw: &str) -> Vec<String> {
    let normalized = raw.replace([',', ';'], " ");
    normalized
        .split_whitespace()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(|item| item.to_string())
        .collect()
}

fn parse_providers_value(value: &toml::Value) -> Vec<String> {
    match value {
        toml::Value::String(s) => parse_providers(s),
        toml::Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str())
            .map(|item| item.trim())
            .filter(|item| !item.is_empty())
            .map(|item| item.to_string())
            .collect(),
        _ => Vec::new(),
    }
}

fn write_config_file(path: &Path, config: &Config, keys: Option<&HashSet<String>>) -> Result<(), String> {
    let include_all = keys.is_none();
    let should_include = |key: &str| include_all || keys.map_or(false, |set| set.contains(key));
    let mut table = toml::map::Map::new();

    if should_include("LLM_MCP_PROVIDER") {
        table.insert("LLM_MCP_PROVIDER".to_string(), toml::Value::String(config.provider.clone()));
    }
    if should_include("LLM_MCP_PROVIDERS") {
        let items = config
            .providers
            .iter()
            .cloned()
            .map(toml::Value::String)
            .collect::<Vec<_>>();
        table.insert("LLM_MCP_PROVIDERS".to_string(), toml::Value::Array(items));
    }
    if should_include("LLM_MCP_PROVIDER_ENDPOINT") {
        if let Some(endpoint) = &config.provider_endpoint {
            table.insert("LLM_MCP_PROVIDER_ENDPOINT".to_string(), toml::Value::String(endpoint.clone()));
        }
    }
    if should_include("LLM_MCP_PROVIDER_API_KEY") {
        if let Some(key) = &config.provider_api_key {
            table.insert("LLM_MCP_PROVIDER_API_KEY".to_string(), toml::Value::String(key.clone()));
        }
    }
    if should_include("LLM_MCP_PROVIDER_API_KEY_HEADER") {
        table.insert(
            "LLM_MCP_PROVIDER_API_KEY_HEADER".to_string(),
            toml::Value::String(config.provider_api_key_header.clone()),
        );
    }
    if should_include("LLM_MCP_PROVIDER_API_KEY_PREFIX") {
        table.insert(
            "LLM_MCP_PROVIDER_API_KEY_PREFIX".to_string(),
            toml::Value::String(config.provider_api_key_prefix.clone()),
        );
    }
    if should_include("LLM_MCP_MODEL_MAPPING") {
        table.insert(
            "LLM_MCP_MODEL_MAPPING".to_string(),
            toml::Value::String(config.model_mapping_mode.as_str().to_string()),
        );
    }

    if should_include("LLM_MCP_GEMINI_API_KEY") {
        table.insert("LLM_MCP_GEMINI_API_KEY".to_string(), toml::Value::String(config.gemini_api_key.clone()));
    }
    if should_include("LLM_MCP_CEREBRAS_API_KEY") {
        table.insert("LLM_MCP_CEREBRAS_API_KEY".to_string(), toml::Value::String(config.cerebras_api_key.clone()));
    }
    if should_include("LLM_MCP_OPENAI_API_KEY") {
        table.insert("LLM_MCP_OPENAI_API_KEY".to_string(), toml::Value::String(config.openai_api_key.clone()));
    }
    if should_include("LLM_MCP_BIG_MODEL") {
        table.insert("LLM_MCP_BIG_MODEL".to_string(), toml::Value::String(config.big_model.clone()));
    }
    if should_include("LLM_MCP_SMALL_MODEL") {
        table.insert("LLM_MCP_SMALL_MODEL".to_string(), toml::Value::String(config.small_model.clone()));
    }
    if should_include("LLM_MCP_MAX_TOKENS_LIMIT") {
        table.insert(
            "LLM_MCP_MAX_TOKENS_LIMIT".to_string(),
            toml::Value::Integer(config.max_tokens_limit as i64),
        );
    }
    if should_include("LLM_MCP_REQUEST_TIMEOUT") {
        table.insert(
            "LLM_MCP_REQUEST_TIMEOUT".to_string(),
            toml::Value::Integer(config.request_timeout as i64),
        );
    }
    if should_include("LLM_MCP_MAX_RETRIES") {
        table.insert(
            "LLM_MCP_MAX_RETRIES".to_string(),
            toml::Value::Integer(config.max_retries as i64),
        );
    }
    if should_include("LLM_MCP_MAX_STREAMING_RETRIES") {
        table.insert(
            "LLM_MCP_MAX_STREAMING_RETRIES".to_string(),
            toml::Value::Integer(config.max_streaming_retries as i64),
        );
    }
    if should_include("LLM_MCP_RETRY_BACKOFF_MS") {
        table.insert(
            "LLM_MCP_RETRY_BACKOFF_MS".to_string(),
            toml::Value::Integer(config.retry_backoff_ms as i64),
        );
    }
    if should_include("LLM_MCP_STREAMING_RETRY_BACKOFF_MS") {
        table.insert(
            "LLM_MCP_STREAMING_RETRY_BACKOFF_MS".to_string(),
            toml::Value::Integer(config.streaming_retry_backoff_ms as i64),
        );
    }
    if should_include("LLM_MCP_FORCE_DISABLE_STREAMING") {
        table.insert(
            "LLM_MCP_FORCE_DISABLE_STREAMING".to_string(),
            toml::Value::Boolean(config.force_disable_streaming),
        );
    }
    if should_include("LLM_MCP_EMERGENCY_DISABLE_STREAMING") {
        table.insert(
            "LLM_MCP_EMERGENCY_DISABLE_STREAMING".to_string(),
            toml::Value::Boolean(config.emergency_disable_streaming),
        );
    }

    let output = toml::to_string_pretty(&toml::Value::Table(table))
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    fs::write(path, output).map_err(|e| format!("Failed to write config: {}", e))?;
    Ok(())
}

pub fn load_config() -> Result<Config, String> {
    let mut config = Config::defaults();
    config.apply_env_overrides();

    let path = config_path()?;
    if path.exists() {
        info!("config: found {} (reading)", path.display());
    } else {
        info!("config: not found at {} (using defaults)", path.display());
    }
    let config_result = read_config_file(&path)?;
    match config_result {
        ConfigReadOutcome::Parsed(parsed, keys) => {
            info!("config: loaded {} keys from {}", keys.len(), path.display());
            config.apply_toml_overrides(parsed);
            if keys.is_empty() {
                write_config_file(&path, &config, None)?;
            } else {
                write_config_file(&path, &config, Some(&keys))?;
            }
        }
        ConfigReadOutcome::MissingOrEmpty => {
            info!("config: writing defaults to {}", path.display());
            write_config_file(&path, &config, None)?;
        }
        ConfigReadOutcome::Invalid => {
            info!("config: invalid TOML, keeping existing file and using defaults");
        }
    }

    if config.provider.eq_ignore_ascii_case("openai")
        && config.big_model == "gemini-3-pro-preview"
        && config.small_model == "gemini-3-flash-preview"
    {
        config.big_model = "gpt-5.2-pro".to_string();
        config.small_model = "gpt-5.2-chat-latest".to_string();
    }

    Ok(config)
}
