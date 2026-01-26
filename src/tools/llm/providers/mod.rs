mod cerebras;
mod gemini;
mod openai;

use super::config::Config;
use serde_json::Value;

pub trait ProviderAdapter: Sync {
    fn name(&self) -> &'static str;
    fn default_endpoint(&self) -> &'static str;
    fn api_key(&self, config: &Config) -> Option<String>;
    fn detect_env(&self, config: &mut Config) -> bool;
    fn probe(&self, config: &Config) -> Option<ProviderProbe>;
    fn tool_names(&self) -> Vec<String> {
        let name = self.name();
        vec![format!("ai_messages_{}", name), format!("ai_count_tokens_{}", name)]
    }
    fn prepare_request_body(&self, _body: &mut Value) {}
    fn postprocess_response(&self, _response: &mut Value) {}
}

pub enum ProviderProbe {
    ModelsList { endpoint: String },
    ChatCompletions { endpoint: String, model: String },
}

static GEMINI_PROVIDER: gemini::GeminiProvider = gemini::GeminiProvider;
static CEREBRAS_PROVIDER: cerebras::CerebrasProvider = cerebras::CerebrasProvider;
static OPENAI_PROVIDER: openai::OpenaiProvider = openai::OpenaiProvider;
static PROVIDERS: [&dyn ProviderAdapter; 3] = [
    &GEMINI_PROVIDER,
    &CEREBRAS_PROVIDER,
    &OPENAI_PROVIDER,
];

pub fn known_providers() -> &'static [&'static dyn ProviderAdapter] {
    &PROVIDERS
}

pub fn provider_by_name(name: &str) -> Option<&'static dyn ProviderAdapter> {
    let target = name.trim().to_lowercase();
    for provider in known_providers() {
        if provider.name() == target {
            return Some(*provider);
        }
    }
    None
}

pub fn probe_spec(name: &str, config: &Config) -> Option<ProviderProbe> {
    provider_by_name(name).and_then(|provider| provider.probe(config))
}

pub fn read_env_key(keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Ok(value) = std::env::var(key) {
            if !value.trim().is_empty() {
                return Some(value);
            }
        }
    }
    None
}

pub fn models_list_probe_for(config: &Config, provider: &str) -> Option<ProviderProbe> {
    let chat_endpoint = config.effective_endpoint_for(provider);
    let endpoint = match chat_endpoint.strip_suffix("/chat/completions") {
        Some(base) => format!("{base}/models"),
        None => format!("{}/models", chat_endpoint.trim_end_matches('/')),
    };
    if endpoint.trim().is_empty() {
        return None;
    }
    Some(ProviderProbe::ModelsList { endpoint })
}
