use super::super::config::Config;
use super::{read_env_key, ProviderAdapter, ProviderProbe};

pub struct GeminiProvider;

impl ProviderAdapter for GeminiProvider {
    fn name(&self) -> &'static str {
        "gemini"
    }

    fn default_endpoint(&self) -> &'static str {
        "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    }

    fn api_key(&self, config: &Config) -> Option<String> {
        if config.gemini_api_key.trim().is_empty() {
            None
        } else {
            Some(config.gemini_api_key.clone())
        }
    }

    fn detect_env(&self, config: &mut Config) -> bool {
        if !config.gemini_api_key.trim().is_empty() {
            return true;
        }
        if let Some(value) = read_env_key(&["LLM_MCP_GEMINI_API_KEY", "GEMINI_API_KEY"]) {
            config.gemini_api_key = value;
            return true;
        }
        false
    }

    fn probe(&self, config: &Config) -> Option<ProviderProbe> {
        let endpoint = config.effective_endpoint_for(self.name());
        if endpoint.trim().is_empty() || config.big_model.trim().is_empty() {
            return None;
        }
        Some(ProviderProbe::ChatCompletions {
            endpoint,
            model: config.big_model.clone(),
        })
    }
}
