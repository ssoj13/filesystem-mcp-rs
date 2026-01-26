use super::super::config::Config;
use super::{models_list_probe_for, read_env_key, ProviderAdapter, ProviderProbe};

pub struct OpenaiProvider;

impl ProviderAdapter for OpenaiProvider {
    fn name(&self) -> &'static str {
        "openai"
    }

    fn default_endpoint(&self) -> &'static str {
        "https://api.openai.com/v1/chat/completions"
    }

    fn api_key(&self, config: &Config) -> Option<String> {
        if config.openai_api_key.trim().is_empty() {
            None
        } else {
            Some(config.openai_api_key.clone())
        }
    }

    fn detect_env(&self, config: &mut Config) -> bool {
        if !config.openai_api_key.trim().is_empty() {
            return true;
        }
        if let Some(value) = read_env_key(&["LLM_MCP_OPENAI_API_KEY", "OPENAI_API_KEY"]) {
            config.openai_api_key = value;
            return true;
        }
        false
    }

    fn probe(&self, config: &Config) -> Option<ProviderProbe> {
        models_list_probe_for(config, self.name())
    }
}
