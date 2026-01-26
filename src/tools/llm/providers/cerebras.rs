use super::super::config::Config;
use super::{models_list_probe_for, read_env_key, ProviderAdapter, ProviderProbe};

pub struct CerebrasProvider;

impl ProviderAdapter for CerebrasProvider {
    fn name(&self) -> &'static str {
        "cerebras"
    }

    fn default_endpoint(&self) -> &'static str {
        "https://api.cerebras.ai/v1/chat/completions"
    }

    fn api_key(&self, config: &Config) -> Option<String> {
        if config.cerebras_api_key.trim().is_empty() {
            None
        } else {
            Some(config.cerebras_api_key.clone())
        }
    }

    fn detect_env(&self, config: &mut Config) -> bool {
        if !config.cerebras_api_key.trim().is_empty() {
            return true;
        }
        if let Some(value) = read_env_key(&["LLM_MCP_CEREBRAS_API_KEY", "CEREBRAS_API_KEY"]) {
            config.cerebras_api_key = value;
            return true;
        }
        false
    }

    fn probe(&self, config: &Config) -> Option<ProviderProbe> {
        models_list_probe_for(config, self.name())
    }
}
