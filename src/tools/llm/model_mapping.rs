use std::collections::HashSet;

use super::config::{Config, ModelMappingMode};

#[derive(Clone)]
pub struct ModelManager {
    gemini_models: HashSet<String>,
    big_model: String,
    small_model: String,
}

impl ModelManager {
    pub fn new(config: &Config) -> Self {
        let base_models = [
            "gemini-1.5-pro-latest",
            "gemini-1.5-pro-preview-0514",
            "gemini-1.5-flash-latest",
            "gemini-1.5-flash-preview-0514",
            "gemini-pro",
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            "gemini-3-pro-preview",
            "gemini-3-flash-preview",
            "gemini-2.5-pro-preview-05-06",
            "gemini-2.5-flash-preview-04-17",
            "gemini-2.0-flash-exp",
            "gemini-exp-1206",
        ];
        let mut gemini_models = base_models.iter().map(|m| m.to_string()).collect::<HashSet<_>>();
        if config.big_model.starts_with("gemini") {
            gemini_models.insert(config.big_model.clone());
        }
        if config.small_model.starts_with("gemini") {
            gemini_models.insert(config.small_model.clone());
        }
        Self {
            gemini_models,
            big_model: config.big_model.clone(),
            small_model: config.small_model.clone(),
        }
    }

    pub fn validate_and_map_model(
        &self,
        original: &str,
        provider: &str,
        mode: ModelMappingMode,
    ) -> (String, bool) {
        if mode == ModelMappingMode::Off {
            return (original.to_string(), false);
        }

        let clean = Self::clean_model_name(original);
        if !provider.eq_ignore_ascii_case("gemini") {
            return (clean, false);
        }

        let mapped = match mode {
            ModelMappingMode::Auto => self.map_model_alias(&clean),
            ModelMappingMode::Passthrough => clean.clone(),
            ModelMappingMode::Off => clean.clone(),
        };

        if mapped != clean {
            return (mapped, true);
        }

        if self.gemini_models.contains(&clean) {
            return (clean, true);
        }

        if mode == ModelMappingMode::Auto {
            return (self.big_model.clone(), true);
        }

        (clean, false)
    }

    fn clean_model_name(model: &str) -> String {
        if let Some(stripped) = model.strip_prefix("gemini/") {
            return stripped.to_string();
        }
        if let Some(stripped) = model.strip_prefix("anthropic/") {
            return stripped.to_string();
        }
        if let Some(stripped) = model.strip_prefix("openai/") {
            return stripped.to_string();
        }
        model.to_string()
    }

    fn map_model_alias(&self, clean_model: &str) -> String {
        let lower = clean_model.to_lowercase();
        if lower.contains("haiku")
            || lower.contains("sonnet")
            || lower.contains("mini")
            || lower.contains("small")
            || lower.contains("lite")
            || lower.contains("tiny")
        {
            self.small_model.clone()
        } else if lower.contains("opus")
            || lower.contains("gpt")
            || lower.contains("claude")
            || lower.contains("o1")
            || lower.contains("deepseek")
            || lower.contains("qwen")
            || lower.contains("grok")
            || lower.contains("llama")
            || lower.contains("mistral")
            || lower.contains("mixtral")
        {
            self.big_model.clone()
        } else {
            clean_model.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_aliases_to_size_models() {
        let mut config = Config::defaults();
        config.big_model = "gemini-3-pro-preview".to_string();
        config.small_model = "gemini-3-flash-preview".to_string();
        let manager = ModelManager::new(&config);

        let (mapped, ok) =
            manager.validate_and_map_model("claude-3-5-sonnet-20241022", "gemini", ModelMappingMode::Auto);
        assert_eq!(mapped, "gemini-3-flash-preview");
        assert!(ok);

        let (mapped, ok) =
            manager.validate_and_map_model("gpt-4o-mini", "gemini", ModelMappingMode::Auto);
        assert_eq!(mapped, "gemini-3-flash-preview");
        assert!(ok);

        let (mapped, ok) = manager.validate_and_map_model("gpt-4o", "gemini", ModelMappingMode::Auto);
        assert_eq!(mapped, "gemini-3-pro-preview");
        assert!(ok);

        let (mapped, ok) =
            manager.validate_and_map_model("deepseek-chat", "gemini", ModelMappingMode::Auto);
        assert_eq!(mapped, "gemini-3-pro-preview");
        assert!(ok);
    }
}
