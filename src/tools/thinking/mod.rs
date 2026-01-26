//! Sequential thinking tools for structured problem-solving.
//!
//! Provides `seq_think` tool for dynamic, reflective reasoning with branching and revision.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::info;

/// Input for a thinking step
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ThoughtInput {
    /// Current thinking step content
    pub thought: String,
    /// Whether another thought step is needed
    pub next_thought_needed: bool,
    /// Current thought number (1-based)
    #[serde(default = "default_one")]
    pub thought_number: u32,
    /// Estimated total thoughts needed
    #[serde(default = "default_one")]
    pub total_thoughts: u32,
    /// Whether this revises previous thinking
    #[serde(default)]
    pub is_revision: Option<bool>,
    /// Which thought is being reconsidered
    #[serde(default)]
    pub revises_thought: Option<u32>,
    /// Branching point thought number
    #[serde(default)]
    pub branch_from_thought: Option<u32>,
    /// Branch identifier
    #[serde(default)]
    pub branch_id: Option<String>,
    /// If more thoughts are needed beyond estimate
    #[serde(default)]
    pub needs_more_thoughts: Option<bool>,
}

pub fn default_one() -> u32 {
    1
}

/// Stored thought with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThoughtData {
    pub thought: String,
    pub thought_number: u32,
    pub total_thoughts: u32,
    pub next_thought_needed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_revision: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revises_thought: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch_from_thought: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_more_thoughts: Option<bool>,
}

impl From<ThoughtInput> for ThoughtData {
    fn from(input: ThoughtInput) -> Self {
        Self {
            thought: input.thought,
            thought_number: input.thought_number,
            total_thoughts: input.total_thoughts,
            next_thought_needed: input.next_thought_needed,
            is_revision: input.is_revision,
            revises_thought: input.revises_thought,
            branch_from_thought: input.branch_from_thought,
            branch_id: input.branch_id,
            needs_more_thoughts: input.needs_more_thoughts,
        }
    }
}

/// Output from processing a thought
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ThoughtOutput {
    pub thought_number: u32,
    pub total_thoughts: u32,
    pub next_thought_needed: bool,
    pub branches: Vec<String>,
    pub thought_history_length: usize,
}

/// Sequential thinking server state
pub struct ThinkingState {
    thought_history: Mutex<Vec<ThoughtData>>,
    branches: Mutex<HashMap<String, Vec<ThoughtData>>>,
    disable_logging: bool,
}

impl Default for ThinkingState {
    fn default() -> Self {
        Self::new()
    }
}

impl ThinkingState {
    pub fn new() -> Self {
        let disable_logging = std::env::var("DISABLE_THOUGHT_LOGGING")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Self {
            thought_history: Mutex::new(Vec::new()),
            branches: Mutex::new(HashMap::new()),
            disable_logging,
        }
    }

    /// Process a thought and return result
    pub fn process(&self, input: ThoughtInput) -> ThoughtOutput {
        let mut data = ThoughtData::from(input);

        // Adjust total if thought_number exceeds it
        if data.thought_number > data.total_thoughts {
            data.total_thoughts = data.thought_number;
        }

        // Log formatted thought
        if !self.disable_logging {
            self.log_thought(&data);
        }

        // Store in history
        {
            let mut history = self.thought_history.lock().expect("mutex poisoned");
            history.push(data.clone());
        }

        // Store in branch if applicable
        if let (Some(_branch_from), Some(branch_id)) = (data.branch_from_thought, &data.branch_id) {
            let mut branches = self.branches.lock().expect("mutex poisoned");
            branches.entry(branch_id.clone()).or_default().push(data.clone());
        }

        // Build output
        let history_len = self.thought_history.lock().expect("mutex poisoned").len();
        let branch_keys: Vec<String> = self.branches.lock().expect("mutex poisoned").keys().cloned().collect();

        ThoughtOutput {
            thought_number: data.thought_number,
            total_thoughts: data.total_thoughts,
            next_thought_needed: data.next_thought_needed,
            branches: branch_keys,
            thought_history_length: history_len,
        }
    }

    fn log_thought(&self, data: &ThoughtData) {
        let (prefix, context) = if data.is_revision == Some(true) {
            ("REVISION", format!(" (revising thought {})", data.revises_thought.unwrap_or(0)))
        } else if let Some(branch_from) = data.branch_from_thought {
            ("BRANCH", format!(" (from thought {}, ID: {})", branch_from, data.branch_id.as_deref().unwrap_or("?")))
        } else {
            ("THOUGHT", String::new())
        };

        let header = format!("{} {}/{}{}", prefix, data.thought_number, data.total_thoughts, context);
        let content_width = data.thought.len().max(header.len()) + 4;
        let border = "-".repeat(content_width);

        info!("\n+{}+\n| {} |\n+{}+\n| {} |\n+{}+", border, header, border, data.thought, border);
    }
}
