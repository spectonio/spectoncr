//! Echo / no-op LLM — used when `[pilot] backend = "echo"` so the HTTP
//! chat surface and dashboard sidebar work without an external API key.

use async_trait::async_trait;

use super::{
    ChatMessage, ChatRole, LlmClient, LlmError, LlmProvider, LlmStep, ToolDescriptor,
};

/// Returns a short text reply summarising available tools + last user message.
pub struct EchoClient;

#[async_trait]
impl LlmClient for EchoClient {
    fn provider(&self) -> LlmProvider {
        LlmProvider::Echo
    }
    fn model(&self) -> &str {
        "echo"
    }

    async fn step(
        &self,
        _system: Option<&str>,
        msgs: &[ChatMessage],
        tools: &[ToolDescriptor],
    ) -> Result<LlmStep, LlmError> {
        let last_user = msgs
            .iter()
            .rev()
            .find(|m| matches!(m.role, ChatRole::User))
            .map(|m| m.content.as_str())
            .unwrap_or("");
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        Ok(LlmStep::Text(format!(
            "specton-pilot echo backend (no external LLM). \
             Available tools: {}. \
             You said: {last_user}",
            names.join(", ")
        )))
    }
}
