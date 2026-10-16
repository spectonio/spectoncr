//! SpectonCR AI agent — `specton-pilot` (design 019).
//!
//! - **P1b:** read-only tools (`list_repositories`, `inspect_image`,
//!   `query_audit`, `get_scan_findings`)
//! - **P2:** mutating tools (`trigger_rebuild`, `promote_tag`,
//!   `trigger_scan`, `evaluate_admission`, suppress, GC) with dry-run
//! - **P3:** MCP server + CLI REPL binaries
//! - **P4:** spend caps (`budget`) + audited invoke + `/v2/_pilot/chat`

pub mod bootstrap;
pub mod budget;
pub mod chat;
pub mod client;
pub mod llm;
pub mod registry;
pub mod tool;
pub mod tools;

pub use bootstrap::default_tools;
pub use budget::{BudgetTracker, SpendCap};
pub use chat::{ChatConfig, ChatError, ChatTurn, run_turn, run_turn_with_budget};
pub use client::RegistryClient;
pub use llm::{
    ChatMessage, ChatRole, LlmClient, LlmError, LlmProvider, LlmStep, LlmToolCall, ToolDescriptor,
    anthropic::AnthropicClient, ollama::OllamaClient, openai::OpenAiClient,
};
pub use registry::ToolRegistry;
pub use tool::{
    Destructiveness, Tool, ToolCtx, ToolError, ToolOutcome, ToolOutput, ToolPermission,
};
