//! ToolRegistry — name -> Arc<dyn Tool> dispatcher.

use crate::tool::{Destructiveness, Tool, ToolCtx, ToolError, ToolOutput};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;

#[derive(Default)]
pub struct ToolRegistry {
    tools: HashMap<&'static str, Arc<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<T: Tool + 'static>(mut self, tool: T) -> Self {
        let name = tool.name();
        self.tools.insert(name, Arc::new(tool));
        self
    }

    pub fn names(&self) -> Vec<&'static str> {
        let mut n: Vec<_> = self.tools.keys().copied().collect();
        n.sort_unstable();
        n
    }

    pub fn descriptors(&self) -> Vec<crate::llm::ToolDescriptor> {
        self.tools
            .values()
            .map(|t| crate::llm::ToolDescriptor {
                name: t.name().to_string(),
                description: t.description().to_string(),
                input_schema: t.input_schema(),
            })
            .collect()
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Tool>> {
        self.tools.get(name).cloned()
    }

    pub async fn invoke(
        &self,
        name: &str,
        ctx: &ToolCtx,
        input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError> {
        let tool = self
            .get(name)
            .ok_or_else(|| ToolError::NotFound(format!("unknown tool: {name}")))?;

        // Destructive tools force dry-run unless confirm phrase present.
        let mut effective_ctx = ctx.clone();
        if tool.destructiveness() == Destructiveness::Destructive {
            let confirmed = input
                .get("confirm")
                .and_then(|v| v.as_str())
                .map(|s| s == "I_UNDERSTAND")
                .unwrap_or(false);
            if !confirmed {
                effective_ctx.dry_run = true;
            }
        }

        info!(
            tool = name,
            actor = %ctx.actor_sub,
            tenant = %ctx.tenant,
            dry_run = effective_ctx.dry_run,
            "pilot tool invoke"
        );

        let out = tool.invoke(&effective_ctx, input.clone()).await?;
        info!(
            tool = name,
            outcome = ?out.outcome,
            "pilot tool complete"
        );
        Ok(out)
    }
}
