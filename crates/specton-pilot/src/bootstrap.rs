//! Build a default ToolRegistry wired to a registry HTTP client.

use std::sync::Arc;

use sqlx::PgPool;

use crate::client::RegistryClient;
use crate::registry::ToolRegistry;
use crate::tools::{
    EvaluateAdmissionTool, InspectImageTool, ListFindingsTool, ListRepositoriesTool, PingTool,
    PromoteTagTool, QueryAuditTool, TriggerRebuildTool, TriggerScanTool,
};

pub fn default_tools(client: Arc<RegistryClient>, pool: Option<PgPool>) -> ToolRegistry {
    ToolRegistry::new()
        .register(PingTool)
        .register(ListRepositoriesTool {
            client: client.clone(),
        })
        .register(InspectImageTool {
            client: client.clone(),
        })
        .register(QueryAuditTool {
            client: client.clone(),
        })
        .register(ListFindingsTool {
            pool,
            client: client.clone(),
        })
        .register(TriggerRebuildTool {
            client: client.clone(),
        })
        .register(PromoteTagTool {
            client: client.clone(),
        })
        .register(TriggerScanTool {
            client: client.clone(),
        })
        .register(EvaluateAdmissionTool { client })
}
