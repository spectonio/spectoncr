//! Read-only pilot tools (P1b): list / inspect / audit / findings.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::PgPool;

use crate::client::RegistryClient;
use crate::tool::{Destructiveness, Tool, ToolCtx, ToolError, ToolOutput, ToolPermission};

pub struct ListRepositoriesTool {
    pub client: Arc<RegistryClient>,
}

#[async_trait]
impl Tool for ListRepositoriesTool {
    fn name(&self) -> &'static str {
        "list_repositories"
    }
    fn description(&self) -> &'static str {
        "List repositories visible in the registry catalog for the current tenant."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "n": { "type": "integer", "description": "page size", "default": 100 }
            }
        })
    }
    fn permission(&self) -> ToolPermission {
        ToolPermission("tenant:read".into())
    }
    fn destructiveness(&self) -> Destructiveness {
        Destructiveness::ReadOnly
    }
    async fn invoke(
        &self,
        ctx: &ToolCtx,
        input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError> {
        let n = input.get("n").and_then(|v| v.as_u64()).unwrap_or(100);
        let path = format!("/v2/_catalog?n={n}");
        let data = self
            .client
            .get_json(&path)
            .await
            .map_err(ToolError::Internal)?;
        // Filter to tenant prefix when catalog returns full names.
        let repos = data
            .get("repositories")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|r| {
                r.as_str()
                    .map(|s| s.starts_with(&format!("{}/", ctx.tenant)) || s.contains(&ctx.tenant))
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        Ok(ToolOutput::allow(serde_json::json!({
            "tenant": ctx.tenant,
            "repositories": repos,
        })))
    }
}

pub struct InspectImageTool {
    pub client: Arc<RegistryClient>,
}

#[async_trait]
impl Tool for InspectImageTool {
    fn name(&self) -> &'static str {
        "inspect_image"
    }
    fn description(&self) -> &'static str {
        "Inspect an image ref (tenant/project/repo:tag) — status + digest readiness."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "ref": { "type": "string", "description": "tenant/project/repo:tag" }
            },
            "required": ["ref"]
        })
    }
    fn permission(&self) -> ToolPermission {
        ToolPermission("repo:read".into())
    }
    fn destructiveness(&self) -> Destructiveness {
        Destructiveness::ReadOnly
    }
    async fn invoke(
        &self,
        _ctx: &ToolCtx,
        input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError> {
        let r = input
            .get("ref")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("missing 'ref'".into()))?;
        let (path, reference) = split_ref(r)?;
        let status_path = format!("/v2/{path}/status/{reference}");
        let data = self
            .client
            .get_json(&status_path)
            .await
            .map_err(ToolError::Internal)?;
        Ok(ToolOutput::allow(data))
    }
}

pub struct QueryAuditTool {
    pub client: Arc<RegistryClient>,
}

#[async_trait]
impl Tool for QueryAuditTool {
    fn name(&self) -> &'static str {
        "query_audit"
    }
    fn description(&self) -> &'static str {
        "Query the chained registry audit log (GET /v2/_audit)."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "limit": { "type": "integer", "default": 50 },
                "category": { "type": "string" }
            }
        })
    }
    fn permission(&self) -> ToolPermission {
        ToolPermission("tenant:audit".into())
    }
    fn destructiveness(&self) -> Destructiveness {
        Destructiveness::ReadOnly
    }
    async fn invoke(
        &self,
        _ctx: &ToolCtx,
        input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError> {
        let limit = input.get("limit").and_then(|v| v.as_u64()).unwrap_or(50);
        let mut path = format!("/v2/_audit?limit={limit}");
        if let Some(cat) = input.get("category").and_then(|v| v.as_str()) {
            path.push_str(&format!("&category={cat}"));
        }
        let data = self
            .client
            .get_json(&path)
            .await
            .map_err(ToolError::Internal)?;
        Ok(ToolOutput::allow(data))
    }
}

pub struct ListFindingsTool {
    pub pool: Option<PgPool>,
    pub client: Arc<RegistryClient>,
}

#[async_trait]
impl Tool for ListFindingsTool {
    fn name(&self) -> &'static str {
        "get_scan_findings"
    }
    fn description(&self) -> &'static str {
        "List vulnerability / detector findings for an image digest."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "digest": { "type": "string" },
                "limit": { "type": "integer", "default": 50 }
            },
            "required": ["digest"]
        })
    }
    fn permission(&self) -> ToolPermission {
        ToolPermission("repo:read".into())
    }
    fn destructiveness(&self) -> Destructiveness {
        Destructiveness::ReadOnly
    }
    async fn invoke(
        &self,
        _ctx: &ToolCtx,
        input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError> {
        let digest = input
            .get("digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("missing 'digest'".into()))?;
        let limit = input.get("limit").and_then(|v| v.as_i64()).unwrap_or(50);

        if let Some(pool) = &self.pool {
            // Prefer detector findings table when present.
            let rows = sqlx::query(
                "SELECT finding_id, severity, raw FROM findings
                 WHERE digest = $1 ORDER BY detected_at DESC LIMIT $2",
            )
            .bind(digest)
            .bind(limit)
            .fetch_all(pool)
            .await;
            if let Ok(rows) = rows {
                use sqlx::Row;
                let items: Vec<_> = rows
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "finding_id": r.try_get::<String, _>("finding_id").ok(),
                            "severity": r.try_get::<String, _>("severity").ok(),
                            "raw": r.try_get::<serde_json::Value, _>("raw").ok(),
                        })
                    })
                    .collect();
                return Ok(ToolOutput::allow(serde_json::json!({
                    "digest": digest,
                    "source": "postgres",
                    "items": items,
                })));
            }
        }

        // Fallback: live scan API if mounted.
        let path = format!("/v2/scan/live/{digest}");
        match self.client.get_json(&path).await {
            Ok(data) => Ok(ToolOutput::allow(data)),
            Err(e) => Err(ToolError::Internal(e)),
        }
    }
}

fn split_ref(r: &str) -> Result<(String, String), ToolError> {
    let (path, reference) = if let Some((p, d)) = r.split_once('@') {
        (p, d.to_string())
    } else if let Some((p, t)) = r.rsplit_once(':') {
        if p.contains('/') {
            (p, t.to_string())
        } else {
            return Err(ToolError::InvalidInput(format!("bad ref '{r}'")));
        }
    } else {
        return Err(ToolError::InvalidInput(format!("bad ref '{r}'")));
    };
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() != 3 {
        return Err(ToolError::InvalidInput(format!(
            "expected tenant/project/repo:tag, got '{r}'"
        )));
    }
    Ok((path.to_string(), reference))
}
