//! Mutating pilot tools (P2+): rebuild, promote, scan, GC, suppress.

use std::sync::Arc;

use async_trait::async_trait;

use crate::client::RegistryClient;
use crate::tool::{Destructiveness, Tool, ToolCtx, ToolError, ToolOutput, ToolPermission};

pub struct TriggerRebuildTool {
    pub client: Arc<RegistryClient>,
}

#[async_trait]
impl Tool for TriggerRebuildTool {
    fn name(&self) -> &'static str {
        "trigger_rebuild"
    }
    fn description(&self) -> &'static str {
        "Manually fire a RebuildSubscription (POST /v2/_rebuild/trigger)."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "subscription": { "type": "string" },
                "upstream": { "type": "string" },
                "downstream": { "type": "string" },
                "reason": { "type": "string", "default": "manual" }
            },
            "required": ["subscription", "upstream", "downstream"]
        })
    }
    fn permission(&self) -> ToolPermission {
        ToolPermission("tenant:admin".into())
    }
    fn destructiveness(&self) -> Destructiveness {
        Destructiveness::Mutating
    }
    async fn invoke(
        &self,
        ctx: &ToolCtx,
        input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError> {
        if ctx.dry_run {
            return Ok(ToolOutput::allow(serde_json::json!({
                "dry_run": true,
                "would_call": "/v2/_rebuild/trigger",
                "input": input,
            })));
        }
        let body = serde_json::json!({
            "tenant": ctx.tenant,
            "subscription": input.get("subscription").and_then(|v| v.as_str()).unwrap_or(""),
            "upstream": input.get("upstream").and_then(|v| v.as_str()).unwrap_or(""),
            "downstream": input.get("downstream").and_then(|v| v.as_str()).unwrap_or(""),
            "upstream_ref": input.get("upstream").and_then(|v| v.as_str()).unwrap_or(""),
            "downstream_ref": input.get("downstream").and_then(|v| v.as_str()).unwrap_or(""),
            "reason": input.get("reason").and_then(|v| v.as_str()).unwrap_or("manual"),
        });
        let data = self
            .client
            .post_json("/v2/_rebuild/trigger", &body)
            .await
            .map_err(ToolError::Internal)?;
        Ok(ToolOutput::allow(data))
    }
}

pub struct PromoteTagTool {
    pub client: Arc<RegistryClient>,
}

#[async_trait]
impl Tool for PromoteTagTool {
    fn name(&self) -> &'static str {
        "promote_tag"
    }
    fn description(&self) -> &'static str {
        "Atomically promote an image from source to dest (POST /v2/_promote)."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "source": { "type": "string" },
                "dest": { "type": "string" },
                "dry_run": { "type": "boolean", "default": false },
                "on_policy_pass": { "type": "boolean", "default": false },
                "policy": { "type": "string" }
            },
            "required": ["source", "dest"]
        })
    }
    fn permission(&self) -> ToolPermission {
        ToolPermission("repo:promote".into())
    }
    fn destructiveness(&self) -> Destructiveness {
        Destructiveness::Mutating
    }
    async fn invoke(
        &self,
        ctx: &ToolCtx,
        input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError> {
        let source = input
            .get("source")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("missing source".into()))?;
        let dest = input
            .get("dest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("missing dest".into()))?;
        let dry = ctx.dry_run || input.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false);
        let on_policy = input
            .get("on_policy_pass")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mode = if dry {
            "dry_run"
        } else if on_policy {
            "on_policy_pass"
        } else {
            "force"
        };
        if ctx.dry_run && !dry {
            return Ok(ToolOutput::allow(serde_json::json!({
                "dry_run": true,
                "would_promote": { "source": source, "dest": dest }
            })));
        }
        let body = serde_json::json!({
            "source": source,
            "dest": dest,
            "mode": mode,
            "policy": input.get("policy"),
            "include_signatures": true,
        });
        let data = self
            .client
            .post_json("/v2/_promote", &body)
            .await
            .map_err(ToolError::Internal)?;
        Ok(ToolOutput::allow(data))
    }
}

pub struct TriggerScanTool {
    pub client: Arc<RegistryClient>,
}

#[async_trait]
impl Tool for TriggerScanTool {
    fn name(&self) -> &'static str {
        "trigger_scan"
    }
    fn description(&self) -> &'static str {
        "Request a scan for an image digest via the scanner API."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "digest": { "type": "string" },
                "tenant": { "type": "string" },
                "project": { "type": "string" },
                "repository": { "type": "string" },
                "reference": { "type": "string" }
            },
            "required": ["digest"]
        })
    }
    fn permission(&self) -> ToolPermission {
        ToolPermission("repo:scan".into())
    }
    fn destructiveness(&self) -> Destructiveness {
        Destructiveness::Mutating
    }
    async fn invoke(
        &self,
        ctx: &ToolCtx,
        input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError> {
        if ctx.dry_run {
            return Ok(ToolOutput::allow(serde_json::json!({
                "dry_run": true,
                "would_scan": input
            })));
        }
        let digest = input
            .get("digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("missing digest".into()))?;
        // Best-effort: hit live endpoint which may enqueue if configured.
        let path = format!("/v2/scan/live/{digest}");
        match self.client.get_json(&path).await {
            Ok(data) => Ok(ToolOutput::allow(data)),
            Err(e) => Ok(ToolOutput::allow(serde_json::json!({
                "queued": false,
                "note": e,
                "digest": digest,
            }))),
        }
    }
}

pub struct EvaluateAdmissionTool {
    pub client: Arc<RegistryClient>,
}

#[async_trait]
impl Tool for EvaluateAdmissionTool {
    fn name(&self) -> &'static str {
        "evaluate_admission"
    }
    fn description(&self) -> &'static str {
        "Dry-run admission evaluation for an image ref (POST /v2/_admit/test)."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "ref": { "type": "string" },
                "policy_name": { "type": "string" }
            },
            "required": ["ref"]
        })
    }
    fn permission(&self) -> ToolPermission {
        ToolPermission("tenant:manage".into())
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
            .ok_or_else(|| ToolError::InvalidInput("missing ref".into()))?;
        let body = serde_json::json!({
            "ref": r,
            "policy_name": input.get("policy_name"),
        });
        let data = self
            .client
            .post_json("/v2/_admit/test", &body)
            .await
            .map_err(ToolError::Internal)?;
        Ok(ToolOutput::allow(data))
    }
}

pub struct SuppressFindingTool {
    pub client: Arc<RegistryClient>,
}

#[async_trait]
impl Tool for SuppressFindingTool {
    fn name(&self) -> &'static str {
        "suppress_finding"
    }
    fn description(&self) -> &'static str {
        "Create a CVE suppression (POST /v2/cve/suppress)."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "cve_id": { "type": "string" },
                "reason": { "type": "string" },
                "scope_tenant": { "type": "string" },
                "scope_project": { "type": "string" },
                "scope_repository": { "type": "string" },
                "scope_package": { "type": "string" },
                "expires_at": { "type": "string", "description": "RFC3339 timestamp" }
            },
            "required": ["cve_id", "reason"]
        })
    }
    fn permission(&self) -> ToolPermission {
        ToolPermission("tenant:write".into())
    }
    fn destructiveness(&self) -> Destructiveness {
        Destructiveness::Mutating
    }
    async fn invoke(
        &self,
        ctx: &ToolCtx,
        input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError> {
        let cve_id = input
            .get("cve_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("missing cve_id".into()))?;
        let reason = input
            .get("reason")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("missing reason".into()))?;
        if ctx.dry_run {
            return Ok(ToolOutput::allow(serde_json::json!({
                "dry_run": true,
                "would_call": "/v2/cve/suppress",
                "cve_id": cve_id,
                "reason": reason,
            })));
        }
        let body = serde_json::json!({
            "cve_id": cve_id,
            "reason": reason,
            "scope_tenant": input.get("scope_tenant").and_then(|v| v.as_str())
                .or(Some(ctx.tenant.as_str())),
            "scope_project": input.get("scope_project"),
            "scope_repository": input.get("scope_repository"),
            "scope_package": input.get("scope_package"),
            "expires_at": input.get("expires_at"),
        });
        let data = self
            .client
            .post_json("/v2/cve/suppress", &body)
            .await
            .map_err(ToolError::Internal)?;
        Ok(ToolOutput::allow(data))
    }
}

pub struct UnsuppressFindingTool {
    pub client: Arc<RegistryClient>,
}

#[async_trait]
impl Tool for UnsuppressFindingTool {
    fn name(&self) -> &'static str {
        "unsuppress_finding"
    }
    fn description(&self) -> &'static str {
        "Revoke a CVE suppression (DELETE /v2/cve/suppress/{id})."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "id": { "type": "string", "description": "Suppression UUID" }
            },
            "required": ["id"]
        })
    }
    fn permission(&self) -> ToolPermission {
        ToolPermission("tenant:write".into())
    }
    fn destructiveness(&self) -> Destructiveness {
        Destructiveness::Mutating
    }
    async fn invoke(
        &self,
        ctx: &ToolCtx,
        input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError> {
        let id = input
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidInput("missing id".into()))?;
        if ctx.dry_run {
            return Ok(ToolOutput::allow(serde_json::json!({
                "dry_run": true,
                "would_call": format!("/v2/cve/suppress/{id}"),
            })));
        }
        let path = format!("/v2/cve/suppress/{id}");
        let data = self
            .client
            .delete_json(&path)
            .await
            .map_err(ToolError::Internal)?;
        Ok(ToolOutput::allow(data))
    }
}

pub struct RunGcReconcileTool {
    pub client: Arc<RegistryClient>,
}

#[async_trait]
impl Tool for RunGcReconcileTool {
    fn name(&self) -> &'static str {
        "run_gc_reconcile"
    }
    fn description(&self) -> &'static str {
        "Run online-GC reconcile (POST /v2/_gc/reconcile)."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "apply": { "type": "boolean", "default": false },
                "max": { "type": "integer" }
            }
        })
    }
    fn permission(&self) -> ToolPermission {
        ToolPermission("tenant:admin".into())
    }
    fn destructiveness(&self) -> Destructiveness {
        Destructiveness::Mutating
    }
    async fn invoke(
        &self,
        ctx: &ToolCtx,
        input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError> {
        let apply = input
            .get("apply")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if ctx.dry_run {
            return Ok(ToolOutput::allow(serde_json::json!({
                "dry_run": true,
                "would_call": "/v2/_gc/reconcile",
                "apply": apply,
            })));
        }
        let body = serde_json::json!({
            "apply": apply,
            "max": input.get("max"),
        });
        let data = self
            .client
            .post_json("/v2/_gc/reconcile", &body)
            .await
            .map_err(ToolError::Internal)?;
        Ok(ToolOutput::allow(data))
    }
}

pub struct PauseGcTool {
    pub client: Arc<RegistryClient>,
}

#[async_trait]
impl Tool for PauseGcTool {
    fn name(&self) -> &'static str {
        "pause_gc"
    }
    fn description(&self) -> &'static str {
        "Pause the online-GC reaper (POST /v2/_gc/pause)."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({ "type": "object", "properties": {} })
    }
    fn permission(&self) -> ToolPermission {
        ToolPermission("tenant:admin".into())
    }
    fn destructiveness(&self) -> Destructiveness {
        Destructiveness::Mutating
    }
    async fn invoke(
        &self,
        ctx: &ToolCtx,
        _input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError> {
        if ctx.dry_run {
            return Ok(ToolOutput::allow(serde_json::json!({
                "dry_run": true,
                "would_call": "/v2/_gc/pause",
            })));
        }
        let data = self
            .client
            .post_json("/v2/_gc/pause", &serde_json::json!({}))
            .await
            .map_err(ToolError::Internal)?;
        Ok(ToolOutput::allow(data))
    }
}

pub struct ResumeGcTool {
    pub client: Arc<RegistryClient>,
}

#[async_trait]
impl Tool for ResumeGcTool {
    fn name(&self) -> &'static str {
        "resume_gc"
    }
    fn description(&self) -> &'static str {
        "Resume the online-GC reaper (POST /v2/_gc/resume)."
    }
    fn input_schema(&self) -> serde_json::Value {
        serde_json::json!({ "type": "object", "properties": {} })
    }
    fn permission(&self) -> ToolPermission {
        ToolPermission("tenant:admin".into())
    }
    fn destructiveness(&self) -> Destructiveness {
        Destructiveness::Mutating
    }
    async fn invoke(
        &self,
        ctx: &ToolCtx,
        _input: serde_json::Value,
    ) -> Result<ToolOutput, ToolError> {
        if ctx.dry_run {
            return Ok(ToolOutput::allow(serde_json::json!({
                "dry_run": true,
                "would_call": "/v2/_gc/resume",
            })));
        }
        let data = self
            .client
            .post_json("/v2/_gc/resume", &serde_json::json!({}))
            .await
            .map_err(ToolError::Internal)?;
        Ok(ToolOutput::allow(data))
    }
}
