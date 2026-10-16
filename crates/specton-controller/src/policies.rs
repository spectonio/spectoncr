//! ImageVerificationPolicy, RebuildSubscription, AdmissionPolicy CRDs + reconcilers.
//!
//! Kept separate from `tenancy` so the main-branch tenancy refactor stays intact
//! while Phase A–D policy controllers remain registered.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, CustomResource, Resource, ResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::tenancy::Tenant;
use crate::{ControllerError, Ctx, EventInfo, publish_event};

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct Condition {
    #[serde(rename = "type")]
    pub type_: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ImageVerificationPolicy CRD (design 001 B4)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyScopeSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projects: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repositories: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TrustedSignerSpec {
    /// `Key` or `Keyless` (keyless is v1.1).
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_pattern: Option<String>,
}

#[derive(CustomResource, Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "spectoncr.io",
    version = "v1alpha1",
    kind = "ImageVerificationPolicy",
    plural = "imageverificationpolicies",
    shortname = "ivp",
    status = "ImageVerificationPolicyStatus",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct ImageVerificationPolicySpec {
    pub tenant_ref: String,
    #[serde(default)]
    pub scope: PolicyScopeSpec,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_signers: Vec<TrustedSignerSpec>,
    /// `block` | `warn` | `log`
    #[serde(default = "default_on_violation")]
    pub on_violation: String,
}

fn default_on_violation() -> String {
    "block".into()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct ImageVerificationPolicyStatus {
    #[serde(default)]
    pub phase: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

// ---------------------------------------------------------------------------
// RebuildSubscription CRD (design 018 R2)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RebuildWatchSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bases: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub descendants: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RebuildTriggersSpec {
    #[serde(default = "default_true")]
    pub on_cve_fix: bool,
    #[serde(default)]
    pub on_base_push: bool,
    #[serde(default = "default_min_sev")]
    pub min_severity_fixed: String,
}

fn default_min_sev() -> String {
    "high".into()
}

impl Default for RebuildTriggersSpec {
    fn default() -> Self {
        Self {
            on_cve_fix: true,
            on_base_push: false,
            min_severity_fixed: default_min_sev(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RebuildEmitterSpec {
    /// `github-dispatch` | `gitlab-trigger` | `webhook` | `tekton`
    #[serde(rename = "type")]
    pub type_: String,
    // GitHub
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    /// Secret name holding the GitHub PAT (key `token` by default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_secret_ref: Option<String>,
    // GitLab
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ref")]
    pub git_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_token_secret_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_base: Option<String>,
    // Webhook / Tekton
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_secret_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_secret_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_header_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RebuildRateLimitSpec {
    #[serde(default = "default_per_day")]
    pub per_downstream_per_day: i32,
}

fn default_per_day() -> i32 {
    1
}

impl Default for RebuildRateLimitSpec {
    fn default() -> Self {
        Self {
            per_downstream_per_day: default_per_day(),
        }
    }
}

#[derive(CustomResource, Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "spectoncr.io",
    version = "v1alpha1",
    kind = "RebuildSubscription",
    plural = "rebuildsubscriptions",
    shortname = "rsub",
    status = "RebuildSubscriptionStatus",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct RebuildSubscriptionSpec {
    pub tenant_ref: String,
    #[serde(default)]
    pub watch: RebuildWatchSpec,
    #[serde(default)]
    pub triggers: RebuildTriggersSpec,
    pub emitter: RebuildEmitterSpec,
    #[serde(default)]
    pub rate_limit: RebuildRateLimitSpec,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct RebuildSubscriptionStatus {
    #[serde(default)]
    pub phase: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

// ---------------------------------------------------------------------------
// AdmissionPolicy CRD (design 002 D2)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionSeverityRules {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub medium: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionSeverityThreshold {
    #[serde(default)]
    pub block: AdmissionSeverityRules,
    #[serde(default)]
    pub warn: AdmissionSeverityRules,
}

#[derive(CustomResource, Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "spectoncr.io",
    version = "v1alpha1",
    kind = "AdmissionPolicy",
    plural = "admissionpolicies",
    shortname = "admit",
    status = "AdmissionPolicyStatus",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionPolicySpec {
    pub tenant_ref: String,
    #[serde(default)]
    pub scope: PolicyScopeSpec,
    #[serde(default)]
    pub signature_required: bool,
    #[serde(default)]
    pub severity_threshold: AdmissionSeverityThreshold,
    #[serde(default = "default_on_unknown")]
    pub on_unknown: String,
    #[serde(default = "default_on_timeout")]
    pub on_timeout: String,
    #[serde(default = "default_scan_wait")]
    pub scan_wait_secs: u64,
}

fn default_on_unknown() -> String {
    "block".into()
}
fn default_on_timeout() -> String {
    "block".into()
}
fn default_scan_wait() -> u64 {
    5
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct AdmissionPolicyStatus {
    #[serde(default)]
    pub phase: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

async fn update_status<T>(
    api: &Api<T>,
    name: &str,
    status: serde_json::Value,
) -> Result<(), ControllerError>
where
    T: Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + Serialize,
{
    let patch = serde_json::json!({ "status": status });
    let pp = PatchParams::apply("specton-controller").force();
    api.patch_status(name, &pp, &Patch::Merge(&patch)).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: publish a Kubernetes Event

async fn sync_to_registry(
    http: &reqwest::Client,
    base_url: &str,
    path: &str,
    body: &serde_json::Value,
    bearer: Option<&str>,
) -> Result<(), ControllerError> {
    let url = format!("{base_url}{path}");
    let mut req = http.put(&url).json(body);
    if let Some(token) = bearer {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(ControllerError::Validation(format!(
            "registry sync {url} → {status}: {text}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------

// Reconcile: ImageVerificationPolicy
// ---------------------------------------------------------------------------

pub(crate) async fn reconcile_image_verification_policy(
    policy: Arc<ImageVerificationPolicy>,
    ctx: Arc<Ctx>,
) -> Result<Action, ControllerError> {
    let name = policy.name_any();
    let ns = policy.namespace().unwrap_or_default();
    info!(%name, %ns, "reconciling ImageVerificationPolicy");

    let tenants: Api<Tenant> = Api::all(ctx.client.clone());
    if tenants.get_opt(&policy.spec.tenant_ref).await?.is_none() {
        return Err(ControllerError::Validation(format!(
            "referenced Tenant '{}' not found",
            policy.spec.tenant_ref
        )));
    }

    let on_violation = match policy.spec.on_violation.as_str() {
        "warn" | "log" | "block" => policy.spec.on_violation.clone(),
        other => {
            return Err(ControllerError::Validation(format!(
                "onViolation must be block|warn|log, got '{other}'"
            )));
        }
    };

    let mut trusted_signers = Vec::new();
    for s in &policy.spec.trusted_signers {
        match s.kind.as_str() {
            "Key" => {
                let key_ref = s.key_ref.clone().ok_or_else(|| {
                    ControllerError::Validation("Key signer requires keyRef".into())
                })?;
                trusted_signers.push(serde_json::json!({
                    "key": { "key_ref": key_ref, "identity_name": s.identity_name }
                }));
            }
            "Keyless" => {
                trusted_signers.push(serde_json::json!({
                    "keyless": {
                        "issuer": s.issuer.clone().unwrap_or_default(),
                        "subject_pattern": s.subject_pattern.clone().unwrap_or_default()
                    }
                }));
            }
            other => {
                return Err(ControllerError::Validation(format!(
                    "trustedSigner.kind must be Key or Keyless, got '{other}'"
                )));
            }
        }
    }

    let uid = policy.uid().unwrap_or_default();
    let body = serde_json::json!({
        "id": uid.to_string(),
        "enabled": true,
        "on_violation": on_violation,
        "spec": {
            "scope": {
                "projects": policy.spec.scope.projects,
                "repositories": policy.spec.scope.repositories,
            },
            "required": policy.spec.required,
            "trusted_signers": trusted_signers,
            "on_violation": on_violation,
        }
    });

    if let Some(ref registry_url) = ctx.registry_service_url {
        if let Err(e) = sync_to_registry(
            &ctx.http,
            registry_url,
            &format!(
                "/v2/_signing/policies/{}/{}",
                policy.spec.tenant_ref, name
            ),
            &body,
            ctx.registry_admin_token.as_deref(),
        )
        .await
        {
            warn!(%name, error = %e, "failed to sync ImageVerificationPolicy; will retry");
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
    } else {
        info!(
            %name,
            "REGISTRY_SERVICE_URL unset; ImageVerificationPolicy validated only"
        );
    }

    let api: Api<ImageVerificationPolicy> = Api::namespaced(ctx.client.clone(), &ns);
    let now = Utc::now().to_rfc3339();
    let status = serde_json::json!({
        "phase": "Active",
        "conditions": [{
            "type": "Ready",
            "status": "True",
            "lastTransitionTime": now,
            "reason": "Reconciled",
            "message": "ImageVerificationPolicy reconciled",
        }]
    });
    update_status(&api, &name, status).await?;

    let msg = format!("ImageVerificationPolicy {name} reconciled");
    if let Err(e) = publish_event(
        &ctx.client,
        &EventInfo {
            namespace: Some(&ns),
            regarding_kind: "ImageVerificationPolicy",
            regarding_name: &name,
            regarding_uid: &uid,
            reason: "Reconciled",
            message: &msg,
            event_type: "Normal",
        },
    )
    .await
    {
        warn!(%name, error = %e, "failed to publish event");
    }

    Ok(Action::requeue(Duration::from_secs(300)))
}

pub(crate) fn image_verification_policy_error_policy(
    policy: Arc<ImageVerificationPolicy>,
    error: &ControllerError,
    _ctx: Arc<Ctx>,
) -> Action {
    let name = policy.name_any();
    error!(%name, %error, "image-verification-policy reconciliation failed");
    Action::requeue(Duration::from_secs(60))
}

// ---------------------------------------------------------------------------
// Reconcile: RebuildSubscription
// ---------------------------------------------------------------------------

async fn read_secret_key(
    client: &Client,
    ns: &str,
    secret_name: &str,
    key: &str,
) -> Result<String, ControllerError> {
    let secrets: Api<k8s_openapi::api::core::v1::Secret> = Api::namespaced(client.clone(), ns);
    let secret = secrets.get(secret_name).await?;
    let data = secret.data.unwrap_or_default();
    let bytes = data.get(key).ok_or_else(|| {
        ControllerError::Validation(format!("secret {secret_name} missing key '{key}'"))
    })?;
    Ok(String::from_utf8_lossy(&bytes.0).into_owned())
}

async fn build_rebuild_emitter_json(
    sub: &RebuildSubscription,
    ctx: &Ctx,
    ns: &str,
) -> Result<serde_json::Value, ControllerError> {
    let emitter = &sub.spec.emitter;
    match emitter.type_.as_str() {
        "github-dispatch" => {
            let repo = emitter
                .repo
                .clone()
                .ok_or_else(|| ControllerError::Validation("emitter.repo required".into()))?;
            let mut token: Option<String> = None;
            if let Some(ref secret_name) = emitter.token_secret_ref {
                token = Some(read_secret_key(&ctx.client, ns, secret_name, "token").await?);
            }
            Ok(serde_json::json!({
                "type": "github-dispatch",
                "repo": repo,
                "event_type": emitter.event_type.clone()
                    .unwrap_or_else(|| "rebuild-on-cve".into()),
                "workflow": emitter.workflow,
                "token": token,
                "api_base": emitter.api_base,
            }))
        }
        "gitlab-trigger" => {
            let project = emitter
                .project
                .clone()
                .ok_or_else(|| ControllerError::Validation("emitter.project required".into()))?;
            let mut trigger_token: Option<String> = None;
            if let Some(ref secret_name) = emitter.trigger_token_secret_ref {
                trigger_token =
                    Some(read_secret_key(&ctx.client, ns, secret_name, "token").await?);
            }
            Ok(serde_json::json!({
                "type": "gitlab-trigger",
                "project": project,
                "ref": emitter.git_ref.clone().unwrap_or_else(|| "main".into()),
                "trigger_token": trigger_token,
                "api_base": emitter.api_base,
            }))
        }
        "webhook" => {
            let url = emitter
                .url
                .clone()
                .ok_or_else(|| ControllerError::Validation("emitter.url required".into()))?;
            let mut hmac_secret: Option<String> = None;
            if let Some(ref secret_name) = emitter.hmac_secret_ref {
                hmac_secret =
                    Some(read_secret_key(&ctx.client, ns, secret_name, "secret").await?);
            }
            Ok(serde_json::json!({
                "type": "webhook",
                "url": url,
                "hmac_secret": hmac_secret,
                "header_name": emitter.header_name,
            }))
        }
        "tekton" => {
            let url = emitter
                .url
                .clone()
                .ok_or_else(|| ControllerError::Validation("emitter.url required".into()))?;
            let mut auth_header_value: Option<String> = None;
            if let Some(ref secret_name) = emitter.auth_secret_ref {
                auth_header_value =
                    Some(read_secret_key(&ctx.client, ns, secret_name, "token").await?);
            }
            Ok(serde_json::json!({
                "type": "tekton",
                "url": url,
                "auth_header_name": emitter.auth_header_name,
                "auth_header_value": auth_header_value,
            }))
        }
        other => Err(ControllerError::Validation(format!(
            "emitter.type must be github-dispatch|gitlab-trigger|webhook|tekton (got '{other}')"
        ))),
    }
}

pub(crate) async fn reconcile_rebuild_subscription(
    sub: Arc<RebuildSubscription>,
    ctx: Arc<Ctx>,
) -> Result<Action, ControllerError> {
    let name = sub.name_any();
    let ns = sub.namespace().unwrap_or_default();
    info!(%name, %ns, "reconciling RebuildSubscription");

    let tenants: Api<Tenant> = Api::all(ctx.client.clone());
    if tenants.get_opt(&sub.spec.tenant_ref).await?.is_none() {
        return Err(ControllerError::Validation(format!(
            "referenced Tenant '{}' not found",
            sub.spec.tenant_ref
        )));
    }

    let emitter_json = build_rebuild_emitter_json(&sub, &ctx, &ns).await?;

    let uid = sub.uid().unwrap_or_default();
    let body = serde_json::json!({
        "id": uid.to_string(),
        "enabled": true,
        "spec": {
            "watch": {
                "bases": sub.spec.watch.bases,
                "descendants": sub.spec.watch.descendants,
            },
            "triggers": {
                "on_cve_fix": sub.spec.triggers.on_cve_fix,
                "on_base_push": sub.spec.triggers.on_base_push,
                "min_severity_fixed": sub.spec.triggers.min_severity_fixed,
            },
            "emitter": emitter_json,
            "rate_limit": {
                "per_downstream_per_day": sub.spec.rate_limit.per_downstream_per_day,
            },
        }
    });

    if let Some(ref registry_url) = ctx.registry_service_url {
        if let Err(e) = sync_to_registry(
            &ctx.http,
            registry_url,
            &format!(
                "/v2/_rebuild/subscriptions/{}/{}",
                sub.spec.tenant_ref, name
            ),
            &body,
            ctx.registry_admin_token.as_deref(),
        )
        .await
        {
            warn!(%name, error = %e, "failed to sync RebuildSubscription; will retry");
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
    } else {
        info!(%name, "REGISTRY_SERVICE_URL unset; RebuildSubscription validated only");
    }

    let api: Api<RebuildSubscription> = Api::namespaced(ctx.client.clone(), &ns);
    let now = Utc::now().to_rfc3339();
    let status = serde_json::json!({
        "phase": "Active",
        "conditions": [{
            "type": "Ready",
            "status": "True",
            "lastTransitionTime": now,
            "reason": "Reconciled",
            "message": "RebuildSubscription reconciled",
        }]
    });
    update_status(&api, &name, status).await?;
    Ok(Action::requeue(Duration::from_secs(300)))
}

pub(crate) fn rebuild_subscription_error_policy(
    sub: Arc<RebuildSubscription>,
    error: &ControllerError,
    _ctx: Arc<Ctx>,
) -> Action {
    let name = sub.name_any();
    error!(%name, %error, "rebuild-subscription reconciliation failed");
    Action::requeue(Duration::from_secs(60))
}

pub(crate) async fn reconcile_admission_policy(
    policy: Arc<AdmissionPolicy>,
    ctx: Arc<Ctx>,
) -> Result<Action, ControllerError> {
    let name = policy.name_any();
    let ns = policy.namespace().unwrap_or_default();
    info!(%name, %ns, "reconciling AdmissionPolicy");

    let tenants: Api<Tenant> = Api::all(ctx.client.clone());
    if tenants.get_opt(&policy.spec.tenant_ref).await?.is_none() {
        return Err(ControllerError::Validation(format!(
            "referenced Tenant '{}' not found",
            policy.spec.tenant_ref
        )));
    }
    if !matches!(
        policy.spec.on_unknown.as_str(),
        "block" | "scan" | "allow"
    ) {
        return Err(ControllerError::Validation(format!(
            "onUnknown must be block|scan|allow, got '{}'",
            policy.spec.on_unknown
        )));
    }
    if !matches!(policy.spec.on_timeout.as_str(), "block" | "warn" | "allow") {
        return Err(ControllerError::Validation(format!(
            "onTimeout must be block|warn|allow, got '{}'",
            policy.spec.on_timeout
        )));
    }

    let uid = policy.uid().unwrap_or_default();
    let body = serde_json::json!({
        "id": uid.to_string(),
        "enabled": true,
        "spec": {
            "scope": {
                "projects": policy.spec.scope.projects,
                "repositories": policy.spec.scope.repositories,
            },
            "signature_required": policy.spec.signature_required,
            "severity_threshold": {
                "block": {
                    "critical": policy.spec.severity_threshold.block.critical,
                    "high": policy.spec.severity_threshold.block.high,
                    "medium": policy.spec.severity_threshold.block.medium,
                    "low": policy.spec.severity_threshold.block.low,
                },
                "warn": {
                    "critical": policy.spec.severity_threshold.warn.critical,
                    "high": policy.spec.severity_threshold.warn.high,
                    "medium": policy.spec.severity_threshold.warn.medium,
                    "low": policy.spec.severity_threshold.warn.low,
                },
            },
            "on_unknown": policy.spec.on_unknown,
            "on_timeout": policy.spec.on_timeout,
            "scan_wait_secs": policy.spec.scan_wait_secs,
        }
    });

    if let Some(ref registry_url) = ctx.registry_service_url {
        if let Err(e) = sync_to_registry(
            &ctx.http,
            registry_url,
            &format!(
                "/v2/_admit/policies/{}/{}",
                policy.spec.tenant_ref, name
            ),
            &body,
            ctx.registry_admin_token.as_deref(),
        )
        .await
        {
            warn!(%name, error = %e, "failed to sync AdmissionPolicy; will retry");
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
    } else {
        info!(%name, "REGISTRY_SERVICE_URL unset; AdmissionPolicy validated only");
    }

    let api: Api<AdmissionPolicy> = Api::namespaced(ctx.client.clone(), &ns);
    let now = Utc::now().to_rfc3339();
    let status = serde_json::json!({
        "phase": "Active",
        "conditions": [{
            "type": "Ready",
            "status": "True",
            "lastTransitionTime": now,
            "reason": "Reconciled",
            "message": "AdmissionPolicy reconciled",
        }]
    });
    update_status(&api, &name, status).await?;
    Ok(Action::requeue(Duration::from_secs(300)))
}

pub(crate) fn admission_policy_error_policy(
    policy: Arc<AdmissionPolicy>,
    error: &ControllerError,
    _ctx: Arc<Ctx>,
) -> Action {
    let name = policy.name_any();
    error!(%name, %error, "admission-policy reconciliation failed");
    Action::requeue(Duration::from_secs(60))
}
