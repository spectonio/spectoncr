//! Tenant, Project, AccessPolicy and TokenPolicy: types and reconcilers.
//!
//! The installed CRDs (`deploy/helm/spectoncr/templates/crds/*.yaml`) are the
//! contract: the API server validates against them and prunes any field they
//! don't declare. The types here mirror those schemas field for field
//! (camelCase), and `tests::rust_types_match_installed_crds` fails the build
//! if they drift apart again.
//!
//! Each reconciler validates references, pushes the spec to the auth service
//! and reports the outcome truthfully: a non-2xx answer is a `Synced=False`
//! condition, never a success.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{CustomResource, Resource, ResourceExt};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{ControllerError, Ctx, EventInfo, publish_event};

const SYNCED_REQUEUE: Duration = Duration::from_secs(300);
const UNSYNCED_REQUEUE: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    #[serde(rename = "type")]
    pub type_: String,
    /// "True", "False" or "Unknown".
    pub status: String,
    pub last_transition_time: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ---------------------------------------------------------------------------
// Tenant
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TenantQuotas {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_bytes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_repositories: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tags_per_repository: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_rate_limit: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_rate_limit: Option<i32>,
}

#[derive(CustomResource, Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "spectoncr.io",
    version = "v1alpha1",
    kind = "Tenant",
    plural = "tenants",
    status = "TenantStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct TenantSpec {
    pub display_name: String,
    pub admin_email: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_subject: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quotas: Option<TenantQuotas>,
    /// One of filesystem, s3, gcs, azure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_backend_override: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ip_cidrs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TenantStatus {
    /// One of Pending, Active, Suspended, Deleting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_count: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_used_bytes: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

// ---------------------------------------------------------------------------
// Project
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VulnerabilityScanning {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub block_on_critical: bool,
    #[serde(default)]
    pub block_on_high: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RetentionPolicy {
    #[serde(default)]
    pub enabled: bool,
    /// e.g. "30d", "12w", "6m", "1y".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tag_age: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_last_n: Option<i32>,
    #[serde(default = "default_true")]
    pub keep_semver: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectQuotas {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_repositories: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tags_per_repository: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_bytes: Option<i64>,
}

#[derive(CustomResource, Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "spectoncr.io",
    version = "v1alpha1",
    kind = "Project",
    plural = "projects",
    status = "ProjectStatus",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSpec {
    pub tenant_ref: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// One of private, internal, public.
    #[serde(default = "default_visibility")]
    pub visibility: String,
    #[serde(default)]
    pub immutable_tags: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vulnerability_scanning: Option<VulnerabilityScanning>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_policy: Option<RetentionPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quotas: Option<ProjectQuotas>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels: Option<BTreeMap<String, String>>,
}

fn default_visibility() -> String {
    "private".to_string()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectStatus {
    /// One of Pending, Active, Suspended, Deleting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_count: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_used_bytes: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

// ---------------------------------------------------------------------------
// AccessPolicy
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Subject {
    /// One of User, Group, ServiceAccount, Anonymous.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_value: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyResource {
    /// One of repository, tag, manifest, blob, project.
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default = "default_name_pattern")]
    pub name_pattern: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_ref: Option<String>,
}

fn default_name_pattern() -> String {
    "*".to_string()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PolicyCondition {
    /// One of SourceIP, TimeWindow, MFARequired.
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_cidrs: Option<Vec<String>>,
    /// "HH:MM".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window_start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window_end: Option<String>,
}

#[derive(CustomResource, Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "spectoncr.io",
    version = "v1alpha1",
    kind = "AccessPolicy",
    plural = "accesspolicies",
    status = "AccessPolicyStatus",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct AccessPolicySpec {
    pub tenant_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub priority: i32,
    /// Allow or Deny.
    pub effect: String,
    pub subjects: Vec<Subject>,
    pub resources: Vec<PolicyResource>,
    /// Any of pull, push, delete, list, admin, *.
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<PolicyCondition>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccessPolicyStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_evaluated: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

// ---------------------------------------------------------------------------
// TokenPolicy
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Rotation {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_period: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Revocation {
    #[serde(default = "default_true")]
    pub revoke_on_password_change: bool,
    #[serde(default = "default_true")]
    pub revoke_on_suspension: bool,
    #[serde(default)]
    pub revoke_on_policy_change: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IpRestrictions {
    #[serde(default)]
    pub bind_to_ip: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_cidrs: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RobotAccounts {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_per_project: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_token_lifetime: Option<String>,
}

#[derive(CustomResource, Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[kube(
    group = "spectoncr.io",
    version = "v1alpha1",
    kind = "TokenPolicy",
    plural = "tokenpolicies",
    status = "TokenPolicyStatus",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct TokenPolicySpec {
    pub tenant_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Duration like "1h"; the CRD defaults it to "1h".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_token_lifetime: Option<String>,
    /// Duration like "24h"; the CRD defaults it to "24h".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_refresh_token_lifetime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_sessions: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<Rotation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<Revocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_restrictions: Option<IpRestrictions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub robot_accounts: Option<RobotAccounts>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TokenPolicyStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_token_count: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rotation_time: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Result of pushing a spec to the auth service.
#[derive(Debug, PartialEq, Eq)]
pub enum SyncOutcome {
    Synced,
    /// The auth service answered with a non-2xx status.
    Rejected {
        status: u16,
        body: String,
    },
    Unreachable(String),
}

impl SyncOutcome {
    fn ok(&self) -> bool {
        *self == SyncOutcome::Synced
    }

    /// (reason, message) for the Synced condition.
    fn describe(&self, path: &str) -> (&'static str, String) {
        match self {
            SyncOutcome::Synced => ("Synced", format!("PUT {path} succeeded")),
            SyncOutcome::Rejected { status, body } => {
                let body: String = body.chars().take(200).collect();
                (
                    "AuthServiceRejected",
                    format!("PUT {path} returned {status}: {body}"),
                )
            }
            SyncOutcome::Unreachable(e) => ("AuthServiceUnreachable", format!("PUT {path}: {e}")),
        }
    }
}

async fn sync_to_auth_service(ctx: &Ctx, path: &str, body: &impl Serialize) -> SyncOutcome {
    let url = format!("{}{path}", ctx.auth_service_url);
    match ctx.http.put(&url).json(body).send().await {
        Ok(resp) if resp.status().is_success() => SyncOutcome::Synced,
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            warn!(%url, status, %body, "auth service rejected sync");
            SyncOutcome::Rejected { status, body }
        }
        Err(e) => {
            warn!(%url, error = %e, "auth service unreachable");
            SyncOutcome::Unreachable(e.to_string())
        }
    }
}

/// Set a condition, keeping `lastTransitionTime` when the status is
/// unchanged. Returns whether the status flipped.
pub fn set_condition(
    conditions: &mut Vec<Condition>,
    type_: &str,
    ok: bool,
    reason: &str,
    message: impl Into<String>,
) -> bool {
    let status = if ok { "True" } else { "False" };
    let message = Some(message.into());
    match conditions.iter_mut().find(|c| c.type_ == type_) {
        Some(c) => {
            let flipped = c.status != status;
            if flipped {
                c.status = status.into();
                c.last_transition_time = Utc::now().to_rfc3339();
            }
            c.reason = Some(reason.into());
            c.message = message;
            flipped
        }
        None => {
            conditions.push(Condition {
                type_: type_.into(),
                status: status.into(),
                last_transition_time: Utc::now().to_rfc3339(),
                reason: Some(reason.into()),
                message,
            });
            true
        }
    }
}

/// Merge-patch the status subresource, but only when it changed: every
/// status write is a watch event that triggers another reconcile.
async fn write_status<K, S>(
    api: &Api<K>,
    name: &str,
    prev: &S,
    next: &S,
) -> Result<(), ControllerError>
where
    K: Resource + Clone + Debug + DeserializeOwned + Serialize,
    S: Serialize + PartialEq,
{
    if prev == next {
        return Ok(());
    }
    let patch = serde_json::json!({ "status": next });
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

struct Transition<'a> {
    kind: &'a str,
    name: &'a str,
    namespace: Option<&'a str>,
    uid: String,
    ok: bool,
    reason: &'a str,
    message: &'a str,
}

/// Publish an Event, but only when the Ready state flipped, so a steady
/// resource doesn't emit one every resync.
async fn announce(ctx: &Ctx, t: Transition<'_>) {
    if let Err(e) = publish_event(
        &ctx.client,
        &EventInfo {
            namespace: t.namespace,
            regarding_kind: t.kind,
            regarding_name: t.name,
            regarding_uid: &t.uid,
            reason: t.reason,
            message: t.message,
            event_type: if t.ok { "Normal" } else { "Warning" },
        },
    )
    .await
    {
        warn!(name = %t.name, error = %e, "failed to publish event");
    }
}

fn requeue(ok: bool) -> Action {
    Action::requeue(if ok { SYNCED_REQUEUE } else { UNSYNCED_REQUEUE })
}

async fn tenant_exists(ctx: &Ctx, tenant_ref: &str) -> Result<bool, ControllerError> {
    let tenants: Api<Tenant> = Api::all(ctx.client.clone());
    Ok(tenants.get_opt(tenant_ref).await?.is_some())
}

// ---------------------------------------------------------------------------
// Reconcilers
// ---------------------------------------------------------------------------

pub async fn reconcile_tenant(
    tenant: Arc<Tenant>,
    ctx: Arc<Ctx>,
) -> Result<Action, ControllerError> {
    let name = tenant.name_any();
    info!(%name, "reconciling Tenant");

    let path = format!("/api/v1/tenants/{name}");
    let outcome = sync_to_auth_service(&ctx, &path, &tenant.spec).await;
    let (reason, message) = outcome.describe(&path);

    let prev = tenant.status.clone().unwrap_or_default();
    let mut next = prev.clone();
    next.observed_generation = tenant.metadata.generation;
    next.phase = Some(
        match (tenant.spec.enabled, outcome.ok()) {
            (false, _) => "Suspended",
            (true, true) => "Active",
            (true, false) => "Pending",
        }
        .into(),
    );
    set_condition(
        &mut next.conditions,
        "Synced",
        outcome.ok(),
        reason,
        &message,
    );
    let flipped = set_condition(
        &mut next.conditions,
        "Ready",
        outcome.ok(),
        reason,
        &message,
    );

    // lastReconcileTime alone must not count as a change (see write_status).
    let mut compare = next.clone();
    compare.last_reconcile_time = prev.last_reconcile_time.clone();
    if compare != prev {
        next.last_reconcile_time = Some(Utc::now().to_rfc3339());
    }
    let api: Api<Tenant> = Api::all(ctx.client.clone());
    write_status(&api, &name, &prev, &next).await?;

    if flipped {
        announce(
            &ctx,
            Transition {
                kind: "Tenant",
                name: &name,
                namespace: None,
                uid: tenant.uid().unwrap_or_default(),
                ok: outcome.ok(),
                reason,
                message: &message,
            },
        )
        .await;
    }
    Ok(requeue(outcome.ok()))
}

pub async fn reconcile_project(
    project: Arc<Project>,
    ctx: Arc<Ctx>,
) -> Result<Action, ControllerError> {
    let name = project.name_any();
    let ns = project.namespace().unwrap_or_default();
    let tenant_ref = &project.spec.tenant_ref;
    info!(%name, %ns, "reconciling Project");

    let prev = project.status.clone().unwrap_or_default();
    let mut next = prev.clone();
    next.observed_generation = project.metadata.generation;

    let (ok, reason, message) = if !tenant_exists(&ctx, tenant_ref).await? {
        (
            false,
            "TenantNotFound",
            format!("Tenant '{tenant_ref}' not found"),
        )
    } else {
        let path = format!("/api/v1/tenants/{tenant_ref}/projects/{name}");
        let outcome = sync_to_auth_service(&ctx, &path, &project.spec).await;
        let (reason, message) = outcome.describe(&path);
        set_condition(
            &mut next.conditions,
            "Synced",
            outcome.ok(),
            reason,
            &message,
        );
        (outcome.ok(), reason, message)
    };
    next.phase = Some(if ok { "Active" } else { "Pending" }.into());
    let flipped = set_condition(&mut next.conditions, "Ready", ok, reason, &message);

    let api: Api<Project> = Api::namespaced(ctx.client.clone(), &ns);
    write_status(&api, &name, &prev, &next).await?;
    if flipped {
        announce(
            &ctx,
            Transition {
                kind: "Project",
                name: &name,
                namespace: Some(&ns),
                uid: project.uid().unwrap_or_default(),
                ok,
                reason,
                message: &message,
            },
        )
        .await;
    }
    Ok(requeue(ok))
}

pub async fn reconcile_access_policy(
    policy: Arc<AccessPolicy>,
    ctx: Arc<Ctx>,
) -> Result<Action, ControllerError> {
    let name = policy.name_any();
    let ns = policy.namespace().unwrap_or_default();
    let tenant_ref = &policy.spec.tenant_ref;
    info!(%name, %ns, "reconciling AccessPolicy");

    let prev = policy.status.clone().unwrap_or_default();
    let mut next = prev.clone();
    next.observed_generation = policy.metadata.generation;

    // References are validated here; field shapes are enforced by the CRD.
    let mut invalid = None;
    if !tenant_exists(&ctx, tenant_ref).await? {
        invalid = Some(("TenantNotFound", format!("Tenant '{tenant_ref}' not found")));
    } else {
        let projects: Api<Project> = Api::namespaced(ctx.client.clone(), &ns);
        for project_ref in policy
            .spec
            .resources
            .iter()
            .filter_map(|r| r.project_ref.as_deref())
        {
            if projects.get_opt(project_ref).await?.is_none() {
                invalid = Some((
                    "ProjectNotFound",
                    format!("Project '{project_ref}' not found in namespace {ns}"),
                ));
                break;
            }
        }
    }
    next.valid = Some(invalid.is_none());

    let (ok, reason, message) = match invalid {
        Some((reason, message)) => (false, reason, message),
        None => {
            let path = format!("/api/v1/tenants/{tenant_ref}/access-policies/{name}");
            let outcome = sync_to_auth_service(&ctx, &path, &policy.spec).await;
            let (reason, message) = outcome.describe(&path);
            set_condition(
                &mut next.conditions,
                "Synced",
                outcome.ok(),
                reason,
                &message,
            );
            (outcome.ok(), reason, message)
        }
    };
    let flipped = set_condition(&mut next.conditions, "Ready", ok, reason, &message);

    let api: Api<AccessPolicy> = Api::namespaced(ctx.client.clone(), &ns);
    write_status(&api, &name, &prev, &next).await?;
    if flipped {
        announce(
            &ctx,
            Transition {
                kind: "AccessPolicy",
                name: &name,
                namespace: Some(&ns),
                uid: policy.uid().unwrap_or_default(),
                ok,
                reason,
                message: &message,
            },
        )
        .await;
    }
    Ok(requeue(ok))
}

pub async fn reconcile_token_policy(
    policy: Arc<TokenPolicy>,
    ctx: Arc<Ctx>,
) -> Result<Action, ControllerError> {
    let name = policy.name_any();
    let ns = policy.namespace().unwrap_or_default();
    let tenant_ref = &policy.spec.tenant_ref;
    info!(%name, %ns, "reconciling TokenPolicy");

    let prev = policy.status.clone().unwrap_or_default();
    let mut next = prev.clone();
    next.observed_generation = policy.metadata.generation;

    let (ok, reason, message) = if !tenant_exists(&ctx, tenant_ref).await? {
        (
            false,
            "TenantNotFound",
            format!("Tenant '{tenant_ref}' not found"),
        )
    } else {
        let path = format!("/api/v1/tenants/{tenant_ref}/token-policies/{name}");
        let outcome = sync_to_auth_service(&ctx, &path, &policy.spec).await;
        let (reason, message) = outcome.describe(&path);
        set_condition(
            &mut next.conditions,
            "Synced",
            outcome.ok(),
            reason,
            &message,
        );
        (outcome.ok(), reason, message)
    };
    let flipped = set_condition(&mut next.conditions, "Ready", ok, reason, &message);

    let api: Api<TokenPolicy> = Api::namespaced(ctx.client.clone(), &ns);
    write_status(&api, &name, &prev, &next).await?;
    if flipped {
        announce(
            &ctx,
            Transition {
                kind: "TokenPolicy",
                name: &name,
                namespace: Some(&ns),
                uid: policy.uid().unwrap_or_default(),
                ok,
                reason,
                message: &message,
            },
        )
        .await;
    }
    Ok(requeue(ok))
}

pub fn error_policy<K: ResourceExt>(
    obj: Arc<K>,
    error: &ControllerError,
    _ctx: Arc<Ctx>,
) -> Action {
    error!(name = %obj.name_any(), %error, "tenancy reconciliation failed");
    Action::requeue(Duration::from_secs(60))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;
    use std::collections::BTreeSet;

    /// Load an installed CRD from the chart, dropping the Helm template
    /// directives so it parses as plain YAML.
    fn chart_crd(file: &str) -> serde_json::Value {
        let path = format!(
            "{}/../../deploy/helm/spectoncr/templates/crds/{file}",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let stripped: String = raw
            .lines()
            .filter(|l| !l.trim_start().starts_with("{{"))
            .collect::<Vec<_>>()
            .join("\n");
        serde_yaml::from_str(&stripped).unwrap()
    }

    fn schema(crd: &serde_json::Value) -> &serde_json::Value {
        &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]
    }

    /// Every property path with its JSON type, plus which paths are required.
    fn shape(
        s: &serde_json::Value,
        prefix: &str,
        types: &mut BTreeSet<String>,
        required: &mut BTreeSet<String>,
    ) {
        if let Some(req) = s["required"].as_array() {
            for r in req {
                required.insert(format!("{prefix}{}", r.as_str().unwrap()));
            }
        }
        let Some(props) = s["properties"].as_object() else {
            return;
        };
        for (key, val) in props {
            // Standard object metadata isn't part of our contract.
            if prefix.is_empty() && matches!(key.as_str(), "apiVersion" | "kind" | "metadata") {
                continue;
            }
            let path = format!("{prefix}{key}");
            let ty = val["type"].as_str().unwrap_or("?");
            types.insert(format!("{path}: {ty}"));
            match ty {
                "object" => shape(val, &format!("{path}."), types, required),
                "array" => shape(&val["items"], &format!("{path}[]."), types, required),
                _ => {}
            }
        }
    }

    fn assert_matches(file: &str, generated: serde_json::Value) {
        let installed = chart_crd(file);
        let (mut want_t, mut want_r) = (BTreeSet::new(), BTreeSet::new());
        let (mut got_t, mut got_r) = (BTreeSet::new(), BTreeSet::new());
        shape(schema(&installed), "", &mut want_t, &mut want_r);
        shape(schema(&generated), "", &mut got_t, &mut got_r);
        let missing: Vec<_> = want_t.difference(&got_t).collect();
        let extra: Vec<_> = got_t.difference(&want_t).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{file}: Rust types drifted from the installed CRD\n  \
             in CRD, not in Rust: {missing:?}\n  in Rust, not in CRD: {extra:?}"
        );
        // Rust must not require what the CRD makes optional (it would fail
        // to deserialize), and must require what the CRD requires.
        assert_eq!(want_r, got_r, "{file}: required fields differ");
        assert_eq!(
            installed["spec"]["scope"], generated["spec"]["scope"],
            "{file}: scope differs"
        );
    }

    #[test]
    fn rust_types_match_installed_crds() {
        assert_matches("tenant.yaml", serde_json::to_value(Tenant::crd()).unwrap());
        assert_matches(
            "project.yaml",
            serde_json::to_value(Project::crd()).unwrap(),
        );
        assert_matches(
            "accesspolicy.yaml",
            serde_json::to_value(AccessPolicy::crd()).unwrap(),
        );
        assert_matches(
            "tokenpolicy.yaml",
            serde_json::to_value(TokenPolicy::crd()).unwrap(),
        );
    }

    #[test]
    fn documented_tenant_deserializes_and_round_trips() {
        let tenant: TenantSpec = serde_yaml::from_str(
            "displayName: My Organization\n\
             adminEmail: admin@my-org.com\n\
             quotas:\n  storageBytes: 107374182400\n  maxRepositories: 500\n  \
             pullRateLimit: 1000\n  pushRateLimit: 500\n",
        )
        .unwrap();
        assert!(tenant.enabled, "enabled defaults to true like the CRD");
        assert_eq!(
            tenant.quotas.as_ref().unwrap().storage_bytes,
            Some(107_374_182_400)
        );
        let json = serde_json::to_value(&tenant).unwrap();
        assert_eq!(json["displayName"], "My Organization");
        assert_eq!(json["quotas"]["pullRateLimit"], 1000);
        assert!(json.get("display_name").is_none());
    }

    #[test]
    fn access_policy_deserializes_crd_shape() {
        let spec: AccessPolicySpec = serde_yaml::from_str(
            "tenantRef: acme\n\
             effect: Allow\n\
             subjects:\n  - kind: Group\n    name: developers\n\
             resources:\n  - type: repository\n    projectRef: web\n\
             actions: [pull, push]\n",
        )
        .unwrap();
        assert_eq!(spec.resources[0].name_pattern, "*");
        assert_eq!(spec.resources[0].project_ref.as_deref(), Some("web"));
        assert_eq!(spec.priority, 0);
    }

    #[test]
    fn sync_outcome_describes_failures() {
        let (reason, msg) = SyncOutcome::Rejected {
            status: 404,
            body: "not found".into(),
        }
        .describe("/api/v1/tenants/acme");
        assert_eq!(reason, "AuthServiceRejected");
        assert!(msg.contains("404"));
        assert!(!SyncOutcome::Unreachable("x".into()).ok());
        assert!(SyncOutcome::Synced.ok());
    }

    #[test]
    fn set_condition_reports_flips_only() {
        let mut c = Vec::new();
        assert!(set_condition(&mut c, "Ready", false, "Pending", "a"));
        let t = c[0].last_transition_time.clone();
        assert!(!set_condition(&mut c, "Ready", false, "Pending", "b"));
        assert_eq!(c[0].last_transition_time, t);
        assert!(set_condition(&mut c, "Ready", true, "Synced", "c"));
    }
}
