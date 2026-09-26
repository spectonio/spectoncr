//! Reconcile loop for `SpectonRegistry`.

use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::batch::v1::{CronJob, Job};
use k8s_openapi::api::core::v1::{ConfigMap, Service};
use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use kube::runtime::controller::Action;
use kube::{Client, Resource, ResourceExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::{error, info, warn};

use super::resources::{self, Component, MANAGER};
use super::{
    BackupStatus, ComponentStatus, OperatorCondition, SpectonRegistry, SpectonRegistryStatus, image,
};
use crate::{EventInfo, publish_event};

const PROGRESS_REQUEUE: Duration = Duration::from_secs(10);
const STEADY_REQUEUE: Duration = Duration::from_secs(300);

pub struct OperatorCtx {
    pub client: Client,
    pub http: reqwest::Client,
}

#[derive(Debug, thiserror::Error)]
pub enum OperatorError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("{0}")]
    Invalid(String),
}

pub mod phase {
    pub const PENDING: &str = "Pending";
    pub const PROGRESSING: &str = "Progressing";
    pub const BACKING_UP: &str = "BackingUp";
    pub const UPGRADING: &str = "Upgrading";
    pub const READY: &str = "Ready";
    pub const DEGRADED: &str = "Degraded";
    pub const PAUSED: &str = "Paused";
}

/// Which image each Deployment should run on this pass.
#[derive(Debug, PartialEq, Eq)]
pub struct RolloutPlan {
    pub auth_image: String,
    pub registry_image: String,
    /// An image change is in flight (as opposed to install or config drift).
    pub upgrading: bool,
    /// This pass moves auth off its old image, i.e. the upgrade starts now.
    pub starts_upgrade: bool,
}

/// Decide the image for each component. Upgrades go auth first, then the
/// registry once auth has fully rolled out: auth is stateless and backwards
/// compatible with an older registry, while the registry runs the schema
/// migrations on start, so it goes last.
pub fn plan_rollout(
    target: &str,
    live_auth: Option<&str>,
    auth_rolled_out: bool,
    live_registry: Option<&str>,
) -> RolloutPlan {
    let registry_now = live_registry.unwrap_or(target).to_string();
    match live_auth {
        // Fresh install (or auth deleted): nothing to sequence against.
        None => RolloutPlan {
            auth_image: target.into(),
            registry_image: target.into(),
            upgrading: false,
            starts_upgrade: false,
        },
        Some(auth) if auth != target => RolloutPlan {
            auth_image: target.into(),
            registry_image: registry_now,
            upgrading: true,
            starts_upgrade: true,
        },
        Some(_) if !auth_rolled_out => RolloutPlan {
            auth_image: target.into(),
            upgrading: registry_now != target,
            registry_image: registry_now,
            starts_upgrade: false,
        },
        Some(_) => RolloutPlan {
            auth_image: target.into(),
            registry_image: target.into(),
            upgrading: live_registry.is_some_and(|r| r != target),
            starts_upgrade: false,
        },
    }
}

/// A Deployment has finished rolling out when the controller has seen the
/// latest spec and every replica is updated and available.
pub fn rolled_out(d: &Deployment) -> bool {
    let desired = d.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
    let Some(status) = &d.status else {
        return false;
    };
    status.observed_generation >= d.metadata.generation
        && status.updated_replicas.unwrap_or(0) == desired
        && status.available_replicas.unwrap_or(0) == desired
        && status.replicas.unwrap_or(0) == desired
}

fn deadline_exceeded(d: &Deployment) -> bool {
    d.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .is_some_and(|conds| {
            conds.iter().any(|c| {
                c.type_ == "Progressing"
                    && c.status == "False"
                    && c.reason.as_deref() == Some("ProgressDeadlineExceeded")
            })
        })
}

fn component_status(d: &Deployment) -> ComponentStatus {
    let desired = d.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
    let status = d.status.clone().unwrap_or_default();
    let ready = status.ready_replicas.unwrap_or(0);
    ComponentStatus {
        desired,
        ready,
        updated: status.updated_replicas.unwrap_or(0),
        summary: format!("{ready}/{desired}"),
    }
}

fn container_image(d: &Deployment) -> Option<String> {
    d.spec
        .as_ref()?
        .template
        .spec
        .as_ref()?
        .containers
        .first()?
        .image
        .clone()
}

#[derive(Debug, PartialEq, Eq)]
pub enum JobState {
    Running,
    Succeeded,
    Failed,
}

pub fn job_state(job: &Job) -> JobState {
    let Some(status) = &job.status else {
        return JobState::Running;
    };
    if status.succeeded.unwrap_or(0) > 0 {
        return JobState::Succeeded;
    }
    let failed = status.conditions.as_ref().is_some_and(|conds| {
        conds
            .iter()
            .any(|c| c.type_ == "Failed" && c.status == "True")
    });
    if failed {
        JobState::Failed
    } else {
        JobState::Running
    }
}

/// Set a condition, keeping `lastTransitionTime` when the status is unchanged
/// so an idle reconcile doesn't rewrite the status.
fn set_condition(
    conditions: &mut Vec<OperatorCondition>,
    type_: &str,
    ok: bool,
    reason: &str,
    message: impl Into<String>,
) {
    let status = if ok { "True" } else { "False" };
    let message = Some(message.into());
    match conditions.iter_mut().find(|c| c.type_ == type_) {
        Some(c) => {
            if c.status != status {
                c.status = status.into();
                c.last_transition_time = Some(Utc::now().to_rfc3339());
            }
            c.reason = Some(reason.into());
            c.message = message;
        }
        None => conditions.push(OperatorCondition {
            type_: type_.into(),
            status: status.into(),
            last_transition_time: Some(Utc::now().to_rfc3339()),
            reason: Some(reason.into()),
            message,
        }),
    }
}

async fn apply<K>(api: &Api<K>, obj: &K) -> Result<K, kube::Error>
where
    K: Resource + Clone + Debug + DeserializeOwned + Serialize,
{
    api.patch(
        &obj.name_any(),
        &PatchParams::apply(MANAGER).force(),
        &Patch::Apply(obj),
    )
    .await
}

async fn delete_if_exists<K>(api: &Api<K>, name: &str) -> Result<(), kube::Error>
where
    K: Resource + Clone + Debug + DeserializeOwned,
{
    match api.delete(name, &DeleteParams::background()).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
        Err(e) => Err(e),
    }
}

/// Work out the image to roll towards, resolving the tag's digest when
/// auto-update is on. Updates the digest-tracking fields of `status`.
async fn resolve_target(
    cr: &SpectonRegistry,
    status: &mut SpectonRegistryStatus,
    ctx: &OperatorCtx,
) -> String {
    let img = &cr.spec.image;
    let tagged = format!("{}:{}", img.repository, img.tag);
    let auto = &cr.spec.auto_update;
    if !auto.enabled {
        status.tracked_tag = None;
        status.resolved_digest = None;
        status.last_digest_check = None;
        status.conditions.retain(|c| c.type_ != "DigestResolved");
        return tagged;
    }

    if status.tracked_tag.as_deref() != Some(&tagged) {
        // Tag changed under us: the old digest belongs to another tag.
        status.resolved_digest = None;
        status.last_digest_check = None;
    }
    let due = status.resolved_digest.is_none()
        || status
            .last_digest_check
            .as_deref()
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .is_none_or(|t| {
                Utc::now().signed_duration_since(t).num_seconds() >= auto.interval_seconds as i64
            });

    if due {
        match image::resolve_digest(&ctx.http, &img.repository, &img.tag, auto.insecure).await {
            Ok(digest) => {
                if status.resolved_digest.as_deref() != Some(&digest) {
                    info!(image = %tagged, %digest, "resolved new digest");
                }
                status.resolved_digest = Some(digest);
                status.tracked_tag = Some(tagged.clone());
                status.last_digest_check = Some(Utc::now().to_rfc3339());
                set_condition(
                    &mut status.conditions,
                    "DigestResolved",
                    true,
                    "Resolved",
                    format!("{tagged} resolved"),
                );
            }
            Err(e) => {
                warn!(image = %tagged, error = %e, "digest resolution failed; keeping last known");
                set_condition(
                    &mut status.conditions,
                    "DigestResolved",
                    false,
                    "ResolveFailed",
                    e.to_string(),
                );
            }
        }
    }

    match &status.resolved_digest {
        Some(digest) => format!("{}@{digest}", img.repository),
        // Never resolved yet: run the tag rather than nothing.
        None => tagged,
    }
}

async fn write_status(
    api: &Api<SpectonRegistry>,
    cr: &SpectonRegistry,
    prev: &SpectonRegistryStatus,
    status: &SpectonRegistryStatus,
    client: &Client,
) -> Result<(), OperatorError> {
    // Skipping no-op writes matters: every status write is a watch event
    // that would trigger another reconcile.
    if status == prev {
        return Ok(());
    }
    let patch = serde_json::json!({ "status": status });
    api.patch_status(
        &cr.name_any(),
        &PatchParams::default(),
        &Patch::Merge(&patch),
    )
    .await?;

    if status.phase != prev.phase {
        let ns = cr.namespace();
        let name = cr.name_any();
        let uid = cr.uid().unwrap_or_default();
        let degraded = status.phase == phase::DEGRADED;
        let message = status
            .conditions
            .iter()
            .find(|c| c.type_ == "Ready")
            .and_then(|c| c.message.clone())
            .unwrap_or_else(|| format!("phase {}", status.phase));
        if let Err(e) = publish_event(
            client,
            &EventInfo {
                namespace: ns.as_deref(),
                regarding_kind: "SpectonRegistry",
                regarding_name: &name,
                regarding_uid: &uid,
                reason: &status.phase,
                message: &message,
                event_type: if degraded { "Warning" } else { "Normal" },
            },
        )
        .await
        {
            warn!(%name, error = %e, "failed to publish event");
        }
    }
    Ok(())
}

pub async fn reconcile(
    cr: Arc<SpectonRegistry>,
    ctx: Arc<OperatorCtx>,
) -> Result<Action, OperatorError> {
    let name = cr.name_any();
    let ns = cr
        .namespace()
        .ok_or_else(|| OperatorError::Invalid("SpectonRegistry must be namespaced".into()))?;
    info!(%name, %ns, "reconciling SpectonRegistry");

    let client = ctx.client.clone();
    let api: Api<SpectonRegistry> = Api::namespaced(client.clone(), &ns);
    let prev = cr.status.clone().unwrap_or_default();
    let mut status = prev.clone();
    status.observed_generation = cr.metadata.generation;

    if cr.spec.paused {
        status.phase = phase::PAUSED.into();
        set_condition(
            &mut status.conditions,
            "Ready",
            false,
            "Paused",
            "reconciliation paused",
        );
        write_status(&api, &cr, &prev, &status, &client).await?;
        return Ok(Action::requeue(STEADY_REQUEUE));
    }

    // Config hash: editing the ConfigMap changes the pod template, which
    // rolls the pods onto the new config.
    let config_maps: Api<ConfigMap> = Api::namespaced(client.clone(), &ns);
    let Some(config) = config_maps.get_opt(&cr.spec.config_map_name).await? else {
        status.phase = phase::DEGRADED.into();
        set_condition(
            &mut status.conditions,
            "Ready",
            false,
            "ConfigMissing",
            format!("ConfigMap {} not found", cr.spec.config_map_name),
        );
        write_status(&api, &cr, &prev, &status, &client).await?;
        return Ok(Action::requeue(Duration::from_secs(30)));
    };
    let config_bytes = serde_json::to_vec(&(&config.data, &config.binary_data))
        .map_err(|e| OperatorError::Invalid(e.to_string()))?;
    let config_hash = resources::short_hash(&config_bytes);

    let target = resolve_target(&cr, &mut status, &ctx).await;
    status.target_image = Some(target.clone());

    // Services and the backup CronJob don't depend on rollout state.
    let services: Api<Service> = Api::namespaced(client.clone(), &ns);
    for component in [Component::Auth, Component::Registry] {
        apply(&services, &resources::service(&cr, component)).await?;
    }
    let cronjobs: Api<CronJob> = Api::namespaced(client.clone(), &ns);
    match &cr.spec.backup {
        Some(backup) if !backup.schedule.is_empty() => {
            apply(&cronjobs, &resources::backup_cronjob(&cr, backup)).await?;
        }
        _ => delete_if_exists(&cronjobs, &resources::backup_cronjob_name(&cr)).await?,
    }

    let deployments: Api<Deployment> = Api::namespaced(client.clone(), &ns);
    let live_auth = deployments
        .get_opt(&Component::Auth.object_name(&cr))
        .await?;
    let live_registry = deployments
        .get_opt(&Component::Registry.object_name(&cr))
        .await?;
    let plan = plan_rollout(
        &target,
        live_auth.as_ref().and_then(container_image).as_deref(),
        live_auth.as_ref().is_some_and(rolled_out),
        live_registry.as_ref().and_then(container_image).as_deref(),
    );

    // Gate the start of an upgrade on a fresh backup.
    if plan.starts_upgrade {
        let from = live_auth
            .as_ref()
            .and_then(container_image)
            .unwrap_or_default();
        if let Some(backup) = cr.spec.backup.as_ref().filter(|b| b.before_upgrade) {
            let jobs: Api<Job> = Api::namespaced(client.clone(), &ns);
            let job_name = resources::preupgrade_job_name(&cr, &from, &target);
            let job = match jobs.get_opt(&job_name).await? {
                Some(job) => job,
                None => {
                    info!(%name, %job_name, %target, "starting pre-upgrade backup");
                    jobs.create(
                        &PostParams::default(),
                        &resources::preupgrade_job(&cr, backup, &from, &target),
                    )
                    .await?
                }
            };
            match job_state(&job) {
                JobState::Running => {
                    status.phase = phase::BACKING_UP.into();
                    set_condition(
                        &mut status.conditions,
                        "Ready",
                        false,
                        "BackingUp",
                        format!("waiting for pre-upgrade backup {job_name}"),
                    );
                    write_status(&api, &cr, &prev, &status, &client).await?;
                    return Ok(Action::requeue(PROGRESS_REQUEUE));
                }
                JobState::Failed => {
                    status.phase = phase::DEGRADED.into();
                    status.last_backup = Some(BackupStatus {
                        job_name: job_name.clone(),
                        succeeded: false,
                        completion_time: None,
                    });
                    set_condition(
                        &mut status.conditions,
                        "Ready",
                        false,
                        "UpgradeBlocked",
                        format!(
                            "pre-upgrade backup {job_name} failed; fix spec.backup (which retries) \
                             or set backup.beforeUpgrade=false to skip it"
                        ),
                    );
                    write_status(&api, &cr, &prev, &status, &client).await?;
                    return Ok(Action::requeue(Duration::from_secs(120)));
                }
                JobState::Succeeded => {
                    status.last_backup = Some(BackupStatus {
                        job_name,
                        succeeded: true,
                        completion_time: job
                            .status
                            .as_ref()
                            .and_then(|s| s.completion_time.as_ref())
                            .map(|t| t.0.to_rfc3339()),
                    });
                }
            }
        }
        info!(%name, %from, to = %target, "upgrade started");
    }

    let auth = apply(
        &deployments,
        &resources::deployment(&cr, Component::Auth, &plan.auth_image, &config_hash),
    )
    .await?;
    let registry = apply(
        &deployments,
        &resources::deployment(&cr, Component::Registry, &plan.registry_image, &config_hash),
    )
    .await?;

    status.auth = component_status(&auth);
    status.registry = component_status(&registry);
    let done = !plan.upgrading
        && plan.registry_image == target
        && rolled_out(&auth)
        && rolled_out(&registry);
    // Once both specs point at the target the plan no longer calls it an
    // upgrade, but it still is one until the registry pods have rolled.
    let upgrading = plan.upgrading
        || prev
            .current_image
            .as_deref()
            .is_some_and(|current| current != target);

    if deadline_exceeded(&auth) || deadline_exceeded(&registry) {
        status.phase = phase::DEGRADED.into();
        set_condition(
            &mut status.conditions,
            "Ready",
            false,
            "ProgressDeadlineExceeded",
            "a Deployment failed to roll out; check pod events and logs",
        );
    } else if done {
        status.phase = phase::READY.into();
        status.current_image = Some(target.clone());
        set_condition(
            &mut status.conditions,
            "Ready",
            true,
            "RolledOut",
            format!("running {target}"),
        );
    } else if upgrading {
        status.phase = phase::UPGRADING.into();
        let stage = if plan.registry_image == target {
            "rolling registry"
        } else {
            "rolling auth"
        };
        set_condition(
            &mut status.conditions,
            "Ready",
            false,
            "Upgrading",
            format!("{stage} to {target}"),
        );
    } else {
        status.phase = if prev.phase.is_empty() {
            phase::PENDING.into()
        } else {
            phase::PROGRESSING.into()
        };
        set_condition(
            &mut status.conditions,
            "Ready",
            false,
            "RollingOut",
            "waiting for Deployments to become available",
        );
    }

    write_status(&api, &cr, &prev, &status, &client).await?;

    let requeue = if status.phase == phase::READY {
        if cr.spec.auto_update.enabled {
            STEADY_REQUEUE.min(Duration::from_secs(
                cr.spec.auto_update.interval_seconds.max(30),
            ))
        } else {
            STEADY_REQUEUE
        }
    } else {
        PROGRESS_REQUEUE
    };
    Ok(Action::requeue(requeue))
}

pub fn error_policy(
    cr: Arc<SpectonRegistry>,
    err: &OperatorError,
    _ctx: Arc<OperatorCtx>,
) -> Action {
    error!(name = %cr.name_any(), error = %err, "SpectonRegistry reconciliation failed");
    Action::requeue(Duration::from_secs(30))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::apps::v1::{DeploymentSpec, DeploymentStatus};
    use k8s_openapi::api::batch::v1::{JobCondition, JobStatus};

    #[test]
    fn fresh_install_rolls_both_at_once() {
        let plan = plan_rollout("img:v2", None, false, None);
        assert_eq!(plan.auth_image, "img:v2");
        assert_eq!(plan.registry_image, "img:v2");
        assert!(!plan.upgrading);
        assert!(!plan.starts_upgrade);
    }

    #[test]
    fn upgrade_moves_auth_first_and_holds_registry() {
        let plan = plan_rollout("img:v2", Some("img:v1"), true, Some("img:v1"));
        assert_eq!(plan.auth_image, "img:v2");
        assert_eq!(plan.registry_image, "img:v1");
        assert!(plan.upgrading);
        assert!(plan.starts_upgrade);
    }

    #[test]
    fn registry_waits_for_auth_rollout() {
        let plan = plan_rollout("img:v2", Some("img:v2"), false, Some("img:v1"));
        assert_eq!(plan.registry_image, "img:v1");
        assert!(plan.upgrading);
        assert!(!plan.starts_upgrade);
    }

    #[test]
    fn registry_follows_once_auth_is_out() {
        let plan = plan_rollout("img:v2", Some("img:v2"), true, Some("img:v1"));
        assert_eq!(plan.registry_image, "img:v2");
        assert!(plan.upgrading);
    }

    #[test]
    fn steady_state_is_not_an_upgrade() {
        let plan = plan_rollout("img:v2", Some("img:v2"), true, Some("img:v2"));
        assert_eq!(plan.registry_image, "img:v2");
        assert!(!plan.upgrading);
    }

    fn deployment(
        generation: i64,
        observed: i64,
        replicas: i32,
        updated: i32,
        available: i32,
        total: i32,
    ) -> Deployment {
        Deployment {
            metadata: kube::api::ObjectMeta {
                generation: Some(generation),
                ..Default::default()
            },
            spec: Some(DeploymentSpec {
                replicas: Some(replicas),
                ..Default::default()
            }),
            status: Some(DeploymentStatus {
                observed_generation: Some(observed),
                updated_replicas: Some(updated),
                available_replicas: Some(available),
                replicas: Some(total),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn rolled_out_requires_observed_generation_and_all_replicas() {
        assert!(rolled_out(&deployment(3, 3, 2, 2, 2, 2)));
        assert!(
            !rolled_out(&deployment(3, 2, 2, 2, 2, 2)),
            "stale observedGeneration"
        );
        assert!(
            !rolled_out(&deployment(3, 3, 2, 1, 2, 3)),
            "old pod still around"
        );
        assert!(
            !rolled_out(&deployment(3, 3, 2, 2, 1, 2)),
            "not yet available"
        );
    }

    #[test]
    fn job_state_reads_status() {
        let mut job = Job::default();
        assert_eq!(job_state(&job), JobState::Running);
        job.status = Some(JobStatus {
            succeeded: Some(1),
            ..Default::default()
        });
        assert_eq!(job_state(&job), JobState::Succeeded);
        job.status = Some(JobStatus {
            conditions: Some(vec![JobCondition {
                type_: "Failed".into(),
                status: "True".into(),
                ..Default::default()
            }]),
            ..Default::default()
        });
        assert_eq!(job_state(&job), JobState::Failed);
    }

    #[test]
    fn set_condition_keeps_transition_time_when_unchanged() {
        let mut conds = Vec::new();
        set_condition(&mut conds, "Ready", true, "RolledOut", "ok");
        let first = conds[0].last_transition_time.clone();
        set_condition(&mut conds, "Ready", true, "RolledOut", "still ok");
        assert_eq!(conds[0].last_transition_time, first);
        assert_eq!(conds[0].message.as_deref(), Some("still ok"));
        assert_eq!(conds.len(), 1);
    }
}
