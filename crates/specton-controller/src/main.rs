use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::StreamExt;
use kube::api::{Api, PostParams};
use kube::runtime::Controller;
use kube::runtime::reflector::ObjectRef;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::{Client, CustomResourceExt, ResourceExt};
use tracing::{error, info};

mod operator;
mod tenancy;

use operator::SpectonRegistry;
use operator::reconcile::{
    OperatorCtx, error_policy as operator_error_policy, reconcile as reconcile_registry,
};
use tenancy::{AccessPolicy, Project, Tenant, TokenPolicy};

// ---------------------------------------------------------------------------
// Context shared across reconcilers
// ---------------------------------------------------------------------------

struct Ctx {
    client: Client,
    http: reqwest::Client,
    auth_service_url: String,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
enum ControllerError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// Helper: publish a Kubernetes Event
// ---------------------------------------------------------------------------

struct EventInfo<'a> {
    namespace: Option<&'a str>,
    regarding_kind: &'a str,
    regarding_name: &'a str,
    regarding_uid: &'a str,
    reason: &'a str,
    message: &'a str,
    event_type: &'a str,
}

async fn publish_event(client: &Client, info: &EventInfo<'_>) -> Result<(), ControllerError> {
    let events: Api<k8s_openapi::api::events::v1::Event> = match info.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::default_namespaced(client.clone()),
    };

    let now = Utc::now();
    let event = k8s_openapi::api::events::v1::Event {
        metadata: kube::api::ObjectMeta {
            generate_name: Some(format!("{}-", info.regarding_name)),
            namespace: info.namespace.map(String::from),
            ..Default::default()
        },
        regarding: Some(k8s_openapi::api::core::v1::ObjectReference {
            kind: Some(info.regarding_kind.to_string()),
            name: Some(info.regarding_name.to_string()),
            uid: Some(info.regarding_uid.to_string()),
            namespace: info.namespace.map(String::from),
            api_version: Some("spectoncr.io/v1alpha1".to_string()),
            ..Default::default()
        }),
        reason: Some(info.reason.to_string()),
        note: Some(info.message.to_string()),
        type_: Some(info.event_type.to_string()),
        event_time: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime(
            now,
        )),
        reporting_controller: Some("specton-controller".to_string()),
        reporting_instance: Some("specton-controller-0".to_string()),
        action: Some(info.reason.to_string()),
        ..Default::default()
    };

    let pp = PostParams::default();
    events.create(&pp, &event).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `specton-controller crd` prints the SpectonRegistry CRD, which is how
    // deploy/helm/spectoncr/templates/crds/spectonregistry.yaml is generated.
    if std::env::args().nth(1).as_deref() == Some("crd") {
        print!("{}", serde_yaml::to_string(&SpectonRegistry::crd())?);
        return Ok(());
    }

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    info!("starting specton-controller");

    // The release image builds every workspace binary in one cargo
    // invocation, so feature unification enables both of rustls' crypto
    // backends (ring and aws-lc-rs). rustls then can't pick a process-wide
    // default and the kube client panics while building its TLS config.
    // Choose ring explicitly; `Err` only means one is already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let client = Client::try_default().await?;

    let auth_service_url = std::env::var("AUTH_SERVICE_URL")
        .unwrap_or_else(|_| "http://specton-auth:8080".to_string());

    let ctx = Arc::new(Ctx {
        client: client.clone(),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?,
        auth_service_url,
    });

    // --- Tenant controller (cluster-scoped) ---
    let tenants: Api<Tenant> = Api::all(client.clone());
    let tenant_ctrl = Controller::new(tenants, WatcherConfig::default())
        .shutdown_on_signal()
        .run(
            tenancy::reconcile_tenant,
            tenancy::error_policy,
            ctx.clone(),
        )
        .for_each(|res| async move {
            match res {
                Ok(o) => info!(resource = ?o, "tenant reconciled"),
                Err(e) => error!(error = %e, "tenant reconcile loop error"),
            }
        });

    // --- Project controller ---
    let projects: Api<Project> = Api::all(client.clone());
    let project_ctrl = Controller::new(projects, WatcherConfig::default())
        .shutdown_on_signal()
        .run(
            tenancy::reconcile_project,
            tenancy::error_policy,
            ctx.clone(),
        )
        .for_each(|res| async move {
            match res {
                Ok(o) => info!(resource = ?o, "project reconciled"),
                Err(e) => error!(error = %e, "project reconcile loop error"),
            }
        });

    // --- AccessPolicy controller ---
    let access_policies: Api<AccessPolicy> = Api::all(client.clone());
    let access_ctrl = Controller::new(access_policies, WatcherConfig::default())
        .shutdown_on_signal()
        .run(
            tenancy::reconcile_access_policy,
            tenancy::error_policy,
            ctx.clone(),
        )
        .for_each(|res| async move {
            match res {
                Ok(o) => info!(resource = ?o, "access-policy reconciled"),
                Err(e) => error!(error = %e, "access-policy reconcile loop error"),
            }
        });

    // --- TokenPolicy controller ---
    let token_policies: Api<TokenPolicy> = Api::all(client.clone());
    let token_ctrl = Controller::new(token_policies, WatcherConfig::default())
        .shutdown_on_signal()
        .run(
            tenancy::reconcile_token_policy,
            tenancy::error_policy,
            ctx.clone(),
        )
        .for_each(|res| async move {
            match res {
                Ok(o) => info!(resource = ?o, "token-policy reconciled"),
                Err(e) => error!(error = %e, "token-policy reconcile loop error"),
            }
        });

    // --- SpectonRegistry lifecycle operator ---
    // Owned objects are watched too, so a Deployment finishing its rollout
    // (or someone editing it) triggers a reconcile of its SpectonRegistry.
    let operator_ctx = Arc::new(OperatorCtx {
        client: client.clone(),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?,
    });
    let owned = || WatcherConfig::default().labels("app.kubernetes.io/managed-by=specton-operator");
    let registry_ctrl = Controller::new(
        Api::<SpectonRegistry>::all(client.clone()),
        WatcherConfig::default(),
    );
    // A ConfigMap edit must roll the pods that mount it, so map ConfigMap
    // events back to every SpectonRegistry that references it.
    let registries = registry_ctrl.store();
    let registry_ctrl = registry_ctrl
        .owns(
            Api::<k8s_openapi::api::apps::v1::Deployment>::all(client.clone()),
            owned(),
        )
        .owns(
            Api::<k8s_openapi::api::core::v1::Service>::all(client.clone()),
            owned(),
        )
        .owns(
            Api::<k8s_openapi::api::batch::v1::Job>::all(client.clone()),
            owned(),
        )
        .watches(
            Api::<k8s_openapi::api::core::v1::ConfigMap>::all(client.clone()),
            WatcherConfig::default(),
            move |cm| {
                let ns = cm.namespace();
                let name = cm.name_any();
                registries
                    .state()
                    .into_iter()
                    .filter(|r| r.namespace() == ns && r.spec.config_map_name == name)
                    .map(|r| ObjectRef::from_obj(&*r))
                    .collect::<Vec<_>>()
            },
        )
        .shutdown_on_signal()
        .run(reconcile_registry, operator_error_policy, operator_ctx)
        .for_each(|res| async move {
            match res {
                Ok(o) => info!(resource = ?o, "spectonregistry reconciled"),
                // Owned objects being garbage-collected after their
                // SpectonRegistry was deleted still trigger reconciles.
                Err(kube::runtime::controller::Error::ObjectNotFound(o)) => {
                    tracing::debug!(resource = %o, "spectonregistry already deleted")
                }
                Err(e) => error!(error = %e, "spectonregistry reconcile loop error"),
            }
        });

    info!("all controllers started; waiting for shutdown signal");

    // Run all controllers concurrently — they all exit on SIGTERM.
    tokio::select! {
        () = tenant_ctrl => info!("tenant controller exited"),
        () = project_ctrl => info!("project controller exited"),
        () = access_ctrl => info!("access-policy controller exited"),
        () = token_ctrl => info!("token-policy controller exited"),
        () = registry_ctrl => info!("spectonregistry operator exited"),
    }

    info!("specton-controller shut down");
    Ok(())
}
