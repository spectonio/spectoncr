//! HTTP surface for specton-import (design 012).
//!
//! Kill-switch: `[import] enabled = false` (default) → routes return 403.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use object_store::ObjectStore;
use serde::{Deserialize, Serialize};
use specton_common::config::ImportConfig;
use specton_common::errors::RegistryError;
use specton_common::models::Role;
use specton_import::{
    AcrSource, DistributionSource, HarborSource, ImportJobStore, ImportPhase,
    ImportRunner, ImportRunnerConfig, InMemoryDestination, NexusSource, ObjectStoreDestination,
    PgImportJobStore, RegistryDestination, RegistrySource,
};
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use specton_common::auth::TokenClaims;

use crate::{AppState, AuthenticatedClaims};

fn import_enabled(state: &AppState) -> Result<(), RegistryError> {
    if state.config.import.enabled {
        Ok(())
    } else {
        Err(RegistryError::Forbidden {
            reason: "import disabled ([import] enabled=false)".into(),
        })
    }
}

fn require_import_read(claims: &TokenClaims) -> Result<(), RegistryError> {
    match claims.role {
        Role::Admin | Role::Maintainer | Role::Reader => Ok(()),
    }
}

fn require_import_admin(claims: &TokenClaims) -> Result<(), RegistryError> {
    if claims.role == Role::Admin {
        Ok(())
    } else {
        Err(RegistryError::Forbidden {
            reason: "import mutating endpoints require Admin role".into(),
        })
    }
}

/// Catalog of source adapters returned by GET `/v2/_import/sources`.
pub fn build_sources_response(cfg: &ImportConfig) -> serde_json::Value {
    let master = cfg.enabled;
    serde_json::json!({
        "enabled": master,
        "sources": [
            {
                "id": "distribution",
                "enabled": master,
                "features": ["catalog", "tags", "manifests", "blobs"],
            },
            {
                "id": "nexus",
                "enabled": master,
                "features": ["catalog", "docker-repo-filter", "distribution-delegate"],
            },
            {
                "id": "harbor",
                "enabled": master,
                "features": ["harbor-api-catalog", "project-filter", "distribution-delegate"],
            },
            {
                "id": "acr",
                "enabled": master,
                "features": ["acr-catalog", "distribution-delegate"],
            },
        ],
    })
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ImportJobSpec {
    pub source_type: String,
    pub source_url: String,
    #[serde(default)]
    pub source_repo: Option<String>,
    #[serde(default)]
    pub bearer: Option<String>,
    pub target_tenant: String,
    pub target_project: String,
    #[serde(default)]
    pub target_prefix: Option<String>,
    #[serde(default)]
    pub dry_run: Option<bool>,
    #[serde(default)]
    pub parallelism: Option<u32>,
}

fn build_source(spec: &ImportJobSpec) -> Result<Arc<dyn RegistrySource>, RegistryError> {
    let kind = spec.source_type.to_lowercase();
    let src: Arc<dyn RegistrySource> = match kind.as_str() {
        "distribution" => Arc::new(DistributionSource::new(
            spec.source_url.clone(),
            spec.bearer.clone(),
        )),
        "nexus" => Arc::new(NexusSource::new(
            spec.source_url.clone(),
            spec.bearer.clone(),
            spec.source_repo.clone(),
        )),
        "harbor" => {
            // Optional bearer as `user:pass` basic-auth pair for Harbor API.
            let (user, pass) = spec
                .bearer
                .as_deref()
                .and_then(|b| b.split_once(':'))
                .map(|(u, p)| (Some(u.to_string()), Some(p.to_string())))
                .unwrap_or((None, spec.bearer.clone()));
            Arc::new(HarborSource::new(
                spec.source_url.clone(),
                user,
                pass,
                spec.source_repo.clone(),
            ))
        }
        "acr" => Arc::new(AcrSource::new(
            spec.source_url.clone(),
            spec.bearer.clone(),
        )),
        other => {
            return Err(RegistryError::ManifestInvalid {
                reason: format!(
                    "unknown import source_type '{other}' (distribution|nexus|harbor|acr)"
                ),
            });
        }
    };
    Ok(src)
}

fn runner_config(spec: &ImportJobSpec) -> ImportRunnerConfig {
    ImportRunnerConfig {
        tenant: spec.target_tenant.clone(),
        project: spec.target_project.clone(),
        parallelism: spec.parallelism.unwrap_or(1).max(1),
        include_prefix: spec.target_prefix.clone(),
    }
}

fn destination_for_spec(
    spec: &ImportJobSpec,
    store: Arc<dyn ObjectStore>,
) -> Arc<dyn RegistryDestination> {
    if spec.dry_run.unwrap_or(false) {
        Arc::new(InMemoryDestination::new())
    } else {
        Arc::new(ObjectStoreDestination::new(store))
    }
}

async fn spawn_import_runner(
    store: Arc<dyn ObjectStore>,
    pool: PgPool,
    job_id: Uuid,
    spec: ImportJobSpec,
) {
    let job_store = PgImportJobStore::new(pool.clone());
    if let Err(e) = job_store.set_phase(job_id, ImportPhase::Running).await {
        error!(%job_id, error = %e, "import: failed to mark job running");
        return;
    }

    let source = match build_source(&spec) {
        Ok(s) => s,
        Err(e) => {
            error!(%job_id, error = %e, "import: invalid source spec");
            let _ = job_store.set_phase(job_id, ImportPhase::Failed).await;
            return;
        }
    };
    let destination = destination_for_spec(&spec, store);
    let runner = ImportRunner {
        source,
        destination,
        config: runner_config(&spec),
    };

    match runner.run().await {
        Ok(report) => {
            info!(
                %job_id,
                repos = report.repos_copied,
                tags = report.tags_copied,
                blobs = report.blobs_copied,
                bytes = report.bytes_copied,
                failures = report.failures,
                "import job finished"
            );
            let phase = if report.failures > 0 {
                ImportPhase::Failed
            } else {
                ImportPhase::Succeeded
            };
            if let Err(e) = job_store.set_phase(job_id, phase).await {
                warn!(%job_id, error = %e, "import: failed to set terminal phase");
            }
        }
        Err(e) => {
            error!(%job_id, error = %e, "import job failed");
            let _ = job_store.set_phase(job_id, ImportPhase::Failed).await;
        }
    }
}

pub async fn list_import_sources(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
) -> Result<impl IntoResponse, RegistryError> {
    import_enabled(&state)?;
    require_import_read(&claims)?;
    Ok(Json(build_sources_response(&state.config.import)))
}

#[derive(Debug, Deserialize)]
pub struct CreateImportJobBody {
    pub source_type: String,
    pub source_url: String,
    #[serde(default)]
    pub source_repo: Option<String>,
    #[serde(default)]
    pub bearer: Option<String>,
    pub target_tenant: String,
    pub target_project: String,
    #[serde(default)]
    pub target_prefix: Option<String>,
    #[serde(default)]
    pub dry_run: Option<bool>,
    #[serde(default)]
    pub parallelism: Option<u32>,
}

impl From<CreateImportJobBody> for ImportJobSpec {
    fn from(b: CreateImportJobBody) -> Self {
        Self {
            source_type: b.source_type,
            source_url: b.source_url,
            source_repo: b.source_repo,
            bearer: b.bearer,
            target_tenant: b.target_tenant,
            target_project: b.target_project,
            target_prefix: b.target_prefix,
            dry_run: b.dry_run,
            parallelism: b.parallelism,
        }
    }
}

pub async fn create_import_job(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Json(body): Json<CreateImportJobBody>,
) -> Result<impl IntoResponse, RegistryError> {
    import_enabled(&state)?;
    require_import_admin(&claims)?;

    let spec: ImportJobSpec = body.into();
    build_source(&spec)?;

    let pool = state
        .gc_pool
        .as_ref()
        .ok_or_else(|| RegistryError::Internal("import requires Postgres".into()))?
        .clone();
    let tenant = claims
        .tenant_name
        .clone()
        .unwrap_or_else(|| spec.target_tenant.clone());
    let spec_json =
        serde_json::to_value(&spec).map_err(|e| RegistryError::Internal(e.to_string()))?;
    let job_store = PgImportJobStore::new(pool.clone());
    let job = job_store
        .create(&tenant, spec_json)
        .await
        .map_err(|e| RegistryError::Internal(e.to_string()))?;

    let store = state.store.clone();
    let job_id = job.id;
    let run_spec = spec.clone();
    tokio::spawn(async move {
        spawn_import_runner(store, pool, job_id, run_spec).await;
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "id": job.id })),
    ))
}

#[derive(Debug, Serialize)]
struct ImportJobStatusResponse {
    id: Uuid,
    tenant: String,
    spec: serde_json::Value,
    phase: ImportPhase,
    repos_total: i32,
    repos_copied: i32,
    tags_total: i32,
    tags_copied: i32,
    bytes_copied: i64,
    started_at: Option<chrono::DateTime<chrono::Utc>>,
    finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<specton_import::ImportJobRow> for ImportJobStatusResponse {
    fn from(row: specton_import::ImportJobRow) -> Self {
        Self {
            id: row.id,
            tenant: row.tenant,
            spec: row.spec,
            phase: row.phase,
            repos_total: row.repos_total,
            repos_copied: row.repos_copied,
            tags_total: row.tags_total,
            tags_copied: row.tags_copied,
            bytes_copied: row.bytes_copied,
            started_at: row.started_at,
            finished_at: row.finished_at,
        }
    }
}

pub async fn get_import_job(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, RegistryError> {
    import_enabled(&state)?;
    require_import_admin(&claims)?;

    let pool = state
        .gc_pool
        .as_ref()
        .ok_or_else(|| RegistryError::Internal("import requires Postgres".into()))?
        .clone();
    let job_store = PgImportJobStore::new(pool);
    let job = job_store
        .get(id)
        .await
        .map_err(|e| RegistryError::Internal(e.to_string()))?
        .ok_or_else(|| RegistryError::TagUnknown {
            tag: id.to_string(),
        })?;
    Ok(Json(ImportJobStatusResponse::from(job)))
}

pub async fn abort_import_job(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, RegistryError> {
    import_enabled(&state)?;
    require_import_admin(&claims)?;

    let pool = state
        .gc_pool
        .as_ref()
        .ok_or_else(|| RegistryError::Internal("import requires Postgres".into()))?
        .clone();
    let job_store = PgImportJobStore::new(pool);
    let job = job_store
        .get(id)
        .await
        .map_err(|e| RegistryError::Internal(e.to_string()))?
        .ok_or_else(|| RegistryError::TagUnknown {
            tag: id.to_string(),
        })?;
    if job.phase == ImportPhase::Running {
        warn!(%id, "import abort requested while job still running (phase marker only)");
    }
    job_store
        .set_phase(id, ImportPhase::Aborted)
        .await
        .map_err(|e| RegistryError::Internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn resume_import_job(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, RegistryError> {
    import_enabled(&state)?;
    require_import_admin(&claims)?;

    let pool = state
        .gc_pool
        .as_ref()
        .ok_or_else(|| RegistryError::Internal("import requires Postgres".into()))?
        .clone();
    let job_store = PgImportJobStore::new(pool.clone());
    let job = job_store
        .get(id)
        .await
        .map_err(|e| RegistryError::Internal(e.to_string()))?
        .ok_or_else(|| RegistryError::TagUnknown {
            tag: id.to_string(),
        })?;
    if !matches!(
        job.phase,
        ImportPhase::Aborted | ImportPhase::Failed | ImportPhase::Queued
    ) {
        return Err(RegistryError::ManifestInvalid {
            reason: format!("cannot resume job in phase {:?}", job.phase),
        });
    }
    let spec: ImportJobSpec = serde_json::from_value(job.spec.clone()).map_err(|e| {
        RegistryError::Internal(format!("import job spec corrupt: {e}"))
    })?;

    let store = state.store.clone();
    tokio::spawn(async move {
        spawn_import_runner(store, pool, id, spec).await;
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "id": id, "resumed": true })),
    ))
}

pub async fn import_dry_run(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Json(body): Json<CreateImportJobBody>,
) -> Result<impl IntoResponse, RegistryError> {
    import_enabled(&state)?;
    require_import_admin(&claims)?;

    let spec: ImportJobSpec = body.into();
    let source = build_source(&spec)?;
    let prefix = spec.target_prefix.as_deref();

    let repos = source
        .list_repositories()
        .await
        .map_err(|e| RegistryError::Internal(e.to_string()))?;

    let mut repositories = 0u64;
    let mut tags = 0u64;
    for repo in repos {
        if matches!(prefix, Some(p) if !repo.name.starts_with(p)) {
            continue;
        }
        repositories += 1;
        let tag_list = source
            .list_tags(&repo)
            .await
            .map_err(|e| RegistryError::Internal(e.to_string()))?;
        tags += tag_list.len() as u64;
    }

    Ok(Json(serde_json::json!({
        "source_type": spec.source_type,
        "repositories": repositories,
        "tags": tags,
        "dry_run": true,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_list_includes_four_adapters() {
        let off = build_sources_response(&ImportConfig::default());
        assert_eq!(off["sources"].as_array().unwrap().len(), 4);
        assert!(!off["enabled"].as_bool().unwrap());

        let mut on = ImportConfig::default();
        on.enabled = true;
        let enabled = build_sources_response(&on);
        assert!(enabled["enabled"].as_bool().unwrap());
        assert!(
            enabled["sources"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["enabled"].as_bool() == Some(true))
        );
    }
}
