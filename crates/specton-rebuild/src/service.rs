//! Fire a rebuild: rate-limit → emit → record event (design 018 R2).

use sqlx::{Pool, Postgres};
use tracing::{info, warn};
use uuid::Uuid;

use crate::emitter::{
    EmitError, GitHubDispatchEmitter, RebuildEmitter, RebuildEvent, TriggerCause,
};
use crate::rate_limit::RateLimit;
use crate::subscription::{EmitterSpec, RebuildSubscription};

#[derive(Debug, Clone)]
pub struct FireRequest {
    pub subscription: RebuildSubscription,
    pub upstream_ref: String,
    pub downstream_ref: String,
    pub trigger: TriggerCause,
    pub fixed_cves: Vec<String>,
    pub severity_max: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FireResult {
    pub subscription_id: Uuid,
    pub subscription_name: String,
    pub status: String,
    pub response: Option<String>,
    pub rate_limited: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum FireError {
    #[error("rate limit: {0}")]
    RateLimit(#[from] crate::rate_limit::RateLimitError),
    #[error("emit: {0}")]
    Emit(#[from] EmitError),
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("config: {0}")]
    Config(String),
}

pub struct RebuildService {
    pool: Pool<Postgres>,
}

impl RebuildService {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    pub async fn fire(&self, req: FireRequest) -> Result<FireResult, FireError> {
        let sub = &req.subscription;
        let cap = sub.spec.rate_limit.per_downstream_per_day;
        let rl = RateLimit::new(self.pool.clone(), cap);

        let allowed = rl
            .check_and_increment(sub.id, &req.downstream_ref)
            .await?;
        if !allowed {
            let _ = self
                .record_event(
                    sub.id,
                    &req,
                    "rate-limited",
                    Some("per_downstream_per_day cap reached".into()),
                )
                .await;
            return Ok(FireResult {
                subscription_id: sub.id,
                subscription_name: sub.name.clone(),
                status: "rate-limited".into(),
                response: None,
                rate_limited: true,
            });
        }

        let emitter = build_emitter(&sub.spec.emitter)?;
        match emitter.emit(&RebuildEvent {
            trigger: req.trigger,
            fixed_cves: req.fixed_cves.clone(),
            upstream_ref: req.upstream_ref.clone(),
            downstream_ref: req.downstream_ref.clone(),
            severity_max: req.severity_max.clone(),
        })
        .await
        {
            Ok(resp) => {
                self.record_event(sub.id, &req, "sent", Some(resp.clone()))
                    .await?;
                info!(
                    subscription = %sub.name,
                    downstream = %req.downstream_ref,
                    "rebuild event emitted"
                );
                Ok(FireResult {
                    subscription_id: sub.id,
                    subscription_name: sub.name.clone(),
                    status: "sent".into(),
                    response: Some(resp),
                    rate_limited: false,
                })
            }
            Err(e) => {
                let _ = rl
                    .decrement_on_failure(sub.id, &req.downstream_ref)
                    .await;
                let msg = e.to_string();
                let _ = self
                    .record_event(sub.id, &req, "failed", Some(msg.clone()))
                    .await;
                warn!(
                    subscription = %sub.name,
                    error = %msg,
                    "rebuild emit failed"
                );
                Err(FireError::Emit(e))
            }
        }
    }

    async fn record_event(
        &self,
        subscription_id: Uuid,
        req: &FireRequest,
        status: &str,
        response: Option<String>,
    ) -> Result<(), FireError> {
        sqlx::query(
            "INSERT INTO rebuild_events
                 (id, subscription_id, upstream_ref, downstream_ref,
                  fixed_cves, severity_max, emitter_status, emitter_response, fired_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8, NOW())",
        )
        .bind(Uuid::new_v4())
        .bind(subscription_id)
        .bind(&req.upstream_ref)
        .bind(&req.downstream_ref)
        .bind(&req.fixed_cves)
        .bind(&req.severity_max)
        .bind(status)
        .bind(response)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_events(
        &self,
        tenant: &str,
        limit: i64,
    ) -> Result<Vec<serde_json::Value>, FireError> {
        let rows: Vec<(
            Uuid,
            Uuid,
            String,
            String,
            Vec<String>,
            String,
            String,
            Option<String>,
            chrono::DateTime<chrono::Utc>,
            String,
        )> = sqlx::query_as(
            "SELECT e.id, e.subscription_id, e.upstream_ref, e.downstream_ref,
                    e.fixed_cves, e.severity_max, e.emitter_status, e.emitter_response,
                    e.fired_at, s.name
             FROM rebuild_events e
             JOIN rebuild_subscriptions s ON s.id = e.subscription_id
             WHERE s.tenant = $1
             ORDER BY e.fired_at DESC
             LIMIT $2",
        )
        .bind(tenant)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    subscription_id,
                    upstream_ref,
                    downstream_ref,
                    fixed_cves,
                    severity_max,
                    emitter_status,
                    emitter_response,
                    fired_at,
                    name,
                )| {
                    serde_json::json!({
                        "id": id,
                        "subscription_id": subscription_id,
                        "subscription_name": name,
                        "upstream_ref": upstream_ref,
                        "downstream_ref": downstream_ref,
                        "fixed_cves": fixed_cves,
                        "severity_max": severity_max,
                        "emitter_status": emitter_status,
                        "emitter_response": emitter_response,
                        "fired_at": fired_at,
                    })
                },
            )
            .collect())
    }
}

fn build_emitter(spec: &EmitterSpec) -> Result<Box<dyn RebuildEmitter>, FireError> {
    match spec {
        EmitterSpec::GithubDispatch {
            repo,
            event_type,
            token,
            api_base,
            workflow: _,
        } => {
            let token = token
                .clone()
                .or_else(|| std::env::var("GITHUB_TOKEN").ok())
                .ok_or_else(|| {
                    FireError::Config("github-dispatch requires token or GITHUB_TOKEN".into())
                })?;
            let mut e = GitHubDispatchEmitter::new(repo, token, event_type);
            if let Some(base) = api_base {
                e = e.with_api_base(base);
            }
            Ok(Box::new(e))
        }
    }
}
