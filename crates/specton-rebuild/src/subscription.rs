//! Rebuild subscription store + matching (design 018 R2).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WatchSpec {
    #[serde(default)]
    pub bases: Vec<String>,
    #[serde(default)]
    pub descendants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggersSpec {
    #[serde(default = "default_true")]
    pub on_cve_fix: bool,
    #[serde(default)]
    pub on_base_push: bool,
    #[serde(default = "default_min_severity")]
    pub min_severity_fixed: String,
}

fn default_true() -> bool {
    true
}
fn default_min_severity() -> String {
    "high".into()
}

impl Default for TriggersSpec {
    fn default() -> Self {
        Self {
            on_cve_fix: true,
            on_base_push: false,
            min_severity_fixed: default_min_severity(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum EmitterSpec {
    #[serde(rename = "github-dispatch")]
    GithubDispatch {
        repo: String,
        #[serde(default = "default_event_type")]
        event_type: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        workflow: Option<String>,
        /// PAT or fine-grained token. Prefer Secret refs at the CRD layer;
        /// the registry store keeps the resolved token for emit.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_base: Option<String>,
    },
}

fn default_event_type() -> String {
    "rebuild-on-cve".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitSpec {
    #[serde(default = "default_per_day")]
    pub per_downstream_per_day: i32,
}

fn default_per_day() -> i32 {
    1
}

impl Default for RateLimitSpec {
    fn default() -> Self {
        Self {
            per_downstream_per_day: default_per_day(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionSpec {
    #[serde(default)]
    pub watch: WatchSpec,
    #[serde(default)]
    pub triggers: TriggersSpec,
    pub emitter: EmitterSpec,
    #[serde(default)]
    pub rate_limit: RateLimitSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebuildSubscription {
    pub id: Uuid,
    pub tenant: String,
    pub name: String,
    pub spec: SubscriptionSpec,
    pub enabled: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum SubscriptionStoreError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("invalid spec: {0}")]
    Spec(String),
}

#[async_trait]
pub trait SubscriptionStore: Send + Sync {
    async fn upsert(&self, sub: &RebuildSubscription) -> Result<(), SubscriptionStoreError>;
    async fn get(
        &self,
        tenant: &str,
        name: &str,
    ) -> Result<Option<RebuildSubscription>, SubscriptionStoreError>;
    async fn list_for_tenant(
        &self,
        tenant: &str,
    ) -> Result<Vec<RebuildSubscription>, SubscriptionStoreError>;
    async fn list_enabled(&self) -> Result<Vec<RebuildSubscription>, SubscriptionStoreError>;
    async fn delete(&self, tenant: &str, name: &str) -> Result<bool, SubscriptionStoreError>;
}

pub struct PgSubscriptionStore {
    pool: Pool<Postgres>,
}

impl PgSubscriptionStore {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &Pool<Postgres> {
        &self.pool
    }
}

#[async_trait]
impl SubscriptionStore for PgSubscriptionStore {
    async fn upsert(&self, sub: &RebuildSubscription) -> Result<(), SubscriptionStoreError> {
        let spec = serde_json::to_value(&sub.spec)
            .map_err(|e| SubscriptionStoreError::Spec(e.to_string()))?;
        sqlx::query(
            "INSERT INTO rebuild_subscriptions (id, tenant, name, spec, enabled, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6)
             ON CONFLICT (tenant, name) DO UPDATE SET
                 id = EXCLUDED.id,
                 spec = EXCLUDED.spec,
                 enabled = EXCLUDED.enabled,
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(sub.id)
        .bind(&sub.tenant)
        .bind(&sub.name)
        .bind(spec)
        .bind(sub.enabled)
        .bind(sub.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &str,
        name: &str,
    ) -> Result<Option<RebuildSubscription>, SubscriptionStoreError> {
        let row: Option<(Uuid, String, String, serde_json::Value, bool, DateTime<Utc>)> =
            sqlx::query_as(
                "SELECT id, tenant, name, spec, enabled, updated_at
                 FROM rebuild_subscriptions WHERE tenant = $1 AND name = $2",
            )
            .bind(tenant)
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(row_to_sub).transpose()?)
    }

    async fn list_for_tenant(
        &self,
        tenant: &str,
    ) -> Result<Vec<RebuildSubscription>, SubscriptionStoreError> {
        let rows: Vec<(Uuid, String, String, serde_json::Value, bool, DateTime<Utc>)> =
            sqlx::query_as(
                "SELECT id, tenant, name, spec, enabled, updated_at
                 FROM rebuild_subscriptions WHERE tenant = $1 ORDER BY name",
            )
            .bind(tenant)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(row_to_sub).collect()
    }

    async fn list_enabled(&self) -> Result<Vec<RebuildSubscription>, SubscriptionStoreError> {
        let rows: Vec<(Uuid, String, String, serde_json::Value, bool, DateTime<Utc>)> =
            sqlx::query_as(
                "SELECT id, tenant, name, spec, enabled, updated_at
                 FROM rebuild_subscriptions WHERE enabled = TRUE ORDER BY tenant, name",
            )
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(row_to_sub).collect()
    }

    async fn delete(&self, tenant: &str, name: &str) -> Result<bool, SubscriptionStoreError> {
        let r = sqlx::query("DELETE FROM rebuild_subscriptions WHERE tenant = $1 AND name = $2")
            .bind(tenant)
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }
}

fn row_to_sub(
    (id, tenant, name, spec_val, enabled, updated_at): (
        Uuid,
        String,
        String,
        serde_json::Value,
        bool,
        DateTime<Utc>,
    ),
) -> Result<RebuildSubscription, SubscriptionStoreError> {
    let spec: SubscriptionSpec = serde_json::from_value(spec_val)
        .map_err(|e| SubscriptionStoreError::Spec(e.to_string()))?;
    Ok(RebuildSubscription {
        id,
        tenant,
        name,
        spec,
        enabled,
        updated_at,
    })
}

/// Simple glob: `*` matches any substring; otherwise exact equality.
///
/// Convenience: a trailing `/*` also matches OCI tag form `prefix:tag`
/// (so `acme/prod/api/*` matches `acme/prod/api:latest`).
pub fn glob_match(pattern: &str, value: &str) -> bool {
    if glob_match_inner(pattern, value) {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return glob_match_inner(&format!("{prefix}:*"), value)
            || glob_match_inner(&format!("{prefix}*"), value);
    }
    false
}

fn glob_match_inner(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    if !value.starts_with(parts[0]) {
        return false;
    }
    let mut pos = parts[0].len();
    for (i, part) in parts.iter().enumerate().skip(1) {
        if part.is_empty() {
            if i == parts.len() - 1 {
                return true; // trailing *
            }
            continue;
        }
        if i == parts.len() - 1 {
            // Final literal must be a suffix of the remaining value.
            return value[pos..].ends_with(part);
        }
        match value[pos..].find(part) {
            Some(idx) => pos += idx + part.len(),
            None => return false,
        }
    }
    pos == value.len() || pattern.ends_with('*')
}

impl RebuildSubscription {
    /// Whether this subscription cares about `upstream` (base) for `downstream`.
    pub fn matches(&self, upstream_ref: &str, downstream_ref: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let bases = &self.spec.watch.bases;
        let base_ok = bases.is_empty()
            || bases
                .iter()
                .any(|b| glob_match(b, upstream_ref) || upstream_ref.contains(b.as_str()));
        if !base_ok {
            return false;
        }
        let desc = &self.spec.watch.descendants;
        desc.is_empty() || desc.iter().any(|d| glob_match(d, downstream_ref))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_exact_and_star() {
        assert!(glob_match("acme/prod/api:latest", "acme/prod/api:latest"));
        assert!(!glob_match("acme/prod/api:latest", "acme/prod/api:v2"));
        assert!(glob_match("acme/prod/api/*", "acme/prod/api:latest"));
        assert!(glob_match("acme/*/api:*", "acme/prod/api:v1"));
        assert!(glob_match("*", "anything"));
        assert!(!glob_match("acme/prod/*", "other/prod/x"));
    }

    #[test]
    fn subscription_matches_watch() {
        let sub = RebuildSubscription {
            id: Uuid::nil(),
            tenant: "acme".into(),
            name: "api".into(),
            enabled: true,
            updated_at: Utc::now(),
            spec: SubscriptionSpec {
                watch: WatchSpec {
                    bases: vec!["debian:bookworm-slim".into()],
                    descendants: vec!["acme/prod/api/*".into()],
                },
                triggers: TriggersSpec::default(),
                emitter: EmitterSpec::GithubDispatch {
                    repo: "acme/api".into(),
                    event_type: "rebuild-on-cve".into(),
                    workflow: None,
                    token: Some("t".into()),
                    api_base: None,
                },
                rate_limit: RateLimitSpec::default(),
            },
        };
        assert!(sub.matches("debian:bookworm-slim", "acme/prod/api:latest"));
        assert!(!sub.matches("alpine:3.20", "acme/prod/api:latest"));
        assert!(!sub.matches("debian:bookworm-slim", "acme/dev/web:latest"));
    }
}
