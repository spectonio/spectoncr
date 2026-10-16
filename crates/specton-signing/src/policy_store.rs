//! Postgres-backed [`ImageVerificationPolicy`] store (design 001 B4).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::policy::{OnViolation, TrustedSigner, VerificationPolicy};

/// Scope filters for a stored policy (matches CRD `spec.scope`).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PolicyScope {
    #[serde(default)]
    pub projects: Vec<String>,
    #[serde(default)]
    pub repositories: Vec<String>,
}

impl PolicyScope {
    /// `*` or empty list matches everything.
    pub fn matches(&self, project: &str, repository: &str) -> bool {
        let project_ok = self.projects.is_empty()
            || self.projects.iter().any(|p| p == "*" || p == project);
        let repo_ok = self.repositories.is_empty()
            || self
                .repositories
                .iter()
                .any(|r| r == "*" || r == repository);
        project_ok && repo_ok
    }
}

/// JSON blob stored in `verification_policies.spec`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySpec {
    #[serde(default)]
    pub scope: PolicyScope,
    #[serde(default = "default_required")]
    pub required: bool,
    #[serde(default)]
    pub trusted_signers: Vec<TrustedSigner>,
    #[serde(default)]
    pub on_violation: OnViolation,
}

fn default_required() -> bool {
    true
}

impl PolicySpec {
    pub fn to_verification_policy(&self, id: Uuid, name: &str) -> VerificationPolicy {
        VerificationPolicy {
            id,
            name: name.to_string(),
            required: self.required,
            trusted_signers: self.trusted_signers.clone(),
            on_violation: self.on_violation,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredVerificationPolicy {
    pub id: Uuid,
    pub name: String,
    pub tenant: String,
    pub spec: PolicySpec,
    pub enabled: bool,
    pub on_violation: OnViolation,
    pub updated_at: DateTime<Utc>,
}

impl StoredVerificationPolicy {
    pub fn as_verification_policy(&self) -> VerificationPolicy {
        let mut vp = self.spec.to_verification_policy(self.id, &self.name);
        // Row-level on_violation wins when set independently of spec.
        vp.on_violation = self.on_violation;
        vp
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyStoreError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("invalid policy spec: {0}")]
    Spec(String),
}

#[async_trait]
pub trait PolicyStore: Send + Sync {
    async fn upsert(&self, policy: &StoredVerificationPolicy) -> Result<(), PolicyStoreError>;
    async fn get(
        &self,
        tenant: &str,
        name: &str,
    ) -> Result<Option<StoredVerificationPolicy>, PolicyStoreError>;
    async fn list_for_tenant(
        &self,
        tenant: &str,
    ) -> Result<Vec<StoredVerificationPolicy>, PolicyStoreError>;
    async fn delete(&self, tenant: &str, name: &str) -> Result<bool, PolicyStoreError>;
    /// First enabled policy whose scope matches `(project, repository)`.
    async fn resolve(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
    ) -> Result<Option<StoredVerificationPolicy>, PolicyStoreError>;
}

pub struct PgPolicyStore {
    pool: Pool<Postgres>,
}

impl PgPolicyStore {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PolicyStore for PgPolicyStore {
    async fn upsert(&self, policy: &StoredVerificationPolicy) -> Result<(), PolicyStoreError> {
        let spec = serde_json::to_value(&policy.spec)
            .map_err(|e| PolicyStoreError::Spec(e.to_string()))?;
        let on_violation = match policy.on_violation {
            OnViolation::Block => "block",
            OnViolation::Warn => "warn",
            OnViolation::Log => "log",
        };
        sqlx::query(
            "INSERT INTO verification_policies
                 (id, name, tenant, spec, enabled, on_violation, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (tenant, name) DO UPDATE SET
                 id = EXCLUDED.id,
                 spec = EXCLUDED.spec,
                 enabled = EXCLUDED.enabled,
                 on_violation = EXCLUDED.on_violation,
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(policy.id)
        .bind(&policy.name)
        .bind(&policy.tenant)
        .bind(spec)
        .bind(policy.enabled)
        .bind(on_violation)
        .bind(policy.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &str,
        name: &str,
    ) -> Result<Option<StoredVerificationPolicy>, PolicyStoreError> {
        let row: Option<(Uuid, String, String, serde_json::Value, bool, String, DateTime<Utc>)> =
            sqlx::query_as(
                "SELECT id, name, tenant, spec, enabled, on_violation, updated_at
                 FROM verification_policies
                 WHERE tenant = $1 AND name = $2",
            )
            .bind(tenant)
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(row_to_policy).transpose()?)
    }

    async fn list_for_tenant(
        &self,
        tenant: &str,
    ) -> Result<Vec<StoredVerificationPolicy>, PolicyStoreError> {
        let rows: Vec<(Uuid, String, String, serde_json::Value, bool, String, DateTime<Utc>)> =
            sqlx::query_as(
                "SELECT id, name, tenant, spec, enabled, on_violation, updated_at
                 FROM verification_policies
                 WHERE tenant = $1
                 ORDER BY name",
            )
            .bind(tenant)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(row_to_policy).collect()
    }

    async fn delete(&self, tenant: &str, name: &str) -> Result<bool, PolicyStoreError> {
        let r = sqlx::query("DELETE FROM verification_policies WHERE tenant = $1 AND name = $2")
            .bind(tenant)
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    async fn resolve(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
    ) -> Result<Option<StoredVerificationPolicy>, PolicyStoreError> {
        let policies = self.list_for_tenant(tenant).await?;
        Ok(policies
            .into_iter()
            .filter(|p| p.enabled)
            .find(|p| p.spec.scope.matches(project, repository)))
    }
}

fn parse_on_violation(s: &str) -> OnViolation {
    match s {
        "warn" => OnViolation::Warn,
        "log" => OnViolation::Log,
        _ => OnViolation::Block,
    }
}

fn row_to_policy(
    (id, name, tenant, spec_val, enabled, on_violation, updated_at): (
        Uuid,
        String,
        String,
        serde_json::Value,
        bool,
        String,
        DateTime<Utc>,
    ),
) -> Result<StoredVerificationPolicy, PolicyStoreError> {
    let spec: PolicySpec =
        serde_json::from_value(spec_val).map_err(|e| PolicyStoreError::Spec(e.to_string()))?;
    Ok(StoredVerificationPolicy {
        id,
        name,
        tenant,
        spec,
        enabled,
        on_violation: parse_on_violation(&on_violation),
        updated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_wildcard_and_exact() {
        let s = PolicyScope {
            projects: vec!["prod".into()],
            repositories: vec!["*".into()],
        };
        assert!(s.matches("prod", "api"));
        assert!(!s.matches("dev", "api"));

        let all = PolicyScope::default();
        assert!(all.matches("anything", "goes"));
    }
}
