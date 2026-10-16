//! Pull-time admission gate (design 002 D1–D3).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use specton_common::errors::RegistryError;
use specton_scanner::{EphemeralStore, Policy, PolicyEvaluation, PolicyStatus, ScanResult};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnUnknown {
    Block,
    Scan,
    Allow,
}

impl Default for OnUnknown {
    fn default() -> Self {
        Self::Block
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnTimeout {
    Block,
    Warn,
    Allow,
}

impl Default for OnTimeout {
    fn default() -> Self {
        Self::Block
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SeverityThreshold {
    #[serde(default)]
    pub block: specton_scanner::BlockRules,
    #[serde(default)]
    pub warn: specton_scanner::BlockRules,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AdmissionScope {
    #[serde(default)]
    pub projects: Vec<String>,
    #[serde(default)]
    pub repositories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionPolicySpec {
    #[serde(default)]
    pub scope: AdmissionScope,
    #[serde(default)]
    pub signature_required: bool,
    #[serde(default)]
    pub severity_threshold: SeverityThreshold,
    #[serde(default)]
    pub on_unknown: OnUnknown,
    #[serde(default)]
    pub on_timeout: OnTimeout,
    #[serde(default = "default_scan_wait")]
    pub scan_wait_secs: u64,
}

fn default_scan_wait() -> u64 {
    5
}

impl Default for AdmissionPolicySpec {
    fn default() -> Self {
        Self {
            scope: AdmissionScope::default(),
            signature_required: false,
            severity_threshold: SeverityThreshold::default(),
            on_unknown: OnUnknown::Block,
            on_timeout: OnTimeout::Block,
            scan_wait_secs: default_scan_wait(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    pub id: Uuid,
    pub name: String,
    pub tenant: String,
    pub spec: AdmissionPolicySpec,
    pub enabled: bool,
    pub updated_at: DateTime<Utc>,
}

impl AdmissionPolicy {
    pub fn matches_scope(&self, project: &str, repository: &str) -> bool {
        let projects_ok = self.spec.scope.projects.is_empty()
            || self
                .spec
                .scope
                .projects
                .iter()
                .any(|p| p == "*" || p == project);
        let repos_ok = self.spec.scope.repositories.is_empty()
            || self
                .spec
                .scope
                .repositories
                .iter()
                .any(|r| r == "*" || r == repository || glob_match(r, repository));
        projects_ok && repos_ok
    }
}

fn glob_match(pattern: &str, value: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        pattern == value
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum AdmissionVerdict {
    Allow,
    Warn { reason: String },
    Block { reason: String, code: String },
}

impl AdmissionVerdict {
    #[allow(dead_code)] // used by future dashboard / audit callers
    pub fn is_block(&self) -> bool {
        matches!(self, Self::Block { .. })
    }
}

#[derive(Clone)]
struct CacheEntry {
    verdict: AdmissionVerdict,
    expires: Instant,
}

/// Short-TTL decision cache (Redis substitute when Redis unavailable).
#[derive(Default)]
pub struct DecisionCache {
    inner: RwLock<HashMap<String, CacheEntry>>,
    ttl: Duration,
}

impl DecisionCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs.max(1)),
        }
    }

    pub async fn get(&self, key: &str) -> Option<AdmissionVerdict> {
        let guard = self.inner.read().await;
        let e = guard.get(key)?;
        if Instant::now() >= e.expires {
            return None;
        }
        Some(e.verdict.clone())
    }

    pub async fn put(&self, key: String, verdict: AdmissionVerdict) {
        let mut guard = self.inner.write().await;
        guard.insert(
            key,
            CacheEntry {
                verdict,
                expires: Instant::now() + self.ttl,
            },
        );
        // Opportunistic prune
        if guard.len() > 10_000 {
            let now = Instant::now();
            guard.retain(|_, v| v.expires > now);
        }
    }
}

pub struct EvaluateInput<'a> {
    pub tenant: &'a str,
    pub project: &'a str,
    pub repository: &'a str,
    pub digest: &'a str,
    /// Actor subject; reserved for audit attribution on the hot path.
    #[allow(dead_code)]
    pub subject: &'a str,
    pub bypass: bool,
    pub signature_ok: Option<bool>,
}

pub async fn evaluate(
    policies: &[AdmissionPolicy],
    scan: Option<&ScanResult>,
    cache: &DecisionCache,
    input: EvaluateInput<'_>,
) -> AdmissionVerdict {
    if input.bypass {
        return AdmissionVerdict::Allow;
    }

    let applicable: Vec<_> = policies
        .iter()
        .filter(|p| {
            p.enabled
                && p.tenant == input.tenant
                && p.matches_scope(input.project, input.repository)
        })
        .collect();

    if applicable.is_empty() {
        return AdmissionVerdict::Allow;
    }

    let mut worst = AdmissionVerdict::Allow;
    for policy in applicable {
        let cache_key = format!("admit:{}:{}", input.digest, policy.id);
        if let Some(cached) = cache.get(&cache_key).await {
            worst = merge_verdict(worst, cached);
            continue;
        }

        let v = evaluate_one(policy, scan, input.signature_ok);
        cache.put(cache_key, v.clone()).await;
        worst = merge_verdict(worst, v);
    }
    worst
}

fn merge_verdict(a: AdmissionVerdict, b: AdmissionVerdict) -> AdmissionVerdict {
    match (&a, &b) {
        (AdmissionVerdict::Block { .. }, _) => a,
        (_, AdmissionVerdict::Block { .. }) => b,
        (AdmissionVerdict::Warn { .. }, AdmissionVerdict::Allow) => a,
        (AdmissionVerdict::Allow, AdmissionVerdict::Warn { .. }) => b,
        _ => a,
    }
}

fn evaluate_one(
    policy: &AdmissionPolicy,
    scan: Option<&ScanResult>,
    signature_ok: Option<bool>,
) -> AdmissionVerdict {
    if policy.spec.signature_required {
        match signature_ok {
            Some(true) => {}
            Some(false) => {
                return AdmissionVerdict::Block {
                    reason: format!(
                        "policy {}: signature required but missing/invalid",
                        policy.name
                    ),
                    code: "MANIFEST_UNVERIFIED".into(),
                };
            }
            None => {
                // Signature check not performed by caller — treat as unknown.
                return AdmissionVerdict::Block {
                    reason: format!("policy {}: signature required", policy.name),
                    code: "MANIFEST_UNVERIFIED".into(),
                };
            }
        }
    }

    let Some(result) = scan else {
        return match policy.spec.on_unknown {
            OnUnknown::Allow => AdmissionVerdict::Allow,
            OnUnknown::Scan => AdmissionVerdict::Warn {
                reason: format!(
                    "policy {}: no scan result; scan-on-pull deferred",
                    policy.name
                ),
            },
            OnUnknown::Block => AdmissionVerdict::Block {
                reason: format!("policy {}: no scan result for digest", policy.name),
                code: "MANIFEST_UNVERIFIED".into(),
            },
        };
    };

    let block_policy = Policy {
        block_if: policy.spec.severity_threshold.block.clone(),
    };
    let block_eval = block_policy.evaluate(&result.vulnerabilities);
    if block_eval.status == PolicyStatus::Fail {
        return AdmissionVerdict::Block {
            reason: format!(
                "policy {}: {}",
                policy.name,
                block_eval
                    .reason
                    .unwrap_or_else(|| "severity threshold exceeded".into())
            ),
            code: "MANIFEST_UNVERIFIED".into(),
        };
    }

    let warn_policy = Policy {
        block_if: policy.spec.severity_threshold.warn.clone(),
    };
    let warn_eval = warn_policy.evaluate(&result.vulnerabilities);
    if warn_eval.status == PolicyStatus::Fail {
        return AdmissionVerdict::Warn {
            reason: format!(
                "policy {}: {}",
                policy.name,
                warn_eval
                    .reason
                    .unwrap_or_else(|| "warn threshold exceeded".into())
            ),
        };
    }

    let _ = PolicyEvaluation {
        status: PolicyStatus::Pass,
        violations: vec![],
        reason: None,
    };
    AdmissionVerdict::Allow
}

pub struct PgAdmissionStore {
    pool: sqlx::PgPool,
}

impl PgAdmissionStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    pub async fn upsert(&self, policy: &AdmissionPolicy) -> Result<(), RegistryError> {
        let spec = serde_json::to_value(&policy.spec)
            .map_err(|e| RegistryError::Internal(e.to_string()))?;
        sqlx::query(
            "INSERT INTO admission_policies (id, name, tenant, spec, enabled, updated_at)
             VALUES ($1,$2,$3,$4,$5,NOW())
             ON CONFLICT (tenant, name) DO UPDATE SET
               id = EXCLUDED.id,
               spec = EXCLUDED.spec,
               enabled = EXCLUDED.enabled,
               updated_at = NOW()",
        )
        .bind(policy.id)
        .bind(&policy.name)
        .bind(&policy.tenant)
        .bind(spec)
        .bind(policy.enabled)
        .execute(&self.pool)
        .await
        .map_err(|e| RegistryError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn list_tenant(&self, tenant: &str) -> Result<Vec<AdmissionPolicy>, RegistryError> {
        let rows = sqlx::query(
            "SELECT id, name, tenant, spec, enabled, updated_at
             FROM admission_policies WHERE tenant = $1 AND enabled = TRUE",
        )
        .bind(tenant)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RegistryError::Internal(e.to_string()))?;
        use sqlx::Row;
        let mut out = Vec::new();
        for r in rows {
            let spec: serde_json::Value = r.get("spec");
            let spec: AdmissionPolicySpec = serde_json::from_value(spec)
                .map_err(|e| RegistryError::Internal(format!("admission policy spec: {e}")))?;
            out.push(AdmissionPolicy {
                id: r.get("id"),
                name: r.get("name"),
                tenant: r.get("tenant"),
                spec,
                enabled: r.get("enabled"),
                updated_at: r.get("updated_at"),
            });
        }
        Ok(out)
    }

    #[allow(dead_code)] // controller / admin list path
    pub async fn list_all_enabled(&self) -> Result<Vec<AdmissionPolicy>, RegistryError> {
        let rows = sqlx::query(
            "SELECT id, name, tenant, spec, enabled, updated_at
             FROM admission_policies WHERE enabled = TRUE",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| RegistryError::Internal(e.to_string()))?;
        use sqlx::Row;
        let mut out = Vec::new();
        for r in rows {
            let spec: serde_json::Value = r.get("spec");
            let spec: AdmissionPolicySpec = serde_json::from_value(spec).unwrap_or_default();
            out.push(AdmissionPolicy {
                id: r.get("id"),
                name: r.get("name"),
                tenant: r.get("tenant"),
                spec,
                enabled: r.get("enabled"),
                updated_at: r.get("updated_at"),
            });
        }
        Ok(out)
    }

    pub async fn record_decision(
        &self,
        digest: &str,
        policy_id: Option<Uuid>,
        verdict: &AdmissionVerdict,
        subject: &str,
    ) -> Result<(), RegistryError> {
        let (v, reason) = match verdict {
            AdmissionVerdict::Allow => ("allow", None),
            AdmissionVerdict::Warn { reason } => ("warn", Some(reason.as_str())),
            AdmissionVerdict::Block { reason, .. } => ("block", Some(reason.as_str())),
        };
        sqlx::query(
            "INSERT INTO admission_decisions (digest, policy_id, verdict, reason, subject)
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(digest)
        .bind(policy_id)
        .bind(v)
        .bind(reason)
        .bind(subject)
        .execute(&self.pool)
        .await
        .map_err(|e| RegistryError::Internal(e.to_string()))?;
        Ok(())
    }
}

pub async fn fetch_scan(
    store: Option<&Arc<dyn EphemeralStore>>,
    digest: &str,
) -> Option<ScanResult> {
    let store = store?;
    store.get(digest).await.ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use specton_scanner::{ScanSummary, Severity, Vulnerability};

    fn vuln(sev: Severity) -> Vulnerability {
        Vulnerability {
            id: "CVE-1".into(),
            aliases: vec![],
            package: "glibc".into(),
            ecosystem: "deb".into(),
            installed_version: "1".into(),
            fixed_version: None,
            severity: sev,
            cvss_score: None,
            summary: None,
            description: None,
            layer_digest: None,
            references: vec![],
            suppressed: false,
        }
    }

    #[tokio::test]
    async fn blocks_on_critical() {
        let policy = AdmissionPolicy {
            id: Uuid::new_v4(),
            name: "prod".into(),
            tenant: "acme".into(),
            enabled: true,
            updated_at: Utc::now(),
            spec: AdmissionPolicySpec {
                severity_threshold: SeverityThreshold {
                    block: specton_scanner::BlockRules {
                        critical: Some(">0".into()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                on_unknown: OnUnknown::Allow,
                ..Default::default()
            },
        };
        let scan = ScanResult {
            id: Uuid::new_v4(),
            digest: "sha256:x".into(),
            tenant: "acme".into(),
            project: "prod".into(),
            repository: "api".into(),
            reference: "latest".into(),
            status: specton_scanner::ScanStatus::Completed,
            error: None,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            summary: ScanSummary::default(),
            vulnerabilities: vec![vuln(Severity::Critical)],
            policy_evaluation: None,
            packages: vec![],
        };
        let cache = DecisionCache::new(30);
        let v = evaluate(
            &[policy],
            Some(&scan),
            &cache,
            EvaluateInput {
                tenant: "acme",
                project: "prod",
                repository: "api",
                digest: "sha256:x",
                subject: "user",
                bypass: false,
                signature_ok: Some(true),
            },
        )
        .await;
        assert!(v.is_block());
    }

    #[tokio::test]
    async fn bypass_always_allows() {
        let policy = AdmissionPolicy {
            id: Uuid::new_v4(),
            name: "prod".into(),
            tenant: "acme".into(),
            enabled: true,
            updated_at: Utc::now(),
            spec: AdmissionPolicySpec {
                on_unknown: OnUnknown::Block,
                ..Default::default()
            },
        };
        let cache = DecisionCache::new(30);
        let v = evaluate(
            &[policy],
            None,
            &cache,
            EvaluateInput {
                tenant: "acme",
                project: "prod",
                repository: "api",
                digest: "sha256:x",
                subject: "user",
                bypass: true,
                signature_ok: None,
            },
        )
        .await;
        assert_eq!(v, AdmissionVerdict::Allow);
    }

    #[tokio::test]
    async fn unknown_blocks_by_default() {
        let policy = AdmissionPolicy {
            id: Uuid::new_v4(),
            name: "prod".into(),
            tenant: "acme".into(),
            enabled: true,
            updated_at: Utc::now(),
            spec: AdmissionPolicySpec::default(),
        };
        let cache = DecisionCache::new(30);
        let v = evaluate(
            &[policy],
            None,
            &cache,
            EvaluateInput {
                tenant: "acme",
                project: "prod",
                repository: "api",
                digest: "sha256:x",
                subject: "user",
                bypass: false,
                signature_ok: Some(true),
            },
        )
        .await;
        assert!(v.is_block());
    }
}
