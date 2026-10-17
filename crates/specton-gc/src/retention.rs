//! Per-project tag retention (design 004 slice 3).

use crate::refcount::GcError;
use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Effective retention policy for a project (CRD + DB overlay).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RetentionPolicy {
    pub max_tag_count: Option<i32>,
    pub expire_days: Option<i32>,
    pub keep_regex: Option<String>,
    pub always_keep: Vec<String>,
    pub dry_run: bool,
    pub respect_promotion: bool,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_tag_count: None,
            expire_days: None,
            keep_regex: None,
            always_keep: Vec::new(),
            dry_run: false,
            respect_promotion: true,
        }
    }
}

impl RetentionPolicy {
    /// Build from controller CRD fields (`tenancy::RetentionPolicy`).
    pub fn from_crd(
        max_tag_age: Option<&str>,
        keep_last_n: Option<i32>,
        keep_semver: bool,
        expire_days: Option<i32>,
        keep_regex: Option<String>,
        always_keep: Option<Vec<String>>,
        dry_run: Option<bool>,
        respect_promotion: Option<bool>,
    ) -> Self {
        let always = always_keep.unwrap_or_default();
        let regex = keep_regex.or_else(|| {
            if keep_semver {
                Some(r"^v\d+\.\d+\.\d+$".into())
            } else {
                None
            }
        });
        let expire = expire_days.or_else(|| max_tag_age.and_then(parse_max_tag_age_days));
        Self {
            max_tag_count: keep_last_n,
            expire_days: expire,
            keep_regex: regex,
            always_keep: always,
            dry_run: dry_run.unwrap_or(false),
            respect_promotion: respect_promotion.unwrap_or(true),
        }
    }
}

/// Tag row used for pure keep-set computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagInfo {
    pub repository: String,
    pub tag: String,
    pub pushed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetentionReport {
    pub tags_kept: u32,
    pub tags_deleted: u32,
    pub deleted: Vec<String>,
    pub dry_run: bool,
}

pub struct RetentionRunner {
    pool: Pool<Postgres>,
}

impl RetentionRunner {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    pub async fn apply(
        &self,
        tenant: &str,
        project: &str,
        policy: &RetentionPolicy,
    ) -> Result<RetentionReport, GcError> {
        let run_id = Uuid::new_v4();
        let now = Utc::now();

        let tags = self.load_tags(tenant, project).await?;
        let promoted = if policy.respect_promotion {
            load_promoted_tags(&self.pool, tenant, project).await?
        } else {
            HashSet::new()
        };

        let to_delete = compute_deletes(&tags, policy, &promoted, now);
        let kept = tags.len().saturating_sub(to_delete.len()) as u32;
        let dry_run = policy.dry_run;

        if dry_run {
            for key in &to_delete {
                info!(tenant, project, tag = %key, "retention dry-run: would delete tag");
            }
        } else {
            for key in &to_delete {
                if let Some((repo, tag)) = split_tag_key(key) {
                    let r = sqlx::query(
                        "DELETE FROM tags
                         WHERE tenant = $1 AND project = $2
                           AND repository = $3 AND tag = $4",
                    )
                    .bind(tenant)
                    .bind(project)
                    .bind(repo)
                    .bind(tag)
                    .execute(&self.pool)
                    .await?;
                    if r.rows_affected() > 0 {
                        debug!(tenant, project, repository = repo, tag, "retention deleted tag row");
                    }
                }
            }
        }

        sqlx::query(
            "INSERT INTO retention_runs
                 (id, tenant, project, tags_kept, tags_deleted, dry_run)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(run_id)
        .bind(tenant)
        .bind(project)
        .bind(kept as i32)
        .bind(to_delete.len() as i32)
        .bind(dry_run)
        .execute(&self.pool)
        .await?;

        Ok(RetentionReport {
            tags_kept: kept,
            tags_deleted: to_delete.len() as u32,
            deleted: to_delete,
            dry_run,
        })
    }

    pub async fn upsert_policy(
        &self,
        tenant: &str,
        project: &str,
        policy: &RetentionPolicy,
    ) -> Result<(), GcError> {
        sqlx::query(
            "INSERT INTO retention_policies
                 (tenant, project, max_tag_count, expire_days, keep_regex,
                  always_keep, dry_run, respect_promotion, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
             ON CONFLICT (tenant, project) DO UPDATE SET
                 max_tag_count = EXCLUDED.max_tag_count,
                 expire_days = EXCLUDED.expire_days,
                 keep_regex = EXCLUDED.keep_regex,
                 always_keep = EXCLUDED.always_keep,
                 dry_run = EXCLUDED.dry_run,
                 respect_promotion = EXCLUDED.respect_promotion,
                 updated_at = NOW()",
        )
        .bind(tenant)
        .bind(project)
        .bind(policy.max_tag_count)
        .bind(policy.expire_days)
        .bind(&policy.keep_regex)
        .bind(&policy.always_keep)
        .bind(policy.dry_run)
        .bind(policy.respect_promotion)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_policy(
        &self,
        tenant: &str,
        project: &str,
    ) -> Result<Option<RetentionPolicy>, GcError> {
        let row: Option<RetentionPolicyRow> = sqlx::query_as(
            "SELECT max_tag_count, expire_days, keep_regex, always_keep,
                    dry_run, respect_promotion
             FROM retention_policies
             WHERE tenant = $1 AND project = $2",
        )
        .bind(tenant)
        .bind(project)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.into_policy()))
    }

    async fn load_tags(&self, tenant: &str, project: &str) -> Result<Vec<TagInfo>, GcError> {
        let rows: Vec<TagRow> = sqlx::query_as(
            "SELECT repository, tag, pushed_at
             FROM tags
             WHERE tenant = $1 AND project = $2",
        )
        .bind(tenant)
        .bind(project)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| TagInfo {
                repository: r.repository,
                tag: r.tag,
                pushed_at: r.pushed_at,
            })
            .collect())
    }
}

#[derive(sqlx::FromRow)]
struct TagRow {
    repository: String,
    tag: String,
    pushed_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct RetentionPolicyRow {
    max_tag_count: Option<i32>,
    expire_days: Option<i32>,
    keep_regex: Option<String>,
    always_keep: Vec<String>,
    dry_run: bool,
    respect_promotion: bool,
}

impl RetentionPolicyRow {
    fn into_policy(self) -> RetentionPolicy {
        RetentionPolicy {
            max_tag_count: self.max_tag_count,
            expire_days: self.expire_days,
            keep_regex: self.keep_regex,
            always_keep: self.always_keep,
            dry_run: self.dry_run,
            respect_promotion: self.respect_promotion,
        }
    }
}

fn tag_key(repo: &str, tag: &str) -> String {
    format!("{repo}/{tag}")
}

fn split_tag_key(key: &str) -> Option<(&str, &str)> {
    key.split_once('/')
}

/// Pure keep-set: returns `repository/tag` keys to delete.
pub fn compute_deletes(
    tags: &[TagInfo],
    policy: &RetentionPolicy,
    promoted: &HashSet<(String, String)>,
    now: DateTime<Utc>,
) -> Vec<String> {
    let regex = policy
        .keep_regex
        .as_ref()
        .and_then(|p| Regex::new(p).ok());

    let always: HashSet<&str> = policy
        .always_keep
        .iter()
        .map(|s| s.as_str())
        .collect();

    let mut by_repo: HashMap<&str, Vec<&TagInfo>> = HashMap::new();
    for t in tags {
        by_repo.entry(t.repository.as_str()).or_default().push(t);
    }

    let mut keep: HashSet<String> = HashSet::new();

    for (repo, repo_tags) in &by_repo {
        for t in repo_tags.iter() {
            if always.contains(t.tag.as_str()) {
                keep.insert(tag_key(repo, &t.tag));
            }
            if let Some(re) = regex.as_ref() {
                if re.is_match(&t.tag) {
                    keep.insert(tag_key(repo, &t.tag));
                }
            }
            if let Some(days) = policy.expire_days {
                if days > 0 {
                    let cutoff = now - Duration::days(days as i64);
                    if t.pushed_at >= cutoff {
                        keep.insert(tag_key(repo, &t.tag));
                    }
                }
            }
        }

        if let Some(n) = policy.max_tag_count {
            if n > 0 {
                let mut sorted: Vec<&TagInfo> = repo_tags.to_vec();
                sorted.sort_by(|a, b| b.pushed_at.cmp(&a.pushed_at));
                for t in sorted.into_iter().take(n as usize) {
                    keep.insert(tag_key(repo, &t.tag));
                }
            }
        }
    }

    let mut deletes = Vec::new();
    for t in tags {
        let key = tag_key(&t.repository, &t.tag);
        if keep.contains(&key) {
            continue;
        }
        if policy.respect_promotion
            && promoted.contains(&(t.repository.clone(), t.tag.clone()))
        {
            continue;
        }
        deletes.push(key);
    }
    deletes.sort();
    deletes
}

async fn load_promoted_tags(
    pool: &Pool<Postgres>,
    tenant: &str,
    project: &str,
) -> Result<HashSet<(String, String)>, GcError> {
    let result = sqlx::query_as::<_, (String, String)>(
        "SELECT repository, tag FROM tag_records
         WHERE tenant = $1 AND project = $2 AND state = 'promoted'",
    )
    .bind(tenant)
    .bind(project)
    .fetch_all(pool)
    .await;

    match result {
        Ok(rows) => Ok(rows.into_iter().collect()),
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("42P01") => {
            warn!("tag_records table missing; skipping promotion filter");
            Ok(HashSet::new())
        }
        Err(e) => Err(e.into()),
    }
}

/// Parse `maxTagAge` strings like `90d`, `12w`, `6m`, `1y` into days.
pub fn parse_max_tag_age_days(raw: &str) -> Option<i32> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (num, unit) = raw.split_at(raw.len().saturating_sub(1));
    let n: i32 = num.parse().ok()?;
    match unit {
        "d" => Some(n),
        "w" => n.checked_mul(7),
        "m" => n.checked_mul(30),
        "y" => n.checked_mul(365),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tag(repo: &str, name: &str, days_ago: i64) -> TagInfo {
        TagInfo {
            repository: repo.into(),
            tag: name.into(),
            pushed_at: Utc::now() - Duration::days(days_ago),
        }
    }

    #[test]
    fn always_keep_and_count() {
        let tags = vec![
            tag("app", "latest", 100),
            tag("app", "v1", 10),
            tag("app", "v2", 5),
            tag("app", "v3", 1),
        ];
        let policy = RetentionPolicy {
            max_tag_count: Some(2),
            always_keep: vec!["latest".into()],
            ..Default::default()
        };
        let del = compute_deletes(&tags, &policy, &HashSet::new(), Utc::now());
        assert!(del.contains(&"app/v1".into()));
        assert!(!del.contains(&"app/latest".into()));
        assert!(!del.contains(&"app/v3".into()));
        assert!(!del.contains(&"app/v2".into()));
    }

    #[test]
    fn expire_days_keeps_recent() {
        let tags = vec![tag("app", "old", 100), tag("app", "new", 1)];
        let policy = RetentionPolicy {
            expire_days: Some(30),
            ..Default::default()
        };
        let del = compute_deletes(&tags, &policy, &HashSet::new(), Utc::now());
        assert_eq!(del, vec!["app/old"]);
    }

    #[test]
    fn regex_keep() {
        let tags = vec![tag("app", "v1.0.0", 200), tag("app", "dev", 1)];
        let policy = RetentionPolicy {
            keep_regex: Some(r"^v\d+\.\d+\.\d+$".into()),
            ..Default::default()
        };
        let del = compute_deletes(&tags, &policy, &HashSet::new(), Utc::now());
        assert_eq!(del, vec!["app/dev"]);
    }

    #[test]
    fn promoted_skipped() {
        let tags = vec![tag("app", "x", 100)];
        let policy = RetentionPolicy {
            expire_days: Some(1),
            respect_promotion: true,
            ..Default::default()
        };
        let mut promoted = HashSet::new();
        promoted.insert(("app".into(), "x".into()));
        let del = compute_deletes(&tags, &policy, &promoted, Utc::now());
        assert!(del.is_empty());
    }

    #[test]
    fn parse_age() {
        assert_eq!(parse_max_tag_age_days("90d"), Some(90));
        assert_eq!(parse_max_tag_age_days("2w"), Some(14));
    }
}
