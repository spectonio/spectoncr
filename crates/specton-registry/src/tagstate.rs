//! Tag immutability + quarantine state machine (design 003).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use specton_common::errors::RegistryError;
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TagState {
    Pending,
    Scanning,
    Approved,
    Quarantined,
    Promoted,
}

impl TagState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Scanning => "scanning",
            Self::Approved => "approved",
            Self::Quarantined => "quarantined",
            Self::Promoted => "promoted",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "scanning" => Some(Self::Scanning),
            "approved" => Some(Self::Approved),
            "quarantined" => Some(Self::Quarantined),
            "promoted" => Some(Self::Promoted),
            _ => None,
        }
    }

    /// Pull allowed without bypass when in these states.
    pub fn pull_allowed(self) -> bool {
        matches!(self, Self::Approved | Self::Promoted)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TagRef {
    pub tenant: String,
    pub project: String,
    pub repository: String,
    pub tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagRecord {
    pub id: Uuid,
    pub tenant: String,
    pub project: String,
    pub repository: String,
    pub tag: String,
    pub digest: String,
    pub state: TagState,
    pub state_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    pub id: i64,
    pub from_state: Option<TagState>,
    pub to_state: TagState,
    pub reason: Option<String>,
    pub actor: String,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectSettings {
    pub immutable_tags: bool,
    pub quarantine_default: bool,
}

#[derive(Clone)]
pub struct TagStateService {
    pool: Option<PgPool>,
    on_db_error: String,
}

impl TagStateService {
    pub fn new(pool: Option<PgPool>, on_db_error: String) -> Self {
        Self { pool, on_db_error }
    }

    fn degrade(&self, op: &str, err: impl std::fmt::Display) -> RegistryError {
        if self.on_db_error == "degrade" {
            warn!(op, error = %err, "tagstate db error (degraded)");
            RegistryError::Internal(format!("tagstate degraded: {op}"))
        } else {
            RegistryError::Internal(format!("tagstate {op}: {err}"))
        }
    }

    fn pool(&self) -> Option<&PgPool> {
        self.pool.as_ref()
    }

    pub fn transition_allowed(from: TagState, to: TagState) -> bool {
        use TagState::*;
        if from == to {
            return true;
        }
        matches!(
            (from, to),
            (Pending, Scanning)
                | (Pending, Approved)
                | (Pending, Quarantined)
                | (Scanning, Approved)
                | (Scanning, Quarantined)
                | (Approved, Quarantined)
                | (Approved, Promoted)
                | (Quarantined, Approved)
        )
    }

    pub async fn project_settings(
        &self,
        tenant: &str,
        project: &str,
    ) -> Result<ProjectSettings, RegistryError> {
        let Some(pool) = self.pool() else {
            return Ok(ProjectSettings::default());
        };
        let row = sqlx::query_as::<_, (bool, bool)>(
            "SELECT immutable_tags, quarantine_default FROM project_settings WHERE tenant = $1 AND project = $2",
        )
        .bind(tenant)
        .bind(project)
        .fetch_optional(pool)
        .await
        .map_err(|e| self.degrade("project_settings", e))?;

        Ok(match row {
            Some((immutable_tags, quarantine_default)) => ProjectSettings {
                immutable_tags,
                quarantine_default,
            },
            None => ProjectSettings::default(),
        })
    }

    pub async fn upsert_project_settings(
        &self,
        tenant: &str,
        project: &str,
        immutable_tags: bool,
        quarantine_default: bool,
    ) -> Result<ProjectSettings, RegistryError> {
        let Some(pool) = self.pool() else {
            return Ok(ProjectSettings {
                immutable_tags,
                quarantine_default,
            });
        };
        sqlx::query(
            "INSERT INTO project_settings (tenant, project, immutable_tags, quarantine_default)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant, project) DO UPDATE SET
               immutable_tags = EXCLUDED.immutable_tags,
               quarantine_default = EXCLUDED.quarantine_default",
        )
        .bind(tenant)
        .bind(project)
        .bind(immutable_tags)
        .bind(quarantine_default)
        .execute(pool)
        .await
        .map_err(|e| self.degrade("upsert_project_settings", e))?;

        Ok(ProjectSettings {
            immutable_tags,
            quarantine_default,
        })
    }

    pub async fn check_immutable(
        &self,
        t: &TagRef,
        new_digest: &str,
        immutable: bool,
    ) -> Result<(), RegistryError> {
        if !immutable {
            return Ok(());
        }
        let Some(rec) = self.current(t).await? else {
            return Ok(());
        };
        if rec.digest != new_digest {
            return Err(RegistryError::ManifestTagImmutable {
                tag: t.tag.clone(),
                existing_digest: rec.digest,
                attempted_digest: new_digest.to_string(),
            });
        }
        Ok(())
    }

    pub async fn on_push(
        &self,
        t: &TagRef,
        digest: &str,
        actor: &str,
        quarantine_default: bool,
    ) -> Result<TagRecord, RegistryError> {
        let Some(pool) = self.pool() else {
            return Ok(TagRecord {
                id: Uuid::nil(),
                tenant: t.tenant.clone(),
                project: t.project.clone(),
                repository: t.repository.clone(),
                tag: t.tag.clone(),
                digest: digest.to_string(),
                state: if quarantine_default {
                    TagState::Pending
                } else {
                    TagState::Approved
                },
                state_reason: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            });
        };

        let initial = if quarantine_default {
            TagState::Pending
        } else {
            TagState::Approved
        };

        let mut tx = pool
            .begin()
            .await
            .map_err(|e| self.degrade("on_push begin", e))?;

        let existing = sqlx::query_as::<_, (Uuid, String, String)>(
            "SELECT id, digest, state FROM tag_records
             WHERE tenant = $1 AND project = $2 AND repository = $3 AND tag = $4
             FOR UPDATE",
        )
        .bind(&t.tenant)
        .bind(&t.project)
        .bind(&t.repository)
        .bind(&t.tag)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| self.degrade("on_push select", e))?;

        let (_id, from_state) = if let Some((id, old_digest, old_state)) = existing {
            let from = TagState::parse(&old_state).unwrap_or(TagState::Pending);
            if old_digest != digest {
                sqlx::query(
                    "UPDATE tag_records SET digest = $2, state = $3, state_reason = NULL, updated_at = NOW()
                     WHERE id = $1",
                )
                .bind(id)
                .bind(digest)
                .bind(initial.as_str())
                .execute(&mut *tx)
                .await
                .map_err(|e| self.degrade("on_push update", e))?;

                sqlx::query(
                    "INSERT INTO tag_transitions (tag_record_id, from_state, to_state, reason, actor)
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(id)
                .bind(from.as_str())
                .bind(initial.as_str())
                .bind("manifest push")
                .bind(actor)
                .execute(&mut *tx)
                .await
                .map_err(|e| self.degrade("on_push transition", e))?;
            } else {
                sqlx::query("UPDATE tag_records SET updated_at = NOW() WHERE id = $1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| self.degrade("on_push touch", e))?;
            }
            (id, Some(from))
        } else {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO tag_records (id, tenant, project, repository, tag, digest, state)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(id)
            .bind(&t.tenant)
            .bind(&t.project)
            .bind(&t.repository)
            .bind(&t.tag)
            .bind(digest)
            .bind(initial.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|e| self.degrade("on_push insert", e))?;

            sqlx::query(
                "INSERT INTO tag_transitions (tag_record_id, from_state, to_state, reason, actor)
                 VALUES ($1, NULL, $2, $3, $4)",
            )
            .bind(id)
            .bind(initial.as_str())
            .bind("manifest push")
            .bind(actor)
            .execute(&mut *tx)
            .await
            .map_err(|e| self.degrade("on_push transition insert", e))?;
            (id, None)
        };

        let _ = from_state;

        tx.commit()
            .await
            .map_err(|e| self.degrade("on_push commit", e))?;

        self.current(t)
            .await?
            .ok_or_else(|| RegistryError::Internal("tag record missing after on_push".into()))
    }

    pub async fn transition(
        &self,
        t: &TagRef,
        to: TagState,
        reason: &str,
        actor: &str,
    ) -> Result<TagRecord, RegistryError> {
        let Some(pool) = self.pool() else {
            return Ok(TagRecord {
                id: Uuid::nil(),
                tenant: t.tenant.clone(),
                project: t.project.clone(),
                repository: t.repository.clone(),
                tag: t.tag.clone(),
                digest: String::new(),
                state: to,
                state_reason: Some(reason.to_string()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            });
        };

        let mut tx = pool
            .begin()
            .await
            .map_err(|e| self.degrade("transition begin", e))?;

        let row = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, state FROM tag_records
             WHERE tenant = $1 AND project = $2 AND repository = $3 AND tag = $4
             FOR UPDATE",
        )
        .bind(&t.tenant)
        .bind(&t.project)
        .bind(&t.repository)
        .bind(&t.tag)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| self.degrade("transition select", e))?
        .ok_or_else(|| RegistryError::TagUnknown {
            tag: t.tag.clone(),
        })?;

        let (id, from_str) = row;
        let from = TagState::parse(&from_str).unwrap_or(TagState::Pending);
        if !Self::transition_allowed(from, to) {
            return Err(RegistryError::Forbidden {
                reason: format!("transition {from:?} → {to:?} not allowed"),
            });
        }

        let state_reason = if to == TagState::Quarantined {
            Some(reason.to_string())
        } else {
            None
        };

        sqlx::query(
            "UPDATE tag_records SET state = $2, state_reason = $3, updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(to.as_str())
        .bind(&state_reason)
        .execute(&mut *tx)
        .await
        .map_err(|e| self.degrade("transition update", e))?;

        sqlx::query(
            "INSERT INTO tag_transitions (tag_record_id, from_state, to_state, reason, actor)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(from.as_str())
        .bind(to.as_str())
        .bind(reason)
        .bind(actor)
        .execute(&mut *tx)
        .await
        .map_err(|e| self.degrade("transition audit", e))?;

        tx.commit()
            .await
            .map_err(|e| self.degrade("transition commit", e))?;

        self.current(t)
            .await?
            .ok_or_else(|| RegistryError::Internal("tag record missing after transition".into()))
    }

    pub async fn current(&self, t: &TagRef) -> Result<Option<TagRecord>, RegistryError> {
        let Some(pool) = self.pool() else {
            return Ok(None);
        };
        let row = sqlx::query_as::<_, TagRecordRow>(
            "SELECT id, tenant, project, repository, tag, digest, state, state_reason, created_at, updated_at
             FROM tag_records
             WHERE tenant = $1 AND project = $2 AND repository = $3 AND tag = $4",
        )
        .bind(&t.tenant)
        .bind(&t.project)
        .bind(&t.repository)
        .bind(&t.tag)
        .fetch_optional(pool)
        .await
        .map_err(|e| self.degrade("current", e))?;

        Ok(row.map(|r| r.into_record()))
    }

    pub async fn list(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
    ) -> Result<Vec<TagRecord>, RegistryError> {
        let Some(pool) = self.pool() else {
            return Ok(Vec::new());
        };
        let rows = sqlx::query_as::<_, TagRecordRow>(
            "SELECT id, tenant, project, repository, tag, digest, state, state_reason, created_at, updated_at
             FROM tag_records
             WHERE tenant = $1 AND project = $2 AND repository = $3
             ORDER BY updated_at DESC",
        )
        .bind(tenant)
        .bind(project)
        .bind(repository)
        .fetch_all(pool)
        .await
        .map_err(|e| self.degrade("list", e))?;

        Ok(rows.into_iter().map(|r| r.into_record()).collect())
    }

    pub async fn history(&self, t: &TagRef) -> Result<Vec<Transition>, RegistryError> {
        let Some(pool) = self.pool() else {
            return Ok(Vec::new());
        };
        let rec = self.current(t).await?;
        let Some(rec) = rec else {
            return Ok(Vec::new());
        };

        let rows = sqlx::query_as::<_, TransitionRow>(
            "SELECT id, from_state, to_state, reason, actor, at
             FROM tag_transitions WHERE tag_record_id = $1 ORDER BY at ASC",
        )
        .bind(rec.id)
        .fetch_all(pool)
        .await
        .map_err(|e| self.degrade("history", e))?;

        Ok(rows.into_iter().map(|r| r.into_transition()).collect())
    }
}

#[derive(sqlx::FromRow)]
struct TagRecordRow {
    id: Uuid,
    tenant: String,
    project: String,
    repository: String,
    tag: String,
    digest: String,
    state: String,
    state_reason: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TagRecordRow {
    fn into_record(self) -> TagRecord {
        TagRecord {
            id: self.id,
            tenant: self.tenant,
            project: self.project,
            repository: self.repository,
            tag: self.tag,
            digest: self.digest,
            state: TagState::parse(&self.state).unwrap_or(TagState::Pending),
            state_reason: self.state_reason,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TransitionRow {
    id: i64,
    from_state: Option<String>,
    to_state: String,
    reason: Option<String>,
    actor: String,
    at: DateTime<Utc>,
}

impl TransitionRow {
    fn into_transition(self) -> Transition {
        Transition {
            id: self.id,
            from_state: self.from_state.and_then(|s| TagState::parse(&s)),
            to_state: TagState::parse(&self.to_state).unwrap_or(TagState::Pending),
            reason: self.reason,
            actor: self.actor,
            at: self.at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_matrix() {
        assert!(TagStateService::transition_allowed(
            TagState::Pending,
            TagState::Approved
        ));
        assert!(TagStateService::transition_allowed(
            TagState::Quarantined,
            TagState::Approved
        ));
        assert!(!TagStateService::transition_allowed(
            TagState::Promoted,
            TagState::Approved
        ));
        assert!(TagState::Approved.pull_allowed());
        assert!(!TagState::Pending.pull_allowed());
    }

    #[tokio::test]
    async fn in_memory_no_pool_is_noop() {
        let svc = TagStateService::new(None, "fail".into());
        let t = TagRef {
            tenant: "t".into(),
            project: "p".into(),
            repository: "r".into(),
            tag: "v1".into(),
        };
        assert!(svc.current(&t).await.unwrap().is_none());
        assert!(svc.list("t", "p", "r").await.unwrap().is_empty());
        let rec = svc.on_push(&t, "sha256:abc", "sub", true).await.unwrap();
        assert_eq!(rec.state, TagState::Pending);
    }

    #[tokio::test]
    async fn optional_postgres_transitions() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(u) => u,
            Err(_) => {
                eprintln!("DATABASE_URL unset — skipping tagstate postgres test");
                return;
            }
        };
        let pool = PgPool::connect(&url).await.expect("connect");
        for stmt in include_str!("../../specton-db/migrations/0021_tag_state.sql").split(';') {
            let s = stmt.trim();
            if s.is_empty() {
                continue;
            }
            let _ = sqlx::query(s).execute(&pool).await;
        }

        let svc = TagStateService::new(Some(pool.clone()), "fail".into());
        let t = TagRef {
            tenant: format!("t-{}", Uuid::new_v4()),
            project: "p".into(),
            repository: "r".into(),
            tag: "v1".into(),
        };
        svc.upsert_project_settings(&t.tenant, &t.project, true, true)
            .await
            .unwrap();
        let rec = svc.on_push(&t, "sha256:aaa", "actor", true).await.unwrap();
        assert_eq!(rec.state, TagState::Pending);

        let err = svc
            .check_immutable(&t, "sha256:bbb", true)
            .await
            .unwrap_err();
        assert!(matches!(err, RegistryError::ManifestTagImmutable { .. }));

        let approved = svc
            .transition(&t, TagState::Approved, "manual", "admin")
            .await
            .unwrap();
        assert_eq!(approved.state, TagState::Approved);
    }
}
