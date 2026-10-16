//! Postgres-backed hash-chained audit sink.
//!
//! Schema: `migrations/0017_registry_audit.sql`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{Pool, Postgres, Row};
use tokio::sync::RwLock;

use crate::event::{Actor, AuditEvent, AuditRow, Category, Outcome, Subject};
use crate::hash::{GENESIS_PREV, compute_row_hash};
use crate::sink::{AuditError, AuditQuery, AuditSink, ChainVerdict, EventId};

/// HMAC key material keyed by `hmac_key_id`.
#[derive(Clone)]
pub struct Keyring {
    active_id: String,
    keys: HashMap<String, Vec<u8>>,
}

impl Keyring {
    pub fn single(id: impl Into<String>, key: impl Into<Vec<u8>>) -> Self {
        let id = id.into();
        let key = key.into();
        let mut keys = HashMap::new();
        keys.insert(id.clone(), key);
        Self {
            active_id: id,
            keys,
        }
    }

    pub fn active_id(&self) -> &str {
        &self.active_id
    }

    pub fn active_key(&self) -> Result<&[u8], AuditError> {
        self.keys
            .get(&self.active_id)
            .map(|k| k.as_slice())
            .ok_or_else(|| AuditError::UnknownKey(self.active_id.clone()))
    }

    pub fn get(&self, id: &str) -> Result<&[u8], AuditError> {
        self.keys
            .get(id)
            .map(|k| k.as_slice())
            .ok_or_else(|| AuditError::UnknownKey(id.to_string()))
    }

    pub fn rotate(&mut self, new_id: impl Into<String>, new_key: impl Into<Vec<u8>>) {
        let new_id = new_id.into();
        self.keys.insert(new_id.clone(), new_key.into());
        self.active_id = new_id;
    }
}

pub struct PgChainedAudit {
    pool: Pool<Postgres>,
    keyring: Arc<RwLock<Keyring>>,
}

impl PgChainedAudit {
    pub fn new(pool: Pool<Postgres>, keyring: Keyring) -> Self {
        Self {
            pool,
            keyring: Arc::new(RwLock::new(keyring)),
        }
    }

    pub fn pool(&self) -> &Pool<Postgres> {
        &self.pool
    }

    /// Ensure the active key id is registered in `registry_audit_keys`.
    pub async fn ensure_key_row(&self) -> Result<(), AuditError> {
        let kr = self.keyring.read().await;
        sqlx::query(
            "INSERT INTO registry_audit_keys (key_id, active)
             VALUES ($1, TRUE)
             ON CONFLICT (key_id) DO UPDATE SET active = TRUE",
        )
        .bind(kr.active_id())
        .execute(&self.pool)
        .await?;
        // Mark others inactive.
        sqlx::query("UPDATE registry_audit_keys SET active = FALSE WHERE key_id <> $1")
            .bind(kr.active_id())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn rotate_key(
        &self,
        new_id: impl Into<String>,
        new_key: impl Into<Vec<u8>>,
    ) -> Result<(), AuditError> {
        let new_id = new_id.into();
        let new_key = new_key.into();
        {
            let mut kr = self.keyring.write().await;
            kr.rotate(new_id.clone(), new_key);
        }
        self.ensure_key_row().await
    }

    fn tenant_of(event: &AuditEvent) -> Option<String> {
        event.subject.as_ref().and_then(|s| s.tenant.clone())
    }

    #[allow(clippy::too_many_arguments)]
    fn row_from_db(
        id: i64,
        at: DateTime<Utc>,
        tenant: Option<String>,
        category: String,
        action: String,
        actor_sub: String,
        actor_ip: Option<String>,
        actor_ua: Option<String>,
        subject: Option<Value>,
        outcome: String,
        error_code: Option<String>,
        attributes: Value,
        prev_hash: Option<Vec<u8>>,
        row_hash: Vec<u8>,
        hmac_key_id: String,
    ) -> Result<AuditRow, AuditError> {
        let category = Category::parse(&category).ok_or_else(|| {
            AuditError::Unavailable(format!("unknown category in row {id}: {category}"))
        })?;
        let outcome = match outcome.as_str() {
            "success" => Outcome::Success,
            "failure" => Outcome::Failure {
                code: error_code.clone().unwrap_or_else(|| "unknown".into()),
            },
            other => {
                return Err(AuditError::Unavailable(format!(
                    "unknown outcome in row {id}: {other}"
                )));
            }
        };
        let subject: Option<Subject> = match subject {
            Some(v) => Some(serde_json::from_value(v)?),
            None => None,
        };
        let attributes = match attributes {
            Value::Object(m) => m,
            _ => Default::default(),
        };
        Ok(AuditRow {
            id,
            tenant,
            prev_hash,
            row_hash,
            hmac_key_id,
            event: AuditEvent {
                at,
                category,
                action,
                actor: Actor {
                    sub: actor_sub,
                    role: None,
                    source_ip: actor_ip,
                    ua: actor_ua,
                },
                subject,
                outcome,
                attributes,
            },
        })
    }
}

#[async_trait]
impl AuditSink for PgChainedAudit {
    async fn append(&self, event: AuditEvent) -> Result<EventId, AuditError> {
        let kr = self.keyring.read().await;
        let key = kr.active_key()?.to_vec();
        let key_id = kr.active_id().to_string();
        drop(kr);

        let mut tx = self.pool.begin().await?;

        // Lock the tip of the chain so concurrent appends serialize.
        let tip: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
            "SELECT row_hash FROM registry_audit_log ORDER BY id DESC LIMIT 1 FOR UPDATE",
        )
        .fetch_optional(&mut *tx)
        .await?;

        let prev_hash: [u8; 32] = match tip {
            Some((Some(bytes),)) if bytes.len() == 32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&bytes);
                buf
            }
            _ => GENESIS_PREV,
        };

        let row_hash = compute_row_hash(&key, &prev_hash, &event, &key_id)?;
        let tenant = Self::tenant_of(&event);
        let subject_json = match &event.subject {
            Some(s) => Some(serde_json::to_value(s)?),
            None => None,
        };
        let attributes = Value::Object(event.attributes.clone());

        let id: (i64,) = sqlx::query_as(
            "INSERT INTO registry_audit_log
                (at, tenant, category, action, actor_sub, actor_ip, actor_ua,
                 subject, outcome, error_code, attributes, prev_hash, row_hash, hmac_key_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
             RETURNING id",
        )
        .bind(event.at)
        .bind(&tenant)
        .bind(event.category.as_str())
        .bind(&event.action)
        .bind(&event.actor.sub)
        .bind(&event.actor.source_ip)
        .bind(&event.actor.ua)
        .bind(&subject_json)
        .bind(event.outcome.as_str())
        .bind(event.outcome.error_code())
        .bind(&attributes)
        .bind(prev_hash.as_slice())
        .bind(row_hash.as_slice())
        .bind(&key_id)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(id.0)
    }

    async fn query(&self, q: AuditQuery) -> Result<Vec<AuditRow>, AuditError> {
        let limit = if q.limit == 0 { 100 } else { q.limit } as i64;
        let category = q.category.map(|c| c.as_str().to_string());

        let rows = sqlx::query(
            "SELECT id, at, tenant, category, action, actor_sub, actor_ip, actor_ua,
                    subject, outcome, error_code, attributes, prev_hash, row_hash, hmac_key_id
             FROM registry_audit_log
             WHERE ($1::timestamptz IS NULL OR at >= $1)
               AND ($2::timestamptz IS NULL OR at <= $2)
               AND ($3::text IS NULL OR actor_sub = $3)
               AND ($4::text IS NULL OR category = $4)
               AND ($5::text IS NULL OR tenant = $5)
             ORDER BY id DESC
             LIMIT $6",
        )
        .bind(q.since)
        .bind(q.until)
        .bind(q.actor.as_deref())
        .bind(category.as_deref())
        .bind(q.tenant.as_deref())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(Self::row_from_db(
                r.get("id"),
                r.get("at"),
                r.get("tenant"),
                r.get("category"),
                r.get("action"),
                r.get("actor_sub"),
                r.get("actor_ip"),
                r.get("actor_ua"),
                r.get("subject"),
                r.get("outcome"),
                r.get("error_code"),
                r.get("attributes"),
                r.get("prev_hash"),
                r.get("row_hash"),
                r.get("hmac_key_id"),
            )?);
        }
        Ok(out)
    }

    async fn get(&self, id: EventId) -> Result<AuditRow, AuditError> {
        let r = sqlx::query(
            "SELECT id, at, tenant, category, action, actor_sub, actor_ip, actor_ua,
                    subject, outcome, error_code, attributes, prev_hash, row_hash, hmac_key_id
             FROM registry_audit_log WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AuditError::NotFound(id))?;

        Self::row_from_db(
            r.get("id"),
            r.get("at"),
            r.get("tenant"),
            r.get("category"),
            r.get("action"),
            r.get("actor_sub"),
            r.get("actor_ip"),
            r.get("actor_ua"),
            r.get("subject"),
            r.get("outcome"),
            r.get("error_code"),
            r.get("attributes"),
            r.get("prev_hash"),
            r.get("row_hash"),
            r.get("hmac_key_id"),
        )
    }

    async fn verify_chain(&self, from: EventId, to: EventId) -> Result<ChainVerdict, AuditError> {
        let rows = sqlx::query(
            "SELECT id, at, tenant, category, action, actor_sub, actor_ip, actor_ua,
                    subject, outcome, error_code, attributes, prev_hash, row_hash, hmac_key_id
             FROM registry_audit_log
             WHERE id >= $1 AND id <= $2
             ORDER BY id ASC",
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;

        let kr = self.keyring.read().await;
        let mut checked = 0u64;
        let mut expected_prev = GENESIS_PREV.to_vec();

        if from > 1 {
            let prior: Option<(Vec<u8>,)> = sqlx::query_as(
                "SELECT row_hash FROM registry_audit_log WHERE id < $1 ORDER BY id DESC LIMIT 1",
            )
            .bind(from)
            .fetch_optional(&self.pool)
            .await?;
            if let Some((h,)) = prior {
                expected_prev = h;
            }
        }

        for r in rows {
            let row = Self::row_from_db(
                r.get("id"),
                r.get("at"),
                r.get("tenant"),
                r.get("category"),
                r.get("action"),
                r.get("actor_sub"),
                r.get("actor_ip"),
                r.get("actor_ua"),
                r.get("subject"),
                r.get("outcome"),
                r.get("error_code"),
                r.get("attributes"),
                r.get("prev_hash"),
                r.get("row_hash"),
                r.get("hmac_key_id"),
            )?;

            let key = kr.get(&row.hmac_key_id)?;
            let mut prev = [0u8; 32];
            if expected_prev.len() != 32 {
                return Ok(ChainVerdict {
                    ok: false,
                    checked,
                    broken_at: Some(row.id),
                    expected_hash: Some(hex::encode(&expected_prev)),
                    actual_hash: row.prev_hash.as_ref().map(hex::encode),
                });
            }
            prev.copy_from_slice(&expected_prev);

            if let Some(ref stored_prev) = row.prev_hash
                && stored_prev.as_slice() != prev.as_slice()
            {
                return Ok(ChainVerdict {
                    ok: false,
                    checked,
                    broken_at: Some(row.id),
                    expected_hash: Some(hex::encode(prev)),
                    actual_hash: Some(hex::encode(stored_prev)),
                });
            }

            let expected = compute_row_hash(key, &prev, &row.event, &row.hmac_key_id)?;
            if expected.as_slice() != row.row_hash.as_slice() {
                return Ok(ChainVerdict {
                    ok: false,
                    checked,
                    broken_at: Some(row.id),
                    expected_hash: Some(hex::encode(expected)),
                    actual_hash: Some(hex::encode(&row.row_hash)),
                });
            }
            expected_prev = row.row_hash.clone();
            checked += 1;
        }

        Ok(ChainVerdict {
            ok: true,
            checked,
            broken_at: None,
            expected_hash: None,
            actual_hash: None,
        })
    }
}
