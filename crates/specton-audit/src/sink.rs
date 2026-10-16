//! `AuditSink` trait — the only write surface for the chained log.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::event::{AuditEvent, AuditRow, Category};

/// Opaque event id (BIGSERIAL).
pub type EventId = i64;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("hash: {0}")]
    Hash(#[from] crate::hash::HashError),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("unknown hmac key id: {0}")]
    UnknownKey(String),
    #[error("chain broken at id {id}: expected {expected}, got {actual}")]
    ChainBroken {
        id: EventId,
        expected: String,
        actual: String,
    },
    #[error("not found: {0}")]
    NotFound(EventId),
    #[error("backend unavailable: {0}")]
    Unavailable(String),
}

#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub actor: Option<String>,
    pub category: Option<Category>,
    pub tenant: Option<String>,
    pub limit: usize,
}

impl AuditQuery {
    pub fn recent(limit: usize) -> Self {
        Self {
            limit,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainVerdict {
    pub ok: bool,
    pub checked: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_hash: Option<String>,
}

/// Append-only, queryable, verifiable audit sink.
#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn append(&self, event: AuditEvent) -> Result<EventId, AuditError>;

    async fn query(&self, q: AuditQuery) -> Result<Vec<AuditRow>, AuditError>;

    async fn get(&self, id: EventId) -> Result<AuditRow, AuditError>;

    async fn verify_chain(&self, from: EventId, to: EventId) -> Result<ChainVerdict, AuditError>;
}
