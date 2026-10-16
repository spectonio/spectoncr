//! Merkle checkpoint persistence for audit exports.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{Pool, Postgres};
use tokio::sync::RwLock;

use crate::export::{ExportDestination, ExportError, ExportResult, export_range};
use crate::sink::{AuditSink, EventId};

#[derive(Debug, Clone, Serialize)]
pub struct Checkpoint {
    pub id: i64,
    pub range_from: EventId,
    pub range_to: EventId,
    pub merkle_root: Vec<u8>,
    pub exported_to: Option<String>,
    pub at: DateTime<Utc>,
}

#[async_trait]
pub trait CheckpointStore: Send + Sync {
    async fn last(&self) -> Result<Option<Checkpoint>, ExportError>;
    async fn insert(
        &self,
        range_from: EventId,
        range_to: EventId,
        merkle_root: &[u8],
        exported_to: &str,
    ) -> Result<Checkpoint, ExportError>;
}

/// In-memory checkpoints for tests / memory backend.
#[derive(Default)]
pub struct MemoryCheckpointStore {
    rows: RwLock<Vec<Checkpoint>>,
    next_id: RwLock<i64>,
}

#[async_trait]
impl CheckpointStore for MemoryCheckpointStore {
    async fn last(&self) -> Result<Option<Checkpoint>, ExportError> {
        Ok(self.rows.read().await.last().cloned())
    }

    async fn insert(
        &self,
        range_from: EventId,
        range_to: EventId,
        merkle_root: &[u8],
        exported_to: &str,
    ) -> Result<Checkpoint, ExportError> {
        let mut id_guard = self.next_id.write().await;
        *id_guard += 1;
        let id = *id_guard;
        let cp = Checkpoint {
            id,
            range_from,
            range_to,
            merkle_root: merkle_root.to_vec(),
            exported_to: Some(exported_to.to_string()),
            at: Utc::now(),
        };
        self.rows.write().await.push(cp.clone());
        Ok(cp)
    }
}

pub struct PgCheckpointStore {
    pool: Pool<Postgres>,
}

impl PgCheckpointStore {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CheckpointStore for PgCheckpointStore {
    async fn last(&self) -> Result<Option<Checkpoint>, ExportError> {
        let row: Option<(i64, i64, i64, Vec<u8>, Option<String>, DateTime<Utc>)> = sqlx::query_as(
            "SELECT id, range_from, range_to, merkle_root, exported_to, at
                 FROM registry_audit_checkpoints
                 ORDER BY id DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ExportError::Audit(e.into()))?;
        Ok(row.map(
            |(id, range_from, range_to, merkle_root, exported_to, at)| Checkpoint {
                id,
                range_from,
                range_to,
                merkle_root,
                exported_to,
                at,
            },
        ))
    }

    async fn insert(
        &self,
        range_from: EventId,
        range_to: EventId,
        merkle_root: &[u8],
        exported_to: &str,
    ) -> Result<Checkpoint, ExportError> {
        let row: (i64, DateTime<Utc>) = sqlx::query_as(
            "INSERT INTO registry_audit_checkpoints
                (range_from, range_to, merkle_root, exported_to)
             VALUES ($1, $2, $3, $4)
             RETURNING id, at",
        )
        .bind(range_from)
        .bind(range_to)
        .bind(merkle_root)
        .bind(exported_to)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ExportError::Audit(e.into()))?;
        Ok(Checkpoint {
            id: row.0,
            range_from,
            range_to,
            merkle_root: merkle_root.to_vec(),
            exported_to: Some(exported_to.to_string()),
            at: row.1,
        })
    }
}

/// Highest event id known to the sink (best-effort via query).
pub async fn tip_id(sink: &dyn AuditSink) -> Result<Option<EventId>, ExportError> {
    let rows = sink
        .query(crate::sink::AuditQuery {
            limit: 1,
            ..Default::default()
        })
        .await?;
    Ok(rows.into_iter().next().map(|r| r.id))
}

/// Export every row after the last checkpoint (or from id 1).
pub async fn export_pending(
    sink: &dyn AuditSink,
    checkpoints: &dyn CheckpointStore,
    dest: &dyn ExportDestination,
    compress: bool,
) -> Result<ExportResult, ExportError> {
    let from = match checkpoints.last().await? {
        Some(cp) => cp.range_to + 1,
        None => 1,
    };
    let to = tip_id(sink).await?.ok_or(ExportError::Empty)?;
    if to < from {
        return Err(ExportError::Empty);
    }

    let (result, root, _) = export_range(sink, dest, from, to, compress).await?;
    checkpoints
        .insert(
            result.range_from,
            result.range_to,
            &root,
            &result.exported_to,
        )
        .await?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Actor, AuditEvent, Category};
    use crate::export::MemoryDestination;
    use crate::memory::InMemoryAudit;

    #[tokio::test]
    async fn pending_exports_incrementally() {
        let sink = InMemoryAudit::for_tests();
        let cps = MemoryCheckpointStore::default();
        let dest = MemoryDestination::default();

        for i in 0..3 {
            sink.append(AuditEvent::success(
                Category::Push,
                format!("p{i}"),
                Actor::system(),
            ))
            .await
            .unwrap();
        }
        let r1 = export_pending(&sink, &cps, &dest, false).await.unwrap();
        assert_eq!(r1.row_count, 3);

        // Nothing new → Empty
        assert!(matches!(
            export_pending(&sink, &cps, &dest, false).await,
            Err(ExportError::Empty)
        ));

        sink.append(AuditEvent::success(Category::Push, "p3", Actor::system()))
            .await
            .unwrap();
        let r2 = export_pending(&sink, &cps, &dest, false).await.unwrap();
        assert_eq!(r2.range_from, 4);
        assert_eq!(r2.row_count, 1);
    }
}
