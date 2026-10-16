//! Audit JSONL export + Merkle checkpoint.
//!
//! Slice A3: dump a contiguous id range to an [`ExportDestination`],
//! compute the Merkle root over `row_hash` leaves, and record a
//! checkpoint. Compression is optional zstd.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::event::AuditRow;
use crate::merkle::{as_hash32, merkle_root};
use crate::sink::{AuditError, AuditSink, EventId};

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("audit: {0}")]
    Audit(#[from] AuditError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("object store: {0}")]
    ObjectStore(String),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("nothing to export")]
    Empty,
    #[error("zstd: {0}")]
    Zstd(String),
}

/// Where exported JSONL (optionally `.zst`) is written.
#[async_trait]
pub trait ExportDestination: Send + Sync {
    async fn put(&self, key: &str, body: Bytes) -> Result<String, ExportError>;
}

/// In-memory destination for tests — returns `memory://{key}`.
#[derive(Default)]
pub struct MemoryDestination {
    pub objects: tokio::sync::RwLock<std::collections::HashMap<String, Bytes>>,
}

#[async_trait]
impl ExportDestination for MemoryDestination {
    async fn put(&self, key: &str, body: Bytes) -> Result<String, ExportError> {
        self.objects.write().await.insert(key.to_string(), body);
        Ok(format!("memory://{key}"))
    }
}

/// Local filesystem destination (`file://` URI in checkpoint).
pub struct FilesystemDestination {
    root: PathBuf,
}

impl FilesystemDestination {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

#[async_trait]
impl ExportDestination for FilesystemDestination {
    async fn put(&self, key: &str, body: Bytes) -> Result<String, ExportError> {
        let path = self.root.join(key);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&path, &body).await?;
        Ok(format!("file://{}", path.display()))
    }
}

/// Object-store backed destination (S3 / GCS / Azure / etc.).
pub struct ObjectStoreDestination {
    store: Arc<dyn object_store::ObjectStore>,
    /// URI prefix shown in checkpoints, e.g. `s3://bucket/audit`.
    uri_prefix: String,
}

impl ObjectStoreDestination {
    pub fn new(store: Arc<dyn object_store::ObjectStore>, uri_prefix: impl Into<String>) -> Self {
        Self {
            store,
            uri_prefix: uri_prefix.into().trim_end_matches('/').to_string(),
        }
    }
}

#[async_trait]
impl ExportDestination for ObjectStoreDestination {
    async fn put(&self, key: &str, body: Bytes) -> Result<String, ExportError> {
        let path = object_store::path::Path::from(key);
        self.store
            .put(&path, body.clone().into())
            .await
            .map_err(|e| ExportError::ObjectStore(e.to_string()))?;
        Ok(format!("{}/{}", self.uri_prefix, key))
    }
}

/// One JSONL line — hashes hex-encoded for portability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportLine {
    pub id: i64,
    pub at: DateTime<Utc>,
    pub tenant: Option<String>,
    pub category: String,
    pub action: String,
    pub actor_sub: String,
    pub actor_ip: Option<String>,
    pub actor_ua: Option<String>,
    pub subject: Option<serde_json::Value>,
    pub outcome: String,
    pub error_code: Option<String>,
    pub attributes: serde_json::Map<String, serde_json::Value>,
    pub prev_hash: Option<String>,
    pub row_hash: String,
    pub hmac_key_id: String,
}

impl From<&AuditRow> for ExportLine {
    fn from(row: &AuditRow) -> Self {
        Self {
            id: row.id,
            at: row.event.at,
            tenant: row.tenant.clone(),
            category: row.event.category.as_str().to_string(),
            action: row.event.action.clone(),
            actor_sub: row.event.actor.sub.clone(),
            actor_ip: row.event.actor.source_ip.clone(),
            actor_ua: row.event.actor.ua.clone(),
            subject: row
                .event
                .subject
                .as_ref()
                .and_then(|s| serde_json::to_value(s).ok()),
            outcome: row.event.outcome.as_str().to_string(),
            error_code: row.event.outcome.error_code().map(str::to_string),
            attributes: row.event.attributes.clone(),
            prev_hash: row.prev_hash.as_ref().map(hex::encode),
            row_hash: hex::encode(&row.row_hash),
            hmac_key_id: row.hmac_key_id.clone(),
        }
    }
}

/// Result of a successful export.
#[derive(Debug, Clone, Serialize)]
pub struct ExportResult {
    pub range_from: EventId,
    pub range_to: EventId,
    pub merkle_root: String,
    pub exported_to: String,
    pub row_count: u64,
    pub compressed: bool,
}

/// Build newline-delimited JSON bytes from rows (chain order ascending).
pub fn encode_jsonl(rows: &[AuditRow]) -> Result<Vec<u8>, ExportError> {
    let mut out = Vec::new();
    for row in rows {
        let line = ExportLine::from(row);
        serde_json::to_writer(&mut out, &line)?;
        out.push(b'\n');
    }
    Ok(out)
}

/// Optionally zstd-compress JSONL bytes.
pub fn maybe_compress(jsonl: &[u8], compress: bool) -> Result<(Vec<u8>, bool), ExportError> {
    if !compress {
        return Ok((jsonl.to_vec(), false));
    }
    zstd::encode_all(jsonl, 3)
        .map(|b| (b, true))
        .map_err(|e| ExportError::Zstd(e.to_string()))
}

/// Merkle root over the rows' `row_hash` values (ascending id order).
pub fn root_for_rows(rows: &[AuditRow]) -> Result<[u8; 32], ExportError> {
    let mut leaves = Vec::with_capacity(rows.len());
    for r in rows {
        let h = as_hash32(&r.row_hash).ok_or_else(|| {
            ExportError::Audit(AuditError::Unavailable(format!(
                "row {} has non-32-byte hash",
                r.id
            )))
        })?;
        leaves.push(h);
    }
    Ok(merkle_root(&leaves))
}

/// Content-addressed path segment: `audit/{yyyy}/{mm}/{dd}/{hh}-{from}-{to}.jsonl[.zst]`.
pub fn export_object_key(
    at: DateTime<Utc>,
    range_from: EventId,
    range_to: EventId,
    compressed: bool,
) -> String {
    let ext = if compressed { "jsonl.zst" } else { "jsonl" };
    format!(
        "audit/{}/{:02}/{:02}/{:02}-{}-{}.{}",
        at.format("%Y"),
        at.month(),
        at.day(),
        at.hour(),
        range_from,
        range_to,
        ext
    )
}

use chrono::Datelike;
use chrono::Timelike;

/// Export a concrete id range from any sink to a destination.
pub async fn export_range(
    sink: &dyn AuditSink,
    dest: &dyn ExportDestination,
    from: EventId,
    to: EventId,
    compress: bool,
) -> Result<(ExportResult, [u8; 32], Vec<AuditRow>), ExportError> {
    if to < from {
        return Err(ExportError::Empty);
    }
    // Fetch ascending by walking ids (query returns newest-first; re-get range).
    let mut rows = Vec::new();
    for id in from..=to {
        match sink.get(id).await {
            Ok(row) => rows.push(row),
            Err(AuditError::NotFound(_)) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    if rows.is_empty() {
        return Err(ExportError::Empty);
    }
    rows.sort_by_key(|r| r.id);
    let actual_from = rows.first().map(|r| r.id).unwrap();
    let actual_to = rows.last().map(|r| r.id).unwrap();

    let root = root_for_rows(&rows)?;
    let jsonl = encode_jsonl(&rows)?;
    let (body, compressed) = maybe_compress(&jsonl, compress)?;
    let key = export_object_key(Utc::now(), actual_from, actual_to, compressed);
    let exported_to = dest.put(&key, Bytes::from(body)).await?;

    Ok((
        ExportResult {
            range_from: actual_from,
            range_to: actual_to,
            merkle_root: hex::encode(root),
            exported_to,
            row_count: rows.len() as u64,
            compressed,
        },
        root,
        rows,
    ))
}

/// Integrity check: re-hash JSONL lines' `row_hash` field into a Merkle root.
pub fn verify_export_bytes(jsonl: &[u8]) -> Result<[u8; 32], ExportError> {
    let mut leaves = Vec::new();
    for line in jsonl.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let parsed: ExportLine = serde_json::from_slice(line)?;
        let bytes = hex::decode(&parsed.row_hash)
            .map_err(|e| ExportError::Audit(AuditError::Unavailable(e.to_string())))?;
        let h = as_hash32(&bytes).ok_or_else(|| {
            ExportError::Audit(AuditError::Unavailable("bad row_hash length".into()))
        })?;
        leaves.push(h);
    }
    if leaves.is_empty() {
        return Err(ExportError::Empty);
    }
    Ok(merkle_root(&leaves))
}

/// SHA-256 of the raw export body (useful as an additional digest).
pub fn content_digest(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Actor, AuditEvent, Category};
    use crate::memory::InMemoryAudit;

    #[tokio::test]
    async fn export_round_trip_merkle() {
        let sink = InMemoryAudit::for_tests();
        for i in 0..5 {
            sink.append(AuditEvent::success(
                Category::Push,
                format!("manifest.push.{i}"),
                Actor::system(),
            ))
            .await
            .unwrap();
        }
        let dest = MemoryDestination::default();
        let (result, root, _) = export_range(&sink, &dest, 1, 5, false).await.unwrap();
        assert_eq!(result.row_count, 5);
        assert_eq!(result.merkle_root, hex::encode(root));

        let key = dest.objects.read().await.keys().next().unwrap().clone();
        let body = dest.objects.read().await.get(&key).unwrap().clone();
        let verified = verify_export_bytes(&body).unwrap();
        assert_eq!(verified, root);
    }

    #[tokio::test]
    async fn export_zstd_round_trip() {
        let sink = InMemoryAudit::for_tests();
        sink.append(AuditEvent::success(
            Category::Delete,
            "manifest.delete",
            Actor::system(),
        ))
        .await
        .unwrap();
        let dest = MemoryDestination::default();
        let (result, root, _) = export_range(&sink, &dest, 1, 1, true).await.unwrap();
        assert!(result.compressed);
        let key = dest.objects.read().await.keys().next().unwrap().clone();
        let body = dest.objects.read().await.get(&key).unwrap().clone();
        let jsonl = zstd::decode_all(body.as_ref()).unwrap();
        assert_eq!(verify_export_bytes(&jsonl).unwrap(), root);
    }
}
