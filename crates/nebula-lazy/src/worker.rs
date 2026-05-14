//! Lazy-pull indexer worker.
//!
//! Claims jobs from `lazy_jobs` via FOR UPDATE SKIP LOCKED, dispatches
//! to a registered `TocIndexer` impl by format, and records the
//! result in `lazy_index` (or marks the job failed). Multiple workers
//! can run concurrently — SKIP LOCKED keeps them from claiming the
//! same row.
//!
//! Slice 2 ships the worker + a stub indexer. Slice 3 plugs in the
//! real eStargz / zstd-chunked / SOCI implementations.

use crate::indexer::{IndexFormat, LazyError, TocIndexer};
use crate::referrers::{PgReferrerStore, Referrer, ReferrerStore as _};
use bytes::Bytes;
use chrono::Utc;
use sqlx::{Pool, Postgres};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("indexer: {0}")]
    Indexer(#[from] LazyError),
    #[error("referrer: {0}")]
    Referrer(String),
}

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub idle_sleep: Duration,
    pub max_attempts: i32,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            idle_sleep: Duration::from_secs(15),
            max_attempts: 3,
        }
    }
}

pub struct WorkerControl {
    stop: AtomicBool,
}

impl WorkerControl {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            stop: AtomicBool::new(false),
        })
    }
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
    }
    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
}

/// Source of layer bytes by digest. The registry's ObjectStore
/// satisfies this once a small adapter wraps it (slice 3); for
/// slice-2 tests an in-memory map works too.
#[async_trait::async_trait]
pub trait LayerFetcher: Send + Sync {
    async fn fetch(&self, layer_digest: &str) -> Result<Bytes, LazyError>;
}

pub struct InMemoryLayerFetcher {
    pub blobs: HashMap<String, Bytes>,
}

#[async_trait::async_trait]
impl LayerFetcher for InMemoryLayerFetcher {
    async fn fetch(&self, layer_digest: &str) -> Result<Bytes, LazyError> {
        self.blobs
            .get(layer_digest)
            .cloned()
            .ok_or_else(|| LazyError::Storage(format!("missing layer {layer_digest}")))
    }
}

pub struct Worker {
    pool: Pool<Postgres>,
    fetcher: Arc<dyn LayerFetcher>,
    indexers: HashMap<IndexFormat, Arc<dyn TocIndexer>>,
    config: WorkerConfig,
    control: Arc<WorkerControl>,
}

impl Worker {
    pub fn new(
        pool: Pool<Postgres>,
        fetcher: Arc<dyn LayerFetcher>,
        indexers: Vec<Arc<dyn TocIndexer>>,
        config: WorkerConfig,
        control: Arc<WorkerControl>,
    ) -> Self {
        let mut map: HashMap<IndexFormat, Arc<dyn TocIndexer>> = HashMap::new();
        for ix in indexers {
            map.insert(ix.format(), ix);
        }
        Self {
            pool,
            fetcher,
            indexers: map,
            config,
            control,
        }
    }

    pub async fn run(&self) {
        info!(
            indexers = self.indexers.len(),
            "lazy-pull worker starting"
        );
        while !self.control.is_stopped() {
            match self.claim_and_run_one().await {
                Ok(true) => {
                    // ran a job — try again immediately
                }
                Ok(false) => {
                    tokio::time::sleep(self.config.idle_sleep).await;
                }
                Err(e) => {
                    warn!(error = %e, "lazy worker cycle failed");
                    tokio::time::sleep(self.config.idle_sleep).await;
                }
            }
        }
        info!("lazy-pull worker stopped");
    }

    /// Claim one queued job and run it. Returns `Ok(true)` if a job
    /// ran (success or failure), `Ok(false)` if the queue was empty.
    pub async fn claim_and_run_one(&self) -> Result<bool, WorkerError> {
        // Claim a queued job, transitioning it to 'running' atomically.
        let row: Option<(Uuid, String, String, i32)> = sqlx::query_as(
            "WITH next AS (
                 SELECT id FROM lazy_jobs
                 WHERE status = 'queued'
                 ORDER BY enqueued_at
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             )
             UPDATE lazy_jobs j
             SET status = 'running',
                 started_at = NOW(),
                 attempts = j.attempts + 1
             FROM next
             WHERE j.id = next.id
             RETURNING j.id, j.layer_digest, j.format, j.attempts",
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some((job_id, layer_digest, format, attempts)) = row else {
            return Ok(false);
        };

        let format_enum = IndexFormat::parse(&format)
            .ok_or_else(|| WorkerError::Indexer(LazyError::Parse(format!("bad format {format}"))))?;

        let Some(indexer) = self.indexers.get(&format_enum).cloned() else {
            self.mark_failed(job_id, &format!("no indexer for format {format}"))
                .await?;
            return Ok(true);
        };

        debug!(%job_id, %layer_digest, %format, attempts, "lazy worker claimed");

        // Fetch + index. Failures route through max-attempts logic.
        let result = async {
            let bytes = self.fetcher.fetch(&layer_digest).await?;
            let bytes_original = bytes.len() as i64;
            let out = indexer.index(bytes).await?;
            Ok::<_, WorkerError>((bytes_original, out))
        }
        .await;

        match result {
            Ok((bytes_original, out)) => {
                self.persist_success(&job_id, &layer_digest, &format, bytes_original, &out)
                    .await?;
            }
            Err(e) => {
                let final_failure = attempts >= self.config.max_attempts;
                if final_failure {
                    self.mark_failed(job_id, &e.to_string()).await?;
                } else {
                    self.requeue(job_id, &e.to_string()).await?;
                }
            }
        }
        Ok(true)
    }

    async fn persist_success(
        &self,
        job_id: &Uuid,
        layer_digest: &str,
        format: &str,
        bytes_original: i64,
        out: &crate::indexer::TocOutput,
    ) -> Result<(), WorkerError> {
        // The TOC artifact is content-addressed; its sha256 is what
        // links it into the referrers table. The registry's actual
        // blob upload of the TOC bytes happens in slice 3; for now
        // we record the metadata so consumers can plan against it.
        let toc_digest = sha256_digest(&out.toc_blob);
        let indexed_digest = match &out.indexed_layer {
            Some(b) => sha256_digest(b),
            None => layer_digest.to_string(),
        };

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO lazy_index
                 (layer_digest, format, indexed_digest, toc_digest,
                  bytes_original, bytes_indexed)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (layer_digest, format) DO UPDATE
             SET indexed_digest = EXCLUDED.indexed_digest,
                 toc_digest = EXCLUDED.toc_digest,
                 bytes_original = EXCLUDED.bytes_original,
                 bytes_indexed = EXCLUDED.bytes_indexed,
                 indexed_at = NOW()",
        )
        .bind(layer_digest)
        .bind(format)
        .bind(&indexed_digest)
        .bind(&toc_digest)
        .bind(bytes_original)
        .bind(out.bytes_indexed)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE lazy_jobs
             SET status = 'done',
                 finished_at = NOW(),
                 error = NULL
             WHERE id = $1",
        )
        .bind(job_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        debug!(%job_id, %layer_digest, %format, "lazy worker recorded success");

        // Register the TOC as a referrer of the source layer. This is
        // best-effort — failures here just mean the referrers list
        // misses one row and the reconciler picks it up later.
        let store = PgReferrerStore::new(self.pool.clone());
        let r = Referrer {
            subject_digest: layer_digest.to_string(),
            artifact_digest: toc_digest,
            artifact_type: IndexFormat::parse(format)
                .map(|f| f.artifact_type().to_string())
                .unwrap_or_else(|| format.to_string()),
            media_type: "application/vnd.oci.descriptor.v1+json".to_string(),
            size: out.toc_blob.len() as i64,
        };
        if let Err(e) = store.register(&r).await {
            warn!(error = %e, "failed to register lazy TOC referrer");
        }

        Ok(())
    }

    async fn requeue(&self, job_id: Uuid, msg: &str) -> Result<(), WorkerError> {
        sqlx::query(
            "UPDATE lazy_jobs
             SET status = 'queued',
                 error = $2
             WHERE id = $1",
        )
        .bind(job_id)
        .bind(msg)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn mark_failed(&self, job_id: Uuid, msg: &str) -> Result<(), WorkerError> {
        sqlx::query(
            "UPDATE lazy_jobs
             SET status = 'failed',
                 error = $2,
                 finished_at = NOW()
             WHERE id = $1",
        )
        .bind(job_id)
        .bind(msg)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// Stub indexer used in slice 2 — proves the queue + persistence
/// pipeline end to end without rewriting any layer bytes. The TOC
/// blob is a CycloneDX-shaped JSON manifest of file paths; for the
/// stub we emit a tiny placeholder so the referrers row gets the
/// right shape.
pub struct StubEstargzIndexer;

#[async_trait::async_trait]
impl TocIndexer for StubEstargzIndexer {
    fn format(&self) -> IndexFormat {
        IndexFormat::Estargz
    }
    fn supports_media_type(&self, mt: &str) -> bool {
        mt == "application/vnd.oci.image.layer.v1.tar+gzip"
            || mt == "application/vnd.docker.image.rootfs.diff.tar.gzip"
    }
    async fn index(&self, src: Bytes) -> Result<crate::indexer::TocOutput, LazyError> {
        let toc = serde_json::json!({
            "format": IndexFormat::Estargz.as_str(),
            "stub":   true,
            "indexed_at": Utc::now().to_rfc3339(),
            "source_bytes": src.len(),
        });
        let toc_blob = Bytes::from(serde_json::to_vec(&toc).unwrap());
        Ok(crate::indexer::TocOutput {
            bytes_original: src.len() as i64,
            bytes_indexed: toc_blob.len() as i64,
            toc_blob,
            indexed_layer: None,
        })
    }
}

fn sha256_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_indexer_emits_toc_blob() {
        let stub = StubEstargzIndexer;
        let src = Bytes::from_static(b"compressed-tarball-bytes");
        let out = stub.index(src.clone()).await.unwrap();
        assert!(out.indexed_layer.is_none(), "stub does not rewrite bytes");
        assert!(out.toc_blob.len() > 0);
        let parsed: serde_json::Value = serde_json::from_slice(&out.toc_blob).unwrap();
        assert_eq!(parsed["format"], "estargz");
        assert_eq!(parsed["stub"], true);
        assert_eq!(parsed["source_bytes"], src.len());
    }

    #[test]
    fn sha256_digest_is_stable_and_prefixed() {
        let d = sha256_digest(b"abc");
        assert!(d.starts_with("sha256:"));
        assert_eq!(d.len(), "sha256:".len() + 64);
    }
}
