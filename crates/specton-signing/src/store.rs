//! Postgres signature metadata store (design 001 B3).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRecord {
    pub id: Uuid,
    pub subject_digest: String,
    pub tenant: String,
    pub project: String,
    pub repository: String,
    pub signature_digest: String,
    pub signer_identity: Option<String>,
    pub signature_type: String,
    pub media_type: Option<String>,
    pub size_bytes: i64,
    pub rekor_log_index: Option<i64>,
    pub signed_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureStoreError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

#[async_trait]
pub trait SignatureStore: Send + Sync {
    async fn put(&self, rec: &SignatureRecord) -> Result<(), SignatureStoreError>;
    async fn list_for_subject(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
        subject_digest: &str,
    ) -> Result<Vec<SignatureRecord>, SignatureStoreError>;
    async fn list_by_digest(
        &self,
        subject_digest: &str,
    ) -> Result<Vec<SignatureRecord>, SignatureStoreError>;
}

pub struct PgSignatureStore {
    pool: Pool<Postgres>,
}

impl PgSignatureStore {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &Pool<Postgres> {
        &self.pool
    }
}

#[async_trait]
impl SignatureStore for PgSignatureStore {
    async fn put(&self, rec: &SignatureRecord) -> Result<(), SignatureStoreError> {
        sqlx::query(
            "INSERT INTO signatures
                 (id, subject_digest, tenant, project, repository,
                  signature_digest, signer_identity, signature_type,
                  media_type, size_bytes, rekor_log_index, signed_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
             ON CONFLICT (subject_digest, signature_digest) DO UPDATE SET
                 signer_identity = EXCLUDED.signer_identity,
                 signature_type = EXCLUDED.signature_type,
                 media_type = EXCLUDED.media_type,
                 size_bytes = EXCLUDED.size_bytes,
                 signed_at = EXCLUDED.signed_at",
        )
        .bind(rec.id)
        .bind(&rec.subject_digest)
        .bind(&rec.tenant)
        .bind(&rec.project)
        .bind(&rec.repository)
        .bind(&rec.signature_digest)
        .bind(&rec.signer_identity)
        .bind(&rec.signature_type)
        .bind(&rec.media_type)
        .bind(rec.size_bytes)
        .bind(rec.rekor_log_index)
        .bind(rec.signed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_for_subject(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
        subject_digest: &str,
    ) -> Result<Vec<SignatureRecord>, SignatureStoreError> {
        let rows: Vec<(
            Uuid,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            String,
            Option<String>,
            i64,
            Option<i64>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            "SELECT id, subject_digest, tenant, project, repository,
                    signature_digest, signer_identity, signature_type,
                    media_type, size_bytes, rekor_log_index, signed_at
             FROM signatures
             WHERE tenant = $1 AND project = $2 AND repository = $3
               AND subject_digest = $4
             ORDER BY signed_at DESC",
        )
        .bind(tenant)
        .bind(project)
        .bind(repository)
        .bind(subject_digest)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_rec).collect())
    }

    async fn list_by_digest(
        &self,
        subject_digest: &str,
    ) -> Result<Vec<SignatureRecord>, SignatureStoreError> {
        let rows: Vec<(
            Uuid,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            String,
            Option<String>,
            i64,
            Option<i64>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            "SELECT id, subject_digest, tenant, project, repository,
                    signature_digest, signer_identity, signature_type,
                    media_type, size_bytes, rekor_log_index, signed_at
             FROM signatures
             WHERE subject_digest = $1
             ORDER BY signed_at DESC",
        )
        .bind(subject_digest)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(row_to_rec).collect())
    }
}

fn row_to_rec(
    (
        id,
        subject_digest,
        tenant,
        project,
        repository,
        signature_digest,
        signer_identity,
        signature_type,
        media_type,
        size_bytes,
        rekor_log_index,
        signed_at,
    ): (
        Uuid,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        i64,
        Option<i64>,
        DateTime<Utc>,
    ),
) -> SignatureRecord {
    SignatureRecord {
        id,
        subject_digest,
        tenant,
        project,
        repository,
        signature_digest,
        signer_identity,
        signature_type,
        media_type,
        size_bytes,
        rekor_log_index,
        signed_at,
    }
}

/// Parse subject digest from a cosign tag `sha256-<hex>.sig`.
pub fn subject_digest_from_sig_tag(tag: &str) -> Option<String> {
    let rest = tag.strip_suffix(".sig")?;
    let hex = rest.strip_prefix("sha256-")?;
    if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("sha256:{hex}"))
}

pub fn is_cosign_sig_tag(tag: &str) -> bool {
    subject_digest_from_sig_tag(tag).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cosign_sig_tag() {
        let d = subject_digest_from_sig_tag(
            "sha256-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.sig",
        )
        .unwrap();
        assert_eq!(
            d,
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );
        assert!(is_cosign_sig_tag(&format!("{}.sig", d.replace(':', "-"))));
        assert!(!is_cosign_sig_tag("latest"));
    }
}
