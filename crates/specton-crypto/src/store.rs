use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use object_store::path::Path as StorePath;
use object_store::{ObjectStore, PutPayload};
use serde::{Deserialize, Serialize};
use specton_common::storage::sha256_digest;
use specton_db::sqlx::PgPool;
use tokio::sync::RwLock;
use tracing::debug;

use crate::dek::{self, generate_dek};
use crate::key_provider::{KeyProvider, WrappedDek};
use crate::CryptoError;

const BLOB_NONCE_LEN: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMeta {
    pub digest: String,
    pub size_plaintext: u64,
    pub size_ciphertext: u64,
    pub key_id: String,
}

#[async_trait]
pub trait EncryptedStore: Send + Sync {
    async fn put_blob(
        &self,
        tenant: &str,
        path: &str,
        data: Bytes,
    ) -> Result<BlobMeta, CryptoError>;
    async fn get_blob(&self, tenant: &str, path: &str) -> Result<Bytes, CryptoError>;
    async fn tenant_key_status(&self, tenant: &str) -> Result<TenantKeyRow, CryptoError>;
    async fn rotate_tenant_kek(&self, tenant: &str) -> Result<String, CryptoError>;
}

#[async_trait]
trait WrappedDekStore: Send + Sync {
    async fn save(&self, row: &WrappedDek) -> Result<(), CryptoError>;
    async fn load(&self, tenant: &str, digest: &str) -> Result<WrappedDek, CryptoError>;
    async fn count_for_tenant(&self, tenant: &str) -> Result<i64, CryptoError>;
    async fn upsert_tenant_key(
        &self,
        tenant: &str,
        provider: &str,
        key_id: &str,
    ) -> Result<(), CryptoError>;
    async fn tenant_key_info(
        &self,
        tenant: &str,
    ) -> Result<Option<TenantKeyRow>, CryptoError>;
}

#[derive(Debug, Clone, Serialize)]
pub struct TenantKeyRow {
    pub tenant: String,
    pub provider: String,
    pub current_key_id: String,
    pub rotated_at: chrono::DateTime<chrono::Utc>,
    pub wrapped_dek_count: i64,
}

pub struct EnvelopeEncryptedStore {
    inner: Arc<dyn ObjectStore>,
    provider: Arc<dyn KeyProvider>,
    dek_store: Arc<dyn WrappedDekStore>,
}

impl EnvelopeEncryptedStore {
    pub fn new(
        inner: Arc<dyn ObjectStore>,
        provider: Arc<dyn KeyProvider>,
        pool: Option<PgPool>,
    ) -> Self {
        let dek_store: Arc<dyn WrappedDekStore> = match pool {
            Some(p) => Arc::new(PgWrappedDekStore { pool: p }),
            None => Arc::new(MemoryWrappedDekStore::default()),
        };
        Self {
            inner,
            provider,
            dek_store,
        }
    }

}

#[async_trait]
impl EncryptedStore for EnvelopeEncryptedStore {
    async fn put_blob(
        &self,
        tenant: &str,
        path: &str,
        data: Bytes,
    ) -> Result<BlobMeta, CryptoError> {
        let digest = sha256_digest(&data);
        let dek = generate_dek();
        let (blob_nonce, ciphertext) = dek::encrypt_blob(dek.as_ref(), &data)?;

        let mut wrapped = self.provider.wrap(tenant, dek.as_ref()).await?;
        wrapped.tenant = tenant.to_string();
        wrapped.digest = digest.clone();
        let key_id = wrapped.key_id.0.clone();

        self.dek_store
            .upsert_tenant_key(tenant, self.provider.provider_name(), &key_id)
            .await?;
        self.dek_store.save(&wrapped).await?;

        let mut stored = Vec::with_capacity(BLOB_NONCE_LEN + ciphertext.len());
        stored.extend_from_slice(&blob_nonce);
        stored.extend_from_slice(&ciphertext);
        let size_ciphertext = stored.len() as u64;

        let store_path = StorePath::from(path);
        self.inner
            .put(&store_path, PutPayload::from_bytes(Bytes::from(stored)))
            .await
            .map_err(|e| CryptoError::Storage(e.to_string()))?;

        debug!(%tenant, %digest, %path, "envelope-encrypted blob stored");

        Ok(BlobMeta {
            digest,
            size_plaintext: data.len() as u64,
            size_ciphertext,
            key_id,
        })
    }

    async fn get_blob(&self, tenant: &str, path: &str) -> Result<Bytes, CryptoError> {
        let digest = digest_from_blob_path(path)?;
        let wrapped = self.dek_store.load(tenant, &digest).await?;
        let dek = self.provider.unwrap(&wrapped).await?;

        let store_path = StorePath::from(path);
        let result = self.inner.get(&store_path).await.map_err(|e| {
            if matches!(e, object_store::Error::NotFound { .. }) {
                CryptoError::BlobNotFound
            } else {
                CryptoError::Storage(e.to_string())
            }
        })?;
        let raw = result
            .bytes()
            .await
            .map_err(|e| CryptoError::Storage(e.to_string()))?;
        if raw.len() < BLOB_NONCE_LEN {
            return Err(CryptoError::Crypto("ciphertext too short".into()));
        }
        let (nonce, ct) = raw.split_at(BLOB_NONCE_LEN);
        let plain = dek::decrypt_blob(dek.as_ref(), nonce, ct)?;
        Ok(Bytes::from(plain))
    }

    async fn tenant_key_status(&self, tenant: &str) -> Result<TenantKeyRow, CryptoError> {
        self.tenant_key_status_impl(tenant).await
    }

    async fn rotate_tenant_kek(&self, tenant: &str) -> Result<String, CryptoError> {
        self.rotate_tenant_kek_impl(tenant).await
    }
}

impl EnvelopeEncryptedStore {
    async fn tenant_key_status_impl(&self, tenant: &str) -> Result<TenantKeyRow, CryptoError> {
        let count = self.dek_store.count_for_tenant(tenant).await?;
        match self.dek_store.tenant_key_info(tenant).await? {
            Some(row) => Ok(TenantKeyRow {
                wrapped_dek_count: count,
                ..row
            }),
            None => Err(CryptoError::TenantKeyNotFound {
                tenant: tenant.into(),
            }),
        }
    }

    async fn rotate_tenant_kek_impl(&self, tenant: &str) -> Result<String, CryptoError> {
        let new_id = self.provider.rotate(tenant).await?;
        self.dek_store
            .upsert_tenant_key(tenant, self.provider.provider_name(), &new_id.0)
            .await?;
        Ok(new_id.0)
    }
}

/// Extract `sha256:<hex>` from a registry blob object path.
pub fn digest_from_blob_path(path: &str) -> Result<String, CryptoError> {
    let marker = "/blobs/sha256/";
    let idx = path
        .find(marker)
        .ok_or_else(|| CryptoError::DigestFromPath {
            path: path.into(),
        })?;
    let hex = &path[idx + marker.len()..];
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CryptoError::DigestFromPath {
            path: path.into(),
        });
    }
    Ok(format!("sha256:{hex}"))
}

#[derive(Default)]
struct MemoryWrappedDekStore {
    deks: RwLock<HashMap<(String, String), WrappedDek>>,
    tenant_keys: RwLock<HashMap<String, TenantKeyRow>>,
}

#[async_trait]
impl WrappedDekStore for MemoryWrappedDekStore {
    async fn save(&self, row: &WrappedDek) -> Result<(), CryptoError> {
        self.deks.write().await.insert(
            (row.tenant.clone(), row.digest.clone()),
            row.clone(),
        );
        Ok(())
    }

    async fn load(&self, tenant: &str, digest: &str) -> Result<WrappedDek, CryptoError> {
        self.deks
            .read()
            .await
            .get(&(tenant.to_string(), digest.to_string()))
            .cloned()
            .ok_or_else(|| CryptoError::WrappedDekNotFound {
                digest: digest.into(),
            })
    }

    async fn count_for_tenant(&self, tenant: &str) -> Result<i64, CryptoError> {
        let n = self
            .deks
            .read()
            .await
            .keys()
            .filter(|(t, _)| t == tenant)
            .count();
        Ok(n as i64)
    }

    async fn upsert_tenant_key(
        &self,
        tenant: &str,
        provider: &str,
        key_id: &str,
    ) -> Result<(), CryptoError> {
        let mut keys = self.tenant_keys.write().await;
        keys.insert(
            tenant.to_string(),
            TenantKeyRow {
                tenant: tenant.to_string(),
                provider: provider.to_string(),
                current_key_id: key_id.to_string(),
                rotated_at: chrono::Utc::now(),
                wrapped_dek_count: 0,
            },
        );
        Ok(())
    }

    async fn tenant_key_info(&self, tenant: &str) -> Result<Option<TenantKeyRow>, CryptoError> {
        Ok(self.tenant_keys.read().await.get(tenant).cloned())
    }
}

struct PgWrappedDekStore {
    pool: PgPool,
}

#[async_trait]
impl WrappedDekStore for PgWrappedDekStore {
    async fn save(&self, row: &WrappedDek) -> Result<(), CryptoError> {
        sqlx::query(
            r#"
            INSERT INTO wrapped_deks (digest, tenant, key_id, algorithm, nonce, ciphertext)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (tenant, digest) DO UPDATE SET
                key_id = EXCLUDED.key_id,
                algorithm = EXCLUDED.algorithm,
                nonce = EXCLUDED.nonce,
                ciphertext = EXCLUDED.ciphertext
            "#,
        )
        .bind(&row.digest)
        .bind(&row.tenant)
        .bind(&row.key_id.0)
        .bind("AES-GCM-256-WRAP")
        .bind(&row.nonce)
        .bind(&row.ciphertext)
        .execute(&self.pool)
        .await
        .map_err(|e| CryptoError::Database(e.to_string()))?;
        Ok(())
    }

    async fn load(&self, tenant: &str, digest: &str) -> Result<WrappedDek, CryptoError> {
        use crate::key_provider::{KeyId, WrapAlgo};
        let rec = sqlx::query_as::<_, (String, String, String, Vec<u8>, Vec<u8>)>(
            r#"
            SELECT key_id, algorithm, digest, nonce, ciphertext
            FROM wrapped_deks WHERE tenant = $1 AND digest = $2
            "#,
        )
        .bind(tenant)
        .bind(digest)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| CryptoError::Database(e.to_string()))?
        .ok_or_else(|| CryptoError::WrappedDekNotFound {
            digest: digest.into(),
        })?;

        Ok(WrappedDek {
            tenant: tenant.to_string(),
            digest: rec.2,
            key_id: KeyId(rec.0),
            algorithm: WrapAlgo::AesGcm256Wrap,
            nonce: rec.3,
            ciphertext: rec.4,
        })
    }

    async fn count_for_tenant(&self, tenant: &str) -> Result<i64, CryptoError> {
        let (n,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM wrapped_deks WHERE tenant = $1",
        )
        .bind(tenant)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| CryptoError::Database(e.to_string()))?;
        Ok(n)
    }

    async fn upsert_tenant_key(
        &self,
        tenant: &str,
        provider: &str,
        key_id: &str,
    ) -> Result<(), CryptoError> {
        sqlx::query(
            r#"
            INSERT INTO tenant_keys (tenant, provider, current_key_id, spec, rotated_at)
            VALUES ($1, $2, $3, '{}'::jsonb, NOW())
            ON CONFLICT (tenant) DO UPDATE SET
                provider = EXCLUDED.provider,
                current_key_id = EXCLUDED.current_key_id,
                rotated_at = NOW()
            "#,
        )
        .bind(tenant)
        .bind(provider)
        .bind(key_id)
        .execute(&self.pool)
        .await
        .map_err(|e| CryptoError::Database(e.to_string()))?;
        Ok(())
    }

    async fn tenant_key_info(&self, tenant: &str) -> Result<Option<TenantKeyRow>, CryptoError> {
        let row = sqlx::query_as::<_, (String, String, String, chrono::DateTime<chrono::Utc>)>(
            r#"
            SELECT tenant, provider, current_key_id, rotated_at
            FROM tenant_keys WHERE tenant = $1
            "#,
        )
        .bind(tenant)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| CryptoError::Database(e.to_string()))?;

        Ok(row.map(|r| TenantKeyRow {
            tenant: r.0,
            provider: r.1,
            current_key_id: r.2,
            rotated_at: r.3,
            wrapped_dek_count: 0,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalDevProvider;
    use object_store::memory::InMemory;

    #[tokio::test]
    async fn envelope_roundtrip_memory() {
        let inner: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let provider = Arc::new(LocalDevProvider::memory());
        let store = EnvelopeEncryptedStore::new(inner, provider, None);
        let data = Bytes::from_static(b"layer-by-layer envelope encryption");
        let digest = sha256_digest(&data);
        let hex = digest.strip_prefix("sha256:").unwrap();
        let path = format!("acme/web/nginx/blobs/sha256/{hex}");

        let meta = store
            .put_blob("acme", &path, data.clone())
            .await
            .expect("put");
        assert_eq!(meta.digest, digest);

        let out = store.get_blob("acme", &path).await.expect("get");
        assert_eq!(out, data);
    }
}
