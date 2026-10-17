use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use rand::RngCore;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::dek::{self, DEK_LEN};
use crate::key_provider::{KeyId, KeyProvider, WrapAlgo, WrappedDek};
use crate::CryptoError;

#[derive(Debug)]
enum KekBacking {
    Memory(Arc<RwLock<[u8; DEK_LEN]>>),
    File { path: std::path::PathBuf },
}

/// Dev-only KEK provider (file or in-memory). Refuses `from_env` when
/// `SPECTONCR_ENV=prod` and encryption is enabled.
pub struct LocalDevProvider {
    backing: KekBacking,
    key_id: Arc<RwLock<KeyId>>,
}

impl LocalDevProvider {
    pub fn memory() -> Self {
        let mut kek = [0u8; DEK_LEN];
        rand::rng().fill_bytes(&mut kek);
        Self {
            backing: KekBacking::Memory(Arc::new(RwLock::new(kek))),
            key_id: Arc::new(RwLock::new(KeyId("local-dev-v1".into()))),
        }
    }

    pub async fn from_file(path: impl AsRef<Path>) -> Result<Self, CryptoError> {
        let path = path.as_ref().to_path_buf();
        ensure_kek_file(&path).await?;
        Ok(Self {
            backing: KekBacking::File { path },
            key_id: Arc::new(RwLock::new(KeyId("local-dev-v1".into()))),
        })
    }

    /// Load from `[encryption].local_key_path` or env `SPECTONCR_ENCRYPTION__LOCAL_KEY_PATH`.
    pub async fn from_env(enabled: bool, local_key_path: Option<&str>) -> Result<Self, CryptoError> {
        if enabled && std::env::var("SPECTONCR_ENV").as_deref() == Ok("prod") {
            return Err(CryptoError::LocalDevInProduction);
        }
        let path = local_key_path
            .map(|s| s.to_string())
            .or_else(|| std::env::var("SPECTONCR_ENCRYPTION__LOCAL_KEY_PATH").ok());
        match path {
            Some(p) => Self::from_file(p).await,
            None => Ok(Self::memory()),
        }
    }

    async fn load_kek(&self) -> Result<[u8; DEK_LEN], CryptoError> {
        match &self.backing {
            KekBacking::Memory(k) => Ok(*k.read().await),
            KekBacking::File { path } => {
                let bytes = tokio::fs::read(path).await?;
                if bytes.len() != DEK_LEN {
                    return Err(CryptoError::InvalidKey(format!(
                        "KEK file must be {} bytes, got {}",
                        DEK_LEN,
                        bytes.len()
                    )));
                }
                let mut kek = [0u8; DEK_LEN];
                kek.copy_from_slice(&bytes);
                Ok(kek)
            }
        }
    }
}

async fn ensure_kek_file(path: &Path) -> Result<(), CryptoError> {
    if tokio::fs::metadata(path).await.is_ok() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut kek = [0u8; DEK_LEN];
    rand::rng().fill_bytes(&mut kek);
    tokio::fs::write(path, kek).await?;
    Ok(())
}

#[async_trait]
impl KeyProvider for LocalDevProvider {
    async fn wrap(&self, _tenant_id: &str, dek: &[u8]) -> Result<WrappedDek, CryptoError> {
        let kek = self.load_kek().await?;
        let (nonce, ciphertext) = dek::wrap_dek(&kek, dek)?;
        let key_id = self.key_id.read().await.clone();
        Ok(WrappedDek {
            tenant: String::new(),
            digest: String::new(),
            key_id,
            algorithm: WrapAlgo::AesGcm256Wrap,
            nonce,
            ciphertext,
        })
    }

    async fn unwrap(&self, w: &WrappedDek) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let kek = self.load_kek().await?;
        dek::unwrap_dek(&kek, &w.nonce, &w.ciphertext)
    }

    async fn rotate(&self, _tenant_id: &str) -> Result<KeyId, CryptoError> {
        let mut new_kek = [0u8; DEK_LEN];
        rand::rng().fill_bytes(&mut new_kek);
        match &self.backing {
            KekBacking::Memory(k) => {
                *k.write().await = new_kek;
            }
            KekBacking::File { path } => {
                tokio::fs::write(path, new_kek).await?;
            }
        }
        let new_id = KeyId(format!("local-dev-{}", uuid::Uuid::new_v4()));
        *self.key_id.write().await = new_id.clone();
        Ok(new_id)
    }

    fn provider_name(&self) -> &'static str {
        "local"
    }
}
