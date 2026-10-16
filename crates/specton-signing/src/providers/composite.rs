//! Route `key_ref` by URI scheme across several providers.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::KeyProviderError;
use crate::key_provider::{KeyMaterial, KeyProvider, MemoryKeyProvider};
use crate::providers::file::FilePemKeyProvider;
use crate::providers::vault::VaultKvKeyProvider;

pub struct CompositeKeyProvider {
    memory: Option<Arc<MemoryKeyProvider>>,
    file: Option<Arc<FilePemKeyProvider>>,
    vault_kv: Option<Arc<VaultKvKeyProvider>>,
}

impl CompositeKeyProvider {
    pub fn builder() -> CompositeKeyProviderBuilder {
        CompositeKeyProviderBuilder::default()
    }
}

#[derive(Default)]
pub struct CompositeKeyProviderBuilder {
    memory: Option<Arc<MemoryKeyProvider>>,
    file: Option<Arc<FilePemKeyProvider>>,
    vault_kv: Option<Arc<VaultKvKeyProvider>>,
}

impl CompositeKeyProviderBuilder {
    pub fn memory(mut self, p: Arc<MemoryKeyProvider>) -> Self {
        self.memory = Some(p);
        self
    }

    pub fn file(mut self, p: Arc<FilePemKeyProvider>) -> Self {
        self.file = Some(p);
        self
    }

    pub fn vault_kv(mut self, p: Arc<VaultKvKeyProvider>) -> Self {
        self.vault_kv = Some(p);
        self
    }

    pub fn build(self) -> CompositeKeyProvider {
        CompositeKeyProvider {
            memory: self.memory,
            file: self.file,
            vault_kv: self.vault_kv,
        }
    }
}

#[async_trait]
impl KeyProvider for CompositeKeyProvider {
    async fn resolve(&self, key_ref: &str) -> Result<KeyMaterial, KeyProviderError> {
        if key_ref.starts_with("vault://transit/") {
            return Err(KeyProviderError::Unavailable(
                "vault://transit/ refs require VaultTransitSigner, not KeyProvider::resolve".into(),
            ));
        }
        if key_ref.starts_with("vault://") {
            if let Some(ref v) = self.vault_kv {
                return v.resolve(key_ref).await;
            }
            return Err(KeyProviderError::Unavailable(
                "vault provider not configured".into(),
            ));
        }
        if key_ref.starts_with("file://")
            || key_ref.starts_with('/')
            || key_ref.starts_with("./")
            || key_ref.ends_with(".pem")
            || key_ref.ends_with(".key")
        {
            if let Some(ref f) = self.file {
                return f.resolve(key_ref).await;
            }
            return Err(KeyProviderError::Unavailable(
                "file provider not configured".into(),
            ));
        }
        // memory://, cosign://, or bare names registered in MemoryKeyProvider
        if let Some(ref m) = self.memory {
            if let Ok(mat) = m.resolve(key_ref).await {
                return Ok(mat);
            }
            if let Some(name) = key_ref
                .strip_prefix("memory://")
                .or_else(|| key_ref.strip_prefix("cosign://"))
            {
                if let Ok(mat) = m.resolve(&format!("cosign://{name}")).await {
                    return Ok(mat);
                }
                return m.resolve(name).await;
            }
            return Err(KeyProviderError::NotFound(key_ref.to_string()));
        }
        Err(KeyProviderError::NotFound(key_ref.to_string()))
    }
}
