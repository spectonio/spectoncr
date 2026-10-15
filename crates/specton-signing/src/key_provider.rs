//! Resolve `key_ref` → PEM / raw key material.
//!
//! B1 ships [`MemoryKeyProvider`]. B2 adds Vault Transit + file PEM.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

use crate::error::KeyProviderError;

/// Material returned by a [`KeyProvider`].
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    pub key_ref: String,
    /// PKCS#8 PEM private key (signing) when used.
    pub private_pem: Option<String>,
    /// SPKI PEM public key (verify) when used.
    pub public_pem: Option<String>,
    /// Raw ed25519 signing seed (32 bytes) for the memory provider.
    pub ed25519_seed: Option<[u8; 32]>,
    /// Raw ed25519 verifying key (32 bytes).
    pub ed25519_public: Option<[u8; 32]>,
}

#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn resolve(&self, key_ref: &str) -> Result<KeyMaterial, KeyProviderError>;
}

/// In-process key map — tests and local dawn-of-signing.
#[derive(Default)]
pub struct MemoryKeyProvider {
    keys: RwLock<HashMap<String, KeyMaterial>>,
}

impl MemoryKeyProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, material: KeyMaterial) {
        self.keys
            .write()
            .expect("key provider lock")
            .insert(material.key_ref.clone(), material);
    }

    /// Register an ed25519 keypair under `key_ref` and return the provider.
    pub fn with_ed25519_keypair(
        key_ref: impl Into<String>,
        seed: [u8; 32],
        public: [u8; 32],
    ) -> Arc<Self> {
        let key_ref = key_ref.into();
        let provider = Arc::new(Self::new());
        provider.insert(KeyMaterial {
            key_ref,
            private_pem: None,
            public_pem: None,
            ed25519_seed: Some(seed),
            ed25519_public: Some(public),
        });
        provider
    }
}

#[async_trait]
impl KeyProvider for MemoryKeyProvider {
    async fn resolve(&self, key_ref: &str) -> Result<KeyMaterial, KeyProviderError> {
        self.keys
            .read()
            .expect("key provider lock")
            .get(key_ref)
            .cloned()
            .ok_or_else(|| KeyProviderError::NotFound(key_ref.to_string()))
    }
}
