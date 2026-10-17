use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum WrapAlgo {
    #[serde(rename = "AES-GCM-256-WRAP")]
    AesGcm256Wrap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedDek {
    pub tenant: String,
    pub digest: String,
    pub key_id: KeyId,
    pub algorithm: WrapAlgo,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn wrap(&self, tenant_id: &str, dek: &[u8]) -> Result<WrappedDek, super::CryptoError>;
    async fn unwrap(&self, w: &WrappedDek) -> Result<Zeroizing<Vec<u8>>, super::CryptoError>;
    async fn rotate(&self, tenant_id: &str) -> Result<KeyId, super::CryptoError>;
    fn provider_name(&self) -> &'static str;
}
