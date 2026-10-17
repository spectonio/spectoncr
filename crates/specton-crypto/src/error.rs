use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption disabled")]
    Disabled,
    #[error("local dev provider refused in production")]
    LocalDevInProduction,
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
    #[error("storage: {0}")]
    Storage(String),
    #[error("blob not found")]
    BlobNotFound,
    #[error("wrapped DEK not found for digest {digest}")]
    WrappedDekNotFound { digest: String },
    #[error("tenant key not found: {tenant}")]
    TenantKeyNotFound { tenant: String },
    #[error("digest could not be derived from path: {path}")]
    DigestFromPath { path: String },
    #[error("database: {0}")]
    Database(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
