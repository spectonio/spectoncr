//! Signing / verification errors.

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("unknown key ref: {0}")]
    UnknownKey(String),
    #[error("key provider unavailable: {0}")]
    ProviderUnavailable(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("invalid identity: {0}")]
    InvalidIdentity(String),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("no signatures provided")]
    NoSignatures,
    #[error("unknown key ref: {0}")]
    UnknownKey(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("malformed signature artifact: {0}")]
    Malformed(String),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyProviderError {
    #[error("key not found: {0}")]
    NotFound(String),
    #[error("unavailable: {0}")]
    Unavailable(String),
    #[error("invalid pem: {0}")]
    InvalidPem(String),
}
