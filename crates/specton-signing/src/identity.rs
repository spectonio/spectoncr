//! Signing identity — keyed now, keyless stubs for v1.1.

use serde::{Deserialize, Serialize};

/// Who / which key is used to produce a signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningIdentity {
    /// Resolve PEM (or later Vault Transit material) via [`crate::KeyProvider`].
    Keyed { key_ref: String },
    /// Fulcio + OIDC — wired in B2/v1.1; MemoryKeyedSigner rejects this.
    Keyless {
        fulcio: FulcioConfig,
        oidc: OidcToken,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FulcioConfig {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcToken {
    /// Raw bearer token (never logged).
    pub token: String,
}

impl SigningIdentity {
    pub fn keyed(key_ref: impl Into<String>) -> Self {
        Self::Keyed {
            key_ref: key_ref.into(),
        }
    }

    pub fn key_ref(&self) -> Option<&str> {
        match self {
            Self::Keyed { key_ref } => Some(key_ref.as_str()),
            Self::Keyless { .. } => None,
        }
    }
}
