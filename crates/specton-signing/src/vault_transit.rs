//! Vault Transit remote signing for `vault://transit/<key-name>` refs.
//!
//! The private key never leaves Vault; we POST the base64 payload to
//! `/v1/transit/sign/<key>` and wrap the returned signature.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Deserialize;

use crate::artifact::SignatureArtifact;
use crate::cosign_payload::{
    CosignEnvelope, CosignSimpleSigning, MEDIA_TYPE_COSIGN_ENVELOPE_V1,
};
use crate::error::SignError;
use crate::identity::SigningIdentity;
use crate::signer::Signer;

#[derive(Debug, Clone)]
pub struct VaultTransitConfig {
    pub addr: String,
    pub token: String,
    /// Transit mount path (default `transit`).
    pub mount: String,
}

impl VaultTransitConfig {
    pub fn from_env() -> Option<Self> {
        let token = std::env::var("VAULT_TOKEN").ok().filter(|t| !t.is_empty())?;
        let addr =
            std::env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".into());
        Some(Self {
            addr,
            token,
            mount: std::env::var("VAULT_TRANSIT_MOUNT").unwrap_or_else(|_| "transit".into()),
        })
    }
}

#[derive(Debug, Deserialize)]
struct TransitSignResponse {
    data: TransitSignData,
}

#[derive(Debug, Deserialize)]
struct TransitSignData {
    signature: String,
}

/// Signs via Vault Transit. Only accepts `vault://transit/<name>` identities.
pub struct VaultTransitSigner {
    http: reqwest::Client,
    config: VaultTransitConfig,
}

impl VaultTransitSigner {
    pub fn new(config: VaultTransitConfig) -> Self {
        Self {
            http: reqwest::Client::new(),
            config,
        }
    }

    fn key_name(key_ref: &str) -> Result<&str, SignError> {
        key_ref
            .strip_prefix("vault://transit/")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SignError::InvalidIdentity(format!(
                    "VaultTransitSigner expects vault://transit/<key>, got {key_ref}"
                ))
            })
    }
}

#[async_trait]
impl Signer for VaultTransitSigner {
    async fn sign(
        &self,
        subject_digest: &str,
        identity: &SigningIdentity,
    ) -> Result<SignatureArtifact, SignError> {
        let key_ref = match identity {
            SigningIdentity::Keyed { key_ref } => key_ref.as_str(),
            SigningIdentity::Keyless { .. } => {
                return Err(SignError::InvalidIdentity(
                    "VaultTransitSigner does not support keyless".into(),
                ));
            }
        };
        let key_name = Self::key_name(key_ref)?;
        if !subject_digest.starts_with("sha256:") {
            return Err(SignError::InvalidIdentity(format!(
                "subject digest must be sha256:..., got {subject_digest}"
            )));
        }

        let simple = CosignSimpleSigning::for_digest(subject_digest);
        let payload = simple.to_canonical_bytes()?;
        let input_b64 = B64.encode(&payload);

        let url = format!(
            "{}/v1/{}/sign/{}",
            self.config.addr.trim_end_matches('/'),
            self.config.mount,
            key_name
        );
        let body = serde_json::json!({
            "input": input_b64,
            // Prehashed=false: Vault hashes for us depending on key type.
        });
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", &self.config.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| SignError::ProviderUnavailable(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(SignError::ProviderUnavailable(format!(
                "vault transit sign {status}: {text}"
            )));
        }
        let parsed: TransitSignResponse = resp
            .json()
            .await
            .map_err(|e| SignError::ProviderUnavailable(e.to_string()))?;

        // Vault returns `vault:v1:<base64>`. Store the full string as the
        // signature blob so verify can round-trip through Transit if needed.
        let envelope = CosignEnvelope {
            digest: subject_digest.to_string(),
            key_ref: key_ref.to_string(),
            payload_b64: input_b64,
            signature_b64: B64.encode(parsed.data.signature.as_bytes()),
            algorithm: "vault-transit".into(),
        };
        Ok(SignatureArtifact {
            media_type: MEDIA_TYPE_COSIGN_ENVELOPE_V1.into(),
            body: serde_json::to_vec(&envelope)?,
            signer_identity: key_ref.to_string(),
            signature_type: "cosign-key".into(),
        })
    }
}
