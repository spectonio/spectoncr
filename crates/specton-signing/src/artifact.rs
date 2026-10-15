//! Cosign-oriented signature artifact shapes.

use serde::{Deserialize, Serialize};

/// Media type for B1 ed25519 simple envelopes. B2 switches to
/// cosign-bundle (`application/vnd.dev.sigstore.bundle.v0.3+json`).
pub const MEDIA_TYPE_ED25519_V1: &str = "application/vnd.spectoncr.signing.ed25519.v1+json";

/// A signature payload ready to be stored as an OCI artifact / `.sig` tag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureArtifact {
    /// OCI media type of `body`.
    pub media_type: String,
    /// Raw artifact bytes (JSON envelope for B1).
    pub body: Vec<u8>,
    /// Key ref or OIDC subject that produced this signature.
    pub signer_identity: String,
    /// Algorithm label (`ed25519`, `ecdsa-p256`, …).
    pub signature_type: String,
}

impl SignatureArtifact {
    /// Cosign tag convention: `sha256:<hex>` → `sha256-<hex>.sig`.
    pub fn cosign_sig_tag(subject_digest: &str) -> Option<String> {
        let hex = subject_digest.strip_prefix("sha256:")?;
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        Some(format!("sha256-{hex}.sig"))
    }
}

/// On-disk / wire envelope for the B1 ed25519 signer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519Envelope {
    pub digest: String,
    pub key_ref: String,
    /// Base64 (standard) of the 64-byte ed25519 signature.
    pub signature: String,
    pub algorithm: String,
}

impl Ed25519Envelope {
    pub fn to_artifact(&self, signer_identity: impl Into<String>) -> Result<SignatureArtifact, serde_json::Error> {
        Ok(SignatureArtifact {
            media_type: MEDIA_TYPE_ED25519_V1.into(),
            body: serde_json::to_vec(self)?,
            signer_identity: signer_identity.into(),
            signature_type: "cosign-key".into(),
        })
    }

    pub fn from_artifact(artifact: &SignatureArtifact) -> Result<Self, String> {
        if artifact.media_type != MEDIA_TYPE_ED25519_V1 {
            return Err(format!(
                "unsupported media type: {}",
                artifact.media_type
            ));
        }
        serde_json::from_slice(&artifact.body).map_err(|e| e.to_string())
    }
}
