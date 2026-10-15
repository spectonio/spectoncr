//! Cosign simple-signing payload (what keyed cosign signs).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

/// Media type for cosign simple-signing JSON (unsigned payload).
pub const MEDIA_TYPE_COSIGN_SIMPLE: &str =
    "application/vnd.dev.cosign.simplesigning.v1+json";

/// SpectonCR envelope wrapping payload + signature for B2 storage.
pub const MEDIA_TYPE_COSIGN_ENVELOPE_V1: &str =
    "application/vnd.spectoncr.signing.cosign-envelope.v1+json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosignCritical {
    pub identity: CosignIdentity,
    pub image: CosignImage,
    #[serde(rename = "type")]
    pub typ: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosignIdentity {
    #[serde(rename = "docker-reference")]
    pub docker_reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosignImage {
    #[serde(rename = "docker-manifest-digest")]
    pub docker_manifest_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosignSimpleSigning {
    pub critical: CosignCritical,
    pub optional: Option<serde_json::Value>,
}

impl CosignSimpleSigning {
    pub fn for_digest(subject_digest: &str) -> Self {
        Self {
            critical: CosignCritical {
                identity: CosignIdentity {
                    docker_reference: String::new(),
                },
                image: CosignImage {
                    docker_manifest_digest: subject_digest.to_string(),
                },
                typ: "cosign container image signature".into(),
            },
            optional: None,
        }
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        // Cosign uses compact JSON; field order from serde derive is stable
        // for our structs.
        serde_json::to_vec(self)
    }
}

/// Wire envelope stored as a SignatureArtifact body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosignEnvelope {
    pub digest: String,
    pub key_ref: String,
    /// Base64 of the simple-signing JSON bytes.
    pub payload_b64: String,
    /// Base64 of the raw signature bytes.
    pub signature_b64: String,
    pub algorithm: String,
}

impl CosignEnvelope {
    pub fn payload_bytes(&self) -> Result<Vec<u8>, String> {
        B64.decode(&self.payload_b64).map_err(|e| e.to_string())
    }

    pub fn signature_bytes(&self) -> Result<Vec<u8>, String> {
        B64.decode(&self.signature_b64).map_err(|e| e.to_string())
    }
}
