//! Keyed cosign-compatible signer/verifier using `sigstore` crypto.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use sigstore::crypto::signing_key::SigStoreKeyPair;
use sigstore::crypto::{Signature, SigningScheme, verification_key::CosignVerificationKey};

use crate::artifact::SignatureArtifact;
use crate::cosign_payload::{
    CosignEnvelope, CosignSimpleSigning, MEDIA_TYPE_COSIGN_ENVELOPE_V1,
};
use crate::error::{SignError, VerifyError};
use crate::identity::SigningIdentity;
use crate::key_provider::KeyProvider;
use crate::policy::{OnViolation, VerificationOutcome, VerificationPolicy};
use crate::signer::Signer;
use crate::verifier::Verifier;

fn scheme_for_keypair(kp: &SigStoreKeyPair) -> SigningScheme {
    match kp {
        SigStoreKeyPair::ECDSA(_) => SigningScheme::ECDSA_P256_SHA256_ASN1,
        SigStoreKeyPair::ED25519(_) => SigningScheme::ED25519,
        SigStoreKeyPair::RSA(_) => SigningScheme::RSA_PSS_SHA256(2048),
    }
}

fn scheme_label(scheme: &SigningScheme) -> String {
    scheme.to_string()
}

fn keypair_from_material(
    material: &crate::key_provider::KeyMaterial,
) -> Result<SigStoreKeyPair, SignError> {
    if let Some(ref pem) = material.private_pem {
        return SigStoreKeyPair::from_pem(pem.as_bytes())
            .map_err(|e| SignError::Crypto(e.to_string()));
    }
    // Bridge B1 raw ed25519 seeds into sigstore by synthesizing PKCS8 PEM
    // via a temporary SigningScheme key — not available from seed alone
    // without dalek. Caller should use MemoryKeyedSigner for seed keys.
    Err(SignError::Crypto(format!(
        "key {} has no PEM private key; use MemoryKeyedSigner for raw ed25519 seeds",
        material.key_ref
    )))
}

fn verification_key_from_material(
    material: &crate::key_provider::KeyMaterial,
    scheme: &SigningScheme,
) -> Result<CosignVerificationKey, VerifyError> {
    if let Some(ref pub_pem) = material.public_pem {
        return CosignVerificationKey::from_pem(pub_pem.as_bytes(), scheme)
            .map_err(|e| VerifyError::Crypto(e.to_string()));
    }
    if let Some(ref priv_pem) = material.private_pem {
        let kp = SigStoreKeyPair::from_pem(priv_pem.as_bytes())
            .map_err(|e| VerifyError::Crypto(e.to_string()))?;
        return kp
            .to_verification_key(scheme)
            .map_err(|e| VerifyError::Crypto(e.to_string()));
    }
    Err(VerifyError::Crypto(format!(
        "key {} has no PEM material for verification",
        material.key_ref
    )))
}

/// Keyed signer that produces cosign simple-signing envelopes via sigstore-rs.
pub struct SigstoreSigner {
    keys: Arc<dyn KeyProvider>,
}

impl SigstoreSigner {
    pub fn new(keys: Arc<dyn KeyProvider>) -> Self {
        Self { keys }
    }
}

#[async_trait]
impl Signer for SigstoreSigner {
    async fn sign(
        &self,
        subject_digest: &str,
        identity: &SigningIdentity,
    ) -> Result<SignatureArtifact, SignError> {
        let key_ref = match identity {
            SigningIdentity::Keyed { key_ref } => key_ref.as_str(),
            SigningIdentity::Keyless { .. } => {
                return Err(SignError::NotImplemented(
                    "keyless Fulcio signing lands with Rekor wiring (post-B2)".into(),
                ));
            }
        };
        if key_ref.starts_with("vault://transit/") {
            return Err(SignError::InvalidIdentity(
                "use VaultTransitSigner for vault://transit/ refs".into(),
            ));
        }
        if !subject_digest.starts_with("sha256:") {
            return Err(SignError::InvalidIdentity(format!(
                "subject digest must be sha256:..., got {subject_digest}"
            )));
        }

        let material = self
            .keys
            .resolve(key_ref)
            .await
            .map_err(|e| SignError::UnknownKey(e.to_string()))?;
        let kp = keypair_from_material(&material)?;
        let scheme = scheme_for_keypair(&kp);
        let signer = kp
            .to_sigstore_signer(&scheme)
            .map_err(|e| SignError::Crypto(e.to_string()))?;

        let simple = CosignSimpleSigning::for_digest(subject_digest);
        let payload = simple.to_canonical_bytes()?;
        let sig = signer
            .sign(&payload)
            .map_err(|e| SignError::Crypto(e.to_string()))?;

        let envelope = CosignEnvelope {
            digest: subject_digest.to_string(),
            key_ref: key_ref.to_string(),
            payload_b64: B64.encode(&payload),
            signature_b64: B64.encode(&sig),
            algorithm: scheme_label(&scheme),
        };
        Ok(SignatureArtifact {
            media_type: MEDIA_TYPE_COSIGN_ENVELOPE_V1.into(),
            body: serde_json::to_vec(&envelope)?,
            signer_identity: key_ref.to_string(),
            signature_type: "cosign-key".into(),
        })
    }
}

/// Verifies cosign envelopes produced by [`SigstoreSigner`].
pub struct SigstoreVerifier {
    keys: Arc<dyn KeyProvider>,
}

impl SigstoreVerifier {
    pub fn new(keys: Arc<dyn KeyProvider>) -> Self {
        Self { keys }
    }
}

#[async_trait]
impl Verifier for SigstoreVerifier {
    async fn verify(
        &self,
        subject_digest: &str,
        signatures: &[SignatureArtifact],
        policy: &VerificationPolicy,
    ) -> Result<VerificationOutcome, VerifyError> {
        if signatures.is_empty() {
            if policy.required {
                return match policy.on_violation {
                    OnViolation::Block => Err(VerifyError::NoSignatures),
                    OnViolation::Warn | OnViolation::Log => Ok(VerificationOutcome {
                        trusted: false,
                        matched_signers: vec![],
                        policy_id: policy.id,
                        reason: Some("no signatures".into()),
                    }),
                };
            }
            return Ok(VerificationOutcome {
                trusted: true,
                matched_signers: vec![],
                policy_id: policy.id,
                reason: None,
            });
        }

        let trusted_refs: Vec<&str> = policy
            .trusted_signers
            .iter()
            .filter_map(|s| s.key_ref())
            .collect();

        let mut matched = Vec::new();

        for artifact in signatures {
            if artifact.media_type != MEDIA_TYPE_COSIGN_ENVELOPE_V1 {
                continue;
            }
            let envelope: CosignEnvelope = match serde_json::from_slice(&artifact.body) {
                Ok(e) => e,
                Err(_) => continue,
            };
            if envelope.digest != subject_digest {
                continue;
            }
            if !trusted_refs.is_empty() && !trusted_refs.contains(&envelope.key_ref.as_str()) {
                continue;
            }
            if envelope.algorithm == "vault-transit" {
                // Local verify cannot check Transit signatures without calling
                // Vault; treat as unmatched here.
                continue;
            }

            let material = match self.keys.resolve(&envelope.key_ref).await {
                Ok(m) => m,
                Err(_) => continue,
            };
            let scheme = SigningScheme::try_from(envelope.algorithm.as_str()).unwrap_or_default();
            let vk = match verification_key_from_material(&material, &scheme) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let payload = match envelope.payload_bytes() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let sig = match envelope.signature_bytes() {
                Ok(s) => s,
                Err(_) => continue,
            };
            if vk
                .verify_signature(Signature::Raw(&sig), &payload)
                .is_ok()
            {
                matched.push(envelope.key_ref.clone());
            }
        }

        if policy.required && matched.is_empty() {
            let reason = "no trusted signature verified".to_string();
            return match policy.on_violation {
                OnViolation::Block => Err(VerifyError::PolicyDenied(reason)),
                OnViolation::Warn | OnViolation::Log => Ok(VerificationOutcome {
                    trusted: false,
                    matched_signers: matched,
                    policy_id: policy.id,
                    reason: Some(reason),
                }),
            };
        }

        Ok(VerificationOutcome {
            trusted: !matched.is_empty() || !policy.required,
            matched_signers: matched,
            policy_id: policy.id,
            reason: None,
        })
    }
}

/// Write a freshly generated keypair to PEM files (for tests / CLI `keygen`).
pub fn generate_pem_keypair(
    scheme: SigningScheme,
) -> Result<(String, String), SignError> {
    let signer = scheme
        .create_signer()
        .map_err(|e| SignError::Crypto(e.to_string()))?;
    let kp = signer
        .to_sigstore_keypair()
        .map_err(|e| SignError::Crypto(e.to_string()))?;
    let private = kp
        .private_key_to_pem()
        .map_err(|e| SignError::Crypto(e.to_string()))?
        .to_string();
    let public = kp
        .public_key_to_pem()
        .map_err(|e| SignError::Crypto(e.to_string()))?;
    Ok((private, public))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::file::FilePemKeyProvider;
    use crate::providers::CompositeKeyProvider;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[tokio::test]
    async fn pem_file_round_trip_ecdsa() {
        let dir = tempdir().unwrap();
        let (priv_pem, pub_pem) =
            generate_pem_keypair(SigningScheme::ECDSA_P256_SHA256_ASN1).unwrap();
        let priv_path = dir.path().join("cosign.key");
        let pub_path = dir.path().join("cosign.key.pub");
        std::fs::write(&priv_path, &priv_pem).unwrap();
        std::fs::write(&pub_path, &pub_pem).unwrap();

        let key_ref = format!("file://{}", priv_path.display());
        let keys = Arc::new(
            CompositeKeyProvider::builder()
                .file(Arc::new(FilePemKeyProvider::new()))
                .build(),
        );
        let signer = SigstoreSigner::new(keys.clone());
        let verifier = SigstoreVerifier::new(keys);
        let digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let art = signer
            .sign(digest, &SigningIdentity::keyed(&key_ref))
            .await
            .unwrap();
        assert_eq!(art.media_type, MEDIA_TYPE_COSIGN_ENVELOPE_V1);

        let policy = VerificationPolicy::require_keys("prod", &[key_ref.as_str()]);
        let out = verifier.verify(digest, &[art], &policy).await.unwrap();
        assert!(out.trusted);
    }
}
