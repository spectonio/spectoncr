//! In-memory ed25519 keyed signer / verifier (B1).

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{
    Signature, Signer as DalekSigner, SigningKey, Verifier as DalekVerifier, VerifyingKey,
};
use rand_core::OsRng;

use crate::artifact::{Ed25519Envelope, SignatureArtifact};
use crate::error::{SignError, VerifyError};
use crate::identity::SigningIdentity;
use crate::key_provider::{KeyProvider, MemoryKeyProvider};
use crate::policy::{OnViolation, VerificationOutcome, VerificationPolicy};
use crate::signer::Signer;
use crate::verifier::Verifier;

/// Payload bytes that are signed for a subject digest.
///
/// B1 signs the UTF-8 digest string. B2 will switch to the cosign
/// simple-signing JSON payload.
pub fn signing_payload(subject_digest: &str) -> Vec<u8> {
    subject_digest.as_bytes().to_vec()
}

/// Generate a fresh ed25519 keypair registered under `key_ref`.
pub fn generate_ed25519(
    key_ref: impl Into<String>,
) -> (Arc<MemoryKeyProvider>, [u8; 32], [u8; 32]) {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    let seed = signing.to_bytes();
    let public = verifying.to_bytes();
    let provider = MemoryKeyProvider::with_ed25519_keypair(key_ref, seed, public);
    (provider, seed, public)
}

fn signing_key_from_material(
    material: &crate::key_provider::KeyMaterial,
) -> Result<SigningKey, SignError> {
    if let Some(seed) = material.ed25519_seed {
        return Ok(SigningKey::from_bytes(&seed));
    }
    // PEM / PKCS#8 parsing arrives with the file+Vault KeyProvider in B2.
    if material.private_pem.is_some() {
        return Err(SignError::NotImplemented(
            "PEM private keys require Sigstore/Vault provider (B2)".into(),
        ));
    }
    Err(SignError::Crypto(format!(
        "key {} has no ed25519 private material",
        material.key_ref
    )))
}

fn verifying_key_from_material(
    material: &crate::key_provider::KeyMaterial,
) -> Result<VerifyingKey, VerifyError> {
    if let Some(public) = material.ed25519_public {
        return VerifyingKey::from_bytes(&public)
            .map_err(|e| VerifyError::Crypto(format!("public key: {e}")));
    }
    if let Some(seed) = material.ed25519_seed {
        let sk = SigningKey::from_bytes(&seed);
        return Ok(sk.verifying_key());
    }
    if material.public_pem.is_some() {
        return Err(VerifyError::NotImplemented(
            "PEM public keys require Sigstore/Vault provider (B2)".into(),
        ));
    }
    Err(VerifyError::Crypto(format!(
        "key {} has no ed25519 public material",
        material.key_ref
    )))
}

/// Keyed ed25519 signer backed by a [`KeyProvider`].
pub struct MemoryKeyedSigner {
    keys: Arc<dyn KeyProvider>,
}

impl MemoryKeyedSigner {
    pub fn new(keys: Arc<dyn KeyProvider>) -> Self {
        Self { keys }
    }
}

#[async_trait]
impl Signer for MemoryKeyedSigner {
    async fn sign(
        &self,
        subject_digest: &str,
        identity: &SigningIdentity,
    ) -> Result<SignatureArtifact, SignError> {
        let key_ref = match identity {
            SigningIdentity::Keyed { key_ref } => key_ref.as_str(),
            SigningIdentity::Keyless { .. } => {
                return Err(SignError::InvalidIdentity(
                    "MemoryKeyedSigner does not support keyless; use SigstoreSigner (B2)".into(),
                ));
            }
        };
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
        let sk = signing_key_from_material(&material)?;
        let payload = signing_payload(subject_digest);
        let sig: Signature = sk.sign(&payload);

        let envelope = Ed25519Envelope {
            digest: subject_digest.to_string(),
            key_ref: key_ref.to_string(),
            signature: B64.encode(sig.to_bytes()),
            algorithm: "ed25519".into(),
        };
        Ok(envelope.to_artifact(key_ref)?)
    }
}

/// Keyed ed25519 verifier backed by a [`KeyProvider`].
pub struct MemoryKeyedVerifier {
    keys: Arc<dyn KeyProvider>,
}

impl MemoryKeyedVerifier {
    pub fn new(keys: Arc<dyn KeyProvider>) -> Self {
        Self { keys }
    }
}

#[async_trait]
impl Verifier for MemoryKeyedVerifier {
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
        let payload = signing_payload(subject_digest);

        for artifact in signatures {
            let envelope = match Ed25519Envelope::from_artifact(artifact) {
                Ok(e) => e,
                Err(e) => {
                    tracing::debug!(error = %e, "skip malformed signature artifact");
                    continue;
                }
            };
            if envelope.digest != subject_digest {
                continue;
            }
            if !trusted_refs.is_empty() && !trusted_refs.contains(&envelope.key_ref.as_str()) {
                continue;
            }

            let material = match self.keys.resolve(&envelope.key_ref).await {
                Ok(m) => m,
                Err(_) => continue,
            };
            let vk = match verifying_key_from_material(&material) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let sig_bytes = match B64.decode(&envelope.signature) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if sig_bytes.len() != 64 {
                continue;
            }
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&sig_bytes);
            let signature = Signature::from_bytes(&arr);
            if vk.verify(&payload, &signature).is_ok() {
                matched.push(envelope.key_ref.clone());
            }
        }

        let trusted = !matched.is_empty() || (!policy.required && signatures.is_empty());
        // If policy.required and we found no match:
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
            trusted,
            matched_signers: matched,
            policy_id: policy.id,
            reason: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SigningIdentity;
    use crate::policy::VerificationPolicy;

    #[tokio::test]
    async fn sign_verify_round_trip() {
        let (keys, _, _) = generate_ed25519("cosign://test");
        let signer = MemoryKeyedSigner::new(keys.clone());
        let verifier = MemoryKeyedVerifier::new(keys);
        let digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let art = signer
            .sign(digest, &SigningIdentity::keyed("cosign://test"))
            .await
            .unwrap();
        assert_eq!(art.signature_type, "cosign-key");
        assert_eq!(
            SignatureArtifact::cosign_sig_tag(digest).unwrap(),
            "sha256-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.sig"
        );

        let policy = VerificationPolicy::require_keys("prod", &["cosign://test"]);
        let out = verifier.verify(digest, &[art], &policy).await.unwrap();
        assert!(out.trusted);
        assert_eq!(out.matched_signers, vec!["cosign://test".to_string()]);
    }

    #[tokio::test]
    async fn wrong_key_fails() {
        let (keys_a, _, _) = generate_ed25519("cosign://a");
        let (keys_b, _, _) = generate_ed25519("cosign://b");
        // Merge B's public into a provider that only has A for verify of A's policy —
        // sign with A, verify requiring B.
        let signer = MemoryKeyedSigner::new(keys_a);
        let digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let art = signer
            .sign(digest, &SigningIdentity::keyed("cosign://a"))
            .await
            .unwrap();

        let verifier = MemoryKeyedVerifier::new(keys_b);
        let policy = VerificationPolicy::require_keys("prod", &["cosign://b"]);
        let err = verifier.verify(digest, &[art], &policy).await.unwrap_err();
        assert!(matches!(err, VerifyError::PolicyDenied(_)));
    }
}
