//! SpectonCR image signing — design 001.
//!
//! - **B1:** [`Signer`] / [`Verifier`], [`MemoryKeyedSigner`] (ed25519 seeds)
//! - **B2:** [`SigstoreSigner`] / [`SigstoreVerifier`] (cosign simple-signing
//!   via sigstore-rs), [`FilePemKeyProvider`], [`VaultKvKeyProvider`],
//!   [`VaultTransitSigner`], `specton-sign` CLI
//! - **B3:** [`SignatureStore`] + cosign `.sig` tag helpers + registry routes
//! - **B4:** [`PolicyStore`] + verify-on-pull + `ImageVerificationPolicy` CRD
//!
//! Kill-switch: `[signing] enabled = false` (wired in B4 registry hooks).

pub mod artifact;
pub mod cosign_payload;
pub mod error;
pub mod identity;
pub mod key_provider;
pub mod memory;
pub mod notation;
pub mod policy;
pub mod policy_store;
pub mod providers;
pub mod signer;
pub mod sigstore_keyed;
pub mod store;
pub mod vault_transit;
pub mod verifier;

pub use artifact::{Ed25519Envelope, MEDIA_TYPE_ED25519_V1, SignatureArtifact};
pub use cosign_payload::{
    CosignEnvelope, CosignSimpleSigning, MEDIA_TYPE_COSIGN_ENVELOPE_V1, MEDIA_TYPE_COSIGN_SIMPLE,
};
pub use error::{KeyProviderError, SignError, VerifyError};
pub use identity::{FulcioConfig, OidcToken, SigningIdentity};
pub use key_provider::{KeyMaterial, KeyProvider, MemoryKeyProvider};
pub use memory::{
    MemoryKeyedSigner, MemoryKeyedVerifier, generate_ed25519, signing_payload,
};
pub use notation::NotationStub;
pub use policy::{OnViolation, TrustedSigner, VerificationOutcome, VerificationPolicy};
pub use policy_store::{
    PgPolicyStore, PolicyScope, PolicySpec, PolicyStore, PolicyStoreError, StoredVerificationPolicy,
};
pub use providers::{
    CompositeKeyProvider, FilePemKeyProvider, VaultKvConfig, VaultKvKeyProvider,
};
pub use signer::Signer;
pub use sigstore_keyed::{SigstoreSigner, SigstoreVerifier, generate_pem_keypair};
pub use store::{
    PgSignatureStore, SignatureRecord, SignatureStore, SignatureStoreError, is_cosign_sig_tag,
    subject_digest_from_sig_tag,
};
pub use vault_transit::{VaultTransitConfig, VaultTransitSigner};
pub use verifier::Verifier;
