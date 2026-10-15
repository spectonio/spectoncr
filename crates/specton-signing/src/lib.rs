//! SpectonCR image signing — design 001.
//!
//! **B1 (this slice):** [`Signer`] / [`Verifier`] traits, [`MemoryKeyedSigner`] /
//! [`MemoryKeyedVerifier`] (ed25519), [`MemoryKeyProvider`], [`NotationStub`].
//!
//! **B2:** sigstore-rs + Vault / file PEM [`KeyProvider`].
//! **B3:** store cosign `.sig` artifacts + audit.
//! **B4:** `ImageVerificationPolicy` CRD + verify-on-pull.
//!
//! Kill-switch: `[signing] enabled = false` (wired in B4 registry hooks).

pub mod artifact;
pub mod error;
pub mod identity;
pub mod key_provider;
pub mod memory;
pub mod notation;
pub mod policy;
pub mod signer;
pub mod verifier;

pub use artifact::{Ed25519Envelope, MEDIA_TYPE_ED25519_V1, SignatureArtifact};
pub use error::{KeyProviderError, SignError, VerifyError};
pub use identity::{FulcioConfig, OidcToken, SigningIdentity};
pub use key_provider::{KeyMaterial, KeyProvider, MemoryKeyProvider};
pub use memory::{
    MemoryKeyedSigner, MemoryKeyedVerifier, generate_ed25519, signing_payload,
};
pub use notation::NotationStub;
pub use policy::{OnViolation, TrustedSigner, VerificationOutcome, VerificationPolicy};
pub use signer::Signer;
pub use verifier::Verifier;
