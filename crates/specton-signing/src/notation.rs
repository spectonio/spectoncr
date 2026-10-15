//! Notation stub — keeps the trait pluggable until a real notary-rs impl.

use async_trait::async_trait;

use crate::artifact::SignatureArtifact;
use crate::error::{SignError, VerifyError};
use crate::identity::SigningIdentity;
use crate::policy::{VerificationOutcome, VerificationPolicy};
use crate::signer::Signer;
use crate::verifier::Verifier;

/// Placeholder Notation signer/verifier. Always returns `NotImplemented`.
pub struct NotationStub;

#[async_trait]
impl Signer for NotationStub {
    async fn sign(
        &self,
        _subject_digest: &str,
        _identity: &SigningIdentity,
    ) -> Result<SignatureArtifact, SignError> {
        Err(SignError::NotImplemented(
            "Notation signing lands after cosign keyed path (B2+)".into(),
        ))
    }
}

#[async_trait]
impl Verifier for NotationStub {
    async fn verify(
        &self,
        _subject_digest: &str,
        _signatures: &[SignatureArtifact],
        _policy: &VerificationPolicy,
    ) -> Result<VerificationOutcome, VerifyError> {
        Err(VerifyError::NotImplemented(
            "Notation verification not implemented".into(),
        ))
    }
}
