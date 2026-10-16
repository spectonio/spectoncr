//! [`Verifier`] trait.

use async_trait::async_trait;

use crate::artifact::SignatureArtifact;
use crate::error::VerifyError;
use crate::policy::{VerificationOutcome, VerificationPolicy};

#[async_trait]
pub trait Verifier: Send + Sync {
    /// Verify all signatures attached to `subject_digest` against `policy`.
    async fn verify(
        &self,
        subject_digest: &str,
        signatures: &[SignatureArtifact],
        policy: &VerificationPolicy,
    ) -> Result<VerificationOutcome, VerifyError>;
}
