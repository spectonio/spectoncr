//! [`Signer`] trait.

use async_trait::async_trait;

use crate::artifact::SignatureArtifact;
use crate::error::SignError;
use crate::identity::SigningIdentity;

#[async_trait]
pub trait Signer: Send + Sync {
    /// Sign the descriptor of a manifest by digest. Returns a cosign-style
    /// `.sig` artifact body and its OCI media type.
    async fn sign(
        &self,
        subject_digest: &str,
        identity: &SigningIdentity,
    ) -> Result<SignatureArtifact, SignError>;
}
