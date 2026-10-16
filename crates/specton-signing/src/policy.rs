//! Verification policy shapes (CRD-aligned; CRD lands in B4).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnViolation {
    #[default]
    Block,
    Warn,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedSigner {
    Key {
        key_ref: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity_name: Option<String>,
    },
    /// v1.1 — MemoryKeyedVerifier ignores these.
    Keyless {
        issuer: String,
        subject_pattern: String,
    },
}

impl TrustedSigner {
    pub fn key(key_ref: impl Into<String>) -> Self {
        Self::Key {
            key_ref: key_ref.into(),
            identity_name: None,
        }
    }

    pub fn key_ref(&self) -> Option<&str> {
        match self {
            Self::Key { key_ref, .. } => Some(key_ref.as_str()),
            Self::Keyless { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationPolicy {
    pub id: Uuid,
    pub name: String,
    /// When true, at least one trusted signature must verify.
    pub required: bool,
    pub trusted_signers: Vec<TrustedSigner>,
    pub on_violation: OnViolation,
}

impl VerificationPolicy {
    pub fn require_keys(name: impl Into<String>, key_refs: &[&str]) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            required: true,
            trusted_signers: key_refs.iter().map(|k| TrustedSigner::key(*k)).collect(),
            on_violation: OnViolation::Block,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationOutcome {
    pub trusted: bool,
    pub matched_signers: Vec<String>,
    pub policy_id: Uuid,
    /// Human-readable reason when `trusted == false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
