//! Hash-chain helpers for the registry audit log.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::event::{AuditEvent, CanonicalPayload};

type HmacSha256 = Hmac<Sha256>;

/// Genesis previous-hash (32 zero bytes) used when the chain is empty.
pub const GENESIS_PREV: [u8; 32] = [0u8; 32];

/// Build the canonical JSON bytes for an event under a given key id.
pub fn canonical_bytes(event: &AuditEvent, hmac_key_id: &str) -> Result<Vec<u8>, serde_json::Error> {
    let payload = CanonicalPayload {
        at: &event.at,
        category: event.category.as_str(),
        action: &event.action,
        actor_sub: &event.actor.sub,
        actor_ip: event.actor.source_ip.as_deref(),
        actor_ua: event.actor.ua.as_deref(),
        subject: event.subject.as_ref(),
        outcome: event.outcome.as_str(),
        error_code: event.outcome.error_code(),
        attributes: &event.attributes,
        hmac_key_id,
    };
    serde_json::to_vec(&payload)
}

/// `row_hash = HMAC-SHA256(key, prev_hash || canonical_json(event))`.
pub fn compute_row_hash(
    hmac_key: &[u8],
    prev_hash: &[u8],
    event: &AuditEvent,
    hmac_key_id: &str,
) -> Result<[u8; 32], HashError> {
    let canonical = canonical_bytes(event, hmac_key_id).map_err(HashError::Canonical)?;
    let mut mac = HmacSha256::new_from_slice(hmac_key).map_err(|_| HashError::BadKey)?;
    mac.update(prev_hash);
    mac.update(&canonical);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("canonical json: {0}")]
    Canonical(serde_json::Error),
    #[error("invalid hmac key length")]
    BadKey,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Actor, Category, Outcome};
    use chrono::{TimeZone, Utc};

    fn sample_event() -> AuditEvent {
        AuditEvent {
            at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            category: Category::Push,
            action: "manifest.push".into(),
            actor: Actor {
                sub: "ci@example.com".into(),
                role: None,
                source_ip: Some("127.0.0.1".into()),
                ua: None,
            },
            subject: None,
            outcome: Outcome::Success,
            attributes: Default::default(),
        }
    }

    #[test]
    fn same_input_same_hash() {
        let e = sample_event();
        let key = b"test-hmac-key-32-bytes-long!!!!!!";
        let a = compute_row_hash(key, &GENESIS_PREV, &e, "v1").unwrap();
        let b = compute_row_hash(key, &GENESIS_PREV, &e, "v1").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_prev_different_hash() {
        let e = sample_event();
        let key = b"test-hmac-key-32-bytes-long!!!!!!";
        let a = compute_row_hash(key, &GENESIS_PREV, &e, "v1").unwrap();
        let other = [1u8; 32];
        let b = compute_row_hash(key, &other, &e, "v1").unwrap();
        assert_ne!(a, b);
    }
}
