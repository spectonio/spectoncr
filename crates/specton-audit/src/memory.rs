//! In-memory chained audit sink — default when `[audit] backend = "memory"`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::event::{AuditEvent, AuditRow};
use crate::hash::{GENESIS_PREV, compute_row_hash};
use crate::sink::{AuditError, AuditQuery, AuditSink, ChainVerdict, EventId};

/// Dev / test / default backend. Survives only for the process lifetime.
pub struct InMemoryAudit {
    rows: RwLock<Vec<AuditRow>>,
    next_id: AtomicI64,
    hmac_key: Vec<u8>,
    hmac_key_id: String,
    /// Optional extra keys for mid-stream rotation tests.
    keys: RwLock<HashMap<String, Vec<u8>>>,
}

impl InMemoryAudit {
    pub fn new(hmac_key: impl Into<Vec<u8>>, hmac_key_id: impl Into<String>) -> Self {
        let hmac_key = hmac_key.into();
        let hmac_key_id = hmac_key_id.into();
        let mut keys = HashMap::new();
        keys.insert(hmac_key_id.clone(), hmac_key.clone());
        Self {
            rows: RwLock::new(Vec::new()),
            next_id: AtomicI64::new(1),
            hmac_key,
            hmac_key_id,
            keys: RwLock::new(keys),
        }
    }

    /// Convenience constructor with a fixed test key.
    pub fn for_tests() -> Self {
        Self::new(b"test-hmac-key-32-bytes-long!!!!!!".to_vec(), "v1")
    }

    /// Switch active key for mid-stream rotation tests.
    pub fn register_and_activate(
        &mut self,
        new_id: impl Into<String>,
        new_key: impl Into<Vec<u8>>,
    ) {
        let new_id = new_id.into();
        let new_key = new_key.into();
        self.keys.get_mut().insert(new_id.clone(), new_key.clone());
        self.hmac_key = new_key;
        self.hmac_key_id = new_id;
    }

    fn tenant_of(event: &AuditEvent) -> Option<String> {
        event.subject.as_ref().and_then(|s| s.tenant.clone())
    }

    async fn resolve_key(&self, key_id: &str) -> Result<Vec<u8>, AuditError> {
        if key_id == self.hmac_key_id {
            return Ok(self.hmac_key.clone());
        }
        self.keys
            .read()
            .await
            .get(key_id)
            .cloned()
            .ok_or_else(|| AuditError::UnknownKey(key_id.to_string()))
    }
}

#[async_trait]
impl AuditSink for InMemoryAudit {
    async fn append(&self, event: AuditEvent) -> Result<EventId, AuditError> {
        let mut rows = self.rows.write().await;
        let prev_hash: [u8; 32] = match rows.last() {
            Some(last) => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(&last.row_hash);
                buf
            }
            None => GENESIS_PREV,
        };
        let row_hash = compute_row_hash(&self.hmac_key, &prev_hash, &event, &self.hmac_key_id)?;
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let tenant = Self::tenant_of(&event);
        rows.push(AuditRow {
            id,
            event,
            tenant,
            prev_hash: Some(prev_hash.to_vec()),
            row_hash: row_hash.to_vec(),
            hmac_key_id: self.hmac_key_id.clone(),
        });
        Ok(id)
    }

    async fn query(&self, q: AuditQuery) -> Result<Vec<AuditRow>, AuditError> {
        let rows = self.rows.read().await;
        let limit = if q.limit == 0 { 100 } else { q.limit };
        let filtered: Vec<AuditRow> = rows
            .iter()
            .rev()
            .filter(|r| {
                if let Some(since) = q.since
                    && r.event.at < since
                {
                    return false;
                }
                if let Some(until) = q.until
                    && r.event.at > until
                {
                    return false;
                }
                if let Some(ref actor) = q.actor
                    && r.event.actor.sub != *actor
                {
                    return false;
                }
                if let Some(cat) = q.category
                    && r.event.category != cat
                {
                    return false;
                }
                if let Some(ref tenant) = q.tenant
                    && r.tenant.as_deref() != Some(tenant.as_str())
                {
                    return false;
                }
                true
            })
            .take(limit)
            .cloned()
            .collect();
        Ok(filtered)
    }

    async fn get(&self, id: EventId) -> Result<AuditRow, AuditError> {
        self.rows
            .read()
            .await
            .iter()
            .find(|r| r.id == id)
            .cloned()
            .ok_or(AuditError::NotFound(id))
    }

    async fn verify_chain(&self, from: EventId, to: EventId) -> Result<ChainVerdict, AuditError> {
        let rows = self.rows.read().await;
        let slice: Vec<&AuditRow> = rows.iter().filter(|r| r.id >= from && r.id <= to).collect();

        let mut checked = 0u64;
        let mut expected_prev = GENESIS_PREV.to_vec();

        // If `from` is not the first row, seed prev from the row before `from`.
        if let Some(before) = rows.iter().rev().find(|r| r.id < from) {
            expected_prev = before.row_hash.clone();
        } else if from > 1 {
            // Chain starts mid-stream without prior — use stored prev_hash of first.
            if let Some(first) = slice.first()
                && let Some(ref ph) = first.prev_hash
            {
                expected_prev = ph.clone();
            }
        }

        for row in slice {
            let key = self.resolve_key(&row.hmac_key_id).await?;
            let mut prev = [0u8; 32];
            if expected_prev.len() == 32 {
                prev.copy_from_slice(&expected_prev);
            } else {
                return Ok(ChainVerdict {
                    ok: false,
                    checked,
                    broken_at: Some(row.id),
                    expected_hash: Some(hex::encode(&expected_prev)),
                    actual_hash: Some(hex::encode(row.prev_hash.clone().unwrap_or_default())),
                });
            }

            if let Some(ref stored_prev) = row.prev_hash
                && stored_prev.as_slice() != prev.as_slice()
            {
                return Ok(ChainVerdict {
                    ok: false,
                    checked,
                    broken_at: Some(row.id),
                    expected_hash: Some(hex::encode(prev)),
                    actual_hash: Some(hex::encode(stored_prev)),
                });
            }

            let expected = compute_row_hash(&key, &prev, &row.event, &row.hmac_key_id)?;
            if expected.as_slice() != row.row_hash.as_slice() {
                return Ok(ChainVerdict {
                    ok: false,
                    checked,
                    broken_at: Some(row.id),
                    expected_hash: Some(hex::encode(expected)),
                    actual_hash: Some(hex::encode(&row.row_hash)),
                });
            }
            expected_prev = row.row_hash.clone();
            checked += 1;
        }

        Ok(ChainVerdict {
            ok: true,
            checked,
            broken_at: None,
            expected_hash: None,
            actual_hash: None,
        })
    }
}

/// Mutate a stored row hash to simulate tampering (test / chaos only).
pub async fn tamper_row_hash_for_test(sink: &InMemoryAudit, id: EventId) {
    let mut rows = sink.rows.write().await;
    if let Some(row) = rows.iter_mut().find(|r| r.id == id) {
        row.row_hash[0] ^= 0xff;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Actor, Category};

    #[tokio::test]
    async fn tamper_breaks_verify() {
        let sink = InMemoryAudit::for_tests();
        sink.append(AuditEvent::success(
            Category::Push,
            "manifest.push",
            Actor::system(),
        ))
        .await
        .unwrap();
        sink.append(AuditEvent::success(
            Category::Push,
            "manifest.push",
            Actor::system(),
        ))
        .await
        .unwrap();
        tamper_row_hash_for_test(&sink, 1).await;
        let v = sink.verify_chain(1, 2).await.unwrap();
        assert!(!v.ok);
        assert_eq!(v.broken_at, Some(1));
    }
}
