//! Registry-side audit log — ring buffer + chained [`specton_audit::AuditSink`].
//!
//! Slice A2: every `record` dual-writes to the in-memory ring (dashboard
//! compat) and to the configured sink. Write-class events (`push`,
//! `delete`, `replicated`) fail closed when the durable sink errors;
//! pull-class events are sampled and never fail the request.

use std::collections::VecDeque;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use rand::Rng;
use serde::Serialize;
use specton_audit::{
    Actor, AuditEvent, AuditSink, Category, Outcome, Subject,
};
use tokio::sync::RwLock;
use tracing::warn;

/// Maximum number of audit events to keep in the memory ring.
const MAX_EVENTS: usize = 10_000;

/// A registry activity audit event (dashboard / ring-buffer shape).
#[derive(Debug, Clone, Serialize)]
pub struct RegistryAuditEvent {
    pub timestamp: DateTime<Utc>,
    /// Event type: "manifest.push", "manifest.pull", "manifest.delete",
    /// "blob.pull", "blob.push", "tag.list", "catalog.list",
    /// "manifest.replicated"
    pub event_type: String,
    /// Subject identity from JWT (e.g. user/service account).
    pub subject: String,
    /// Tenant name.
    pub tenant: String,
    /// Project name.
    pub project: String,
    /// Repository name.
    pub repository: String,
    /// Tag or digest reference (if applicable).
    pub reference: String,
    /// Content digest (if applicable).
    pub digest: String,
    /// Size in bytes (for push operations).
    pub size_bytes: u64,
    /// HTTP status code of the response.
    pub status_code: u16,
    /// Duration of the operation in milliseconds.
    pub duration_ms: u64,
}

impl RegistryAuditEvent {
    fn category(&self) -> Category {
        match self.event_type.as_str() {
            "manifest.push" | "blob.push" | "manifest.replicated" => Category::Push,
            "manifest.pull" | "blob.pull" | "tag.list" | "catalog.list" => Category::Pull,
            "manifest.delete" => Category::Delete,
            "manifest.promote" => Category::Promote,
            _ => Category::Admin,
        }
    }

    fn is_write(&self) -> bool {
        matches!(
            self.event_type.as_str(),
            "manifest.push"
                | "blob.push"
                | "manifest.delete"
                | "manifest.replicated"
                | "manifest.promote"
        )
    }

    fn is_pull(&self) -> bool {
        matches!(
            self.event_type.as_str(),
            "manifest.pull" | "blob.pull" | "tag.list" | "catalog.list"
        )
    }

    fn to_chained(&self) -> AuditEvent {
        let outcome = if self.status_code < 400 {
            Outcome::Success
        } else {
            Outcome::Failure {
                code: self.status_code.to_string(),
            }
        };
        AuditEvent {
            at: self.timestamp,
            category: self.category(),
            action: self.event_type.clone(),
            actor: Actor {
                sub: self.subject.clone(),
                role: None,
                source_ip: None,
                ua: None,
            },
            subject: Some(Subject {
                tenant: Some(self.tenant.clone()),
                project: Some(self.project.clone()),
                repo: Some(self.repository.clone()),
                reference: Some(self.reference.clone()),
                digest: Some(self.digest.clone()),
            }),
            outcome,
            attributes: [
                ("size_bytes".into(), serde_json::json!(self.size_bytes)),
                ("status_code".into(), serde_json::json!(self.status_code)),
                ("duration_ms".into(), serde_json::json!(self.duration_ms)),
            ]
            .into_iter()
            .collect(),
        }
    }
}

/// Thread-safe ring buffer + durable sink.
pub struct RegistryAuditLog {
    events: RwLock<VecDeque<RegistryAuditEvent>>,
    sink: Arc<dyn AuditSink>,
    /// Fraction of pull events to persist (0.0–1.0). Writes always persist.
    sample_pulls: f64,
    /// When true, sink failures on write-class events bubble up.
    fail_closed_writes: bool,
}

impl RegistryAuditLog {
    pub fn new() -> Self {
        Self::with_sink(Arc::new(specton_audit::InMemoryAudit::for_tests()), 0.0, false)
    }

    pub fn with_sink(
        sink: Arc<dyn AuditSink>,
        sample_pulls: f64,
        fail_closed_writes: bool,
    ) -> Self {
        Self {
            events: RwLock::new(VecDeque::with_capacity(MAX_EVENTS)),
            sink,
            sample_pulls: sample_pulls.clamp(0.0, 1.0),
            fail_closed_writes,
        }
    }

    pub fn sink(&self) -> Arc<dyn AuditSink> {
        self.sink.clone()
    }

    /// Record a new audit event. Write-class events may return
    /// [`AuditPersistError`] when the durable sink fails and fail-closed
    /// is enabled.
    pub async fn record(&self, event: RegistryAuditEvent) -> Result<(), AuditPersistError> {
        // Ring buffer always accepts (dashboard).
        {
            let mut events = self.events.write().await;
            if events.len() >= MAX_EVENTS {
                events.pop_front();
            }
            events.push_back(event.clone());
        }

        let persist = if event.is_write() {
            true
        } else if event.is_pull() {
            self.sample_pulls > 0.0 && rand::rng().random::<f64>() < self.sample_pulls
        } else {
            true
        };

        if !persist {
            return Ok(());
        }

        match self.sink.append(event.to_chained()).await {
            Ok(_) => Ok(()),
            Err(e) => {
                if event.is_write() && self.fail_closed_writes {
                    Err(AuditPersistError(e.to_string()))
                } else {
                    warn!(error = %e, event_type = %event.event_type, "audit sink append failed");
                    Ok(())
                }
            }
        }
    }

    /// Get the most recent N audit events.
    pub async fn recent(&self, limit: usize) -> Vec<RegistryAuditEvent> {
        let events = self.events.read().await;
        events.iter().rev().take(limit).cloned().collect()
    }

    /// Get the total number of events in the buffer.
    pub async fn count(&self) -> usize {
        self.events.read().await.len()
    }

    /// Get events filtered by event type.
    pub async fn by_type(&self, event_type: &str, limit: usize) -> Vec<RegistryAuditEvent> {
        let events = self.events.read().await;
        events
            .iter()
            .rev()
            .filter(|e| e.event_type == event_type)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get events filtered by subject (who).
    pub async fn by_subject(&self, subject: &str, limit: usize) -> Vec<RegistryAuditEvent> {
        let events = self.events.read().await;
        events
            .iter()
            .rev()
            .filter(|e| e.subject == subject)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get summary statistics.
    pub async fn stats(&self) -> AuditStats {
        let events = self.events.read().await;
        let mut stats = AuditStats::default();

        for event in events.iter() {
            match event.event_type.as_str() {
                "manifest.push" | "manifest.replicated" => {
                    stats.total_pushes += 1;
                    stats.total_push_bytes += event.size_bytes;
                }
                "manifest.pull" | "blob.pull" => {
                    stats.total_pulls += 1;
                }
                "manifest.delete" => {
                    stats.total_deletes += 1;
                }
                _ => {}
            }
            stats.total_events += 1;

            if stats.latest_event.is_none() || event.timestamp > stats.latest_event.unwrap() {
                stats.latest_event = Some(event.timestamp);
            }
        }

        let recent: Vec<_> = events.iter().rev().take(100).collect();
        if !recent.is_empty() {
            let total_ms: u64 = recent.iter().map(|e| e.duration_ms).sum();
            stats.avg_latency_ms = total_ms as f64 / recent.len() as f64;
        }

        stats
    }
}

impl Default for RegistryAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Durable sink refused a write-class event.
#[derive(Debug, thiserror::Error)]
#[error("audit persist failed: {0}")]
pub struct AuditPersistError(pub String);

/// Summary statistics for the audit log.
#[derive(Debug, Clone, Serialize, Default)]
pub struct AuditStats {
    pub total_events: u64,
    pub total_pushes: u64,
    pub total_pulls: u64,
    pub total_deletes: u64,
    pub total_push_bytes: u64,
    pub avg_latency_ms: f64,
    pub latest_event: Option<DateTime<Utc>>,
}
