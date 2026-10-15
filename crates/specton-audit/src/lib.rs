//! SpectonCR append-only hash-chained registry audit log.
//!
//! Slice 1 (PR A1) ships:
//! - [`AuditSink`] trait — `append` / `query` / `get` / `verify_chain`
//! - [`InMemoryAudit`] — default backend (`[audit] backend = "memory"`)
//! - [`PgChainedAudit`] — Postgres backend (`migrations/0017_registry_audit.sql`)
//! - HMAC-SHA256 chain: `row_hash = HMAC(key, prev_hash || canonical_json)`
//!
//! Slice 2 wires call sites + HTTP routes. Slice 3 adds S3 export and
//! Merkle checkpoints. See `docs/design/005-audit-log.md` and
//! `docs/design/PHASE-A-D-BUILD-LIFECYCLE.md`.
//!
//! **Naming:** tables are `registry_audit_*` so we do not collide with the
//! scanner's simpler `audit_log` from `0001_init.sql`.

pub mod event;
pub mod hash;
pub mod memory;
pub mod postgres;
pub mod sink;

pub use event::{Actor, AuditEvent, AuditRow, Category, Outcome, Subject};
pub use hash::{GENESIS_PREV, HashError, compute_row_hash};
pub use memory::InMemoryAudit;
pub use postgres::{Keyring, PgChainedAudit};
pub use sink::{AuditError, AuditQuery, AuditSink, ChainVerdict, EventId};
