//! SpectonCR append-only hash-chained registry audit log.
//!
//! - **A1:** [`AuditSink`], [`InMemoryAudit`], [`PgChainedAudit`], schema `0017`
//! - **A2:** registry dual-write + `/v2/_audit` routes
//! - **A3:** JSONL export, Merkle checkpoints, `specton-audit` CLI
//!
//! See `docs/design/005-audit-log.md` and
//! `docs/design/PHASE-A-D-BUILD-LIFECYCLE.md`.
//!
//! **Naming:** tables are `registry_audit_*` so we do not collide with the
//! scanner's simpler `audit_log` from `0001_init.sql`.

#![allow(clippy::double_must_use)] // async_trait + Future on rustc ≥1.99

pub mod checkpoint;
pub mod event;
pub mod export;
pub mod hash;
pub mod memory;
pub mod merkle;
pub mod postgres;
pub mod sink;

pub use checkpoint::{
    Checkpoint, CheckpointStore, MemoryCheckpointStore, PgCheckpointStore, export_pending, tip_id,
};
pub use event::{Actor, AuditEvent, AuditRow, Category, Outcome, Subject};
pub use export::{
    ExportDestination, ExportError, ExportLine, ExportResult, FilesystemDestination,
    MemoryDestination, ObjectStoreDestination, content_digest, encode_jsonl, export_range,
    root_for_rows, verify_export_bytes,
};
pub use hash::{GENESIS_PREV, HashError, compute_row_hash};
pub use memory::InMemoryAudit;
pub use merkle::merkle_root;
pub use postgres::{Keyring, PgChainedAudit};
pub use sink::{AuditError, AuditQuery, AuditSink, ChainVerdict, EventId};
