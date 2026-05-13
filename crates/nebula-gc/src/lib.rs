//! NebulaCR online garbage collector.
//!
//! Slice 1 ships the live refcount writer:
//! - [`BlobRefCounter`] trait — `add_refs` on manifest push, `remove_refs`
//!   on manifest delete. Both run inside a caller-supplied Postgres tx so
//!   the refcount mutation is atomic with the manifest mutation.
//! - [`PgBlobRefCounter`] — the Postgres implementation backed by tables
//!   created by `migrations/0004_online_gc.sql`.
//! - [`extract_blob_digests`] — pulls layer + config descriptors out of an
//!   OCI manifest or image index without needing the registry to depend
//!   on this crate's parser.
//!
//! Slices 2-4 add the continuous reaper, the reconciler, and operator
//! surfaces (CLI / MCP / Helm). They share this trait.

pub mod manifest;
pub mod refcount;

pub use manifest::{extract_blob_digests, BlobDescriptor, ManifestParseError};
pub use refcount::{BlobRefCounter, GcError, NoopBlobRefCounter, PgBlobRefCounter};
