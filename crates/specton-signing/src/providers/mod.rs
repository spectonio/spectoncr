//! Key providers that resolve `key_ref` URIs to PEM / material.
//!
//! Supported schemes:
//! - `file://` / bare path — [`FilePemKeyProvider`]
//! - `vault://kv/...` — [`VaultKvKeyProvider`] (KV v2 PEM material)
//! - `vault://transit/...` — public key export hint; signing uses
//!   [`crate::vault_transit::VaultTransitSigner`] (remote sign)
//! - `memory://` / `cosign://` — delegated to an inner [`MemoryKeyProvider`]

pub mod composite;
pub mod file;
pub mod vault;

pub use composite::CompositeKeyProvider;
pub use file::FilePemKeyProvider;
pub use vault::{VaultKvConfig, VaultKvKeyProvider};
