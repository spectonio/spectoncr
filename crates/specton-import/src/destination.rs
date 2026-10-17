//! Destination trait + an HTTP impl that pushes through the
//! SpectonCR registry's standard OCI Distribution API.
//!
//! The runner is source-agnostic on the read side
//! (`RegistrySource`) and destination-agnostic on the write side
//! (`RegistryDestination`) — wiring is via small adapters. This
//! lets unit tests drive the runner against an in-memory
//! destination without standing up a registry.

use crate::source::ImportError;
use async_trait::async_trait;
use bytes::Bytes;
use object_store::path::Path as StorePath;
use object_store::ObjectStore;
use specton_common::storage::{blob_path, manifest_path, sha256_digest, tag_link_path};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[async_trait]
pub trait RegistryDestination: Send + Sync {
    /// Upload a blob. Implementations are responsible for
    /// idempotency (HEAD before upload).
    async fn put_blob(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
        digest: &str,
        bytes: Bytes,
    ) -> Result<(), ImportError>;

    /// Upload a manifest under `tenant/project/repository:tag`.
    async fn put_manifest(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
        tag: &str,
        bytes: Bytes,
        media_type: &str,
    ) -> Result<(), ImportError>;
}

/// In-process destination — used for unit tests + dry-run runs.
/// Records every put without actually shipping bytes anywhere.
#[derive(Default, Clone)]
pub struct InMemoryDestination {
    pub blobs: Arc<RwLock<HashMap<String, Bytes>>>,
    pub manifests: Arc<RwLock<HashMap<String, (Bytes, String)>>>,
}

impl InMemoryDestination {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn blob_count(&self) -> usize {
        self.blobs.read().unwrap().len()
    }
    pub fn manifest_count(&self) -> usize {
        self.manifests.read().unwrap().len()
    }
}

#[async_trait]
impl RegistryDestination for InMemoryDestination {
    async fn put_blob(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
        digest: &str,
        bytes: Bytes,
    ) -> Result<(), ImportError> {
        let key = format!("{tenant}/{project}/{repository}/{digest}");
        self.blobs.write().unwrap().insert(key, bytes);
        Ok(())
    }

    async fn put_manifest(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
        tag: &str,
        bytes: Bytes,
        media_type: &str,
    ) -> Result<(), ImportError> {
        let key = format!("{tenant}/{project}/{repository}:{tag}");
        self.manifests
            .write()
            .unwrap()
            .insert(key, (bytes, media_type.to_string()));
        Ok(())
    }
}

/// Writes blobs/manifests/tag links into the registry object store using
/// the same path layout as `specton-registry`.
pub struct ObjectStoreDestination {
    store: Arc<dyn ObjectStore>,
}

impl ObjectStoreDestination {
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }

    async fn exists(&self, path: &str) -> Result<bool, ImportError> {
        match self.store.head(&StorePath::from(path)).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(ImportError::Parse(format!("object store head: {e}"))),
        }
    }
}

#[async_trait]
impl RegistryDestination for ObjectStoreDestination {
    async fn put_blob(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
        digest: &str,
        bytes: Bytes,
    ) -> Result<(), ImportError> {
        let path = blob_path(tenant, project, repository, digest);
        if self.exists(&path).await? {
            return Ok(());
        }
        self.store
            .put(&StorePath::from(path), bytes.into())
            .await
            .map_err(|e| ImportError::Parse(format!("object store put blob: {e}")))?;
        Ok(())
    }

    async fn put_manifest(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
        tag: &str,
        bytes: Bytes,
        _media_type: &str,
    ) -> Result<(), ImportError> {
        let digest = sha256_digest(&bytes);
        let man_path = manifest_path(tenant, project, repository, &digest);
        if !self.exists(&man_path).await? {
            self.store
                .put(&StorePath::from(man_path), bytes.into())
                .await
                .map_err(|e| ImportError::Parse(format!("object store put manifest: {e}")))?;
        }
        let tag_path = tag_link_path(tenant, project, repository, tag);
        self.store
            .put(&StorePath::from(tag_path), digest.into())
            .await
            .map_err(|e| ImportError::Parse(format!("object store put tag link: {e}")))?;
        Ok(())
    }
}
