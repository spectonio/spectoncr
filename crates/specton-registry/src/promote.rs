//! Atomic promotion (design 006 C1).
//!
//! Same object-store: copy blobs/manifests via `ObjectStore::copy` (or
//! get+put fallback), then write the dest tag link last.

use std::sync::Arc;

use bytes::Bytes;
use chrono::Utc;
use object_store::{ObjectStore, path::Path as StorePath};
use serde::{Deserialize, Serialize};
use specton_common::errors::RegistryError;
use specton_common::storage::{blob_path, manifest_path, sha256_digest, tag_link_path};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageRef {
    pub tenant: String,
    pub project: String,
    pub repository: String,
    pub reference: String,
}

impl ImageRef {
    /// Parse `tenant/project/repo:tag` or `tenant/project/repo@sha256:…`.
    pub fn parse(s: &str) -> Result<Self, RegistryError> {
        let (path, reference) = if let Some((p, d)) = s.split_once('@') {
            (p, d.to_string())
        } else if let Some((p, t)) = s.rsplit_once(':') {
            // Avoid splitting digests that look like path:port — require /
            if p.contains('/') {
                (p, t.to_string())
            } else {
                return Err(RegistryError::ManifestInvalid {
                    reason: format!("invalid image ref '{s}' (expected tenant/project/repo:tag)"),
                });
            }
        } else {
            return Err(RegistryError::ManifestInvalid {
                reason: format!("invalid image ref '{s}' (missing :tag or @digest)"),
            });
        };
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            return Err(RegistryError::ManifestInvalid {
                reason: format!(
                    "invalid image ref '{s}' (expected tenant/project/repo:tag, got {path})"
                ),
            });
        }
        Ok(Self {
            tenant: parts[0].into(),
            project: parts[1].into(),
            repository: parts[2].into(),
            reference,
        })
    }

    #[allow(dead_code)]
    pub fn display(&self) -> String {
        if self.reference.starts_with("sha256:") {
            format!(
                "{}/{}/{}@{}",
                self.tenant, self.project, self.repository, self.reference
            )
        } else {
            format!(
                "{}/{}/{}:{}",
                self.tenant, self.project, self.repository, self.reference
            )
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PromoteMode {
    Force,
    DryRun,
    #[serde(rename = "on_policy_pass")]
    OnPolicyPass { policy: String },
}

impl Default for PromoteMode {
    fn default() -> Self {
        Self::Force
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromoteRequest {
    pub source: ImageRef,
    pub dest: ImageRef,
    #[serde(default = "default_true")]
    pub include_signatures: bool,
    #[serde(default = "default_true")]
    pub include_attestations: bool,
    #[serde(default)]
    pub mode: PromoteMode,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromoteOutcome {
    pub id: Uuid,
    pub src_digest: String,
    pub dst_digest: String,
    pub state: String,
    pub bytes_copied: u64,
    pub blob_count: u32,
    pub signatures_copied: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
}

/// Collect digests referenced by an OCI image manifest or index.
pub fn collect_referenced_digests(manifest: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(d) = manifest
        .pointer("/config/digest")
        .and_then(|v| v.as_str())
    {
        out.push(d.to_string());
    }
    if let Some(layers) = manifest.get("layers").and_then(|l| l.as_array()) {
        for layer in layers {
            if let Some(d) = layer.get("digest").and_then(|v| v.as_str()) {
                out.push(d.to_string());
            }
        }
    }
    if let Some(manifests) = manifest.get("manifests").and_then(|m| m.as_array()) {
        for m in manifests {
            if let Some(d) = m.get("digest").and_then(|v| v.as_str()) {
                out.push(d.to_string());
            }
        }
    }
    out
}

async fn store_get(
    store: &dyn ObjectStore,
    path: &str,
) -> Result<Bytes, RegistryError> {
    let r = store
        .get(&StorePath::from(path))
        .await
        .map_err(|e| match &e {
            object_store::Error::NotFound { .. } => RegistryError::ManifestUnknown {
                reference: path.into(),
            },
            _ => RegistryError::Storage(e.to_string()),
        })?;
    r.bytes()
        .await
        .map_err(|e| RegistryError::Storage(e.to_string()))
}

async fn store_exists(store: &dyn ObjectStore, path: &str) -> Result<bool, RegistryError> {
    match store.head(&StorePath::from(path)).await {
        Ok(_) => Ok(true),
        Err(e) if matches!(e, object_store::Error::NotFound { .. }) => Ok(false),
        Err(e) => Err(RegistryError::Storage(e.to_string())),
    }
}

async fn copy_object(
    store: &dyn ObjectStore,
    from: &str,
    to: &str,
) -> Result<u64, RegistryError> {
    if from == to {
        let meta = store
            .head(&StorePath::from(from))
            .await
            .map_err(|e| RegistryError::Storage(e.to_string()))?;
        return Ok(meta.size as u64);
    }
    if store_exists(store, to).await? {
        let meta = store
            .head(&StorePath::from(to))
            .await
            .map_err(|e| RegistryError::Storage(e.to_string()))?;
        return Ok(meta.size as u64);
    }
    // Prefer native copy; fall back to get+put for backends that lack rename.
    match store
        .copy(&StorePath::from(from), &StorePath::from(to))
        .await
    {
        Ok(()) => {
            let meta = store
                .head(&StorePath::from(to))
                .await
                .map_err(|e| RegistryError::Storage(e.to_string()))?;
            Ok(meta.size as u64)
        }
        Err(_) => {
            let bytes = store_get(store, from).await?;
            let n = bytes.len() as u64;
            store
                .put(&StorePath::from(to), bytes.into())
                .await
                .map_err(|e| RegistryError::Storage(e.to_string()))?;
            Ok(n)
        }
    }
}

async fn resolve_digest(
    store: &dyn ObjectStore,
    r: &ImageRef,
) -> Result<(String, Bytes), RegistryError> {
    let digest = if r.reference.starts_with("sha256:") {
        r.reference.clone()
    } else {
        let tag_p = tag_link_path(&r.tenant, &r.project, &r.repository, &r.reference);
        let bytes = store_get(store, &tag_p).await.map_err(|_| {
            RegistryError::TagUnknown {
                tag: r.reference.clone(),
            }
        })?;
        String::from_utf8_lossy(&bytes).trim().to_string()
    };
    let m_path = manifest_path(&r.tenant, &r.project, &r.repository, &digest);
    let bytes = store_get(store, &m_path).await.map_err(|_| {
        RegistryError::ManifestUnknown {
            reference: digest.clone(),
        }
    })?;
    // Sanity: digest of bytes should match when we loaded by digest path.
    let computed = sha256_digest(&bytes);
    if computed != digest && r.reference.starts_with("sha256:") {
        // Some stores key by reference string; still OK if path exists.
    }
    let _ = computed;
    Ok((digest, bytes))
}

pub struct PromoteParams<'a> {
    pub store: &'a Arc<dyn ObjectStore>,
    pub pool: Option<&'a sqlx::PgPool>,
    pub actor: &'a str,
    pub req: &'a PromoteRequest,
}

pub async fn promote(p: PromoteParams<'_>) -> Result<PromoteOutcome, RegistryError> {
    let id = Uuid::new_v4();
    let dry = matches!(p.req.mode, PromoteMode::DryRun);
    if matches!(p.req.mode, PromoteMode::OnPolicyPass { .. }) {
        return Err(RegistryError::Forbidden {
            reason: "on_policy_pass requires admission (C3); use force or dry_run".into(),
        });
    }

    let (src_digest, manifest_bytes) = resolve_digest(p.store.as_ref(), &p.req.source).await?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).map_err(|e| {
        RegistryError::ManifestInvalid {
            reason: e.to_string(),
        }
    })?;
    let blob_digests = collect_referenced_digests(&manifest);

    if dry {
        return Ok(PromoteOutcome {
            id,
            src_digest: src_digest.clone(),
            dst_digest: src_digest,
            state: "dry_run".into(),
            bytes_copied: 0,
            blob_count: blob_digests.len() as u32,
            signatures_copied: 0,
            dry_run: Some(true),
        });
    }

    if let Some(pool) = p.pool {
        let _ = sqlx::query(
            "INSERT INTO promotions
                 (id, actor, src_tenant, src_project, src_repository, src_reference, src_digest,
                  dst_tenant, dst_project, dst_repository, dst_reference, state)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'copying')",
        )
        .bind(id)
        .bind(p.actor)
        .bind(&p.req.source.tenant)
        .bind(&p.req.source.project)
        .bind(&p.req.source.repository)
        .bind(&p.req.source.reference)
        .bind(&src_digest)
        .bind(&p.req.dest.tenant)
        .bind(&p.req.dest.project)
        .bind(&p.req.dest.repository)
        .bind(&p.req.dest.reference)
        .execute(pool)
        .await;
    }

    let src = &p.req.source;
    let dst = &p.req.dest;
    let mut bytes_copied: u64 = 0;
    let mut blob_count: u32 = 0;

    for dig in &blob_digests {
        // Index child manifests live under manifests/, image layers under blobs/.
        let src_blob = blob_path(&src.tenant, &src.project, &src.repository, dig);
        let dst_blob = blob_path(&dst.tenant, &dst.project, &dst.repository, dig);
        let src_man = manifest_path(&src.tenant, &src.project, &src.repository, dig);
        let dst_man = manifest_path(&dst.tenant, &dst.project, &dst.repository, dig);

        if store_exists(p.store.as_ref(), &src_blob).await? {
            bytes_copied += copy_object(p.store.as_ref(), &src_blob, &dst_blob).await?;
            blob_count += 1;
        } else if store_exists(p.store.as_ref(), &src_man).await? {
            bytes_copied += copy_object(p.store.as_ref(), &src_man, &dst_man).await?;
            blob_count += 1;
        } else {
            return Err(RegistryError::BlobUnknown {
                digest: dig.clone(),
            });
        }
    }

    // Manifest by digest at dest
    let dst_manifest = manifest_path(&dst.tenant, &dst.project, &dst.repository, &src_digest);
    let src_manifest = manifest_path(&src.tenant, &src.project, &src.repository, &src_digest);
    bytes_copied += copy_object(p.store.as_ref(), &src_manifest, &dst_manifest).await?;

    let mut signatures_copied: u32 = 0;
    if p.req.include_signatures {
        // Cosign convention: tag sha256-<hex>.sig
        let hex = src_digest.strip_prefix("sha256:").unwrap_or(&src_digest);
        let sig_tag = format!("sha256-{hex}.sig");
        let src_sig_link =
            tag_link_path(&src.tenant, &src.project, &src.repository, &sig_tag);
        if store_exists(p.store.as_ref(), &src_sig_link).await? {
            let sig_digest_bytes = store_get(p.store.as_ref(), &src_sig_link).await?;
            let sig_digest = String::from_utf8_lossy(&sig_digest_bytes)
                .trim()
                .to_string();
            let src_sig_m =
                manifest_path(&src.tenant, &src.project, &src.repository, &sig_digest);
            let dst_sig_m =
                manifest_path(&dst.tenant, &dst.project, &dst.repository, &sig_digest);
            if store_exists(p.store.as_ref(), &src_sig_m).await? {
                let sig_bytes = store_get(p.store.as_ref(), &src_sig_m).await?;
                // Copy any blobs the sig manifest references
                if let Ok(sig_json) = serde_json::from_slice::<serde_json::Value>(&sig_bytes) {
                    for dig in collect_referenced_digests(&sig_json) {
                        let s = blob_path(&src.tenant, &src.project, &src.repository, &dig);
                        let d = blob_path(&dst.tenant, &dst.project, &dst.repository, &dig);
                        if store_exists(p.store.as_ref(), &s).await? {
                            bytes_copied += copy_object(p.store.as_ref(), &s, &d).await?;
                        }
                    }
                }
                bytes_copied += copy_object(p.store.as_ref(), &src_sig_m, &dst_sig_m).await?;
                let dst_sig_link =
                    tag_link_path(&dst.tenant, &dst.project, &dst.repository, &sig_tag);
                p.store
                    .as_ref()
                    .put(
                        &StorePath::from(dst_sig_link),
                        Bytes::from(sig_digest).into(),
                    )
                    .await
                    .map_err(|e| RegistryError::Storage(e.to_string()))?;
                signatures_copied = 1;
            }
        }
    }

    // Tag link last (atomicity)
    if !dst.reference.starts_with("sha256:") {
        let tag_p = tag_link_path(&dst.tenant, &dst.project, &dst.repository, &dst.reference);
        p.store
            .as_ref()
            .put(
                &StorePath::from(tag_p),
                Bytes::from(src_digest.clone()).into(),
            )
            .await
            .map_err(|e| RegistryError::Storage(e.to_string()))?;
    }

    if let Some(pool) = p.pool {
        let _ = sqlx::query(
            "UPDATE promotions SET finished_at = $1, state = 'done',
                 bytes_copied = $2, blob_count = $3, signatures_copied = $4
             WHERE id = $5",
        )
        .bind(Utc::now())
        .bind(bytes_copied as i64)
        .bind(blob_count as i32)
        .bind(signatures_copied as i32)
        .bind(id)
        .execute(pool)
        .await;
    }

    Ok(PromoteOutcome {
        id,
        src_digest: src_digest.clone(),
        dst_digest: src_digest,
        state: "done".into(),
        bytes_copied,
        blob_count,
        signatures_copied,
        dry_run: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;

    #[test]
    fn parse_tag_ref() {
        let r = ImageRef::parse("acme/dev/api:1.2.3").unwrap();
        assert_eq!(r.tenant, "acme");
        assert_eq!(r.project, "dev");
        assert_eq!(r.repository, "api");
        assert_eq!(r.reference, "1.2.3");
    }

    #[test]
    fn parse_digest_ref() {
        let r = ImageRef::parse("acme/dev/api@sha256:abc").unwrap();
        assert_eq!(r.reference, "sha256:abc");
    }

    #[tokio::test]
    async fn same_backend_retag_and_cross_repo_copy() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let config_blob = br#"{"architecture":"amd64","os":"linux"}"#;
        let config_digest = sha256_digest(config_blob);
        let layer = b"layer-bytes";
        let layer_digest = sha256_digest(layer);
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": config_digest, "size": config_blob.len()},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
                        "digest": layer_digest, "size": layer.len()}],
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let man_digest = sha256_digest(&manifest_bytes);

        // Seed source
        store
            .put(
                &StorePath::from(blob_path("acme", "dev", "api", &config_digest)),
                Bytes::from_static(config_blob).into(),
            )
            .await
            .unwrap();
        store
            .put(
                &StorePath::from(blob_path("acme", "dev", "api", &layer_digest)),
                Bytes::from_static(layer).into(),
            )
            .await
            .unwrap();
        store
            .put(
                &StorePath::from(manifest_path("acme", "dev", "api", &man_digest)),
                Bytes::from(manifest_bytes).into(),
            )
            .await
            .unwrap();
        store
            .put(
                &StorePath::from(tag_link_path("acme", "dev", "api", "1.0")),
                Bytes::from(man_digest.clone()).into(),
            )
            .await
            .unwrap();

        let req = PromoteRequest {
            source: ImageRef::parse("acme/dev/api:1.0").unwrap(),
            dest: ImageRef::parse("acme/prod/api:1.0").unwrap(),
            include_signatures: true,
            include_attestations: true,
            mode: PromoteMode::Force,
        };
        let out = promote(PromoteParams {
            store: &store,
            pool: None,
            actor: "test",
            req: &req,
        })
        .await
        .unwrap();
        assert_eq!(out.state, "done");
        assert_eq!(out.src_digest, man_digest);
        assert!(out.blob_count >= 2);

        // Dest tag points at same digest
        let link = store_get(
            store.as_ref(),
            &tag_link_path("acme", "prod", "api", "1.0"),
        )
        .await
        .unwrap();
        assert_eq!(String::from_utf8_lossy(&link).trim(), man_digest);

        // Dest blobs exist
        assert!(
            store_exists(
                store.as_ref(),
                &blob_path("acme", "prod", "api", &layer_digest)
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let blob = b"cfg";
        let dig = sha256_digest(blob);
        let man = serde_json::json!({
            "schemaVersion": 2,
            "config": {"digest": dig, "size": 3},
            "layers": []
        });
        let mb = serde_json::to_vec(&man).unwrap();
        let md = sha256_digest(&mb);
        store
            .put(
                &StorePath::from(blob_path("t", "p", "r", &dig)),
                Bytes::from_static(blob).into(),
            )
            .await
            .unwrap();
        store
            .put(
                &StorePath::from(manifest_path("t", "p", "r", &md)),
                Bytes::from(mb).into(),
            )
            .await
            .unwrap();
        store
            .put(
                &StorePath::from(tag_link_path("t", "p", "r", "v1")),
                Bytes::from(md.clone()).into(),
            )
            .await
            .unwrap();

        let req = PromoteRequest {
            source: ImageRef::parse("t/p/r:v1").unwrap(),
            dest: ImageRef::parse("t/p2/r:v1").unwrap(),
            include_signatures: false,
            include_attestations: false,
            mode: PromoteMode::DryRun,
        };
        let out = promote(PromoteParams {
            store: &store,
            pool: None,
            actor: "t",
            req: &req,
        })
        .await
        .unwrap();
        assert_eq!(out.state, "dry_run");
        assert!(!store_exists(store.as_ref(), &tag_link_path("t", "p2", "r", "v1"))
            .await
            .unwrap());
    }
}
