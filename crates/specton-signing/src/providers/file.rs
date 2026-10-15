//! Load PKCS#8 PEM private keys (and optional sibling `.pub`) from disk.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tokio::fs;

use crate::error::KeyProviderError;
use crate::key_provider::{KeyMaterial, KeyProvider};

/// Resolves `file:///abs/path.pem` or relative paths to PEM bytes.
pub struct FilePemKeyProvider {
    /// Optional chroot — relative refs are joined under this directory.
    root: Option<PathBuf>,
}

impl FilePemKeyProvider {
    pub fn new() -> Self {
        Self { root: None }
    }

    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self {
            root: Some(root.into()),
        }
    }

    fn path_from_ref(&self, key_ref: &str) -> Result<PathBuf, KeyProviderError> {
        let raw = key_ref
            .strip_prefix("file://")
            .unwrap_or(key_ref);
        let path = PathBuf::from(raw);
        if path.is_absolute() {
            return Ok(path);
        }
        if let Some(ref root) = self.root {
            return Ok(root.join(path));
        }
        Ok(path)
    }

    async fn read_optional_pub(priv_path: &Path) -> Option<String> {
        let candidates = [
            priv_path.with_extension("pub"),
            PathBuf::from(format!("{}.pub", priv_path.display())),
        ];
        for c in candidates {
            if let Ok(s) = fs::read_to_string(&c).await {
                return Some(s);
            }
        }
        None
    }
}

impl Default for FilePemKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyProvider for FilePemKeyProvider {
    async fn resolve(&self, key_ref: &str) -> Result<KeyMaterial, KeyProviderError> {
        if !(key_ref.starts_with("file://")
            || key_ref.starts_with('/')
            || key_ref.starts_with("./")
            || key_ref.ends_with(".pem")
            || key_ref.ends_with(".key"))
        {
            return Err(KeyProviderError::NotFound(key_ref.to_string()));
        }
        let path = self.path_from_ref(key_ref)?;
        let private_pem = fs::read_to_string(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                KeyProviderError::NotFound(path.display().to_string())
            } else {
                KeyProviderError::Unavailable(e.to_string())
            }
        })?;
        let public_pem = Self::read_optional_pub(&path).await;
        Ok(KeyMaterial {
            key_ref: key_ref.to_string(),
            private_pem: Some(private_pem),
            public_pem,
            ed25519_seed: None,
            ed25519_public: None,
        })
    }
}
