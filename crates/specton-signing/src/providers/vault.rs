//! HashiCorp Vault KV v2 key provider.
//!
//! Refs: `vault://kv/<mount>/<path>` or `vault://secret/<path>`
//! Secret data keys: `private_key` (required for sign) and optional
//! `public_key`.
//!
//! Transit remote signing is handled by
//! [`crate::vault_transit::VaultTransitSigner`] for
//! `vault://transit/<key-name>` refs.

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;

use crate::error::KeyProviderError;
use crate::key_provider::{KeyMaterial, KeyProvider};

#[derive(Debug, Clone)]
pub struct VaultKvConfig {
    pub addr: String,
    pub token: String,
    /// Default KV v2 mount when the ref is `vault://secret/...`.
    pub default_mount: String,
}

impl VaultKvConfig {
    pub fn from_env() -> Option<Self> {
        let token = std::env::var("VAULT_TOKEN").ok().filter(|t| !t.is_empty())?;
        let addr =
            std::env::var("VAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".into());
        Some(Self {
            addr,
            token,
            default_mount: "secret".into(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct VaultKvResponse {
    data: VaultKvData,
}

#[derive(Debug, Deserialize)]
struct VaultKvData {
    data: HashMap<String, String>,
}

pub struct VaultKvKeyProvider {
    http: reqwest::Client,
    config: VaultKvConfig,
}

impl VaultKvKeyProvider {
    pub fn new(config: VaultKvConfig) -> Self {
        Self {
            http: reqwest::Client::new(),
            config,
        }
    }

    /// Parse `vault://kv/<mount>/<path...>` or `vault://secret/<path...>`.
    fn parse_ref(key_ref: &str, default_mount: &str) -> Result<(String, String), KeyProviderError> {
        let rest = key_ref
            .strip_prefix("vault://")
            .ok_or_else(|| KeyProviderError::NotFound(key_ref.to_string()))?;
        if rest.starts_with("transit/") {
            return Err(KeyProviderError::Unavailable(
                "use VaultTransitSigner for vault://transit/ refs".into(),
            ));
        }
        if let Some(after) = rest.strip_prefix("kv/") {
            let (mount, path) = after
                .split_once('/')
                .ok_or_else(|| KeyProviderError::NotFound(key_ref.to_string()))?;
            return Ok((mount.to_string(), path.to_string()));
        }
        if let Some(path) = rest.strip_prefix("secret/") {
            return Ok((default_mount.to_string(), path.to_string()));
        }
        // `vault://<mount>/<path>`
        let (mount, path) = rest
            .split_once('/')
            .ok_or_else(|| KeyProviderError::NotFound(key_ref.to_string()))?;
        Ok((mount.to_string(), path.to_string()))
    }
}

#[async_trait]
impl KeyProvider for VaultKvKeyProvider {
    async fn resolve(&self, key_ref: &str) -> Result<KeyMaterial, KeyProviderError> {
        if !key_ref.starts_with("vault://") {
            return Err(KeyProviderError::NotFound(key_ref.to_string()));
        }
        let (mount, path) = Self::parse_ref(key_ref, &self.config.default_mount)?;
        let url = format!(
            "{}/v1/{}/data/{}",
            self.config.addr.trim_end_matches('/'),
            mount,
            path
        );
        let resp = self
            .http
            .get(&url)
            .header("X-Vault-Token", &self.config.token)
            .send()
            .await
            .map_err(|e| KeyProviderError::Unavailable(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(KeyProviderError::NotFound(key_ref.to_string()));
        }
        if !resp.status().is_success() {
            return Err(KeyProviderError::Unavailable(format!(
                "vault HTTP {}",
                resp.status()
            )));
        }
        let body: VaultKvResponse = resp
            .json()
            .await
            .map_err(|e| KeyProviderError::Unavailable(e.to_string()))?;
        let private_pem = body
            .data
            .data
            .get("private_key")
            .cloned()
            .ok_or_else(|| {
                KeyProviderError::InvalidPem("'private_key' missing in Vault secret".into())
            })?;
        let public_pem = body.data.data.get("public_key").cloned();
        Ok(KeyMaterial {
            key_ref: key_ref.to_string(),
            private_pem: Some(private_pem),
            public_pem,
            ed25519_seed: None,
            ed25519_public: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kv_ref() {
        let (m, p) = VaultKvKeyProvider::parse_ref("vault://kv/secret/spectoncr/cosign", "secret")
            .unwrap();
        assert_eq!(m, "secret");
        assert_eq!(p, "spectoncr/cosign");
    }

    #[test]
    fn parse_secret_shorthand() {
        let (m, p) =
            VaultKvKeyProvider::parse_ref("vault://secret/team/key", "secret").unwrap();
        assert_eq!(m, "secret");
        assert_eq!(p, "team/key");
    }
}
