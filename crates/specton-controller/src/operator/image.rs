//! Resolve an image tag to its manifest digest via the OCI distribution API.
//!
//! Used by auto-update: the operator pins pods to `repo@sha256:…` and rolls
//! them when the digest behind the tracked tag moves. Only anonymous (public)
//! pulls and the standard Bearer token challenge are supported.

use reqwest::StatusCode;
use reqwest::header::{ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE};

const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
application/vnd.docker.distribution.manifest.list.v2+json, \
application/vnd.oci.image.manifest.v1+json, \
application/vnd.docker.distribution.manifest.v2+json";

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("registry returned {0} for {1}")]
    Status(StatusCode, String),
    #[error("unsupported auth challenge: {0}")]
    Challenge(String),
    #[error("registry response had no Docker-Content-Digest header")]
    NoDigest,
}

/// Registry host and repository path of an image reference.
#[derive(Debug, PartialEq, Eq)]
pub struct ImageRef {
    pub host: String,
    pub path: String,
}

/// Split `repository` (no tag or digest) into host and path, applying the
/// Docker Hub defaults (`registry-1.docker.io`, `library/` prefix).
pub fn parse_repository(repository: &str) -> ImageRef {
    match repository.split_once('/') {
        Some((first, rest))
            if first.contains('.') || first.contains(':') || first == "localhost" =>
        {
            let host = if first == "docker.io" || first == "index.docker.io" {
                "registry-1.docker.io".to_string()
            } else {
                first.to_string()
            };
            let path = if host == "registry-1.docker.io" && !rest.contains('/') {
                format!("library/{rest}")
            } else {
                rest.to_string()
            };
            ImageRef { host, path }
        }
        Some(_) => ImageRef {
            host: "registry-1.docker.io".to_string(),
            path: repository.to_string(),
        },
        None => ImageRef {
            host: "registry-1.docker.io".to_string(),
            path: format!("library/{repository}"),
        },
    }
}

/// Parameters of a `WWW-Authenticate: Bearer realm="…",service="…",scope="…"`
/// challenge.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BearerChallenge {
    pub realm: String,
    pub service: Option<String>,
    pub scope: Option<String>,
}

pub fn parse_bearer_challenge(header: &str) -> Option<BearerChallenge> {
    let (scheme, params) = header.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let mut challenge = BearerChallenge::default();
    // Values are quoted and may contain commas (e.g. multi-action scopes),
    // so split on `,` only outside quotes.
    let mut in_quotes = false;
    let mut start = 0;
    let mut parts = Vec::new();
    for (i, c) in params.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                parts.push(&params[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&params[start..]);
    for part in parts {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_string();
        match key.trim().to_ascii_lowercase().as_str() {
            "realm" => challenge.realm = value,
            "service" => challenge.service = Some(value),
            "scope" => challenge.scope = Some(value),
            _ => {}
        }
    }
    (!challenge.realm.is_empty()).then_some(challenge)
}

/// Resolve `repository:tag` to its manifest digest (`sha256:…`).
pub async fn resolve_digest(
    http: &reqwest::Client,
    repository: &str,
    tag: &str,
    insecure: bool,
) -> Result<String, ImageError> {
    let image = parse_repository(repository);
    let scheme = if insecure { "http" } else { "https" };
    let url = format!(
        "{scheme}://{}/v2/{}/manifests/{tag}",
        image.host, image.path
    );

    let resp = http
        .head(&url)
        .header(ACCEPT, MANIFEST_ACCEPT)
        .send()
        .await?;

    let resp = if resp.status() == StatusCode::UNAUTHORIZED {
        let header = resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let challenge =
            parse_bearer_challenge(&header).ok_or_else(|| ImageError::Challenge(header.clone()))?;
        let token = fetch_token(http, &challenge, &image.path).await?;
        http.head(&url)
            .header(ACCEPT, MANIFEST_ACCEPT)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await?
    } else {
        resp
    };

    if !resp.status().is_success() {
        return Err(ImageError::Status(resp.status(), url));
    }
    resp.headers()
        .get("docker-content-digest")
        .and_then(|v| v.to_str().ok())
        .filter(|d| d.starts_with("sha256:"))
        .map(str::to_string)
        .ok_or(ImageError::NoDigest)
}

async fn fetch_token(
    http: &reqwest::Client,
    challenge: &BearerChallenge,
    path: &str,
) -> Result<String, ImageError> {
    #[derive(serde::Deserialize)]
    struct TokenResponse {
        token: Option<String>,
        access_token: Option<String>,
    }

    let scope = challenge
        .scope
        .clone()
        .unwrap_or_else(|| format!("repository:{path}:pull"));
    let mut query = vec![("scope", scope)];
    if let Some(service) = &challenge.service {
        query.push(("service", service.clone()));
    }
    let resp = http.get(&challenge.realm).query(&query).send().await?;
    if !resp.status().is_success() {
        return Err(ImageError::Status(resp.status(), challenge.realm.clone()));
    }
    let body: TokenResponse = resp.json().await?;
    body.token
        .or(body.access_token)
        .ok_or_else(|| ImageError::Challenge("token endpoint returned no token".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(host: &str, path: &str) -> ImageRef {
        ImageRef {
            host: host.into(),
            path: path.into(),
        }
    }

    #[test]
    fn parses_docker_hub_references() {
        assert_eq!(
            parse_repository("nginx"),
            r("registry-1.docker.io", "library/nginx")
        );
        assert_eq!(
            parse_repository("bwalia/spectoncr"),
            r("registry-1.docker.io", "bwalia/spectoncr")
        );
        assert_eq!(
            parse_repository("docker.io/nginx"),
            r("registry-1.docker.io", "library/nginx")
        );
        assert_eq!(
            parse_repository("docker.io/bwalia/spectoncr"),
            r("registry-1.docker.io", "bwalia/spectoncr")
        );
    }

    #[test]
    fn parses_other_registries() {
        assert_eq!(
            parse_repository("ghcr.io/spectonio/spectoncr"),
            r("ghcr.io", "spectonio/spectoncr")
        );
        assert_eq!(
            parse_repository("192.168.1.104:30500/spectoncr"),
            r("192.168.1.104:30500", "spectoncr")
        );
        assert_eq!(parse_repository("localhost/app"), r("localhost", "app"));
    }

    #[test]
    fn parses_bearer_challenge() {
        let c = parse_bearer_challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:bwalia/spectoncr:pull,push""#,
        )
        .unwrap();
        assert_eq!(c.realm, "https://auth.docker.io/token");
        assert_eq!(c.service.as_deref(), Some("registry.docker.io"));
        assert_eq!(
            c.scope.as_deref(),
            Some("repository:bwalia/spectoncr:pull,push")
        );
    }

    #[test]
    fn rejects_non_bearer_challenge() {
        assert!(parse_bearer_challenge(r#"Basic realm="registry""#).is_none());
        assert!(parse_bearer_challenge("Bearer service=\"x\"").is_none());
    }
}
