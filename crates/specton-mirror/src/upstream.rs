use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use metrics::{counter, histogram};
use serde::{Deserialize, Serialize};
use specton_resilience::{CircuitBreaker, CircuitBreakerConfig, RetryPolicy};
use tracing::{debug, info};

fn record_upstream_outcome(
    upstream: &str,
    kind: &'static str,
    started: Instant,
    outcome: &'static str,
    bytes_len: u64,
) {
    let elapsed = started.elapsed().as_secs_f64();
    histogram!("spectoncr_mirror_upstream_latency_seconds",
        "upstream" => upstream.to_string(), "kind" => kind)
    .record(elapsed);
    counter!("spectoncr_mirror_upstream_requests_total",
        "upstream" => upstream.to_string(), "kind" => kind, "outcome" => outcome)
    .increment(1);
    if outcome == "success" && bytes_len > 0 {
        counter!("spectoncr_mirror_upstream_bytes_total",
            "upstream" => upstream.to_string(), "kind" => kind)
        .increment(bytes_len);
    }
}

/// Configuration for an upstream registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Unique name for this upstream.
    pub name: String,
    /// Base URL of the upstream registry (e.g., "https://registry-1.docker.io").
    pub url: String,
    /// Optional credentials for the upstream.
    pub username: Option<String>,
    pub password: Option<String>,
    /// Cache TTL in seconds for manifests from this upstream.
    pub cache_ttl_secs: u64,
    /// Only mirror for repositories matching this tenant prefix.
    pub tenant_prefix: Option<String>,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            name: "docker-hub".into(),
            url: "https://registry-1.docker.io".into(),
            username: None,
            password: None,
            cache_ttl_secs: 3600,
            tenant_prefix: None,
        }
    }
}

/// Response from an upstream registry fetch.
pub struct UpstreamResponse {
    pub data: Bytes,
    pub content_type: String,
    pub digest: Option<String>,
}

/// Response from a registry token endpoint (Docker token auth spec). Docker
/// Hub and SpectonCR return `token`; some registries return `access_token`.
#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Parameters of a `WWW-Authenticate` challenge.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Challenge {
    pub scheme: String,
    pub realm: Option<String>,
    pub service: Option<String>,
    pub scope: Option<String>,
}

/// Parse a `WWW-Authenticate` header, e.g.
/// `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:x:pull"`.
/// Values are quoted and may contain commas (multi-action scopes), so split
/// on commas only outside quotes.
pub(crate) fn parse_challenge(header: &str) -> Option<Challenge> {
    let header = header.trim();
    let (scheme, params) = match header.split_once(' ') {
        Some((s, p)) => (s, p),
        None => (header, ""),
    };
    if scheme.is_empty() {
        return None;
    }
    let mut challenge = Challenge {
        scheme: scheme.to_ascii_lowercase(),
        ..Default::default()
    };
    let mut parts = Vec::new();
    let (mut in_quotes, mut start) = (false, 0);
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
            "realm" => challenge.realm = Some(value),
            "service" => challenge.service = Some(value),
            "scope" => challenge.scope = Some(value),
            _ => {}
        }
    }
    Some(challenge)
}

/// A relative realm (e.g. `/auth/token`, as a registry behind a path-routing
/// ingress may send) is resolved against the upstream's origin.
fn resolve_realm(realm: &str, upstream_url: &str) -> String {
    if realm.starts_with("http://") || realm.starts_with("https://") {
        return realm.to_string();
    }
    let origin = match upstream_url.find("://") {
        Some(i) => {
            let rest = &upstream_url[i + 3..];
            let host_end = rest
                .find('/')
                .map(|j| i + 3 + j)
                .unwrap_or(upstream_url.len());
            &upstream_url[..host_end]
        }
        None => upstream_url,
    };
    format!(
        "{}/{}",
        origin.trim_end_matches('/'),
        realm.trim_start_matches('/')
    )
}

/// Bearer tokens per scope, so each blob of a pull doesn't re-authenticate.
type TokenCache = Arc<Mutex<HashMap<String, (String, Instant)>>>;

/// Default token lifetime when the token endpoint doesn't say (the Docker
/// token spec's default is 60s).
const DEFAULT_TOKEN_TTL_SECS: u64 = 60;

enum Auth<'a> {
    Bearer(&'a str),
    Basic(&'a str, &'a str),
}

/// Client for fetching content from an upstream OCI registry.
pub struct UpstreamClient {
    http: reqwest::Client,
    config: UpstreamConfig,
    circuit_breaker: Arc<CircuitBreaker>,
    tokens: TokenCache,
    #[allow(dead_code)]
    retry_policy: RetryPolicy,
}

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("upstream request failed: {0}")]
    Request(String),
    #[error("upstream returned {status}: {body}")]
    Http { status: u16, body: String },
    #[error("upstream authentication failed: {0}")]
    Auth(String),
    #[error("circuit breaker open for upstream '{name}'")]
    CircuitBreakerOpen { name: String },
    #[error("manifest not found on upstream: {reference}")]
    ManifestNotFound { reference: String },
    #[error("blob not found on upstream: {digest}")]
    BlobNotFound { digest: String },
}

impl UpstreamError {
    /// Returns true when this upstream-level error means "the upstream
    /// has no answer for us." From the domain perspective this
    /// collapses: explicit 404s, breaker-open, transport failures,
    /// and upstream 5xx all mean the same thing — spectoncr cannot
    /// serve this blob from this upstream, so try the next one or
    /// return 404 to the client.
    pub fn is_not_found_equivalent(&self) -> bool {
        match self {
            UpstreamError::ManifestNotFound { .. } => true,
            UpstreamError::BlobNotFound { .. } => true,
            UpstreamError::CircuitBreakerOpen { .. } => true,
            UpstreamError::Request(_) => true,
            UpstreamError::Http { status, .. } => *status >= 500 || *status == 404,
            UpstreamError::Auth(_) => false,
        }
    }
}

impl UpstreamClient {
    pub fn new(config: UpstreamConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");

        let circuit_breaker = Arc::new(CircuitBreaker::new(
            format!("upstream-{}", config.name),
            CircuitBreakerConfig {
                failure_threshold: 5,
                success_threshold: 3,
                open_duration_secs: 30,
            },
        ));

        Self {
            http,
            config,
            circuit_breaker,
            tokens: Arc::new(Mutex::new(HashMap::new())),
            retry_policy: RetryPolicy {
                max_retries: 2,
                base_delay_ms: 200,
                max_delay_ms: 2000,
                jitter: true,
            },
        }
    }

    /// GET `url` from the upstream, authenticating the way the upstream asks.
    ///
    /// Follows the Docker registry token-auth flow for any upstream (not just
    /// Docker Hub): try a cached bearer token for this repo; otherwise send
    /// the request and, on `401` with a `Bearer` challenge, fetch a token from
    /// the challenge's realm (with Basic credentials when configured), cache
    /// it and retry. A `Basic` challenge is answered with the credentials.
    /// Previously only docker.io got a token and every other upstream was
    /// sent Basic auth directly, which token-auth registries (SpectonCR,
    /// ghcr.io, quay.io, ...) reject with 401.
    async fn authed_get(
        http: &reqwest::Client,
        config: &UpstreamConfig,
        tokens: &TokenCache,
        url: &str,
        repo: &str,
        accept: Option<&str>,
    ) -> Result<reqwest::Response, UpstreamError> {
        let request = |auth: Option<Auth<'_>>| {
            let mut req = http.get(url);
            if let Some(a) = accept {
                req = req.header("Accept", a);
            }
            match auth {
                Some(Auth::Bearer(t)) => req.bearer_auth(t),
                Some(Auth::Basic(u, p)) => req.basic_auth(u, Some(p)),
                None => req,
            }
        };
        let send = |req: reqwest::RequestBuilder| async move {
            req.send()
                .await
                .map_err(|e| UpstreamError::Request(e.to_string()))
        };

        let default_scope = format!("repository:{repo}:pull");
        let cached = tokens
            .lock()
            .ok()
            .and_then(|t| t.get(&default_scope).cloned())
            .filter(|(_, expires)| Instant::now() < *expires)
            .map(|(tok, _)| tok);
        if let Some(token) = cached {
            let resp = send(request(Some(Auth::Bearer(&token)))).await?;
            if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
                return Ok(resp);
            }
            if let Ok(mut t) = tokens.lock() {
                t.remove(&default_scope);
            }
        }

        let resp = send(request(None)).await?;
        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }
        let Some(challenge) = resp
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_challenge)
        else {
            return Ok(resp);
        };
        let creds = config.username.as_deref().zip(config.password.as_deref());

        match (challenge.scheme.as_str(), challenge.realm.as_deref()) {
            ("bearer", Some(realm)) => {
                let realm = resolve_realm(realm, &config.url);
                let scope = challenge.scope.clone().unwrap_or(default_scope.clone());
                let mut query: Vec<(&str, &str)> = vec![("scope", scope.as_str())];
                if let Some(service) = challenge.service.as_deref() {
                    query.push(("service", service));
                }
                let mut token_req = http.get(&realm).query(&query);
                if let Some((user, pass)) = creds {
                    token_req = token_req.basic_auth(user, Some(pass));
                }
                let token_resp = token_req
                    .send()
                    .await
                    .map_err(|e| UpstreamError::Auth(format!("token request to {realm}: {e}")))?;
                if !token_resp.status().is_success() {
                    return Err(UpstreamError::Auth(format!(
                        "token endpoint {realm} returned {}",
                        token_resp.status()
                    )));
                }
                let body: TokenResponse = token_resp.json().await.map_err(|e| {
                    UpstreamError::Auth(format!("token response from {realm}: {e}"))
                })?;
                let ttl = body.expires_in.unwrap_or(DEFAULT_TOKEN_TTL_SECS);
                let Some(token) = body.token.or(body.access_token) else {
                    return Err(UpstreamError::Auth(format!(
                        "token endpoint {realm} returned no token"
                    )));
                };
                if let Ok(mut t) = tokens.lock() {
                    // Expire a little early so a token isn't used at the edge.
                    let expires =
                        Instant::now() + Duration::from_secs(ttl.saturating_sub(5).max(1));
                    t.insert(scope.clone(), (token.clone(), expires));
                    if scope != default_scope {
                        t.insert(default_scope, (token.clone(), expires));
                    }
                }
                send(request(Some(Auth::Bearer(&token)))).await
            }
            ("basic", _) => match creds {
                Some((user, pass)) => send(request(Some(Auth::Basic(user, pass)))).await,
                None => Ok(resp),
            },
            _ => Ok(resp),
        }
    }

    /// Fetch a manifest from the upstream registry.
    pub async fn get_manifest(
        &self,
        repo: &str,
        reference: &str,
    ) -> Result<UpstreamResponse, UpstreamError> {
        info!(
            upstream = %self.config.name,
            repo = %repo,
            reference = %reference,
            "Fetching manifest from upstream"
        );

        let url = format!("{}/v2/{}/manifests/{}", self.config.url, repo, reference);
        let started = Instant::now();

        let cb = self.circuit_breaker.clone();
        let result = cb
            .call(|| {
                let url = url.clone();
                let http = self.http.clone();
                let config = self.config.clone();
                let tokens = self.tokens.clone();
                let repo = repo.to_string();
                let reference = reference.to_string();

                async move {
                    let resp = Self::authed_get(
                        &http,
                        &config,
                        &tokens,
                        &url,
                        &repo,
                        Some(
                            "application/vnd.oci.image.manifest.v1+json, \
                             application/vnd.oci.image.index.v1+json, \
                             application/vnd.docker.distribution.manifest.v2+json, \
                             application/vnd.docker.distribution.manifest.list.v2+json",
                        ),
                    )
                    .await?;

                    if resp.status() == reqwest::StatusCode::NOT_FOUND {
                        return Err(UpstreamError::ManifestNotFound {
                            reference: reference.to_string(),
                        });
                    }

                    if !resp.status().is_success() {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        return Err(UpstreamError::Http { status, body });
                    }

                    let content_type = resp
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("application/vnd.oci.image.manifest.v1+json")
                        .to_string();

                    let digest = resp
                        .headers()
                        .get("docker-content-digest")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    let data = resp
                        .bytes()
                        .await
                        .map_err(|e| UpstreamError::Request(e.to_string()))?;

                    Ok(UpstreamResponse {
                        data,
                        content_type,
                        digest,
                    })
                }
            })
            .await;

        match result {
            Ok(r) => {
                let len = r.data.len() as u64;
                record_upstream_outcome(&self.config.name, "manifest", started, "success", len);
                Ok(r)
            }
            Err(specton_resilience::circuit_breaker::CircuitBreakerCallError::BreakerOpen(_)) => {
                record_upstream_outcome(&self.config.name, "manifest", started, "breaker_open", 0);
                Err(UpstreamError::CircuitBreakerOpen {
                    name: self.config.name.clone(),
                })
            }
            Err(specton_resilience::circuit_breaker::CircuitBreakerCallError::Inner(e)) => {
                let outcome = match &e {
                    UpstreamError::ManifestNotFound { .. } => "not_found",
                    UpstreamError::Auth(_) => "auth_error",
                    UpstreamError::Http { status, .. } if *status >= 500 => "upstream_5xx",
                    _ => "error",
                };
                record_upstream_outcome(&self.config.name, "manifest", started, outcome, 0);
                Err(e)
            }
        }
    }

    /// Fetch a blob from the upstream registry.
    pub async fn get_blob(
        &self,
        repo: &str,
        digest: &str,
    ) -> Result<UpstreamResponse, UpstreamError> {
        debug!(
            upstream = %self.config.name,
            repo = %repo,
            digest = %digest,
            "Fetching blob from upstream"
        );

        let url = format!("{}/v2/{}/blobs/{}", self.config.url, repo, digest);
        let started = Instant::now();

        let cb = self.circuit_breaker.clone();
        let result = cb
            .call(|| {
                let url = url.clone();
                let http = self.http.clone();
                let config = self.config.clone();
                let tokens = self.tokens.clone();
                let repo = repo.to_string();
                let digest = digest.to_string();

                async move {
                    let resp = Self::authed_get(&http, &config, &tokens, &url, &repo, None).await?;

                    if resp.status() == reqwest::StatusCode::NOT_FOUND {
                        return Err(UpstreamError::BlobNotFound {
                            digest: digest.to_string(),
                        });
                    }

                    if !resp.status().is_success() {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        return Err(UpstreamError::Http { status, body });
                    }

                    let content_type = resp
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("application/octet-stream")
                        .to_string();

                    let data = resp
                        .bytes()
                        .await
                        .map_err(|e| UpstreamError::Request(e.to_string()))?;

                    Ok(UpstreamResponse {
                        data,
                        content_type,
                        digest: Some(digest),
                    })
                }
            })
            .await;

        match result {
            Ok(r) => {
                let len = r.data.len() as u64;
                record_upstream_outcome(&self.config.name, "blob", started, "success", len);
                Ok(r)
            }
            Err(specton_resilience::circuit_breaker::CircuitBreakerCallError::BreakerOpen(_)) => {
                record_upstream_outcome(&self.config.name, "blob", started, "breaker_open", 0);
                Err(UpstreamError::CircuitBreakerOpen {
                    name: self.config.name.clone(),
                })
            }
            Err(specton_resilience::circuit_breaker::CircuitBreakerCallError::Inner(e)) => {
                let outcome = match &e {
                    UpstreamError::BlobNotFound { .. } => "not_found",
                    UpstreamError::Auth(_) => "auth_error",
                    UpstreamError::Http { status, .. } if *status >= 500 => "upstream_5xx",
                    _ => "error",
                };
                record_upstream_outcome(&self.config.name, "blob", started, outcome, 0);
                Err(e)
            }
        }
    }

    pub fn config(&self) -> &UpstreamConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn parses_bearer_challenge_with_commas_in_scope() {
        let c = parse_challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:a/b:pull,push""#,
        )
        .unwrap();
        assert_eq!(c.scheme, "bearer");
        assert_eq!(c.realm.as_deref(), Some("https://auth.docker.io/token"));
        assert_eq!(c.service.as_deref(), Some("registry.docker.io"));
        assert_eq!(c.scope.as_deref(), Some("repository:a/b:pull,push"));
        assert_eq!(
            parse_challenge(r#"Basic realm="x""#).unwrap().scheme,
            "basic"
        );
    }

    #[test]
    fn resolves_relative_realm_against_upstream_origin() {
        assert_eq!(
            resolve_realm("/auth/token", "http://spectoncr-registry.acc.svc:5000"),
            "http://spectoncr-registry.acc.svc:5000/auth/token"
        );
        assert_eq!(
            resolve_realm("https://auth.example/token", "http://x:5000"),
            "https://auth.example/token"
        );
    }

    /// A token-auth registry like SpectonCR: /v2 needs `Bearer good-token`,
    /// the token endpoint needs Basic `robot:secret` unless `anon` is set.
    #[derive(Clone)]
    struct Mock {
        base: String,
        anon: bool,
        basic_only: bool,
        token_hits: Arc<AtomicUsize>,
    }

    fn challenge(m: &Mock, repo: &str) -> Response {
        let mut h = HeaderMap::new();
        let value = if m.basic_only {
            r#"Basic realm="mock""#.to_string()
        } else {
            format!(
                r#"Bearer realm="{}/token",service="mock",scope="repository:{repo}:pull""#,
                m.base
            )
        };
        h.insert("www-authenticate", value.parse().unwrap());
        (StatusCode::UNAUTHORIZED, h).into_response()
    }

    fn authorized(m: &Mock, h: &HeaderMap) -> bool {
        let auth = h
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if m.basic_only {
            auth == "Basic cm9ib3Q6c2VjcmV0" // robot:secret
        } else {
            auth == "Bearer good-token"
        }
    }

    async fn manifest(State(m): State<Mock>, h: HeaderMap) -> Response {
        if !authorized(&m, &h) {
            return challenge(&m, "team/app");
        }
        let mut out = HeaderMap::new();
        out.insert("docker-content-digest", "sha256:abc".parse().unwrap());
        out.insert(
            "content-type",
            "application/vnd.oci.image.manifest.v1+json"
                .parse()
                .unwrap(),
        );
        (StatusCode::OK, out, "{}").into_response()
    }

    async fn blob(State(m): State<Mock>, h: HeaderMap) -> Response {
        if !authorized(&m, &h) {
            return challenge(&m, "team/app");
        }
        (StatusCode::OK, "blob-bytes").into_response()
    }

    async fn token(State(m): State<Mock>, h: HeaderMap) -> Response {
        m.token_hits.fetch_add(1, Ordering::SeqCst);
        let auth = h
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !m.anon && auth != "Basic cm9ib3Q6c2VjcmV0" {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        axum::Json(serde_json::json!({"token": "good-token", "expires_in": 300})).into_response()
    }

    async fn serve(anon: bool, basic_only: bool) -> Mock {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let m = Mock {
            base,
            anon,
            basic_only,
            token_hits: Arc::new(AtomicUsize::new(0)),
        };
        let app = axum::Router::new()
            .route("/v2/team/app/manifests/{reference}", get(manifest))
            .route("/v2/team/app/blobs/{digest}", get(blob))
            .route("/token", get(token))
            .with_state(m.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        m
    }

    fn client(m: &Mock, creds: Option<(&str, &str)>) -> UpstreamClient {
        UpstreamClient::new(UpstreamConfig {
            name: "00-primary".into(),
            url: m.base.clone(),
            username: creds.map(|c| c.0.to_string()),
            password: creds.map(|c| c.1.to_string()),
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn bearer_upstream_with_credentials_serves_manifest_and_blob() {
        let m = serve(false, false).await;
        let c = client(&m, Some(("robot", "secret")));
        let man = c.get_manifest("team/app", "v1").await.expect("manifest");
        assert_eq!(man.digest.as_deref(), Some("sha256:abc"));
        let blob = c.get_blob("team/app", "sha256:def").await.expect("blob");
        assert_eq!(&blob.data[..], b"blob-bytes");
        // The blob reused the cached token: one token request in total.
        assert_eq!(m.token_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn bearer_upstream_anonymous_token_works() {
        // Like a public ghcr.io / quay.io image: token issued without creds.
        let m = serve(true, false).await;
        let c = client(&m, None);
        assert!(c.get_manifest("team/app", "v1").await.is_ok());
    }

    #[tokio::test]
    async fn wrong_credentials_are_an_auth_error() {
        let m = serve(false, false).await;
        let c = client(&m, Some(("robot", "wrong")));
        let err = c
            .get_manifest("team/app", "v1")
            .await
            .err()
            .expect("must fail");
        assert!(matches!(err, UpstreamError::Auth(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn basic_challenge_is_answered_with_credentials() {
        let m = serve(false, true).await;
        let c = client(&m, Some(("robot", "secret")));
        let man = c.get_manifest("team/app", "v1").await.expect("manifest");
        assert_eq!(man.digest.as_deref(), Some("sha256:abc"));
        assert_eq!(m.token_hits.load(Ordering::SeqCst), 0);
    }
}
