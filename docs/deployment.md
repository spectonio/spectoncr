# Deployment

This guide covers deploying SpectonCR in Docker (single container and docker-compose), Kubernetes with Helm, and the associated configuration for storage backends, TLS, and ingress.

## Table of Contents

- [Docker](#docker)
- [Kubernetes with Helm](#kubernetes-with-helm)
- [Storage Backend Configuration](#storage-backend-configuration)
- [TLS and Ingress Setup](#tls-and-ingress-setup)
- [Environment Variables Reference](#environment-variables-reference)

---

## Docker

### Single Container (Quick Test)

For a quick test, you can run the registry and auth services from the same image:

```bash
# Generate JWT signing keys
mkdir -p keys
openssl genrsa -out keys/private.pem 4096
openssl rsa -in keys/private.pem -pubout -out keys/public.pem

# Run the auth service
docker run -d --name specton-auth \
  -p 5001:5001 \
  -v $(pwd)/keys:/etc/spectoncr/keys \
  -e RUST_LOG=info \
  -e SPECTONCR_SERVER__AUTH_LISTEN_ADDR=0.0.0.0:5001 \
  -e SPECTONCR_AUTH__ISSUER=spectoncr \
  -e SPECTONCR_AUTH__AUDIENCE=spectoncr-registry \
  -e SPECTONCR_AUTH__SIGNING_ALGORITHM=RS256 \
  -e SPECTONCR_AUTH__SIGNING_KEY_PATH=/etc/spectoncr/keys/private.pem \
  -e SPECTONCR_AUTH__VERIFICATION_KEY_PATH=/etc/spectoncr/keys/public.pem \
  -e SPECTONCR_AUTH__TOKEN_TTL_SECONDS=300 \
  -e SPECTONCR_AUTH__BOOTSTRAP_ADMIN__USERNAME=admin \
  -e 'SPECTONCR_AUTH__BOOTSTRAP_ADMIN__PASSWORD_HASH=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918' \
  ghcr.io/spectonio/spectoncr:latest specton-auth

# Run the registry service
docker run -d --name specton-registry \
  -p 5000:5000 -p 9090:9090 \
  -v $(pwd)/keys:/etc/spectoncr/keys:ro \
  -v spectoncr-data:/var/lib/spectoncr/data \
  -e RUST_LOG=info \
  -e SPECTONCR_SERVER__LISTEN_ADDR=0.0.0.0:5000 \
  -e SPECTONCR_SERVER__METRICS_ADDR=0.0.0.0:9090 \
  -e SPECTONCR_AUTH__ISSUER=spectoncr \
  -e SPECTONCR_AUTH__AUDIENCE=spectoncr-registry \
  -e SPECTONCR_AUTH__SIGNING_ALGORITHM=RS256 \
  -e SPECTONCR_AUTH__VERIFICATION_KEY_PATH=/etc/spectoncr/keys/public.pem \
  -e SPECTONCR_STORAGE__BACKEND=filesystem \
  -e SPECTONCR_STORAGE__ROOT=/var/lib/spectoncr/data \
  ghcr.io/spectonio/spectoncr:latest specton-registry
```

### Docker Compose (Recommended for Development)

The repository includes a full `docker-compose.yml`:

```bash
# Start all services (registry + auth + key generation)
docker compose up -d

# Verify health
curl http://localhost:5000/health
curl http://localhost:5001/health

# Login and push
docker login localhost:5000 -u admin -p admin
docker tag myimage:latest localhost:5000/demo/default/myimage:latest
docker push localhost:5000/demo/default/myimage:latest
```

To include MinIO for S3-compatible storage:

```bash
docker compose --profile minio up -d
```

Then set the registry to use MinIO by adding these environment variables to the registry service:

```bash
SPECTONCR_STORAGE__BACKEND=minio
SPECTONCR_STORAGE__ROOT=spectoncr
SPECTONCR_STORAGE__ENDPOINT=http://minio:9000
SPECTONCR_STORAGE__ACCESS_KEY=minioadmin
SPECTONCR_STORAGE__SECRET_KEY=minioadmin
```

### Stopping and Cleaning Up

```bash
# Stop services
docker compose down

# Stop and remove all data
docker compose down -v
```

---

## Kubernetes with Helm

SpectonCR provides a Helm chart published to GHCR:

```bash
helm install spectoncr oci://ghcr.io/bwalia/charts/spectoncr
```

Or from the local chart:

```bash
helm install spectoncr ./deploy/helm/spectoncr
```

### Minimal Install (Pull-Through Cache)

The default values enable pull-through caching for Docker Hub, GHCR, GCR, Quay.io, and registry.k8s.io with no auth configuration required:

```bash
helm install spectoncr oci://ghcr.io/bwalia/charts/spectoncr \
  --namespace spectoncr --create-namespace
```

Configure your container runtime to use SpectonCR as a mirror. For containerd (`/etc/containerd/config.toml`):

```toml
[plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
  endpoint = ["http://spectoncr-registry.spectoncr.svc.cluster.local:5000"]
```

### Production with OIDC + S3

```bash
helm install spectoncr oci://ghcr.io/bwalia/charts/spectoncr \
  --namespace spectoncr --create-namespace \
  --values production-values.yaml
```

`production-values.yaml`:

```yaml
registry:
  replicas: 3
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: "2"
      memory: 1Gi

auth:
  replicas: 3
  resources:
    requests:
      cpu: 250m
      memory: 256Mi
    limits:
      cpu: "1"
      memory: 512Mi

oidc:
  enabled: true
  issuerUrl: "https://accounts.google.com"
  clientId: "your-client-id.apps.googleusercontent.com"
  clientSecret: "your-client-secret"
  tenantClaim: "hd"
  scopes:
    - openid
    - profile
    - email

jwt:
  existingSecret: "spectoncr-jwt-keys"
  accessTokenTtl: 300

storage:
  backend: s3
  s3:
    bucket: "my-spectoncr-bucket"
    region: "us-east-1"
    existingSecret: "spectoncr-s3-credentials"
    encrypt: true

ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "600"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  host: registry.example.com
  tls:
    enabled: true
    secretName: registry-tls

serviceMonitor:
  enabled: true
  interval: 30s

rateLimiting:
  enabled: true
  requestsPerSecond: 200
  burst: 400

autoscaling:
  registry:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
  auth:
    enabled: true
    minReplicas: 3
    maxReplicas: 6

podDisruptionBudget:
  registry:
    enabled: true
    minAvailable: 2
  auth:
    enabled: true
    minAvailable: 2
```

Create the required secrets before installing:

```bash
# JWT signing keys
kubectl create secret generic spectoncr-jwt-keys \
  --namespace spectoncr \
  --from-file=private.pem=./keys/private.pem \
  --from-file=public.pem=./keys/public.pem

# S3 credentials (if not using IRSA)
kubectl create secret generic spectoncr-s3-credentials \
  --namespace spectoncr \
  --from-literal=access-key=AKIAIOSFODNN7EXAMPLE \
  --from-literal=secret-key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### High Availability (Multi-Region)

```yaml
multiRegion:
  enabled: true
  localRegion: "us-east-1"
  healthCheckIntervalSecs: 10
  internalPort: 5002
  replication:
    mode: "async"
    maxLagSecs: 60
    batchSize: 50
    sweepIntervalSecs: 10
  regions:
    - name: "us-east-1"
      endpoint: "https://registry-us.example.com"
      internalEndpoint: "http://registry-us-internal:5002"
      isPrimary: true
      priority: 1
    - name: "eu-west-1"
      endpoint: "https://registry-eu.example.com"
      internalEndpoint: "http://registry-eu-internal:5002"
      isPrimary: false
      priority: 2
```

### Using IRSA (AWS) or Workload Identity (GCP)

Instead of static S3 credentials, use IAM Roles for Service Accounts:

```yaml
serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/spectoncr"

storage:
  backend: s3
  s3:
    bucket: "my-spectoncr-bucket"
    region: "us-east-1"
    # No accessKey/secretKey needed -- IRSA provides credentials
```

### Upgrading

```bash
helm upgrade spectoncr oci://ghcr.io/bwalia/charts/spectoncr \
  --namespace spectoncr \
  --values production-values.yaml
```

---

## Storage Backend Configuration

### Filesystem

Best for development and single-node deployments:

```toml
[storage]
backend = "filesystem"
root = "/var/lib/spectoncr/data"
```

Helm values:

```yaml
storage:
  backend: filesystem
  filesystem:
    rootDirectory: /var/lib/spectoncr/data
    persistence:
      enabled: true
      storageClass: "gp3"
      size: 100Gi
```

### Amazon S3

```toml
[storage]
backend = "s3"
root = "my-spectoncr-bucket"
region = "us-east-1"
# For non-AWS S3-compatible services:
# endpoint = "https://s3.us-east-1.amazonaws.com"
# For static credentials (prefer IAM roles):
# access_key = "AKIAIOSFODNN7EXAMPLE"
# secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

Helm values:

```yaml
storage:
  backend: s3
  s3:
    bucket: "my-spectoncr-bucket"
    region: "us-east-1"
    encrypt: true
    sseAlgorithm: "AES256"
    existingSecret: "spectoncr-s3-credentials"
```

### MinIO (S3-compatible)

```toml
[storage]
backend = "minio"
root = "spectoncr"
endpoint = "http://minio:9000"
access_key = "minioadmin"
secret_key = "minioadmin"
```

The `minio` backend automatically enables path-style addressing and allows HTTP connections.

### Google Cloud Storage

```toml
[storage]
backend = "gcs"
root = "my-spectoncr-bucket"
```

GCS uses Application Default Credentials. On GKE, use Workload Identity. For local development, set `GOOGLE_APPLICATION_CREDENTIALS`.

Helm values:

```yaml
storage:
  backend: gcs
  gcs:
    bucket: "my-spectoncr-bucket"
    existingSecret: "spectoncr-gcs-keyfile"
    keyfileField: "keyfile.json"
```

### Azure Blob Storage

```toml
[storage]
backend = "azure"
root = "my-spectoncr-container"
```

Helm values:

```yaml
storage:
  backend: azure
  azure:
    container: "my-spectoncr-container"
    accountName: "myaccount"
    existingSecret: "spectoncr-azure-credentials"
    accountKeyField: "account-key"
```

---

## TLS and Ingress Setup

### Kubernetes Ingress with nginx and cert-manager

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    # Required: Docker push can send arbitrarily large layers
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
    # Recommended: large layers need time to upload
    nginx.ingress.kubernetes.io/proxy-read-timeout: "600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "600"
    # TLS via cert-manager
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  host: registry.example.com
  tls:
    enabled: true
    secretName: registry-tls
  # Path routing
  registryPath: /v2
  authPath: /auth
  # Security: only expose token and JWKS endpoints
  security:
    exposeAllAuthPaths: false
    exposeGitHubActions: false
```

Important nginx annotations for container registries:

| Annotation | Value | Purpose |
|-----------|-------|---------|
| `proxy-body-size` | `"0"` | Disable body size limit for layer uploads |
| `proxy-read-timeout` | `"600"` | Allow 10 minutes for large layer transfers |
| `proxy-send-timeout` | `"600"` | Allow 10 minutes for large layer transfers |
| `proxy-buffering` | `"off"` | Stream large responses without buffering |

### Self-Signed TLS for Development

```bash
# Generate a self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout tls.key -out tls.crt \
  -days 365 -nodes -subj "/CN=registry.local"

# Create Kubernetes secret
kubectl create secret tls registry-tls \
  --cert=tls.crt --key=tls.key \
  --namespace spectoncr
```

To use self-signed certificates with Docker, add the certificate to Docker's trusted certificates:

```bash
# Linux
sudo mkdir -p /etc/docker/certs.d/registry.local:5000
sudo cp tls.crt /etc/docker/certs.d/registry.local:5000/ca.crt
sudo systemctl restart docker

# macOS (Docker Desktop)
# Add tls.crt to Keychain Access, then restart Docker Desktop
```

### TLS Without Ingress (Direct TLS Termination)

If you prefer to terminate TLS at the service level rather than at the ingress, mount certificates directly and configure the services:

```yaml
registry:
  extraVolumes:
    - name: tls
      secret:
        secretName: registry-tls
  extraVolumeMounts:
    - name: tls
      mountPath: /etc/spectoncr/tls
      readOnly: true
  extraEnv:
    - name: SPECTONCR_SERVER__TLS_CERT_PATH
      value: /etc/spectoncr/tls/tls.crt
    - name: SPECTONCR_SERVER__TLS_KEY_PATH
      value: /etc/spectoncr/tls/tls.key
```

---

## Environment Variables Reference

All configuration options can be set via environment variables. The prefix is `SPECTONCR_` and nesting uses double underscores (`__`).

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `SPECTONCR_SERVER__LISTEN_ADDR` | `0.0.0.0:5000` | Registry API bind address |
| `SPECTONCR_SERVER__AUTH_LISTEN_ADDR` | `0.0.0.0:5001` | Auth service bind address |
| `SPECTONCR_SERVER__METRICS_ADDR` | `0.0.0.0:9090` | Prometheus metrics bind address |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `SPECTONCR_AUTH__SIGNING_ALGORITHM` | `RS256` | JWT signing algorithm (`RS256` or `EdDSA`) |
| `SPECTONCR_AUTH__SIGNING_KEY_PATH` | `/etc/spectoncr/keys/private.pem` | Path to private signing key |
| `SPECTONCR_AUTH__VERIFICATION_KEY_PATH` | `/etc/spectoncr/keys/public.pem` | Path to public verification key |
| `SPECTONCR_AUTH__TOKEN_TTL_SECONDS` | `300` | Access token lifetime in seconds |
| `SPECTONCR_AUTH__ISSUER` | `spectoncr` | JWT issuer claim |
| `SPECTONCR_AUTH__AUDIENCE` | `spectoncr-registry` | JWT audience claim |
| `SPECTONCR_AUTH__BOOTSTRAP_ADMIN__USERNAME` | (none) | Bootstrap admin username |
| `SPECTONCR_AUTH__BOOTSTRAP_ADMIN__PASSWORD_HASH` | (none) | Bootstrap admin password SHA-256 hash |

### Storage

| Variable | Default | Description |
|----------|---------|-------------|
| `SPECTONCR_STORAGE__BACKEND` | `filesystem` | Backend type: `filesystem`, `s3`, `minio`, `gcs`, `azure` |
| `SPECTONCR_STORAGE__ROOT` | `/var/lib/spectoncr/data` | Root path or bucket name |
| `SPECTONCR_STORAGE__ENDPOINT` | (none) | S3-compatible endpoint URL |
| `SPECTONCR_STORAGE__REGION` | (none) | AWS region for S3 |
| `SPECTONCR_STORAGE__ACCESS_KEY` | (none) | Static access key for S3/MinIO |
| `SPECTONCR_STORAGE__SECRET_KEY` | (none) | Static secret key for S3/MinIO |

### Observability

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level filter (tracing env-filter syntax) |
| `SPECTONCR_OBSERVABILITY__LOG_LEVEL` | `info` | Log level |
| `SPECTONCR_OBSERVABILITY__LOG_FORMAT` | `json` | Log format: `json` or `pretty` |
| `SPECTONCR_OBSERVABILITY__OTLP_ENDPOINT` | (none) | OpenTelemetry OTLP collector endpoint |

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `SPECTONCR_RATE_LIMIT__DEFAULT_RPS` | `100` | Default requests/second per tenant |
| `SPECTONCR_RATE_LIMIT__IP_RPS` | `50` | Requests/second per IP (unauthenticated) |
| `SPECTONCR_RATE_LIMIT__TOKEN_ISSUE_RPM` | `60` | Token issuance requests/minute per tenant |

### Configuration Loading Order

Configuration is loaded in this order (later sources override earlier):

1. Compiled defaults
2. Config file (`/etc/spectoncr/config.toml` or path from `SPECTONCR_CONFIG_PATH`)
3. Environment variables (prefixed with `SPECTONCR_`, double-underscore for nesting)
