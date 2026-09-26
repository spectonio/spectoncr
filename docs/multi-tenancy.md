# Multi-Tenancy

SpectonCR provides full multi-tenancy with isolated storage, access control, quotas, and rate limiting per tenant. The tenancy model uses a three-segment repository path: `tenant/project/repository`.

## Table of Contents

- [Tenant / Project / Repository Model](#tenant--project--repository-model)
- [Default Tenant for Standard Docker Paths](#default-tenant-for-standard-docker-paths)
- [Kubernetes CRDs](#kubernetes-crds)
- [Isolation Guarantees](#isolation-guarantees)
- [Quotas and Rate Limiting](#quotas-and-rate-limiting)

---

## Tenant / Project / Repository Model

SpectonCR organizes images in a three-level hierarchy:

```
tenant / project / repository : tag
```

| Level | Description | Example |
|-------|-------------|---------|
| Tenant | Top-level organizational unit (company, team, or individual) | `acme` |
| Project | Logical grouping within a tenant (team, application, environment) | `backend` |
| Repository | A single container image | `api-server` |

Full image reference: `registry.example.com/acme/backend/api-server:v1.2.3`

This maps to the OCI Distribution path as:

```
/v2/acme/backend/api-server/manifests/v1.2.3
/v2/acme/backend/api-server/blobs/sha256:abc123...
```

### Why Three Segments?

Two-segment paths (like Docker Hub's `library/nginx`) conflate ownership and organization. The three-segment model separates concerns:

- **Tenant**: Who owns it (billing, quotas, admin boundary)
- **Project**: How it is organized (visibility, retention, access policies)
- **Repository**: What it is (a single image with tags)

---

## Default Tenant for Standard Docker Paths

For backward compatibility with standard Docker 2-segment paths, SpectonCR uses a special default tenant named `_` (underscore). When a path has only two segments, the registry automatically maps it to the `_` tenant.

```bash
# Standard 2-segment path -- tenant defaults to "_"
docker pull registry.example.com/library/nginx:latest

# Equivalent explicit 3-segment path
docker pull registry.example.com/_/library/nginx:latest
```

This is particularly useful for:

- Pull-through cache mirrors (where upstream images have 2-segment paths)
- Migration from registries that use 2-segment paths
- Simple setups where multi-tenancy is not needed

The `_` tenant is created automatically and cannot be deleted. It has default quotas and rate limits applied.

---

## Kubernetes CRDs

SpectonCR provides four Custom Resource Definitions (CRDs) in the `spectoncr.io/v1alpha1` API group. The `specton-controller` watches these resources, checks their references, and pushes each spec to the auth service.

The installed CRD schemas (`deploy/helm/spectoncr/templates/crds/`) are the reference for every field below. The API server rejects missing required fields and **silently drops fields the schema doesn't declare**, so a misspelled field has no effect. `kubectl explain tenant.spec` lists the valid fields.

> **Sync status.** The auth service does not implement the `/api/v1/tenants/...` endpoints the controller pushes to yet. Until it does, every resource reports `Ready=False` with reason `AuthServiceRejected` (HTTP 404), and phase `Pending`. The controller reports this honestly rather than marking resources as reconciled.

### Tenant

Tenants are cluster-scoped resources (not namespaced).

```yaml
apiVersion: spectoncr.io/v1alpha1
kind: Tenant
metadata:
  name: acme
spec:
  displayName: "Acme Corporation"
  adminEmail: "admin@acme.com"          # required
  enabled: true                          # false suspends the tenant
  # Override the global storage backend: filesystem, s3, gcs or azure
  storageBackendOverride: "s3"
  # Restrict access to specific IP ranges
  allowedIpCidrs:
    - "10.0.0.0/8"
    - "203.0.113.0/24"
  quotas:
    storageBytes: 107374182400           # 100 GiB
    maxRepositories: 500
    maxTagsPerRepository: 1000
    pullRateLimit: 1000
    pushRateLimit: 200
  labels:
    team: platform
```

Check tenant status:

```bash
kubectl get tenants
kubectl describe tenant acme
```

`status.phase` is `Pending`, `Active`, `Suspended` (when `enabled: false`) or `Deleting`. The conditions say whether the last sync worked:

```
Status:
  Phase:  Active
  Conditions:
    Type:     Synced
    Status:   True
    Reason:   Synced
    Message:  PUT /api/v1/tenants/acme succeeded
    Type:     Ready
    Status:   True
    Reason:   Synced
```

### Project

Projects are namespaced resources that reference a parent tenant. A Project whose tenant doesn't exist stays `Pending` with reason `TenantNotFound`.

```yaml
apiVersion: spectoncr.io/v1alpha1
kind: Project
metadata:
  name: backend
  namespace: spectoncr
spec:
  tenantRef: acme                        # required
  displayName: "Backend Services"        # required
  description: "Backend service images"
  visibility: private                    # private (default), internal or public
  immutableTags: true                    # prevent overwriting existing tags
  vulnerabilityScanning:
    enabled: true
    blockOnCritical: true
    blockOnHigh: false
  retentionPolicy:
    enabled: true
    maxTagAge: 90d                       # <n>d, <n>w, <n>m or <n>y
    keepLastN: 20
    keepSemver: true                     # never expire semver tags
  quotas:
    maxRepositories: 100
    storageBytes: 53687091200            # 50 GiB
```

```bash
kubectl get projects -n spectoncr
kubectl describe project backend -n spectoncr
```

### AccessPolicy

AccessPolicy allows or denies actions on resources to subjects within a tenant. When policies overlap, the one with the higher `priority` (-1000 to 1000, default 0) takes precedence.

```yaml
apiVersion: spectoncr.io/v1alpha1
kind: AccessPolicy
metadata:
  name: acme-backend-devs
  namespace: spectoncr
spec:
  tenantRef: acme                        # required
  description: "Backend developers can push to backend repos"
  effect: Allow                          # required: Allow or Deny
  priority: 0
  subjects:                              # required, at least one
    - kind: Group
      name: "backend-developers"
    - kind: User
      name: "alice@acme.com"
    - kind: ServiceAccount
      name: "ci-bot"
    - kind: Group                        # match an OIDC claim instead of a name
      oidcClaim: "groups"
      claimValue: "platform-admins"
  resources:                             # required, at least one
    - type: repository                   # repository, tag, manifest, blob or project
      namePattern: "backend/*"           # glob; defaults to "*"
      projectRef: backend                # must exist in the same namespace
  actions:                               # required: pull, push, delete, list, admin or *
    - pull
    - push
  conditions:                            # optional extra conditions
    - type: SourceIP
      sourceCidrs: ["10.0.0.0/8"]
    - type: TimeWindow
      timeWindowStart: "08:00"
      timeWindowEnd: "20:00"
```

`status.valid` is `false` when the tenant or a `projectRef` doesn't exist.

Subject kinds:

| Kind | Description |
|------|-------------|
| `User` | An individual user, identified by username or email |
| `Group` | A group of users (e.g., from OIDC group claims) |
| `ServiceAccount` | A CI/CD service account or bot |
| `Anonymous` | Unauthenticated clients |

### TokenPolicy

TokenPolicy controls JWT token behavior per tenant. Durations use `<n>s`, `<n>m`, `<n>h` or `<n>d`.

```yaml
apiVersion: spectoncr.io/v1alpha1
kind: TokenPolicy
metadata:
  name: acme-token-policy
  namespace: spectoncr
spec:
  tenantRef: acme                        # required
  maxTokenLifetime: 10m                  # default 1h
  maxRefreshTokenLifetime: 24h           # default 24h
  allowedScopes:
    - repository:pull
    - repository:push
  maxConcurrentSessions: 0               # 0 = unlimited
  rotation:
    enabled: true
    rotationInterval: 30d
    gracePeriod: 5m
  revocation:
    revokeOnPasswordChange: true
    revokeOnSuspension: true
    revokeOnPolicyChange: false
  ipRestrictions:
    bindToIp: false
    allowedCidrs:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
  robotAccounts:
    enabled: true
    maxPerProject: 10
    maxTokenLifetime: 365d
```

The referenced tenant must exist; field formats are enforced by the CRD schema.

---

## Isolation Guarantees

SpectonCR enforces strict isolation between tenants at multiple levels:

### Storage Isolation

Each tenant's data is stored under a separate prefix in the storage backend:

```
/var/lib/spectoncr/data/
  acme/
    backend/
      api-server/
        manifests/
        blobs/
    frontend/
      ...
  other-tenant/
    ...
```

For cloud storage backends (S3, GCS, Azure), tenants can optionally use separate buckets or containers by setting `storageBackend` on the Tenant CRD.

### Authentication Isolation

- Tokens are scoped to specific tenant/project/repository paths
- A token issued for `acme/backend/api-server:pull` cannot be used to access `other-tenant/...`
- Token scope is encoded in the JWT `access` claim and validated on every request

### Network Isolation

- Per-tenant IP allowlists via `allowedIpRanges` on the Tenant CRD
- Per-tenant IP restrictions on token issuance via TokenPolicy

### Namespace Isolation

- Project, AccessPolicy, and TokenPolicy CRDs are namespaced
- Kubernetes RBAC can restrict which teams can create or modify these resources

---

## Quotas and Rate Limiting

### Tenant Quotas

Set via the Tenant CRD:

```yaml
spec:
  quotas:
    maxProjects: 50           # Maximum number of projects
    maxRepositories: 500      # Maximum total repositories across all projects
    maxStorageBytes: 107374182400  # 100 GiB total storage
```

When a quota is exceeded, push operations return `429 Too Many Requests` or `403 Forbidden` with a descriptive error message.

### Rate Limiting

Rate limits are applied at multiple levels:

**Global defaults** (config file or environment variables):

```toml
[rate_limit]
default_rps = 100       # Default requests/second per tenant
ip_rps = 50             # Requests/second per IP (unauthenticated)
token_issue_rpm = 60    # Token requests/minute per tenant
```

```bash
SPECTONCR_RATE_LIMIT__DEFAULT_RPS=100
SPECTONCR_RATE_LIMIT__IP_RPS=50
SPECTONCR_RATE_LIMIT__TOKEN_ISSUE_RPM=60
```

**Per-tenant override** via Tenant CRD:

```yaml
spec:
  rateLimitRps: 200     # This tenant gets 200 req/s instead of the default 100
```

**Helm chart values** for Kubernetes deployments:

```yaml
rateLimiting:
  enabled: true
  requestsPerSecond: 100
  burst: 200
  pullRatePerTenant: 1000    # Pulls per minute per tenant
  pushRatePerTenant: 500     # Pushes per minute per tenant
```

### Rate Limit Headers

When rate limits are approached or exceeded, the registry returns standard rate limit headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 42
X-RateLimit-Reset: 1705312200
```

When the limit is exceeded:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 1
```

### Monitoring Quotas

Quota usage is exposed via Prometheus metrics:

```
spectoncr_tenant_storage_bytes{tenant="acme"}
spectoncr_tenant_repository_count{tenant="acme"}
spectoncr_tenant_project_count{tenant="acme"}
spectoncr_rate_limit_rejected_total{tenant="acme", endpoint="push"}
```

See the [Observability](observability.md) guide for setting up monitoring dashboards.
