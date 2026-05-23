# Troubleshooting

This guide covers common issues when operating SpectonCR, with diagnostic steps and solutions.

## Table of Contents

- [Common Errors](#common-errors)
- [Docker Push and Pull Debugging](#docker-push-and-pull-debugging)
- [JWT Token Issues](#jwt-token-issues)
- [Storage Backend Connectivity](#storage-backend-connectivity)
- [Network and Ingress Issues](#network-and-ingress-issues)
- [Log Analysis Tips](#log-analysis-tips)
- [kubectl Commands for Debugging](#kubectl-commands-for-debugging)

---

## Common Errors

### 401 Unauthorized

**Symptom**: Docker push or pull fails with `unauthorized: authentication required`.

**Possible causes and fixes**:

1. **Not logged in**:
   ```bash
   docker login registry.example.com -u admin -p admin
   ```

2. **Expired token**: Tokens expire after 5 minutes by default. Docker should refresh automatically, but if it does not:
   ```bash
   docker logout registry.example.com
   docker login registry.example.com -u admin -p admin
   ```

3. **Auth service unreachable from registry**: The registry must be able to reach the auth service to validate tokens. Check connectivity:
   ```bash
   # From inside the registry pod
   kubectl exec -it deploy/spectoncr-registry -n spectoncr -- \
     curl -f http://spectoncr-auth:5001/health
   ```

4. **Key mismatch**: The auth service signs tokens with the private key, and the registry verifies with the public key. Both must correspond:
   ```bash
   # Verify keys match
   openssl rsa -in private.pem -pubout 2>/dev/null | diff - public.pem
   ```

5. **Wrong audience or issuer**: The `issuer` and `audience` values must match between auth and registry:
   ```bash
   # Check auth service config
   kubectl exec -it deploy/spectoncr-auth -n spectoncr -- env | grep SPECTONCR_AUTH

   # Check registry config
   kubectl exec -it deploy/spectoncr-registry -n spectoncr -- env | grep SPECTONCR_AUTH
   ```

### 404 Not Found on Push

**Symptom**: `docker push` fails with `error parsing HTTP 404 response body` or `name unknown`.

**Possible causes and fixes**:

1. **Wrong image path format**: SpectonCR uses 3-segment paths (`tenant/project/repository`):
   ```bash
   # Wrong (1 segment)
   docker push registry.example.com/myimage:latest

   # Wrong (2 segments without pull-through cache)
   docker push registry.example.com/myorg/myimage:latest

   # Correct (3 segments)
   docker push registry.example.com/acme/backend/myimage:latest
   ```

2. **Ingress path routing misconfigured**: Ensure the ingress routes `/v2/` to the registry service. See the [Network and Ingress Issues](#network-and-ingress-issues) section.

3. **Tenant or project does not exist**: If using CRDs, the tenant and project must be created first:
   ```bash
   kubectl get tenants
   kubectl get projects -n spectoncr
   ```

### 502 Bad Gateway

**Symptom**: Requests return `502 Bad Gateway` from the ingress controller.

**Possible causes and fixes**:

1. **Registry pod not ready**: Check pod status:
   ```bash
   kubectl get pods -n spectoncr -l app=spectoncr-registry
   kubectl describe pod -n spectoncr -l app=spectoncr-registry
   ```

2. **Health check failing**: Verify the health endpoint directly:
   ```bash
   kubectl port-forward svc/spectoncr-registry 5000:5000 -n spectoncr
   curl http://localhost:5000/health
   ```

3. **Resource limits too low**: The pod may be OOMKilled. Check events:
   ```bash
   kubectl get events -n spectoncr --sort-by='.lastTimestamp' | grep -i oom
   ```

4. **Ingress timeout**: Large layer uploads can exceed default timeouts. See [Network and Ingress Issues](#network-and-ingress-issues).

### 429 Too Many Requests

**Symptom**: Requests fail with `429 Too Many Requests`.

**Cause**: Rate limiting is active and the client exceeded the configured threshold.

**Fixes**:

1. Check current rate limit settings:
   ```bash
   kubectl exec -it deploy/spectoncr-registry -n spectoncr -- \
     env | grep RATE_LIMIT
   ```

2. Increase limits for the specific tenant via the Tenant CRD:
   ```yaml
   spec:
     rateLimitRps: 500
   ```

3. Or increase global defaults:
   ```bash
   SPECTONCR_RATE_LIMIT__DEFAULT_RPS=200
   ```

### 413 Request Entity Too Large

**Symptom**: Push fails for large images.

**Cause**: Ingress controller body size limit.

**Fix**: Set the nginx annotation to remove the limit:
```yaml
nginx.ingress.kubernetes.io/proxy-body-size: "0"
```

---

## Docker Push and Pull Debugging

### Enable Docker Client Debug Logging

```bash
# Linux: edit /etc/docker/daemon.json
{
  "debug": true
}
sudo systemctl restart docker

# View debug logs
journalctl -u docker -f

# macOS (Docker Desktop): Enable in Settings > Docker Engine
```

### Trace the Token Exchange

```bash
# Step 1: Hit the /v2/ endpoint to get the auth challenge
curl -v http://localhost:5000/v2/ 2>&1 | grep -i www-authenticate
```

Expected output:
```
Www-Authenticate: Bearer realm="http://localhost:5001/auth/token",service="spectoncr-registry"
```

```bash
# Step 2: Request a token from the auth service
curl -v -u admin:admin \
  "http://localhost:5001/auth/token?service=spectoncr-registry&scope=repository:demo/default/myimage:push,pull"
```

```bash
# Step 3: Use the token to access the registry
TOKEN="<token from step 2>"
curl -v -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/v2/demo/default/myimage/tags/list
```

### Common Push Failures

**"blob unknown to registry"**: The blob upload was interrupted or the digest does not match. Retry the push:
```bash
docker push registry.example.com/acme/backend/myimage:latest
```

**"manifest invalid"**: The manifest references blobs that do not exist in the registry. Ensure all layers were pushed before the manifest:
```bash
# Force a full re-push
docker push registry.example.com/acme/backend/myimage:latest
```

**Slow uploads**: Check network bandwidth and storage backend latency:
```bash
# Check storage latency metric
curl -s http://localhost:9090/metrics | grep storage_operation_duration
```

---

## JWT Token Issues

### Decode a Token for Inspection

```bash
# Extract and decode the JWT payload (does not verify signature)
TOKEN="eyJhbGciOiJSUzI1NiIs..."
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

Expected output:
```json
{
  "iss": "spectoncr",
  "aud": "spectoncr-registry",
  "sub": "admin",
  "exp": 1705312500,
  "iat": 1705312200,
  "access": [
    {
      "type": "repository",
      "name": "demo/default/myimage",
      "actions": ["push", "pull"]
    }
  ]
}
```

### Token Expired

Check the `exp` claim:
```bash
# Convert Unix timestamp to human-readable
date -d @1705312500    # Linux
date -r 1705312500     # macOS
```

If tokens expire too quickly, increase the TTL:
```bash
SPECTONCR_AUTH__TOKEN_TTL_SECONDS=600
```

### Token Scope Mismatch

The `access` claim must include the correct repository path and actions. If you get `insufficient_scope`, the token was issued for a different repository or action than what you are requesting.

```bash
# Request a token with the correct scope
curl -u admin:admin \
  "http://localhost:5001/auth/token?service=spectoncr-registry&scope=repository:acme/backend/myimage:push,pull"
```

### Key Rotation

When rotating JWT signing keys:

1. Generate new keys.
2. Update the auth service with the new private key.
3. Update the registry with the new public key.
4. Restart both services. Existing tokens signed with the old key will fail validation -- they will expire within the TTL window (default 5 minutes).

```bash
# Generate new keys
openssl genrsa -out private-new.pem 4096
openssl rsa -in private-new.pem -pubout -out public-new.pem

# Update the Kubernetes secret
kubectl create secret generic spectoncr-jwt-keys \
  --from-file=private.pem=private-new.pem \
  --from-file=public.pem=public-new.pem \
  --namespace spectoncr \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart services to pick up new keys
kubectl rollout restart deploy/spectoncr-auth deploy/spectoncr-registry -n spectoncr
```

---

## Storage Backend Connectivity

### Filesystem

Check disk space and permissions:
```bash
# Inside the container
kubectl exec -it deploy/spectoncr-registry -n spectoncr -- df -h /var/lib/spectoncr/data
kubectl exec -it deploy/spectoncr-registry -n spectoncr -- ls -la /var/lib/spectoncr/data
```

Check if the PersistentVolumeClaim is bound:
```bash
kubectl get pvc -n spectoncr
```

### S3

Verify connectivity from the pod:
```bash
kubectl exec -it deploy/spectoncr-registry -n spectoncr -- \
  curl -s -o /dev/null -w "%{http_code}" https://s3.us-east-1.amazonaws.com
```

Common S3 issues:

- **AccessDenied**: Check IAM permissions. The service account needs `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, `s3:ListBucket`.
- **NoSuchBucket**: The bucket does not exist or the region is wrong.
- **Connection timeout**: Check network policies and VPC endpoints.

For MinIO:
```bash
kubectl exec -it deploy/spectoncr-registry -n spectoncr -- \
  curl -s http://minio:9000/minio/health/live
```

### GCS

Verify workload identity or service account key:
```bash
kubectl exec -it deploy/spectoncr-registry -n spectoncr -- \
  env | grep GOOGLE
```

### Azure Blob

Verify the container exists and credentials are correct:
```bash
kubectl exec -it deploy/spectoncr-registry -n spectoncr -- \
  env | grep SPECTONCR_STORAGE
```

### Storage Metrics

Check the circuit breaker state and error rates:
```bash
curl -s http://localhost:9090/metrics | grep -E "circuit_breaker|storage_operation_errors"
```

If the circuit breaker is open (value `2`), the storage backend has been experiencing consecutive failures. Check the storage backend's health and wait for the breaker to transition to half-open (default: 30 seconds).

---

## Network and Ingress Issues

### Ingress Not Routing Correctly

Verify the ingress resource:
```bash
kubectl get ingress -n spectoncr -o yaml
```

Check that the ingress controller sees the backends:
```bash
# For nginx ingress
kubectl logs deploy/ingress-nginx-controller -n ingress-nginx | grep spectoncr
```

### Large Push Timeouts

Layer uploads for large images can take minutes. Ensure these annotations are set on the ingress:

```yaml
nginx.ingress.kubernetes.io/proxy-body-size: "0"
nginx.ingress.kubernetes.io/proxy-read-timeout: "600"
nginx.ingress.kubernetes.io/proxy-send-timeout: "600"
nginx.ingress.kubernetes.io/proxy-buffering: "off"
```

### TLS Certificate Errors

```bash
# Check the certificate presented by the ingress
openssl s_client -connect registry.example.com:443 -servername registry.example.com </dev/null 2>/dev/null | openssl x509 -noout -dates -subject

# If using cert-manager, check the Certificate resource
kubectl get certificates -n spectoncr
kubectl describe certificate registry-tls -n spectoncr
```

For self-signed certificates, configure Docker to trust them:
```bash
# Linux
sudo mkdir -p /etc/docker/certs.d/registry.example.com
sudo cp ca.crt /etc/docker/certs.d/registry.example.com/ca.crt
sudo systemctl restart docker
```

### Service-to-Service Communication

The registry must be able to reach the auth service. Verify internal DNS resolution and connectivity:
```bash
kubectl exec -it deploy/spectoncr-registry -n spectoncr -- \
  nslookup spectoncr-auth.spectoncr.svc.cluster.local

kubectl exec -it deploy/spectoncr-registry -n spectoncr -- \
  curl -s http://spectoncr-auth:5001/health
```

### Network Policies

If NetworkPolicy is enabled, ensure the rules allow:
- Ingress controller to reach registry (port 5000) and auth (port 5001)
- Registry to reach auth (port 5001)
- Prometheus to reach metrics ports (9090, 9091)
- Registry to reach the storage backend (S3, GCS, etc.)

```bash
kubectl get networkpolicy -n spectoncr -o yaml
```

---

## Log Analysis Tips

### View Logs in Kubernetes

```bash
# Registry logs
kubectl logs deploy/spectoncr-registry -n spectoncr -f

# Auth logs
kubectl logs deploy/spectoncr-auth -n spectoncr -f

# Previous container (after crash)
kubectl logs deploy/spectoncr-registry -n spectoncr --previous

# All pods for a service
kubectl logs -l app=spectoncr-registry -n spectoncr --tail=100
```

### Filter JSON Logs with jq

```bash
# Show only errors
kubectl logs deploy/spectoncr-registry -n spectoncr | jq 'select(.level == "ERROR")'

# Show push events
kubectl logs deploy/spectoncr-registry -n spectoncr | jq 'select(.message == "manifest pushed")'

# Show requests for a specific tenant
kubectl logs deploy/spectoncr-registry -n spectoncr | jq 'select(.span.tenant == "acme")'

# Show slow requests (over 1 second)
kubectl logs deploy/spectoncr-registry -n spectoncr | jq 'select(.fields.duration_ms > 1000)'

# Show auth failures
kubectl logs deploy/spectoncr-auth -n spectoncr | jq 'select(.level == "WARN" or .level == "ERROR")'
```

### Docker Compose Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f registry

# Since a specific time
docker compose logs -f --since 5m registry
```

### Common Log Patterns to Watch For

| Log Message | Meaning | Action |
|-------------|---------|--------|
| `"auth-service sync returned non-success"` | Controller failed to sync CRD to auth service | Check auth service health |
| `"circuit breaker opened"` | Storage backend consecutive failures | Check storage backend |
| `"rate limit exceeded"` | Client hit rate limit | Review rate limit config |
| `"token validation failed"` | Invalid or expired JWT | Check key configuration |
| `"referenced Tenant does not exist"` | Project CRD references missing tenant | Create the tenant first |
| `"upstream fetch failed"` | Pull-through cache upstream error | Check upstream registry availability |

---

## kubectl Commands for Debugging

### Pod and Service Status

```bash
# Overview of all SpectonCR resources
kubectl get all -n spectoncr

# Detailed pod information
kubectl describe pod -n spectoncr -l app=spectoncr-registry

# Check events (sorted by time)
kubectl get events -n spectoncr --sort-by='.lastTimestamp'

# Check resource usage
kubectl top pods -n spectoncr
```

### CRD Status

```bash
# List all tenants and their status
kubectl get tenants -o wide

# List all projects
kubectl get projects -n spectoncr -o wide

# List access policies
kubectl get accesspolicies -n spectoncr -o wide

# List token policies
kubectl get tokenpolicies -n spectoncr -o wide

# Describe a specific tenant with conditions
kubectl describe tenant acme

# Check controller logs
kubectl logs deploy/specton-controller -n spectoncr -f
```

### Network Debugging

```bash
# Check services
kubectl get svc -n spectoncr

# Check endpoints (are pods registered?)
kubectl get endpoints -n spectoncr

# DNS resolution test
kubectl run dns-test --rm -it --image=busybox --restart=Never -- \
  nslookup spectoncr-registry.spectoncr.svc.cluster.local

# Port-forward for direct access
kubectl port-forward svc/spectoncr-registry 5000:5000 -n spectoncr
kubectl port-forward svc/spectoncr-auth 5001:5001 -n spectoncr
```

### Storage Debugging

```bash
# Check PVC status
kubectl get pvc -n spectoncr

# Check PV details
kubectl get pv | grep spectoncr

# Check disk usage inside the pod
kubectl exec -it deploy/spectoncr-registry -n spectoncr -- df -h

# List stored data
kubectl exec -it deploy/spectoncr-registry -n spectoncr -- \
  ls -la /var/lib/spectoncr/data/
```

### Helm Debugging

```bash
# Check installed release
helm list -n spectoncr

# Show computed values
helm get values spectoncr -n spectoncr

# Show all values (including defaults)
helm get values spectoncr -n spectoncr --all

# Show the rendered templates
helm template spectoncr oci://ghcr.io/bwalia/charts/spectoncr \
  --values production-values.yaml

# Check release history
helm history spectoncr -n spectoncr

# Rollback to a previous release
helm rollback spectoncr 1 -n spectoncr
```

### Quick Health Check Script

```bash
#!/bin/bash
# spectoncr-healthcheck.sh
NAMESPACE=${1:-spectoncr}

echo "=== Pod Status ==="
kubectl get pods -n "$NAMESPACE" -o wide

echo ""
echo "=== Service Endpoints ==="
kubectl get endpoints -n "$NAMESPACE"

echo ""
echo "=== PVC Status ==="
kubectl get pvc -n "$NAMESPACE"

echo ""
echo "=== Recent Events ==="
kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' | tail -20

echo ""
echo "=== CRD Status ==="
kubectl get tenants 2>/dev/null || echo "No Tenant CRDs found"
kubectl get projects -n "$NAMESPACE" 2>/dev/null || echo "No Project CRDs found"

echo ""
echo "=== Health Checks ==="
kubectl exec -it deploy/spectoncr-registry -n "$NAMESPACE" -- \
  curl -s -o /dev/null -w "Registry: %{http_code}\n" http://localhost:5000/health 2>/dev/null
kubectl exec -it deploy/spectoncr-auth -n "$NAMESPACE" -- \
  curl -s -o /dev/null -w "Auth: %{http_code}\n" http://localhost:5001/health 2>/dev/null
```
