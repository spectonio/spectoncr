# Auto-rebuild CI recipes (design 018)

SpectonCR fires rebuild events; your CI rebuilds the image. Enable with
`--set rebuild.enabled=true` and a `RebuildSubscription`.

## GitHub Actions (`github-dispatch`)

```yaml
apiVersion: spectoncr.io/v1alpha1
kind: RebuildSubscription
metadata:
  name: api-on-base-cve
spec:
  tenantRef: acme
  watch:
    bases: ["python:3.12-slim"]
    descendants: ["acme/prod/api/*"]
  emitter:
    type: github-dispatch
    repo: acme/api
    eventType: rebuild-on-cve
    tokenSecretRef: gh-pat
```

Workflow filter:

```yaml
on:
  repository_dispatch:
    types: [rebuild-on-cve]
jobs:
  rebuild:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          echo "upstream=${{ github.event.client_payload.upstream_ref }}"
          docker build -t "$REGISTRY/acme/prod/api:latest" .
          docker push "$REGISTRY/acme/prod/api:latest"
```

## GitLab CI (`gitlab-trigger`)

```yaml
spec:
  emitter:
    type: gitlab-trigger
    project: "12345"
    ref: main
    triggerTokenSecretRef: gl-trigger
```

Variables set on the pipeline: `SPECTONCR_TRIGGER`, `SPECTONCR_UPSTREAM`,
`SPECTONCR_DOWNSTREAM`, `SPECTONCR_SEVERITY_MAX`.

## Generic webhook (`webhook`)

```yaml
spec:
  emitter:
    type: webhook
    url: https://ci.example.com/hooks/rebuild
    hmacSecretRef: ci-hmac
```

Verify `X-SpectonCR-Signature: sha256=<hex>` over the raw JSON body.

## Tekton (`tekton`)

```yaml
spec:
  emitter:
    type: tekton
    url: http://el-rebuild.tekton-pipelines.svc/rebuild
    authSecretRef: tekton-token
    authHeaderName: Authorization
```

Point a Tekton `EventListener` + `Trigger` at the JSON `RebuildEvent` body.

## Manual fire

```bash
curl -X POST "$REGISTRY/v2/_rebuild/trigger" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant": "acme",
    "subscription": "api-on-base-cve",
    "upstream": "python:3.12-slim",
    "downstream": "acme/prod/api:latest",
    "reason": "manual"
  }'
```
