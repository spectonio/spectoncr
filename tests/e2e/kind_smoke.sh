#!/usr/bin/env bash
# Live cluster smoke (kind + Helm).
#
# 1. Always: helm template the chart (JWT keys required).
# 2. When Docker+kind available and a matching-arch image exists: create a
#    kind cluster, load the image, helm install, port-forward /health.
# 3. Always (when cargo available): run auto_rebuild_e2e unit path.
#
# Prerequisites: helm, openssl. Optional: docker, kind, kubectl, cargo.
# Installs `kind` via brew when missing (macOS).
#
# Run from repo root:
#   bash tests/e2e/kind_smoke.sh
#
# Env:
#   KIND_CLUSTER     cluster name (default: spectoncr-smoke)
#   SKIP_CLEANUP=1   leave cluster running
#   HELM_TIMEOUT     helm --timeout (default: 10m)
#   SPECTONCR_IMAGE  image to load into kind (default: bwalia/spectoncr:latest
#                    if present locally). Must match node arch (arm64 on Apple
#                    Silicon kind nodes).

set -euo pipefail

log()  { printf "[kind-smoke] %s\n" "$*"; }
fail() { printf "[kind-smoke][FAIL] %s\n" "$*" >&2; exit 1; }
skip_live() { printf "[kind-smoke][SKIP-LIVE] %s\n" "$*"; }

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

CLUSTER="${KIND_CLUSTER:-spectoncr-smoke}"
NS="spectoncr"
CHART="$ROOT/deploy/helm/spectoncr"
HELM_TIMEOUT="${HELM_TIMEOUT:-10m}"
KEYDIR=""
PF_PID=""
DEFAULT_LOCAL_IMAGE="bwalia/spectoncr:latest"
LIVE=0

cleanup_pf() { [[ -n "${PF_PID:-}" ]] && kill "$PF_PID" 2>/dev/null || true; }
cleanup() {
  cleanup_pf
  [[ -n "${KEYDIR:-}" ]] && rm -rf "$KEYDIR"
  if [[ "$LIVE" -eq 1 ]]; then
    if [[ "${SKIP_CLEANUP:-}" == "1" ]]; then
      log "SKIP_CLEANUP=1 — leaving cluster $CLUSTER"
    else
      log "deleting kind cluster $CLUSTER"
      kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
    fi
  fi
}
trap cleanup EXIT

command -v helm >/dev/null || fail "helm not installed"
command -v openssl >/dev/null || fail "openssl not installed"

KEYDIR="$(mktemp -d)"
openssl genrsa -out "$KEYDIR/signing.pem" 2048 2>/dev/null \
  || fail "openssl genrsa failed"
openssl rsa -in "$KEYDIR/signing.pem" -pubout -out "$KEYDIR/verification.pem" 2>/dev/null \
  || fail "openssl rsa pubout failed"
SIGNING_B64="$(base64 < "$KEYDIR/signing.pem" | tr -d '\n')"
VERIFY_B64="$(base64 < "$KEYDIR/verification.pem" | tr -d '\n')"

log "helm template (chart render check)"
helm template spectoncr "$CHART" \
  --namespace "$NS" \
  --set registry.replicas=1 \
  --set auth.replicas=1 \
  --set autoscaling.enabled=false \
  --set redis.enabled=false \
  --set storage.backend=filesystem \
  --set storage.filesystem.persistence.enabled=false \
  --set signing.enabled=false \
  --set rebuild.enabled=false \
  --set promotion.enabled=false \
  --set admission.enabled=false \
  --set pilot.enabled=false \
  --set-string jwt.signingKey="$SIGNING_B64" \
  --set-string jwt.verificationKey="$VERIFY_B64" \
  >/dev/null \
  || fail "helm template failed"

log "helm template OK"

# ── optional live kind path ──────────────────────────────────────────
run_live=1
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  skip_live "docker not available"
  run_live=0
elif ! command -v kubectl >/dev/null 2>&1; then
  skip_live "kubectl not installed"
  run_live=0
fi

if [[ "$run_live" -eq 1 ]] && ! command -v kind >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    log "installing kind via brew"
    brew install kind || { skip_live "brew install kind failed"; run_live=0; }
  else
    skip_live "kind not installed and brew unavailable"
    run_live=0
  fi
fi

IMAGE="${SPECTONCR_IMAGE:-}"
if [[ "$run_live" -eq 1 && -z "$IMAGE" ]] && docker image inspect "$DEFAULT_LOCAL_IMAGE" >/dev/null 2>&1; then
  IMAGE="$DEFAULT_LOCAL_IMAGE"
fi

if [[ "$run_live" -eq 1 && -n "$IMAGE" ]]; then
  IMG_ARCH="$(docker image inspect "$IMAGE" --format '{{.Architecture}}' 2>/dev/null || true)"
  HOST_ARCH="$(uname -m)"
  case "$HOST_ARCH" in
    arm64|aarch64) NEED=arm64 ;;
    x86_64|amd64)  NEED=amd64 ;;
    *)             NEED="$HOST_ARCH" ;;
  esac
  if [[ -n "$IMG_ARCH" && "$IMG_ARCH" != "$NEED" ]]; then
    skip_live "image $IMAGE is $IMG_ARCH but kind node needs $NEED — rebuild multi-arch or set SPECTONCR_IMAGE"
    run_live=0
  fi
elif [[ "$run_live" -eq 1 && -z "$IMAGE" ]]; then
  skip_live "no SPECTONCR_IMAGE / local $DEFAULT_LOCAL_IMAGE — skipping kind deploy"
  run_live=0
fi

if [[ "$run_live" -eq 1 ]]; then
  LIVE=1
  if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    log "creating kind cluster $CLUSTER"
    kind create cluster --name "$CLUSTER" || fail "kind create failed"
  else
    log "reusing existing kind cluster $CLUSTER"
    kubectl cluster-info --context "kind-$CLUSTER" >/dev/null \
      || fail "cannot talk to kind-$CLUSTER"
  fi
  kubectl config use-context "kind-$CLUSTER" >/dev/null

  log "loading image into kind: $IMAGE"
  kind load docker-image "$IMAGE" --name "$CLUSTER" \
    || fail "kind load docker-image failed"

  IMG_REPO="${IMAGE%:*}"
  IMG_TAG="${IMAGE##*:}"

  log "helm upgrade --install spectoncr"
  if ! helm upgrade --install spectoncr "$CHART" \
    --namespace "$NS" --create-namespace \
    --set registry.replicas=1 \
    --set auth.replicas=1 \
    --set autoscaling.enabled=false \
    --set registry.resources.requests.memory=128Mi \
    --set registry.resources.limits.memory=256Mi \
    --set redis.enabled=false \
    --set storage.backend=filesystem \
    --set storage.filesystem.persistence.enabled=false \
    --set signing.enabled=false \
    --set rebuild.enabled=false \
    --set promotion.enabled=false \
    --set admission.enabled=false \
    --set pilot.enabled=false \
    --set "registry.image.repository=$IMG_REPO" \
    --set "registry.image.tag=$IMG_TAG" \
    --set "registry.image.pullPolicy=Never" \
    --set "auth.image.repository=$IMG_REPO" \
    --set "auth.image.tag=$IMG_TAG" \
    --set "auth.image.pullPolicy=Never" \
    --set-string jwt.signingKey="$SIGNING_B64" \
    --set-string jwt.verificationKey="$VERIFY_B64" \
    --timeout "$HELM_TIMEOUT" \
    --wait; then
    log "helm wait failed — dumping pod status"
    kubectl -n "$NS" get pods,deploy -o wide || true
    kubectl -n "$NS" describe pods 2>/dev/null | tail -60 || true
    fail "helm install failed"
  fi

  log "port-forward + health check"
  kubectl -n "$NS" port-forward svc/spectoncr-registry 15000:5000 >/tmp/spectoncr-pf.log 2>&1 &
  PF_PID=$!
  sleep 3
  HEALTH="$(curl -sf --max-time 10 http://127.0.0.1:15000/health || true)"
  if [[ -z "$HEALTH" ]]; then
    log "port-forward log:"; cat /tmp/spectoncr-pf.log || true
    kubectl -n "$NS" get pods -o wide || true
    fail "health check failed"
  fi
  log "health OK: $HEALTH"
fi

if command -v cargo >/dev/null 2>&1; then
  log "running auto_rebuild unit path"
  bash tests/e2e/auto_rebuild_e2e.sh || fail "auto_rebuild_e2e failed"
else
  skip_live "cargo not available — skipped auto_rebuild unit path"
fi

log "PASS — kind smoke complete"
