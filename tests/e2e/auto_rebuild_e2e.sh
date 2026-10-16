#!/usr/bin/env bash
# Auto-rebuild emitter smoke (design 018 R3).
#
# Starts a tiny Python HTTP mock that accepts GitHub/GitLab/webhook/Tekton
# shaped POSTs, then runs `cargo test -p specton-rebuild` emitter mocks.
# Optional live path: if REGISTRY_URL is set and rebuild is enabled, upserts
# a webhook subscription and fires /v2/_rebuild/trigger against the mock.
#
# Run from repo root:
#   bash tests/e2e/auto_rebuild_e2e.sh

set -euo pipefail

log()  { printf "[rebuild-e2e] %s\n" "$*"; }
fail() { printf "[rebuild-e2e][FAIL] %s\n" "$*" >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

log "unit/integration: specton-rebuild emitters"
cargo test -p specton-rebuild --quiet -- --test-threads=4 \
  || fail "specton-rebuild tests failed"

if [[ -z "${REGISTRY_URL:-}" ]]; then
  log "REGISTRY_URL unset — skipping live trigger path (unit tests passed)"
  exit 0
fi

if ! command -v python3 >/dev/null; then
  log "python3 missing — skipping live path"
  exit 0
fi

MOCK_PORT="${MOCK_PORT:-18765}"
HIT_FILE="$(mktemp)"
trap 'rm -f "$HIT_FILE"; kill ${MOCK_PID:-} 2>/dev/null || true' EXIT

python3 - "$MOCK_PORT" "$HIT_FILE" <<'PY' &
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[1])
hit_file = sys.argv[2]

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        with open(hit_file, "a") as f:
            f.write(f"{self.path}|{self.headers.get('X-SpectonCR-Signature','')}|{len(body)}\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", port), H).serve_forever()
PY
MOCK_PID=$!
sleep 0.4

TENANT="${TENANT:-acme}"
SUB="${SUB:-e2e-webhook}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
MOCK_URL="http://127.0.0.1:${MOCK_PORT}/hooks/rebuild"

log "upserting webhook subscription via registry"
TOKEN=$(curl -fsS -u "$ADMIN_USER:$ADMIN_PASS" \
  "$REGISTRY_URL/auth/token?service=spectoncr-registry&scope=repository:${TENANT}/*:pull,push" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")

curl -fsS -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "$REGISTRY_URL/v2/_rebuild/subscriptions/$TENANT/$SUB" \
  -d "$(python3 - <<PY
import json
print(json.dumps({
  "enabled": True,
  "spec": {
    "watch": {"bases": ["alpine:3.20"], "descendants": ["$TENANT/*"]},
    "triggers": {"on_cve_fix": True, "on_base_push": False, "min_severity_fixed": "high"},
    "emitter": {"type": "webhook", "url": "$MOCK_URL", "hmac_secret": "e2e-secret"},
    "rate_limit": {"per_downstream_per_day": 10}
  }
}))
PY
)" >/dev/null || fail "subscription upsert failed (is rebuild.enabled=true?)"

log "firing trigger"
curl -fsS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "$REGISTRY_URL/v2/_rebuild/trigger" \
  -d "{\"tenant\":\"$TENANT\",\"subscription\":\"$SUB\",\"upstream\":\"alpine:3.20\",\"downstream\":\"$TENANT/prod/api:latest\",\"reason\":\"manual\"}" \
  >/dev/null || fail "trigger failed"

sleep 0.3
[[ -s "$HIT_FILE" ]] || fail "mock received no POST"
grep -q "/hooks/rebuild" "$HIT_FILE" || fail "unexpected mock hit: $(cat "$HIT_FILE")"
log "live webhook path OK"
