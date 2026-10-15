# Phase A–D: Build Lifecycle + AI Agent — PR / Slice Plan

**Primary goal:** An operator (or Cursor/Claude via MCP) can ask SpectonCR to
detect vulnerable images, trigger CI rebuilds, promote only green+signed
artifacts to prod, and prove every step in a tamper-evident audit trail —
without SpectonCR becoming a build farm.

**How we get there:** Ship the substrate first (audit + signing), then the
rebuild/promote loop, then the agent surface that drives it.

Each slice = one PR. Kill-switch OFF by default. Design docs are source of
truth; this file is the execution order and PR checklist.

**Naming note:** Scanner already owns table `audit_log` (`0001_init.sql`).
Design 005's chained registry log lands as `registry_audit_log` (+
`registry_audit_checkpoints`, `registry_audit_keys`) in migration
`0017_registry_audit.sql`.

---

## Dependency order (do not reorder)

```
A1 → A2 → A3 ─┐
              ├─→ C* (admission audits; promote audits)
B1 → B2 → B3 → B4 ─┘
R2 → R3  (rebuild; R1 lineage already landed)
P* completes after A2 + R2 + promote slice 1
```

`R1` / partial `P1` already exist in-tree; finish rather than restart.

---

## Phase A — Durable audit (design 005)  ~3 PRs

**How this serves the primary goal:** Every rebuild, promote, and agent
mutation needs a restart-safe, verifiable record before we allow the agent
to change state.

### PR A1 — `feat(audit): specton-audit crate + chained schema` ✅ landed locally
- **Docs:** `docs/design/005-audit-log.md` §§b,e,g,h,i slice 1
- **Copy patterns from:** `crates/specton-cost` (trait + Pg + Noop),
  `crates/specton-gc` (crate header / kill-switch style)
- **Deliver:**
  - Workspace crate `specton-audit`
  - Migration `0017_registry_audit.sql`
  - `AuditSink` trait: `append`, `query`, `verify_chain`
  - `InMemoryAudit` (default / tests)
  - `PgChainedAudit` (HMAC hash chain)
  - Unit tests: append order, tamper detect (memory); optional sqlx if CI has PG
- **Verify:** `cargo test -p specton-audit`; chain breaks on mutated row
- **Anti-patterns:** Do not overwrite scanner `audit_log`; do not call
  `UPDATE`/`DELETE` on chained rows from app code

### PR A2 — `feat(audit): wire registry + auth + HTTP query routes` ✅ landed locally (auth call sites deferred / registry done)
- **Docs:** 005 §§b,d,g,i slice 2
- **Deliver:**
  - `[audit]` config: `backend = "memory"|"postgres"`, `sample_pulls`, HMAC key ref
  - Shim `RegistryAuditLog` → `AuditSink` (compat for one minor)
  - Replace `state.audit_log.record(...)` call sites
  - Routes: `GET /v2/_audit`, `GET /v2/_audit/{id}`, `POST /v2/_audit/verify`
  - Rewire dashboard `/api/audit`
  - Fail closed (503) on write ops when postgres backend and PG down
- **Verify:** push image → row in `registry_audit_log`; verify endpoint OK
- **Anti-patterns:** Silent drop of push/delete audit events

### PR A3 — `feat(audit): S3 export + Merkle checkpoint + CLI` ✅ landed locally
- **Docs:** 005 §§b,d,e,i slice 3
- **Deliver:** export job, `POST /v2/_audit/export`, key rotation event,
  `spectoncr audit query|verify|export` (or module stubs if CLI binary absent)
- **Verify:** export JSONL + checkpoint; rotate key mid-stream still verifies
- **Done when:** design status → `in-progress`/`shipped` for 005

---

## Phase A′ / B — Image signing (design 001)  ~4 PRs

**How this serves the primary goal:** Promotion and admission require
signatures; rebuilds must be able to re-attach or verify cosign artifacts.

### PR B1 — `feat(signing): specton-signing traits + keyed in-memory signer`
- **Docs:** `001-image-signing.md` §§b,h,i slice 1
- **Deliver:** crate, `Signer`/`Verifier`, in-memory PEM keyed impl, vector tests
- **Verify:** sign digest → verify OK; wrong key fails

### PR B2 — `feat(signing): sigstore-rs + Vault key provider + CLI sign`
- **Docs:** 001 §§b,g,i slice 2
- **Deliver:** `SigstoreSigner`, Vault Transit / file PEM `KeyProvider`,
  `spectoncr sign` (or registry admin route if CLI deferred)
- **Verify:** round-trip with fixed PEM; Vault optional behind feature

### PR B3 — `feat(signing): store cosign .sig artifacts + referrers + audit`
- **Docs:** 001 §§b,d,e,i slice 3 — **depends on A2**
- **Deliver:** tag `sha256-<hex>.sig`, signatures table if needed,
  `POST/GET .../signatures/{digest}`, audit category `Sign`
- **Verify:** push → sign → referrers lists sig; audit row present

### PR B4 — `feat(signing): ImageVerificationPolicy + verify-on-pull`
- **Docs:** 001 §§c,f,g,i slice 4
- **Deliver:** CRD + reconciler, middleware on `get_manifest`, Helm
  `[signing] enabled=false`
- **Verify:** unsigned pull blocked when policy requires; warn mode audits only

---

## Phase B″ — Auto-rebuild (design 018)  ~2 PRs (R1 done)

**How this serves the primary goal:** Registry detects base CVE fix and
tells CI to rebuild — SpectonCR stays the trigger, not the builder.

### Already landed (do not redo)
- `specton-rebuild`: lineage extractor, emitters stubs, rate_limit
- Migration `0013_auto_rebuild.sql`

### PR R2 — `feat(rebuild): subscriptions + GitHub dispatch + trigger API`
- **Docs:** `018-auto-rebuild.md` §§b,c,d,i slice 2
- **Deliver:** `RebuildSubscription` CRD/reconciler, GitHub
  `repository_dispatch` emitter, rate limit enforce, `POST /v2/_rebuild/trigger`,
  lineage write on push
- **Verify:** mock GH API receives dispatch once per day bucket

### PR R3 — `feat(rebuild): GitLab + Tekton + webhook emitters + e2e`
- **Docs:** 018 slice 3
- **Deliver:** remaining emitters, CLI/MCP tools, e2e script, docs recipes
- **Verify:** patch base fixture → downstream event

---

## Phase C — Promote + admission (006 + 002)  ~6 PRs

**How this serves the primary goal:** Staging → prod without digest loss;
pulls blocked unless policy (scan + signature) passes.

### Promotion (006)
| PR | Title | Depends |
|----|-------|---------|
| C1 | Same-backend retag `_promote` + schema + CLI | A2 |
| C2 | Cross-backend copy + copy signatures | B3, C1 |
| C3 | `OnPolicyPass` + history + dashboard | C2, admission slice 1 |

### Admission (002)
| PR | Title | Depends |
|----|-------|---------|
| D1 | Evaluator + Redis cache + block/allow on pull | scanner results |
| D2 | `AdmissionPolicy` CRD + scan-on-unknown | D1 |
| D3 | Bypass permission + `_admit/test` + audit | A2, D2; B4 for signatureRequired |

(Rename PRs in GitHub as `feat(promote):…` / `feat(admission):…` — letters
here are phase-local.)

---

## Phase D — AI agent build orchestration (019)  ~4 PRs (partial P1)

**How this serves the primary goal:** Natural language / MCP drives
inspect → rebuild → promote with RBAC, dry-run, and audit.

### Already landed (partial)
- `specton-pilot`: Tool trait, registry, LLM clients, chat loop, PingTool
- Migration `0014_pilot.sql`
- **Gap:** lib.rs claims 4 read-only tools; only `PingTool` exists

### PR P1b — `feat(pilot): read-only tools (list/inspect/audit/findings)`
- Wire real tools against catalog/scan/audit sinks
- **Depends on:** A2 for real `query_audit`

### PR P2 — `feat(pilot): mutating tools + dry-run + approval`
- `trigger_scan`, `suppress_finding`, `trigger_rebuild`, `promote_tag`,
  `run_gc_reconcile`, destructive deletes with confirm phrase
- **Depends on:** R2, C1, A2

### PR P3 — `feat(pilot): MCP server specton-mcp + CLI REPL`
- Each Tool → MCP tool; `spectoncr pilot --once "…"`
- Cursor/Claude Code can drive rebuild+promote

### PR P4 — `feat(pilot): spend caps + audit integration + dashboard chat hook`
- Token budget, every tool invoke → `registry_audit_log`, UI sidebar stub for 007

---

## Suggested weekly cadence

| Week | PRs |
|------|-----|
| 1 | **A1**, A2 start |
| 2 | A2, A3 |
| 3 | B1, B2 |
| 4 | B3, R2 |
| 5 | B4, R3 |
| 6 | C1, D1 (admission) |
| 7 | C2, D2 |
| 8 | C3, D3 |
| 9 | P1b, P2 |
| 10 | P3, P4 |

~21 PRs total; parallelize B with R after A2; never start P2 before A2+C1+R2.

---

## Definition of done (Phase A–D)

An operator can:

1. Enable `[audit] backend = "postgres"` and verify chain after pushes
2. Sign images; refuse unsigned pulls under policy
3. On base CVE fix, receive GitHub `repository_dispatch` for descendants
4. `POST /v2/_promote` staging → prod copying signatures
5. Via MCP: *"rebuild everything on python:3.12-slim with criticals, then promote if scan pass"* — agent uses tools only, all audited

---

## Explicitly not in this plan

- ACR Tasks / in-registry BuildKit · npm/Maven/PyPI · Connected edge registry
- Design 003/004/007/008/009–017 except where promote/admission already depend
- Force-completing incubating GC/lazy/peer unless a slice needs them
