-- 001 image signing (specton-signing B3) — signature metadata + verification policies.

CREATE TABLE IF NOT EXISTS signatures (
    id               UUID PRIMARY KEY,
    subject_digest   TEXT NOT NULL,
    tenant           TEXT NOT NULL,
    project          TEXT NOT NULL,
    repository       TEXT NOT NULL,
    signature_digest TEXT NOT NULL,
    signer_identity  TEXT,
    signature_type   TEXT NOT NULL,
    media_type       TEXT,
    size_bytes       BIGINT NOT NULL DEFAULT 0,
    rekor_log_index  BIGINT,
    signed_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (subject_digest, signature_digest)
);
CREATE INDEX IF NOT EXISTS signatures_subject_idx
    ON signatures (subject_digest);
CREATE INDEX IF NOT EXISTS signatures_tenant_repo_idx
    ON signatures (tenant, project, repository);
CREATE INDEX IF NOT EXISTS signatures_signed_at_idx
    ON signatures (signed_at DESC);

CREATE TABLE IF NOT EXISTS verification_policies (
    id            UUID PRIMARY KEY,
    name          TEXT NOT NULL,
    tenant        TEXT NOT NULL,
    spec          JSONB NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    on_violation  TEXT NOT NULL DEFAULT 'block',
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant, name)
);
CREATE INDEX IF NOT EXISTS verification_policies_tenant_idx
    ON verification_policies (tenant) WHERE enabled;
