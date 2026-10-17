-- 008 CMK envelope encryption (slice 1).

CREATE TABLE IF NOT EXISTS tenant_keys (
    tenant          TEXT PRIMARY KEY,
    provider        TEXT NOT NULL,
    current_key_id  TEXT NOT NULL,
    spec            JSONB NOT NULL DEFAULT '{}',
    rotated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS wrapped_deks (
    digest          TEXT NOT NULL,
    tenant          TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    algorithm       TEXT NOT NULL,
    nonce           BYTEA NOT NULL,
    ciphertext      BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rewrapped_at    TIMESTAMPTZ,
    PRIMARY KEY (tenant, digest)
);
CREATE INDEX IF NOT EXISTS wrapped_deks_tenant_keyid_idx
    ON wrapped_deks (tenant, key_id);

CREATE TABLE IF NOT EXISTS rewrap_jobs (
    id              UUID PRIMARY KEY,
    tenant          TEXT NOT NULL,
    from_key_id     TEXT NOT NULL,
    to_key_id       TEXT NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    deks_total      INT NOT NULL DEFAULT 0,
    deks_done       INT NOT NULL DEFAULT 0,
    state           TEXT NOT NULL DEFAULT 'pending'
);
