-- 002 Pull-time admission gate.

CREATE TABLE IF NOT EXISTS admission_policies (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    tenant      TEXT NOT NULL,
    spec        JSONB NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant, name)
);

CREATE TABLE IF NOT EXISTS admission_decisions (
    id          BIGSERIAL PRIMARY KEY,
    decided_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    digest      TEXT NOT NULL,
    policy_id   UUID REFERENCES admission_policies(id) ON DELETE SET NULL,
    verdict     TEXT NOT NULL,                    -- 'allow' | 'warn' | 'block'
    reason      TEXT,
    subject     TEXT NOT NULL,
    request_id  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS admission_decisions_digest_time_idx
    ON admission_decisions (digest, decided_at DESC);
