-- 005 Append-only hash-chained registry audit log (specton-audit).
-- Named registry_audit_* to avoid colliding with the scanner's
-- simpler `audit_log` table from 0001_init.sql.

CREATE TABLE IF NOT EXISTS registry_audit_keys (
    key_id      TEXT PRIMARY KEY,
    -- Application holds the secret material; we only track which
    -- key id is active so verify_chain can select the right key.
    active      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS registry_audit_log (
    id            BIGSERIAL PRIMARY KEY,
    at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant        TEXT,
    category      TEXT NOT NULL,
    action        TEXT NOT NULL,
    actor_sub     TEXT NOT NULL,
    actor_ip      TEXT,
    actor_ua      TEXT,
    subject       JSONB,
    outcome       TEXT NOT NULL,              -- 'success' | 'failure'
    error_code    TEXT,
    attributes    JSONB NOT NULL DEFAULT '{}',
    prev_hash     BYTEA,                      -- 32 bytes; NULL for genesis
    row_hash      BYTEA NOT NULL,             -- 32 bytes
    hmac_key_id   TEXT NOT NULL REFERENCES registry_audit_keys(key_id)
);

CREATE INDEX IF NOT EXISTS registry_audit_log_at_idx
    ON registry_audit_log (at DESC);
CREATE INDEX IF NOT EXISTS registry_audit_log_tenant_at_idx
    ON registry_audit_log (tenant, at DESC);
CREATE INDEX IF NOT EXISTS registry_audit_log_actor_at_idx
    ON registry_audit_log (actor_sub, at DESC);
CREATE INDEX IF NOT EXISTS registry_audit_log_subject_idx
    ON registry_audit_log USING GIN (subject jsonb_path_ops);
CREATE INDEX IF NOT EXISTS registry_audit_log_category_idx
    ON registry_audit_log (category, at DESC);

CREATE TABLE IF NOT EXISTS registry_audit_checkpoints (
    id           BIGSERIAL PRIMARY KEY,
    range_from   BIGINT NOT NULL REFERENCES registry_audit_log(id),
    range_to     BIGINT NOT NULL REFERENCES registry_audit_log(id),
    merkle_root  BYTEA NOT NULL,
    exported_to  TEXT,
    at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tamper-evidence at the DB role level. Superuser still can; app roles
-- must not UPDATE/DELETE chained rows.
REVOKE UPDATE, DELETE ON registry_audit_log FROM PUBLIC;
