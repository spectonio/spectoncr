-- 006 Atomic promotion API (C1).

CREATE TABLE IF NOT EXISTS promotions (
    id                UUID PRIMARY KEY,
    started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at       TIMESTAMPTZ,
    actor             TEXT NOT NULL,
    src_tenant        TEXT NOT NULL,
    src_project       TEXT NOT NULL,
    src_repository    TEXT NOT NULL,
    src_reference     TEXT NOT NULL,
    src_digest        TEXT NOT NULL,
    dst_tenant        TEXT NOT NULL,
    dst_project       TEXT NOT NULL,
    dst_repository    TEXT NOT NULL,
    dst_reference     TEXT NOT NULL,
    state             TEXT NOT NULL,                 -- 'pending' | 'copying' | 'done' | 'failed' | 'dry_run'
    error             TEXT,
    bytes_copied      BIGINT NOT NULL DEFAULT 0,
    blob_count        INT NOT NULL DEFAULT 0,
    signatures_copied INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS promotions_dst_idx
    ON promotions (dst_tenant, dst_project, dst_repository, started_at DESC);
CREATE INDEX IF NOT EXISTS promotions_src_idx
    ON promotions (src_digest);
