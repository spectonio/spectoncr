-- 004 GC retention + mark/sweep run bookkeeping (design 004).

CREATE TABLE IF NOT EXISTS gc_runs (
    id           UUID PRIMARY KEY,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at  TIMESTAMPTZ,
    phase        TEXT NOT NULL,
    blobs_marked BIGINT NOT NULL DEFAULT 0,
    blobs_swept  BIGINT NOT NULL DEFAULT 0,
    bytes_freed  BIGINT NOT NULL DEFAULT 0,
    error        TEXT,
    dry_run      BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE UNLOGGED TABLE IF NOT EXISTS gc_marks (
    run_id       UUID NOT NULL REFERENCES gc_runs(id) ON DELETE CASCADE,
    digest       TEXT NOT NULL,
    PRIMARY KEY (run_id, digest)
);

CREATE TABLE IF NOT EXISTS pending_uploads (
    upload_id     UUID PRIMARY KEY,
    tenant        TEXT NOT NULL,
    project       TEXT NOT NULL,
    repository    TEXT NOT NULL,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_chunk_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS pending_uploads_started_idx ON pending_uploads (started_at);

CREATE TABLE IF NOT EXISTS retention_runs (
    id           UUID PRIMARY KEY,
    tenant       TEXT NOT NULL,
    project      TEXT NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tags_kept    INT NOT NULL DEFAULT 0,
    tags_deleted INT NOT NULL DEFAULT 0,
    dry_run      BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS retention_policies (
    tenant              TEXT NOT NULL,
    project             TEXT NOT NULL,
    max_tag_count       INT,
    expire_days         INT,
    keep_regex          TEXT,
    always_keep         TEXT[] NOT NULL DEFAULT '{}',
    dry_run             BOOLEAN NOT NULL DEFAULT FALSE,
    respect_promotion   BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant, project)
);
