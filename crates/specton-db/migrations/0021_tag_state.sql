-- 0021 Tag immutability + quarantine state machine (design 003).

CREATE TABLE IF NOT EXISTS tag_records (
    id            UUID PRIMARY KEY,
    tenant        TEXT NOT NULL,
    project       TEXT NOT NULL,
    repository    TEXT NOT NULL,
    tag           TEXT NOT NULL,
    digest        TEXT NOT NULL,
    state         TEXT NOT NULL,
    state_reason  TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant, project, repository, tag),
    CONSTRAINT tag_records_state_chk CHECK (
        state IN ('pending', 'scanning', 'approved', 'quarantined', 'promoted')
    )
);

CREATE INDEX IF NOT EXISTS tag_records_state_idx ON tag_records (state, updated_at);

CREATE TABLE IF NOT EXISTS tag_transitions (
    id            BIGSERIAL PRIMARY KEY,
    tag_record_id UUID NOT NULL REFERENCES tag_records(id) ON DELETE CASCADE,
    from_state    TEXT,
    to_state      TEXT NOT NULL,
    reason        TEXT,
    actor         TEXT NOT NULL,
    at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT tag_transitions_from_state_chk CHECK (
        from_state IS NULL
        OR from_state IN ('pending', 'scanning', 'approved', 'quarantined', 'promoted')
    ),
    CONSTRAINT tag_transitions_to_state_chk CHECK (
        to_state IN ('pending', 'scanning', 'approved', 'quarantined', 'promoted')
    )
);

CREATE INDEX IF NOT EXISTS tag_transitions_record_at_idx
    ON tag_transitions (tag_record_id, at);

CREATE TABLE IF NOT EXISTS project_settings (
    tenant              TEXT NOT NULL,
    project             TEXT NOT NULL,
    immutable_tags      BOOLEAN NOT NULL DEFAULT FALSE,
    quarantine_default  BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (tenant, project)
);
