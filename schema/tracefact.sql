PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    application TEXT NOT NULL,
    started_at_ms INTEGER NOT NULL,
    ended_at_ms INTEGER,
    schema_version TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'completed'
        CHECK (status IN ('running', 'completed', 'interrupted', 'failed'))
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    timestamp_ms INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    pid INTEGER,
    executable TEXT,
    subject TEXT,
    target TEXT,
    metadata_json TEXT NOT NULL,
    source TEXT NOT NULL,
    sensitivity TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_run_time
ON events(run_id, timestamp_ms);

CREATE INDEX IF NOT EXISTS idx_events_type
ON events(event_type);

CREATE TABLE IF NOT EXISTS passports (
    passport_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    generated_at_ms INTEGER NOT NULL,
    passport_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT PRIMARY KEY,
    application TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    policy_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baselines (
    name TEXT PRIMARY KEY COLLATE NOCASE
        CHECK (length(trim(name)) BETWEEN 1 AND 120),
    name_key TEXT NOT NULL UNIQUE,
    created_at_ms INTEGER NOT NULL,
    application TEXT NOT NULL,
    source_run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE RESTRICT,
    baseline_schema_version TEXT NOT NULL,
    passport_json TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    coverage_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_baselines_created
ON baselines(created_at_ms DESC, name);

CREATE INDEX IF NOT EXISTS idx_baselines_source_run
ON baselines(source_run_id);
