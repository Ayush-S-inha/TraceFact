-- TraceFact database schema migration 1.
-- Existing runs tables are upgraded by migrate_run_status() in Rust.
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
