-- TraceFact database schema migration 2: named Runtime Passport baselines.
-- Baselines retain the source run reference and the scope/coverage that qualified it.

CREATE TABLE baselines (
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

CREATE INDEX idx_baselines_created
ON baselines(created_at_ms DESC, name);

CREATE INDEX idx_baselines_source_run
ON baselines(source_run_id);
