# SQLite migrations

TraceFact tracks the local database version with SQLite `PRAGMA user_version`. The current schema version is 2.

- Migration files are ordered and immutable once released.
- Each migration and its `user_version` update run in one transaction.
- Add future migrations as `0003_...sql`, `0004_...sql`, and so on.
- `schema/tracefact.sql` documents the current consolidated schema.
- Migration 1 also upgrades databases created before run lifecycle status was added.
- Migration 2 adds named Runtime Passport baselines and retains a reference to their source run.
- A database created by a newer TraceFact build is rejected instead of silently opened with an older schema.
