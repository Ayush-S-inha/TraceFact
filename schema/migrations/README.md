# SQLite migrations

TraceFact tracks the local database version with SQLite `PRAGMA user_version`.

- Migration files are ordered and immutable once released.
- Each migration and its `user_version` update run in one transaction.
- Add future migrations as `0002_...sql`, `0003_...sql`, and so on.
- `schema/tracefact.sql` documents the current consolidated schema.
- Migration 1 also upgrades databases created before run lifecycle status was added.
- A database created by a newer TraceFact build is rejected instead of silently opened with an older schema.
