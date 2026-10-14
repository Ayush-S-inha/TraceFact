# Part 3 Notes: Versioned Storage and Evidence Export

## Changes

- Added SQLite schema version tracking through `PRAGMA user_version`.
- Added the version 1 migration and migration workflow documentation.
- Preserved the legacy run-status upgrade in the versioned migration transaction.
- Rejects databases whose schema version is newer than the current build supports.
- Added `tracefact export <run_id|latest> <path.json>`.
- Export requires a finalized run and refuses to overwrite an existing file.
- Evidence bundles include run metadata, inferred observation scope, event counts, collector provenance, structured event metadata, the Runtime Passport, and explicit coverage limitations.
- Added `schema/evidence_bundle.schema.json`.
- Updated the README, storage documentation, build plan, and release roadmap.

## Windows verification

The following checks were run on the Windows development machine:

- `cargo fmt` completed successfully.
- `cargo test` passed: 33 tests, 0 failures.
- `cargo check` completed successfully.
- `git diff --check` reported no errors.
- Exported a finalized saved run containing 7 events.
- Validated the exported JSON against `schema/evidence_bundle.schema.json`, including its Runtime Passport schema reference.
- Confirmed that exporting to an existing destination fails with a nonzero exit code without changing the original file.

The live export test used a saved Windows process-watch run. These checks do not constitute full production-release acceptance testing.

## Remaining limitations

- Filesystem access and loaded-library observation are not implemented.
- Named baseline management and deterministic behavior comparison remain unfinished.
- Observation scope is inferred from available collector provenance and event metadata.
- The absence of an event is not proof that the behavior did not occur.
- A live migration test against a copy of an existing pre-versioned on-disk database has not been separately verified.
- Exported evidence may contain process IDs, executable names, and network endpoint addresses and ports. Inspect evidence before sharing it.

TraceFact remains under active development and is not production-ready.
