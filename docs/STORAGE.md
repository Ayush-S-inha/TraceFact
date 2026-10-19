# Local Storage

TraceFact keeps runtime observations on the same computer where they were collected.

The storage layer uses SQLite. A saved run contains its Runtime Events and Runtime Passport. SQLite schema migrations are versioned with `PRAGMA user_version`; each migration and version update run in a transaction. Migration SQL lives under `schema/migrations/`. `schema/tracefact.sql` is the consolidated reference schema. Version 2 adds named Runtime Passport baselines.

## Database location

- Windows: `%LOCALAPPDATA%\TraceFact\tracefact.db`
- macOS: `~/Library/Application Support/TraceFact/tracefact.db`
- Linux: `$XDG_DATA_HOME/TraceFact/tracefact.db`, or `~/.local/share/TraceFact/tracefact.db` when `XDG_DATA_HOME` is unset.
- Windows uses a temporary-directory path if `LOCALAPPDATA` is unset. Linux falls back to a temporary-directory path if it cannot resolve the home directory. macOS requires the home directory to be available.

TraceFact does not send the database to a TraceFact server.

## Saved data

A saved run contains:

- run metadata, including `running`, `completed`, `interrupted`, or `failed` status
- process and network events currently supported by the collectors
- structured event metadata, source provenance, and sensitivity classification
- the generated Runtime Passport

Watch startup and its bootstrap events are inserted in one SQLite transaction. Finalization updates the end timestamp, terminal status, and final Runtime Passport together. Databases created by earlier TraceFact builds are upgraded through a versioned migration. Legacy records without an end timestamp are classified as interrupted rather than clean completions.

The current Windows process collector does not collect command lines or file contents. The network collector records connection metadata only, not packet payloads.

## CLI

Use:

```text
tracefact history
```

to list recent saved runs.

Use:

```text
tracefact inspect <run_id>
```

to inspect one run, including the stored events and Runtime Passport.

Use:

```text
tracefact export <run_id|latest> <path.json>
```

to write a standalone JSON evidence bundle. Exported bundles contain the run's status, observation scope, collector provenance, per-event structured metadata, Runtime Passport, and known coverage limitations. Export requires a finalized run and refuses to overwrite an existing output path.

Use the baseline commands to capture a named reference from a completed run:

```text
tracefact baseline save "desktop stable" latest
tracefact baseline list
tracefact baseline inspect "desktop stable"
tracefact baseline export "desktop stable" desktop-baseline.json
```

The word latest selects the most recent completed run for baseline creation. Baseline names are unique without regard to case, and an existing baseline is never silently replaced. Each baseline stores the source run ID, normalized Passport observations, inferred scope, collector counts, and known coverage limitations. The export does not copy all source events; use the source run ID to inspect or export the run's evidence separately. The baseline schema refers to the existing Runtime Passport schema.

The bundle format is defined by `schema/evidence_bundle.schema.json`, which references `schema/runtime_passport.schema.json`. It can be validated independently of TraceFact's UI or SQLite database using a JSON Schema Draft 2020-12 validator.

Exported evidence may include process IDs, executable names, and network endpoint addresses and ports. Review it before sharing. Raw application payloads are not collected.

The history, inspect, and export commands read the local database only. If the database does not exist yet, TraceFact creates an empty local database so the command can report that there are no saved runs.

## Testing

Storage tests cover versioned schema migrations, legacy run-status migration, run lifecycle persistence, atomic bootstrap writes and rollback, terminal status recording, named baseline round-tripping, duplicate-name rejection, and history. Evidence-bundle tests check provenance, coverage limitations, incomplete runs, and rejection of malformed event metadata.
