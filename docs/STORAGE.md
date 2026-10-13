# Local Storage

TraceFact keeps runtime observations on the same computer where they were collected.

The storage layer uses SQLite. A process run is saved as one record with its Runtime Events and Runtime Passport.

On Windows the default database is stored under the user's local application data directory:

```text
%LOCALAPPDATA%\TraceFact\tracefact.db
```

TraceFact does not send the database to a TraceFact server.

## Saved data

A saved run contains:

* run metadata, including `running`, `completed`, `interrupted`, or `failed` status
* process observation events
* event metadata
* the generated Runtime Passport

Watch startup and its bootstrap events are inserted in one SQLite transaction. Finalization updates the end timestamp, terminal status, and final Runtime Passport together. When opening an older database, TraceFact adds the status column and classifies records with no end timestamp as interrupted rather than treating them as clean completions.

The current Windows process collector does not collect command lines or file contents.

## CLI

After running a process observation, use:

```text
tracefact history
```

to list recent saved runs.

Use:

```text
tracefact inspect <run_id>
```

to read one saved run. The command shows the stored events and the Runtime Passport linked to that run.

The history and inspect commands read the local database only. If the database does not exist yet, TraceFact creates an empty local database so the command can report that there are no saved runs.

## Testing

The storage module includes round trip tests using an in memory SQLite database. The tests verify the run lifecycle, atomic bootstrap persistence and rollback, legacy status migration, terminal status recording, run inspection, and history listing.
