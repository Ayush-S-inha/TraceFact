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

* run metadata
* process observation events
* event metadata
* the generated Runtime Passport

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

The storage module includes round trip tests using an in memory SQLite database. The tests verify that a run, event, and Passport can be saved and read through the storage layer, that a stored run can be inspected, and that the history limit is applied.
