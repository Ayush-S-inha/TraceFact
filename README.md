# TraceFact

> See what your software actually does.

TraceFact watches an application while it runs and builds a local record of its behavior. The project is being built so that behavior can be compared with earlier runs and unexpected changes can be investigated.

## The idea

```text
WHAT YOU EXPECTED
       |
WHAT ACTUALLY HAPPENED
       |
WHAT CHANGED
       |
WHY IT MATTERS
       |
PROOF
```

## Current state

The Windows process collector is working in two modes.

`tracefact process <pid>` takes a point in time snapshot of a selected process tree, builds a Runtime Passport, and saves the result to local SQLite storage.

`tracefact watch <pid>` keeps the selected process tree under observation. It records process start and exit events as they happen, saves them to SQLite, and finishes the run with an updated Runtime Passport.

The process observer records process IDs, parent process IDs, process names, thread counts, and the position of each process in the selected tree. It does not collect command lines. Its WMI event queue holds up to 4,096 lifecycle events; overflow and events left queued at shutdown appear in a process-watch summary. Process-set comparison is skipped when the summary reports loss or when an older run has no summary.

The watch command also includes an experimental Windows TCP observer. It records connection metadata for processes in the selected tree, including endpoint addresses and ports. It does not store network payloads. The network observer requires an Administrator PowerShell and is still being validated on Windows systems.

Filesystem observation, runtime dependency tracking, comparison, security checks, and the interface are separate stages of the project.

## Try it

Build the project with Cargo, then give TraceFact the PID of a running Windows process. The commands below are examples, not one script to paste all at once. For a comparison, use a baseline and a later run of the same application captured in the same observation mode.

```text
tracefact process <pid>
tracefact watch <pid>
tracefact history
tracefact inspect latest
tracefact export latest tracefact-evidence.json
tracefact baseline save "desktop stable" <completed_run_id>
tracefact baseline list
tracefact baseline inspect "desktop stable"
tracefact baseline export "desktop stable" desktop-baseline.json
tracefact compare "desktop stable" <later_completed_run_id>
tracefact compare "desktop stable" <later_completed_run_id> comparison.json
```

Named Runtime Passport baselines can be saved from completed runs. Baselines retain their source run, observation scope, and coverage limitations. Names are unique without regard to case; saving an existing name fails rather than replacing it. `tracefact compare <baseline_name> <run_id|latest>` compares a completed run against a baseline. Findings link to stored event IDs where possible; add a JSON path to export the report. For a meaningful comparison, capture the baseline and the later run using the same observation mode for the same application. Comparing a snapshot to a watch run produces a scope mismatch, so behavior-set findings are skipped. `latest` selects the latest completed run, which may still be the baseline's source run if you have not recorded another run. The first comparison pass covers process names and network targets when both runs have suitable provenance. Files and libraries are skipped until those collectors exist. A `not_observed` finding does not prove behavior stopped.

The process command saves a point in time observation. The watch command keeps listening until the root process exits or you stop the run with Ctrl+C. The export command writes a standalone JSON evidence bundle for a finalized run. It refuses to overwrite an existing path. History lists saved runs and their lifecycle status (`running`, `completed`, `interrupted`, or `failed`). Inspect shows the stored events, final status, and Runtime Passport. A run stopped with Ctrl+C is marked interrupted; a run whose root process exits normally is completed; an observer or persistence error is reported as failed when the final state can be written.

The Windows process watcher and TCP observer should be run from an Administrator PowerShell. Windows can reject WMI event subscriptions or kernel network tracing when the process lacks the required permissions. A network tracing session can also fail if another kernel tracing session is already active.

## Privacy

TraceFact is designed to keep its data on the user's machine. It does not need an account, cloud service, API key, or telemetry. Raw payloads are off by default. The default scope is a process or application selected by the user, not the whole computer.

Sensitive values should be filtered at collection time rather than being saved and cleaned up later. An exported evidence file can include process IDs, executable names, and network endpoints; review it before sharing. Missing events are not evidence that a behavior did not occur.

## SQLite storage limits

TraceFact applies two configurable safeguards to its local SQLite database:

* It retains up to 500 runs by default. When a new run is saved, the oldest eligible runs are deleted with their events and Passports.
* SQLite limits the main database file to 1 GiB by default. The page limit does not cap rollback-journal, WAL, or shared-memory sidecar files; `tracefact doctor` includes existing sidecars in its disk-usage figure.

These are starting defaults, not workload guarantees. Measure a representative observation period with `tracefact doctor` and adjust the limits to match the applications and event rates you actually monitor.

Retention never deletes an active run, a run referenced by a named baseline, the latest run, or the latest completed run. Cleanup runs in a transaction and may remove eligible completed history while another run is active; it never deletes that active run. Run reads load the run, Passport, and events within one read transaction. Connections wait up to five seconds after an `SQLITE_BUSY` result before returning a lock error; if a cleanup still cannot commit, its transaction rolls back rather than leaving a partial deletion. If protected runs alone exceed the configured run target, TraceFact keeps them all and reports the actual count in `tracefact doctor`. Saved baselines are never removed by automatic retention. Save a named baseline for any completed run that must remain available as a comparison source.

Configure the limits with environment variables before starting TraceFact:

* `TRACEFACT_MAX_RUNS` changes the retained-run target. Set it to `0` to disable automatic run cleanup.
* `TRACEFACT_MAX_DATABASE_MB` changes the SQLite page limit in MiB. Set it to `0` to disable the page limit.

`tracefact doctor` reports total database and sidecar usage, the effective main-database page limit, the retained-run target, protected-run count, and emergency reserve size. If an existing database already exceeds a newly configured limit, SQLite cannot lower the effective cap below its current page count. Deleting old runs frees pages for reuse; it does not shrink the database file automatically.

When SQLite returns `SQLITE_FULL`, TraceFact releases its 1 MiB emergency reserve, removes eligible unpinned history one complete run per transaction, and retries the failed write once. Per-run transactions bound cleanup journal work and prevent a failed delete from leaving a partially removed run. Emergency cleanup can remove history even when the run count is below its normal target, but it never removes active runs, baseline sources, the latest run, or the latest completed run. Set `TRACEFACT_MAX_RUNS=0` to disable both normal and emergency automatic cleanup. The `SQLITE_FULL` error can mean either that the filesystem is full or that the configured SQLite page limit has been reached; releasing the reserve does not override that page limit. If a run's final Passport still cannot be stored, TraceFact makes a final attempt to mark the run `failed` without replacing its previous Passport. If the database cannot accept even that update, the run may remain `running` and needs manual recovery.

## Resource use

TraceFact is meant to stay running without getting in the way. The collectors use bounded queues and inventories, and SQLite now has configurable retention and a page limit.

The starting targets are roughly:

* less than 30 to 50 MB RAM while idle
* less than 1 to 2 percent CPU during normal observation

These numbers are targets. We will measure them on real workloads and adjust the implementation where needed.

## Project layout

```text
src/
  analysis/
  collectors/
  model/
  storage/
web/
schema/
docs/
examples/
demo/
```

## License

TraceFact is released under the Apache License 2.0. See `LICENSE` and `NOTICE`.
