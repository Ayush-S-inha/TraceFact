# TraceFact

> See what your software actually does.

TraceFact watches an application while it runs and builds a local record of its behavior. The project is being built so that behavior can be compared with earlier runs and unexpected changes can be investigated.

## The idea

```text
WHAT YOU EXPECTED
       ↓
WHAT ACTUALLY HAPPENED
       ↓
WHAT CHANGED
       ↓
WHY IT MATTERS
       ↓
PROOF
```

## Current state

The Windows process collector is working in two modes.

`tracefact process <pid>` takes a point in time snapshot of a selected process tree, builds a Runtime Passport, and saves the result to local SQLite storage.

`tracefact watch <pid>` keeps the selected process tree under observation. It records process start and exit events as they happen, saves them to SQLite, and finishes the run with an updated Runtime Passport.

The process observer records process IDs, parent process IDs, process names, thread counts, and the position of each process in the selected tree. It does not collect command lines.

Network, filesystem, runtime dependency, comparison, security, and interface work will be added separately.

## Try it

Build the project with Cargo, then give TraceFact the PID of a running Windows process.

```text
tracefact process <pid>
tracefact watch <pid>
tracefact history
tracefact inspect latest
```

The process command saves a point in time observation. The watch command keeps listening until the root process exits or you stop the run with Ctrl+C. History lists saved runs, and inspect shows the stored events and Runtime Passport.

The current Windows event watcher should be run from an Administrator PowerShell. Without the required WMI permissions, Windows can reject the event subscription.

## Privacy

TraceFact is designed to keep its data on the user's machine. It does not need an account, cloud service, API key, or telemetry. Raw payloads are off by default. The default scope is a process or application selected by the user, not the whole computer.

Sensitive values should be filtered at collection time rather than being saved and cleaned up later.

## Resource use

TraceFact is meant to stay running without getting in the way. The collector design is event driven and storage is bounded.

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
