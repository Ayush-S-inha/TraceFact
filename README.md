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

The watch command also includes an experimental Windows TCP observer. It records connection metadata for processes in the selected tree, including endpoint addresses and ports. It does not store network payloads. The network observer requires an Administrator PowerShell and is still being validated on Windows systems.

Filesystem observation, runtime dependency tracking, comparison, security checks, and the interface are separate stages of the project.

## Try it

Build the project with Cargo, then give TraceFact the PID of a running Windows process.

```text
tracefact process <pid>
tracefact watch <pid>
tracefact history
tracefact inspect latest
```

The process command saves a point in time observation. The watch command keeps listening until the root process exits or you stop the run with Ctrl+C. History lists saved runs and their lifecycle status (`running`, `completed`, `interrupted`, or `failed`). Inspect shows the stored events, final status, and Runtime Passport. A run stopped with Ctrl+C is marked interrupted; a run whose root process exits normally is completed; an observer or persistence error is reported as failed when the final state can be written.

The Windows process watcher and TCP observer should be run from an Administrator PowerShell. Windows can reject WMI event subscriptions or kernel network tracing when the process lacks the required permissions. A network tracing session can also fail if another kernel tracing session is already active.

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
