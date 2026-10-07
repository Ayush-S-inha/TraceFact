# TraceFact

> See what your software actually does.

TraceFact watches an application while it is running and builds a local record of its behavior. The project is being built so that behavior can be compared with earlier runs and unexpected changes can be investigated.

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

The foundation is in place.

TraceFact currently has a Windows process collector that can inspect a selected process tree, build a Runtime Passport, and save the observation to local SQLite storage. The command line interface can list saved runs and inspect them later.

The collector records process IDs, parent process IDs, process names, thread counts, and the position of each process in the selected tree. It does not collect command lines.

The next collectors and analysis features will be added as separate parts of the project.

## Try it

Build the project with Cargo, then give TraceFact the PID of a running Windows process.

```text
tracefact process <pid>
tracefact history
tracefact inspect latest
```

The process command saves the observation locally. The history command lists saved runs, and the inspect command shows the stored event data and Runtime Passport for one run.

## Planned

The next parts of the project are:

* network observation
* filesystem observation
* runtime dependency observations
* comparison between runs
* basic security checks
* local web interface
* reports and passport exports
* deeper Linux collection
* optional AI explanations

These features are not all implemented yet.

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
