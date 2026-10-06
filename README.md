# TraceFact

> See what your software actually does.

TraceFact watches an application while it is running and builds a local record of its behavior. It can then compare that behavior with an earlier run so a developer can see what changed and what needs a closer look.

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

## First release

The first version is built around a few things:

* process and process tree observation
* network destinations and ports
* filesystem paths
* runtime and library observations
* Runtime Passports
* comparison between a baseline and a new run
* basic security checks backed by observed evidence
* a local web interface and CLI
* SQLite storage
* reports and passport exports
* a small built in demo

HTTP inspection, deeper Linux eBPF collection, and optional AI come later.

## Privacy

TraceFact is designed to keep its data on the user's machine. It does not need an account, cloud service, API key, or telemetry. Raw payloads are off by default. The default scope is a process or application selected by the user, not the whole computer.

Sensitive values should be filtered at collection time rather than being saved and cleaned up later.

## Resource use

TraceFact is meant to stay running without getting in the way. The collector design is event driven and storage is bounded.

The starting targets are roughly:

* less than 30 to 50 MB RAM while idle
* less than 1 to 2 percent CPU during normal observation

These numbers are targets. We will measure them on real workloads and adjust the implementation where needed.

## Current state

This repository is the foundation. It contains the data model, SQLite schema, collector interface, analysis scaffolding, demo data, and the first UI shell.

The next step is the real Windows process collector.

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
