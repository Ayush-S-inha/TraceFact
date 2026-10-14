# TraceFact Build Plan

## Main goal

TraceFact watches software while it runs and tells the developer what it actually did, what was unexpected, and why.

## Current state

The first Windows process collector is working. It can inspect a selected process tree, build a Runtime Passport, and save the observation to local SQLite storage.

Continuous Windows process observation is working. The watcher records process start and exit events for the selected process tree, persists them as they arrive, and finalizes the run with an updated Runtime Passport.

Windows TCP destination observation has been implemented as the next collector. An initial live test on Windows observed an outbound HTTPS connection and its disconnect event, but broader validation across process trees, IPv6, permissions, and failure conditions remains outstanding. The collector records TCP connection lifecycle metadata for the selected process tree without saving application payloads.

## Part 1 hardening checkpoint

The first hardening pass keeps diagnostic samples free of process IDs and endpoint values, retains terminal ETW stream errors even when the bounded message queue is full, and treats failed process-tree attribution as an explicit counted condition instead of immediately ending the watch. Windows build and live regression verification remain outstanding.

## Part 2 lifecycle checkpoint

Watch runs now have a persisted lifecycle status. Bootstrap events are inserted atomically with the run record, watch-loop errors are captured for shutdown, and the network observer is stopped before a final queue drain and passport update are attempted. Ctrl+C drains queued process events up to a fixed limit and reports when that limit is exceeded. The WMI process notification iterators still do not have a cooperative cancellation path in this checkpoint, so a clean cross-collector shutdown has not yet been fully verified.

The Part 3 implementation checkpoint adds SQLite schema versioning using `PRAGMA user_version`, an ordered migration directory, and a standalone JSON evidence export command. Exported evidence preserves run status, inferred observation scope, collector provenance, structured event metadata, and explicit coverage limitations. The evidence schema and cross-platform database locations are documented. Windows formatting, tests, export validation, and live regression checks still need to pass before this checkpoint is considered verified.

## Build order

1. Event schema
2. Rust core, SQLite, and localhost API
3. Windows process and process tree observer
4. Local persistence for collected runs
5. Continuous Windows process observation (working)
6. Network destination and port observer (initial live test passed; broader validation outstanding)
7. Filesystem observer
8. Runtime and library observer
9. Runtime Passport improvements
10. Baseline and current behavior comparison
11. Basic security checks with evidence
12. Local layered UI
13. Basic policy creation and verification
14. Exportable reports and passport files
15. Built in demo application
16. CPU, RAM, disk, and privacy benchmarks
17. Self contained packaging for each platform
18. Later work: deeper Linux eBPF support, HTTP and other protocol observers, and optional AI

## Rules that should not change without a good reason

* local first
* no account
* no cloud dependency
* no API key
* no required LLM
* no automatic telemetry
* no raw payload capture by default
* user selected observation scope
* bounded local storage
* event driven collection
* low CPU and RAM usage

## UI rules

1. Show the useful result before the raw data.
2. Every important claim should have evidence behind it.
3. Keep observed facts, conclusions, and AI explanations separate.
4. Do the repetitive investigation work for the user.
5. Make exported reports useful on their own.
6. Let the demo explain the product without a long setup.
7. Make the privacy state visible.
8. Treat the CLI as part of the main product.

## Architecture

The core will be Rust. The local interface will use TypeScript and a web UI. SQLite will hold local data.

Collectors should feed an operating system independent event model. Windows and Linux are the first targets. Linux can get deeper observation later through carefully chosen eBPF integrations.
