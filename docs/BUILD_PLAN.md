# TraceFact Build Plan

## Main goal

TraceFact watches software while it runs and tells the developer what it actually did, what was unexpected, and why.

## Current state

The first Windows process collector is working. It can inspect a selected process tree, build a Runtime Passport, and save the observation to local SQLite storage.

Continuous Windows process observation is working. The watcher records process start and exit events for the selected process tree, persists them as they arrive, and finalizes the run with an updated Runtime Passport.

Windows TCP destination observation has been implemented as the next collector and is awaiting live validation on the target Windows system. It records TCP connection lifecycle metadata for the selected process tree without saving application payloads.

## Build order

1. Event schema
2. Rust core, SQLite, and localhost API
3. Windows process and process tree observer
4. Local persistence for collected runs
5. Continuous Windows process observation (working)
6. Network destination and port observer (implemented, awaiting live validation)
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
