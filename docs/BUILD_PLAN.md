# TraceFact Build Plan

## Main goal

TraceFact watches software while it runs and tells the developer what it actually did, what was unexpected, and why.

## Current state

The first Windows process collector is working. It can inspect a selected process tree, build a Runtime Passport, and save the observation to local SQLite storage.

## Build order

1. Event schema
2. Rust core, SQLite, and localhost API
3. Windows process and process tree observer
4. Local persistence for collected runs
5. Network destination and port observer
6. Filesystem observer
7. Runtime and library observer
8. Runtime Passport improvements
9. Baseline and current behavior comparison
10. Basic security checks with evidence
11. Local layered UI
12. Basic policy creation and verification
13. Exportable reports and passport files
14. Built in demo application
15. CPU, RAM, disk, and privacy benchmarks
16. Self contained packaging for each platform
17. Later work: deeper Linux eBPF support, HTTP and other protocol observers, and optional AI

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
