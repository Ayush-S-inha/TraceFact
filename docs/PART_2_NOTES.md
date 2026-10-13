# Part 2 Notes: Watch Lifecycle and Error Recovery

## Changes

- Added a persisted run status: `running`, `completed`, `interrupted`, or `failed`.
- Added an idempotent migration for older SQLite databases. Previously finished rows are classified as `completed`; rows with no end timestamp are classified as `interrupted`.
- Added `finish_run_with_status` while retaining `finish_run` as a compatibility wrapper for callers that mean a successful completion.
- Added `begin_run_with_events`, which inserts the run, initial Passport and bootstrap process events in a single transaction.
- Moved Ctrl+C handler registration before run creation.
- Changed the watch loop to capture errors and then attempt observer shutdown, a final network queue drain, and final Passport/run persistence.
- Process and network event sequence numbers advance only after the event has been successfully persisted.
- On Ctrl+C, the live process-event queue is drained up to 4,096 additional events. If more records remain, the CLI reports a lower-bound discard count rather than implying the stop was lossless.
- Network messages are processed in batches of at most 1,024 per main-loop pass, so continuous ETW traffic cannot starve process lifecycle handling. Once ETW is stopped, the remaining bounded network queue is drained before finalization.
- `history` and `inspect` now show run status.

## Status semantics

- `completed`: the root process exited and no watch error was recorded.
- `interrupted`: the user stopped the watch and no watch error was recorded.
- `failed`: the watch encountered an observer or event-persistence error, and TraceFact was able to persist the final run state.

If SQLite itself becomes unavailable during finalization, TraceFact cannot guarantee that the final timestamp or status will be written; the CLI reports the finalization error.

## Known limitation

The network ETW worker is joined on normal watch shutdown and is stopped explicitly on the handled startup-failure paths. The current synchronous WMI process-event iterators do not expose a cooperative cancellation control in the wrapper, so those background workers are not yet explicitly joined. The command-line process exits after the watch returns, but this does not satisfy the final collector-lifecycle acceptance criterion. A later part must address it rather than claiming full cleanup.

## Verification required on Windows

Run `cargo fmt -- --check`, `cargo test`, and `cargo check`, then test `watch` with Ctrl+C, natural root-process exit, an induced observer error if available, and opening a database created by the previous schema. This environment has no Cargo/Rust toolchain, so those commands were not run here.
