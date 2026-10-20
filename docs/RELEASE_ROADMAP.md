# TraceFact Product Roadmap

## Product definition

TraceFact is a local-first runtime behavior observer. It records what a selected application does while it runs, compares the observed behavior with a baseline, identifies meaningful changes, and presents claims with inspectable evidence.

The product's explanation flow is:

1. What was expected
2. What happened
3. What changed
4. Why it matters
5. Evidence supporting the finding

TraceFact must distinguish directly observed events from deterministic conclusions and optional AI-generated interpretation. AI is not required to collect data, compare behavior, use the interface, or export a report.

## Release principles

- Local-first by default, with no account, telemetry, cloud dependency, or mandatory API key.
- Explicit, visible observation scope selected by the user.
- No packet payload, HTTP body, cookie, password, authorization header, or other application content capture by default.
- Every important finding links to the underlying event or evidence.
- System-wide event sources must be filtered before persistence, and diagnostic output must avoid exposing unrelated endpoint data.
- Bounded queues and caches; loss and incomplete observation must be visible rather than reported as a clean result.
- The UI must not imply that an unobserved behavior did not occur.
- CLI workflows remain supported alongside the local UI.
- Windows is the first supported implementation target. Linux is planned; platform-specific coverage must be stated honestly.

## Implementation parts

### Part 1: Collector hardening

Harden the current process and TCP observers. Keep diagnostic samples schema-only, retain ETW terminal errors when a bounded queue cannot accept them, and distinguish process-tree attribution failures from events known to be outside the selected tree.

**Acceptance criteria**
- Diagnostic samples contain no process IDs, IP addresses, or port values.
- Queue saturation is reported, and a terminal ETW error is not silently lost.
- A process snapshot error during network attribution does not immediately abort the watch.
- Formatting/whitespace checks pass and a Windows test run confirms compilation and existing tests.

### Part 2: Watch lifecycle and error recovery

Make watch startup, stop, finalization, and cleanup predictable. Ensure a run is marked as completed, interrupted, or failed even when a collector or persistence operation fails, and ensure collector threads are stopped on all paths.

**Acceptance criteria**
- Each started run has a persisted status and final timestamp when storage remains available.
- Ctrl+C drains live queued process events up to a fixed 4,096-event limit and reports when the limit is exceeded; network queue draining is batched at 1,024 messages per main-loop pass and the remaining bounded network queue is drained after the ETW observer stops.
- Watch-loop errors are surfaced after finalization is attempted, rather than returning from the loop before updating the run record.
- Bootstrap run metadata and initial process events are persisted atomically, and old databases are migrated without falsely marking unfinished runs as completed.
- Remaining requirement: the current synchronous WMI notification iterators do not yet support cooperative cancellation. Do not mark the collector-cleanup acceptance criterion complete until that is implemented and Windows-tested.
- Windows tests must exercise startup failure, collector failure, queue saturation, Ctrl+C, root exit, and legacy database migration.

### Part 3: Evidence and persistence foundations

Stabilize database schema evolution and make saved run evidence portable. Preserve timestamps, process identity, source, sensitivity, and structured metadata. Export evidence without introducing hidden data collection.

**Part 3 checkpoint**
- SQLite schema evolution uses `PRAGMA user_version` and an ordered, transactional migration directory.
- Legacy databases are upgraded without falsely marking unfinished runs as completed.
- `tracefact export <run_id|latest> <path.json>` writes a standalone JSON evidence bundle, refuses to overwrite files, and includes run status, inferred scope, collector provenance, structured events, the Runtime Passport, and explicit coverage limitations.
- A JSON Schema is provided for exported evidence.
- Database locations and export privacy implications are documented for Windows, macOS, and Linux.

**Acceptance criteria**
- Schema migrations are versioned and tested.
- Every exported event retains its stored collector provenance and metadata.
- Exported evidence can be validated independently of the live UI.
- Exported files are not silently overwritten and incomplete coverage is not represented as absence of behavior.

### Part 4: Runtime Passport and baseline management

The first baseline-management pass adds named Runtime Passport baselines from completed saved runs. Baselines are kept in SQLite, retain their source run ID, and carry the observation scope and collection limitations that qualify the Passport. Names are unique case-insensitively, and an existing baseline is never silently replaced.

**Implemented in this checkpoint**
- Save, list, inspect, and export commands for named baselines.
- A version 2 SQLite migration for baseline storage.
- A versioned baseline JSON Schema referencing the Runtime Passport schema.
- Stable ordering and duplicate removal for Passport observation lists when a baseline is captured.
- Explicit source-run, scope, collector, and coverage metadata.

**Verified on Windows**
- The Part 4 Rust suite passed with 39 tests; `cargo check`, `cargo build`, and formatting passed.
- Migration 1 to 2 was tested on a copy of the existing Part 3 database; existing runs and events remained intact and the foreign-key check was clean.
- A fresh process snapshot was saved as a baseline, listed, inspected, exported, and validated against the baseline JSON Schema.
- Duplicate names, including a Unicode case variant, were rejected; existing export files were preserved; interrupted runs were rejected as baselines.

Baseline comparison was intentionally left for Part 5.

### Part 5: Behavior comparison and drift detection

The first comparison pass is `tracefact compare <baseline_name> <run_id|latest> [report.json]`. It compares stable Passport observation sets, links differences to stored event IDs, and records changes to scope and event-source provenance separately. It reports an item missing from the current Passport as `not_observed`, not as proof that behavior was removed. Filesystem and loaded-library categories remain out of scope until those collectors exist.

**Acceptance criteria**
- Equivalent observation sets do not generate differences because of timestamps or ordering.
- Findings link to source event IDs where a matching stored event exists.
- Scope mismatches prevent behavior-set findings rather than producing misleading differences.
- Categories without suitable provenance are skipped and named in the report.
- Comparison output validates against its JSON Schema and refuses to overwrite an existing report path.
- Missing telemetry is not misrepresented as proof of absence.
- Comparison logic has deterministic unit tests.

The initial set comparison does not yet infer property-level changes such as a process executable changing version or path. Those require stable entity identity and richer collected attributes.

### Part 6: Windows filesystem observation

Add event-driven observation for relevant file and directory activity within the user-selected scope. Record metadata needed to understand creation, writes, renames, and deletion without collecting file contents by default.

**Acceptance criteria**
- Events are correlated with process identity where the platform provides it.
- The watcher makes filtering, queue loss, and permission gaps visible.
- Tests cover common lifecycle operations and excluded paths.

### Part 7: Runtime dependencies and evidence-based checks

Track relevant loaded modules and runtime dependencies, then add a small, explainable set of security and policy checks. Do not present TraceFact as a full penetration-testing or universal vulnerability-scanning tool.

**Acceptance criteria**
- Each check states the condition that triggered it and cites source events or metadata.
- Findings include severity rationale and explicit limitations.
- Rules can be tested against positive, negative, and incomplete evidence.

### Part 8: Local API and interface

Serve the TypeScript interface from the Rust core on localhost. Present the useful result first, with raw event details and evidence available on demand. Make scope, collection status, and privacy state visible throughout a run.

**Acceptance criteria**
- The server binds only to loopback by default.
- Mutating or exporting operations have clear error handling and bounded request sizes.
- The main flow supports starting or selecting a run, inspecting a Passport, comparing a baseline, reviewing evidence, and exporting results.
- The interface works without a cloud service or LLM.

### Part 9: Demo, export, and release packaging

Create a repeatable demo application and sample dataset. Produce self-contained builds for explicitly supported platform versions, clear installation instructions, licensing notices, and recovery guidance.

**Acceptance criteria**
- A first-time user can install, run the demo, inspect the output, and remove local data using the documentation.
- Release artifacts are versioned and checksummed.
- A clean build from source is verified on each claimed platform.
- No release is described as launch-ready until the acceptance suite passes.

## Release gate

Before calling TraceFact launch-ready, run the relevant tests on a clean checkout, verify a live run on each claimed operating system, test permission-denied and interrupted cases, inspect exported data for privacy leaks, and document unsupported behavior. A successful build or one live TCP test alone is not sufficient.
