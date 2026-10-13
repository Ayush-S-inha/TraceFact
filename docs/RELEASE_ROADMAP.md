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

Stabilize the event contract and database migrations. Preserve timestamps, process identity, source, sensitivity, and structured metadata. Add useful query paths and exportable evidence bundles without introducing hidden data collection.

**Acceptance criteria**
- Schema migrations are versioned and tested.
- Every stored event belongs to a known run and retains its collector provenance.
- Exported evidence can be validated independently of the live UI.
- Database and export paths are documented for each supported operating system.

### Part 4: Runtime Passport and baseline management

Define a versioned Runtime Passport that describes observed processes, network peers, files, and runtime dependencies. Capture a named baseline and preserve the observation scope and coverage information that qualify it.

**Acceptance criteria**
- A baseline can be named, stored, inspected, and exported.
- Passport fields have stable meanings and schema validation.
- Incomplete collector coverage is explicitly represented.

### Part 5: Behavior comparison and drift detection

Compare a selected run with its chosen baseline. Produce added, removed, and changed observations, using stable keys and avoiding claims unsupported by the stored evidence.

**Acceptance criteria**
- Equivalent runs do not generate noisy differences from timestamps or unstable ordering.
- Every detected change links to the baseline and current evidence.
- Missing telemetry is not misrepresented as proof of absence.
- Comparison logic has deterministic unit tests.

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
