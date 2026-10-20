# Part 5: Behavior comparison

The first comparison pass adds `tracefact compare <baseline_name> <run_id|latest> [report.json]`. It compares a completed run against a named Runtime Passport baseline and can print the result or write a JSON report. The report includes event totals and counts by type for each run. Event-count differences are context, not automatic behavior findings. The report export refuses to overwrite an existing file.

The current implementation compares process-name sets and network-target sets when the stored provenance is sufficient. Findings link to baseline and current event IDs where a matching event can be identified. A baseline item missing from the current Passport is labelled `not_observed`; it is not called removed, because an absent event is not proof that behavior stopped. If the observation scopes differ, set-based findings are skipped and the scope difference is reported. Categories without sufficient provenance are skipped and named in the report.

Filesystem and loaded-library comparisons are not implemented. This pass also does not infer attribute-level changes such as an executable version or path changing; that requires stable entity identity and richer collected attributes.

## Validation status

Unit tests were added for evidence-linked added and `not_observed` findings, scope mismatch handling, skipping network comparisons without sufficient provenance, rejecting incomplete runs and different applications, and avoiding noisy changes from reordered observations or changed timestamps.

Rust formatting, compilation, tests, and Windows CLI verification have not been run in the artifact environment. Run these on the Windows development checkout before committing:

- `cargo fmt`
- `cargo test`
- `cargo check`
- `cargo build`
- `git diff --check`

Then use a copy of the database to save a baseline from one completed process observation, create a second completed observation of the same application, compare the second run with the baseline, validate the JSON report against `schema/behavior_drift_report.schema.json`, and confirm an existing report path is not overwritten. Also test that an interrupted run is rejected and that scope mismatches do not produce behavior-set findings.

TraceFact remains under development. The comparison report is deterministic with respect to the stored observation sets, but its generation timestamp and source run IDs necessarily differ between executions.
