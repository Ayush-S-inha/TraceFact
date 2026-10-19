# Part 4: Runtime Passport Baselines



Part 4 adds named Runtime Passport baselines to TraceFact. A baseline is saved from a completed run, so an interrupted or failed observation cannot quietly become the reference for later comparisons.



Each baseline keeps the source run ID, Passport, observation scope, event counts, collector sources, and known coverage limitations. The observation lists are sorted and duplicate entries are removed when the baseline is created. Previous change findings are cleared because this is meant to represent the expected state, not a comparison result.



Baseline names must be unique, regardless of letter case. Saving an existing name fails rather than replacing the old baseline. The baseline can be inspected or exported as JSON, while the original run and its individual events remain in local storage.



SQLite migration 0002 adds the baseline table and indexes. Migration 0001 remains unchanged. The baseline export has its own JSON Schema and reuses the existing Runtime Passport schema.



## Verification



I tested Part 4 on Windows. Formatting, all 39 tests, cargo check, cargo build, and git diff --check passed.



I tested the migration using a copy of my existing database. All 16 runs and 49 events survived, the schema advanced to version 2, and SQLite reported no foreign-key violations.



Saving, listing, inspecting, and exporting a baseline all worked. The exported JSON passed schema validation. Duplicate names, including Unicode case variants, were rejected. Exporting to an existing file did not change its contents, and interrupted runs could not be saved as baselines.



## Still to do



Behavior-drift comparison is not implemented yet. Filesystem access and loaded-library observation are also unfinished. These remain future work; TraceFact is still under development.
