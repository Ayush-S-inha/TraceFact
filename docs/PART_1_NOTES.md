# Part 1 checkpoint notes

## Included

This checkpoint includes the existing uncommitted Windows TCP collector work in the supplied archive, plus the first hardening changes.

- Diagnostic samples now record event shape, decoding status, and field-presence information without printing endpoint addresses, port values, or process IDs from system-wide ETW traffic.
- A terminal ETW stream error is retained in shared diagnostics even if the bounded message queue cannot accept an error message.
- A failed process snapshot during network attribution is counted as unverified attribution rather than immediately ending the watch. Failed lookups are briefly cached to avoid repeated snapshots for every event from the same PID.
- The Windows network collector documentation now states that initial live validation succeeded, while broader validation remains incomplete.
- `docs/RELEASE_ROADMAP.md` records the intended product scope and staged release acceptance criteria.

## Checks performed in this environment

- `git diff --check`: passed.
- Whitespace scan of modified and new files: passed.
- `Cargo.toml` and `Cargo.lock`: parsed successfully as TOML.
- All four JSON files: parsed successfully.
- `schema/tracefact.sql`: executed successfully against an in-memory SQLite database, creating the expected tables.
- Static assertions for the part-one source changes: passed.

## Checks still required on Windows

The available execution environment does not have `cargo`, `rustc`, or `rustfmt`. Therefore, this checkpoint has **not** been compiled, formatted with Rust's formatter, or run through `cargo test`. The new Rust regression test for diagnostic redaction is included but has not been executed. Run the Windows build and test suite before relying on these changes.

Suggested verification commands:

```powershell
cargo fmt -- --check
cargo test
cargo check
```

Then repeat the live `tracefact watch <pid>` test with a process that opens an outbound TCP connection and confirm that connect and disconnect events are persisted, queue drops are reported, and diagnostic output contains no raw endpoints or process IDs when no scoped network events are saved.
