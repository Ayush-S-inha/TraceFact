# Windows Process Collector

The first real TraceFact collector reads the Windows process table and builds the process tree for a selected process ID. TraceFact also has a continuous watcher that subscribes to Windows process start and exit notifications for the selected process tree.

Run it with:

```text
tracefact process <pid>
tracefact watch <pid>
```

The collector records:

* process ID
* parent process ID
* executable name
* thread count
* tree depth
* relationship to the selected process

It does not collect command lines or file contents.

## How it works

Windows provides a process snapshot through the Tool Help API. TraceFact takes one read only snapshot, walks the process records, then builds the selected process tree in memory. Microsoft documents `CreateToolhelp32Snapshot`, `Process32FirstW`, and `Process32NextW` for this style of process enumeration.

The snapshot handle is owned by a small Rust wrapper so it is closed when the wrapper is dropped.

## Error handling

Collector failures are returned instead of being converted into an empty observation. This matters because an observation failure should not look like an application that has no activity.

## Continuous observation

Use `tracefact watch <pid>` to keep the selected process tree under observation until the root process exits or you press Ctrl+C.

On current Windows setups, run the watcher from an Administrator PowerShell. The WMI event subscription can otherwise be rejected by Windows with an access denied error.

The watcher uses the Windows WMI process event classes `Win32_ProcessStartTrace` and `Win32_ProcessStopTrace`. These are event notifications for process start and termination rather than a timer based process table scan. TraceFact keeps the received events scoped to the selected process tree before writing them to SQLite.

The watcher starts its event subscriptions before taking the bootstrap snapshot. This reduces the race between initial discovery and live event collection. A process start that cannot be connected to the tracked tree from in memory state triggers a one time process table lookup to reconstruct its ancestry.

Each lifecycle event is written to SQLite as it arrives. The run stays open while observation is active and is finalized with an updated Runtime Passport when observation stops.

The existing `tracefact process <pid>` command remains a point in time snapshot and is unchanged.
