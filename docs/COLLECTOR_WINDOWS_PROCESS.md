# Windows Process Collector

The first real TraceFact collector reads the Windows process table and builds the process tree for a selected process ID.

Run it with:

```text
tracefact process <pid>
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

## Current scope

This collector takes a point in time snapshot. It is not yet a continuous process event watcher.

A later collector version can consume Windows process start and exit events while keeping the same Runtime Event model. Windows exposes process start and end events through its event tracing facilities.
