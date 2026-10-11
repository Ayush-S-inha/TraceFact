# Windows Network Collector

The network collector adds TCP connection lifecycle evidence to a continuous `tracefact watch <pid>` run. It records connection metadata for the selected process tree and does not save application payloads.

## Events collected

The first version records TCP connect, accept, reconnect, and disconnect events when Windows provides a process ID and both endpoints. Each saved event includes the process ID, executable name, parent process ID when known, selected root process ID, tree depth, timestamp, operation, source IP and port, and destination IP and port.

Send, receive, retransmit, copy, and unknown TCP events are ignored. UDP and DNS attribution are not part of this collector yet. The observer does not capture HTTP bodies, headers, cookies, passwords, authorization values, or packet contents.

For an outgoing connection, the Runtime Passport target is the destination endpoint. For an accepted connection, the target is the source endpoint. A disconnect is linked to a previously observed connection when the endpoint pair can be matched. The collector keeps the process identity with each tracked flow so a delayed disconnect can still be attributed if the process has already exited.

IPv4 and IPv6 endpoints are supported. IPv6 endpoint strings use brackets around the address before the port.

## Event source and permissions

The collector uses Windows Event Tracing for Windows with the kernel TCP/IP provider. Run the watch command from an Administrator PowerShell. Windows may reject the tracing session if another kernel tracing session is already active.

Kernel network events are system-wide at the source. TraceFact uses the process ID inside the decoded TCP event payload, then checks whether that process belongs to the selected process tree before saving the event. The event header process ID is not used as the network process attribution source.

If an event arrives before the process start notification has been added to the in-memory tree, TraceFact takes a process snapshot and checks the parent chain. PIDs found to be outside the selected tree are briefly cached to avoid repeatedly taking snapshots for unrelated system traffic.

## Limits and privacy

ETW is a live event source, not a packet archive. Events can be missed when Windows or an event queue is overloaded. TraceFact bounds the application queue and reports how many events were dropped by that queue. It cannot report losses inside the underlying Windows ETW delivery channel unless that source exposes a loss counter through the selected API.

The collector keeps only structured connection metadata in its own event queue. Network events from unrelated process trees are not persisted. The Runtime Passport adds observed peer endpoints from connect and accept events, rather than every address seen on the computer.

The collector is experimental until it has passed live tests on the target Windows system. Its startup can fail because of missing privileges or a conflicting kernel trace session. Such failures should be shown to the user, not treated as an empty network observation.
