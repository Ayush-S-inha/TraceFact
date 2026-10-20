mod analysis;
mod collectors;
mod model;
mod storage;

use std::env;
use std::process::ExitCode;

#[cfg(windows)]
use crate::collectors::Collector;
#[cfg(windows)]
use std::collections::{BTreeMap, HashMap};
#[cfg(windows)]
use std::net::SocketAddr;
#[cfg(windows)]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::Receiver,
    Arc,
};
#[cfg(windows)]
use std::time::{Duration, Instant};

fn print_help() {
    println!("TraceFact 0.1.0");
    println!();
    println!("Usage:");
    println!("  tracefact doctor");
    println!("  tracefact demo");
    println!("  tracefact process <pid>");
    println!("  tracefact watch <pid>");
    println!("  tracefact history");
    println!("  tracefact inspect <run_id>");
    println!("  tracefact inspect latest");
    println!("  tracefact export <run_id|latest> <path.json>");
    println!("  tracefact baseline save <name> <run_id|latest>");
    println!("  tracefact baseline list");
    println!("  tracefact baseline inspect <name>");
    println!("  tracefact baseline export <name> <path.json>");
    println!("  tracefact compare <baseline_name> <run_id|latest> [report.json]");
    println!("  tracefact help");
    println!();
    println!(
        "The process command reads the selected Windows process tree, builds a Runtime Passport, and saves it locally."
    );
}

fn run_process(pid: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        let mut collector = collectors::windows_process::WindowsProcessCollector::new(pid);
        let started_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0);

        let events = collector.collect().map_err(|error| error.to_string())?;

        if events.is_empty() {
            return Err(format!(
                "TraceFact could not observe process {pid}. Check that the process exists."
            ));
        }

        let application = events
            .iter()
            .find(|event| event.process.pid == collector.root_pid())
            .map(|event| event.process.executable.clone())
            .unwrap_or_else(|| format!("pid:{pid}"));

        let snapshot = model::RuntimeSnapshot {
            schema_version: "0.1".to_string(),
            snapshot_id: format!("snap-{started_at_ms}"),
            application: application.clone(),
            started_at_ms,
            ended_at_ms: Some(started_at_ms),
            events,
        };
        let passport = analysis::passport_from_snapshot(&snapshot, started_at_ms);

        let (mut connection, database_path) =
            storage::open_default().map_err(|error| error.to_string())?;
        storage::save_snapshot_and_passport(&mut connection, &snapshot, &passport)
            .map_err(|error| error.to_string())?;

        println!("TraceFact process");
        println!();
        println!("  Root process:    {application}");
        println!("  Root PID:        {pid}");
        println!("  Processes seen:  {}", snapshot.events.len());
        println!("  Saved locally:   yes");
        println!("  Database:        {}", database_path.display());
        println!("  Run ID:          {}", snapshot.snapshot_id);
        println!("  Passport ID:     {}", passport.passport_id);
        println!();
        println!("Runtime Passport");
        println!(
            "{}",
            serde_json::to_string_pretty(&passport)
                .map_err(|error| format!("Could not serialize Runtime Passport: {error}"))?
        );
    }

    #[cfg(not(windows))]
    {
        let _ = pid;
        return Err("The Windows process collector is available only on Windows.".to_string());
    }

    Ok(())
}

#[cfg(windows)]
#[derive(Debug, Clone)]
struct ActiveProcess {
    name: String,
    depth: u32,
    parent_pid: Option<u32>,
}

#[cfg(windows)]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct NetworkFlowKey {
    pid: u32,
    first: SocketAddr,
    second: SocketAddr,
}

#[cfg(windows)]
impl NetworkFlowKey {
    fn new(pid: u32, source: SocketAddr, destination: SocketAddr) -> Self {
        if source <= destination {
            Self {
                pid,
                first: source,
                second: destination,
            }
        } else {
            Self {
                pid,
                first: destination,
                second: source,
            }
        }
    }
}

#[cfg(windows)]
#[derive(Debug, Clone)]
struct TrackedNetworkFlow {
    target: String,
    process: ActiveProcess,
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum NetworkPersistOutcome {
    Saved,
    Filtered,
    AttributionUnavailable(String),
}

#[cfg(windows)]
fn cached_process_for_disconnect(
    operation: collectors::windows_network::NetworkOperation,
    flow_key: &NetworkFlowKey,
    flow_targets: &HashMap<NetworkFlowKey, TrackedNetworkFlow>,
) -> Option<ActiveProcess> {
    if operation != collectors::windows_network::NetworkOperation::Disconnect {
        return None;
    }

    flow_targets
        .get(flow_key)
        .map(|tracked_flow| tracked_flow.process.clone())
}

#[cfg(windows)]
fn persist_network_observation(
    observation: collectors::windows_network::NetworkObservation,
    root_pid: u32,
    run_id: &str,
    active: &BTreeMap<u32, ActiveProcess>,
    ignored_pids_until: &mut HashMap<u32, Instant>,
    unresolved_pids_until: &mut HashMap<u32, Instant>,
    flow_targets: &mut HashMap<NetworkFlowKey, TrackedNetworkFlow>,
    connection: &mut rusqlite::Connection,
    passport: &mut analysis::PassportAccumulator,
    sequence: &mut u64,
) -> Result<NetworkPersistOutcome, String> {
    use collectors::windows_network::{endpoint, NetworkOperation};

    const FLOW_CACHE_LIMIT: usize = 8192;
    const NEGATIVE_PID_CACHE_TTL: Duration = Duration::from_secs(2);

    let now = Instant::now();
    ignored_pids_until.retain(|_, expires_at| *expires_at > now);
    unresolved_pids_until.retain(|_, expires_at| *expires_at > now);

    let source = SocketAddr::new(observation.source_ip, observation.source_port);
    let destination = SocketAddr::new(observation.destination_ip, observation.destination_port);
    let flow_key = NetworkFlowKey::new(observation.process_id, source, destination);

    // A disconnect notification can arrive after the process exit notification.
    // Prefer the identity saved with this exact flow so the event is not lost
    // simply because the process was already removed from the active tree.
    let cached_disconnect_process =
        cached_process_for_disconnect(observation.operation, &flow_key, flow_targets);

    let process = if let Some(process) = cached_disconnect_process {
        process
    } else if let Some(process) = active.get(&observation.process_id) {
        process.clone()
    } else {
        if ignored_pids_until
            .get(&observation.process_id)
            .is_some_and(|expires_at| *expires_at > now)
        {
            return Ok(NetworkPersistOutcome::Filtered);
        }

        if unresolved_pids_until
            .get(&observation.process_id)
            .is_some_and(|expires_at| *expires_at > now)
        {
            return Ok(NetworkPersistOutcome::AttributionUnavailable(
                "A recent process snapshot failed, so membership remains unverified.".to_string(),
            ));
        }

        let member = match collectors::windows_process::identify_process_in_tree(
            root_pid,
            observation.process_id,
        ) {
            Ok(member) => member,
            Err(error) => {
                // A transient process snapshot failure must not abort the entire watch.
                // Cache the failure briefly to avoid repeating a system snapshot for every event.
                if unresolved_pids_until.len() < 4096 {
                    unresolved_pids_until
                        .insert(observation.process_id, now + NEGATIVE_PID_CACHE_TTL);
                }
                return Ok(NetworkPersistOutcome::AttributionUnavailable(
                    error.to_string(),
                ));
            }
        };

        let Some(member) = member else {
            if ignored_pids_until.len() < 4096 {
                ignored_pids_until.insert(observation.process_id, now + NEGATIVE_PID_CACHE_TTL);
            }
            return Ok(NetworkPersistOutcome::Filtered);
        };

        ActiveProcess {
            name: member.name,
            depth: member.depth,
            parent_pid: member.parent_pid,
        }
    };

    let target = match observation.operation {
        NetworkOperation::Connect | NetworkOperation::Reconnect => {
            let target = endpoint(observation.destination_ip, observation.destination_port);
            if flow_targets.len() < FLOW_CACHE_LIMIT || flow_targets.contains_key(&flow_key) {
                flow_targets.insert(
                    flow_key,
                    TrackedNetworkFlow {
                        target: target.clone(),
                        process: process.clone(),
                    },
                );
            }
            Some(target)
        }
        NetworkOperation::Accept => {
            let target = endpoint(observation.source_ip, observation.source_port);
            if flow_targets.len() < FLOW_CACHE_LIMIT || flow_targets.contains_key(&flow_key) {
                flow_targets.insert(
                    flow_key,
                    TrackedNetworkFlow {
                        target: target.clone(),
                        process: process.clone(),
                    },
                );
            }
            Some(target)
        }
        NetworkOperation::Disconnect => flow_targets.remove(&flow_key).map(|flow| flow.target),
    };

    let next_sequence = (*sequence).wrapping_add(1);
    let relationship = if observation.process_id == root_pid {
        "root"
    } else {
        "child"
    };
    let runtime_event = model::RuntimeEvent {
        id: format!("{run_id}-event-{next_sequence}"),
        timestamp_ms: observation.timestamp_ms,
        event_type: model::EventType::NetworkConnection,
        process: model::ProcessIdentity {
            pid: observation.process_id,
            executable: process.name.clone(),
            command_line: None,
            parent_pid: process.parent_pid,
        },
        subject: "tcp".to_string(),
        target: target.clone(),
        metadata: serde_json::json!({
            "protocol": "tcp",
            "operation": observation.operation.as_str(),
            "source_ip": observation.source_ip.to_string(),
            "source_port": observation.source_port,
            "destination_ip": observation.destination_ip.to_string(),
            "destination_port": observation.destination_port,
            "root_pid": root_pid,
            "parent_pid": process.parent_pid,
            "depth": process.depth,
            "relationship": relationship
        }),
        source: "windows_network_watch".to_string(),
        sensitivity: model::Sensitivity::SystemMetadata,
    };

    storage::append_event(connection, run_id, &runtime_event).map_err(|error| error.to_string())?;
    *sequence = next_sequence;
    passport.observe(&runtime_event);

    match observation.operation {
        NetworkOperation::Connect | NetworkOperation::Reconnect => println!(
            "  + tcp {}: {} (PID {}) -> {}",
            observation.operation.as_str(),
            process.name,
            observation.process_id,
            target.as_deref().unwrap_or("endpoint unavailable")
        ),
        NetworkOperation::Accept => println!(
            "  + tcp accept: {} (PID {}) <- {}",
            process.name,
            observation.process_id,
            target.as_deref().unwrap_or("peer unavailable")
        ),
        NetworkOperation::Disconnect => println!(
            "  - tcp disconnect: {} (PID {}){}",
            process.name,
            observation.process_id,
            target
                .as_ref()
                .map(|value| format!(" -> {value}"))
                .unwrap_or_default()
        ),
    }

    Ok(NetworkPersistOutcome::Saved)
}

#[cfg(windows)]
fn drain_network_queue(
    receiver: &Receiver<collectors::windows_network::NetworkWatchMessage>,
    disconnected_is_error: bool,
    root_pid: u32,
    run_id: &str,
    active: &BTreeMap<u32, ActiveProcess>,
    ignored_pids_until: &mut HashMap<u32, Instant>,
    unresolved_pids_until: &mut HashMap<u32, Instant>,
    flow_targets: &mut HashMap<NetworkFlowKey, TrackedNetworkFlow>,
    connection: &mut rusqlite::Connection,
    passport: &mut analysis::PassportAccumulator,
    sequence: &mut u64,
    network_events_saved: &mut u64,
    network_events_filtered: &mut u64,
    network_attribution_failures: &mut u64,
    first_attribution_error: &mut Option<String>,
) -> Result<Option<String>, String> {
    use collectors::windows_network::NetworkWatchMessage;
    use std::sync::mpsc::TryRecvError;

    // Yield back to the process-event watcher regularly, even if ETW keeps
    // producing records while this queue is being drained.
    const MAX_MESSAGES_PER_DRAIN: usize = 1024;

    let mut first_error = None;
    let mut drained = 0_usize;
    loop {
        if drained >= MAX_MESSAGES_PER_DRAIN {
            break;
        }

        match receiver.try_recv() {
            Ok(message) => {
                drained += 1;
                match message {
                    NetworkWatchMessage::Event(observation) => {
                        match persist_network_observation(
                            observation,
                            root_pid,
                            run_id,
                            active,
                            ignored_pids_until,
                            unresolved_pids_until,
                            flow_targets,
                            connection,
                            passport,
                            sequence,
                        )? {
                            NetworkPersistOutcome::Saved => {
                                *network_events_saved = (*network_events_saved).wrapping_add(1);
                            }
                            NetworkPersistOutcome::Filtered => {
                                *network_events_filtered =
                                    (*network_events_filtered).wrapping_add(1);
                            }
                            NetworkPersistOutcome::AttributionUnavailable(message) => {
                                *network_attribution_failures =
                                    (*network_attribution_failures).wrapping_add(1);
                                if first_attribution_error.is_none() {
                                    *first_attribution_error = Some(message);
                                }
                            }
                        }
                    }
                    NetworkWatchMessage::Error(message) => {
                        if first_error.is_none() {
                            first_error = Some(message);
                        }
                    }
                }
            }
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => {
                if disconnected_is_error && first_error.is_none() {
                    first_error = Some(
                        "Windows network event watcher disconnected unexpectedly.".to_string(),
                    );
                }
                break;
            }
        }
    }

    Ok(first_error)
}

#[cfg(windows)]
fn run_watch(pid: u32) -> Result<(), String> {
    use collectors::windows_network::WindowsNetworkEventWatcher;
    use collectors::windows_process::{
        build_process_exit_event, build_process_lifecycle_event, classify_process_depth,
        snapshot_process_tree, wait_for_watchers, ProcessWatchEvent, WatchSource,
        WindowsProcessEventWatcher,
    };

    let started_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0);
    let run_id = format!("watch-{started_at_ms}-{pid}");

    // Install Ctrl+C handling before any run record is created. A handler setup
    // failure must not leave an unfinished run in the database.
    let stop_requested = Arc::new(AtomicBool::new(false));
    let stop_handler = Arc::clone(&stop_requested);
    ctrlc::set_handler(move || {
        stop_handler.store(true, Ordering::SeqCst);
    })
    .map_err(|error| format!("Could not install Ctrl+C handler: {error}"))?;

    let (mut connection, database_path) =
        storage::open_default().map_err(|error| error.to_string())?;

    // Start ETW first so failures to start it do not leave the WMI watcher
    // threads running in the background without a consumer.
    let mut network_watcher =
        WindowsNetworkEventWatcher::start().map_err(|error| error.to_string())?;
    let watcher = WindowsProcessEventWatcher::start();
    let receiver = watcher.receiver();

    let queued_events = match wait_for_watchers(receiver, Duration::from_secs(10)) {
        Ok(events) => events,
        Err(error) => {
            let stop_result = network_watcher.stop();
            return Err(match stop_result {
                Ok(()) => error.to_string(),
                Err(stop_error) => format!("{error}; additionally, {stop_error}"),
            });
        }
    };

    let initial_events = match snapshot_process_tree(pid, &run_id) {
        Ok(events) => events,
        Err(error) => {
            let stop_result = network_watcher.stop();
            return Err(match stop_result {
                Ok(()) => error.to_string(),
                Err(stop_error) => format!("{error}; additionally, {stop_error}"),
            });
        }
    };
    let root_event = initial_events
        .iter()
        .find(|event| event.process.pid == pid)
        .ok_or_else(|| format!("Process with PID {pid} was not found."))?;
    let application = root_event.process.executable.clone();

    let initial_snapshot = model::RuntimeSnapshot {
        schema_version: "0.1".to_string(),
        snapshot_id: run_id.clone(),
        application: application.clone(),
        started_at_ms,
        ended_at_ms: None,
        events: vec![],
    };
    let initial_passport =
        analysis::PassportAccumulator::default().finish(&run_id, started_at_ms, &application);
    storage::begin_run_with_events(
        &mut connection,
        &initial_snapshot,
        &initial_passport,
        &initial_events,
    )
    .map_err(|error| error.to_string())?;

    let mut active = BTreeMap::<u32, ActiveProcess>::new();
    let mut passport = analysis::PassportAccumulator::default();
    let mut sequence = 0_u64;
    let mut network_events_saved = 0_u64;
    let mut network_events_filtered = 0_u64;
    let mut network_attribution_failures = 0_u64;
    let mut first_attribution_error = None;
    let mut ignored_pids_until = HashMap::<u32, Instant>::new();
    let mut unresolved_pids_until = HashMap::<u32, Instant>::new();
    let mut flow_targets = HashMap::<NetworkFlowKey, TrackedNetworkFlow>::new();

    for event in initial_events {
        active.insert(
            event.process.pid,
            ActiveProcess {
                name: event.process.executable.clone(),
                parent_pid: event.process.parent_pid,
                depth: event
                    .metadata
                    .get("depth")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0) as u32,
            },
        );
        passport.observe(&event);
        sequence = sequence.wrapping_add(1);
    }

    println!("TraceFact process watch");
    println!();
    println!("  Root process:    {application}");
    println!("  Root PID:        {pid}");
    println!("  Processes seen:  {}", active.len());
    println!("  Saved locally:   yes");
    println!("  Database:        {}", database_path.display());
    println!("  Run ID:          {run_id}");
    println!();
    println!("Watching process starts, exits, and TCP connection metadata. Press Ctrl+C to stop.");

    const MAX_QUEUED_PROCESS_EVENTS_ON_STOP: usize = 4096;
    let mut process_events_drained_after_stop = 0_usize;
    let mut process_events_discarded_at_stop = 0_usize;
    let mut process_queue_drain_limited = false;
    let mut stop_reason = "stopped by user";
    let mut network_error = None;

    let watch_result = (|| -> Result<(), String> {
        let network_receiver = network_watcher.receiver();
        let mut pending_events = queued_events.into_iter();

        'watch: loop {
            if let Some(message) = drain_network_queue(
                network_receiver,
                true,
                pid,
                &run_id,
                &active,
                &mut ignored_pids_until,
                &mut unresolved_pids_until,
                &mut flow_targets,
                &mut connection,
                &mut passport,
                &mut sequence,
                &mut network_events_saved,
                &mut network_events_filtered,
                &mut network_attribution_failures,
                &mut first_attribution_error,
            )? {
                network_error = Some(message);
                stop_reason = "network observer stopped";
                break 'watch;
            }

            let incoming = if let Some(event) = pending_events.next() {
                Some(event)
            } else if stop_requested.load(Ordering::SeqCst) {
                if process_events_drained_after_stop < MAX_QUEUED_PROCESS_EVENTS_ON_STOP {
                    match receiver.try_recv() {
                        Ok(event) => {
                            process_events_drained_after_stop += 1;
                            Some(event)
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty)
                        | Err(std::sync::mpsc::TryRecvError::Disconnected) => None,
                    }
                } else {
                    match receiver.try_recv() {
                        Ok(_event) => {
                            process_queue_drain_limited = true;
                            process_events_discarded_at_stop = 1 + receiver
                                .try_iter()
                                .take(MAX_QUEUED_PROCESS_EVENTS_ON_STOP)
                                .count();
                            None
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty)
                        | Err(std::sync::mpsc::TryRecvError::Disconnected) => None,
                    }
                }
            } else {
                match receiver.recv_timeout(Duration::from_millis(250)) {
                    Ok(event) => Some(event),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue 'watch,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        return Err("Windows process event watchers disconnected.".to_string());
                    }
                }
            };

            let Some(event) = incoming else {
                break 'watch;
            };

            match event {
                ProcessWatchEvent::Start(event) => {
                    let timestamp_ms =
                        collectors::windows_process::WindowsProcessCollector::now_ms();

                    let depth = active
                        .get(&event.parent_process_id)
                        .map(|parent| parent.depth.saturating_add(1))
                        .or_else(|| {
                            let processes = collectors::windows_process::WindowsProcessCollector::enumerate_processes().ok()?;
                            classify_process_depth(&processes, pid, event.process_id)
                        });

                    let Some(depth) = depth else {
                        continue 'watch;
                    };

                    if active.contains_key(&event.process_id) {
                        continue 'watch;
                    }

                    let next_sequence = sequence.wrapping_add(1);
                    let runtime_event = build_process_lifecycle_event(
                        &run_id,
                        next_sequence,
                        pid,
                        timestamp_ms,
                        &event,
                        depth,
                    );
                    storage::append_event(&mut connection, &run_id, &runtime_event)
                        .map_err(|error| error.to_string())?;

                    sequence = next_sequence;
                    active.insert(
                        event.process_id,
                        ActiveProcess {
                            name: event.process_name.clone(),
                            depth,
                            parent_pid: Some(event.parent_process_id).filter(|parent| *parent != 0),
                        },
                    );
                    passport.observe(&runtime_event);

                    println!(
                        "  + process started: {} (PID {}, depth {})",
                        event.process_name, event.process_id, depth
                    );
                }
                ProcessWatchEvent::Exit(event) => {
                    let Some(previous) = active.get(&event.process_id).cloned() else {
                        continue 'watch;
                    };

                    // The stop notification identifies the process by PID and name.
                    // ParentProcessId is not required to match the bootstrap record,
                    // especially for the root process where Windows may report a
                    // different or unavailable parent at exit time.
                    if previous.name != event.process_name {
                        continue 'watch;
                    }

                    let next_sequence = sequence.wrapping_add(1);
                    let relationship = if event.process_id == pid {
                        "root"
                    } else {
                        "child"
                    };
                    let runtime_event = build_process_exit_event(
                        &run_id,
                        next_sequence,
                        pid,
                        collectors::windows_process::WindowsProcessCollector::now_ms(),
                        &event,
                        previous.depth,
                        relationship,
                    );
                    storage::append_event(&mut connection, &run_id, &runtime_event)
                        .map_err(|error| error.to_string())?;

                    sequence = next_sequence;
                    active.remove(&event.process_id);
                    passport.observe(&runtime_event);

                    println!(
                        "  - process exited: {} (PID {}, exit status {})",
                        event.process_name, event.process_id, event.exit_status
                    );

                    if event.process_id == pid {
                        stop_reason = "root process exited";
                        break 'watch;
                    }
                }
                ProcessWatchEvent::Ready(source) => match source {
                    WatchSource::Starts | WatchSource::Exits => {}
                },
                ProcessWatchEvent::Error(message) => {
                    return Err(message);
                }
            }
        }

        Ok(())
    })();

    if let Err(message) = watch_result {
        stop_reason = "watch interrupted by error";
        match &mut network_error {
            Some(existing) if existing != &message => {
                existing.push_str("; additional watch error: ");
                existing.push_str(&message);
            }
            Some(_) => {}
            None => network_error = Some(message),
        }
    }

    if let Err(error) = network_watcher.stop() {
        if network_error.is_none() {
            network_error = Some(error.to_string());
        }
    }

    match drain_network_queue(
        network_watcher.receiver(),
        false,
        pid,
        &run_id,
        &active,
        &mut ignored_pids_until,
        &mut unresolved_pids_until,
        &mut flow_targets,
        &mut connection,
        &mut passport,
        &mut sequence,
        &mut network_events_saved,
        &mut network_events_filtered,
        &mut network_attribution_failures,
        &mut first_attribution_error,
    ) {
        Ok(Some(message)) => {
            if network_error.is_none() {
                network_error = Some(message);
            }
        }
        Ok(None) => {}
        Err(message) => {
            if network_error.is_none() {
                network_error = Some(format!("Could not fully drain network events: {message}"));
            }
        }
    }

    let network_diagnostics = network_watcher.diagnostics();
    if network_error.is_none() {
        network_error = network_diagnostics.stream_error.clone();
    }

    let terminal_status = if network_error.is_some() {
        "failed"
    } else if stop_reason == "root process exited" {
        "completed"
    } else {
        "interrupted"
    };
    let ended_at_ms = collectors::windows_process::WindowsProcessCollector::now_ms();
    let final_passport = passport.finish(&run_id, ended_at_ms, &application);
    storage::finish_run_with_status(
        &mut connection,
        &run_id,
        ended_at_ms,
        &final_passport,
        terminal_status,
    )
    .map_err(|error| format!("Could not finalize run {run_id}: {error}"))?;

    println!();
    println!("Watch finished: {stop_reason}");
    println!("  Status:               {terminal_status}");
    println!("  Events saved:         {sequence}");
    println!("  Network events saved: {network_events_saved}");
    println!("  Network events filtered: {network_events_filtered}");
    println!("  Network events with unverified attribution: {network_attribution_failures}");
    if process_queue_drain_limited {
        println!(
            "  Process events not drained at stop: at least {} (shutdown drain cap {})",
            process_events_discarded_at_stop, MAX_QUEUED_PROCESS_EVENTS_ON_STOP
        );
    }
    if let Some(message) = &first_attribution_error {
        println!("  First attribution error: {message}");
    }
    println!(
        "  Network queue drops:  {}",
        network_watcher.dropped_events()
    );
    println!(
        "  Tracked without exit event at stop:       {}",
        active.len()
    );

    if network_events_saved == 0 {
        println!();
        println!("Network collector diagnostics");
        println!(
            "  ETW records received:       {}",
            network_diagnostics.raw_events_seen
        );
        println!(
            "  TCP records decoded:        {}",
            network_diagnostics.tcp_events_decoded
        );
        println!(
            "  Other records decoded:      {}",
            network_diagnostics.other_events_decoded
        );
        println!(
            "  Unsupported TCP operations: {}",
            network_diagnostics.unsupported_tcp_operations
        );
        println!(
            "  Incomplete TCP records:     {}",
            network_diagnostics.incomplete_tcp_events
        );
        println!(
            "  TCP observations queued:    {}",
            network_diagnostics.observations_enqueued
        );

        if !network_diagnostics.event_shapes.is_empty() {
            println!("  ETW event shapes:");
            for (shape, count) in &network_diagnostics.event_shapes {
                println!("    {count:>6}  {shape}");
            }
            if network_diagnostics.additional_shape_event_count > 0 {
                println!(
                    "    Records belonging to additional event shapes: {}",
                    network_diagnostics.additional_shape_event_count
                );
            }
        }

        if !network_diagnostics.raw_event_samples.is_empty() {
            println!("  Raw record samples:");
            for sample in &network_diagnostics.raw_event_samples {
                println!("    {sample}");
            }
        }

        if !network_diagnostics.tcp_event_samples.is_empty() {
            println!("  Decoded TCP samples:");
            for sample in &network_diagnostics.tcp_event_samples {
                println!("    {sample}");
            }
        }
    }
    println!("  Run ID:               {run_id}");
    println!("  Passport ID:          {}", final_passport.passport_id);

    if let Some(message) = network_error {
        return Err(message);
    }

    Ok(())
}

fn display_sensitivity(value: &str) -> &str {
    match value {
        "PublicMetadata" => "SystemMetadata",
        other => other,
    }
}

fn run_inspect(run_id: &str) -> Result<(), String> {
    let (connection, database_path) = storage::open_default().map_err(|error| error.to_string())?;
    let resolved_run_id = if run_id == "latest" {
        storage::latest_run_id(&connection)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "No saved runs were found.".to_string())?
    } else {
        run_id.to_string()
    };

    let run = storage::get_run(&connection, &resolved_run_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("Run {resolved_run_id} was not found."))?;

    println!("TraceFact inspect");
    println!();
    println!("  Database:        {}", database_path.display());
    println!("  Run ID:          {}", run.run_id);
    println!("  Application:     {}", run.application);
    println!("  Schema version:  {}", run.schema_version);
    println!("  Status:          {}", run.status);
    println!("  Started at:      {}", run.started_at_ms);
    println!(
        "  Ended at:        {}",
        run.ended_at_ms
            .map_or_else(|| "not recorded".to_string(), |value| value.to_string())
    );
    println!("  Passport ID:     {}", run.passport.passport_id);
    println!();
    println!("Events ({})", run.events.len());

    for event in &run.events {
        println!();
        println!("  Event ID:     {}", event.event_id);
        println!("  Timestamp:    {}", event.timestamp_ms);
        println!("  Type:         {}", event.event_type);
        println!(
            "  PID:          {}",
            event
                .pid
                .map_or_else(|| "not recorded".to_string(), |value| value.to_string())
        );
        println!(
            "  Executable:   {}",
            event.executable.as_deref().unwrap_or("not recorded")
        );
        println!(
            "  Subject:      {}",
            event.subject.as_deref().unwrap_or("not recorded")
        );
        println!(
            "  Target:       {}",
            event.target.as_deref().unwrap_or("not recorded")
        );
        println!("  Source:       {}", event.source);
        println!(
            "  Sensitivity:  {}",
            display_sensitivity(&event.sensitivity)
        );
        println!("  Metadata:     {}", event.metadata_json);
    }

    println!();
    println!("Runtime Passport");
    println!(
        "{}",
        serde_json::to_string_pretty(&run.passport)
            .map_err(|error| format!("Could not serialize Runtime Passport: {error}"))?
    );

    Ok(())
}

fn run_export(run_id: &str, output_path: &str) -> Result<(), String> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    let (connection, database_path) = storage::open_default().map_err(|error| error.to_string())?;
    let resolved_run_id = if run_id == "latest" {
        storage::latest_run_id(&connection)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "No saved runs were found.".to_string())?
    } else {
        run_id.to_string()
    };

    let run = storage::get_run(&connection, &resolved_run_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("Run {resolved_run_id} was not found."))?;

    if run.status == "running" {
        return Err(format!(
            "Run {} is still running. Stop or finalize it before exporting evidence.",
            run.run_id
        ));
    }

    let exported_at_ms: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("System clock is before the Unix epoch: {error}"))?
        .as_millis()
        .try_into()
        .map_err(|_| "Export timestamp is outside the supported range.".to_string())?;

    let bundle = analysis::evidence_bundle_from_run(&run, exported_at_ms)?;
    let json = serde_json::to_vec_pretty(&bundle)
        .map_err(|error| format!("Could not serialize evidence bundle: {error}"))?;
    let path = std::path::Path::new(output_path);

    // Never overwrite an existing evidence file without an explicit user action.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!(
                "Could not create export at {} (existing files are not overwritten): {error}",
                path.display()
            )
        })?;

    if let Err(error) = file.write_all(&json).and_then(|_| file.write_all(b"\n")) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("Could not write evidence bundle: {error}"));
    }

    println!("TraceFact evidence export");
    println!();
    println!("  Run ID:          {}", run.run_id);
    println!("  Application:     {}", run.application);
    println!("  Run status:      {}", run.status);
    println!("  Events:          {}", bundle.coverage.event_count);
    println!("  Database:        {}", database_path.display());
    println!("  Exported to:     {}", path.display());
    println!();
    println!("Review the exported file before sharing it. Event metadata may contain process IDs,");
    println!(
        "executable names, and network endpoints. Raw application payloads are not collected."
    );
    Ok(())
}

fn current_unix_ms() -> Result<i64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| format!("System clock is before the Unix epoch: {error}"))?
        .as_millis()
        .try_into()
        .map_err(|_| "Timestamp is outside the supported range.".to_string())
}

fn run_baseline_save(name: &str, run_id: &str) -> Result<(), String> {
    storage::validate_baseline_name(name).map_err(|error| error.to_string())?;
    let (mut connection, database_path) =
        storage::open_default().map_err(|error| error.to_string())?;
    let resolved_run_id = if run_id == "latest" {
        storage::latest_completed_run_id(&connection)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "No completed saved runs were found.".to_string())?
    } else {
        run_id.to_string()
    };
    let run = storage::get_run(&connection, &resolved_run_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("Run {resolved_run_id} was not found."))?;
    let baseline = analysis::baseline_from_run(&run, name, current_unix_ms()?)?;
    storage::save_baseline(&mut connection, &baseline).map_err(|error| error.to_string())?;

    println!("Runtime Passport baseline saved");
    println!();
    println!("  Name:          {}", baseline.name);
    println!("  Application:   {}", baseline.application);
    println!("  Source run:    {}", baseline.source_run_id);
    println!("  Events:        {}", baseline.coverage.event_count);
    println!(
        "  Collectors:    {}",
        baseline.coverage.collector_sources.join(", ")
    );
    println!("  Database:      {}", database_path.display());
    println!();
    println!(
        "The baseline is local. Its name is unique (case-insensitive) and will not be overwritten."
    );
    println!("Inspect coverage limitations before using it as an expected-behavior reference.");
    Ok(())
}

fn run_baseline_list() -> Result<(), String> {
    let (connection, database_path) = storage::open_default().map_err(|error| error.to_string())?;
    let baselines = storage::list_baselines(&connection, 100).map_err(|error| error.to_string())?;

    println!("TraceFact baselines");
    println!();
    println!("  Database: {}", database_path.display());
    println!();
    if baselines.is_empty() {
        println!("  No saved baselines.");
        return Ok(());
    }

    println!("  NAME                 APPLICATION              EVENTS  SOURCE RUN");
    println!("  -----------------------------------------------------------------");
    for baseline in baselines {
        println!(
            "  {:<20} {:<24} {:>6}  {}",
            baseline.name, baseline.application, baseline.event_count, baseline.source_run_id
        );
        if !baseline.collector_sources.is_empty() {
            println!("    Collectors: {}", baseline.collector_sources.join(", "));
        }
    }
    Ok(())
}

fn run_baseline_inspect(name: &str) -> Result<(), String> {
    let (connection, database_path) = storage::open_default().map_err(|error| error.to_string())?;
    let baseline = storage::get_baseline(&connection, name)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("Baseline '{name}' was not found."))?;

    println!("TraceFact baseline inspect");
    println!();
    println!("  Database:      {}", database_path.display());
    println!("  Name:          {}", baseline.name);
    println!("  Schema:        {}", baseline.baseline_schema_version);
    println!("  Application:   {}", baseline.application);
    println!("  Source run:    {}", baseline.source_run_id);
    println!("  Created at:    {}", baseline.created_at_ms);
    println!("  Events:        {}", baseline.coverage.event_count);
    println!(
        "  Collectors:    {}",
        baseline.coverage.collector_sources.join(", ")
    );
    println!();
    println!("Event counts by type");
    for (event_type, count) in &baseline.coverage.event_counts_by_type {
        println!("  {event_type}: {count}");
    }
    println!();
    println!("Observation scope");
    println!(
        "{}",
        serde_json::to_string_pretty(&baseline.scope)
            .map_err(|error| format!("Could not serialize baseline scope: {error}"))?
    );
    println!();
    println!("Coverage limitations");
    for limitation in &baseline.coverage.limitations {
        println!("  - {limitation}");
    }
    println!();
    println!("Runtime Passport");
    println!(
        "{}",
        serde_json::to_string_pretty(&baseline.passport)
            .map_err(|error| format!("Could not serialize Runtime Passport: {error}"))?
    );
    Ok(())
}

fn run_baseline_export(name: &str, output_path: &str) -> Result<(), String> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    let (connection, database_path) = storage::open_default().map_err(|error| error.to_string())?;
    let baseline = storage::get_baseline(&connection, name)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("Baseline '{name}' was not found."))?;
    let json = serde_json::to_vec_pretty(&baseline)
        .map_err(|error| format!("Could not serialize baseline: {error}"))?;
    let path = std::path::Path::new(output_path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!(
                "Could not create baseline export at {} (existing files are not overwritten): {error}",
                path.display()
            )
        })?;

    if let Err(error) = file.write_all(&json).and_then(|_| file.write_all(b"\n")) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("Could not write baseline export: {error}"));
    }

    println!("Runtime Passport baseline exported");
    println!();
    println!("  Name:          {}", baseline.name);
    println!("  Source run:    {}", baseline.source_run_id);
    println!("  Events:        {}", baseline.coverage.event_count);
    println!("  Database:      {}", database_path.display());
    println!("  Exported to:   {}", path.display());
    println!();
    println!("Review the file before sharing it; the scope and Passport may contain process IDs, process names, and network endpoints.");
    Ok(())
}

fn run_compare(baseline_name: &str, run_id: &str, output_path: Option<&str>) -> Result<(), String> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    let (connection, database_path) = storage::open_default().map_err(|error| error.to_string())?;
    let baseline = storage::get_baseline(&connection, baseline_name)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("Baseline '{baseline_name}' was not found."))?;
    let baseline_run = storage::get_run(&connection, &baseline.source_run_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "Baseline source run '{}' was not found.",
                baseline.source_run_id
            )
        })?;
    if baseline_run.status != "completed" {
        return Err(format!(
            "Baseline source run '{}' is no longer completed; refusing to compare against it.",
            baseline.source_run_id
        ));
    }

    let resolved_run_id = if run_id == "latest" {
        storage::latest_completed_run_id(&connection)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "No completed saved runs were found.".to_string())?
    } else {
        run_id.to_string()
    };
    let current_run = storage::get_run(&connection, &resolved_run_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("Run {resolved_run_id} was not found."))?;
    let report = analysis::compare_baseline_to_run(
        &baseline,
        &baseline_run,
        &current_run,
        current_unix_ms()?,
    )?;

    println!("TraceFact behavior comparison");
    println!();
    println!("  Database:       {}", database_path.display());
    println!("  Baseline:       {}", report.baseline_name);
    println!("  Baseline run:   {}", report.baseline_source_run_id);
    println!("  Current run:    {}", report.current_run_id);
    println!("  Application:    {}", report.application);
    println!(
        "  Scope match:    {}",
        if report.comparable {
            "yes"
        } else {
            "no; findings skipped"
        }
    );
    println!(
        "  Events:         baseline {}, current {}",
        report.baseline_event_count, report.current_event_count
    );
    println!(
        "  Compared:       {}",
        if report.compared_categories.is_empty() {
            "none".to_string()
        } else {
            report.compared_categories.join(", ")
        }
    );
    println!(
        "  Skipped:        {}",
        if report.skipped_categories.is_empty() {
            "none".to_string()
        } else {
            report.skipped_categories.join(", ")
        }
    );
    println!();
    if !report.comparable {
        println!(
            "No behavior-set findings were generated because the observation scopes do not match."
        );
    } else if report.compared_categories.is_empty() {
        println!("No behavior-set findings were generated because no category had sufficient stored provenance.");
    } else if report.findings.is_empty() {
        println!("No set differences were found in the comparable observation categories.");
    } else {
        println!("Findings");
        for finding in &report.findings {
            println!(
                "  {} [{}] {}: {}",
                finding.finding_id, finding.kind, finding.category, finding.observation
            );
            println!("    {}", finding.explanation);
            println!(
                "    Baseline evidence: {}",
                if finding.baseline_event_ids.is_empty() {
                    "no matching event IDs".to_string()
                } else {
                    finding.baseline_event_ids.join(", ")
                }
            );
            println!(
                "    Current evidence:  {}",
                if finding.current_event_ids.is_empty() {
                    "no matching event IDs".to_string()
                } else {
                    finding.current_event_ids.join(", ")
                }
            );
            if !finding.current_context_event_ids.is_empty() {
                println!(
                    "    Current category context: {}",
                    finding.current_context_event_ids.join(", ")
                );
            }
        }
    }

    println!();
    println!("Event counts by type");
    println!(
        "  Baseline: {}",
        serde_json::to_string(&report.baseline_event_counts_by_type)
            .map_err(|error| format!("Could not serialize baseline event counts: {error}"))?
    );
    println!(
        "  Current:  {}",
        serde_json::to_string(&report.current_event_counts_by_type)
            .map_err(|error| format!("Could not serialize current event counts: {error}"))?
    );

    if !report.coverage_changes.is_empty() {
        println!();
        println!("Coverage and scope changes");
        for change in &report.coverage_changes {
            println!(
                "  [{}] {}: {}",
                change.kind, change.category, change.explanation
            );
            if change.baseline_value.is_some() || change.current_value.is_some() {
                println!(
                    "    Baseline: {}",
                    change.baseline_value.as_deref().unwrap_or("not recorded")
                );
                println!(
                    "    Current:  {}",
                    change.current_value.as_deref().unwrap_or("not recorded")
                );
            }
        }
    }

    println!();
    println!("Limitations");
    for limitation in &report.limitations {
        println!("  - {limitation}");
    }
    println!();
    println!("A difference is a deterministic result from stored observations, not proof of malicious behavior.");

    if let Some(output_path) = output_path {
        let json = serde_json::to_vec_pretty(&report)
            .map_err(|error| format!("Could not serialize comparison report: {error}"))?;
        let path = std::path::Path::new(output_path);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| format!(
                "Could not create comparison report at {} (existing files are not overwritten): {error}",
                path.display()
            ))?;
        if let Err(error) = file.write_all(&json).and_then(|_| file.write_all(b"\n")) {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(format!("Could not write comparison report: {error}"));
        }
        println!("Comparison report exported to: {}", path.display());
        println!("Inspect the report before sharing it; it contains local process and endpoint metadata.");
    }

    Ok(())
}

fn run_history(limit: u32) -> Result<(), String> {
    let (connection, database_path) = storage::open_default().map_err(|error| error.to_string())?;
    let runs = storage::list_runs(&connection, limit).map_err(|error| error.to_string())?;

    println!("TraceFact history");
    println!();
    println!("  Database: {}", database_path.display());
    println!();

    if runs.is_empty() {
        println!("  No saved runs.");
        return Ok(());
    }

    println!("  RUN ID                 APPLICATION              STATUS       EVENTS   STARTED AT");
    println!("  -------------------------------------------------------------------------------");

    for run in runs {
        println!(
            "  {:<22} {:<24} {:<12} {:>6}   {}",
            run.run_id, run.application, run.status, run.event_count, run.started_at_ms
        );
    }

    Ok(())
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);

    match args.next().as_deref() {
        Some("doctor") => {
            println!("TraceFact doctor");
            println!("  Core:            ready");
            println!("  Storage design:  SQLite");
            println!("  Network:         TCP metadata in watch mode");
            println!("  Payload capture: disabled");
            println!("  Telemetry:       disabled");
            println!("  AI:              optional / not required");
            ExitCode::SUCCESS
        }
        Some("demo") => {
            let passport = collectors::demo::build_demo_passport();
            match serde_json::to_string_pretty(&passport) {
                Ok(json) => {
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("TraceFact could not serialize the demo passport: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("watch") => match args.next().and_then(|value| value.parse::<u32>().ok()) {
            Some(pid) => {
                #[cfg(windows)]
                {
                    match run_watch(pid) {
                        Ok(()) => ExitCode::SUCCESS,
                        Err(error) => {
                            eprintln!("TraceFact could not watch process {pid}: {error}");
                            ExitCode::FAILURE
                        }
                    }
                }
                #[cfg(not(windows))]
                {
                    let _ = pid;
                    eprintln!("The Windows process watcher is available only on Windows.");
                    ExitCode::FAILURE
                }
            }
            None => {
                eprintln!("Usage: tracefact watch <pid>");
                ExitCode::FAILURE
            }
        },
        Some("process") => match args.next().and_then(|value| value.parse::<u32>().ok()) {
            Some(pid) => match run_process(pid) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("TraceFact could not observe process {pid}: {error}");
                    ExitCode::FAILURE
                }
            },
            None => {
                eprintln!("Usage: tracefact process <pid>");
                ExitCode::FAILURE
            }
        },
        Some("inspect") => match args.next() {
            Some(run_id) => match run_inspect(&run_id) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("TraceFact could not inspect run {run_id}: {error}");
                    ExitCode::FAILURE
                }
            },
            None => {
                eprintln!("Usage: tracefact inspect <run_id|latest>");
                ExitCode::FAILURE
            }
        },
        Some("export") => match (args.next(), args.next()) {
            (Some(run_id), Some(path)) => match run_export(&run_id, &path) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("TraceFact could not export evidence: {error}");
                    ExitCode::FAILURE
                }
            },
            _ => {
                eprintln!("Usage: tracefact export <run_id|latest> <path.json>");
                ExitCode::FAILURE
            }
        },
        Some("baseline") => match args.next().as_deref() {
            Some("save") => match (args.next(), args.next()) {
                (Some(name), Some(run_id)) => match run_baseline_save(&name, &run_id) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => {
                        eprintln!("TraceFact could not save baseline: {error}");
                        ExitCode::FAILURE
                    }
                },
                _ => {
                    eprintln!("Usage: tracefact baseline save <name> <run_id|latest>");
                    ExitCode::FAILURE
                }
            },
            Some("list") => match run_baseline_list() {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("TraceFact could not list baselines: {error}");
                    ExitCode::FAILURE
                }
            },
            Some("inspect") => match args.next() {
                Some(name) => match run_baseline_inspect(&name) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => {
                        eprintln!("TraceFact could not inspect baseline: {error}");
                        ExitCode::FAILURE
                    }
                },
                None => {
                    eprintln!("Usage: tracefact baseline inspect <name>");
                    ExitCode::FAILURE
                }
            },
            Some("export") => match (args.next(), args.next()) {
                (Some(name), Some(path)) => match run_baseline_export(&name, &path) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => {
                        eprintln!("TraceFact could not export baseline: {error}");
                        ExitCode::FAILURE
                    }
                },
                _ => {
                    eprintln!("Usage: tracefact baseline export <name> <path.json>");
                    ExitCode::FAILURE
                }
            },
            _ => {
                eprintln!("Usage: tracefact baseline <save|list|inspect|export> ...");
                ExitCode::FAILURE
            }
        },
        Some("compare") => match (args.next(), args.next()) {
            (Some(baseline_name), Some(run_id)) => {
                let output_path = args.next();
                match run_compare(&baseline_name, &run_id, output_path.as_deref()) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => {
                        eprintln!("TraceFact could not compare behavior: {error}");
                        ExitCode::FAILURE
                    }
                }
            }
            _ => {
                eprintln!("Usage: tracefact compare <baseline_name> <run_id|latest> [report.json]");
                ExitCode::FAILURE
            }
        },
        Some("history") => match run_history(20) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("TraceFact could not read history: {error}");
                ExitCode::FAILURE
            }
        },
        _ => {
            print_help();
            ExitCode::SUCCESS
        }
    }
}

#[cfg(all(test, windows))]
mod network_flow_tests {
    use super::NetworkFlowKey;
    use std::net::SocketAddr;

    #[test]
    fn flow_key_is_independent_of_endpoint_direction() {
        let left: SocketAddr = "192.0.2.10:51000".parse().unwrap();
        let right: SocketAddr = "198.51.100.15:443".parse().unwrap();

        assert_eq!(
            NetworkFlowKey::new(1234, left, right),
            NetworkFlowKey::new(1234, right, left)
        );
    }

    #[test]
    fn flow_key_is_scoped_to_process_id() {
        let left: SocketAddr = "192.0.2.10:51000".parse().unwrap();
        let right: SocketAddr = "198.51.100.15:443".parse().unwrap();

        assert_ne!(
            NetworkFlowKey::new(1234, left, right),
            NetworkFlowKey::new(5678, left, right)
        );
    }

    #[test]
    fn disconnect_can_reuse_process_identity_after_exit() {
        use super::{
            cached_process_for_disconnect, ActiveProcess, NetworkFlowKey, TrackedNetworkFlow,
        };
        use crate::collectors::windows_network::NetworkOperation;
        use std::collections::HashMap;

        let source: SocketAddr = "10.0.0.2:51000".parse().unwrap();
        let destination: SocketAddr = "198.51.100.15:443".parse().unwrap();
        let key = NetworkFlowKey::new(1234, source, destination);
        let process = ActiveProcess {
            name: "powershell.exe".to_string(),
            depth: 1,
            parent_pid: Some(5678),
        };
        let mut flows = HashMap::new();
        flows.insert(
            key.clone(),
            TrackedNetworkFlow {
                target: "198.51.100.15:443".to_string(),
                process: process.clone(),
            },
        );

        let recovered = cached_process_for_disconnect(NetworkOperation::Disconnect, &key, &flows)
            .expect("the observed flow should retain its process identity");
        assert_eq!(flows.get(&key).unwrap().target, "198.51.100.15:443");
        assert_eq!(recovered.name, "powershell.exe");
        assert_eq!(recovered.depth, 1);
        assert_eq!(recovered.parent_pid, Some(5678));
        assert!(cached_process_for_disconnect(NetworkOperation::Connect, &key, &flows).is_none());
    }
}
